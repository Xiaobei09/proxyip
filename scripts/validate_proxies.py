#!/usr/bin/env python3
"""Validate proxy reachability and measure latency.

Reads ``data/download/all.txt`` (``ip:port#country`` lines) and checks each proxy.
A TLS handshake to the proxy itself (works for Cloudflare edge proxies,
which serve TLS on 443/8443/2053/2083/2087/2096) is performed.

Checks run concurrently with asyncio (default 500 in-flight, kept bounded by
an in-flight task pool). Each alive proxy also gets a download speed test on
a freshly-opened TLS connection, gated by a semaphore so
bandwidth stays low-contention. The speed test is steady-state: the first
``--speed-warmup-bytes`` (default 256 KiB) covering TCP slow-start ramp-up
are excluded from timing and only the remaining window is measured.
Outputs are written under ``data/valid/``
mirroring the structure of ``data/``. Non-limited outputs are ordered by
latency (fastest first); ``*_ltd`` outputs pick the fastest per country by
measured speed. ``countries/<cc>/`` and ``sets/<name>/`` are per-country and
per-set directories holding ``all.txt``, ``ltd.txt`` (and, after the quality
run, ``rep.txt``). Lines use the ``ip:port#<flag><cc>-<latency>ms-<speed>MB/s``
format (speed omitted when the test failed). Proxies that connect at the TCP
level but fail the check are retried once.

Alongside ``all.txt`` each country/set directory also gets family and
mainland-China group files: ``v4.txt`` (IPv4-only exit), ``v6.txt``
(IPv6-only exit), ``46.txt`` (dual-stack exit), ``cn.txt`` (China-reachable),
``cn4.txt`` / ``cn6.txt`` / ``cn46.txt`` (China-reachable × family), plus a
``*_ltd.txt`` speed-limited variant per group. Every list additionally gets
a ``*_verified.txt`` variant (full-chain verified: the speed test succeeded,
i.e. TLS + HTTP 2xx + real download all worked — filters half-dead proxies
that handshake but serve no data) and a ``*_stable.txt`` variant (alive in
both this and the previous run, via the previous ``index.json`` — counters
fast churn); root-level ``all_verified.txt`` / ``all_stable.txt`` mirror
this for the global list. Family comes from
``exit_family.json`` (falling back to ``-V4``/``-V6``/``-DS`` line notes);
China reachability from the ``-CN`` line note or ``china.json``
(``verdict == reachable``) as a fallback, matching ``all_cn.txt`` semantics.
"""

import argparse
import asyncio
import json
import logging
import re
import shutil
import ssl
import statistics
import sys
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

import urllib.error
import urllib.request

from common import (
    ALL_FILE,
    CHINA_FILE,
    EXIT_FAMILY_FILE,
    EXT_API_SOURCES,
    EXT_CHECK_FILE,
    INDEX_FILE,
MAX_HISTORY_RECORDS,
    PER_COUNTRY_LIMIT,
    SPEED_FILE,
    VALID_DIR,
    VALID_HISTORY_FILE,
    has_token,
    insert_exit_region,
    now_ts,
    parse_headers,
    parse_line,
    rewrite_latency,
    write_text_if_changed,
)
from download_proxies import COUNTRY_SETS, SMALL_SETS

SPEED_HOST = "cdnjs.cloudflare.com"
TARGET_SNI = SPEED_HOST
SPEED_PATH = "/ajax/libs/three.js/r128/three.js"
SPEED_READ_BYTES = 1048576
SPEED_TIMEOUT = 5
SPEED_MIN_BYTES = 16384
SPEED_WARMUP_BYTES = 256 * 1024
SPEED_HEAD_CAP = 32 * 1024
SPEED_WORKERS = 30
ADAPTIVE_SPEED_RTT_FACTOR = 30
ADAPTIVE_SPEED_MIN_BYTES = 5 * 1024 * 1024
ADAPTIVE_SPEED_MIN_TIMEOUT = 5
TIMEOUT = 5
READ_CAP = 3
WORKERS = 500
RETRY_DELAY = 0.2
EXT_TIMEOUT = 10
EXT_WORKERS = 10

QUICK_TIMEOUT = 2.0    # 预筛 TCP 连接超时（秒）
QUICK_WORKERS = 300    # 预筛并发上限

LATENCY_BUCKETS = [
    (0, 100),
    (100, 200),
    (200, 300),
    (300, 500),
    (500, 1000),
    (1000, None),
]

SPEED_BUCKETS = [
    (0, 0.5),
    (0.5, 1),
    (1, 2),
    (2, 5),
    (5, None),
]

_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE


# ---------------------------------------------------------------- 外部 API 多源检测


def _normalize_ext_response(source: dict, data: dict) -> dict:
    """Normalize raw API response to standard format."""
    name = source["name"]

    if name in ("090227", "cmliu"):
        ipv4 = data.get("probe_results", {}).get("ipv4", {})
        ipv6 = data.get("probe_results", {}).get("ipv6", {})
        return {
            "name": name,
            "ok": bool(data.get("success")),
            "response_ms": data.get("responseTime"),
            "colo": data.get("colo"),
            "ipv4_ok": bool(ipv4.get("ok")),
            "ipv6_ok": bool(ipv6.get("ok")),
            "dual_stack": data.get("dual_stack", False),
            "inferred_stack": data.get("inferred_stack"),
            "exit_geo": ipv4.get("exit"),
        }

    if name == "toicf":
        return {
            "name": name,
            "ok": bool(data.get("ok")),
            "response_ms": None,
            "colo": None,
            "ipv4_ok": bool(data.get("supports_ipv4")),
            "ipv6_ok": bool(data.get("supports_ipv6")),
            "dual_stack": bool(data.get("dual_stack")),
            "inferred_stack": data.get("inferred_stack"),
            "exit_geo": _extract_toicf_exit_geo(data),
        }

    return {"name": name, "ok": False}


def _extract_toicf_exit_geo(data: dict) -> dict | None:
    """Extract exit_geo from ToiCF probe_results format."""
    for probe in data.get("probe_results", []):
        if probe.get("ok") and probe.get("exit_ip"):
            return {
                "country": probe.get("exit_country"),
                "countryCode": probe.get("exit_country"),
                "city": probe.get("exit_city"),
                "asn": probe.get("exit_asn"),
                "org": probe.get("exit_org"),
            }
    return None


async def check_one_ext_api(
    source: dict, ip: str, port: str, timeout: int,
) -> dict:
    """Call one external API source and return a normalized result dict."""
    param = source["param_key"]
    url = f"{source['url']}?{param}={ip}:{port}"

    def _fetch() -> dict:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "proxyip-checker/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    try:
        data = await asyncio.to_thread(_fetch)
        return _normalize_ext_response(source, data)
    except Exception as exc:  # noqa: BLE001
        logging.debug("ext_api %s %s:%s failed: %s", source["name"], ip, port, exc)
        return {"name": source["name"], "ok": False, "error": str(exc)}


async def check_all_ext_apis(
    ip: str, port: str, ext_timeout: int,
) -> list[dict]:
    """Call all external API sources concurrently and return normalized results."""
    tasks = [
        check_one_ext_api(src, ip, port, ext_timeout or src["timeout"])
        for src in EXT_API_SOURCES
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out = []
    for r in results:
        if isinstance(r, Exception):
            out.append({"name": "unknown", "ok": False, "error": str(r)})
        elif isinstance(r, dict):
            out.append(r)
    return out


def merge_ext_verdict(results: list[dict]) -> dict:
    """Multi-source consensus for proxy availability.

    Rules (following china_check.py merge_verdict pattern):
    - 2+ sources ok -> alive
    - 1 source ok -> uncertain
    - 0 sources ok, 2+ failed -> dead
    - all errors -> skipped
    """
    ok = [r for r in results if r.get("ok")]
    fail = [r for r in results if not r.get("ok") and r.get("error")]

    if len(ok) >= 2:
        return {
            "alive": True,
            "basis": [r["name"] for r in ok],
            "merged": merge_geo(ok),
        }
    if len(ok) == 1:
        return {
            "alive": "uncertain",
            "basis": [r["name"] for r in ok],
            "merged": ok[0],
        }
    if len(fail) >= 2:
        return {"alive": False, "basis": [], "merged": None}
    return {"alive": "skipped", "basis": [], "merged": None}


def merge_geo(ok_results: list[dict]) -> dict:
    """Merge exit geo and metadata from multiple ok sources."""
    merged: dict = {
        "response_ms": None,
        "colo": None,
        "ipv4_ok": False,
        "ipv6_ok": False,
        "dual_stack": False,
        "inferred_stack": None,
        "exit_geo": None,
        "geo_mismatch": False,
    }
    geo_countries: list[str] = []
    for r in ok_results:
        if r.get("response_ms") is not None:
            if merged["response_ms"] is None or r["response_ms"] < merged["response_ms"]:
                merged["response_ms"] = r["response_ms"]
        if r.get("colo") and not merged["colo"]:
            merged["colo"] = r["colo"]
        merged["ipv4_ok"] = merged["ipv4_ok"] or r.get("ipv4_ok", False)
        merged["ipv6_ok"] = merged["ipv6_ok"] or r.get("ipv6_ok", False)
        merged["dual_stack"] = merged["dual_stack"] or r.get("dual_stack", False)
        if r.get("inferred_stack") and not merged["inferred_stack"]:
            merged["inferred_stack"] = r["inferred_stack"]
        geo = r.get("exit_geo")
        if geo:
            cc = geo.get("countryCode") or geo.get("country")
            if cc:
                geo_countries.append(cc)
            if not merged["exit_geo"]:
                merged["exit_geo"] = geo
    if len(set(geo_countries)) > 1:
        merged["geo_mismatch"] = True
    return merged


def bucket_latency(latencies: list[float]) -> dict[str, int]:
    """Histogram of latencies (ms) into ``LATENCY_BUCKETS``, in bucket order."""
    counts = {}
    for lo, hi in LATENCY_BUCKETS:
        label = f"{lo}-{hi}" if hi is not None else f"{lo}+"
        if hi is None:
            counts[label] = sum(1 for lat in latencies if lat >= lo)
        else:
            counts[label] = sum(1 for lat in latencies if lo <= lat < hi)
    return counts


def bucket_speed(speeds: list[float]) -> dict[str, int]:
    """Histogram of download speeds (MB/s) into ``SPEED_BUCKETS``, in order."""
    counts = {}
    for lo, hi in SPEED_BUCKETS:
        label = f"{lo}-{hi}" if hi is not None else f"{lo}+"
        if hi is None:
            counts[label] = sum(1 for sp in speeds if sp >= lo)
        else:
            counts[label] = sum(1 for sp in speeds if lo <= sp < hi)
    return counts


def compute_speed(bytes_read: int, elapsed: float) -> float | None:
    """Download speed in MB/s (2 dp), or ``None`` when the sample is unusable."""
    if bytes_read < SPEED_MIN_BYTES or elapsed <= 0:
        return None
    return round(bytes_read / 1024 / 1024 / elapsed, 2)


def adaptive_speed_params(
    tls_latency_ms: float,
    base_bytes: int,
    base_timeout: int,
) -> tuple[int, int]:
    """Compute (cap_bytes, cap_sec) adapted to the measured RTT.

    TCP slow start needs ~4-5 RTTs to reach full speed.  We allow
    ``ADAPTIVE_SPEED_RTT_FACTOR`` round trips and a minimum download
    volume so that high-latency connections reach steady state.
    """
    import math

    rtt_sec = tls_latency_ms / 1000
    adaptive_timeout = max(
        ADAPTIVE_SPEED_MIN_TIMEOUT,
        math.ceil(rtt_sec * ADAPTIVE_SPEED_RTT_FACTOR),
    )
    adaptive_bytes = max(
        ADAPTIVE_SPEED_MIN_BYTES,
        base_bytes,
        int(adaptive_timeout * 1024 * 1024),
    )
    return adaptive_bytes, adaptive_timeout


def flag_of(cc: str) -> str:
    """Regional-indicator emoji flag for an ISO country code (``US`` -> ``🇺🇸``)."""
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c.upper()) - ord("A")) for c in cc)


def fmt_entry(
    ip: str, port: str, cc: str, latency: float, speed: float | None
) -> str:
    """``ip:port#<flag><cc>-<latency>ms-<speed>MB/s`` (speed omitted when None)."""
    parts = [f"{flag_of(cc)}{cc}", f"{latency:.0f}ms"]
    if speed is not None:
        parts.append(f"{speed:.2f}MB/s")
    return f"{ip}:{port}#{'-'.join(parts)}"


def merge_old_note(base_line: str, old_note: str) -> str:
    """把旧行备注里的出口区域和附注 token 接回重生成的基础行。

    ``old_note`` 形如 ``→LAX-120ms-0.44MB/s-NF(US) D+ YT GPT-DC-72-V4-CN``。
    从 old_note 中提取出口区域（``→XXX``）以及剥离延迟/测速后的附注 token
    （CN、streaming、reputation、speed tier、IP type 等），拼接到重生成的
    基础行之后，使跨 update 周期的附注不丢失。
    """
    m = re.match(r"^(→[A-Z]{2,5})?(-\d+(?:\.\d+)?ms)?(-\d+(?:\.\d+)?MB/s)?(.*)", old_note)
    region = m.group(1) or ""
    trailing = (m.group(4) or "").rstrip()
    if not region and not trailing:
        return base_line
    head, sep, tail = base_line.partition("-")
    if not sep:
        return base_line
    return head + region + sep + tail + trailing


GROUP_NAMES = ("v4", "v6", "46", "cn", "cn4", "cn6", "cn46")
ROOT_GROUP_FILES = ("all_46", "all_cn4", "all_cn6", "all_cn46")


def load_family_map(path: Path | None = None) -> dict:
    """``exit_family.json`` → ``{key: family}``；缺失/损坏 → ``{}``。

    ``key`` 为 ``ip:port#cc``，``family`` 取 ``ipv4``/``ipv6``/``dual``。
    """
    path = path or EXIT_FAMILY_FILE
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    proxies = data.get("proxies", data)
    if not isinstance(proxies, dict):
        return {}
    return {
        key: meta["family"]
        for key, meta in proxies.items()
        if isinstance(meta, dict) and meta.get("family") in ("ipv4", "ipv6", "dual")
    }


def load_cn_reachable(path: Path | None = None) -> set[str]:
    """``china.json`` verdict==reachable 的 key 集合；缺失/损坏 → ``set()``。

    与 ``all_cn.txt``（``reachable OR has_cn_note``）的 reachable 侧语义对齐，
    供 cn 分组兜底：行内 ``-CN`` 备注缺失时仍可归入 cn 组。
    """
    path = path or CHINA_FILE
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(data, dict):
        return set()
    proxies = data.get("proxies", data)
    if not isinstance(proxies, dict):
        return set()
    return {
        key
        for key, meta in proxies.items()
        if isinstance(meta, dict) and meta.get("verdict") == "reachable"
    }


def load_cn_ms(path: Path | None = None) -> dict[str, float]:
    """``china.json`` 中 reachable 条目的 ``key -> 大陆实测毫秒`` 映射。

    供 CN 系分组视图把行内延迟替换为大陆 RTT；缺失/损坏 → 空 dict。
    """
    path = path or CHINA_FILE
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    proxies = data.get("proxies", data)
    if not isinstance(proxies, dict):
        return {}
    out: dict[str, float] = {}
    for key, meta in proxies.items():
        if not isinstance(meta, dict) or meta.get("verdict") != "reachable":
            continue
        ms = meta.get("ms")
        if isinstance(ms, (int, float)) and ms > 0:
            out[key] = float(ms)
    return out


def family_of(entry: str, note: str, families: dict) -> str | None:
    """入口家族：优先 ``exit_family.json``，缺失时按行内 ``-V4``/``-V6``/``-DS`` 兜底。"""
    fam = families.get(entry)
    if fam in ("ipv4", "ipv6", "dual"):
        return fam
    if has_token(note, "DS"):
        return "dual"
    if has_token(note, "V4") and has_token(note, "V6"):
        return "dual"
    if has_token(note, "V4"):
        return "ipv4"
    if has_token(note, "V6"):
        return "ipv6"
    return None


def classify_groups(family: str | None, is_cn: bool) -> set[str]:
    """按 家族 × 大陆可达 归组。unknown 家族仅可能进 ``cn`` 组。"""
    groups: set[str] = set()
    if family == "ipv4":
        groups.add("v4")
    elif family == "ipv6":
        groups.add("v6")
    elif family == "dual":
        groups.add("46")
    if is_cn:
        groups.add("cn")
        if family == "ipv4":
            groups.add("cn4")
        elif family == "ipv6":
            groups.add("cn6")
        elif family == "dual":
            groups.add("cn46")
    return groups


def parse_entries(lines: list[str]) -> list[tuple[str, str, str]]:
    entries = []
    for line in lines:
        line = line.strip()
        if not line or "#" not in line:
            continue
        addr, country = line.rsplit("#", 1)
        if ":" not in addr:
            continue
        ip, port = addr.rsplit(":", 1)
        if not port.isdigit():
            continue
        entries.append((ip, port, country))
    return entries


def classify_quick_candidates(
    entries: list[tuple[str, str, str]],
    prev_alive_ipports: set[str],
) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    """把 entries 分成（预连通候选，正常全检）。

    候选 = 上一轮未存活的所有条目（raw 海量枯萎/新建节点）——先做廉价 TCP
    连通性预筛；上一轮存活者直接走完整 TLS/测速流程。TCP 连不通的端口
    必然无法提供 HTTPS 代理，跳过无损。
    """
    candidates, normal = [], []
    for entry in entries:
        eip = f"{entry[0]}:{entry[1]}"
        if eip not in prev_alive_ipports:
            candidates.append(entry)
        else:
            normal.append(entry)
    return candidates, normal


async def quick_prefilter_stale(
    entries: list[tuple[str, str, str]],
    prev_alive_ipports: set[str],
    args: argparse.Namespace,
) -> tuple[list[tuple[str, str, str]], int]:
    """对上一轮未存活的条目做快速 TCP 连通预筛：通者并入全检，不通直接跳过。

    返回（全检条目列表，跳过计数）。
    """
    candidates, normal = classify_quick_candidates(entries, prev_alive_ipports)
    if not candidates:
        return entries, 0
    sem = asyncio.Semaphore(QUICK_WORKERS)
    lock = asyncio.Lock()
    skipped = 0

    async def probe(entry: tuple[str, str, str]) -> None:
        nonlocal skipped
        ok = False
        try:
            async with sem:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(entry[0], int(entry[1])),
                    args.quick_timeout,
                )
            ok = True
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        async with lock:
            if ok:
                normal.append(entry)
            else:
                skipped += 1

    await asyncio.gather(*[probe(c) for c in candidates])
    return normal, skipped


async def open_conn(
    ip: str,
    port: str,
    timeout: int,
    ctx: ssl.SSLContext | None = None,
    sni: str | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    async with asyncio.timeout(timeout):
        return await asyncio.open_connection(
            ip, int(port), ssl=ctx, server_hostname=sni
        )


async def check_proxy(
    ip: str,
    port: str,
    args: argparse.Namespace,
    speed_sem: asyncio.Semaphore | None,
) -> tuple[str, str | None, float | None, float | None, dict | None]:
    """Return ``(status, method, latency_ms, speed_mbps, ext_data)``.

    Alive proxies additionally get a download speed test on a freshly-opened
    connection (gated by ``speed_sem``, so the semaphore-queued probes hold no
    connection while waiting). Speed is ``None`` when the measurement failed
    (the proxy stays alive).
    """

    def elapsed(since: float) -> float:
        return round((time.monotonic() - since) * 1000, 1)

    async def measure_speed(method: str) -> float | None:
        if args.no_speed or speed_sem is None:
            return None
        async with speed_sem:
            return await speed_probe(ip, port, args, method, tls_latency)

    tls_started = time.monotonic()
    try:
        reader, writer = await open_conn(ip, port, args.timeout, ctx=_TLS_CTX, sni=args.sni)
    except ssl.SSLError:
        return "retry", None, None, None, None
    except (OSError, asyncio.TimeoutError, ValueError):
        return "dead", None, None, None, None
    tls_latency = elapsed(tls_started)
    try:
        speed = await measure_speed("tls")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass
    return "ok", "tls", tls_latency, speed, None


async def speed_probe(
    ip: str,
    port: str,
    args: argparse.Namespace,
    method: str,
    tls_latency_ms: float = 0.0,
) -> float | None:
    """Open a fresh TLS connection through the proxy and measure download speed.

    Any failure returns ``None``; the proxy stays alive, it just gets no speed
    entry.
    """
    try:
        reader, writer = await open_conn(ip, port, args.timeout, ctx=_TLS_CTX, sni=args.sni)
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError):
        return None
    try:
        if args.adaptive_speed:
            cap_bytes, cap_sec = adaptive_speed_params(
                tls_latency_ms, args.speed_bytes, args.speed_timeout,
            )
        else:
            cap_bytes, cap_sec = args.speed_bytes, args.speed_timeout
        return await speed_download(
            reader, writer, args.speed_host, args.speed_path,
            cap_bytes, cap_sec,
            warmup_bytes=getattr(args, "speed_warmup_bytes", SPEED_WARMUP_BYTES),
        )
    except (ConnectionError, OSError):
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

async def speed_download(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    path: str,
    cap_bytes: int,
    cap_sec: int,
    warmup_bytes: int = SPEED_WARMUP_BYTES,
    clock: Callable[[], float] = time.monotonic,
) -> float | None:
    """Steady-state download of ``path``, returning MB/s.

    Reads up to ``cap_bytes`` within ``cap_sec``.  The response head is read
    first and only ``2xx`` answers are measured — anything else (403 pages,
    non-HTTP garbage) fails the test instead of polluting speed data.  The
    first ``warmup_bytes`` of body cover the TCP slow-start / TLS+HTTP
    ramp-up and are excluded from timing; throughput is measured only over
    the remaining steady-state window, so a slow ramp no longer drags the
    reported speed down.  When no usable steady-state sample exists (early
    EOF or timeout inside the warm-up), the result falls back to the
    whole-transfer average so coverage stays on par with the previous
    behaviour.
    """
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        writer.write(req.encode("ascii"))
        await writer.drain()
    except (ConnectionError, OSError):
        return None

    def feed(chunk: bytes) -> None:
        nonlocal total, timed_bytes, timed_start
        if not chunk:
            return
        total += len(chunk)
        if timed_start is None:
            if total >= warmup_bytes:
                timed_start = clock()
        else:
            timed_bytes += len(chunk)

    start = clock()
    total = 0
    timed_bytes = 0
    timed_start: float | None = start if warmup_bytes <= 0 else None

    # Read + validate the response head before counting anything.
    head = b""
    while b"\r\n\r\n" not in head:
        remain = cap_sec - (clock() - start)
        if remain <= 0:
            return None
        try:
            chunk = await asyncio.wait_for(reader.read(65536), min(READ_CAP, remain))
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return None
        if not chunk:
            return None
        head += chunk
        if b"\r\n\r\n" not in head and len(head) > SPEED_HEAD_CAP:
            return None
    head_block, _, body = head.partition(b"\r\n\r\n")
    status, _headers = parse_headers(head_block)
    if status is None or not 200 <= status < 300:
        return None
    feed(body)
    while total < cap_bytes:
        remain = cap_sec - (clock() - start)
        if remain <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(65536), min(READ_CAP, remain))
        except (asyncio.TimeoutError, ConnectionError, OSError):
            break
        if not chunk:
            break
        feed(chunk)
    if timed_start is not None and timed_bytes >= SPEED_MIN_BYTES:
        return compute_speed(timed_bytes, clock() - timed_start)
    return compute_speed(total, clock() - start)


def write_index(ordered: list[str], alive: dict) -> None:
    """Write ``index.json``: each alive proxy -> ``[latency_ms, method]``.

    Skipped when byte-identical so stable data produces no extra commits.
    """
    proxies = {entry: [alive[entry][4], alive[entry][3]] for entry in ordered}
    content = (
        json.dumps({"proxies": proxies}, ensure_ascii=False, separators=(",", ":"))
        + "\n"
    )
    write_text_if_changed(INDEX_FILE, content)


def write_speed(alive: dict) -> None:
    """Write ``speed.json``: each speed-tested proxy -> ``speed_mbps``.

    Ordered by speed (fastest first); skipped when byte-identical.
    """
    proxies = {e: alive[e][5] for e in alive if alive[e][5] is not None}
    ordered = sorted(proxies, key=lambda e: (-proxies[e], e))
    content = (
        json.dumps(
            {"proxies": {e: proxies[e] for e in ordered}},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )
    write_text_if_changed(SPEED_FILE, content)


def write_ext_check(alive: dict) -> None:
    """Write ``ext_check.json``: per-proxy external API enrichment data.

    Only includes proxies that have ext_data (ext_check was enabled).
    Skipped when byte-identical.
    """
    proxies = {}
    for entry, tpl in alive.items():
        ext_data = tpl[6] if len(tpl) > 6 else None
        if ext_data:
            proxies[entry] = ext_data
    if not proxies:
        return
    content = (
        json.dumps(
            {"proxies": proxies},
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )
    write_text_if_changed(EXT_CHECK_FILE, content)


def load_prev_alive_keys() -> set[str] | None:
    """上一轮 ``index.json`` 的存活 key 集合；缺失/损坏返回 ``None``。

    用于生成 ``all_stable.txt``（连续两轮存活交集，抗 churn）。必须在
    ``write_index`` 覆盖本轮结果**之前**调用。
    """
    if not INDEX_FILE.exists():
        return None
    try:
        data = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    proxies = data.get("proxies", data) if isinstance(data, dict) else {}
    if not isinstance(proxies, dict):
        return None
    return set(proxies)


def write_valid_outputs(
    alive: dict[str, tuple[str, str, str, str, float, float | None, dict | None]],
    per_country_limit: int,
    families: dict | None = None,
    cn_reachable: set[str] | None = None,
    prev_keys: set[str] | None = None,
) -> dict:
    VALID_DIR.mkdir(parents=True, exist_ok=True)
    if families is None:
        families = load_family_map()
    if cn_reachable is None:
        cn_reachable = load_cn_reachable()
    cn_ms = load_cn_ms()

    old_notes: dict[str, str] = {}
    old_all = VALID_DIR / "all.txt"
    if old_all.exists():
        for old_line in old_all.read_text(encoding="utf-8").splitlines():
            parsed = parse_line(old_line)
            if parsed:
                old_notes[parsed[0]] = parsed[4]

    ordered = sorted(alive, key=lambda e: (alive[e][4], e))

    line_cache: dict[str, str] = {}
    groups_cache: dict[str, set[str]] = {}

    def line(entry: str) -> str:
        if entry in line_cache:
            return line_cache[entry]
        ip, port, cc, _m, latency, speed, ext_data = alive[entry]
        base = fmt_entry(ip, port, cc, latency, speed)
        exit_region = ""
        if ext_data:
            colo = ext_data.get("colo")
            if colo:
                exit_region = f"→{colo}"
            elif ext_data.get("exit_geo"):
                eg = ext_data["exit_geo"]
                exit_region = f"→{eg.get('city', '') or eg.get('countryCode', '')}"
        if exit_region:
            base = insert_exit_region(base, exit_region)
        old = old_notes.get(entry)
        text = merge_old_note(base, old) if old else base
        line_cache[entry] = text
        return text

    def ltd_key(entry: str) -> tuple:
        speed = alive[entry][5]
        if speed is not None:
            return (0, -speed, 0.0)
        return (1, 0.0, alive[entry][4])

    def is_verified(entry: str) -> bool:
        """全链路验证：测速成功 = TLS + HTTP 2xx + 真实下载全部通过。"""
        return alive[entry][5] is not None

    def is_stable(entry: str) -> bool:
        """连续两轮存活：上一轮 index.json 与本轮 alive 的交集（抗 churn）。"""
        return bool(prev_keys) and entry in prev_keys

    def entry_groups(entry: str) -> set[str]:
        if entry in groups_cache:
            return groups_cache[entry]
        text = line(entry)
        parsed = parse_line(text)
        note = parsed[4] if parsed else ""
        groups = classify_groups(
            family_of(entry, note, families),
            has_token(note, "CN") or entry in cn_reachable,
        )
        groups_cache[entry] = groups
        return groups

    def group_map(entries: list[str]) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {g: [] for g in GROUP_NAMES}
        for e in entries:
            for g in entry_groups(e):
                groups[g].append(e)
        return groups

    def write_variant(directory: Path, name: str, entries: list[str]) -> None:
        """写单个清单文件；空清单清理残留文件。

        CN 系分组（``cn*``）行内延迟替换为**大陆实测 RTT**（china.json ms）
        ——CN 视图里 ``ms`` 的语义是"大陆使用者连接该节点的延迟"，而非
        海外 runner 的 TLS 延迟；无大陆观测的行保留海外值。
        """
        cn_view = name == "cn" or name.startswith("cn_") or \
            name in ("cn4", "cn6", "cn46")
        path = directory / f"{name}.txt"
        if entries:
            body = []
            for e in entries:
                text = line(e)
                if cn_view and cn_ms:
                    text = rewrite_latency(text, cn_ms.get(e))
                body.append(text)
            write_text_if_changed(path, "\n".join(body) + "\n")
        elif path.exists():
            path.unlink()

    def write_group_files(
        directory: Path, grouped: dict[str, list[str]], ltd: dict[str, list[str]] | None = None
    ) -> None:
        """写全量分组文件；``ltd`` 提供时写 ``*_ltd`` 分组，否则清理残留。

        每个分组同时派生 ``<g>_verified``（全链路验证）、``<g>_stable``
        （连续两轮存活）及二者的 ``<g>_ltd_*`` 变体，空则清理残留。
        """
        for g in GROUP_NAMES:
            write_variant(directory, g, grouped[g])
            g_ltd = (ltd or {}).get(g, [])
            write_variant(directory, f"{g}_ltd", g_ltd)
            write_variant(
                directory, f"{g}_verified",
                [e for e in grouped[g] if is_verified(e)],
            )
            write_variant(
                directory, f"{g}_stable",
                [e for e in grouped[g] if is_stable(e)],
            )
            write_variant(
                directory, f"{g}_ltd_verified",
                [e for e in g_ltd if is_verified(e)],
            )
            write_variant(
                directory, f"{g}_ltd_stable",
                [e for e in g_ltd if is_stable(e)],
            )

    by_country: dict[str, list[str]] = defaultdict(list)
    by_port: dict[str, list[str]] = defaultdict(list)
    for entry in ordered:
        _ip, port, country, _m, _lat, _sp, _ext = alive[entry]
        by_country[country].append(entry)
        by_port[port].append(entry)

    countries_dir = VALID_DIR / "countries"
    ports_dir = VALID_DIR / "ports"
    sets_dir = VALID_DIR / "sets"
    countries_dir.mkdir(parents=True, exist_ok=True)
    ports_dir.mkdir(parents=True, exist_ok=True)
    sets_dir.mkdir(parents=True, exist_ok=True)

    country_group_ltd: dict[str, dict[str, list[str]]] = {}
    for country in sorted(by_country):
        grouped = group_map(by_country[country])
        country_group_ltd[country] = {
            g: sorted(grouped[g], key=ltd_key)[:per_country_limit]
            if per_country_limit > 0 else []
            for g in GROUP_NAMES
        }
        if country == "ALL":
            continue
        cdir = countries_dir / country
        cdir.mkdir(parents=True, exist_ok=True)
        write_text_if_changed(
            cdir / "all.txt", "\n".join(line(e) for e in by_country[country]) + "\n"
        )
        write_group_files(cdir, grouped, country_group_ltd[country])
        if per_country_limit > 0:
            entries = sorted(by_country[country], key=ltd_key)[:per_country_limit]
            write_text_if_changed(
                cdir / "ltd.txt", "\n".join(line(e) for e in entries) + "\n"
            )
            write_variant(cdir, "ltd_verified", [e for e in entries if is_verified(e)])
            write_variant(cdir, "ltd_stable", [e for e in entries if is_stable(e)])
    expected_countries = {c for c in by_country if c != "ALL"}
    for stale in countries_dir.iterdir():
        if stale.is_dir():
            if stale.name not in expected_countries:
                shutil.rmtree(stale)
        else:
            stale.unlink()

    for port in sorted(by_port, key=int):
        write_text_if_changed(
            ports_dir / f"{port}.txt", "\n".join(line(e) for e in by_port[port]) + "\n"
        )
    expected_ports = {f"{p}.txt" for p in by_port}
    for stale in ports_dir.iterdir():
        if stale.name not in expected_ports:
            stale.unlink()

    country_ltd: dict[str, list[str]] = {}
    for country, entries in by_country.items():
        country_ltd[country] = sorted(entries, key=ltd_key)[:per_country_limit]

    set_counts: dict[str, int] = {}
    for name, countries in {**COUNTRY_SETS, **SMALL_SETS}.items():
        cc_set = set(countries)
        full = [e for e in ordered if alive[e][2] in cc_set]
        sdir = sets_dir / name
        sdir.mkdir(parents=True, exist_ok=True)
        write_text_if_changed(
            sdir / "all.txt", "\n".join(line(e) for e in full) + "\n"
        )
        set_counts[name] = len(full)
        grouped = group_map(full)
        set_group_ltd = {
            g: sorted(
                [
                    e
                    for cc in countries
                    if cc in country_group_ltd
                    for e in country_group_ltd[cc].get(g, [])
                ],
                key=ltd_key,
            )
            for g in GROUP_NAMES
        }
        write_group_files(sdir, grouped, set_group_ltd)
        if per_country_limit > 0:
            ltd: list[str] = []
            for cc in countries:
                if cc in country_ltd:
                    ltd.extend(country_ltd[cc])
            ltd = sorted(ltd, key=ltd_key)
            write_text_if_changed(
                sdir / "ltd.txt", "\n".join(line(e) for e in ltd) + "\n"
            )
            write_variant(sdir, "ltd_verified", [e for e in ltd if is_verified(e)])
            write_variant(sdir, "ltd_stable", [e for e in ltd if is_stable(e)])
            set_counts[f"{name}_ltd"] = len(ltd)
    expected_sets = set({**COUNTRY_SETS, **SMALL_SETS})
    for stale in sets_dir.iterdir():
        if stale.is_dir():
            if stale.name not in expected_sets:
                shutil.rmtree(stale)
        else:
            stale.unlink()

    write_text_if_changed(VALID_DIR / "all.txt", "\n".join(line(e) for e in ordered) + "\n")
    set_counts["all"] = len(ordered)

    # 全链路验证子集：测速成功 = TLS + HTTP 2xx + 真实下载全部通过，
    # 比纯握手判活可靠（过滤"能握手不吐数据"的半死代理）。
    verified = [e for e in ordered if is_verified(e)]
    write_variant(VALID_DIR, "all_verified", verified)
    set_counts["all_verified"] = len(verified)

    # 连续两轮存活交集：上一轮 index.json 与本轮 alive 的交集，抗 churn。
    stable = [e for e in ordered if is_stable(e)]
    write_variant(VALID_DIR, "all_stable", stable)
    set_counts["all_stable"] = len(stable)

    if per_country_limit > 0:
        ltd_all = sorted(
            [e for cc in country_ltd for e in country_ltd[cc]], key=ltd_key
        )
        write_text_if_changed(
            VALID_DIR / "all_ltd.txt", "\n".join(line(e) for e in ltd_all) + "\n"
        )
        set_counts["all_ltd"] = len(ltd_all)
        ltd_ver = [e for e in ltd_all if is_verified(e)]
        ltd_sta = [e for e in ltd_all if is_stable(e)]
        write_variant(VALID_DIR, "all_ltd_verified", ltd_ver)
        write_variant(VALID_DIR, "all_ltd_stable", ltd_sta)
        set_counts["all_ltd_verified"] = len(ltd_ver)
        set_counts["all_ltd_stable"] = len(ltd_sta)
    root_grouped = group_map(ordered)
    for name in ROOT_GROUP_FILES:
        g = name[len("all_"):]
        write_variant(VALID_DIR, name, root_grouped[g])
        ltd = []
        if per_country_limit > 0:
            ltd = sorted(
                [
                    e
                    for cc in country_group_ltd
                    for e in country_group_ltd[cc].get(g, [])
                ],
                key=ltd_key,
            )
        write_variant(VALID_DIR, f"{name}_ltd", ltd)
        if per_country_limit > 0:
            write_variant(
                VALID_DIR, f"{name}_ltd_verified",
                [e for e in ltd if is_verified(e)],
            )
            write_variant(
                VALID_DIR, f"{name}_ltd_stable",
                [e for e in ltd if is_stable(e)],
            )
        write_variant(
            VALID_DIR, f"{name}_verified",
            [e for e in root_grouped[g] if is_verified(e)],
        )
        write_variant(
            VALID_DIR, f"{name}_stable",
            [e for e in root_grouped[g] if is_stable(e)],
        )
    write_index(ordered, alive)
    write_speed(alive)
    return {
        "__countries__": len(by_country),
        "__ports__": len(by_port),
        "__sets__": set_counts,
    }


async def check_entries(
    entries: list[tuple[str, str, str]], args: argparse.Namespace
) -> tuple[dict, dict[str, int], int, float]:
    results: dict[str, tuple[str, str, str, str, float, float | None, dict | None]] = {}
    by_method: dict[str, int] = {}
    retry_pool: list[tuple[str, str, str]] = []
    ext_pending: list[tuple[str, str, str, str, float, float | None]] = []
    lock = asyncio.Lock()
    speed_sem = asyncio.Semaphore(args.speed_workers)
    ext_sem = asyncio.Semaphore(args.ext_workers) if args.ext_check else None
    checked = 0
    ext_ok = 0
    ext_uncertain = 0
    ext_dead = 0
    ext_response_ms_sum = 0.0
    ext_response_ms_count = 0
    started = time.monotonic()
    deadline = started + args.time_budget if args.time_budget else float("inf")

    async def enrich_with_ext(
        ip: str, port: str, cc: str,
        method: str, latency: float, speed: float | None,
    ) -> None:
        """Call external APIs for an alive proxy and merge geo metadata."""
        nonlocal ext_ok, ext_response_ms_sum, ext_response_ms_count
        async with ext_sem:
            ext_results = await check_all_ext_apis(ip, port, args.ext_timeout)
        verdict = merge_ext_verdict(ext_results)
        merged = verdict.get("merged") or {}
        ext_data = {
            "sources": verdict["basis"],
            "alive": verdict["alive"],
            "response_ms": merged.get("response_ms"),
            "colo": merged.get("colo"),
            "ipv4_ok": merged.get("ipv4_ok", False),
            "ipv6_ok": merged.get("ipv6_ok", False),
            "dual_stack": merged.get("dual_stack", False),
            "inferred_stack": merged.get("inferred_stack"),
            "exit_geo": merged.get("exit_geo"),
        }
        async with lock:
            key = f"{ip}:{port}#{cc}"
            if key in results:
                old = results[key]
                results[key] = (old[0], old[1], old[2], old[3], old[4], old[5], ext_data)
            ext_ok += 1
            if merged.get("response_ms") is not None:
                ext_response_ms_sum += merged["response_ms"]
                ext_response_ms_count += 1

    async def recheck_with_ext(
        ip: str, port: str, cc: str,
    ) -> None:
        """Use external APIs as secondary check for TLS-failed proxies."""
        nonlocal ext_ok, ext_uncertain, ext_dead
        nonlocal ext_response_ms_sum, ext_response_ms_count
        async with ext_sem:
            ext_results = await check_all_ext_apis(ip, port, args.ext_timeout)
        verdict = merge_ext_verdict(ext_results)
        merged = verdict.get("merged") or {}
        ext_data = {
            "sources": verdict["basis"],
            "alive": verdict["alive"],
            "response_ms": merged.get("response_ms"),
            "colo": merged.get("colo"),
            "ipv4_ok": merged.get("ipv4_ok", False),
            "ipv6_ok": merged.get("ipv6_ok", False),
            "dual_stack": merged.get("dual_stack", False),
            "inferred_stack": merged.get("inferred_stack"),
            "exit_geo": merged.get("exit_geo"),
        }
        async with lock:
            if verdict["alive"] is True:
                latency = merged.get("response_ms") or 0.0
                results[f"{ip}:{port}#{cc}"] = (
                    ip, port, cc, "ext", latency, None, ext_data,
                )
                by_method["ext"] = by_method.get("ext", 0) + 1
                ext_ok += 1
                if merged.get("response_ms") is not None:
                    ext_response_ms_sum += merged["response_ms"]
                    ext_response_ms_count += 1
            elif verdict["alive"] == "uncertain":
                ext_uncertain += 1
            else:
                ext_dead += 1

    async def worker(ip: str, port: str, cc: str, is_retry: bool) -> None:
        nonlocal checked
        try:
            status, method, latency, speed, _ext = await check_proxy(ip, port, args, speed_sem)
        except Exception as exc:
            logging.debug("check_proxy %s:%s: %s", ip, port, exc)
            status, method, latency, speed = "dead", None, None, None
        async with lock:
            checked += 1
            if status == "ok":
                results[f"{ip}:{port}#{cc}"] = (
                    ip, port, cc, method, latency, speed, None,
                )
                by_method[method] = by_method.get(method, 0) + 1
                if args.ext_check:
                    ext_pending.append((ip, port, cc, method, latency, speed))
            elif status == "retry" and not is_retry:
                retry_pool.append((ip, port, cc))

    async def run_pass(pool: list[tuple[str, str, str]], is_retry: bool) -> None:
        if not pool:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        tasks: set[asyncio.Task] = set()
        idx = 0
        n = len(pool)

        def submit() -> None:
            nonlocal idx
            while len(tasks) < args.workers and idx < n:
                ip, port, cc = pool[idx]
                idx += 1
                t = asyncio.create_task(worker(ip, port, cc, is_retry))
                tasks.add(t)
                t.add_done_callback(tasks.discard)

        submit()
        try:
            while tasks:
                wait_s = min(0.05, max(0.0, deadline - time.monotonic()))
                await asyncio.wait(tasks, timeout=wait_s)
                if time.monotonic() >= deadline:
                    break
                submit()
        except KeyboardInterrupt:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    await run_pass(entries, False)

    # External API enrichment for alive proxies + recheck for failed ones
    if args.ext_check and ext_sem is not None:
        ext_tasks: list[asyncio.Task] = []
        for ip, port, cc, method, latency, speed in ext_pending:
            ext_tasks.append(
                asyncio.create_task(enrich_with_ext(ip, port, cc, method, latency, speed))
            )
        recheck_pool = [
            (ip, port, cc) for ip, port, cc in retry_pool
            if f"{ip}:{port}#{cc}" not in results
        ]
        for ip, port, cc in recheck_pool:
            ext_tasks.append(asyncio.create_task(recheck_with_ext(ip, port, cc)))
        if ext_tasks:
            done, pending = await asyncio.wait(ext_tasks, timeout=args.ext_timeout + 5)
            for t in pending:
                t.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
    elif retry_pool and time.monotonic() < deadline:
        print(f"Retrying {len(retry_pool)} TLS-but-unverified proxies ...")
        await asyncio.sleep(RETRY_DELAY)
        await run_pass(retry_pool, True)

    elapsed = time.monotonic() - started
    ext_stats = {
        "ext_check_total": ext_ok + ext_uncertain + ext_dead,
        "ext_check_ok": ext_ok,
        "ext_check_uncertain": ext_uncertain,
        "ext_check_dead": ext_dead,
        "ext_avg_response_ms": (
            round(ext_response_ms_sum / ext_response_ms_count, 1)
            if ext_response_ms_count else 0
        ),
    }
    return results, by_method, checked, elapsed, ext_stats


async def run(args: argparse.Namespace) -> int:
    if not args.source.exists():
        print(f"Error: {args.source} not found", file=sys.stderr)
        return 1

    entries = parse_entries(args.source.read_text(encoding="utf-8").splitlines())
    if args.limit > 0:
        entries = entries[: args.limit]
    total = len(entries)

    # 上一轮存活集合须在 write_index 覆盖 index.json 之前读取
    prev_keys = load_prev_alive_keys()
    prev_ipports = (
        {k.split("#", 1)[0] for k in prev_keys if "#" in k} if prev_keys else set()
    )
    prefiltered = 0
    if args.quick_prefilter:
        entries, prefiltered = await quick_prefilter_stale(
            entries, prev_ipports, args
        )
        if prefiltered:
            print(
                f"Quick prefilter: skipped {prefiltered} stale-dead entries "
                f"(TCP probe failed)"
            )
    checked_input = len(entries)
    print(f"Checking {checked_input} proxies (+{prefiltered} prefiltered, "
          f"timeout={args.timeout}s, workers={args.workers}) ...")

    results, by_method, checked, elapsed, ext_stats = await check_entries(entries, args)

    dead = (checked - len(results)) + prefiltered
    latencies = [lat for _, _, _, _, lat, _, _ in results.values()]
    speeds = [sp for _, _, _, _, _, sp, _ in results.values() if sp is not None]
    print(
        f"Checked {checked}/{total} in {elapsed:.1f}s: alive={len(results)}, dead={dead}"
        f" ({dict(by_method)})"
    )

    if ext_stats["ext_check_total"] > 0:
        print(
            f"Ext API: total={ext_stats['ext_check_total']}, "
            f"ok={ext_stats['ext_check_ok']}, "
            f"uncertain={ext_stats['ext_check_uncertain']}, "
            f"dead={ext_stats['ext_check_dead']}"
        )

    stats = write_valid_outputs(results, args.per_country_limit, prev_keys=prev_keys)

    if args.ext_check:
        write_ext_check(results)

    lat_stats = {}
    if latencies:
        latencies_sorted = sorted(latencies)
        idx = min(int(len(latencies_sorted) * 0.9), len(latencies_sorted) - 1)
        lat_stats = {
            "avg_ms": round(statistics.mean(latencies), 1),
            "median_ms": round(statistics.median(latencies), 1),
            "p90_ms": round(latencies_sorted[idx], 1),
            "max_ms": latencies_sorted[-1],
        }

    speed_stats = {}
    if speeds:
        speeds_sorted = sorted(speeds)
        idx = min(int(len(speeds_sorted) * 0.9), len(speeds_sorted) - 1)
        speed_stats = {
            "avg_mbps": round(statistics.mean(speeds), 2),
            "median_mbps": round(statistics.median(speeds), 2),
            "p90_mbps": round(speeds_sorted[idx], 2),
            "max_mbps": speeds_sorted[-1],
        }

    per_country: dict[str, int] = {}
    per_port: dict[str, int] = {}
    for _, (_, port, cc, _, _, _, _) in results.items():
        per_country[cc] = per_country.get(cc, 0) + 1
        per_port[port] = per_port.get(port, 0) + 1

    meta = {
        "ts": now_ts(),
        "total": total,
        "checked": checked,
        "prefiltered": prefiltered,
        "alive": len(results),
        "dead": dead,
        "elapsed_s": round(elapsed, 1),
        "checked_per_s": round(checked / elapsed, 1) if elapsed else 0,
        "by_method": dict(sorted(by_method.items())),
        "latency": lat_stats,
        "latency_dist": bucket_latency(latencies),
        "speed": speed_stats,
        "speed_dist": bucket_speed(speeds),
        "per_country": dict(sorted(per_country.items())),
        "per_port": {p: per_port[p] for p in sorted(per_port, key=int)},
        "sets": stats["__sets__"],
    }
    if ext_stats["ext_check_total"] > 0:
        meta["ext_check"] = ext_stats
    meta_file = VALID_DIR / "meta.json"
    write_text_if_changed(
        meta_file, json.dumps(meta, ensure_ascii=False, indent=2) + "\n"
    )
    print(f"Wrote {meta_file}")

    append_history(meta)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ALL_FILE, help="Input proxy list")
    parser.add_argument("--sni", default=TARGET_SNI, help="TLS SNI used for the handshake check")
    parser.add_argument("--speed-host", default=SPEED_HOST, help="Host used for the speed download")
    parser.add_argument("--speed-path", default=SPEED_PATH, help="Path to download for the speed test")
    parser.add_argument("--speed-bytes", type=int, default=SPEED_READ_BYTES, help="Max bytes to read during a speed test")
    parser.add_argument("--speed-timeout", type=int, default=SPEED_TIMEOUT, help="Max seconds per speed test")
    parser.add_argument("--speed-workers", type=int, default=SPEED_WORKERS, help="Max concurrent speed downloads")
    parser.add_argument("--speed-warmup-bytes", type=int, default=SPEED_WARMUP_BYTES, help="Bytes discarded before the steady-state speed window (0 = time from first byte)")
    parser.add_argument("--no-speed", action="store_true", help="Skip speed measurement")
    parser.add_argument("--adaptive-speed", action="store_true", default=True, help="Adapt download window to RTT (default: on)")
    parser.add_argument("--no-adaptive-speed", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--quick-prefilter", action="store_true", default=True,
        help="Pre-probe entries not alive last run with a fast TCP connect "
        "before the full TLS check; unreachable ports are skipped without "
        "wasting the TLS timeout (default: on)",
    )
    parser.add_argument("--no-quick-prefilter", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--quick-timeout", type=float, default=QUICK_TIMEOUT,
        help="TCP connect timeout for the quick prefilter (seconds)",
    )
    parser.add_argument("-t", "--timeout", type=int, default=TIMEOUT, help="Per-proxy timeout (seconds)")
    parser.add_argument("-w", "--workers", type=int, default=WORKERS, help="Max concurrent checks")
    parser.add_argument("--limit", type=int, default=0, help="Max proxies to check (0 = all)")
    parser.add_argument("--time-budget", type=int, default=0, help="Stop after this many seconds (0 = unlimited)")
    parser.add_argument("--per-country-limit", type=int, default=PER_COUNTRY_LIMIT, help="Limit for _ltd outputs")
    parser.add_argument("--ext-check", action="store_true", help="Enable external API multi-source validation")
    parser.add_argument("--no-ext-check", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--ext-timeout", type=int, default=EXT_TIMEOUT, help="Per-source timeout for external API (seconds)")
    parser.add_argument("--ext-workers", type=int, default=EXT_WORKERS, help="Max concurrent external API calls")
    args = parser.parse_args(argv)
    if args.no_ext_check:
        args.ext_check = False
    if args.no_adaptive_speed:
        args.adaptive_speed = False
    if args.no_quick_prefilter:
        args.quick_prefilter = False
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130


def append_history(meta: dict) -> None:
    lines: list[str] = []
    if VALID_HISTORY_FILE.exists():
        lines = VALID_HISTORY_FILE.read_text(encoding="utf-8").splitlines()
    record = {k: meta[k] for k in ("ts", "total", "checked", "alive", "dead")}
    lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    lines = lines[-MAX_HISTORY_RECORDS:]
    tmp = VALID_HISTORY_FILE.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(VALID_HISTORY_FILE)


if __name__ == "__main__":
    sys.exit(main())
