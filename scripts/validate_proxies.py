#!/usr/bin/env python3
"""Validate proxy reachability and measure latency.

Reads ``data/download/all.txt`` (``ip:port#country`` lines) and checks each proxy.
A TLS handshake to the proxy itself (works for Cloudflare edge proxies,
which serve TLS on 443/8443/2053/2083/2087/2096) is performed.

Checks run concurrently with asyncio (default 500 in-flight, kept bounded by
an in-flight task pool). Each alive proxy also gets a download speed test on
a freshly-opened TLS connection, gated by a semaphore so
bandwidth stays low-contention. Outputs are written under ``data/valid/``
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
``*_ltd.txt`` speed-limited variant per group. Family comes from
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
from datetime import datetime, timezone
from pathlib import Path

from common import (
    ALL_FILE,
    CHINA_FILE,
    INDEX_FILE,
    MAX_HISTORY_RECORDS,
    PER_COUNTRY_LIMIT,
    SPEED_FILE,
    VALID_DIR,
    VALID_HISTORY_FILE,
    has_token,
    now_ts,
    parse_line,
    write_text_if_changed,
)
from download_proxies import COUNTRY_SETS, SMALL_SETS

SPEED_HOST = "cdnjs.cloudflare.com"
TARGET_SNI = SPEED_HOST
SPEED_PATH = "/ajax/libs/three.js/r128/three.js"
SPEED_READ_BYTES = 1048576
SPEED_TIMEOUT = 5
SPEED_MIN_BYTES = 16384
SPEED_WORKERS = 30
TIMEOUT = 5
READ_CAP = 3
WORKERS = 500
RETRY_DELAY = 0.2

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
    """把旧行备注里的静态 token 接回重生成的基础行。

    ``old_note`` 形如 ``→LAX-120ms-0.44MB/s-NF(US) D+ YT GPT-DC-72-V4-CN``：
    延迟与测速会被本次重新计算，故剥离；可选的出口区域（``→XXX``）插回
    延迟横线之前，其余静态 token 追加到行尾。存活 key 跨 update 周期保留
    注解，使 quality/china/exit 标注不再被基础重生成抹平。
    """
    match = re.match(r"^(→[A-Z0-9]+)?", old_note)
    region = match.group(1) or ""
    rest = old_note[len(region):]
    rest = re.sub(r"^-[0-9]+(?:\.[0-9]+)?ms", "", rest)
    rest = re.sub(r"^-[0-9]+(?:\.[0-9]+)?MB/s", "", rest)
    if not region and not rest:
        return base_line
    head, sep, tail = base_line.partition("-")
    if not sep:
        return base_line + rest
    return head + region + sep + tail + rest


GROUP_NAMES = ("v4", "v6", "46", "cn", "cn4", "cn6", "cn46")
ROOT_GROUP_FILES = ("all_46", "all_cn4", "all_cn6", "all_cn46")


def load_family_map(path: Path | None = None) -> dict:
    """``exit_family.json`` → ``{key: family}``；缺失/损坏 → ``{}``。

    ``key`` 为 ``ip:port#cc``，``family`` 取 ``ipv4``/``ipv6``/``dual``。
    """
    path = path or VALID_DIR / "exit_family.json"
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
) -> tuple[str, str | None, float | None, float | None]:
    """Return ``(status, method, latency_ms, speed_mbps)``.

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
            return await speed_probe(ip, port, args, method)

    tls_started = time.monotonic()
    try:
        reader, writer = await open_conn(ip, port, args.timeout, ctx=_TLS_CTX, sni=args.sni)
    except ssl.SSLError:
        return "retry", None, None, None
    except (OSError, asyncio.TimeoutError, ValueError):
        return "dead", None, None, None
    tls_latency = elapsed(tls_started)
    try:
        speed = await measure_speed("tls")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass
    return "ok", "tls", tls_latency, speed


async def speed_probe(
    ip: str,
    port: str,
    args: argparse.Namespace,
    method: str,
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
        return await speed_download(
            reader, writer, args.speed_host, args.speed_path,
            args.speed_bytes, args.speed_timeout,
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
) -> float | None:
    """Download ``cap_bytes`` (or up to ``cap_sec``) of ``path`` and return MB/s."""
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
    start = time.monotonic()
    buf = b""
    while len(buf) < cap_bytes:
        remain = cap_sec - (time.monotonic() - start)
        if remain <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(65536), min(READ_CAP, remain))
        except (asyncio.TimeoutError, ConnectionError, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return compute_speed(len(buf), time.monotonic() - start)


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


def write_valid_outputs(
    alive: dict[str, tuple[str, str, str, str, float, float | None]],
    per_country_limit: int,
    families: dict | None = None,
    cn_reachable: set[str] | None = None,
) -> dict:
    VALID_DIR.mkdir(parents=True, exist_ok=True)
    if families is None:
        families = load_family_map()
    if cn_reachable is None:
        cn_reachable = load_cn_reachable()

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
        ip, port, cc, _m, latency, speed = alive[entry]
        base = fmt_entry(ip, port, cc, latency, speed)
        old = old_notes.get(entry)
        text = merge_old_note(base, old) if old else base
        line_cache[entry] = text
        return text

    def ltd_key(entry: str) -> tuple:
        speed = alive[entry][5]
        if speed is not None:
            return (0, -speed, 0.0)
        return (1, 0.0, alive[entry][4])

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

    def write_group_files(
        directory: Path, grouped: dict[str, list[str]], ltd: dict[str, list[str]] | None = None
    ) -> None:
        """写全量分组文件；``ltd`` 提供时写 ``*_ltd`` 分组，否则清理残留。"""
        for g in GROUP_NAMES:
            path = directory / f"{g}.txt"
            if grouped[g]:
                write_text_if_changed(
                    path, "\n".join(line(e) for e in grouped[g]) + "\n"
                )
            elif path.exists():
                path.unlink()
            ltd_path = directory / f"{g}_ltd.txt"
            entries = (ltd or {}).get(g, [])
            if entries:
                write_text_if_changed(
                    ltd_path, "\n".join(line(e) for e in entries) + "\n"
                )
            elif ltd_path.exists():
                ltd_path.unlink()

    by_country: dict[str, list[str]] = defaultdict(list)
    by_port: dict[str, list[str]] = defaultdict(list)
    for entry in ordered:
        _ip, port, country, _m, _lat, _sp = alive[entry]
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
    if per_country_limit > 0:
        ltd_all = sorted(
            [e for cc in country_ltd for e in country_ltd[cc]], key=ltd_key
        )
        write_text_if_changed(
            VALID_DIR / "all_ltd.txt", "\n".join(line(e) for e in ltd_all) + "\n"
        )
        set_counts["all_ltd"] = len(ltd_all)
    root_grouped = group_map(ordered)
    for name in ROOT_GROUP_FILES:
        g = name[len("all_"):]
        path = VALID_DIR / f"{name}.txt"
        if root_grouped[g]:
            write_text_if_changed(
                path, "\n".join(line(e) for e in root_grouped[g]) + "\n"
            )
        elif path.exists():
            path.unlink()
        ltd_path = VALID_DIR / f"{name}_ltd.txt"
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
        if ltd:
            write_text_if_changed(
                ltd_path, "\n".join(line(e) for e in ltd) + "\n"
            )
        elif ltd_path.exists():
            ltd_path.unlink()
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
    results: dict[str, tuple[str, str, str, str, float, float | None]] = {}
    by_method: dict[str, int] = {}
    retry_pool: list[tuple[str, str, str]] = []
    lock = asyncio.Lock()
    speed_sem = asyncio.Semaphore(args.speed_workers)
    checked = 0
    started = time.monotonic()
    deadline = started + args.time_budget if args.time_budget else float("inf")

    async def worker(ip: str, port: str, cc: str, is_retry: bool) -> None:
        nonlocal checked
        try:
            status, method, latency, speed = await check_proxy(ip, port, args, speed_sem)
        except Exception as exc:
            logging.debug("check_proxy %s:%s: %s", ip, port, exc)
            status, method, latency, speed = "dead", None, None, None
        async with lock:
            checked += 1
            if status == "ok":
                results[f"{ip}:{port}#{cc}"] = (ip, port, cc, method, latency, speed)
                by_method[method] = by_method.get(method, 0) + 1
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
    if retry_pool and time.monotonic() < deadline:
        print(f"Retrying {len(retry_pool)} TLS-but-unverified proxies ...")
        await asyncio.sleep(RETRY_DELAY)
        await run_pass(retry_pool, True)

    elapsed = time.monotonic() - started
    return results, by_method, checked, elapsed


async def run(args: argparse.Namespace) -> int:
    if not args.source.exists():
        print(f"Error: {args.source} not found", file=sys.stderr)
        return 1

    entries = parse_entries(args.source.read_text(encoding="utf-8").splitlines())
    if args.limit > 0:
        entries = entries[: args.limit]
    total = len(entries)
    print(f"Checking {total} proxies (timeout={args.timeout}s, workers={args.workers}) ...")

    results, by_method, checked, elapsed = await check_entries(entries, args)

    dead = checked - len(results)
    latencies = [lat for _, _, _, _, lat, _ in results.values()]
    speeds = [sp for _, _, _, _, _, sp in results.values() if sp is not None]
    print(
        f"Checked {checked}/{total} in {elapsed:.1f}s: alive={len(results)}, dead={dead}"
        f" ({dict(by_method)})"
    )

    stats = write_valid_outputs(results, args.per_country_limit)

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
    for _, (_, port, cc, _, _, _) in results.items():
        per_country[cc] = per_country.get(cc, 0) + 1
        per_port[port] = per_port.get(port, 0) + 1

    meta = {
        "ts": now_ts(),
        "total": total,
        "checked": checked,
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
    parser.add_argument("--no-speed", action="store_true", help="Skip speed measurement")
    parser.add_argument("-t", "--timeout", type=int, default=TIMEOUT, help="Per-proxy timeout (seconds)")
    parser.add_argument("-w", "--workers", type=int, default=WORKERS, help="Max concurrent checks")
    parser.add_argument("--limit", type=int, default=0, help="Max proxies to check (0 = all)")
    parser.add_argument("--time-budget", type=int, default=0, help="Stop after this many seconds (0 = unlimited)")
    parser.add_argument("--per-country-limit", type=int, default=PER_COUNTRY_LIMIT, help="Limit for _ltd outputs")
    args = parser.parse_args(argv)
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130


def append_history(meta: dict) -> None:
    lines: list[str] = []
    if VALID_HISTORY_FILE.exists():
        lines = VALID_HISTORY_FILE.read_text(encoding="utf-8").splitlines()
    if lines:
        try:
            last = json.loads(lines[-1])
            last.pop("ts", None)
            current = {
                k: v
                for k, v in meta.items()
                if k in ("total", "checked", "alive", "dead")
            }
            if last == current:
                return
        except (json.JSONDecodeError, KeyError):
            pass
    record = {k: meta[k] for k in ("ts", "total", "checked", "alive", "dead")}
    lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    lines = lines[-MAX_HISTORY_RECORDS:]
    tmp = VALID_HISTORY_FILE.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(VALID_HISTORY_FILE)


if __name__ == "__main__":
    sys.exit(main())
