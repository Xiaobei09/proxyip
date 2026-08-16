#!/usr/bin/env python3
"""Streaming unlock and exit-IP quality checks for alive proxies.

Runs on a bounded population (default ``data/valid/all_ltd.txt``, the
per-country fastest survivors) and writes under ``data/valid/``:

- ``ipinfo.json``      exit IP / address family / dual-stack / geo / IP type /
                      reputation score + source (per checked proxy)
- ``streaming.json``   per-service unlock results (incl. native Netflix)
- ``abuse.json``       optional abuse-score results (key-gated)
- ``reputation.json``  0-100 reputation scores (multi-source weighted merge:
                      net.coffee / ip.nc.gy / ip-api / ipdata / Tor exit lists,
                      optionally GetIPIntel + ipapi.is), keyed by ``ip:port#CC``
- ``all_rep.txt``      ``all_ltd.txt`` lines re-sorted by reputation desc
- ``countries/<cc>/rep.txt``, ``sets/<name>/rep.txt``
                      per-country / per-set ``all.txt`` re-sorted by reputation
- ``quality_meta.json`` aggregated summary for stats and charts
- annotated ``*.txt``  all/countries/ports/sets lines get ``#``-suffix segments
                      (``countries/*/all.txt`` and ``*/ltd.txt``; ``rep.txt`` is
                      written pre-annotated by ``write_reputation_files``)

Two proxy flavors are handled, selected by the method recorded in
``data/valid/index.json``:

1. ``connect`` (standard HTTP CONNECT proxies): full suite - plain-HTTP exit
   IP echo (IPv4 + IPv6 for dual-stack), geo/IP type via ip-api batch, and
   per-service streaming unlocks over a CONNECT + TLS tunnel.
2. ``tls`` (Cloudflare edge proxies): only Cloudflare-fronted hosts are
   reachable via SNI routing, so only ChatGPT/OpenAI
   (``chat.openai.com/cdn-cgi/trace``) is probed; the exit is the edge itself
   and is tagged ``CF``.

Annotation format appends to the existing ``ip:port#<flag><cc>-<lat>-<speed>``
lines as ``-<streaming>-<type>-<rep>``, e.g.
``1.2.3.4:443#US-120ms-0.44MB/s-NF(US) D+ YT GPT-DC-72`` (streaming tokens
space-separated, IP-type tokens after a second dash, then the 0-100 reputation
score). When the exit region is known it is inserted right after the entry
country code as ``<cc>→<exit>`` (CF edge ``loc`` airport code for ``tls``
proxies, exit-IP country otherwise), e.g. ``1.2.3.4:443#US→LAX-120ms-...``.
Lines without results stay untouched.
"""

import argparse
import asyncio
import ipaddress
import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from bisect import bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from download_proxies import OUT_DIR
from validate_proxies import try_connect

VALID_DIR = OUT_DIR / "valid"
INDEX_FILE = VALID_DIR / "index.json"
IPINFO_FILE = VALID_DIR / "ipinfo.json"
STREAMING_FILE = VALID_DIR / "streaming.json"
ABUSE_FILE = VALID_DIR / "abuse.json"
QUALITY_META_FILE = VALID_DIR / "quality_meta.json"
REPUTATION_FILE = VALID_DIR / "reputation.json"
REP_RANK_FILE = VALID_DIR / "all_rep.txt"
DEFAULT_SOURCE = VALID_DIR / "all_ltd.txt"

REP_RISK_HIGH = 30
REP_RISK_MEDIUM = 75

REP_WORKERS = 10
REP_DELAY = 0.15

NETCOFFEE_URL = "https://ip.net.coffee/api/iprisk/{ip}"
NETCOFFEE_TIMEOUT = 8

NCGY_URL = "https://ip.nc.gy/json?ip={ip}"
NCGY_TIMEOUT = 8

IPDATA_URL = "https://ipdata.info/json/{ip}"
IPDATA_TIMEOUT = 8
IPDATA_CAP = 50

GETIPINTEL_URL = (
    "https://check.getipintel.net/check.php?ip={ip}"
    "&contact={email}&flags=m"
)
GETIPINTEL_TIMEOUT = 8
GETIPINTEL_CAP = 300

IPAPI_IS_URL = "https://api.ipapi.is/?q={ip}"
IPAPI_IS_TIMEOUT = 8

IPQUERY_URL = "https://api.ipquery.io/{ip}"
IPQUERY_TIMEOUT = 8

FFRAUD_URL = "https://api.ffraud.com/public/ip/{ip}"
FFRAUD_TIMEOUT = 8

WHATISMYIP_URL = "https://whatismyip.ai/api/lookup/{ip}"
WHATISMYIP_TIMEOUT = 8

# 静态列表（torlist 同款：每 run 拉一次、fail-open、失败即跳过）
FIREHOL_ABUSERS_URL = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/"
    "master/firehol_abusers_1d.netset"
)
DC_ASN_URL = "https://iplogs.com/data/datacenter-asns.csv"
VPN_ASN_URL = "https://iplogs.com/data/vpn-providers.csv"
RESPROXY_ASN_URL = "https://iplogs.com/data/residential-proxy-backbones.csv"
STATIC_LIST_TIMEOUT = 15

ABUSER_SCORE_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)")
ABUSER_SCORE_THRESHOLD = 0.1

TORLIST_URLS = (
    "https://check.torproject.org/exit-addresses",
    "https://www.dan.me.uk/torlist/",
)

IPAPI_PROXY_PENALTY = 25
IPAPI_HOSTING_PENALTY = 10

NETCOFFEE_FLAG_PENALTIES = {
    "is_abuser": 40,
    "is_tor": 35,
    "is_proxy": 30,
    "is_vpn": 25,
    "is_datacenter": 15,
}

NCGY_FLAG_PENALTIES = {
    "is_tor": 45,
    "is_proxy": 30,
    "is_vpn": 25,
    "is_anonymous": 10,
}

IPDATA_FLAG_PENALTIES = {
    "tor": 45,
    "proxy": 30,
    "vpn": 25,
    "anonymous": 10,
}

IPAPI_IS_FLAG_PENALTIES = {
    "is_tor": 45,
    "is_vpn": 30,
    "is_proxy": 25,
    "is_datacenter": 15,
    "is_abuser": 20,
}

IPQUERY_FLAG_PENALTIES = {
    "is_tor": 45,
    "is_vpn": 30,
    "is_proxy": 25,
    "is_datacenter": 15,
}

FFRAUD_FLAG_PENALTIES = {
    "is_tor": 45,
    "is_vpn": 30,
    "is_proxy": 25,
    "is_hosting": 15,
    "is_abuser": 20,
    "recent_abuse": 15,
}

WHATISMYIP_FLAG_PENALTIES = {
    "is_tor": 45,
    "is_vpn": 30,
    "is_proxy": 25,
    "is_hosting": 15,
    "is_blacklisted": 30,
}

# 静态列表源命中即返回固定干净分（100 - 罚分）
STATIC_LIST_SCORES = {
    "abuse_list": 60,   # is_abuse（历史滥用，强信号）
    "dc_asn": 85,       # is_hosting（机房/数据中心）
    "vpn_asn": 70,      # is_vpn
    "resproxy_asn": 75, # is_proxy（住宅代理骨干）
}

REPUTATION_WEIGHTS = {
    "netcoffee": 30,
    "ncgy": 20,
    "ip-api": 15,
    "ipquery": 10,
    "ffraud": 10,
    "ipapi_is": 8,
    "ipdata": 8,
    "whatismyip": 5,
    "dc_asn": 5,
    "abuse_list": 5,
    "torlist": 5,
    "getipintel": 5,
    "vpn_asn": 3,
    "resproxy_asn": 2,
}

DEFAULT_REP_SOURCES = (
    "netcoffee", "ncgy", "ip-api", "ipquery", "ffraud",
    "ipapi_is", "ipdata", "whatismyip", "dc_asn",
    "abuse_list", "torlist", "vpn_asn", "resproxy_asn",
)

# 按源控速 (workers, delay)，避免免 key 接口限流掉单
SOURCE_PACING = {
    "netcoffee": (6, 0.25),
    "ncgy": (6, 0.25),
    "ipapi_is": (6, 0.25),
    "ipquery": (4, 0.25),
    "ffraud": (4, 0.25),
    "whatismyip": (4, 0.25),
}

ECHO_V4_HOST = "api.ipify.org"
ECHO_V6_HOST = "api6.ipify.org"
ECHO_PATH = "/"
ECHO_PORT = 80

IPAPI_BATCH_URL = "http://ip-api.com/batch"
IPAPI_GET_URL = "http://ip-api.com/json/{ip}"
IPAPI_FIELDS = (
    "status,message,country,countryCode,regionName,city,"
    "as,asn,org,isp,proxy,hosting,mobile"
)
BATCH_SIZE = 100

TIMEOUT = 6
READ_CAP = 524288
READ_TIMEOUT = 3
HEADER_CAP = 65536
WORKERS = 40
BATCH_DELAY = 1.2

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
)

_SSL_CTX = ssl.create_default_context()

SERVICES = {
    "netflix": {"host": "www.netflix.com", "path": "/title/80018499"},
    "disney": {"host": "www.disneyplus.com", "path": "/"},
    "youtube": {"host": "www.youtube.com", "path": "/premium"},
    "max": {"host": "www.max.com", "path": "/"},
    "prime": {"host": "www.primevideo.com", "path": "/"},
    "openai": {"host": "chat.openai.com", "path": "/cdn-cgi/trace"},
}

SERVICE_ORDER = tuple(SERVICES)


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ltd_line(line: str):
    """``ip:port#<flag><cc>-...`` -> ``(key, ip, port, cc)`` or ``None``.

    The pseudo-country ``ALL`` (unknown entry country, 3 letters) is kept
    intact instead of collapsing to ``AL`` so it never collides with Albania.
    """
    line = line.strip()
    if not line or "#" not in line:
        return None
    addr, rest = line.rsplit("#", 1)
    i = 0
    while i < len(rest) and not ("A" <= rest[i] <= "Z"):
        i += 1
    if rest[i:].startswith("ALL") and (rest[i + 3:i + 4] in ("", "-")):
        cc = "ALL"
    else:
        cc = rest[i : i + 2]
    if (len(cc) != 2 and cc != "ALL") or not cc.isalpha() or ":" not in addr:
        return None
    ip, port = addr.rsplit(":", 1)
    if not port.isdigit():
        return None
    return f"{addr}#{cc}", ip, port, cc


def line_to_key(line: str) -> str | None:
    parsed = parse_ltd_line(line)
    return parsed[0] if parsed else None


def load_methods() -> dict:
    """``entry`` -> ``"connect"``/``"tls"`` from ``index.json``."""
    if not INDEX_FILE.exists():
        return {}
    try:
        data = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return {k: v[1] for k, v in data.get("proxies", {}).items()}


def build_request(method: str, path: str, host: str) -> bytes:
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {UA}",
        "Accept: */*",
        "Accept-Language: en-US,en;q=0.9",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii", errors="replace")


def parse_headers(raw: bytes) -> tuple[int | None, dict]:
    """``(status_code, headers)`` from a raw HTTP header block."""
    lines = raw.split(b"\r\n")
    match = re.match(rb"HTTP/\d\.\d\s+(\d{3})", lines[0]) if lines else None
    status = int(match.group(1)) if match else None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.decode("latin-1").strip().lower()] = value.decode(
            "latin-1"
        ).strip()
    return status, headers


async def read_until(
    reader: asyncio.StreamReader, delim: bytes, cap: int
) -> bytes:
    data = b""
    while delim not in data and len(data) < cap:
        chunk = await asyncio.wait_for(reader.read(65536), timeout=READ_TIMEOUT)
        if not chunk:
            break
        data += chunk
    return data


async def read_chunked(
    reader: asyncio.StreamReader, cap: int, body: bytes
) -> bytes:
    while len(body) < cap:
        head = await read_until(reader, b"\r\n", 64)
        size = int(head.split(b";", 1)[0].strip() or b"0", 16)
        if size == 0:
            await read_until(reader, b"\r\n", 4096)
            break
        remain = size
        while remain > 0 and len(body) < cap:
            chunk = await asyncio.wait_for(
                reader.read(min(remain, 65536)), timeout=READ_TIMEOUT
            )
            if not chunk:
                break
            body += chunk
            remain -= len(chunk)
        await asyncio.wait_for(reader.read(2), timeout=READ_TIMEOUT)
    return body[:cap]


async def read_http_response(
    reader: asyncio.StreamReader, cap: int
) -> tuple[int | None, dict, bytes]:
    raw = await read_until(reader, b"\r\n\r\n", HEADER_CAP)
    if b"\r\n\r\n" not in raw:
        return None, {}, b""
    head, body = raw.split(b"\r\n\r\n", 1)
    status, headers = parse_headers(head)
    if status is None:
        return None, headers, body
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = await read_chunked(reader, cap, body)
    else:
        clen = headers.get("content-length")
        want = min(int(clen), cap - len(body)) if clen else cap - len(body)
        while len(body) < want:
            chunk = await asyncio.wait_for(
                reader.read(65536), timeout=READ_TIMEOUT
            )
            if not chunk:
                break
            body += chunk
    return status, headers, body[:cap]


def parse_netflix(status: int | None, headers: dict, body: bytes) -> dict:
    text = body.decode("utf-8", errors="replace")
    match = re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', text)
    if status == 200 and match:
        return {"status": "ok", "region": match.group(1)}
    if status in (404, 403) or "not available in your region" in text.lower():
        return {"status": "blocked"}
    if match:
        return {"status": "ok", "region": match.group(1)}
    return {"status": "error", "error": f"unparseable response (http {status})"}


def parse_disney(status: int | None, headers: dict, body: bytes) -> dict:
    if status != 200:
        return {"status": "blocked"}
    text = body.decode("utf-8", errors="replace")
    match = (
        re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', text)
        or re.search(r'"country"\s*:\s*"([A-Z]{2})"', text)
        or re.search(r'"region"\s*:\s*"([A-Z]{2})"', text)
    )
    return {"status": "ok", "region": match.group(1) if match else None}


def parse_youtube(status: int | None, headers: dict, body: bytes) -> dict:
    text = body.decode("utf-8", errors="replace")
    match = re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', text)
    if match:
        return {"status": "ok", "region": match.group(1)}
    if status != 200:
        return {"status": "blocked"}
    return {"status": "error", "error": "premium page has no countryCode"}


def parse_max(status: int | None, headers: dict, body: bytes) -> dict:
    location = headers.get("location", "")
    if status not in (200, 301, 302, 307, 308):
        return {"status": "blocked"}
    text = body.decode("utf-8", errors="replace")
    match = (
        re.search(r"country=([A-Z]{2})", location)
        or re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', text)
        or re.search(r'"region"\s*:\s*"([A-Z]{2})"', text)
    )
    return {"status": "ok", "region": match.group(1) if match else None}


def parse_prime(status: int | None, headers: dict, body: bytes) -> dict:
    location = headers.get("location", "")
    text = body.decode("utf-8", errors="replace")
    match = (
        re.search(r"country=([A-Z]{2})", location)
        or re.search(r'"currentTerritory"\s*:\s*"([A-Z]{2})"', text)
        or re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', text)
    )
    if match:
        return {"status": "ok", "region": match.group(1)}
    if status == 200:
        return {"status": "ok", "region": None}
    return {"status": "blocked"}


def parse_openai(status: int | None, headers: dict, body: bytes) -> dict:
    if status == 200:
        match = re.search(r"^loc=([A-Z]{2,4})", body.decode("latin-1"), re.M)
        return {"status": "ok", "region": match.group(1) if match else None}
    if status == 403:
        return {"status": "blocked"}
    return {"status": "error", "error": f"http {status}"}


PARSERS = {
    "netflix": parse_netflix,
    "disney": parse_disney,
    "youtube": parse_youtube,
    "max": parse_max,
    "prime": parse_prime,
    "openai": parse_openai,
}


async def http_get_via_tunnel(
    ip: str, port: str, host: str, path: str, target_port: int, timeout: int
) -> str | None:
    """Plain-HTTP GET through a CONNECT tunnel; returns the response body text."""
    try:
        reader, writer = await asyncio.open_connection(ip, int(port))
    except (OSError, asyncio.TimeoutError, ValueError):
        return None
    try:
        if not await try_connect(reader, writer, host, target_port):
            return None
        writer.write(build_request("GET", path, host))
        await writer.drain()
        status, _headers, body = await read_http_response(reader, 8192)
        if status != 200:
            return None
        return body.decode("utf-8", errors="replace").strip()
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ConnectionError):
        return None
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def https_get_via_tunnel(
    ip: str,
    port: str,
    host: str,
    path: str,
    timeout: int,
    read_cap: int,
) -> tuple[int | None, dict, bytes, str | None]:
    """CONNECT + TLS (``StreamWriter.start_tls``) + GET to ``host``."""
    try:
        reader, writer = await asyncio.open_connection(ip, int(port))
    except (OSError, asyncio.TimeoutError, ValueError) as exc:
        return None, {}, b"", f"connect: {exc}"
    try:
        if not await try_connect(reader, writer, host, 443):
            return None, {}, b"", "CONNECT rejected"
        await asyncio.wait_for(
            writer.start_tls(_SSL_CTX, server_hostname=host),
            timeout=timeout,
        )
        writer.write(build_request("GET", path, host))
        await writer.drain()
        status, headers, body = await read_http_response(reader, read_cap)
        return status, headers, body, None
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ConnectionError) as exc:
        return None, {}, b"", str(exc)
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def tls_get_direct(
    ip: str,
    port: str,
    host: str,
    path: str,
    timeout: int,
    read_cap: int,
) -> tuple[int | None, dict, bytes, str | None]:
    """Direct TLS to a Cloudflare-edge proxy with ``host`` as SNI."""
    try:
        reader, writer = await asyncio.open_connection(
            ip, int(port), ssl=_SSL_CTX, server_hostname=host
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError) as exc:
        return None, {}, b"", f"tls: {exc}"
    try:
        writer.write(build_request("GET", path, host))
        await writer.drain()
        status, headers, body = await read_http_response(reader, read_cap)
        return status, headers, body, None
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ConnectionError) as exc:
        return None, {}, b"", str(exc)
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def check_one(entry: tuple, method: str, args: argparse.Namespace) -> dict:
    """Run the checks for a single proxy entry."""
    key, ip, port, cc = entry
    base = {"key": key, "ip": ip, "port": port, "cc": cc, "method": method}
    if method == "tls":
        base["tls"] = True
        status, headers, body, _err = await tls_get_direct(
            ip, port, SERVICES["openai"]["host"], SERVICES["openai"]["path"],
            args.timeout, args.read_cap,
        )
        base["streaming"] = {"openai": parse_openai(status, headers, body)}
        return base
    base["v4"] = await http_get_via_tunnel(
        ip, port, ECHO_V4_HOST, ECHO_PATH, ECHO_PORT, args.timeout
    )
    base["v6"] = await http_get_via_tunnel(
        ip, port, ECHO_V6_HOST, ECHO_PATH, ECHO_PORT, args.timeout
    )
    streaming = {}
    for name in args.services:
        svc = SERVICES[name]
        status, headers, body, _err = await https_get_via_tunnel(
            ip, port, svc["host"], svc["path"], args.timeout, args.read_cap
        )
        streaming[name] = PARSERS[name](status, headers, body)
    base["streaming"] = streaming
    return base


async def run_checks(
    entries: list, methods: dict, args: argparse.Namespace
) -> dict:
    sem = asyncio.Semaphore(args.workers)
    lock = asyncio.Lock()
    results: dict = {}

    async def work(entry: tuple) -> None:
        key = entry[0]
        async with sem:
            res = await check_one(entry, methods.get(key, "connect"), args)
        async with lock:
            results[key] = res

    tasks = [asyncio.create_task(work(e)) for e in entries]
    done, pending = await asyncio.wait(tasks, timeout=args.time_budget or None)
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        try:
            task.result()
        except Exception:
            pass
    return results


def group_chunks(items: list, size: int = BATCH_SIZE) -> list[list]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def ipapi_batch_sync(ips: list) -> list:
    payload = json.dumps(ips).encode("utf-8")
    req = urllib.request.Request(
        IPAPI_BATCH_URL + "?fields=" + IPAPI_FIELDS,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "proxyip/quality 1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def ipapi_get_sync(ip: str) -> dict:
    req = urllib.request.Request(
        IPAPI_GET_URL.format(ip=ip) + "?fields=" + IPAPI_FIELDS,
        headers={"User-Agent": "proxyip/quality 1.0"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


async def batch_ipapi(ips: list) -> dict:
    """Batch geo lookup for exit IPs; falls back to rate-limited per-IP GET."""
    out: dict[str, dict] = {}
    any_batch_ok = False
    for chunk in group_chunks(list(dict.fromkeys(ips))):
        try:
            data = await asyncio.to_thread(ipapi_batch_sync, chunk)
            any_batch_ok = True
        except Exception:
            continue
        for item, ip in zip(data, chunk):
            if isinstance(item, dict) and item.get("status") == "success":
                out[ip] = item
        await asyncio.sleep(BATCH_DELAY)
    if any_batch_ok or out:
        return out
    for ip in dict.fromkeys(ips):
        try:
            item = await asyncio.to_thread(ipapi_get_sync, ip)
            if item.get("status") == "success":
                out[ip] = item
        except Exception:
            pass
        await asyncio.sleep(1.5)
    return out


def parse_abuser_score(value) -> float | None:
    """``"0.0039 (Low)"`` → 0.0039；非数值返回 ``None``。"""
    if isinstance(value, (int, float)):
        return float(value)
    m = ABUSER_SCORE_RE.search(str(value))
    return float(m.group(1)) if m else None


ASN_RE = re.compile(r"(?:AS)?(\d+)", re.IGNORECASE)


def norm_asn(value) -> str | None:
    """``"AS15169"`` / ``"15169"`` → ``"AS15169"``；无法解析返回 ``None``。"""
    m = ASN_RE.search(str(value))
    return f"AS{m.group(1)}" if m else None


class IpSet:
    """IP / CIDR 集合，支持精确 IP 与 CIDR 包含判断（stdlib ipaddress + bisect）。"""

    def __init__(self, entries=()):
        self._ips: set = set()
        nets: list = []
        for raw in entries:
            raw = str(raw).strip()
            if not raw or raw.startswith(("#", ";")):
                continue
            if "/" in raw:
                try:
                    nets.append(ipaddress.ip_network(raw, strict=False))
                except ValueError:
                    continue
            else:
                try:
                    self._ips.add(ipaddress.ip_address(raw))
                except ValueError:
                    continue
        nets.sort(key=lambda n: int(n.network_address))
        self._nets = nets
        self._starts = [int(n.network_address) for n in nets]

    def __len__(self) -> int:
        return len(self._ips) + len(self._nets)

    def __contains__(self, ip) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr in self._ips:
            return True
        idx = bisect_right(self._starts, int(addr)) - 1
        for j in range(idx, max(-1, idx - 8), -1):
            if addr in self._nets[j]:
                return True
        return False


def netcoffee_lookup_sync(ip: str) -> dict | None:
    """``GET /api/iprisk/{ip}`` (free, keyless); returns reputation flags."""
    url = NETCOFFEE_URL.format(ip=ip)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=NETCOFFEE_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict):
        return None
    out = {
        "trust_score": data.get("trust_score"),
        "is_datacenter": bool(data.get("is_datacenter")),
        "is_vpn": bool(data.get("is_vpn")),
        "is_proxy": bool(data.get("is_proxy")),
        "is_tor": bool(data.get("is_tor")),
        "is_abuser": bool(data.get("is_abuser")),
        "is_mobile": bool(data.get("is_mobile")),
        "is_crawler": bool(data.get("is_crawler")),
        "isResidential": bool(data.get("isResidential")),
        "company_type": data.get("company_type"),
        "asn_kind": data.get("asn_kind"),
    }
    abuser = parse_abuser_score(data.get("abuser_score"))
    if abuser is not None:
        out["abuser_score"] = abuser
    if out["trust_score"] is None and not any(
        v for k, v in out.items() if k != "trust_score"
    ):
        return None
    return out


async def batch_netcoffee(ips: list) -> dict:
    """Concurrent net.coffee lookups; ``{ip: flags}`` (fails become ``None``)."""
    return await batch_sync(ips, netcoffee_lookup_sync)


def ncgy_lookup_sync(ip: str) -> dict | None:
    """MaxMind GeoIP2 Anonymous IP flags via ``ip.nc.gy/json``."""
    req = urllib.request.Request(
        NCGY_URL.format(ip=ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=NCGY_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    proxy = data.get("proxy") if isinstance(data, dict) else None
    if not isinstance(proxy, dict):
        return None
    out = {
        "is_proxy": bool(proxy.get("is_proxy")),
        "is_vpn": bool(proxy.get("is_vpn")),
        "is_tor": bool(proxy.get("is_tor")),
        "is_hosting": bool(proxy.get("is_hosting")),
        "is_cdn": bool(proxy.get("is_cdn")),
        "is_school": bool(proxy.get("is_school")),
        "is_anonymous": bool(proxy.get("is_anonymous")),
    }
    if not any(out.values()):
        return None
    return out


def ipdata_lookup_sync(ip: str) -> dict | None:
    """Security block (proxy/vpn/tor/anonymous/hosting + threat score)."""
    req = urllib.request.Request(
        IPDATA_URL.format(ip=ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=IPDATA_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict) or not data.get("success", True):
        return None
    security = data.get("security") or {}
    threat = security.get("threat") or {}
    return {
        "is_proxy": bool(data.get("is_proxy")),
        "is_hosting": bool(data.get("is_hosting")),
        "security": {
            key: bool(security.get(key))
            for key in ("anonymous", "proxy", "vpn", "tor", "hosting")
        },
        "threat_score": int(threat.get("score") or 0),
    }


def getipintel_lookup_sync(ip: str, email: str) -> dict | None:
    """Proxy/VPN probability (0-1) via GetIPIntel; negative values are errors."""
    req = urllib.request.Request(
        GETIPINTEL_URL.format(ip=ip, email=urllib.parse.quote(email)),
        headers={"User-Agent": UA},
    )
    with urllib.request.urlopen(req, timeout=GETIPINTEL_TIMEOUT) as resp:
        text = resp.read().decode("utf-8").strip()
    try:
        prob = float(text)
    except ValueError:
        return None
    if prob < 0:
        return None
    return {"probability": prob}


def ipapi_is_lookup_sync(ip: str) -> dict | None:
    """Free keyless ``api.ipapi.is`` security flags."""
    req = urllib.request.Request(
        IPAPI_IS_URL.format(ip=ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=IPAPI_IS_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict):
        return None
    company = data.get("company") or {}
    asn = data.get("asn") or {}
    out = {
        "is_bogon": bool(data.get("is_bogon")),
        "is_mobile": bool(data.get("is_mobile")),
        "is_crawler": bool(data.get("is_crawler")),
        "is_datacenter": bool(data.get("is_datacenter")),
        "is_tor": bool(data.get("is_tor")),
        "is_proxy": bool(data.get("is_proxy")),
        "is_vpn": bool(data.get("is_vpn")),
        "is_abuser": bool(data.get("is_abuser")),
        "company_type": company.get("type"),
        "asn_type": asn.get("type"),
    }
    abuser = parse_abuser_score(company.get("abuser_score"))
    if abuser is not None:
        out["company_abuser_score"] = abuser
    abuser = parse_abuser_score(asn.get("abuser_score"))
    if abuser is not None:
        out["asn_abuser_score"] = abuser
    return out


def ipquery_lookup_sync(ip: str) -> dict | None:
    """Keyless ``api.ipquery.io/{ip}`` risk flags + ISP (proxy/vpn/tor/datacenter)."""
    req = urllib.request.Request(
        IPQUERY_URL.format(ip=ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=IPQUERY_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict):
        return None
    risk = data.get("risk") or {}
    isp = data.get("isp") or {}
    out = {
        "is_mobile": bool(risk.get("is_mobile")),
        "is_vpn": bool(risk.get("is_vpn")),
        "is_tor": bool(risk.get("is_tor")),
        "is_proxy": bool(risk.get("is_proxy")),
        "is_datacenter": bool(risk.get("is_datacenter")),
        "asn": isp.get("asn"),
        "org": isp.get("org"),
    }
    score = risk.get("risk_score")
    if isinstance(score, (int, float)):
        out["risk_score"] = round(score)
    return out


def ffraud_lookup_sync(ip: str) -> dict | None:
    """Keyless ``api.ffraud.com/public/ip/{ip}`` fraud score + flags."""
    req = urllib.request.Request(
        FFRAUD_URL.format(ip=ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=FFRAUD_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict):
        return None
    out = {
        "is_vpn": bool(data.get("vpn")),
        "is_proxy": bool(data.get("proxy")),
        "is_tor": bool(data.get("tor")),
        "is_hosting": bool(data.get("hosting")),
        "is_mobile": bool(data.get("mobile")),
        "is_abuser": bool(data.get("is_abuser")),
        "recent_abuse": bool(data.get("recent_abuse")),
        "is_residential_proxy": bool(data.get("is_residential_proxy")),
        "connection_type": data.get("connection_type"),
    }
    score = data.get("fraud_score")
    if isinstance(score, (int, float)):
        out["fraud_score"] = round(score)
    return out


def whatismyip_lookup_sync(ip: str) -> dict | None:
    """Keyless ``whatismyip.ai/api/lookup/{ip}`` security score + flags."""
    req = urllib.request.Request(
        WHATISMYIP_URL.format(ip=ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=WHATISMYIP_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict):
        return None
    payload = data.get("data") if isinstance(data.get("data"), dict) else {}
    security = payload.get("security") or {}
    network = payload.get("network") or {}
    out = {
        "is_vpn": bool(security.get("isVpn")),
        "is_proxy": bool(security.get("isProxy")),
        "is_tor": bool(security.get("isTor")),
        "is_hosting": bool(security.get("isHosting")),
        "is_blacklisted": bool(security.get("isBlacklisted")),
        "connection_type": network.get("connectionType"),
    }
    score = security.get("score")
    if isinstance(score, (int, float)):
        out["score"] = round(score)
    return out


async def fetch_torlist() -> set[str]:
    """Union of Tor exit IPs from the static free lists."""
    exits: set[str] = set()

    async def fetch_one(url: str) -> None:
        try:
            text = await asyncio.to_thread(
                lambda: urllib.request.urlopen(
                    urllib.request.Request(url, headers={"User-Agent": UA}),
                    timeout=NETCOFFEE_TIMEOUT,
                ).read().decode("utf-8", errors="replace")
            )
        except Exception:
            return
        for line in text.splitlines():
            if "ExitAddress" in line:
                parts = line.split()
                if len(parts) >= 2 and ":" not in parts[1]:
                    exits.add(parts[1])
            elif line.count(".") == 3 and not line.startswith(("#", "Exit")):
                if len(line) <= 15 and all(c.isdigit() or c == "." for c in line):
                    exits.add(line.strip())

    await asyncio.gather(*(fetch_one(u) for u in TORLIST_URLS))
    return exits


async def fetch_text_list(url: str) -> set[str]:
    """Fetch a static list; any failure returns an empty set (fail-open)."""
    out: set[str] = set()
    try:
        text = await asyncio.to_thread(
            lambda: urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": UA}),
                timeout=STATIC_LIST_TIMEOUT,
            ).read().decode("utf-8", errors="replace")
        )
    except Exception:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        out.add(line)
    return out


async def fetch_firehol_abusers() -> IpSet:
    """FireHOL ``firehol_abusers_1d`` (abusive IPs/CIDRs) as an ``IpSet``."""
    return IpSet(await fetch_text_list(FIREHOL_ABUSERS_URL))


async def fetch_asn_list(url: str) -> set[str]:
    """CSV → normalized ``ASxxxx`` set (locates the ``asn`` column by header)."""
    rows = list(await fetch_text_list(url))
    asns: set[str] = set()
    col = 0
    header_idx = None
    for i, row in enumerate(rows):
        parts = [p.strip() for p in row.split(",")]
        if any(p.lower() == "asn" for p in parts):
            col = next(j for j, p in enumerate(parts) if p.lower() == "asn")
            header_idx = i
            break
    for i, row in enumerate(rows):
        if i == header_idx:
            continue
        parts = row.split(",")
        if len(parts) <= col:
            continue
        asn = norm_asn(parts[col].strip())
        if asn:
            asns.add(asn)
    return asns


async def fetch_static_lists(sources: list) -> dict:
    """Fetch enabled static lists in parallel; disabled/failed sources stay empty."""
    out: dict = {
        "abuse_list": IpSet(),
        "dc_asn": set(),
        "vpn_asn": set(),
        "resproxy_asn": set(),
    }
    mapping = []
    if "abuse_list" in sources:
        mapping.append(("abuse_list", fetch_firehol_abusers()))
    if "dc_asn" in sources:
        mapping.append(("dc_asn", fetch_asn_list(DC_ASN_URL)))
    if "vpn_asn" in sources:
        mapping.append(("vpn_asn", fetch_asn_list(VPN_ASN_URL)))
    if "resproxy_asn" in sources:
        mapping.append(("resproxy_asn", fetch_asn_list(RESPROXY_ASN_URL)))
    results = await asyncio.gather(
        *(task for _name, task in mapping), return_exceptions=True
    )
    for (name, _task), res in zip(mapping, results):
        if not isinstance(res, Exception):
            out[name] = res
    return out


async def batch_sync(
    ips: list,
    fn,
    cap: int = 0,
    workers: int = REP_WORKERS,
    delay: float = REP_DELAY,
) -> dict:
    """Run ``fn(ip)`` over unique IPs with a concurrency semaphore + pacing."""
    items = list(dict.fromkeys(ips))
    if cap > 0:
        items = items[:cap]
    sem = asyncio.Semaphore(workers)
    out: dict = {}

    async def work(ip: str) -> None:
        async with sem:
            try:
                res = await asyncio.to_thread(fn, ip)
            except Exception:
                res = None
        if res:
            out[ip] = res
            await asyncio.sleep(delay)

    await asyncio.gather(*(work(ip) for ip in items))
    return out


def source_score(name: str, signal) -> int | None:
    """0-100 cleanliness from a single source's signal; ``None`` = no signal."""
    if signal is None:
        return None
    if name == "netcoffee":
        score = signal.get("trust_score")
        if isinstance(score, (int, float)):
            return max(0, min(100, round(score)))
        penalty = sum(
            amt for flag, amt in NETCOFFEE_FLAG_PENALTIES.items()
            if signal.get(flag)
        )
        if signal.get("company_type") in ("hosting", "datacenter") or \
           signal.get("asn_kind") in ("hosting", "datacenter"):
            penalty += 15
        if (signal.get("abuser_score") or 0) >= ABUSER_SCORE_THRESHOLD:
            penalty += 20
        return max(0, min(100, 100 - penalty))
    if name == "ncgy":
        penalty = sum(
            amt for flag, amt in NCGY_FLAG_PENALTIES.items()
            if signal.get(flag)
        )
        return max(0, min(100, 100 - penalty))
    if name == "ip-api":
        penalty = 0
        if signal.get("proxy"):
            penalty += IPAPI_PROXY_PENALTY
        if signal.get("hosting"):
            penalty += IPAPI_HOSTING_PENALTY
        return 100 - penalty
    if name == "ipdata":
        security = signal.get("security") or {}
        penalty = sum(
            amt for flag, amt in IPDATA_FLAG_PENALTIES.items()
            if security.get(flag)
        )
        penalty += int(signal.get("threat_score") or 0)
        return max(0, min(100, 100 - penalty))
    if name == "torlist":
        return 25 if signal.get("is_tor") else None
    if name == "getipintel":
        prob = signal.get("probability")
        if not isinstance(prob, (int, float)) or prob < 0:
            return None
        return max(0, min(100, 100 - round(prob * 100)))
    if name == "ipapi_is":
        penalty = sum(
            amt for flag, amt in IPAPI_IS_FLAG_PENALTIES.items()
            if signal.get(flag)
        )
        if signal.get("company_type") in ("hosting", "datacenter") or \
           signal.get("asn_type") in ("hosting", "datacenter"):
            penalty += 15
        abuser = signal.get("company_abuser_score")
        if abuser is None:
            abuser = signal.get("asn_abuser_score")
        if (abuser or 0) >= ABUSER_SCORE_THRESHOLD:
            penalty += 20
        return max(0, min(100, 100 - penalty))
    if name == "ipquery":
        penalty = sum(
            amt for flag, amt in IPQUERY_FLAG_PENALTIES.items()
            if signal.get(flag)
        )
        raw = signal.get("risk_score")
        if isinstance(raw, (int, float)):
            penalty = max(penalty, round(raw))
        if not penalty and not signal.get("asn"):
            return None
        return max(0, min(100, 100 - penalty))
    if name == "ffraud":
        penalty = sum(
            amt for flag, amt in FFRAUD_FLAG_PENALTIES.items()
            if signal.get(flag)
        )
        raw = signal.get("fraud_score")
        if isinstance(raw, (int, float)):
            penalty = max(penalty, round(raw))
        if not penalty and not signal.get("connection_type"):
            return None
        return max(0, min(100, 100 - penalty))
    if name == "whatismyip":
        penalty = sum(
            amt for flag, amt in WHATISMYIP_FLAG_PENALTIES.items()
            if signal.get(flag)
        )
        raw = signal.get("score")
        if isinstance(raw, (int, float)):
            penalty = max(penalty, round(raw))
        if not penalty and not signal.get("connection_type"):
            return None
        return max(0, min(100, 100 - penalty))
    if name in STATIC_LIST_SCORES:
        flag = {
            "abuse_list": "is_abuse",
            "dc_asn": "is_hosting",
            "vpn_asn": "is_vpn",
            "resproxy_asn": "is_proxy",
        }[name]
        return STATIC_LIST_SCORES[name] if signal.get(flag) else None
    return None


def weighted_reputation(
    signals: dict, weights: dict
) -> tuple[int | None, list[str]]:
    """Weighted merge of per-source cleanliness scores over responding sources."""
    parts = []
    for name, signal in signals.items():
        score = source_score(name, signal)
        if score is None:
            continue
        weight = weights.get(name, 0)
        if weight <= 0:
            continue
        parts.append((weight, score, name))
    if not parts:
        return None, []
    total = sum(w for w, _s, _n in parts)
    merged = round(sum(w * s for w, s, _n in parts) / total)
    return merged, [name for _w, _s, name in parts]


def compute_reputation(
    signals: dict, abuse: dict | None, weights: dict
) -> int | None:
    """0-100 multi-source reputation; abuse score (100-score) takes precedence."""
    if abuse and isinstance(abuse.get("score"), (int, float)):
        return max(0, min(100, 100 - round(abuse["score"])))
    score, _sources = weighted_reputation(signals, weights)
    return score


def reputation_risk(score: int | None) -> str | None:
    if score is None:
        return None
    if score < REP_RISK_HIGH:
        return "high"
    if score < REP_RISK_MEDIUM:
        return "medium"
    return "low"


def classify_ip(geo: dict) -> str:
    if geo.get("hosting"):
        return "DC"
    if geo.get("mobile"):
        return "MOB"
    if geo.get("proxy"):
        return "PROXY"
    return "RES"


def collect_signals(
    ip: str,
    geo_item: dict,
    risk_data: dict,
    weights: dict,
    include_ipapi: bool = True,
) -> dict:
    """Assemble ``{source: signal}`` for one IP from ``risk_data``."""
    signals: dict = {}
    for source in weights:
        if source == "ip-api":
            continue
        signal = risk_data.get(ip, {}).get(source)
        if signal is not None:
            signals[source] = signal
    if include_ipapi and geo_item.get("countryCode"):
        signals["ip-api"] = geo_item
    return signals


def derive_risk(
    signals: dict, abuse: dict | None, weights: dict
) -> str:
    return reputation_risk(compute_reputation(signals, abuse, weights)) or "low"


def build_ipinfo_map(
    results: dict,
    geo: dict,
    abuse_map: dict,
    risk_data: dict | None = None,
    weights: dict | None = None,
) -> dict[str, dict]:
    risk_data = risk_data or {}
    weights = weights or REPUTATION_WEIGHTS
    info_map: dict[str, dict] = {}
    for res in results.values():
        if res.get("tls"):
            continue
        ip4, ip6 = res.get("v4"), res.get("v6")
        geo_item = geo.get(ip4) or {}
        family, dual = "ipv4", False
        if ip4 and ip6:
            family, dual = "dual", True
        elif not ip4 and ip6:
            family = "ipv6"
        cc = geo_item.get("countryCode")
        exit_ip = ip4 or ip6
        abuse_item = abuse_map.get(res["key"])
        info = {
            "exit_ip": exit_ip,
            "family": family,
            "dual_stack": dual,
            "country": geo_item.get("country"),
            "country_code": cc,
            "region": geo_item.get("regionName"),
            "city": geo_item.get("city"),
            "asn": geo_item.get("asn"),
            "org": geo_item.get("org"),
            "isp": geo_item.get("isp"),
            "proxy": geo_item.get("proxy"),
            "hosting": geo_item.get("hosting"),
            "mobile": geo_item.get("mobile"),
            "listed_country": res["cc"],
            "country_match": (cc == res["cc"]) if cc else None,
            "ip_type": classify_ip(geo_item),
            "geo_checked": bool(cc),
        }
        risk_flags = {
            source: signal
            for source, signal in risk_data.get(exit_ip, {}).items()
        }
        if risk_flags:
            info["risk_flags"] = risk_flags
        signals = collect_signals(exit_ip, geo_item, risk_data, weights)
        score = compute_reputation(signals, abuse_item, weights)
        if score is not None:
            info["reputation"] = score
            if abuse_item:
                info["reputation_source"] = abuse_item.get("service")
            else:
                _score, sources = weighted_reputation(signals, weights)
                info["reputation_source"] = (
                    sources[0] if len(sources) == 1 else "multi"
                )
                info["risk_sources"] = sources
        info["risk"] = derive_risk(signals, abuse_item, weights)
        info_map[res["key"]] = info
    return info_map


def finalize_streaming(results: dict, ipinfo: dict) -> dict[str, dict]:
    streaming: dict[str, dict] = {}
    for res in results.values():
        st = {}
        for name, item in res["streaming"].items():
            item = dict(item)
            if name == "netflix" and item.get("status") == "ok":
                info = ipinfo.get(res["key"]) or {}
                item["native"] = item.get("region") == info.get("country_code")
            st[name] = item
        streaming[res["key"]] = st
    return streaming


def streaming_tokens(streaming: dict) -> str:
    tokens = []
    netflix = streaming.get("netflix", {})
    if netflix.get("status") == "ok":
        region = netflix.get("region")
        tokens.append(f"NF({region})" if region else "NF")
    if streaming.get("disney", {}).get("status") == "ok":
        tokens.append("D+")
    if streaming.get("youtube", {}).get("status") == "ok":
        tokens.append("YT")
    if streaming.get("max", {}).get("status") == "ok":
        tokens.append("MX")
    if streaming.get("prime", {}).get("status") == "ok":
        tokens.append("PV")
    if streaming.get("openai", {}).get("status") == "ok":
        tokens.append("GPT")
    return " ".join(tokens)


def type_tokens(ipinfo: dict) -> str:
    tokens = []
    ip_type = ipinfo.get("ip_type")
    if ip_type:
        tokens.append(ip_type)
    family = ipinfo.get("family")
    if family == "dual":
        tokens.append("DS")
    elif family == "ipv6":
        tokens.append("V6")
    return " ".join(tokens)


def build_annotation(stream_toks: str, type_toks: str) -> str:
    return "-".join(seg for seg in (stream_toks, type_toks) if seg)


def build_reputation_map(
    results: dict,
    ipinfo: dict,
    risk_data: dict,
    weights: dict,
) -> dict[str, dict]:
    rep_map: dict[str, dict] = {}
    for res in results.values():
        if res.get("tls"):
            signals = collect_signals(
                res["ip"], {}, risk_data, weights, include_ipapi=False
            )
            score = compute_reputation(signals, None, weights)
            _score, sources = weighted_reputation(signals, weights)
            source = "multi" if len(sources) != 1 else (sources[0] if sources else None)
        else:
            info = ipinfo.get(res["key"]) or {}
            score = info.get("reputation")
            sources = info.get("risk_sources") or []
            source = info.get("reputation_source")
        if score is None:
            continue
        rep_map[res["key"]] = {
            "score": score,
            "risk": reputation_risk(score),
            "source": source,
            "sources": sources,
        }
    return rep_map


LATENCY_RE = re.compile(r"-(\d+)ms")


def build_ranked(text: str, annotations: dict, rep_map: dict) -> list[str]:
    """Annotate ``text`` lines and re-order them by reputation desc.

    Lines with a reputation score are sorted by ``(score desc, latency asc,
    key)``; unscored lines keep their original relative order at the end.
    """
    scored: list[tuple[dict, str, str]] = []
    unscored: list[str] = []
    for line in text.splitlines():
        if not line:
            continue
        key = line_to_key(line)
        ann = annotations.get(key) if key else None
        out = line + ("-" + ann if ann else "")
        rep = rep_map.get(key)
        if rep:
            scored.append((rep, key, out))
        else:
            unscored.append(out)

    def sort_key(item: tuple[dict, str, str]) -> tuple:
        rep, key, line = item
        lat_match = LATENCY_RE.search(line)
        lat = int(lat_match.group(1)) if lat_match else float("inf")
        return (-rep["score"], lat, key)

    scored.sort(key=sort_key)
    return [line for _rep, _key, line in scored] + unscored


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def write_reputation_files(source_text: str, annotations: dict, rep_map: dict) -> None:
    ranked = build_ranked(source_text, annotations, rep_map)
    _write_atomic(REP_RANK_FILE, "\n".join(ranked) + "\n")
    valid_root = REP_RANK_FILE.parent
    for sub in ("countries", "sets"):
        for src in sorted((valid_root / sub).glob("*/all.txt")):
            ranked = build_ranked(
                src.read_text(encoding="utf-8"), annotations, rep_map
            )
            _write_atomic(src.with_name("rep.txt"), "\n".join(ranked) + "\n")
    entries = {
        key: {
            "score": rep["score"],
            "risk": rep["risk"],
            "source": rep["source"],
            "sources": rep.get("sources") or [],
        }
        for key, rep in rep_map.items()
    }
    entries = dict(
        sorted(entries.items(), key=lambda kv: (-kv[1]["score"], kv[0]))
    )
    write_json(REPUTATION_FILE, keyed_json(entries))


def build_annotations(results: dict, ipinfo: dict, rep_map: dict) -> dict[str, str]:
    annotations: dict[str, str] = {}
    for res in results.values():
        stream_toks = streaming_tokens(res["streaming"])
        if res.get("tls"):
            type_toks = "CF"
        else:
            type_toks = type_tokens(ipinfo.get(res["key"]) or {})
        ann = build_annotation(stream_toks, type_toks)
        rep = rep_map.get(res["key"])
        if rep:
            ann = build_annotation(ann, str(rep["score"]))
        annotations[res["key"]] = ann
    return annotations


def build_exits(results: dict, ipinfo: dict) -> dict[str, str]:
    """Exit region per key: CF edge ``loc`` for ``tls`` proxies, else the exit-IP
    country. Used to annotate ``ip:port#<entry>→<exit>`` on valid lines."""
    exits: dict[str, str] = {}
    for res in results.values():
        if res.get("tls"):
            region = (res.get("streaming") or {}).get("openai", {}).get("region")
        else:
            region = (ipinfo.get(res["key"]) or {}).get("country_code")
        if region:
            exits[res["key"]] = region
    return exits


EXIT_REGION_RE = re.compile(r"^(.*#[^A-Z]*[A-Z]+)")


def insert_exit_region(line: str, exit_region: str) -> str:
    """Insert ``→<exit>`` right after the entry country code (idempotent)."""
    if not exit_region or "→" in line:
        return line
    m = EXIT_REGION_RE.match(line)
    if not m:
        return line
    return line[: m.end(1)] + "→" + exit_region + line[m.end(1):]


def annotate_text(
    text: str, annotations: dict, exits: dict | None = None
) -> tuple[str, bool]:
    out = []
    changed = False
    exits = exits or {}
    for line in text.splitlines():
        if not line:
            continue
        key = line_to_key(line)
        ann = annotations.get(key) if key else None
        exit_region = exits.get(key) if key else None
        out_line = insert_exit_region(line, exit_region) if exit_region else line
        if ann and not out_line.rstrip().endswith("-" + ann):
            out_line = out_line + "-" + ann
        if out_line != line:
            changed = True
        out.append(out_line)
    return "\n".join(out) + "\n", changed


def annotate_valid_files(annotations: dict, exits: dict | None = None) -> None:
    files: list[Path] = [VALID_DIR / "all.txt", VALID_DIR / "all_ltd.txt"]
    for sub in ("countries", "sets"):
        files.extend(sorted((VALID_DIR / sub).glob("*/all.txt")))
        files.extend(sorted((VALID_DIR / sub).glob("*/ltd.txt")))
    files.extend(sorted((VALID_DIR / "ports").glob("*.txt")))
    for path in files:
        if not path.exists():
            continue
        text, changed = annotate_text(
            path.read_text(encoding="utf-8"), annotations, exits
        )
        if changed:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(text, encoding="utf-8")
            tmp.replace(path)


def build_meta(
    results: dict, ipinfo: dict, streaming: dict, abuse_map: dict
) -> dict:
    per_service = {name: {"ok": 0, "blocked": 0, "error": 0} for name in SERVICES}
    streaming_ok = 0
    for st in streaming.values():
        if any(res.get("status") == "ok" for res in st.values()):
            streaming_ok += 1
        for name, res in st.items():
            status = res.get("status", "error")
            if status not in per_service[name]:
                status = "error"
            per_service[name][status] += 1
    by_type = Counter(info["ip_type"] for info in ipinfo.values())
    family = Counter(info["family"] for info in ipinfo.values())
    mismatch = sum(
        1 for info in ipinfo.values() if info.get("country_match") is False
    )
    dual = sum(1 for info in ipinfo.values() if info.get("dual_stack"))
    risk = Counter(
        info["risk"] for info in ipinfo.values() if info.get("risk")
    )
    reps = [
        info["reputation"] for info in ipinfo.values()
        if info.get("reputation") is not None
    ]
    rep_dist = {
        "0-25": sum(1 for r in reps if r < 25),
        "25-50": sum(1 for r in reps if 25 <= r < 50),
        "50-75": sum(1 for r in reps if 50 <= r < 75),
        "75-100": sum(1 for r in reps if r >= 75),
    }
    return {
        "ts": now_ts(),
        "total": len(results),
        "connect": sum(1 for r in results.values() if not r.get("tls")),
        "tls": sum(1 for r in results.values() if r.get("tls")),
        "services": list(SERVICES),
        "streaming": per_service,
        "streaming_ok": streaming_ok,
        "by_type": dict(sorted(by_type.items())),
        "family": dict(sorted(family.items())),
        "dual_stack": dual,
        "country_mismatch": mismatch,
        "risk": dict(sorted(risk.items())),
        "abuse_checked": len(abuse_map),
        "reputation_checked": len(reps),
        "rep_dist": rep_dist,
        "rep_avg": (round(sum(reps) / len(reps), 1) if reps else None),
        "rep_median": (
            round(sorted(reps)[len(reps) // 2], 1) if reps else None
        ),
    }


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)


def keyed_json(entries: dict) -> dict:
    return {"proxies": entries}


def abuse_lookup_sync(ip: str, service: str, key: str) -> dict:
    if service == "abuseipdb":
        url = (
            "https://api.abuseipdb.com/api/v2/check"
            f"?ipAddress={ip}&maxAgeInDays=90"
        )
        req = urllib.request.Request(
            url,
            headers={
                "Key": key,
                "Accept": "application/json",
                "User-Agent": "proxyip/quality 1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))["data"]
        return {
            "service": "abuseipdb",
            "score": data.get("abuseConfidenceScore"),
            "is_tor": data.get("isTor"),
            "is_proxy": data.get("isProxy"),
            "is_hosting": data.get("isHosting"),
            "country_code": data.get("countryCode"),
        }
    url = f"https://ipqualityscore.com/api/json/ip/{key}/{ip}"
    req = urllib.request.Request(
        url, headers={"User-Agent": "proxyip/quality 1.0"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return {
        "service": "ipqs",
        "score": data.get("fraud_score"),
        "proxy": data.get("proxy"),
        "vpn": data.get("vpn"),
        "hosting": data.get("hosting"),
        "mobile": data.get("mobile"),
        "bot": data.get("bot_status"),
        "isp": data.get("isp"),
    }


async def run_abuse(
    results: dict, ipinfo: dict, args: argparse.Namespace
) -> dict:
    if args.abuse_service == "none" or not args.abuse_key:
        return {}
    exit_ips = sorted(
        {info["exit_ip"] for info in ipinfo.values() if info.get("exit_ip")}
    )
    by_ip: dict[str, dict] = {}
    for ip in exit_ips:
        try:
            by_ip[ip] = await asyncio.to_thread(
                abuse_lookup_sync, ip, args.abuse_service, args.abuse_key
            )
        except Exception:
            pass
        await asyncio.sleep(0.3)
    abuse_map: dict[str, dict] = {}
    for key, info in ipinfo.items():
        item = by_ip.get(info.get("exit_ip"))
        if item:
            entry = dict(item)
            entry["risk"] = derive_risk({}, item, args.reputation_weights)
            abuse_map[key] = entry
    return abuse_map


async def lookup_all_risk(
    ips: list, args: argparse.Namespace, asn_map: dict | None = None
) -> dict:
    """Query all enabled reputation sources; ``{ip: {source: signal}}``."""
    sources = args.reputation_sources
    if not sources:
        return {}
    risk_data: dict[str, dict] = {}

    def put(name: str, ip: str, signal) -> None:
        risk_data.setdefault(ip, {})[name] = signal

    pacing = SOURCE_PACING
    if "netcoffee" in sources:
        workers, delay = pacing.get("netcoffee", (REP_WORKERS, REP_DELAY))
        for ip, sig in (
            await batch_sync(ips, netcoffee_lookup_sync, workers=workers, delay=delay)
        ).items():
            put("netcoffee", ip, sig)
    if "ncgy" in sources:
        workers, delay = pacing.get("ncgy", (REP_WORKERS, REP_DELAY))
        for ip, sig in (
            await batch_sync(ips, ncgy_lookup_sync, workers=workers, delay=delay)
        ).items():
            put("ncgy", ip, sig)
    if "ipdata" in sources:
        for ip, sig in (
            await batch_sync(
                ips, ipdata_lookup_sync,
                cap=IPDATA_CAP, workers=2, delay=0.8,
            )
        ).items():
            put("ipdata", ip, sig)
    if "getipintel" in sources:
        if args.getipintel_email:
            fn = lambda ip: getipintel_lookup_sync(ip, args.getipintel_email)
            for ip, sig in (
                await batch_sync(
                    ips, fn, cap=GETIPINTEL_CAP, workers=1, delay=4
                )
            ).items():
                put("getipintel", ip, sig)
        else:
            print(
                "Warning: GETIPINTEL_EMAIL not set; skipping getipintel source",
                file=sys.stderr,
            )
    if "ipapi_is" in sources:
        workers, delay = pacing.get("ipapi_is", (REP_WORKERS, REP_DELAY))
        for ip, sig in (
            await batch_sync(ips, ipapi_is_lookup_sync, workers=workers, delay=delay)
        ).items():
            put("ipapi_is", ip, sig)
    if "ipquery" in sources:
        workers, delay = pacing.get("ipquery", (REP_WORKERS, REP_DELAY))
        for ip, sig in (
            await batch_sync(ips, ipquery_lookup_sync, workers=workers, delay=delay)
        ).items():
            put("ipquery", ip, sig)
    if "ffraud" in sources:
        workers, delay = pacing.get("ffraud", (REP_WORKERS, REP_DELAY))
        for ip, sig in (
            await batch_sync(ips, ffraud_lookup_sync, workers=workers, delay=delay)
        ).items():
            put("ffraud", ip, sig)
    if "whatismyip" in sources:
        workers, delay = pacing.get("whatismyip", (REP_WORKERS, REP_DELAY))
        for ip, sig in (
            await batch_sync(ips, whatismyip_lookup_sync, workers=workers, delay=delay)
        ).items():
            put("whatismyip", ip, sig)
    if "torlist" in sources:
        tor = await fetch_torlist()
        for ip in dict.fromkeys(ips):
            if ip in tor:
                put("torlist", ip, {"is_tor": True})
    static = await fetch_static_lists(sources)
    for ip in dict.fromkeys(ips):
        if ip in static["abuse_list"]:
            put("abuse_list", ip, {"is_abuse": True})
        asn = (asn_map or {}).get(ip)
        if not asn:
            continue
        if asn in static["dc_asn"]:
            put("dc_asn", ip, {"is_hosting": True, "asn": asn})
        if asn in static["vpn_asn"]:
            put("vpn_asn", ip, {"is_vpn": True, "asn": asn})
        if asn in static["resproxy_asn"]:
            put("resproxy_asn", ip, {"is_proxy": True, "asn": asn})
    return risk_data


async def run(args: argparse.Namespace) -> int:
    if not args.source.exists():
        print(f"Error: {args.source} not found", file=sys.stderr)
        return 1
    entries = [
        p for p in (parse_ltd_line(line) for line in args.source.read_text(
            encoding="utf-8"
        ).splitlines()) if p
    ]
    if args.limit > 0:
        entries = entries[: args.limit]
    if not entries:
        print(f"No entries in {args.source}")
        return 0
    methods = load_methods()
    print(
        f"Checking {len(entries)} proxies "
        f"(timeout={args.timeout}s, workers={args.workers}) ..."
    )

    results = await run_checks(entries, methods, args)
    print(f"Completed {len(results)} checks")

    geo = await batch_ipapi(
        [res["v4"] for res in results.values() if res.get("v4")]
    )
    ipinfo = build_ipinfo_map(results, geo, {})
    abuse_map = await run_abuse(results, ipinfo, args)

    rep_ips = []
    asn_map: dict[str, str] = {}
    for res in results.values():
        if res.get("tls"):
            rep_ips.append(res["ip"])
        else:
            info = ipinfo.get(res["key"]) or {}
            if info.get("exit_ip"):
                rep_ips.append(info["exit_ip"])
                if info.get("asn"):
                    asn_map[info["exit_ip"]] = info["asn"]
    risk_data = await lookup_all_risk(rep_ips, args, asn_map)
    if risk_data:
        print(
            f"Reputation: {len(risk_data)}/{len(set(rep_ips))} IPs from "
            f"{', '.join(args.reputation_sources)}"
        )
    ipinfo = build_ipinfo_map(
        results, geo, abuse_map, risk_data, args.reputation_weights
    )
    rep_map = build_reputation_map(
        results, ipinfo, risk_data, args.reputation_weights
    )

    streaming = finalize_streaming(results, ipinfo)
    annotations = build_annotations(results, ipinfo, rep_map)
    source_text = args.source.read_text(encoding="utf-8")
    if rep_map:
        write_reputation_files(source_text, annotations, rep_map)

    write_json(IPINFO_FILE, keyed_json(ipinfo))
    write_json(STREAMING_FILE, keyed_json(streaming))
    if abuse_map:
        write_json(ABUSE_FILE, keyed_json(abuse_map))
    meta = build_meta(results, ipinfo, streaming, abuse_map)
    write_json(QUALITY_META_FILE, meta)
    annotate_valid_files(annotations, build_exits(results, ipinfo))

    print(
        f"streaming_ok={meta['streaming_ok']} "
        f"by_type={meta['by_type']} family={meta['family']} "
        f"mismatch={meta['country_mismatch']} "
        f"rep_avg={meta['rep_avg']} rep_dist={meta['rep_dist']}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, default=DEFAULT_SOURCE,
        help="Input proxy list (default: data/valid/all_ltd.txt)",
    )
    parser.add_argument(
        "--services", nargs="*", default=None,
        help="Services to check (default: all of netflix disney youtube max prime openai)",
    )
    parser.add_argument(
        "--abuse-service", choices=("none", "abuseipdb", "ipqs"), default="none",
        help="Abuse-score provider (key from ABUSEIPDB_KEY / IPQS_KEY env)",
    )
    parser.add_argument(
        "--reputation-provider",
        choices=("multi", "netcoffee", "ip-api", "none"),
        default="multi",
        help="Reputation strategy: multi (weighted merge of --reputation-sources), "
        "netcoffee (legacy net.coffee + ip-api), ip-api (flags only), or none",
    )
    parser.add_argument(
        "--reputation-sources",
        default=None,
        help="Comma list of sources for --reputation-provider multi "
        "(default: netcoffee,ncgy,ip-api,ipquery,ffraud,ipapi_is,ipdata,"
        "whatismyip,dc_asn,abuse_list,torlist,vpn_asn,resproxy_asn)",
    )
    parser.add_argument(
        "--reputation-weights",
        dest="reputation_weights_override",
        default=None,
        help="Comma list of name:weight overrides, e.g. netcoffee:40,ncgy:20",
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=TIMEOUT,
        help="Per-proxy timeout (seconds)",
    )
    parser.add_argument("--read-cap", type=int, default=READ_CAP,
                        help="Max body bytes read per HTTP response")
    parser.add_argument(
        "-w", "--workers", type=int, default=WORKERS,
        help="Max concurrent checks",
    )
    parser.add_argument("--limit", type=int, default=0,
                        help="Max proxies to check (0 = all)")
    parser.add_argument(
        "--time-budget", type=int, default=0,
        help="Stop after this many seconds (0 = unlimited)",
    )
    args = parser.parse_args(argv)
    if not args.services:
        args.services = list(SERVICES)
    import os

    args.abuse_key = ""
    if args.abuse_service != "none":
        env_name = {
            "abuseipdb": "ABUSEIPDB_KEY",
            "ipqs": "IPQS_KEY",
        }[args.abuse_service]
        args.abuse_key = os.environ.get(env_name, "")
        if not args.abuse_key:
            print(
                f"Warning: {env_name} not set; skipping abuse scores",
                file=sys.stderr,
            )
            args.abuse_service = "none"
    args.getipintel_email = os.environ.get("GETIPINTEL_EMAIL", "")
    args.reputation_weights = dict(REPUTATION_WEIGHTS)
    override = args.reputation_weights_override or ""
    for tok in override.split(","):
        if ":" in tok:
            name, weight = tok.split(":", 1)
            try:
                args.reputation_weights[name.strip()] = int(weight)
            except ValueError:
                pass
    args.reputation_sources = args.reputation_sources or ""
    if args.reputation_provider == "none":
        args.reputation_sources = []
    elif args.reputation_provider == "netcoffee":
        args.reputation_sources = ["netcoffee", "ip-api"]
    elif args.reputation_provider == "ip-api":
        args.reputation_sources = ["ip-api"]
    else:
        args.reputation_sources = [
            s.strip() for s in args.reputation_sources.split(",") if s.strip()
        ]
        args.reputation_sources = [
            s for s in args.reputation_sources if s in REPUTATION_WEIGHTS
        ]
        if not args.reputation_sources:
            args.reputation_sources = list(DEFAULT_REP_SOURCES)
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
