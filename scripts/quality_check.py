#!/usr/bin/env python3
"""Streaming unlock and exit-IP quality checks for alive proxies.

Runs on a bounded population (default ``data/valid/all_ltd.txt``, the
per-country fastest survivors) and writes under ``data/valid/``:

- ``ipinfo.json``      exit IP / address family / dual-stack / geo / IP type
- ``streaming.json``   per-service unlock results (incl. native Netflix)
- ``abuse.json``       optional abuse-score results (key-gated)
- ``quality_meta.json`` aggregated summary for stats and charts
- annotated ``*.txt``  all/countries/ports/sets lines get ``#``-suffix segments

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
lines as ``-<streaming>-<type>``, e.g.
``1.2.3.4:443#US-120ms-0.44MB/s-NF(US) D+ YT GPT-DC`` (streaming tokens
space-separated, IP-type tokens after a second dash). Lines without results
stay untouched.
"""

import argparse
import asyncio
import json
import re
import ssl
import sys
import time
import urllib.request
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
DEFAULT_SOURCE = VALID_DIR / "all_ltd.txt"

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
    """``ip:port#<flag><cc>-...`` -> ``(key, ip, port, cc)`` or ``None``."""
    line = line.strip()
    if not line or "#" not in line:
        return None
    addr, rest = line.rsplit("#", 1)
    i = 0
    while i < len(rest) and not ("A" <= rest[i] <= "Z"):
        i += 1
    cc = rest[i : i + 2]
    if len(cc) != 2 or not cc.isalpha() or ":" not in addr:
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
        match = re.search(r"^loc=([A-Z]{2})", body.decode("latin-1"), re.M)
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


def classify_ip(geo: dict) -> str:
    if geo.get("hosting"):
        return "DC"
    if geo.get("mobile"):
        return "MOB"
    if geo.get("proxy"):
        return "PROXY"
    return "RES"


def derive_risk(ipinfo: dict, abuse: dict | None) -> str:
    if abuse and isinstance(abuse.get("score"), (int, float)):
        score = abuse["score"]
        return "high" if score >= 75 else ("medium" if score >= 30 else "low")
    if ipinfo.get("proxy") and ipinfo.get("hosting"):
        return "high"
    if ipinfo.get("proxy") or ipinfo.get("hosting"):
        return "medium"
    return "low"


def build_ipinfo_map(
    results: dict, geo: dict, abuse_map: dict
) -> dict[str, dict]:
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
        info = {
            "exit_ip": ip4 or ip6,
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
        }
        info["risk"] = derive_risk(info, abuse_map.get(res["key"]))
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


def build_annotations(results: dict, ipinfo: dict) -> dict[str, str]:
    annotations: dict[str, str] = {}
    for res in results.values():
        stream_toks = streaming_tokens(res["streaming"])
        if res.get("tls"):
            annotations[res["key"]] = build_annotation(stream_toks, "CF")
        else:
            annotations[res["key"]] = build_annotation(
                stream_toks, type_tokens(ipinfo.get(res["key"]) or {})
            )
    return annotations


def annotate_text(text: str, annotations: dict) -> tuple[str, bool]:
    out = []
    changed = False
    for line in text.splitlines():
        if not line:
            continue
        key = line_to_key(line)
        ann = annotations.get(key) if key else None
        if ann and not line.rstrip().endswith("-" + ann):
            out.append(line + "-" + ann)
            changed = True
        else:
            out.append(line)
    return "\n".join(out) + "\n", changed


def annotate_valid_files(annotations: dict) -> None:
    files: list[Path] = [VALID_DIR / "all.txt", VALID_DIR / "all_ltd.txt"]
    for sub in ("countries", "ports", "sets"):
        files.extend(sorted((VALID_DIR / sub).glob("*.txt")))
    for path in files:
        if not path.exists():
            continue
        text, changed = annotate_text(path.read_text(encoding="utf-8"), annotations)
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
            entry["risk"] = derive_risk(info, item)
            abuse_map[key] = entry
    return abuse_map


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
    if abuse_map:
        ipinfo = build_ipinfo_map(results, geo, abuse_map)
    streaming = finalize_streaming(results, ipinfo)
    annotations = build_annotations(results, ipinfo)

    write_json(IPINFO_FILE, keyed_json(ipinfo))
    write_json(STREAMING_FILE, keyed_json(streaming))
    if abuse_map:
        write_json(ABUSE_FILE, keyed_json(abuse_map))
    meta = build_meta(results, ipinfo, streaming, abuse_map)
    write_json(QUALITY_META_FILE, meta)
    annotate_valid_files(annotations)

    print(
        f"streaming_ok={meta['streaming_ok']} "
        f"by_type={meta['by_type']} family={meta['family']} "
        f"mismatch={meta['country_mismatch']}"
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
    args.abuse_key = ""
    if args.abuse_service != "none":
        import os

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
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
