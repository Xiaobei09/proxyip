#!/usr/bin/env python3
"""Streaming unlock + exit geo checks (extracted from quality_check.py).

TLS direct GETs against the streaming providers in ``SERVICES`` plus
``cloudflare.com/cdn-cgi/trace`` exit echo and ip-api geo batch.
Imported by ``quality_check``.
"""

import argparse
import asyncio
import json
import logging
import re
import ssl
import urllib.parse
import urllib.request

from common import *  # noqa: F401,F403  (paths, UA, build_request, IPAPI_*, ...)
from common import _SSL_CTX  # noqa: F401  (import * skips underscore-prefixed names)

IPAPI_GET_URL = "http://ip-api.com/json/{ip}"
IPAPI_FIELDS = (
    "status,message,country,countryCode,regionName,city,"
    "as,asn,org,isp,proxy,hosting,mobile"
)
TIMEOUT = 6
READ_CAP = 524288
READ_TIMEOUT = 3
HEADER_CAP = 65536
WORKERS = 60
SERVICES = {
    "netflix": {"host": "www.netflix.com", "path": "/title/80018499"},
    "disney": {"host": "www.disneyplus.com", "path": "/"},
    "youtube": {"host": "www.youtube.com", "path": "/premium"},
    "max": {"host": "www.max.com", "path": "/"},
    "prime": {"host": "www.primevideo.com", "path": "/"},
    "openai": {"host": "chat.openai.com", "path": "/cdn-cgi/trace"},
}

SERVICE_ORDER = tuple(SERVICES)
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
        try:
            size = int(head.split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            break
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
        try:
            want = min(int(clen), cap - len(body)) if clen else cap - len(body)
        except (ValueError, TypeError):
            want = cap - len(body)
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
            await writer.wait_closed()
        except OSError:
            pass


async def check_external_api(ip: str, port: str, timeout: int = 30) -> dict:
    """Call external ProxyIP verification API.

    Returns a dict with ``success``, ``response_ms``, ``colo``,
    ``ipv4_ok``, ``ipv6_ok`` and ``exit_geo`` fields. On any error
    returns ``{"success": false}``.
    """
    url = f"{EXTERNAL_CHECK_URL}?proxyip={ip}:{port}"

    def _fetch() -> dict:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "proxyip-checker/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    try:
        data = await asyncio.to_thread(_fetch)
        ipv4 = data.get("probe_results", {}).get("ipv4", {})
        ipv6 = data.get("probe_results", {}).get("ipv6", {})
        return {
            "success": bool(data.get("success")),
            "response_ms": data.get("responseTime"),
            "colo": data.get("colo"),
            "ipv4_ok": bool(ipv4.get("ok")),
            "ipv6_ok": bool(ipv6.get("ok")),
            "exit_geo": ipv4.get("exit"),
        }
    except Exception as exc:  # noqa: BLE001
        logging.debug("check_external_api %s:%s failed: %s", ip, port, exc)
        return {"success": False}


async def check_one(entry: tuple, method: str, args: argparse.Namespace) -> dict:
    """Run the checks for a single proxy entry."""
    key, ip, port, cc = entry
    base = {"key": key, "ip": ip, "port": port, "cc": cc, "method": "tls", "tls": True}
    streaming: dict = {}
    for svc in args.services:
        cfg = SERVICES[svc]
        status, headers, body, _err = await tls_get_direct(
            ip, port, cfg["host"], cfg["path"],
            args.timeout, args.read_cap,
        )
        streaming[svc] = PARSERS[svc](status, headers, body)
    base["streaming"] = streaming
    base["external_check"] = await check_external_api(ip, port, timeout=30)
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
            res = await check_one(entry, methods.get(key, "tls"), args)
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
        except Exception as exc:
            logging.debug("streaming task result: %s", exc)
    return results


def group_chunks(items: list, size: int = IPAPI_BATCH_SIZE) -> list[list]:
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
        except Exception as exc:
            logging.debug("ipapi batch failed: %s", exc)
            continue
        for item, ip in zip(data, chunk):
            if isinstance(item, dict) and item.get("status") == "success":
                out[ip] = item
        await asyncio.sleep(IPAPI_BATCH_DELAY)
    if any_batch_ok or out:
        return out
    for ip in dict.fromkeys(ips):
        try:
            item = await asyncio.to_thread(ipapi_get_sync, ip)
            if item.get("status") == "success":
                out[ip] = item
        except Exception as exc:
            logging.debug("ipapi get %s: %s", ip, exc)
        await asyncio.sleep(1.5)
    return out


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

