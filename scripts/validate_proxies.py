#!/usr/bin/env python3
"""Validate proxy reachability and measure latency.

Reads ``data/all.txt`` (``ip:port#country`` lines) and checks each proxy.
Two checks are performed, in order:

1. HTTP CONNECT tunnel to a target host (works for standard proxies).
2. TLS handshake to the proxy itself (works for Cloudflare edge proxies,
   which serve TLS on 443/8443/2053/2083/2087/2096 but reject plain CONNECT).

Checks run concurrently with asyncio (default 500 in-flight, kept bounded by
an in-flight task pool). Each alive proxy also gets a download speed test on
the same connection (CONNECT tunnel or TLS). Outputs are written under
``data/valid/`` mirroring the structure of ``data/``. Non-limited outputs are
ordered by latency (fastest first); ``*_ltd`` outputs pick the fastest per
country by measured speed. Lines use the ``ip:port#<flag><cc>-<latency>ms-<speed>MB/s``
format (speed omitted when the test failed). Proxies that connect at the TCP
level but fail both checks are retried once.
"""

import argparse
import asyncio
import json
import ssl
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from download_proxies import (
    COUNTRY_SETS,
    OUT_DIR,
    PER_COUNTRY_LIMIT,
    SMALL_SETS,
)

VALID_DIR = OUT_DIR / "valid"
VALID_HISTORY_FILE = VALID_DIR / "history.jsonl"
INDEX_FILE = VALID_DIR / "index.json"
SPEED_FILE = VALID_DIR / "speed.json"
MAX_HISTORY_RECORDS = 1000

SPEED_HOST = "cdnjs.cloudflare.com"
TARGET_HOST = SPEED_HOST
TARGET_PORT = 443
TARGET_SNI = SPEED_HOST
SPEED_PATH = "/ajax/libs/three.js/r128/three.min.js"
SPEED_READ_BYTES = 262144
SPEED_TIMEOUT = 5
SPEED_MIN_BYTES = 16384
SPEED_WORKERS = 10
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


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


async def try_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    target_port: int,
) -> bool:
    req = (
        f"CONNECT {host}:{target_port} HTTP/1.1\r\n"
        f"Host: {host}:{target_port}\r\n"
        "Proxy-Connection: Keep-Alive\r\n\r\n"
    )
    writer.write(req.encode("ascii"))
    await writer.drain()
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=READ_CAP)
            if not chunk:
                return False
            buf += chunk
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return False
    return b" 200 " in buf.split(b"\r\n", 1)[0]


async def check_proxy(
    ip: str,
    port: str,
    args: argparse.Namespace,
    speed_sem: asyncio.Semaphore | None,
) -> tuple[str, str | None, float | None, float | None]:
    """Return ``(status, method, latency_ms, speed_mbps)``.

    Alive proxies additionally download ``speed_path`` from ``speed_host`` on
    the already-established connection to measure throughput. Downloads are
    gated by ``speed_sem`` so bandwidth stays low-contention. Speed is ``None``
    when the measurement failed (the proxy stays alive).
    """
    started = time.monotonic()

    def elapsed(since: float) -> float:
        return round((time.monotonic() - since) * 1000, 1)

    async def measure_speed(reader, writer) -> float | None:
        if args.no_speed or speed_sem is None:
            return None
        async with speed_sem:
            return await speed_download(
                reader, writer, args.speed_host, args.speed_path,
                args.speed_bytes, args.speed_timeout,
            )

    try:
        reader, writer = await open_conn(ip, port, args.timeout)
    except (OSError, asyncio.TimeoutError, ValueError):
        return "dead", None, None, None
    try:
        try:
            if await try_connect(reader, writer, args.host, args.target_port):
                connect_latency = elapsed(started)
                speed = await measure_speed(reader, writer)
                return "ok", "connect", connect_latency, speed
        except (ConnectionError, OSError):
            pass
    finally:
        try:
            writer.close()
        except OSError:
            pass

    tls_started = time.monotonic()
    try:
        reader, writer = await open_conn(ip, port, args.timeout, ctx=_TLS_CTX, sni=args.sni)
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError):
        return "retry", None, None, None
    tls_latency = elapsed(tls_started)
    try:
        speed = await measure_speed(reader, writer)
    finally:
        try:
            writer.close()
        except OSError:
            pass
    return "ok", "tls", tls_latency, speed


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
    if INDEX_FILE.exists() and INDEX_FILE.read_text(encoding="utf-8") == content:
        return
    tmp = INDEX_FILE.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(INDEX_FILE)


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
    if SPEED_FILE.exists() and SPEED_FILE.read_text(encoding="utf-8") == content:
        return
    tmp = SPEED_FILE.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(SPEED_FILE)


def write_valid_outputs(
    alive: dict[str, tuple[str, str, str, str, float, float | None]],
    per_country_limit: int,
) -> dict:
    VALID_DIR.mkdir(parents=True, exist_ok=True)

    ordered = sorted(alive, key=lambda e: (alive[e][4], e))

    def line(entry: str) -> str:
        ip, port, cc, _m, latency, speed = alive[entry]
        return fmt_entry(ip, port, cc, latency, speed)

    def ltd_key(entry: str) -> tuple:
        speed = alive[entry][5]
        if speed is not None:
            return (0, -speed, 0.0)
        return (1, 0.0, alive[entry][4])

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

    for country in sorted(by_country):
        (countries_dir / f"{country}.txt").write_text(
            "\n".join(line(e) for e in by_country[country]) + "\n"
        )
    expected_countries = {f"{c}.txt" for c in by_country}
    for stale in countries_dir.iterdir():
        if stale.name not in expected_countries:
            stale.unlink()

    for port in sorted(by_port, key=int):
        (ports_dir / f"{port}.txt").write_text(
            "\n".join(line(e) for e in by_port[port]) + "\n"
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
        (sets_dir / f"{name}.txt").write_text(
            "\n".join(line(e) for e in full) + "\n"
        )
        set_counts[name] = len(full)
        if per_country_limit > 0:
            ltd: list[str] = []
            for cc in countries:
                if cc in country_ltd:
                    ltd.extend(country_ltd[cc])
            ltd = sorted(ltd, key=ltd_key)
            (sets_dir / f"{name}_ltd.txt").write_text(
                "\n".join(line(e) for e in ltd) + "\n"
            )
            set_counts[f"{name}_ltd"] = len(ltd)
    expected_sets = {f"{n}.txt" for n in {**COUNTRY_SETS, **SMALL_SETS}} | {
        f"{n}_ltd.txt" for n in {**COUNTRY_SETS, **SMALL_SETS}
    }
    for stale in sets_dir.iterdir():
        if stale.name not in expected_sets:
            stale.unlink()

    (VALID_DIR / "all.txt").write_text("\n".join(line(e) for e in ordered) + "\n")
    set_counts["all"] = len(ordered)
    if per_country_limit > 0:
        ltd_all = sorted(
            [e for cc in country_ltd for e in country_ltd[cc]], key=ltd_key
        )
        (VALID_DIR / "all_ltd.txt").write_text(
            "\n".join(line(e) for e in ltd_all) + "\n"
        )
        set_counts["all_ltd"] = len(ltd_all)
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
        except Exception:
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
                wait_ms = min(0.25, max(0.0, deadline - time.monotonic()))
                await asyncio.wait(tasks, timeout=wait_ms)
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
        print(f"Retrying {len(retry_pool)} connectable-but-unverified proxies ...")
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
        lat_stats = {
            "avg_ms": round(statistics.mean(latencies), 1),
            "median_ms": round(statistics.median(latencies), 1),
            "p90_ms": round(latencies_sorted[int(len(latencies_sorted) * 0.9) - 1], 1),
            "max_ms": latencies_sorted[-1],
        }

    speed_stats = {}
    if speeds:
        speeds_sorted = sorted(speeds)
        speed_stats = {
            "avg_mbps": round(statistics.mean(speeds), 2),
            "median_mbps": round(statistics.median(speeds), 2),
            "p90_mbps": round(speeds_sorted[int(len(speeds_sorted) * 0.9) - 1], 2),
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
    tmp = meta_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(meta_file)
    print(f"Wrote {meta_file}")

    append_history(meta)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=OUT_DIR / "all.txt", help="Input proxy list")
    parser.add_argument("--host", default=TARGET_HOST, help="CONNECT target host")
    parser.add_argument("--target-port", type=int, default=TARGET_PORT, help="CONNECT target port")
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
