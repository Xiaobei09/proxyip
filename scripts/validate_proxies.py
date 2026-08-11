#!/usr/bin/env python3
"""Validate proxy reachability and measure latency.

Reads ``data/all.txt`` (``ip:port#country`` lines) and checks each proxy.
Two checks are performed, in order:

1. HTTP CONNECT tunnel to a target host (works for standard proxies).
2. TLS handshake to the proxy itself (works for Cloudflare edge proxies,
   which serve TLS on 443/8443/2053/2083/2087/2096 but reject plain CONNECT).

Outputs are written under ``data/valid/`` mirroring the structure of
``data/``, keeping the ``ip:port#country`` format.
"""

import argparse
import concurrent.futures
import json
import socket
import ssl
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from download_proxies import (
    COUNTRY_SETS,
    COUNTRIES_DIR,
    OUT_DIR,
    PER_COUNTRY_LIMIT,
    PORTS_DIR,
    SETS_DIR,
    SMALL_SETS,
)

VALID_DIR = OUT_DIR / "valid"
VALID_HISTORY_FILE = VALID_DIR / "history.jsonl"
MAX_HISTORY_RECORDS = 1000

TARGET_HOST = "www.gstatic.com"
TARGET_PORT = 443
TARGET_SNI = "cdnjs.cloudflare.com"
TIMEOUT = 5
WORKERS = 100


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def try_connect(sock: socket.socket, host: str, target_port: int, timeout: int) -> bool:
    req = (
        f"CONNECT {host}:{target_port} HTTP/1.1\r\n"
        f"Host: {host}:{target_port}\r\n"
        "Proxy-Connection: Keep-Alive\r\n\r\n"
    )
    sock.sendall(req.encode("ascii"))
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return False
        buf += chunk
    status_line = buf.split(b"\r\n", 1)[0]
    return b" 200 " in status_line


def check_proxy(
    ip: str, port: str, timeout: int, host: str, target_port: int, sni: str
) -> tuple[str, float] | None:
    started = time.monotonic()

    def elapsed() -> float:
        return round((time.monotonic() - started) * 1000, 1)

    try:
        sock = socket.create_connection((ip, int(port)), timeout=timeout)
    except (OSError, socket.timeout, ValueError):
        return None
    try:
        sock.settimeout(timeout)
        try:
            if try_connect(sock, host, target_port, timeout):
                return "connect", elapsed()
        except (OSError, socket.timeout):
            pass
    finally:
        sock.close()

    try:
        sock = socket.create_connection((ip, int(port)), timeout=timeout)
        sock.settimeout(timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=sni):
            pass
        return "tls", elapsed()
    except (OSError, socket.timeout, ssl.SSLError, ValueError):
        return None
    finally:
        try:
            sock.close()
        except (OSError, NameError):
            pass


def write_valid_outputs(
    alive: dict[str, tuple[str, str, float]],
    per_country_limit: int,
) -> dict:
    VALID_DIR.mkdir(parents=True, exist_ok=True)

    by_country: dict[str, set[str]] = defaultdict(set)
    by_port: dict[str, set[str]] = defaultdict(set)
    for entry, (ip, port, country, _ms) in alive.items():
        by_country[country].add(entry)
        by_port[port].add(entry)

    countries_dir = VALID_DIR / "countries"
    ports_dir = VALID_DIR / "ports"
    sets_dir = VALID_DIR / "sets"
    countries_dir.mkdir(parents=True, exist_ok=True)
    ports_dir.mkdir(parents=True, exist_ok=True)
    sets_dir.mkdir(parents=True, exist_ok=True)

    for country in sorted(by_country):
        (countries_dir / f"{country}.txt").write_text(
            "\n".join(sorted(by_country[country])) + "\n"
        )
    expected_countries = {f"{c}.txt" for c in by_country}
    for stale in countries_dir.iterdir():
        if stale.name not in expected_countries:
            stale.unlink()

    for port in sorted(by_port, key=int):
        (ports_dir / f"{port}.txt").write_text(
            "\n".join(sorted(by_port[port])) + "\n"
        )
    expected_ports = {f"{p}.txt" for p in by_port}
    for stale in ports_dir.iterdir():
        if stale.name not in expected_ports:
            stale.unlink()

    set_counts: dict[str, int] = {}
    for name, countries in {**COUNTRY_SETS, **SMALL_SETS}.items():
        full: set[str] = set()
        ltd: set[str] = set()
        for cc in countries:
            if cc not in by_country:
                continue
            cc_entries = sorted(by_country[cc])
            full.update(cc_entries)
            if per_country_limit > 0:
                ltd.update(cc_entries[:per_country_limit])
        (sets_dir / f"{name}.txt").write_text("\n".join(sorted(full)) + "\n")
        set_counts[name] = len(full)
        if per_country_limit > 0:
            (sets_dir / f"{name}_ltd.txt").write_text("\n".join(sorted(ltd)) + "\n")
            set_counts[f"{name}_ltd"] = len(ltd)
    expected_sets = {f"{n}.txt" for n in {**COUNTRY_SETS, **SMALL_SETS}} | {
        f"{n}_ltd.txt" for n in {**COUNTRY_SETS, **SMALL_SETS}
    }
    for stale in sets_dir.iterdir():
        if stale.name not in expected_sets:
            stale.unlink()

    all_entries = sorted(alive)
    (VALID_DIR / "all.txt").write_text("\n".join(all_entries) + "\n")
    set_counts["all"] = len(all_entries)
    if per_country_limit > 0:
        ltd_all = sorted(
            {e for cc in by_country for e in sorted(by_country[cc])[:per_country_limit]}
        )
        (VALID_DIR / "all_ltd.txt").write_text("\n".join(ltd_all) + "\n")
        set_counts["all_ltd"] = len(ltd_all)
    return {
        "__countries__": len(by_country),
        "__ports__": len(by_port),
        "__sets__": set_counts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=OUT_DIR / "all.txt", help="Input proxy list")
    parser.add_argument("--host", default=TARGET_HOST, help="CONNECT target host")
    parser.add_argument("--target-port", type=int, default=TARGET_PORT, help="CONNECT target port")
    parser.add_argument("--sni", default=TARGET_SNI, help="TLS SNI used for the handshake check")
    parser.add_argument("-t", "--timeout", type=int, default=TIMEOUT, help="Per-proxy timeout (seconds)")
    parser.add_argument("-w", "--workers", type=int, default=WORKERS, help="Concurrent workers")
    parser.add_argument("--limit", type=int, default=0, help="Max proxies to check (0 = all)")
    parser.add_argument("--time-budget", type=int, default=0, help="Stop after this many seconds (0 = unlimited)")
    parser.add_argument("--per-country-limit", type=int, default=PER_COUNTRY_LIMIT, help="Limit for _ltd outputs")
    args = parser.parse_args(argv)

    if not args.source.exists():
        print(f"Error: {args.source} not found", file=sys.stderr)
        return 1

    entries = parse_entries(args.source.read_text(encoding="utf-8").splitlines())
    if args.limit > 0:
        entries = entries[: args.limit]
    total = len(entries)
    print(f"Checking {total} proxies (timeout={args.timeout}s, workers={args.workers}) ...")

    alive: dict[str, tuple[str, str, str, float]] = {}
    by_method: dict[str, int] = {}
    checked = 0
    started = time.monotonic()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                check_proxy, ip, port, args.timeout, args.host, args.target_port, args.sni
            ): (ip, port, cc)
            for ip, port, cc in entries
        }
        try:
            for future in concurrent.futures.as_completed(futures):
                checked += 1
                ip, port, cc = futures[future]
                result = future.result()
                if result is not None:
                    method, latency = result
                    alive[f"{ip}:{port}#{cc}"] = (ip, port, cc, latency)
                    by_method[method] = by_method.get(method, 0) + 1
                if args.time_budget and (time.monotonic() - started) >= args.time_budget:
                    for f in futures:
                        f.cancel()
                    break
        except KeyboardInterrupt:
            for f in futures:
                f.cancel()
            print("\nInterrupted", file=sys.stderr)
            return 130

    elapsed = time.monotonic() - started
    dead = checked - len(alive)
    latencies = [ms for _, _, _, ms in alive.values()]
    print(
        f"Checked {checked}/{total} in {elapsed:.1f}s: alive={len(alive)}, dead={dead}"
        f" ({dict(by_method)})"
    )

    stats = write_valid_outputs(alive, args.per_country_limit)

    lat_stats = {}
    if latencies:
        latencies_sorted = sorted(latencies)
        lat_stats = {
            "avg_ms": round(statistics.mean(latencies), 1),
            "median_ms": round(statistics.median(latencies), 1),
            "p90_ms": round(latencies_sorted[int(len(latencies_sorted) * 0.9) - 1], 1),
            "max_ms": latencies_sorted[-1],
        }

    per_country: dict[str, int] = {}
    per_port: dict[str, int] = {}
    for _, (_, port, cc, _) in alive.items():
        per_country[cc] = per_country.get(cc, 0) + 1
        per_port[port] = per_port.get(port, 0) + 1

    meta = {
        "ts": now_ts(),
        "total": total,
        "checked": checked,
        "alive": len(alive),
        "dead": dead,
        "by_method": dict(sorted(by_method.items())),
        "latency": lat_stats,
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

    (OUT_DIR / "valid").mkdir(exist_ok=True)
    return 0


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
