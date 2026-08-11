#!/usr/bin/env python3
"""Download, extract and organize the proxy IP list from zip.cm.edu.kg.

The upstream archive is a zip of TXT files organised as ``<port>/<country>.txt``,
where each file holds one IP per line.
"""

import argparse
import io
import ipaddress
import sys
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path

SOURCE_URL = "https://zip.cm.edu.kg"
ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw"
COUNTRIES_DIR = ROOT / "data" / "countries"
PORTS_DIR = ROOT / "data" / "ports"
OUT_DIR = ROOT / "data"


def download(url: str, timeout: int = 60) -> bytes:
    print(f"[1/3] Downloading {url} ...")
    req = urllib.request.Request(
        url, headers={"User-Agent": "proxyip-updater/1.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def is_valid_ip(line: str) -> bool:
    line = line.strip()
    if not line:
        return False
    try:
        ipaddress.ip_address(line)
        return True
    except ValueError:
        return False


def extract(content: bytes) -> dict:
    print("[2/3] Extracting zip ...")
    by_port: dict[str, dict[str, list[str]]] = defaultdict(dict)
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        for name in zf.namelist():
            if not name.endswith(".txt"):
                continue
            parts = name.split("/")
            if len(parts) != 2 or not parts[0].isdigit():
                continue
            port, country = parts
            if not country.endswith(".txt"):
                continue
            country = country[:-4]
            text = zf.read(name).decode("utf-8", errors="replace")
            ips = [line.strip() for line in text.splitlines() if is_valid_ip(line)]
            if ips:
                by_port[port][country] = sorted(set(ips))
    return by_port


def write_outputs(by_port: dict) -> dict:
    print("[3/3] Writing output files ...")
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    stats: dict[str, int] = {}
    total = 0
    for port, countries in sorted(by_port.items(), key=lambda kv: int(kv[0])):
        port_dir = RAW_DIR / port
        port_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        for country, ips in sorted(countries.items()):
            (port_dir / f"{country}.txt").write_text("\n".join(ips) + "\n")
            count += len(ips)
        stats[port] = count
        total += count

    for port_dir in RAW_DIR.iterdir():
        if not port_dir.is_dir():
            continue
        expected = {f"{c}.txt" for c in by_port.get(port_dir.name, {})}
        for stale in port_dir.iterdir():
            if stale.name not in expected:
                stale.unlink()
        if not any(port_dir.iterdir()):
            port_dir.rmdir()

    by_country: dict[str, set[str]] = defaultdict(set)
    for countries in by_port.values():
        for country, ips in countries.items():
            by_country[country].update(ips)
    COUNTRIES_DIR.mkdir(parents=True, exist_ok=True)
    for country in sorted(by_country):
        (COUNTRIES_DIR / f"{country}.txt").write_text(
            "\n".join(sorted(by_country[country])) + "\n"
        )
    expected_countries = {f"{c}.txt" for c in by_country}
    for stale in COUNTRIES_DIR.iterdir():
        if stale.name not in expected_countries:
            stale.unlink()

    by_port_all = {port: set().union(*countries.values()) for port, countries in by_port.items()}
    PORTS_DIR.mkdir(parents=True, exist_ok=True)
    for port in sorted(by_port_all, key=int):
        (PORTS_DIR / f"{port}.txt").write_text(
            "\n".join(sorted(by_port_all[port])) + "\n"
        )
    expected_ports = {f"{p}.txt" for p in by_port_all}
    for stale in PORTS_DIR.iterdir():
        if stale.name not in expected_ports:
            stale.unlink()

    all_ips = sorted(
        {ip for ports in by_port.values() for ips in ports.values() for ip in ips}
    )
    (OUT_DIR / "all.txt").write_text("\n".join(all_ips) + "\n")
    stats["__total__"] = total
    stats["__unique__"] = len(all_ips)
    stats["__countries__"] = len(by_country)
    stats["__ports__"] = len(by_port_all)
    return stats


def print_stats(stats: dict) -> None:
    print(f"\nTotal entries: {stats.pop('__total__')}")
    print(f"Unique IPs:    {stats.pop('__unique__')}")
    print(f"Countries:     {stats.pop('__countries__')}")
    print(f"Ports:         {stats.pop('__ports__')}")
    for port, count in sorted(stats.items(), key=lambda kv: int(kv[0])):
        print(f"  port {port}: {count}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-u", "--url", default=SOURCE_URL, help="Source archive URL"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=60, help="Download timeout (seconds)"
    )
    args = parser.parse_args(argv)

    try:
        content = download(args.url, timeout=args.timeout)
        by_port = extract(content)
        stats = write_outputs(by_port)
        print_stats(stats)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
