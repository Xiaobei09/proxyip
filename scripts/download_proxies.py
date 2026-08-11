#!/usr/bin/env python3
"""Download, extract and organize the proxy list from zip.cm.edu.kg.

The upstream archive is a zip of TXT files organised as ``<port>/<country>.txt``,
where each file holds one IP per line. Outputs are written in the
``ip:port#country`` format, e.g. ``1.2.3.4:443#US``.
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
SETS_DIR = ROOT / "data" / "sets"
OUT_DIR = ROOT / "data"

COUNTRY_SETS: dict[str, list[str]] = {
    "europe": [
        "AL", "AT", "BE", "BG", "BY", "CH", "CY", "CZ", "DE", "DK",
        "EE", "ES", "FI", "FR", "GB", "GR", "HR", "HU", "IE", "IS",
        "IT", "LT", "LV", "MD", "MK", "NL", "NO", "PL", "PT", "RO",
        "RS", "RU", "SE", "SI", "UA",
    ],
    "asia": [
        "AE", "AM", "AZ", "CN", "GE", "HK", "ID", "IL", "IN", "JP",
        "KH", "KR", "KZ", "MY", "PH", "SA", "SG", "TH", "TR", "TW",
        "UZ", "VN",
    ],
    "north_america": ["CA", "MX", "US", "VG"],
    "south_america": ["AR", "BR", "CL", "EC"],
    "oceania": ["AU", "NZ"],
    "africa": ["EG", "NG", "ZA"],
    "middle_east": ["AE", "IL", "SA", "TR"],
    "hot": ["AU", "CA", "DE", "FR", "GB", "HK", "JP", "KR", "NL", "SG", "TW", "US", "RU"],
}

SMALL_SETS: dict[str, list[str]] = {
    "cn_common": [
        "HK", "TW", "SG", "JP", "KR",
        "US", "DE", "GB", "FR", "NL",
        "RU", "CA", "AU",
    ],
}

PER_COUNTRY_LIMIT = 20


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


def write_outputs(by_port: dict, per_country_limit: int = PER_COUNTRY_LIMIT) -> dict:
    print("[3/3] Writing output files ...")
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    stats: dict[str, int] = {}
    total = 0
    for port, countries in sorted(by_port.items(), key=lambda kv: int(kv[0])):
        port_dir = RAW_DIR / port
        port_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        for country, ips in sorted(countries.items()):
            entries = sorted(f"{ip}:{port}#{country}" for ip in ips)
            (port_dir / f"{country}.txt").write_text("\n".join(entries) + "\n")
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
    by_port_all: dict[str, set[str]] = defaultdict(set)
    for port, countries in by_port.items():
        for country, ips in countries.items():
            if country == "ALL":
                continue
            for ip in ips:
                by_country[country].add(f"{ip}:{port}#{country}")
                by_port_all[port].add(f"{ip}:{port}#{country}")

    COUNTRIES_DIR.mkdir(parents=True, exist_ok=True)
    for country in sorted(by_country):
        (COUNTRIES_DIR / f"{country}.txt").write_text(
            "\n".join(sorted(by_country[country])) + "\n"
        )
    expected_countries = {f"{c}.txt" for c in by_country}
    for stale in COUNTRIES_DIR.iterdir():
        if stale.name not in expected_countries:
            stale.unlink()

    PORTS_DIR.mkdir(parents=True, exist_ok=True)
    for port in sorted(by_port_all, key=int):
        (PORTS_DIR / f"{port}.txt").write_text(
            "\n".join(sorted(by_port_all[port])) + "\n"
        )
    expected_ports = {f"{p}.txt" for p in by_port_all}
    for stale in PORTS_DIR.iterdir():
        if stale.name not in expected_ports:
            stale.unlink()

    SETS_DIR.mkdir(parents=True, exist_ok=True)
    set_counts: dict[str, int] = {}
    all_sets = {**COUNTRY_SETS, **SMALL_SETS}
    for name, countries in all_sets.items():
        full_entries: set[str] = set()
        ltd_entries: set[str] = set()
        for cc in countries:
            if cc not in by_country:
                continue
            cc_entries = sorted(by_country[cc])
            full_entries.update(cc_entries)
            if per_country_limit > 0:
                ltd_entries.update(cc_entries[:per_country_limit])
        full_entries = sorted(full_entries)
        (SETS_DIR / f"{name}.txt").write_text("\n".join(full_entries) + "\n")
        set_counts[name] = len(full_entries)
        if per_country_limit > 0:
            ltd_entries = sorted(ltd_entries)
            (SETS_DIR / f"{name}_ltd.txt").write_text("\n".join(ltd_entries) + "\n")
            set_counts[f"{name}_ltd"] = len(ltd_entries)
    expected_sets = {f"{n}.txt" for n in all_sets} | {f"{n}_ltd.txt" for n in all_sets}
    for stale in SETS_DIR.iterdir():
        if stale.name not in expected_sets:
            stale.unlink()

    all_entries = sorted({e for entries in by_country.values() for e in entries})
    (OUT_DIR / "all.txt").write_text("\n".join(all_entries) + "\n")
    set_counts["all"] = len(all_entries)
    if per_country_limit > 0:
        all_ltd_entries = sorted(
            {
                e
                for cc in by_country
                for e in sorted(by_country[cc])[:per_country_limit]
            }
        )
        (OUT_DIR / "all_ltd.txt").write_text("\n".join(all_ltd_entries) + "\n")
        set_counts["all_ltd"] = len(all_ltd_entries)
    stats["__total__"] = total
    stats["__unique__"] = len(all_entries)
    stats["__countries__"] = len(by_country)
    stats["__ports__"] = len(by_port_all)
    stats["__sets__"] = set_counts
    return stats


def print_stats(stats: dict) -> None:
    print(f"\nTotal entries: {stats.pop('__total__')}")
    print(f"Unique proxies: {stats.pop('__unique__')}")
    print(f"Countries:     {stats.pop('__countries__')}")
    print(f"Ports:         {stats.pop('__ports__')}")
    set_counts = stats.pop("__sets__")
    for port, count in sorted(stats.items(), key=lambda kv: int(kv[0])):
        print(f"  port {port}: {count}")
    print("Sets:")
    for name, count in set_counts.items():
        print(f"  {name}: {count}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-u", "--url", default=SOURCE_URL, help="Source archive URL"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=60, help="Download timeout (seconds)"
    )
    parser.add_argument(
        "--per-country-limit",
        type=int,
        default=PER_COUNTRY_LIMIT,
        help="Max entries per country in small sets (0 = unlimited)",
    )
    args = parser.parse_args(argv)

    try:
        content = download(args.url, timeout=args.timeout)
        by_port = extract(content)
        stats = write_outputs(by_port, per_country_limit=args.per_country_limit)
        print_stats(stats)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
