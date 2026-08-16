#!/usr/bin/env python3
"""Download, extract and organize the proxy list from zip.cm.edu.kg.

The primary source is the upstream ``all.json`` payload: a JSON array of
entries shaped ``{"ip", "port": [...], "meta": {clientIp, country, asn, ...}}``.
Entries are expanded into ``ip:port#country`` lines (e.g. ``1.2.3.4:443#US``)
and the per-IP metadata (actual exit ``clientIp``, ASN, geo, colo) is persisted
into ``data/upstream_meta.json`` for downstream consumers (e.g. the exit-family
cross-check in ``exit_family.py``).

If ``all.json`` is unreachable, the legacy zip archive of ``<port>/<country>.txt``
files is used as a fallback so scheduled runs never break.

A set of Cloudflare 反代 (reverse-proxy) sources from :data:`EXTRA_SOURCES` is
also fetched and merged (port/country bucket aware); entries without a country
tag get one via a best-effort ``ip-api.com/batch`` lookup (``#ALL`` otherwise).
Per-source failures are non-fatal and never break a scheduled run.

Each run also archives the added/removed entries versus the previous committed
list into ``data/diff/`` and records the change counts in ``data/history.jsonl``.
"""

import argparse
import io
import ipaddress
import json
import re
import subprocess
import sys
import time
import urllib.request
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SOURCE_URL = "https://zip.cm.edu.kg"
ALL_JSON_URL = SOURCE_URL + "/all.json"
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
    "hk_us_jp_sg_tw_kr": ["HK", "US", "JP", "SG", "TW", "KR"],
}

PER_COUNTRY_LIMIT = 20
HISTORY_FILE = ROOT / "data" / "history.jsonl"
MAX_HISTORY_RECORDS = 1000
DIFF_DIR = OUT_DIR / "diff"
MAX_DIFF_FILES = 500

# Cloudflare 反代 IP 补充来源：(解析方式, URL)。解析方式：
#   plain —— ``ip:port(#note)?`` 行（note 可为国家码或中文名）
#   ip    —— 裸 ``ip(#note)?`` 行（无端口，统一按 DEFAULT_EXTRA_PORT）
#   csv   —— ``IP,port,区域,延迟`` 表（区域为机场码或国家码）
EXTRA_SOURCES: list[tuple[str, str]] = [
    ("plain", "https://raw.githubusercontent.com/wentao883/TG-wxgqlfx_ZBDW/main/fdip.txt"),
    ("plain", "https://raw.githubusercontent.com/wentao883/TG-wxgqlfx_ZBDW/main/vlid.txt"),
    ("plain", "https://raw.githubusercontent.com/wentao883/TG-wxgqlfx_ZBDW/main/yxip.txt"),
    ("plain", "https://raw.githubusercontent.com/ChatBotPlus/cf-proxyips/main/list.txt"),
    ("ip", "https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestProxy/proxy.txt"),
    ("ip", "https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestProxy/bestproxy%26country.txt"),
    ("csv", "https://raw.githubusercontent.com/mountain787/Lunch-Bag-ip/main/proxyip.csv"),
]
DEFAULT_EXTRA_PORT = "443"
IPAPI_BATCH_URL = "http://ip-api.com/batch"
IPAPI_BATCH_SIZE = 100
IPAPI_BATCH_DELAY = 1.2

CN_COUNTRY_MAP: dict[str, str] = {
    "香港": "HK", "台湾": "TW", "中国": "CN", "澳门": "MO",
    "日本": "JP", "美国": "US", "英国": "GB", "德国": "DE",
    "法国": "FR", "荷兰": "NL", "韩国": "KR", "新加坡": "SG",
    "马来西亚": "MY", "泰国": "TH", "俄罗斯": "RU", "加拿大": "CA",
    "澳大利亚": "AU", "印度": "IN", "印度尼西亚": "ID", "越南": "VN",
    "菲律宾": "PH", "土耳其": "TR", "阿联酋": "AE", "以色列": "IL",
    "意大利": "IT", "西班牙": "ES", "瑞士": "CH", "瑞典": "SE",
    "挪威": "NO", "丹麦": "DK", "芬兰": "FI", "波兰": "PL",
    "乌克兰": "UA", "巴西": "BR", "墨西哥": "MX", "阿根廷": "AR",
    "南非": "ZA", "埃及": "EG", "尼日利亚": "NG", "新西兰": "NZ",
    "爱尔兰": "IE", "比利时": "BE", "葡萄牙": "PT", "奥地利": "AT",
    "希腊": "GR", "匈牙利": "HU", "捷克": "CZ", "罗马尼亚": "RO",
    "保加利亚": "BG", "哈萨克斯坦": "KZ", "乌兹别克斯坦": "UZ",
    "格鲁吉亚": "GE", "阿塞拜疆": "AZ", "亚美尼亚": "AM",
    "塞尔维亚": "RS", "冰岛": "IS", "卢森堡": "LU",
    "斯洛文尼亚": "SI", "克罗地亚": "HR", "立陶宛": "LT",
    "拉脱维亚": "LV", "爱沙尼亚": "EE", "沙特": "SA",
    "巴基斯坦": "PK", "孟加拉": "BD", "斯里兰卡": "LK",
    "缅甸": "MM", "柬埔寨": "KH", "中国香港": "HK", "中国台湾": "TW",
}

AIRPORT_COUNTRY_MAP: dict[str, str] = {
    "NRT": "JP", "HND": "JP", "KIX": "JP", "TYO": "JP", "OKA": "JP",
    "SIN": "SG", "HKG": "HK", "MFM": "MO",
    "HGH": "CN", "PKX": "CN", "PEK": "CN", "SHA": "CN", "PVG": "CN",
    "CAN": "CN", "SZX": "CN", "CTU": "CN",
    "ICN": "KR", "GMP": "KR", "TPE": "TW",
    "SJC": "US", "LAX": "US", "SFO": "US", "JFK": "US", "SEA": "US",
    "ORD": "US", "IAD": "US",
    "LHR": "GB", "FRA": "DE", "CDG": "FR", "AMS": "NL", "ZRH": "CH",
}


def fetch(url: str, timeout: int) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": "proxyip-updater/1.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def download(url: str, timeout: int = 60) -> bytes:
    print(f"[1/3] Downloading {url} ...")
    return fetch(url, timeout)


def is_valid_ip(line: str) -> bool:
    line = line.strip()
    if not line:
        return False
    try:
        ipaddress.ip_address(line)
        return True
    except ValueError:
        return False


def ip_sort_key(entry: str) -> tuple:
    """Numeric IPv4 order key for an ``ip:port#country`` (or bare ``ip``) entry."""
    ip = entry.split("#", 1)[0].rsplit(":", 1)[0]
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts))
    return (1, ip)


def normalize_country(note: str) -> str:
    """Normalize a ``#``-note to an ISO 3166-1 alpha-2 code, else ``"ALL"``.

    Accepts ``US`` / ``US-xxx`` / ``#香港`` / airport codes (``NRT``) and
    emoji-prefixed codes (``#🇺🇸US``). Non-mappable notes yield ``"ALL"`` so the
    country can be filled later by an IP-geo lookup.
    """
    if not note:
        return "ALL"
    tok = note.split("-", 1)[0].strip()
    up = tok.upper()
    if re.fullmatch(r"[A-Z]{2}", up):
        return up
    if up in AIRPORT_COUNTRY_MAP:
        return AIRPORT_COUNTRY_MAP[up]
    if tok in CN_COUNTRY_MAP:
        return CN_COUNTRY_MAP[tok]
    m = re.search(r"[A-Z]{2}$", tok)
    if m:
        return m.group(0)
    return "ALL"


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
                by_port[port][country] = sorted(set(ips), key=ip_sort_key)
    return by_port


META_KEYS = ("clientIp", "asn", "asOrganization", "country", "city", "region",
             "continent")


def extract_json(content: bytes) -> tuple[dict, dict]:
    """Parse the upstream ``all.json`` payload.

    Returns ``(by_port, meta_map)`` where ``by_port`` matches the structure of
    :func:`extract` (``by_port[port][country]`` = sorted set of bare IPs) and
    ``meta_map`` maps each proxy IP to a trimmed copy of its metadata with a
    derived ``family`` field ("ipv6" when the actual exit ``clientIp`` is an
    IPv6 address, otherwise "ipv4").
    """
    print("[2/3] Extracting all.json ...")
    payload = json.loads(content.decode("utf-8", errors="replace"))
    entries = payload.get("data")
    if not isinstance(entries, list):
        raise ValueError("all.json has no 'data' list")
    by_port: dict[str, dict[str, list[str]]] = defaultdict(dict)
    meta_map: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not is_valid_ip(entry.get("ip") or ""):
            continue
        ip = entry["ip"]
        meta = entry.get("meta")
        country = meta.get("country") if isinstance(meta, dict) else None
        if not isinstance(country, str) or not country:
            continue
        ports = entry.get("port")
        if not isinstance(ports, list):
            continue
        for port in ports:
            if not isinstance(port, int):
                continue
            by_port[str(port)].setdefault(country, []).append(ip)
        if isinstance(meta, dict):
            trimmed = {k: meta.get(k) for k in META_KEYS}
            client_ip = meta.get("clientIp")
            trimmed["family"] = "ipv6" if ":" in str(client_ip) else "ipv4"
            colo = meta.get("colo")
            trimmed["colo_iata"] = colo.get("iata") if isinstance(colo, dict) else None
            meta_map[ip] = trimmed
    for port in by_port:
        for country in by_port[port]:
            by_port[port][country] = sorted(set(by_port[port][country]),
                                            key=ip_sort_key)
    return by_port, meta_map


PLAIN_LINE_RE = re.compile(r"^\s*([0-9A-Fa-f:.]+):(\d{2,5})(?:#(\S*))?\s*$")
BARE_IP_RE = re.compile(r"^\s*([0-9A-Fa-f:.]+)(?:#(\S*))?\s*$")
CSV_LINE_RE = re.compile(
    r'^\s*"?\[?([0-9A-Fa-f:.]+)\]?"?\s*,\s*"?(\d{2,5})"?\s*(?:,\s*([^,\n]*))?'
)


def _decode(content) -> str:
    """UTF-8 decode bytes input (str passes through)."""
    return content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content


def extract_plain(content) -> dict:
    """Parse ``ip:port(#note)?`` lines into ``by_port[port][country]``."""
    by_port: dict[str, dict[str, list[str]]] = defaultdict(dict)
    text = _decode(content)
    for line in text.splitlines():
        m = PLAIN_LINE_RE.match(line)
        if not m:
            continue
        ip, port = m.group(1), m.group(2)
        if not is_valid_ip(ip):
            continue
        country = normalize_country(m.group(3))
        by_port[port].setdefault(country, []).append(ip)
    for port in by_port:
        for country in by_port[port]:
            by_port[port][country] = sorted(set(by_port[port][country]),
                                            key=ip_sort_key)
    return by_port


def extract_bare_ips(content, port: str = DEFAULT_EXTRA_PORT) -> dict:
    """Parse ``ip(#note)?`` lines into a single ``port`` bucket."""
    by_port: dict[str, dict[str, list[str]]] = defaultdict(dict)
    text = _decode(content)
    for line in text.splitlines():
        m = BARE_IP_RE.match(line)
        if not m:
            continue
        ip = m.group(1)
        if not is_valid_ip(ip):
            continue
        country = normalize_country(m.group(2))
        by_port[port].setdefault(country, []).append(ip)
    by_port[port] = {
        country: sorted(set(ips), key=ip_sort_key)
        for country, ips in by_port[port].items()
    }
    return by_port


def extract_csv_ports(content) -> dict:
    """Parse ``IP,port,区域,延迟`` rows (airport/country codes in region col)."""
    by_port: dict[str, dict[str, list[str]]] = defaultdict(dict)
    text = _decode(content)
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        m = CSV_LINE_RE.match(line)
        if not m:
            continue
        ip, port = m.group(1), m.group(2)
        if not is_valid_ip(ip):
            continue
        country = normalize_country(m.group(3))
        by_port[port].setdefault(country, []).append(ip)
    for port in by_port:
        for country in by_port[port]:
            by_port[port][country] = sorted(set(by_port[port][country]),
                                            key=ip_sort_key)
    return by_port


def merge_by_port(base: dict, extra: dict) -> dict:
    """Merge ``extra`` buckets into ``base``, dedup+sort within each (port, cc)."""
    for port, countries in extra.items():
        for country, ips in countries.items():
            base.setdefault(port, {}).setdefault(country, [])
            base[port][country] = sorted(set(base[port][country]) | set(ips),
                                         key=ip_sort_key)
    return base


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
            entries = sorted(
                (f"{ip}:{port}#{country}" for ip in ips), key=ip_sort_key
            )
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
    all_only: set[str] = set()
    for port, countries in by_port.items():
        for country, ips in countries.items():
            for ip in ips:
                line = f"{ip}:{port}#{country}"
                if country == "ALL":
                    all_only.add(line)
                    by_port_all[port].add(line)
                else:
                    by_country[country].add(line)
                    by_port_all[port].add(line)

    COUNTRIES_DIR.mkdir(parents=True, exist_ok=True)
    for country in sorted(by_country):
        (COUNTRIES_DIR / f"{country}.txt").write_text(
            "\n".join(sorted(by_country[country], key=ip_sort_key)) + "\n"
        )
    expected_countries = {f"{c}.txt" for c in by_country}
    for stale in COUNTRIES_DIR.iterdir():
        if stale.name not in expected_countries:
            stale.unlink()

    PORTS_DIR.mkdir(parents=True, exist_ok=True)
    for port in sorted(by_port_all, key=int):
        (PORTS_DIR / f"{port}.txt").write_text(
            "\n".join(sorted(by_port_all[port], key=ip_sort_key)) + "\n"
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
            cc_entries = sorted(by_country[cc], key=ip_sort_key)
            full_entries.update(cc_entries)
            if per_country_limit > 0:
                ltd_entries.update(cc_entries[:per_country_limit])
        full_entries = sorted(full_entries, key=ip_sort_key)
        (SETS_DIR / f"{name}.txt").write_text("\n".join(full_entries) + "\n")
        set_counts[name] = len(full_entries)
        if per_country_limit > 0:
            ltd_entries = sorted(ltd_entries, key=ip_sort_key)
            (SETS_DIR / f"{name}_ltd.txt").write_text("\n".join(ltd_entries) + "\n")
            set_counts[f"{name}_ltd"] = len(ltd_entries)
    expected_sets = {f"{n}.txt" for n in all_sets} | {f"{n}_ltd.txt" for n in all_sets}
    for stale in SETS_DIR.iterdir():
        if stale.name not in expected_sets:
            stale.unlink()

    all_entries = sorted(
        {e for entries in by_country.values() for e in entries} | all_only,
        key=ip_sort_key,
    )
    (OUT_DIR / "all.txt").write_text("\n".join(all_entries) + "\n")
    set_counts["all"] = len(all_entries)
    if per_country_limit > 0:
        all_ltd_entries = {
            e
            for cc in by_country
            for e in sorted(by_country[cc], key=ip_sort_key)[:per_country_limit]
        }
        all_ltd_entries.update(sorted(all_only, key=ip_sort_key)[:per_country_limit])
        (OUT_DIR / "all_ltd.txt").write_text(
            "\n".join(sorted(all_ltd_entries, key=ip_sort_key)) + "\n"
        )
        set_counts["all_ltd"] = len(all_ltd_entries)
    stats["__total__"] = total
    stats["__unique__"] = len(all_entries)
    stats["__countries__"] = len(by_country)
    stats["__ports__"] = len(by_port_all)
    stats["__sets__"] = set_counts
    return stats, all_entries


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


def load_previous_all() -> list[str] | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(ROOT), "show", "HEAD:data/all.txt"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def write_diff(previous: list[str] | None, current: list[str]) -> tuple[int, int]:
    DIFF_DIR.mkdir(parents=True, exist_ok=True)
    prev_set = set(previous) if previous is not None else set()
    current_set = set(current)
    added = sorted(current_set - prev_set, key=ip_sort_key)
    removed = sorted(prev_set - current_set, key=ip_sort_key)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = {
        "ts": ts,
        "added_count": len(added),
        "removed_count": len(removed),
        "added": added,
        "removed": removed,
    }

    def write(name: str, data: dict) -> None:
        tmp = DIFF_DIR / f"{name}.json.tmp"
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.replace(DIFF_DIR / f"{name}.json")

    write("latest", record)
    if added or removed:
        write(ts.replace(":", "-"), record)
        archives = sorted(
            (DIFF_DIR / p).name
            for p in DIFF_DIR.glob("*.json")
            if p.name != "latest.json"
        )
        for stale in archives[:-MAX_DIFF_FILES] if len(archives) > MAX_DIFF_FILES else []:
            (DIFF_DIR / stale).unlink()
    print(f"Diff: +{len(added)} added, -{len(removed)} removed")
    return len(added), len(removed)


def build_history_record(stats: dict, added: int = 0, removed: int = 0) -> dict:
    return {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": stats["__total__"],
        "unique": stats["__unique__"],
        "countries": stats["__countries__"],
        "ports": stats["__ports__"],
        "sets": stats["__sets__"],
        "added": added,
        "removed": removed,
    }


def append_history(record: dict) -> bool:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if HISTORY_FILE.exists():
        lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()
    if lines:
        try:
            last = json.loads(lines[-1])
            last.pop("ts", None)
            current = {k: v for k, v in record.items() if k != "ts"}
            if last == current:
                print("No data change; skipping history record")
                return False
        except (json.JSONDecodeError, KeyError):
            pass
    lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    lines = lines[-MAX_HISTORY_RECORDS:]
    tmp = HISTORY_FILE.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(HISTORY_FILE)
    print(f"Appended history record ({len(lines)} total, capped at {MAX_HISTORY_RECORDS})")
    return True


def write_upstream_meta(meta_map: dict) -> None:
    """Persist per-IP upstream metadata for downstream consumers."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    meta_file = OUT_DIR / "upstream_meta.json"
    tmp = meta_file.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(meta_map, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    tmp.replace(meta_file)
    print(f"Wrote upstream metadata for {len(meta_map)} IPs")


def load_source(url: str, timeout: int) -> tuple[dict, dict | None]:
    """Download the source, preferring ``all.json`` with a zip fallback.

    Returns ``(by_port, meta_map)``; ``meta_map`` is ``None`` when the legacy
    zip archive was used (no upstream metadata available).
    """
    if url == SOURCE_URL:
        for attempt in range(2):
            try:
                content = download(ALL_JSON_URL, timeout=timeout)
                return extract_json(content)
            except Exception as exc:  # noqa: BLE001
                if attempt == 0:
                    print(f"all.json attempt {attempt + 1} failed ({exc}); retrying",
                          file=sys.stderr)
                else:
                    print(f"all.json failed ({exc}); falling back to zip",
                          file=sys.stderr)
        content = download(SOURCE_URL, timeout=timeout)
        return extract(content), None
    content = download(url, timeout=timeout)
    if url.endswith(".json"):
        return extract_json(content)
    return extract(content), None


def lookup_countries(ips: list[str], timeout: int, delay: float) -> dict[str, str]:
    """Best-effort batch ``ip-api.com/batch`` countryCode lookup.

    Returns ``{ip: countryCode}``; stops at the first failed batch (the rest is
    left as ``ALL`` for later enrichment by the validation stage).
    """
    found: dict[str, str] = {}
    for start in range(0, len(ips), IPAPI_BATCH_SIZE):
        chunk = [{"query": ip} for ip in ips[start:start + IPAPI_BATCH_SIZE]]
        try:
            req = urllib.request.Request(
                IPAPI_BATCH_URL,
                data=json.dumps(chunk).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "proxyip-updater/1.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            for item in data:
                if isinstance(item, dict) and item.get("status") == "success":
                    q, cc = item.get("query"), item.get("countryCode")
                    if isinstance(q, str) and isinstance(cc, str) and cc:
                        found[q] = cc
        except Exception as exc:  # noqa: BLE001
            print(f"ip-api batch failed ({exc}); skipping country fill",
                  file=sys.stderr)
            break
        if start + IPAPI_BATCH_SIZE < len(ips):
            time.sleep(delay)
    return found


def enrich_countries(
    by_port: dict, extra_all_ips: set[str], timeout: int,
    delay: float = IPAPI_BATCH_DELAY,
) -> int:
    """Move extra-source ``ALL`` entries into their geo country bucket.

    Only IPs that came from an extra source (``extra_all_ips``) are enriched;
    primary-source ``ALL`` entries are left untouched. Returns the number of
    entries relocated.
    """
    if not extra_all_ips:
        return 0
    cc_map = lookup_countries(sorted(extra_all_ips), timeout=timeout, delay=delay)
    if not cc_map:
        return 0
    moved = 0
    for port in list(by_port):
        bucket = by_port[port]
        if "ALL" not in bucket:
            continue
        leftover: list[str] = []
        for ip in bucket["ALL"]:
            cc = cc_map.get(ip) if ip in extra_all_ips else None
            if cc:
                bucket.setdefault(cc, []).append(ip)
                moved += 1
            else:
                leftover.append(ip)
        if leftover:
            bucket["ALL"] = sorted(set(leftover), key=ip_sort_key)
        else:
            del bucket["ALL"]
        if not bucket:
            del by_port[port]
    for port in by_port:
        for country in by_port[port]:
            by_port[port][country] = sorted(set(by_port[port][country]),
                                            key=ip_sort_key)
    return moved


def load_extras(sources: list, timeout: int) -> tuple[dict, set[str]]:
    """Fetch and parse extra proxy sources; per-source failures are non-fatal.

    Returns ``(by_port, extra_all_ips)`` where ``extra_all_ips`` is the set of
    IPs that arrived without a country tag (candidates for geo enrichment).
    """
    by_port: dict = {}
    extra_all_ips: set[str] = set()
    if not sources:
        return by_port, extra_all_ips
    print(f"Downloading {len(sources)} extra source(s) ...")
    for kind, url in sources:
        try:
            content = fetch(url, timeout=timeout)
            if kind == "plain":
                part = extract_plain(content)
            elif kind == "ip":
                part = extract_bare_ips(content)
            elif kind == "csv":
                part = extract_csv_ports(content)
            else:
                print(f"Skipping unknown extra source kind {kind!r} ({url})",
                      file=sys.stderr)
                continue
            count = sum(len(v) for c in part.values() for v in c.values())
            print(f"Extra source {url}: {count} entries")
            for countries in part.values():
                extra_all_ips.update(countries.get("ALL", []))
            merge_by_port(by_port, part)
        except Exception as exc:  # noqa: BLE001
            print(f"Extra source {url} failed ({exc}); skipping",
                  file=sys.stderr)
    return by_port, extra_all_ips


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-u", "--url", default=SOURCE_URL,
        help="Source URL (default: upstream all.json with zip fallback)",
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
    parser.add_argument(
        "--extra-source", action="append", default=[], metavar="KIND,URL",
        help="Append an extra proxy source 'kind,url' (kind: plain|ip|csv); "
        "repeatable",
    )
    parser.add_argument(
        "--no-extra-sources", action="store_true",
        help="Skip the built-in extra CF reverse-proxy sources",
    )
    args = parser.parse_args(argv)

    extra_sources = list(EXTRA_SOURCES)
    if not args.no_extra_sources:
        for spec in args.extra_source:
            kind, sep, url = spec.partition(",")
            if not sep or not url or not kind:
                print(f"Ignoring malformed --extra-source {spec!r}",
                      file=sys.stderr)
                continue
            extra_sources.append((kind, url))
    if args.no_extra_sources:
        extra_sources = []

    try:
        by_port, meta_map = load_source(args.url, timeout=args.timeout)
        extra, extra_all_ips = load_extras(extra_sources, timeout=args.timeout)
        if extra:
            merge_by_port(by_port, extra)
            moved = enrich_countries(by_port, extra_all_ips, timeout=args.timeout)
            if moved:
                print(f"Filled country for {moved} extra-source IPs via ip-api")
        stats, all_entries = write_outputs(by_port, per_country_limit=args.per_country_limit)
        if meta_map is not None:
            write_upstream_meta(meta_map)
        previous = load_previous_all()
        added, removed = write_diff(previous, all_entries)
        append_history(build_history_record(stats, added, removed))
        print_stats(stats)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
