#!/usr/bin/env python3
"""Download, extract and organize the proxy list from zip.cm.edu.kg.

The primary source is the upstream ``all.json`` payload: a JSON array of
entries shaped ``{"ip", "port": [...], "meta": {clientIp, country, asn, ...}}``.
Entries are expanded into ``ip:port#country`` lines (e.g. ``1.2.3.4:443#US``)
and the per-IP metadata (actual exit ``clientIp``, ASN, geo, colo) is persisted
into ``data/quality/upstream_meta.json`` for downstream consumers (e.g. the exit-family
cross-check in ``exit_family.py``).

If ``all.json`` is unreachable, the legacy zip archive of ``<port>/<country>.txt``
files is used as a fallback so scheduled runs never break.

A set of Cloudflare 反代 (reverse-proxy) sources from :data:`EXTRA_SOURCES`
is also fetched and merged (port/country bucket aware); entries without a country
tag get one via a best-effort ``ip-api.com/batch`` lookup (``#ALL`` otherwise).
The merged pool is constrained to the Cloudflare edge ports :data:`CF_EDGE_PORTS`
(``443/8443/2053/2083/2087/2096``) and excludes Cloudflare-owned AS13335 IPs,
so the output doubles as a non-Cloudflare connection pool usable from
``connect()`` inside Cloudflare Workers (where connecting to CF IP ranges is
blocked). Per-source failures are non-fatal and never break a scheduled run.

Each run also archives the added/removed entries versus the previous committed
list into ``data/diff/`` and records the change counts in ``data/quality/history.jsonl``.
"""

import argparse
import concurrent.futures
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

from common import (
    ALL_FILE,
    ALL_LTD_FILE,
    COUNTRIES_DIR,
    DIFF_DIR,
    HISTORY_FILE,
    IPAPI_BATCH_URL,
    IPAPI_BATCH_SIZE,
    IPAPI_BATCH_DELAY,
    IP_SOURCES_FILE,
    MAX_DIFF_FILES,
    MAX_HISTORY_RECORDS,
    PER_COUNTRY_LIMIT,
    PORTS_DIR,
    RAW_DIR,
    ROOT,
    SETS_DIR,
    SOURCE_HISTORY_FILE,
    SOURCE_HISTORY_MAX,
    SOURCE_STATS_FILE,
    UPSTREAM_META_FILE,
    fetch_with_mirror,
    read_json,
    write_text_if_changed,
)

SOURCE_URL = "https://zip.cm.edu.kg"
ALL_JSON_URL = SOURCE_URL + "/all.json"

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

# Cloudflare 反代 IP 补充来源：(解析方式, URL)。解析方式：
#   plain —— ``ip:port(#note)?`` 行（note 可为国家码或中文名）
#   ip    —— 裸 ``ip(#note)?`` 行（无端口，统一按 DEFAULT_EXTRA_PORT）
#   csv   —— ``IP,port,区域,延迟`` 表（区域为机场码或国家码）
#   json  —— ``all.json`` 格式镜像（``{"data":[{"ip","port","meta"}]}``，
#            缺失国家字段的条目归入 ALL；容忍畸形载荷）
#
# 维护目标是「非 Cloudflare AS13335 + Cloudflare 边缘常用端口」的可直连
# 连接池（用于 Cloudflare Worker `connect()` 等自建链路）。因此：不收录
# Cloudflare 官方边缘 IP（AS13335，Workers 出站 TCP 禁止连接 CF IP 网段）。
EXTRA_SOURCES: list[tuple[str, str]] = [
    ("plain", "https://raw.githubusercontent.com/wentao883/TG-wxgqlfx_ZBDW/main/fdip.txt"),
    ("plain", "https://raw.githubusercontent.com/wentao883/TG-wxgqlfx_ZBDW/main/vlid.txt"),
    ("plain", "https://raw.githubusercontent.com/wentao883/TG-wxgqlfx_ZBDW/main/yxip.txt"),
    ("plain", "https://raw.githubusercontent.com/ChatBotPlus/cf-proxyips/main/list.txt"),
    ("ip", "https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestProxy/proxy.txt"),
    ("ip", "https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestProxy/bestproxy%26country.txt"),
    ("ip", "https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestProxy/bestproxy.txt"),
    ("ip", "https://ipdb.api.030101.xyz/?type=proxy"),
    ("csv", "https://raw.githubusercontent.com/mountain787/Lunch-Bag-ip/main/proxyip.csv"),
]
# Cloudflare 边缘常用端口（非 AS13335 反代/IP 直连时常用）。
# 全链路输出只保留这些端口，其余桶一律丢弃。
CF_EDGE_PORTS = frozenset({"443", "8443", "2053", "2083", "2087", "2096"})
DEFAULT_EXTRA_PORT = "443"

SOURCE_LABELS: dict[str, str] = {
    "https://ipdb.api.030101.xyz/?type=proxy": "ipdb_proxy",
    "https://ipdb.api.030101.xyz/?type=bestproxy": "ipdb_bestproxy",
}


# ``all.json``/``all.zip``/``all.txt`` 等通用清单名会被多个镜像共用，仅取
# 文件名主干会产生 ``all`` 碰撞（互覆 stats/归属/健康监控）。此时用
# 注册域作前缀消歧（如 ``mirror-a/all``、``mirror-b/all``）；其余来源
# 保持文件名主干，避免破坏既有 source_stats / 健康历史的标签连续性。
_GENERIC_STEMS = frozenset({"all", "data", "index", "output", "proxylist"})
_GENERIC_HOST_SUFFIXES = (".co.uk", ".com", ".net", ".org", ".co", ".io",
                          ".xyz", ".cc", ".kg", ".jp", ".cn")


def _registrable_host(url: str) -> str:
    """``https://sub.mirror-a.com/...`` -> 注册域主干（剥掉常见 TLD+二级）。"""
    from urllib.parse import urlsplit
    host = (urlsplit(url).hostname or "").lower()
    for suffix in _GENERIC_HOST_SUFFIXES:
        if host.endswith(suffix) and host != suffix:
            host = host[: -len(suffix)]
            break
    return host or "mirror"


def source_label(url: str) -> str:
    """可读的源标签：镜像/列表 URL 用显式映射，其余取文件名主干。

    通用清单名（``all.json``/``all.zip``/``all.txt`` 等）加注册域前缀消歧，
    避免不同镜像共用 ``all`` 标签导致 stats/归属/健康监控互覆。
    """
    if url in SOURCE_LABELS:
        return SOURCE_LABELS[url]
    stem = url.rsplit("/", 1)[-1].split(".")[0] if "/" in url else url
    if stem in _GENERIC_STEMS and "/" in url:
        return f"{_registrable_host(url)}/{stem}"
    return stem


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
    """Fetch bytes; raw.githubusercontent.com URLs fall back to CN mirrors."""
    return fetch_with_mirror(
        url, timeout, headers={"User-Agent": "proxyip-updater/1.0"}
    )


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


def _parse_all_json_entries(
    content: bytes, require_country: bool = True,
) -> tuple[dict, dict]:
    """Parse an ``all.json`` payload into ``(by_port, meta_map)``.

    ``by_port`` matches :func:`extract` (``by_port[port][country]`` = sorted
    set of bare IPs) and ``meta_map`` maps each proxy IP to a trimmed copy of
    its metadata with a derived ``family`` field ("ipv6" when the actual exit
    ``clientIp`` is an IPv6 address, otherwise "ipv4").

    When ``require_country`` is False (extra-source mirrors), entries missing a
    usable ``meta.country`` are bucketed under ``ALL`` instead of dropped, so
    country-less mirrors still contribute to pool coverage.
    """
    payload = json.loads(content.decode("utf-8", errors="replace"))
    entries = payload.get("data")
    if not isinstance(entries, list):
        return {}, {}
    by_port: dict[str, dict[str, list[str]]] = defaultdict(dict)
    meta_map: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not is_valid_ip(entry.get("ip") or ""):
            continue
        ip = entry["ip"]
        meta = entry.get("meta")
        country = meta.get("country") if isinstance(meta, dict) else None
        if not isinstance(country, str) or not country:
            if require_country:
                continue
            country = "ALL"
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
            trimmed["family"] = "ipv6" if isinstance(client_ip, str) and ":" in client_ip else "ipv4"
            colo = meta.get("colo")
            trimmed["colo_iata"] = colo.get("iata") if isinstance(colo, dict) else None
            meta_map[ip] = trimmed
    for port in by_port:
        for country in by_port[port]:
            by_port[port][country] = sorted(set(by_port[port][country]),
                                            key=ip_sort_key)
    return by_port, meta_map


def extract_json(content: bytes) -> tuple[dict, dict]:
    """Parse the upstream ``all.json`` payload into ``(by_port, meta_map)``.

    Mirrors :func:`_parse_all_json_entries` but requires every entry to carry a
    usable ``meta.country`` (the curated upstream always does), raising when the
    payload has no ``data`` list.
    """
    print("[2/3] Extracting all.json ...")
    payload = json.loads(content.decode("utf-8", errors="replace"))
    if not isinstance(payload.get("data"), list):
        raise ValueError("all.json has no 'data' list")
    return _parse_all_json_entries(content, require_country=True)


def extract_json_extra(content: bytes) -> dict:
    """Parse an extra-source ``all.json`` mirror into ``by_port`` only.

    Tolerant variant: entries without ``meta.country`` fall back to ``ALL``
    (rather than being dropped) so country-less mirrors still widen coverage;
    malformed payloads return an empty result instead of raising.
    """
    try:
        by_port, _meta = _parse_all_json_entries(content, require_country=False)
    except (ValueError, json.JSONDecodeError):
        return {}
    return by_port


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
    """Merge ``extra`` buckets into ``base``, dedup+sort within each (port, cc).

    After merging, any ``ALL`` entry whose IP already exists on the same port
    with a known country is dropped (the tagged entry is authoritative). This
    keeps ``ALL`` buckets free of duplicates regardless of merge order and
    avoids pointless geo lookups for them. Returns ``base``.
    """
    for port, countries in extra.items():
        for country, ips in countries.items():
            base.setdefault(port, {}).setdefault(country, [])
            base[port][country] = sorted(set(base[port][country]) | set(ips),
                                         key=ip_sort_key)
    for port in base:
        if "ALL" not in base[port]:
            continue
        known = {
            ip for country, ips in base[port].items()
            if country != "ALL" for ip in ips
        }
        if known:
            base[port]["ALL"] = sorted(set(base[port]["ALL"]) - known,
                                       key=ip_sort_key)
        if not base[port]["ALL"]:
            del base[port]["ALL"]
    return base


def write_outputs(by_port: dict, per_country_limit: int = PER_COUNTRY_LIMIT) -> tuple[dict, set]:
    print("[3/3] Writing output files ...")
    # 只维护 Cloudflare 边缘常用端口：其余端口桶（来自 zip 回退或 extra 源
    # 的普通代理端口）一律丢弃，保证产物可作 Worker connect() 连接池。
    by_port = {
        port: countries for port, countries in by_port.items()
        if port in CF_EDGE_PORTS
    }
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
            write_text_if_changed(port_dir / f"{country}.txt", "\n".join(entries) + "\n")
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
        write_text_if_changed(
            COUNTRIES_DIR / f"{country}.txt",
            "\n".join(sorted(by_country[country], key=ip_sort_key)) + "\n",
        )
    expected_countries = {f"{c}.txt" for c in by_country}
    for stale in COUNTRIES_DIR.iterdir():
        if stale.name not in expected_countries:
            stale.unlink()

    PORTS_DIR.mkdir(parents=True, exist_ok=True)
    for port in sorted(by_port_all, key=int):
        write_text_if_changed(
            PORTS_DIR / f"{port}.txt",
            "\n".join(sorted(by_port_all[port], key=ip_sort_key)) + "\n",
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
        write_text_if_changed(SETS_DIR / f"{name}.txt", "\n".join(full_entries) + "\n")
        set_counts[name] = len(full_entries)
        if per_country_limit > 0:
            ltd_entries = sorted(ltd_entries, key=ip_sort_key)
            write_text_if_changed(SETS_DIR / f"{name}_ltd.txt", "\n".join(ltd_entries) + "\n")
            set_counts[f"{name}_ltd"] = len(ltd_entries)
    expected_sets = {f"{n}.txt" for n in all_sets} | {f"{n}_ltd.txt" for n in all_sets}
    for stale in SETS_DIR.iterdir():
        if stale.name not in expected_sets:
            stale.unlink()

    all_entries = sorted(
        {e for entries in by_country.values() for e in entries} | all_only,
        key=ip_sort_key,
    )
    write_text_if_changed(ALL_FILE, "\n".join(all_entries) + "\n")
    set_counts["all"] = len(all_entries)
    if per_country_limit > 0:
        all_ltd_entries = {
            e
            for cc in by_country
            for e in sorted(by_country[cc], key=ip_sort_key)[:per_country_limit]
        }
        all_ltd_entries.update(sorted(all_only, key=ip_sort_key)[:per_country_limit])
        write_text_if_changed(
            ALL_LTD_FILE, "\n".join(sorted(all_ltd_entries, key=ip_sort_key)) + "\n"
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
            ["git", "-C", str(ROOT), "show", "HEAD:data/download/all.txt"],
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
        write_text_if_changed(
            DIFF_DIR / f"{name}.json",
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        )

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
    lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    lines = lines[-MAX_HISTORY_RECORDS:]
    tmp = HISTORY_FILE.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(HISTORY_FILE)
    print(f"Appended history record ({len(lines)} total, capped at {MAX_HISTORY_RECORDS})")
    return True


def write_upstream_meta(meta_map: dict) -> None:
    """Persist per-IP upstream metadata for downstream consumers.

    Stored as ``{"proxies": {...}}`` (keyed schema, consistent with the other
    data JSON files).
    """
    write_text_if_changed(
        UPSTREAM_META_FILE,
        json.dumps(
            {"proxies": meta_map}, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
        + "\n",
    )
    print(f"Wrote upstream metadata for {len(meta_map)} IPs")


def write_source_attribution(
    by_port: dict,
    main_ips: set[str],
    source_ip_sets: dict[str, set[str]],
) -> None:
    """Persist per-IP download source attribution.

    Builds a ``{ip:port#CC: source_label}`` mapping from the final merged
    ``by_port`` structure and the per-source IP sets, then writes it to
    :data:`IP_SOURCES_FILE`.

    Source labels: ``"main"`` for the primary upstream, or the extra-source
    filename stem (e.g. ``"fdip"``, ``"proxy"``); generic ``all.json``-style
    mirrors are host-disambiguated (e.g. ``mirror-a/all``).  IPs appearing
    in multiple extra sources are labelled ``"multi"``.
    """
    # Map bare IP → list of extra source labels that contributed it
    ip_extra_labels: dict[str, list[str]] = {}
    for url, ips in source_ip_sets.items():
        label = source_label(url)
        for ip in ips:
            ip_extra_labels.setdefault(ip, []).append(label)

    ip_source_map: dict[str, str] = {}
    for port, countries in by_port.items():
        for country, ips in countries.items():
            for ip in ips:
                key = f"{ip}:{port}#{country}"
                if ip in main_ips:
                    ip_source_map[key] = "main"
                elif ip in ip_extra_labels:
                    labels = ip_extra_labels[ip]
                    ip_source_map[key] = labels[0] if len(labels) == 1 else "multi"
                else:
                    ip_source_map[key] = "unknown"

    write_text_if_changed(
        IP_SOURCES_FILE,
        json.dumps(
            {"sources": ip_source_map},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n",
    )
    print(f"Wrote source attribution for {len(ip_source_map)} entries")


def _fetch_retry(url: str, timeout: int, attempts: int) -> bytes:
    """Download ``url`` with linear-backoff retries; raise on final failure."""
    for attempt in range(attempts):
        try:
            return download(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            if attempt == attempts - 1:
                raise
            print(
                f"{url} attempt {attempt + 1}/{attempts} failed ({exc}); "
                f"retrying in {1.5 * (attempt + 1):.1f}s",
                file=sys.stderr,
            )
            time.sleep(1.5 * (attempt + 1))


def load_source(url: str, timeout: int) -> tuple[dict, dict | None]:
    """Download the source, preferring ``all.json`` with a zip fallback.

    Returns ``(by_port, meta_map)``; ``meta_map`` is ``None`` when the legacy
    zip archive was used (no upstream metadata available).
    """
    if url == SOURCE_URL:
        try:
            content = _fetch_retry(ALL_JSON_URL, timeout, attempts=3)
            return extract_json(content)
        except Exception as exc:  # noqa: BLE001
            print(f"all.json failed ({exc}); falling back to zip",
                  file=sys.stderr)
        content = _fetch_retry(SOURCE_URL, timeout, attempts=3)
        return extract(content), None
    if url.endswith(".json"):
        return extract_json(_fetch_retry(url, timeout, attempts=3))
    return extract(_fetch_retry(url, timeout, attempts=2)), None


def lookup_countries(ips: list[str], timeout: int, delay: float) -> dict[str, str]:
    """Best-effort batch ``ip-api.com/batch`` countryCode lookup.

    Returns ``{ip: countryCode}``. 每批单独重试 ``retries`` 次（线性退避），
    终失败只跳过该批继续后续批次（网络抖动时不至于整源放弃国籍填充）。
    """
    found: dict[str, str] = {}
    fields = ["status", "query", "countryCode"]
    for start in range(0, len(ips), IPAPI_BATCH_SIZE):
        chunk = [
            {"query": ip, "fields": fields}
            for ip in ips[start:start + IPAPI_BATCH_SIZE]
        ]
        seen: list | None = None
        retries = 2
        for attempt in range(retries + 1):
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
                    seen = json.loads(
                        resp.read().decode("utf-8", errors="replace")
                    )
                break
            except Exception as exc:  # noqa: BLE001
                if attempt == retries:
                    print(
                        f"ip-api batch @{start} failed ({exc}); skipping "
                        f"country fill for {len(chunk)} IPs",
                        file=sys.stderr,
                    )
                else:
                    time.sleep(delay * (attempt + 1))
        if not isinstance(seen, list):
            continue
        for item in seen:
            if isinstance(item, dict) and item.get("status") == "success":
                q, cc = item.get("query"), item.get("countryCode")
                if isinstance(q, str) and isinstance(cc, str) and cc:
                    found[q] = cc
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
    still_all = {
        ip for countries in by_port.values() for ip in countries.get("ALL", [])
    }
    to_lookup = extra_all_ips & still_all
    cc_map = lookup_countries(sorted(to_lookup), timeout=timeout, delay=delay)
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


def _fetch_extra_retry(url: str, timeout: int, attempts: int = 2) -> bytes:
    """Fetch an extra source with a bounded number of retries.

    Mirrors already chain on ``raw.githubusercontent.com``; this adds a
    restart on transient failures so a single hiccup (e.g. the keyless IPDB
    API having no mirror path) doesn't drop a whole source for a round.
    """
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            return fetch(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            last = exc
            if attempt < attempts - 1:
                time.sleep(1.0 * (attempt + 1))
    raise last  # type: ignore[misc]


def load_extras(
    sources: list, timeout: int
) -> tuple[dict, set[str], dict[str, set[str]]]:
    """Fetch and parse extra proxy sources in parallel; per-source failures are
    non-fatal.

    Returns ``(by_port, extra_all_ips, source_ip_sets)`` where
    ``extra_all_ips`` is the set of IPs that arrived without a country tag
    (candidates for geo enrichment) and ``source_ip_sets`` maps each source
    URL to the set of IPs it contributed.
    """
    by_port: dict = {}
    extra_all_ips: set[str] = set()
    source_ip_sets: dict[str, set[str]] = {}
    if not sources:
        return by_port, extra_all_ips, source_ip_sets

    def parse_source(kind: str, url: str) -> dict:
        content = _fetch_extra_retry(url, timeout=timeout)
        if kind == "plain":
            return extract_plain(content)
        if kind == "ip":
            return extract_bare_ips(content)
        if kind == "csv":
            return extract_csv_ports(content)
        if kind == "json":
            return extract_json_extra(content)
        print(f"Skipping unknown extra source kind {kind!r} ({url})",
              file=sys.stderr)
        return {}

    def collect_ips(by_port_data: dict) -> set[str]:
        ips: set[str] = set()
        for countries in by_port_data.values():
            for country_ips in countries.values():
                ips.update(country_ips)
        return ips

    print(f"Downloading {len(sources)} extra source(s) ...")
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(len(sources), 4)
    ) as pool:
        futures = {
            pool.submit(parse_source, kind, url): (kind, url)
            for kind, url in sources
        }
        for future in concurrent.futures.as_completed(futures):
            kind, url = futures[future]
            try:
                part = future.result()
                if not part:
                    continue
                count = sum(len(v) for c in part.values() for v in c.values())
                print(f"Extra source {url}: {count} entries")
                source_ip_sets[url] = collect_ips(part)
                merge_by_port(by_port, part)
            except Exception as exc:  # noqa: BLE001
                print(f"Extra source {url} failed ({exc}); skipping",
                      file=sys.stderr)
    for countries in by_port.values():
        extra_all_ips.update(countries.get("ALL", []))
    return by_port, extra_all_ips, source_ip_sets


def _collect_all_ips(by_port: dict) -> set[str]:
    """Return the set of all IPs across all (port, country) buckets."""
    ips: set[str] = set()
    for countries in by_port.values():
        for country_ips in countries.values():
            ips.update(country_ips)
    return ips


def _build_source_stats(
    main_ips: set[str],
    source_ip_sets: dict[str, set[str]],
    all_ips: set[str],
) -> dict:
    """Compute per-source IP counts, duplicates and availability.

    ``all_ips`` is the final merged IP set (from ``by_port`` after all merges).
    """
    all_sets = [main_ips] + list(source_ip_sets.values())

    # Count how many sources each IP appears in
    ip_count: dict[str, int] = {}
    for s in all_sets:
        for ip in s:
            ip_count[ip] = ip_count.get(ip, 0) + 1
    overlap_ips = {ip for ip, c in ip_count.items() if c > 1}

    stats: dict[str, dict] = {}
    stats["main (zip.cm.edu.kg)"] = {
        "total": len(main_ips),
        "unique": len(main_ips - overlap_ips),
        "overlap": len(main_ips & overlap_ips),
    }
    for url, ips in source_ip_sets.items():
        label = source_label(url)
        stats[label] = {
            "total": len(ips),
            "unique": len(ips - overlap_ips),
            "overlap": len(ips & overlap_ips),
        }
    return stats


def _append_source_history(ts: str, counts: dict[str, int]) -> None:
    """追加本轮各上游源的 unique 数到 ``source_history.json``（供健康告警）。

    保留最近 ``SOURCE_HISTORY_MAX`` 轮；内容不变时不重写。
    """
    history: list = []
    if SOURCE_HISTORY_FILE.exists():
        existing = read_json(SOURCE_HISTORY_FILE)
        history = list((existing or {}).get("runs", []))
    history.append({"ts": ts, "counts": dict(sorted(counts.items()))})
    history = history[-SOURCE_HISTORY_MAX:]
    write_text_if_changed(
        SOURCE_HISTORY_FILE,
        json.dumps({"runs": history}, ensure_ascii=False, separators=(",", ":"))
        + "\n",
    )


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
        try:
            by_port, meta_map = load_source(args.url, timeout=args.timeout)
        except Exception as exc:  # noqa: BLE001
            print(
                f"Primary source failed ({exc}); proceeding with extra sources "
                "only",
                file=sys.stderr,
            )
            by_port, meta_map = {}, None
        main_ips = _collect_all_ips(by_port)
        extra, extra_all_ips, source_ip_sets = load_extras(
            extra_sources, timeout=args.timeout
        )
        if extra:
            merge_by_port(by_port, extra)
            moved = enrich_countries(by_port, extra_all_ips, timeout=args.timeout)
            if moved:
                print(f"Filled country for {moved} extra-source IPs via ip-api")
        # 空池保护：所有来源都拿不到代理时拒绝覆写（避免把既有连接池清空）。
        if not any(by_port.values()):
            raise RuntimeError(
                "no proxies from any source; refusing to truncate the pool"
            )
        all_ips = _collect_all_ips(by_port)
        source_stats = _build_source_stats(main_ips, source_ip_sets, all_ips)
        src_stats_file = SOURCE_STATS_FILE
        write_text_if_changed(
            src_stats_file,
            json.dumps(
                {"sources": source_stats},
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
        _append_source_history(
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            {label: int(stats["unique"]) for label, stats in source_stats.items()},
        )
        print(f"Wrote {src_stats_file} ({len(source_stats)} sources)")
        stats, all_entries = write_outputs(by_port, per_country_limit=args.per_country_limit)
        write_source_attribution(by_port, main_ips, source_ip_sets)
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
