#!/usr/bin/env python3
"""Multi-source IP reputation / risk scoring (extracted from quality_check.py).

Each source yields a 0-100 cleanliness signal merged by ``REPUTATION_WEIGHTS``
into a single reputation score; static lists (torlist / FireHOL abuse / iplogs
ASN lists) are re-fetched every run, per-IP API signals are cached in
``reputation_cache.json`` with a TTL. Imported by ``quality_check``.
"""

import argparse
import asyncio
import ipaddress
import json
import logging
import re
import sys
import time
import urllib.parse
import urllib.request
from bisect import bisect_right
from pathlib import Path

from common import *  # noqa: F401,F403  (paths, UA, write_json, keyed_json, ...)

REP_RISK_HIGH = 30
REP_RISK_MEDIUM = 75

REP_WORKERS = 10
REP_DELAY = 0.15
CACHEABLE_SOURCES = frozenset((
    "netcoffee",
    "ncgy",
    "ipdata",
    "getipintel",
    "ipapi_is",
    "ipquery",
    "ffraud",
    "whatismyip",
))
NETCOFFEE_URL = "https://ip.net.coffee/api/iprisk/{ip}"
NETCOFFEE_TIMEOUT = 12
NCGY_URL = "https://ip.nc.gy/json?ip={ip}"
NCGY_TIMEOUT = 12
IPDATA_URL = "https://ipdata.info/json/{ip}"
IPDATA_TIMEOUT = 8
IPDATA_CAP = 2000
GETIPINTEL_URL = (
    "https://check.getipintel.net/check.php?ip={ip}"
    "&contact={email}&flags=m"
)
GETIPINTEL_TIMEOUT = 8
GETIPINTEL_CAP = 2000
IPAPI_IS_URL = "https://api.ipapi.is/?q={ip}"
IPAPI_IS_TIMEOUT = 8
IPQUERY_URL = "https://api.ipquery.io/{ip}"
IPQUERY_TIMEOUT = 8
FFRAUD_URL = "https://api.ffraud.com/public/ip/{ip}"
FFRAUD_TIMEOUT = 8
WHATISMYIP_URL = "https://whatismyip.ai/api/lookup/{ip}"
WHATISMYIP_TIMEOUT = 8
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
STATIC_LIST_SCORES = {
    "abuse_list": 60,   # is_abuse（历史滥用，强信号）
    "ipsum": 55,        # is_listed（3+ 黑名单交叉确认）
    "dc_asn": 85,       # is_hosting（机房/数据中心）
    "vpn_asn": 70,      # is_vpn
    "resproxy_asn": 75, # is_proxy（住宅代理骨干）
}
REPUTATION_WEIGHTS = {
    "netcoffee": 20,
    "ncgy": 10,
    "ip-api": 15,
    "ipquery": 12,
    "ffraud": 12,
    "blackbox": 10,
    "otx": 8,
    "ipsum": 8,
    "ipapi_is": 8,
    "ipdata": 8,
    "whatismyip": 3,
    "dc_asn": 5,
    "abuse_list": 5,
    "torlist": 5,
    "getipintel": 5,
    "vpn_asn": 3,
    "resproxy_asn": 2,
}
DEFAULT_REP_SOURCES = (
    "netcoffee", "ncgy", "ip-api", "ipquery", "ffraud",
    "blackbox", "otx", "ipsum",
    "ipapi_is", "ipdata", "whatismyip", "dc_asn",
    "abuse_list", "torlist", "vpn_asn", "resproxy_asn",
)
SOURCE_PACING = {
    "netcoffee": (10, 0.15),
    "ncgy": (10, 0.15),
    "blackbox": (8, 0.2),
    "otx": (6, 0.3),
    "ipapi_is": (8, 0.2),
    "ipquery": (6, 0.2),
    "ffraud": (6, 0.2),
    "whatismyip": (6, 0.2),
}
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
        for j in range(idx, -1, -1):
            if int(self._nets[j].network_address) > int(addr):
                break
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
        return {"clean": True}
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


BLACKBOX_URL = "https://blackbox.ipinfo.app/api/v3beta/{}"
BLACKBOX_TIMEOUT = 8


def blackbox_lookup_sync(ip: str) -> dict | None:
    """Blackbox v3beta classification + signal flags."""
    req = urllib.request.Request(
        BLACKBOX_URL.format(ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=BLACKBOX_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict) or not data.get("classification"):
        return None
    return {
        "classification": data.get("classification"),
        "confidence": data.get("confidence"),
        "suspicious": bool(data.get("suspicious")),
        "signals": data.get("signals") or {},
    }


OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general"
OTX_TIMEOUT = 8


def otx_lookup_sync(ip: str) -> dict | None:
    """AlienVault OTX reputation score + pulse count."""
    req = urllib.request.Request(
        OTX_URL.format(ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=OTX_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict):
        return None
    return {
        "reputation": int(data.get("reputation") or 0),
        "pulse_count": int((data.get("pulse_info") or {}).get("count") or 0),
        "validation": data.get("validation") or [],
    }


IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"


async def fetch_ipsum_list() -> set[str]:
    """IPsum level 3+ blacklist (IPs listed in 3+ blocklists)."""
    return await fetch_text_list(IPSUM_URL)


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
        except Exception as exc:
            logging.debug("torlist fetch %s: %s", url, exc)
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
    except Exception as exc:
        logging.debug("fetch_text_list %s: %s", url, exc)
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
    retries: int = 1,
) -> dict:
    """Run ``fn(ip)`` over unique IPs with a concurrency semaphore + pacing."""
    items = list(dict.fromkeys(ips))
    if cap > 0:
        items = items[:cap]
    sem = asyncio.Semaphore(workers)
    out: dict = {}
    failed: list[str] = []

    async def work(ip: str) -> None:
        async with sem:
            try:
                res = await asyncio.to_thread(fn, ip)
            except Exception as exc:
                logging.debug("batch_sync: %s failed: %s", ip, exc)
                res = None
        if res is not None:
            out[ip] = res
            await asyncio.sleep(delay)
        else:
            failed.append(ip)

    await asyncio.gather(*(work(ip) for ip in items))
    for _attempt in range(retries):
        if not failed:
            break
        retry_list = list(failed)
        failed.clear()
        await asyncio.sleep(1.0)
        await asyncio.gather(*(work(ip) for ip in retry_list))
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
        bonus = 0
        if signal.get("proxy"):
            penalty += IPAPI_PROXY_PENALTY
        if signal.get("hosting"):
            penalty += IPAPI_HOSTING_PENALTY
        if signal.get("mobile"):
            bonus += 10
        return max(0, min(100, 100 - penalty + bonus))
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
    if name == "blackbox":
        cls = signal.get("classification", "")
        cls_scores = {
            "tor": 10, "hosting": 60, "vpn": 55, "privacy_relay": 50,
            "mobile": 90, "residential": 95, "business": 85,
            "bogon": 5, "unknown": 50,
        }
        score = cls_scores.get(cls, 50)
        if signal.get("suspicious"):
            score = max(0, score - 20)
        return max(0, min(100, score))
    if name == "otx":
        rep = int(signal.get("reputation") or 0)
        pulses = int(signal.get("pulse_count") or 0)
        penalty = min(rep * 5, 80) + min(pulses * 2, 20)
        return max(0, min(100, 100 - penalty))
    if name in STATIC_LIST_SCORES:
        flag = {
            "abuse_list": "is_abuse",
            "ipsum": "is_listed",
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
        except Exception as exc:
            logging.debug("abuse lookup %s: %s", ip, exc)
        await asyncio.sleep(0.3)
    abuse_map: dict[str, dict] = {}
    for key, info in ipinfo.items():
        item = by_ip.get(info.get("exit_ip"))
        if item:
            entry = dict(item)
            entry["risk"] = derive_risk({}, item, args.reputation_weights)
            abuse_map[key] = entry
    return abuse_map


def load_rep_cache() -> dict:
    """Load the reputation signal cache; corrupt/missing files read as empty."""
    try:
        data = json.loads(REP_CACHE_FILE.read_text(encoding="utf-8"))
        proxies = data.get("proxies") or {}
        return {ip: e for ip, e in proxies.items() if isinstance(e, dict)}
    except (OSError, ValueError, TypeError):
        return {}


def save_rep_cache(cache: dict) -> None:
    write_json(REP_CACHE_FILE, keyed_json(cache))


def cached_signal(
    cache: dict, ip: str, source: str, now: float, ttl: int
) -> dict | None:
    """Fresh cached signal for ``ip``/``source``, else ``None``.

    Cache format: ``{ip: {source: {"ts": float, "data": dict}}}``.
    Each source has its own timestamp for independent TTL tracking.
    """
    if ttl <= 0:
        return None
    entry = cache.get(ip, {})
    src_entry = entry.get(source)
    if not isinstance(src_entry, dict):
        return None
    if (src_entry.get("ts") or 0) + ttl < now:
        return None
    return src_entry.get("data") if isinstance(src_entry.get("data"), dict) else None


async def lookup_all_risk(
    ips: list, args: argparse.Namespace, asn_map: dict | None = None
) -> dict:
    """Query all enabled reputation sources; ``{ip: {source: signal}}``.

    Per-IP API source signals are served from ``REP_CACHE_FILE`` when still
    fresh (``--rep-cache-ttl``); only missing/expired IPs are re-queried.
    Static-list signals (torlist/abuse/ASN lists) are re-computed every run.
    """
    sources = args.reputation_sources
    if not sources:
        return {}
    risk_data: dict[str, dict] = {}

    def put(name: str, ip: str, signal) -> None:
        risk_data.setdefault(ip, {})[name] = signal

    cache_ttl = 0 if args.no_rep_cache else args.rep_cache_ttl
    cache = load_rep_cache() if cache_ttl else {}
    now = time.time()
    uniq = list(dict.fromkeys(ips))

    async def cached_batch(
        name: str, fn, cap: int = 0, workers: int = REP_WORKERS,
        delay: float = REP_DELAY,
    ) -> None:
        """Fill from fresh cache, query only missing/expired IPs, cache back."""
        need = []
        for ip in uniq:
            sig = cached_signal(cache, ip, name, now, cache_ttl)
            if sig is not None:
                put(name, ip, sig)
            else:
                need.append(ip)
        res = await batch_sync(
            need, fn, cap=cap, workers=workers, delay=delay
        )
        for ip, sig in res.items():
            put(name, ip, sig)
            entry = cache.setdefault(ip, {})
            entry[name] = {"ts": now, "data": sig}

    pacing = SOURCE_PACING
    api_tasks = []
    if "netcoffee" in sources:
        w, d = pacing.get("netcoffee", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("netcoffee", netcoffee_lookup_sync, workers=w, delay=d))
    if "ncgy" in sources:
        w, d = pacing.get("ncgy", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ncgy", ncgy_lookup_sync, workers=w, delay=d))
    if "ipdata" in sources:
        api_tasks.append(cached_batch(
            "ipdata", ipdata_lookup_sync, cap=IPDATA_CAP, workers=2, delay=0.8
        ))
    if "getipintel" in sources:
        if args.getipintel_email:
            fn = lambda ip: getipintel_lookup_sync(ip, args.getipintel_email)
            api_tasks.append(cached_batch(
                "getipintel", fn, cap=GETIPINTEL_CAP, workers=1, delay=4
            ))
        else:
            print(
                "Warning: GETIPINTEL_EMAIL not set; skipping getipintel source",
                file=sys.stderr,
            )
    if "ipapi_is" in sources:
        w, d = pacing.get("ipapi_is", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ipapi_is", ipapi_is_lookup_sync, workers=w, delay=d))
    if "ipquery" in sources:
        w, d = pacing.get("ipquery", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ipquery", ipquery_lookup_sync, workers=w, delay=d))
    if "ffraud" in sources:
        w, d = pacing.get("ffraud", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ffraud", ffraud_lookup_sync, workers=w, delay=d))
    if "whatismyip" in sources:
        w, d = pacing.get("whatismyip", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("whatismyip", whatismyip_lookup_sync, workers=w, delay=d))
    if "blackbox" in sources:
        w, d = pacing.get("blackbox", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("blackbox", blackbox_lookup_sync, workers=w, delay=d))
    if "otx" in sources:
        w, d = pacing.get("otx", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("otx", otx_lookup_sync, workers=w, delay=d))
    if api_tasks:
        await asyncio.gather(*api_tasks)
    if "torlist" in sources:
        tor = await fetch_torlist()
        for ip in uniq:
            if ip in tor:
                put("torlist", ip, {"is_tor": True})
    if "ipsum" in sources:
        ipsum_set = await fetch_ipsum_list()
        for ip in uniq:
            if ip in ipsum_set:
                put("ipsum", ip, {"is_listed": True})
    static = await fetch_static_lists(sources)
    for ip in uniq:
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
    if cache_ttl:
        pruned = {}
        for ip, entry in cache.items():
            fresh = {}
            for src, src_entry in entry.items():
                if isinstance(src_entry, dict) and \
                   (src_entry.get("ts") or 0) + cache_ttl >= now:
                    fresh[src] = src_entry
            if fresh:
                pruned[ip] = fresh
        save_rep_cache(pruned)
    return risk_data

