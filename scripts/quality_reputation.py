#!/usr/bin/env python3
"""Multi-source IP reputation / risk scoring (extracted from quality_check.py).

Each source yields a 0-100 cleanliness signal merged by ``REPUTATION_WEIGHTS``
into a single reputation score; static lists (FireHOL abuse / iplogs
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
import urllib.error
import urllib.parse
import urllib.request
from bisect import bisect_right

from common import *  # noqa: F401,F403  (paths, UA, write_json, keyed_json, ...)

REP_CACHE_MAX = 40000   # 信誉缓存 IP 上限（防无限膨胀，超出按最近使用裁剪）
REP_RISK_HIGH = 30
REP_RISK_MEDIUM = 75

REP_WORKERS = 10
REP_DELAY = 0.15
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
IPWHOIS_URL = "https://ipwhois.app/json/{ip}"
IPWHOIS_TIMEOUT = 8
FIREHOL_ABUSERS_URL = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/"
    "master/firehol_abusers_1d.netset"
)
DC_ASN_URL = "https://iplogs.com/data/datacenter-asns.csv"
VPN_ASN_URL = "https://iplogs.com/data/vpn-providers.csv"
RESPROXY_ASN_URL = "https://iplogs.com/data/residential-proxy-backbones.csv"
TOR_EXITS_URL = "https://check.torproject.org/exit-addresses"
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"
FREEIPAPI_URL = "https://freeipapi.com/api/json/{ip}"
FREEIPAPI_TIMEOUT = 10
HACKMYIP_URL = "https://hackmyip.com/api/lookup?ip={ip}"
HACKMYIP_TIMEOUT = 10
SCAMALYTICS_URL = "https://scamalytics.com/ip/{ip}"
SCAMALYTICS_TIMEOUT = 12
SCAMALYTICS_CAP = 1500
IPLOCATION_URL = "https://api.iplocation.net/?ip={ip}"
IPLOCATION_TIMEOUT = 10
IPLOCATION_CAP = 3000
FREEIPAPI_CAP = 3000
CINS_BADGUYS_URL = "https://cinsscore.com/list/ci-badguys.txt"
ET_COMPROMISED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
DAN_TOR_URL = "https://www.dan.me.uk/torlist"
TOR_BULK_URL = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1&port=443"
BLOCKLIST_DE_URL = "https://lists.blocklist.de/lists/all.txt"
BLOCKLIST_DE_SSH_URL = "https://lists.blocklist.de/lists/ssh.txt"
BLOCKLIST_DE_APACHE_URL = "https://lists.blocklist.de/lists/apache.txt"
GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"
GREYNOISE_TIMEOUT = 8
URLLAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"
FIREHOL_LEVEL1_URL = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/"
    "master/firehol_level1.netset"
)
BINARYDEFENSE_URL = "https://www.binarydefense.com/banlist.txt"
SCAMALYTICS_SCORE_RE = re.compile(r"Fraud Score:\s*(\d+)\b")
SCAMALYTICS_BLACKLIST_RE = re.compile(r'"is_blacklisted_external"\s*:\s*(true|false)')
STATIC_LIST_TIMEOUT = 15
ABUSER_SCORE_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)")
ABUSER_SCORE_THRESHOLD = 0.1
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
PROXYCHECK_FLAG_PENALTIES = {
    "is_proxy": 45,
    "is_vpn": 45,
    "is_tor": 45,
    "is_hosting": 30,
    "is_scraper": 20,
}
IP2LOCATION_FLAG_PENALTIES = {
    "is_proxy": 30,
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
IPWHOIS_FLAG_PENALTIES = {
    "anonymous": 10,
    "proxy": 25,
    "vpn": 30,
    "tor": 45,
    "hosting": 15,
}
GREYNOISE_FLAG_PENALTIES = {
    "is_abuse": 60,   # classification=malicious（观察到的恶意扫描）
    "is_bot": 35,     # riot=true（僵尸网络成员）
    "is_noise": 15,   # 噪音扫描（低危但具干扰性）
}
STATIC_LIST_SCORES = {
    "abuse_list": 60,   # is_abuse（历史滥用，强信号）
    "ipsum": 55,        # is_listed（3+ 黑名单交叉确认）
    "dc_asn": 85,       # is_hosting（机房/数据中心）
    "vpn_asn": 70,      # is_vpn
    "resproxy_asn": 75, # is_proxy（住宅代理骨干）
    "tor_exit": 45,     # is_tor（Tor 出口节点实时列表）
    "spamhaus": 55,     # is_listed（Spamhaus DROP/EDROP 端用户高风险网段）
    "cins": 50,         # is_listed（CINS Army 活跃滥用/拒绝服务 IP）
    "et_compromised": 45,  # is_abuse（EmergingThreats 被入侵主机回连）
    "feodo": 40,         # is_abuse（Feodo 僵尸网络 C2）
    "blocklist_de": 50,  # is_abuse（blocklist.de 僵尸/暴力破解滥用）
    "blocklist_de_ssh": 45,  # is_abuse（SSH 暴力破解源）
    "blocklist_de_apache": 45,  # is_abuse（Web 探测/攻击源）
    "danmeuk_tor": 40,   # is_tor（dan.me.uk Tor 节点，覆盖更全）
    "tor_bulk": 35,      # is_tor（Tor 出口冗余源）
    "urlhaus": 55,       # is_abuse（abuse.ch URLhaus 恶意软件分发托管）
    "threatfox": 55,     # is_abuse（abuse.ch ThreatFox 恶意软件 IOC/C2）
    "firehol_level1": 60,  # is_listed（FireHOL 最严封禁集）
    "binarydefense": 55,   # is_abuse（Binary Defense 恶意 IP 封禁集）
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
    "getipintel": 5,
    "proxycheck": 12,
    "ip2location": 5,
    "vpn_asn": 3,
    "resproxy_asn": 2,
    "ipwhois": 6,
    "tor_exit": 5,
    "spamhaus": 4,
    "freeipapi": 6,
    "hackmyip": 6,
    "scamalytics": 8,
    "iplocation": 3,
    "cins": 5,
    "et_compromised": 4,
    "feodo": 4,
    "blocklist_de": 4,
    "blocklist_de_ssh": 3,
    "blocklist_de_apache": 3,
    "danmeuk_tor": 5,
    "tor_bulk": 4,
    "greynoise": 8,
    "urlhaus": 5,
    "threatfox": 5,
    "firehol_level1": 5,
    "binarydefense": 4,
}
DEFAULT_REP_SOURCES = (
    "netcoffee", "ncgy", "ip-api", "ipquery", "ffraud",
    "blackbox", "otx", "ipsum",
    "ipapi_is", "ipdata", "whatismyip", "dc_asn",
    "abuse_list", "vpn_asn", "resproxy_asn",
    "proxycheck", "ip2location", "ipwhois",
    "tor_exit", "spamhaus",
    "freeipapi", "scamalytics", "iplocation",
    "hackmyip",
    "cins", "et_compromised", "feodo",
    "blocklist_de", "blocklist_de_ssh", "blocklist_de_apache",
    "danmeuk_tor", "tor_bulk",
    "greynoise", "urlhaus", "threatfox",
    "firehol_level1", "binarydefense",
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
    "proxycheck": (8, 0.2),
    "ip2location": (6, 0.2),
    "ipwhois": (6, 0.2),
    "freeipapi": (8, 0.15),
    "hackmyip": (6, 0.2),
    "scamalytics": (4, 0.5),
    "iplocation": (8, 0.12),
    "greynoise": (6, 0.3),
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
            net = self._nets[j]
            if int(net.network_address) + net.num_addresses <= int(addr):
                break
            if addr in net:
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


def greynoise_lookup_sync(ip: str) -> dict | None:
    """GreyNoise Community (keyless) — noise/riot/malicious-scan signal.

    干净/未观测 IP 返回 HTTP 404 但体为 JSON（``{"noise":false,...}``），
    已知扫描者返回 200 且带 ``classification``；两者均解析为信号。
    """
    out: dict = {"is_noise": False, "is_riot": False, "is_malicious": False}
    req = urllib.request.Request(
        GREYNOISE_URL.format(ip=ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=GREYNOISE_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            try:
                data = json.loads(exc.read().decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001
                return None
        else:
            return None
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(data, dict):
        return None
    out["is_noise"] = bool(data.get("noise"))
    out["is_riot"] = bool(data.get("riot"))
    classification = data.get("classification")
    if isinstance(classification, str):
        out["classification"] = classification.lower()
        if classification.lower() == "malicious":
            out["is_abuse"] = True
    if not any(v for k, v in out.items() if k != "classification"):
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


async def fetch_cins_badguys() -> IpSet:
    """CINS Army ``ci-badguys.txt`` 活跃滥用/拒绝服务 IP（单行空白分隔）。"""
    rows: set[str] = set()
    for line in await fetch_text_list(CINS_BADGUYS_URL):
        rows.update(line.split())
    return IpSet(rows)


async def fetch_et_compromised() -> IpSet:
    """EmergingThreats ``compromised-ips.txt`` 被入侵主机（单行空白分隔）。"""
    rows: set[str] = set()
    for line in await fetch_text_list(ET_COMPROMISED_URL):
        rows.update(line.split())
    return IpSet(rows)


async def fetch_feodo() -> IpSet:
    """abuse.ch Feodo Tracker 僵尸网络 C2 IP（``ipblocklist.txt``，单行空白分隔）。"""
    rows: set[str] = set()
    for line in await fetch_text_list(FEODO_URL):
        rows.update(line.split())
    return IpSet(rows)


async def fetch_dan_tor() -> IpSet:
    """dan.me.uk Tor 节点列表（比 check.torproject 覆盖更全，独立权威）。"""
    rows: set[str] = set()
    for line in await fetch_text_list(DAN_TOR_URL):
        rows.update(line.split())
    return IpSet(rows)


async def fetch_tor_bulk() -> IpSet:
    """check.torproject.org TorBulkExitList（出口节点，作为 tor 信号冗余）。"""
    rows: set[str] = set()
    for line in await fetch_text_list(TOR_BULK_URL):
        rows.update(line.split())
    return IpSet(rows)


async def fetch_blocklist_de() -> IpSet:
    """blocklist.de 全集（僵尸/暴力破解/扫描，独立滥用源）。"""
    rows: set[str] = set()
    for line in await fetch_text_list(BLOCKLIST_DE_URL):
        rows.update(line.split())
    return IpSet(rows)


async def fetch_blocklist_de_ssh() -> IpSet:
    """blocklist.de SSH 暴力破解源 IP（独立攻击类别）。"""
    rows: set[str] = set()
    for line in await fetch_text_list(BLOCKLIST_DE_SSH_URL):
        rows.update(line.split())
    return IpSet(rows)


async def fetch_blocklist_de_apache() -> IpSet:
    """blocklist.de Apache 探测/攻击源 IP（独立攻击类别）。"""
    rows: set[str] = set()
    for line in await fetch_text_list(BLOCKLIST_DE_APACHE_URL):
        rows.update(line.split())
    return IpSet(rows)


async def fetch_urlhaus() -> IpSet:
    """abuse.ch URLhaus 恶意软件分发托管（``csv_recent``，URL 主机 IP 聚合）。"""
    rows = list(await fetch_text_list(URLLAUS_URL))
    ips: set[str] = set()
    for row in rows:
        if row.startswith("```") or ("`" in row and "```" in row):
            continue
        parts = [p.strip().strip('"') for p in row.split(",")]
        if len(parts) < 3 or parts[0].lower() in ("id",):
            continue
        url = parts[2]
        try:
            host = urllib.parse.urlsplit(url).hostname or ""
        except ValueError:  # pragma: no cover
            continue
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue
        ips.add(host)
    return IpSet(ips)


async def fetch_threatfox() -> IpSet:
    """abuse.ch ThreatFox 恶意软件 IOC/C2（``json/recent``，ip:port/url/ipv4 取值）。"""
    try:
        text = await asyncio.to_thread(
            lambda: fetch_with_mirror(
                THREATFOX_URL, STATIC_LIST_TIMEOUT, headers={"User-Agent": UA}
            ).decode("utf-8", errors="replace")
        )
    except Exception as exc:  # noqa: BLE001
        logging.warning("fetch threatfox failed open: %s", exc)
        return IpSet()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return IpSet()
    ips: set[str] = set()

    def add_ioc(item: dict) -> None:
        typ = item.get("ioc_type")
        val = item.get("ioc_value")
        if not isinstance(val, str):
            return
        if typ == "ipv4" or typ == "ip:port":
            host = val.split(":", 1)[0]
        elif typ == "url":
            try:
                host = urllib.parse.urlsplit(val).hostname or ""
            except ValueError:  # pragma: no cover
                return
        else:
            return
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return
        ips.add(host)

    if isinstance(data, dict):
        for groups in data.values():
            for item in groups if isinstance(groups, list) else []:
                if isinstance(item, dict):
                    add_ioc(item)
    return IpSet(ips)


async def fetch_firehol_level1() -> IpSet:
    """FireHOL ``firehol_level1`` 严格封禁 IP/CIDR（防火墙级黑名单）。"""
    return IpSet(await fetch_text_list(FIREHOL_LEVEL1_URL))


async def fetch_binarydefense() -> IpSet:
    """Binary Defense Artillery 恶意 IP/CIDR 封禁集。"""
    return IpSet(await fetch_text_list(BINARYDEFENSE_URL))


PROXYCHECK_URL = "https://proxycheck.io/v3/{}"
PROXYCHECK_TIMEOUT = 8


def proxycheck_lookup_sync(ip: str) -> dict | None:
    """Keyless ``proxycheck.io/v3/{ip}`` proxy/VPN/tor/hosting/scraper detection."""
    req = urllib.request.Request(
        PROXYCHECK_URL.format(ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=PROXYCHECK_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict) or data.get("status") != "ok":
        return None
    info = data.get(ip) or {}
    if not isinstance(info, dict):
        return None
    detections = info.get("detections") or {}
    network = info.get("network") or {}
    return {
        "is_proxy": bool(detections.get("proxy")),
        "is_vpn": bool(detections.get("vpn")),
        "is_tor": bool(detections.get("tor")),
        "is_hosting": bool(detections.get("hosting")),
        "is_scraper": bool(detections.get("scraper")),
        "risk": int(detections.get("risk") or 0),
        "type": network.get("type"),
    }


IP2LOCATION_URL = "https://api.ip2location.io/?ip={}"
IP2LOCATION_TIMEOUT = 8


def ip2location_lookup_sync(ip: str) -> dict | None:
    """Keyless ``api.ip2location.io`` is_proxy flag."""
    req = urllib.request.Request(
        IP2LOCATION_URL.format(ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=IP2LOCATION_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict):
        return None
    if "is_proxy" not in data:
        return None
    return {"is_proxy": bool(data.get("is_proxy"))}


def ipwhois_lookup_sync(ip: str) -> dict | None:
    """Free keyless ``ipwhois.app`` security flags + connection type."""
    req = urllib.request.Request(
        IPWHOIS_URL.format(ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=IPWHOIS_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict) or data.get("success") is False:
        return None
    conn = data.get("connection") or {}
    sec = data.get("security")
    sec = sec if isinstance(sec, dict) else {}
    out = {
        "security": {
            k: bool(sec.get(k))
            for k in ("anonymous", "proxy", "vpn", "tor", "hosting")
        },
        "connection_type": conn.get("type"),
    }
    asn = norm_asn(conn.get("asn"))
    if asn:
        out["asn"] = asn
    if not any(out["security"].values()) and not conn.get("type") and not asn:
        return None
    return out


def freeipapi_lookup_sync(ip: str) -> dict | None:
    """Keyless ``freeipapi.com/api/json/{ip}``: isProxy flag + ASN/org."""
    req = urllib.request.Request(
        FREEIPAPI_URL.format(ip=ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=FREEIPAPI_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict) or not data.get("ipAddress"):
        return None
    out = {"is_proxy": bool(data.get("isProxy"))}
    asn = norm_asn(data.get("asn"))
    if asn:
        out["asn"] = asn
    org = data.get("asnOrganization")
    if isinstance(org, str) and org:
        out["org"] = org
    if not out["is_proxy"] and not asn:
        return None
    return out


def hackmyip_lookup_sync(ip: str) -> dict | None:
    """Keyless ``hackmyip.com/api/lookup?ip={ip}``: hosting/proxy/mobile flags.

    Returns ``{"is_hosting", "is_proxy", "is_mobile", "asn"}`` from the
    ``data.privacy`` block; ``None`` when the payload is unusable.
    """
    req = urllib.request.Request(
        HACKMYIP_URL.format(ip=ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=HACKMYIP_TIMEOUT) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("success") is not True:
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    privacy = data.get("privacy")
    privacy = privacy if isinstance(privacy, dict) else {}
    out = {
        "is_hosting": bool(privacy.get("hosting")),
        "is_proxy": bool(privacy.get("proxy")),
        "is_mobile": bool(privacy.get("mobile")),
    }
    network = data.get("network")
    if isinstance(network, dict):
        asn = norm_asn(network.get("asn"))
        if asn:
            out["asn"] = asn
    return out


def scamalytics_lookup_sync(ip: str) -> dict | None:
    """Scrape the free ``scamalytics.com/ip/{ip}`` risk page: ``Fraud Score``
    (0-100) plus the ``is_blacklisted_external`` flag from the embedded API
    preview JSON."""
    req = urllib.request.Request(
        SCAMALYTICS_URL.format(ip=ip),
        headers={"User-Agent": UA},
    )
    with urllib.request.urlopen(req, timeout=SCAMALYTICS_TIMEOUT) as resp:
        html = resp.read().decode("utf-8", "replace")
    m = SCAMALYTICS_SCORE_RE.search(html)
    if not m:
        return None
    out = {"score": int(m.group(1))}
    bl = SCAMALYTICS_BLACKLIST_RE.search(html)
    if bl:
        out["is_blacklisted"] = bl.group(1) == "true"
    return out


def iplocation_lookup_sync(ip: str) -> dict | None:
    """Keyless ``api.iplocation.net/?ip={ip}``: isp + occasional ``is_proxy``."""
    req = urllib.request.Request(
        IPLOCATION_URL.format(ip=ip),
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=IPLOCATION_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict) or not data.get("ip"):
        return None
    out: dict = {}
    proxy = data.get("is_proxy")
    if isinstance(proxy, str) and proxy.lower() == "yes":
        out["is_proxy"] = True
    isp = data.get("isp")
    if isinstance(isp, str) and isp:
        out["isp"] = isp
    if not out.get("is_proxy") and not out.get("isp"):
        return None
    return out


async def fetch_text_list(url: str) -> set[str]:
    """Fetch a static list; any failure returns an empty set (fail-open)."""
    out: set[str] = set()
    try:
        text = await asyncio.to_thread(
            lambda: fetch_with_mirror(
                url, STATIC_LIST_TIMEOUT, headers={"User-Agent": UA}
            ).decode("utf-8", errors="replace")
        )
    except Exception as exc:
        logging.debug("fetch_text_list %s: %s", url, exc)
        logging.warning("fetch_text_list failed open for %s: %s", url, exc)
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


async def fetch_tor_exits() -> IpSet:
    """Tor exit node IPs（``ExitAddress`` 行取第二列）。"""
    lines = await fetch_text_list(TOR_EXITS_URL)
    ips = [
        ln.split()[1]
        for ln in lines if ln.startswith(("ExitAddress",))
    ]
    return IpSet(ips)


async def fetch_spamhaus_drop() -> IpSet:
    """Spamhaus DROP + EDROP CIDR 网段（``<cidr> ; 描述`` 行）。"""
    cidrs = []
    for url in (SPAMHAUS_DROP_URL, SPAMHAUS_EDROP_URL):
        for ln in await fetch_text_list(url):
            entry = ln.split(";")[0].strip()
            if "/" in entry:
                cidrs.append(entry)
    return IpSet(cidrs)


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
        "tor_exit": IpSet(),
        "spamhaus": IpSet(),
        "cins": IpSet(),
        "et_compromised": IpSet(),
        "feodo": IpSet(),
        "blocklist_de": IpSet(),
        "blocklist_de_ssh": IpSet(),
        "blocklist_de_apache": IpSet(),
        "danmeuk_tor": IpSet(),
        "tor_bulk": IpSet(),
        "urlhaus": IpSet(),
        "threatfox": IpSet(),
        "firehol_level1": IpSet(),
        "binarydefense": IpSet(),
    }
    mapping = []
    if "abuse_list" in sources:
        mapping.append(("abuse_list", fetch_firehol_abusers()))
    if "tor_exit" in sources:
        mapping.append(("tor_exit", fetch_tor_exits()))
    if "spamhaus" in sources:
        mapping.append(("spamhaus", fetch_spamhaus_drop()))
    if "cins" in sources:
        mapping.append(("cins", fetch_cins_badguys()))
    if "et_compromised" in sources:
        mapping.append(("et_compromised", fetch_et_compromised()))
    if "feodo" in sources:
        mapping.append(("feodo", fetch_feodo()))
    if "blocklist_de" in sources:
        mapping.append(("blocklist_de", fetch_blocklist_de()))
    if "blocklist_de_ssh" in sources:
        mapping.append(("blocklist_de_ssh", fetch_blocklist_de_ssh()))
    if "blocklist_de_apache" in sources:
        mapping.append(("blocklist_de_apache", fetch_blocklist_de_apache()))
    if "danmeuk_tor" in sources:
        mapping.append(("danmeuk_tor", fetch_dan_tor()))
    if "tor_bulk" in sources:
        mapping.append(("tor_bulk", fetch_tor_bulk()))
    if "urlhaus" in sources:
        mapping.append(("urlhaus", fetch_urlhaus()))
    if "threatfox" in sources:
        mapping.append(("threatfox", fetch_threatfox()))
    if "firehol_level1" in sources:
        mapping.append(("firehol_level1", fetch_firehol_level1()))
    if "binarydefense" in sources:
        mapping.append(("binarydefense", fetch_binarydefense()))
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
        if isinstance(res, Exception):
            logging.warning("static list source %s failed: %s", name, res)
            continue
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
    if name == "proxycheck":
        penalty = sum(
            amt for flag, amt in PROXYCHECK_FLAG_PENALTIES.items()
            if signal.get(flag)
        )
        raw = signal.get("risk")
        if isinstance(raw, (int, float)):
            penalty = max(penalty, round(raw))
        return max(0, min(100, 100 - penalty))
    if name == "ip2location":
        penalty = sum(
            amt for flag, amt in IP2LOCATION_FLAG_PENALTIES.items()
            if signal.get(flag)
        )
        if not penalty:
            return None
        return max(0, min(100, 100 - penalty))
    if name == "ipwhois":
        sec = signal.get("security") if isinstance(
            signal.get("security"), dict
        ) else {}
        penalty = sum(
            amt for flag, amt in IPWHOIS_FLAG_PENALTIES.items()
            if sec.get(flag)
        )
        if not penalty and not signal.get("asn"):
            return None
        return max(0, min(100, 100 - penalty))
    if name == "freeipapi":
        penalty = 30 if signal.get("is_proxy") else 0
        return max(0, min(100, 100 - penalty))
    if name == "scamalytics":
        if not isinstance(signal.get("score"), (int, float)):
            return None
        return max(0, min(100, 100 - round(signal["score"])))
    if name == "iplocation":
        penalty = 30 if signal.get("is_proxy") else 0
        return max(0, min(100, 100 - penalty))
    if name == "greynoise":
        if signal.get("is_abuse"):
            penalty = GREYNOISE_FLAG_PENALTIES.get("is_abuse", 60)
        elif signal.get("is_riot"):
            penalty = GREYNOISE_FLAG_PENALTIES.get("is_bot", 35)
        elif signal.get("is_noise"):
            penalty = GREYNOISE_FLAG_PENALTIES.get("is_noise", 15)
        else:
            return None
        return max(0, min(100, 100 - penalty))
    if name in STATIC_LIST_SCORES:
        flag = {
            "abuse_list": "is_abuse",
            "ipsum": "is_listed",
            "dc_asn": "is_hosting",
            "vpn_asn": "is_vpn",
            "resproxy_asn": "is_proxy",
            "tor_exit": "is_tor",
            "spamhaus": "is_listed",
            "cins": "is_listed",
            "et_compromised": "is_abuse",
            "feodo": "is_abuse",
            "blocklist_de": "is_abuse",
            "blocklist_de_ssh": "is_abuse",
            "blocklist_de_apache": "is_abuse",
            "danmeuk_tor": "is_tor",
            "tor_bulk": "is_tor",
            "urlhaus": "is_abuse",
            "threatfox": "is_abuse",
            "firehol_level1": "is_listed",
            "binarydefense": "is_abuse",
        }.get(name)
        return STATIC_LIST_SCORES[name] if signal.get(flag) else None
    return None


# --- 统一标记投票 (cross-source consensus) -------------------------------------
# 语义维度：proxy/vpn/tor/hosting(数据中心)/mobile/abuse(滥用)/listed(黑名单
# 列表)/scraper(抓取)/crawler(爬虫)/anonymous(匿名)。每个源对它有意见的维度
# 投 +1/-1 票，投票权重 = REPUTATION_WEIGHTS[name]；正票总权重大于负票总权重
# 才认定该维度为真，打平视为无结论（不扣分）。这替代了"每个源各自折算 0-100
# 分再按权平均"的做法——一个 proxy 标记如今由多个源统一表决，单源误报会被群
# 体否定，也避免了大权重的单源独断。
FLAG_PENALTIES = {
    "tor": 40,
    "proxy": 28,
    "vpn": 22,
    "hosting": 10,
    "abuse": 35,
    "listed": 30,
    "scraper": 12,
    "crawler": 5,
    "anonymous": 8,
    "bot": 35,
    "noise": 15,
}
_HOSTING_TYPES = ("hosting", "datacenter", "cloud")


def _flag_opinions(name: str, signal) -> dict:
    """``{family: bool}`` votes cast by one source; absent family = abstain."""
    if not isinstance(signal, dict):
        return {}
    if name == "netcoffee":
        opinions = {
            "tor": signal.get("is_tor"),
            "proxy": signal.get("is_proxy"),
            "vpn": signal.get("is_vpn"),
            "hosting": signal.get("is_datacenter"),
            "mobile": signal.get("is_mobile"),
            "crawler": signal.get("is_crawler"),
            "abuse": signal.get("is_abuser"),
        }
        if (signal.get("company_type") or signal.get("asn_kind")) in \
                _HOSTING_TYPES:
            opinions["hosting"] = True
        at = parse_abuser_score(signal.get("abuser_score"))
        if at is not None and at >= ABUSER_SCORE_THRESHOLD:
            opinions["abuse"] = True
        return {f: v for f, v in opinions.items() if isinstance(v, bool)}
    if name == "ncgy":
        if signal.get("clean"):
            return {f: False for f in ("tor", "proxy", "vpn", "hosting",
                                       "anonymous")}
        return {
            f: v for f, v in {
                "tor": signal.get("is_tor"),
                "proxy": signal.get("is_proxy"),
                "vpn": signal.get("is_vpn"),
                "hosting": signal.get("is_hosting"),
                "anonymous": signal.get("is_anonymous"),
            }.items() if isinstance(v, bool)
        }
    if name == "ip-api":
        return {
            f: v for f, v in {
                "proxy": signal.get("proxy"),
                "hosting": signal.get("hosting"),
                "mobile": signal.get("mobile"),
            }.items() if isinstance(v, bool)
        }
    if name == "ipdata":
        sec = signal.get("security") if isinstance(
            signal.get("security"), dict
        ) else {}
        opinions = {
            "proxy": bool(signal.get("is_proxy") or sec.get("proxy")),
            "vpn": sec.get("vpn"),
            "tor": sec.get("tor"),
            "hosting": bool(signal.get("is_hosting") or sec.get("hosting")),
            "anonymous": sec.get("anonymous"),
        }
        return {f: v for f, v in opinions.items() if isinstance(v, bool)}
    if name == "getipintel":
        return {}
    if name == "ipapi_is":
        opinions = {
            "tor": signal.get("is_tor"),
            "proxy": signal.get("is_proxy"),
            "vpn": signal.get("is_vpn"),
            "hosting": signal.get("is_datacenter"),
            "mobile": signal.get("is_mobile"),
            "crawler": signal.get("is_crawler"),
            "abuse": signal.get("is_abuser"),
        }
        if (signal.get("company_type") or signal.get("asn_type")) in \
                _HOSTING_TYPES:
            opinions["hosting"] = True
        for key in ("company_abuser_score", "asn_abuser_score"):
            at = parse_abuser_score(signal.get(key))
            if at is not None and at >= ABUSER_SCORE_THRESHOLD:
                opinions["abuse"] = True
        return {f: v for f, v in opinions.items() if isinstance(v, bool)}
    if name == "ipquery":
        return {
            f: v for f, v in {
                "tor": signal.get("is_tor"),
                "proxy": signal.get("is_proxy"),
                "vpn": signal.get("is_vpn"),
                "hosting": signal.get("is_datacenter"),
                "mobile": signal.get("is_mobile"),
            }.items() if isinstance(v, bool)
        }
    if name == "ffraud":
        opinions = {
            "tor": signal.get("is_tor"),
            "proxy": signal.get("is_proxy"),
            "vpn": signal.get("is_vpn"),
            "hosting": signal.get("is_hosting"),
            "mobile": signal.get("is_mobile"),
            "abuse": bool(signal.get("is_abuser") or
                          signal.get("recent_abuse") or
                          signal.get("is_residential_proxy")),
        }
        if (signal.get("connection_type") or "") == "hosting":
            opinions["hosting"] = True
        return {f: v for f, v in opinions.items() if isinstance(v, bool)}
    if name == "whatismyip":
        return {
            f: v for f, v in {
                "tor": signal.get("is_tor"),
                "proxy": signal.get("is_proxy"),
                "vpn": signal.get("is_vpn"),
                "hosting": signal.get("is_hosting"),
                "listed": signal.get("is_blacklisted"),
            }.items() if isinstance(v, bool)
        }
    if name == "ipwhois":
        sec = signal.get("security") if isinstance(
            signal.get("security"), dict
        ) else {}
        opinions = {
            "tor": sec.get("tor"),
            "proxy": sec.get("proxy"),
            "vpn": sec.get("vpn"),
            "hosting": sec.get("hosting"),
            "anonymous": sec.get("anonymous"),
        }
        if (signal.get("connection_type") or "").lower() in _HOSTING_TYPES:
            opinions["hosting"] = True
        return {f: v for f, v in opinions.items() if isinstance(v, bool)}
    if name == "blackbox":
        cls = signal.get("classification") or ""
        if cls == "mobile":
            return {"mobile": True}
        if cls == "residential":
            return {"tor": False, "proxy": False, "vpn": False,
                    "hosting": False, "mobile": True}
        if cls == "business":
            return {"tor": False, "proxy": False, "vpn": False}
        if cls in ("tor", "vpn", "privacy_relay", "hosting"):
            return {
                "tor": cls == "tor",
                "proxy": cls == "privacy_relay",
                "vpn": cls == "vpn",
                "hosting": cls == "hosting",
            }
        return {}
    if name == "otx":
        if int(signal.get("pulse_count") or 0) > 0 or \
           int(signal.get("reputation") or 0) < 0:
            return {"listed": True}
        return {}
    if name == "proxycheck":
        return {
            f: v for f, v in {
                "tor": signal.get("is_tor"),
                "proxy": signal.get("is_proxy"),
                "vpn": signal.get("is_vpn"),
                "hosting": signal.get("is_hosting"),
                "scraper": signal.get("is_scraper"),
            }.items() if isinstance(v, bool)
        }
    if name == "ip2location":
        if signal.get("is_proxy"):
            return {"proxy": True}
        return {}
    if name == "abuse_list":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "ipsum":
        return {"listed": True} if signal.get("is_listed") else {}
    if name == "dc_asn":
        return {"hosting": True} if signal.get("is_hosting") else {}
    if name == "vpn_asn":
        return {"vpn": True} if signal.get("is_vpn") else {}
    if name == "resproxy_asn":
        return {"proxy": True} if signal.get("is_proxy") else {}
    if name == "tor_exit":
        return {"tor": True} if signal.get("is_tor") else {}
    if name == "spamhaus":
        return {"listed": True} if signal.get("is_listed") else {}
    if name == "freeipapi":
        return {"proxy": signal.get("is_proxy")} if isinstance(
            signal.get("is_proxy"), bool
        ) else {}
    if name == "scamalytics":
        return {"listed": True} if signal.get("is_blacklisted") else {}
    if name == "iplocation":
        return {"proxy": True} if signal.get("is_proxy") else {}
    if name == "hackmyip":
        return {
            f: v for f, v in {
                "hosting": signal.get("is_hosting"),
                "proxy": signal.get("is_proxy"),
                "mobile": signal.get("is_mobile"),
            }.items() if isinstance(v, bool)
        }
    if name == "cins":
        return {"listed": True} if signal.get("is_listed") else {}
    if name == "feodo":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "et_compromised":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "blocklist_de":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "blocklist_de_ssh":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "blocklist_de_apache":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "danmeuk_tor":
        return {"tor": True} if signal.get("is_tor") else {}
    if name == "tor_bulk":
        return {"tor": True} if signal.get("is_tor") else {}
    if name == "urlhaus":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "threatfox":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "firehol_level1":
        return {"listed": True} if signal.get("is_listed") else {}
    if name == "binarydefense":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "greynoise":
        opinions = {}
        if signal.get("is_abuse"):
            opinions["abuse"] = True
        if signal.get("is_riot"):
            opinions["bot"] = True
        if signal.get("is_noise"):
            opinions["noise"] = True
        return {f: v for f, v in opinions.items() if isinstance(v, bool)}
    return {}


def consensus_flags(
    signals: dict,
    weights: dict,
    *,
    tie: bool | None = None,
    min_confirm_weight: float = 0,
) -> dict:
    """Vote ``{family: bool|None}`` over all responding sources.

    - Weighted majority: ``pos > neg`` → True / ``neg > pos`` → False.
    - A tie yields ``tie`` (default ``None`` = benefit of the doubt, family
      treated as not flagged).
    - ``min_confirm_weight``: when > 0, a family is only confirmed True if its
      positive-vote weight also reaches this floor (inhibits conviction from a
      single weak/低权重来源). Default 0 keeps legacy single-source behavior.
    """
    votes: dict = {}
    for name, signal in signals.items():
        if not isinstance(signal, dict):
            continue
        for family, value in _flag_opinions(name, signal).items():
            votes.setdefault(family, {})[name] = value
    flags: dict = {}
    for family, voters in votes.items():
        pos = sum(
            weights.get(name, 0) for name, v in voters.items() if v is True
        )
        neg = sum(
            weights.get(name, 0) for name, v in voters.items() if v is False
        )
        if pos > neg and pos >= min_confirm_weight:
            flags[family] = True
        elif neg > pos:
            flags[family] = False
        else:
            flags[family] = tie
    return flags


def _numeric_risk_penalty(name: str, signal: dict) -> int | None:
    """Continuous-risk sources → 0..100 penalty (flags handled by consensus)."""
    if name == "netcoffee":
        trust = signal.get("trust_score")
        if isinstance(trust, (int, float)):
            return round(max(0, min(100, 100 - trust)))
        return None
    if name == "getipintel":
        prob = signal.get("probability")
        if not isinstance(prob, (int, float)) or not 0 <= prob <= 1:
            return None
        return round(prob * 100)
    if name == "otx":
        rep = int(signal.get("reputation") or 0)
        pulses = int(signal.get("pulse_count") or 0)
        return min(rep * 5, 80) + min(pulses * 2, 20)
    for key in ("risk_score", "fraud_score", "score", "risk"):
        value = signal.get(key)
        if isinstance(value, (int, float)):
            return round(max(0, min(100, value)))
    return None


def continuous_penalty(
    signals: dict, weights: dict
) -> tuple[int | None, list[str]]:
    """Weighted blend of numeric risk penalties over responding sources."""
    parts = []
    for name, signal in signals.items():
        if not isinstance(signal, dict):
            continue
        penalty = _numeric_risk_penalty(name, signal)
        if penalty is None:
            continue
        weight = weights.get(name, 0)
        if weight > 0:
            parts.append((weight, penalty, name))
    if not parts:
        return None, []
    total = sum(w for w, _p, _n in parts)
    merged = round(sum(w * p for w, p, _n in parts) / total)
    return merged, [name for _w, _p, name in parts]


def _family_penalty(name: str, family: str, signal: dict) -> int:
    """该源对某**已确认**家族的实际罚分；无特例则用通用 ``FLAG_PENALTIES``。

    与 ``GREYNOISE_FLAG_PENALTIES`` / ``STATIC_LIST_SCORES`` 的差异化强度对齐：
    恶意扫描（is_abuse）按 60 从严，botnet 成员 35，噪音扫描 15——避免所有
    家族都退化为通用 ``abuse``(35)/``listed``(30) 的粗粒度扣分。
    """
    if name == "greynoise":
        if family == "abuse":
            return GREYNOISE_FLAG_PENALTIES.get("is_abuse", FLAG_PENALTIES["abuse"])
        if family == "bot":
            return GREYNOISE_FLAG_PENALTIES.get("is_bot", FLAG_PENALTIES.get("bot", 35))
        if family == "noise":
            return GREYNOISE_FLAG_PENALTIES.get("is_noise", FLAG_PENALTIES.get("noise", 15))
    return FLAG_PENALTIES.get(family, 0)


def _mobile_clean_bonus(flags: dict) -> int:
    """仅当确认 mobile 且无任何代理/滥用类标记时给 +5 奖励。

    住宅移动网络的高可用信号不被代理/机房噪声稀释；但一旦同时被认作
    proxy/vpn/tor/abuse/listed/hosting/bot 则不加成（可能为恶意出口）。
    """
    if flags.get("mobile") is True and not any(
        flags.get(f) for f in ("proxy", "vpn", "tor", "listed", "abuse",
                               "hosting", "bot")
    ):
        return 5
    return 0


def vote_reputation(
    signals: dict, weights: dict
) -> tuple[int | None, list[str], list[str], list[str]]:
    """0-100 reputation from cross-source consensus + numeric risk blend.

    Returns ``(score, responding, flagged, numeric_sources)``: ``flagged`` is
    the ordered list of semantic families confirmed by majority vote;
    ``numeric_sources`` are the sources contributing continuous risk.

    A confirmed family's penalty is the **max** penalty among its confirming
    sources (punish with the strongest evidence), capped once per family even
    when multiple independent sources agree on it.
    """
    responding = sorted(
        (n for n, s in signals.items()
         if isinstance(s, dict) and weights.get(n, 0) > 0)
    )
    if not responding:
        return None, [], [], []
    flags = consensus_flags(signals, weights)
    confirmed = {f for f, v in flags.items() if v is True}
    family_pen: dict[str, int] = {}
    for name, signal in signals.items():
        if not isinstance(signal, dict):
            continue
        for fam, val in _flag_opinions(name, signal).items():
            if val is not True or fam not in confirmed:
                continue
            family_pen[fam] = max(
                family_pen.get(fam, 0),
                _family_penalty(name, fam, signal),
            )
    penalty = sum(family_pen.values())
    numeric, numeric_sources = continuous_penalty(signals, weights)
    if numeric is not None:
        penalty += numeric
    score = 100 - penalty
    score += _mobile_clean_bonus(flags)
    score = max(0, min(100, round(score)))
    flagged = sorted(f for f, v in flags.items() if v is True)
    return score, responding, flagged, numeric_sources


def weighted_reputation(
    signals: dict, weights: dict
) -> tuple[int | None, list[str]]:
    """Weighted merge of per-source cleanliness scores over responding sources.

    Legacy path retained for numeric-risk blending; the primary reputation
    path is ``vote_reputation`` (cross-source flag consensus).
    """
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
    """0-100 multi-source reputation; abuse score (100-score) takes precedence.

    Primary path is ``vote_reputation`` (cross-source flag consensus +
    continuous-risk blend); ``weighted_reputation`` is the legacy per-source
    weighted merge kept for numeric labeling.
    """
    if abuse and isinstance(abuse.get("score"), (int, float)):
        return max(0, min(100, 100 - round(abuse["score"])))
    score, _responding, _flagged, _numeric = vote_reputation(signals, weights)
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
    Static-list signals (abuse/ASN lists) are re-computed every run.
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
    if "proxycheck" in sources:
        w, d = pacing.get("proxycheck", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("proxycheck", proxycheck_lookup_sync, workers=w, delay=d))
    if "ip2location" in sources:
        w, d = pacing.get("ip2location", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ip2location", ip2location_lookup_sync, workers=w, delay=d))
    if "ipwhois" in sources:
        w, d = pacing.get("ipwhois", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ipwhois", ipwhois_lookup_sync, workers=w, delay=d))
    if "freeipapi" in sources:
        w, d = pacing.get("freeipapi", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "freeipapi", freeipapi_lookup_sync, cap=FREEIPAPI_CAP, workers=w, delay=d))
    if "hackmyip" in sources:
        w, d = pacing.get("hackmyip", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "hackmyip", hackmyip_lookup_sync, workers=w, delay=d))
    if "scamalytics" in sources:
        w, d = pacing.get("scamalytics", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "scamalytics", scamalytics_lookup_sync, cap=SCAMALYTICS_CAP, workers=w, delay=d))
    if "iplocation" in sources:
        w, d = pacing.get("iplocation", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "iplocation", iplocation_lookup_sync, cap=IPLOCATION_CAP, workers=w, delay=d))
    if "greynoise" in sources:
        w, d = pacing.get("greynoise", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("greynoise", greynoise_lookup_sync, workers=w, delay=d))
    if api_tasks:
        await asyncio.gather(*api_tasks)
    if "ipsum" in sources:
        ipsum_set = await fetch_ipsum_list()
        for ip in uniq:
            if ip in ipsum_set:
                put("ipsum", ip, {"is_listed": True})
    static = await fetch_static_lists(sources)
    for ip in uniq:
        if ip in static["abuse_list"]:
            put("abuse_list", ip, {"is_abuse": True})
        if ip in static["tor_exit"]:
            put("tor_exit", ip, {"is_tor": True})
        if ip in static["spamhaus"]:
            put("spamhaus", ip, {"is_listed": True})
        if ip in static["cins"]:
            put("cins", ip, {"is_listed": True})
        if ip in static["et_compromised"]:
            put("et_compromised", ip, {"is_abuse": True})
        if ip in static["feodo"]:
            put("feodo", ip, {"is_abuse": True})
        if ip in static["blocklist_de"]:
            put("blocklist_de", ip, {"is_abuse": True})
        if ip in static["blocklist_de_ssh"]:
            put("blocklist_de_ssh", ip, {"is_abuse": True})
        if ip in static["blocklist_de_apache"]:
            put("blocklist_de_apache", ip, {"is_abuse": True})
        if ip in static["danmeuk_tor"]:
            put("danmeuk_tor", ip, {"is_tor": True})
        if ip in static["tor_bulk"]:
            put("tor_bulk", ip, {"is_tor": True})
        if ip in static["urlhaus"]:
            put("urlhaus", ip, {"is_abuse": True})
        if ip in static["threatfox"]:
            put("threatfox", ip, {"is_abuse": True})
        if ip in static["firehol_level1"]:
            put("firehol_level1", ip, {"is_listed": True})
        if ip in static["binarydefense"]:
            put("binarydefense", ip, {"is_abuse": True})
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
        if len(pruned) > REP_CACHE_MAX:
            # 超上限：按每个 IP 最近一次信号时间裁剪最旧的
            def last_ts(item) -> float:
                _ip, entry = item
                ts = 0.0
                for src_entry in entry.values():
                    if isinstance(src_entry, dict):
                        ts = max(ts, src_entry.get("ts") or 0)
                return ts
            for ip, _ in sorted(
                pruned.items(), key=last_ts, reverse=True
            )[REP_CACHE_MAX:]:
                del pruned[ip]
        save_rep_cache(pruned)
    return risk_data

