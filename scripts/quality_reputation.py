#!/usr/bin/env python3
"""Multi-source IP reputation / risk scoring (extracted from quality_check.py).

Each source yields a 0-100 cleanliness signal merged by ``REPUTATION_WEIGHTS``
into a single reputation score; static lists (FireHOL abuse / iplogs
ASN lists) are re-fetched every run, per-IP API signals are cached in
``reputation_cache.json`` with a TTL. Expired entries are re-queried on the
next run but retained as a fallback (used if the refresh fails) rather than
deleted. Imported by ``quality_check``.
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
from bisect import bisect_right

from common import *  # noqa: F401,F403  (paths, UA, write_json, keyed_json, ...)

REP_CACHE_MAX = 40000   # 信誉缓存 IP 上限（防无限膨胀，超出按最近使用裁剪）
# 负缓存（成功但无信号）TTL 上限：短于正向 TTL，兼顾省调用与「干净→恶意」
# 检测时延（最坏情况下延迟这么久才重新观测到新增风险）。
NEG_CACHE_TTL = 86400
REP_RISK_HIGH = 30
REP_RISK_MEDIUM = 75

REP_WORKERS = 10
REP_DELAY = 0.15
IPDATA_CAP = 2000
# E1b：以下端点已迁 PCB rep_static（经 _REP_STATIC_BUNDLE loader 获取）：
# DC_ASN_URL / VPN_ASN_URL / RESPROXY_ASN_URL / TOR_EXITS_URL /
# SPAMHAUS_DROP_URL / SPAMHAUS_EDROP_URL（原定义已删）。
IPLOCATION_CAP = 3000
STOPFORUMSPAM_CAP = 3000
MALTIVERSE_CAP = 2500
# DNSBL 七源族（dnsbl/spamcop/dronebl/spamrats/sorbs/uceprotect/psbl）
# 经 DNS-over-HTTPS 免 key 查询的具体实现（端点、zone、sticky、码表）随
# PCB 私有插件 ``rep_dnsbl``（R49 迁入）；公开侧只保留配额兜底值，有包时
# 由 loader 覆盖为插件值，无包时查找函数为 None → fail-open 跳过。
DNSBL_ZEN_CAP = 12000
DNSBL_TIMEOUT = 4
SPAMCOP_CAP = 9000
DRONEBL_CAP = 9000
SPAMRATS_CAP = 9000
SORBS_CAP = 9000
UCEPROTECT_CAP = 9000
PSBL_CAP = 9000
# 以 `is_listed` 投 listed 共识票的 DNSBL 家族（R279 表驱动；评分语义
# 保留公开，端点/实现随 PCB）。
_DNSBL_LISTED_SOURCES = (
    "dnsbl", "spamcop", "dronebl", "spamrats", "sorbs",
    "uceprotect", "psbl",
)
# AbuseIPDB 公共黑名单（近 30 天、置信度高的滥用举报 IP/CIDR，社区镜像，
# GitHub 原始 + jsDelivr 镜像可回退）。独立于本仓库 key 版滥用相位。
# ~8.2MB 是静态源中体量最大的：放宽容限避免慢网统一 15s 超时 fail-open。
# 某上游维护者实测不可达 IP（其 CF 反代候选池的失联项，裸 IP 行）：
# 第三方"用不上"证据，非滥用，温和口径（is_listed + 静态 70 + 权重 2）。
# 同站维护者拉黑 IP（裸 IP 行）：主动拒绝类证据，口径略强于失联
# （is_listed + 静态 65 + 权重 2），仍非滥用定性。
# E1a：以下 6 名单端点已迁 PCB rep_static（公开侧经 _REP_STATIC_BUNDLE
# loader 获取，无包时对应 fetch_* 为 None）：CINS_BADGUYS_URL /
# ET_COMPROMISED_URL / FEODO_URL / DAN_TOR_URL / TOR_BULK_URL /
# BLOCKLIST_DE_URL（原定义已删）。
# BruteForceBlocker（danger.rulez.sk 社区 SSH 爆破榜，`IP # 时间 次数 ID`
# 行内注释格式，取首列；与 blocklist_de_ssh 同信号族同定级）。
# dataplane.org VNC 爆破榜（`count | org | IP | datetime | feed` 管道格式，
# 取第 3 字段；与 maltrail 同解析契约；VNC 爆破新信号族，同 ssh 族定级）。
# drb-ra C2IntelFeeds 30 天审核 C2（`IP,描述` 逗号格式，取首列；单研究员
# 审核 + Possible 定性，口径略弱于聚合：is_abuse + 静态 50 + 权重 4）。
# 同站 NordVPN 出口表（`IP,描述` 逗号格式，取首列；日更；VPN 出口信号，
# 与 x4bnet vpn_ips 同级：is_vpn + 静态 55 + 权重 3）。
# blackhole.monster 每日攻击者裸 IP 表（Maltrail 定性 known attacker）：
# is_abuse + 静态 50 + 权重 4。
# myip.ms 10 天攻击源 htaccess（`deny from IP`，取第 3 列；攻击自家
# 基础设施的扫描/机器人，10 天窗口）：is_abuse + 静态 50 + 权重 4。
# IPnoise（sekuripy.hr 分布式交互蜜罐 7 天窗口，裸 IP；蜜罐无合法服务，
# 连上即敌对）：is_abuse + 静态 50 + 权重 4。
# FireHOL level2（L1 超集 + 更多聚合源，裸 IP + CIDR；比 L1 更广更噪，
# 口径略弱：is_listed + 静态 50 + 权重 4）。
STATIC_LIST_TIMEOUT = 15
# 静态黑名单正文上限：ThreatFox json/recent、FireHOL netset 等可达数十 MB，
# 远超通用 FETCH_BODY_MAX=16MiB。黑洞/截断即静默丢失整源信誉信号，
# 故独立给足上限（同时仍防失控响应）。
STATIC_LIST_MAX = 512 * 1024 * 1024
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
# M2b：分值表已迁 PCB rep_static（经下方 _REP_STATIC_BUNDLE loader
# 回绑 STATIC_LIST_SCORES；无包时为空表，source_score 对应信号计
# None fail-open。原 37 项已删，见插件与 TestScoresParityR173）。
# M3：权重/默认/PACING 三表已迁 PCB _rep_sources（经下方 loader 回绑；
# 无包时依次为空表/空元组/空表，解析/打分天然降级为零源/零权 fail-open）。
# 原 65+54+25 项已删，见插件与 TestRepSourcesRegistryWiring。

# 信誉元数据 loader 优先（R14）：有包时三名字重绑为 PCB 对象
# （`TestRepSourcesRegistryWiring` 锁同一性）；无包为空表/空元组/空表
# fail-open（解析零源、打分零权，见 M3）。
_REP_SOURCES_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep = _load_pcb_plugin("_rep_sources")
    REPUTATION_WEIGHTS = _rep.REPUTATION_WEIGHTS
    DEFAULT_REP_SOURCES = _rep.DEFAULT_REP_SOURCES
    SOURCE_PACING = _rep.SOURCE_PACING
    PROVIDER_GROUPS = _rep.PROVIDER_GROUPS
    _REP_SOURCES_BUNDLE = True
except Exception:
    REPUTATION_WEIGHTS = {}
    DEFAULT_REP_SOURCES = ()
    SOURCE_PACING = {}
    PROVIDER_GROUPS = {}

# R233：信誉数据源名的**不透明公开 id** 派生器（与下载源 dsrc_* 同构、命名空间
# 隔离）。词表权威源是 PCB ``leak_guard.reputation_source_names()``（62 项，
# 实测覆盖已发布数据里出现的全部 25 个名字，零遗漏）。
#
# 无包降级**天然安全**，不需额外守卫：``REPUTATION_WEIGHTS`` 为空表时
# ``vote_reputation`` 返回 ``score=None``，``build_rep_map`` 直接 ``continue``
# ——记录压根不写，也就没有源名可泄漏。降级路径不产生真名。
#
# 语义哨兵：``multi`` 表示多源交叉（对应下载源侧的 ``main``/``multi``），
# 不是来源身份，原样透传不哈希。
REP_PUBLIC_ID = None
try:
    REP_PUBLIC_ID = _load_pcb_plugin("leak_guard").reputation_source_public_id
except Exception:
    REP_PUBLIC_ID = None

#: 不哈希的语义哨兵（多源交叉，非来源身份）。
REP_SENTINELS = frozenset({"multi"})


def _rep_public_vocab() -> frozenset:
    """权威词表（一次性构建）；为空表示词表不可得。"""
    global _REP_PUBLIC_VOCAB
    if _REP_PUBLIC_VOCAB is None:
        vocab = set()
        if REP_PUBLIC_ID is not None:
            try:
                from checks_bundle import load_plugin as _lp
                getter = getattr(_lp("leak_guard"),
                                 "reputation_source_names", None)
                if getter is not None:
                    vocab = {str(n).strip().lower() for n in getter()}
            except Exception:
                vocab = set()
        _REP_PUBLIC_VOCAB = frozenset(vocab)
    return _REP_PUBLIC_VOCAB


_REP_PUBLIC_VOCAB: frozenset | None = None


# R234：具名信誉 provider 的不透明 id 解析。provider 语义（哪些源构成该策略）
# 已迁入 PCB ``_rep_sources.PROVIDER_GROUPS``，公开树因此无需指名任何源名。
# provider token 用 ``provider:`` 命名空间，故与源 token 互不冒充。
REP_PROVIDER_IDS = None
try:
    REP_PROVIDER_IDS = _load_pcb_plugin(
        "leak_guard").reputation_provider_public_ids
except Exception:
    REP_PROVIDER_IDS = None

#: 不算「具名 provider」的哨兵：multi=加权合并全部源，none=不查。
REP_PROVIDER_SENTINELS = ("multi", "none")


def rep_provider_choices() -> tuple:
    """``--reputation-provider`` 的合法取值（哨兵 + 不透明 provider id）。"""
    ids = ()
    if REP_PROVIDER_IDS is not None:
        try:
            ids = tuple(sorted(REP_PROVIDER_IDS()))
        except Exception:
            ids = ()
    return REP_PROVIDER_SENTINELS + ids


def rep_provider_group(provider):
    """不透明 provider id → 源名元组；哨兵/未知返回 ``None``。

    返回的是**内存侧惯用的源名**（下游按名取权重点火），故不透明性只作用于
    CLI 表面与已发布产物，不影响内部逻辑。
    """
    if provider in REP_PROVIDER_SENTINELS or REP_PROVIDER_IDS is None:
        return None
    try:
        m = REP_PROVIDER_IDS()
    except Exception:
        return None
    if provider not in m:
        return None
    return tuple(PROVIDER_GROUPS.get(m[provider], ()))


def rep_public_id(name):
    """信誉数据源名→不透明公开 id；哨兵 / 无包降级 / **词表外**原样返回。

    「词表外原样保留」是**必需的**，不是放水：反查表只覆盖权威词表，若对
    词表外的名字也哈希，落盘后就**无法还原**（round-trip 断裂），缓存条目
    静默失效、信誉信号丢失。R233 round-trip 实测抓到了这一点
    （``some_unknown_source`` → ``rsrc_*`` → 读回仍是 id）。
    词表外的名字按定义不属本仓来源清单（同 R229 对 URL 文件名主干的处理）。
    """
    if not name or name in REP_SENTINELS or REP_PUBLIC_ID is None:
        return name
    if str(name).strip().lower() not in _rep_public_vocab():
        return name
    return REP_PUBLIC_ID(name) or name


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


_REP_NETCOFFEE_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_ncf = _load_pcb_plugin("rep_netcoffee")
    netcoffee_lookup_sync = _rep_ncf.netcoffee_lookup_sync
    _REP_NETCOFFEE_BUNDLE = True
except Exception:
    netcoffee_lookup_sync = None


_REP_NCGY_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_ncy = _load_pcb_plugin("rep_ncgy")
    ncgy_lookup_sync = _rep_ncy.ncgy_lookup_sync
    _REP_NCGY_BUNDLE = True
except Exception:
    ncgy_lookup_sync = None


_REP_GREYNOISE_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_gns = _load_pcb_plugin("rep_greynoise")
    greynoise_lookup_sync = _rep_gns.greynoise_lookup_sync
    _REP_GREYNOISE_BUNDLE = True
except Exception:
    greynoise_lookup_sync = None


_REP_IPDATA_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_ipd = _load_pcb_plugin("rep_ipdata")
    ipdata_lookup_sync = _rep_ipd.ipdata_lookup_sync
    IPDATA_CAP = _rep_ipd.CAP
    _REP_IPDATA_BUNDLE = True
except Exception:
    ipdata_lookup_sync = None
    IPDATA_CAP = 2000


_REP_GETIPINTEL_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_gip = _load_pcb_plugin("rep_getipintel")
    getipintel_lookup_sync = _rep_gip.getipintel_lookup_sync
    GETIPINTEL_CAP = _rep_gip.CAP
    _REP_GETIPINTEL_BUNDLE = True
except Exception:
    getipintel_lookup_sync = None
    GETIPINTEL_CAP = 2000


_REP_IPAPI_IS_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_is = _load_pcb_plugin("rep_ipapi_is")
    ipapi_is_lookup_sync = _rep_is.ipapi_is_lookup_sync
    _REP_IPAPI_IS_BUNDLE = True
except Exception:
    ipapi_is_lookup_sync = None


_REP_IPQUERY_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_iq = _load_pcb_plugin("rep_ipquery")
    ipquery_lookup_sync = _rep_iq.ipquery_lookup_sync
    _REP_IPQUERY_BUNDLE = True
except Exception:
    ipquery_lookup_sync = None


_REP_FFRAUD_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_ff = _load_pcb_plugin("rep_ffraud")
    ffraud_lookup_sync = _rep_ff.ffraud_lookup_sync
    _REP_FFRAUD_BUNDLE = True
except Exception:
    ffraud_lookup_sync = None


_REP_WHATISMYIP_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_wmi = _load_pcb_plugin("rep_whatismyip")
    whatismyip_lookup_sync = _rep_wmi.whatismyip_lookup_sync
    _REP_WHATISMYIP_BUNDLE = True
except Exception:
    whatismyip_lookup_sync = None


_REP_BLACKBOX_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_bbx = _load_pcb_plugin("rep_blackbox")
    blackbox_lookup_sync = _rep_bbx.blackbox_lookup_sync
    _REP_BLACKBOX_BUNDLE = True
except Exception:
    blackbox_lookup_sync = None


_REP_OTX_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_otx = _load_pcb_plugin("rep_otx")
    otx_lookup_sync = _rep_otx.otx_lookup_sync
    _REP_OTX_BUNDLE = True
except Exception:
    otx_lookup_sync = None


# E1a：以下 6 名单抓取已迁 PCB rep_static（公开侧经 _REP_STATIC_BUNDLE
# loader 回绑对应 fetch_*；无包时各为 None，dispatch 守卫跳过）：
# fetch_cins_badguys / fetch_et_compromised / fetch_feodo /
# fetch_dan_tor / fetch_tor_bulk / fetch_blocklist_de（原实现已删）。


# E1d：以下 7 名单抓取已迁 PCB rep_static（经 _REP_STATIC_BUNDLE
# loader 回绑；无包为 None，dispatch 守卫跳过）：blocklist_de_ssh /
# blocklist_de_apache / bruteforceblocker / dataplane_vncrfb /
# blackhole_monster / myipms_blacklist / ipnoise（原实现已删）。


# E1c：以下 11 名单抓取已迁 PCB rep_static（经 _REP_STATIC_BUNDLE
# loader 回绑；无包为 None，dispatch 守卫跳过）：firehol_abusers /
# level1 / level2 / c2_tracker / botscout / sslproxies / socks_proxy /
# dshield / x4bnet_vpn / binarydefense / greensnow（原实现已删）。


_REP_PROXYCHECK_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_pc = _load_pcb_plugin("rep_proxycheck")
    proxycheck_lookup_sync = _rep_pc.proxycheck_lookup_sync
    _REP_PROXYCHECK_BUNDLE = True
except Exception:
    proxycheck_lookup_sync = None


_REP_IP2LOCATION_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_i2l = _load_pcb_plugin("rep_ip2location")
    ip2location_lookup_sync = _rep_i2l.ip2location_lookup_sync
    _REP_IP2LOCATION_BUNDLE = True
except Exception:
    ip2location_lookup_sync = None


_REP_IPWHOIS_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_wh = _load_pcb_plugin("rep_ipwhois")
    ipwhois_lookup_sync = _rep_wh.ipwhois_lookup_sync
    _REP_IPWHOIS_BUNDLE = True
except Exception:
    ipwhois_lookup_sync = None


_REP_STOPFORUMSPAM_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_sfs = _load_pcb_plugin("rep_stopforumspam")
    stopforumspam_lookup_sync = _rep_sfs.stopforumspam_lookup_sync
    STOPFORUMSPAM_CAP = _rep_sfs.CAP
    _REP_STOPFORUMSPAM_BUNDLE = True
except Exception:
    stopforumspam_lookup_sync = None
    STOPFORUMSPAM_CAP = 3000


_REP_MALTIVERSE_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_mvi = _load_pcb_plugin("rep_maltiverse")
    maltiverse_lookup_sync = _rep_mvi.maltiverse_lookup_sync
    MALTIVERSE_CAP = _rep_mvi.CAP
    _REP_MALTIVERSE_BUNDLE = True
except Exception:
    maltiverse_lookup_sync = None
    MALTIVERSE_CAP = 2500


_REP_DNSBL_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_dnsbl = _load_pcb_plugin("rep_dnsbl")
    dnsbl_lookup_sync = _rep_dnsbl.dnsbl_lookup_sync
    spamcop_lookup_sync = _rep_dnsbl.spamcop_lookup_sync
    dronebl_lookup_sync = _rep_dnsbl.dronebl_lookup_sync
    spamrats_lookup_sync = _rep_dnsbl.spamrats_lookup_sync
    sorbs_lookup_sync = _rep_dnsbl.sorbs_lookup_sync
    uceprotect_lookup_sync = _rep_dnsbl.uceprotect_lookup_sync
    psbl_lookup_sync = _rep_dnsbl.psbl_lookup_sync
    DNSBL_ZEN_CAP = _rep_dnsbl.DNSBL_ZEN_CAP
    DNSBL_TIMEOUT = _rep_dnsbl.DNSBL_TIMEOUT
    SPAMCOP_CAP = _rep_dnsbl.SPAMCOP_CAP
    DRONEBL_CAP = _rep_dnsbl.DRONEBL_CAP
    SPAMRATS_CAP = _rep_dnsbl.SPAMRATS_CAP
    SORBS_CAP = _rep_dnsbl.SORBS_CAP
    UCEPROTECT_CAP = _rep_dnsbl.UCEPROTECT_CAP
    PSBL_CAP = _rep_dnsbl.PSBL_CAP
    _REP_DNSBL_BUNDLE = True
except Exception:
    dnsbl_lookup_sync = None
    spamcop_lookup_sync = None
    dronebl_lookup_sync = None
    spamrats_lookup_sync = None
    sorbs_lookup_sync = None
    uceprotect_lookup_sync = None
    psbl_lookup_sync = None


_REP_ABUSE_BUNDLE = False
try:
    _rep_abuse = _load_pcb_plugin("rep_abuse")
    abuse_lookup_sync = _rep_abuse.abuse_lookup_sync
    _REP_ABUSE_BUNDLE = True
except Exception:
    abuse_lookup_sync = None


_REP_STATIC_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_static = _load_pcb_plugin("rep_static")
    fetch_cins_badguys = _rep_static.fetch_cins_badguys
    fetch_et_compromised = _rep_static.fetch_et_compromised
    fetch_feodo = _rep_static.fetch_feodo
    fetch_dan_tor = _rep_static.fetch_dan_tor
    fetch_tor_bulk = _rep_static.fetch_tor_bulk
    fetch_blocklist_de = _rep_static.fetch_blocklist_de
    fetch_tor_exits = _rep_static.fetch_tor_exits
    fetch_spamhaus_drop = _rep_static.fetch_spamhaus_drop
    fetch_dc_asn = _rep_static.fetch_dc_asn
    fetch_vpn_asn = _rep_static.fetch_vpn_asn
    fetch_resproxy_asn = _rep_static.fetch_resproxy_asn
    fetch_firehol_abusers = _rep_static.fetch_firehol_abusers
    fetch_firehol_level1 = _rep_static.fetch_firehol_level1
    fetch_firehol_level2 = _rep_static.fetch_firehol_level2
    fetch_c2_tracker = _rep_static.fetch_c2_tracker
    fetch_botscout = _rep_static.fetch_botscout
    fetch_sslproxies = _rep_static.fetch_sslproxies
    fetch_socks_proxy = _rep_static.fetch_socks_proxy
    fetch_dshield = _rep_static.fetch_dshield
    fetch_x4bnet_vpn = _rep_static.fetch_x4bnet_vpn
    fetch_binarydefense = _rep_static.fetch_binarydefense
    fetch_greensnow = _rep_static.fetch_greensnow
    fetch_blocklist_de_ssh = _rep_static.fetch_blocklist_de_ssh
    fetch_blocklist_de_apache = _rep_static.fetch_blocklist_de_apache
    fetch_bruteforceblocker = _rep_static.fetch_bruteforceblocker
    fetch_dataplane_vncrfb = _rep_static.fetch_dataplane_vncrfb
    fetch_blackhole_monster = _rep_static.fetch_blackhole_monster
    fetch_myipms_blacklist = _rep_static.fetch_myipms_blacklist
    fetch_ipnoise = _rep_static.fetch_ipnoise
    fetch_ipsum_list = _rep_static.fetch_ipsum_list
    fetch_drb_c2 = _rep_static.fetch_drb_c2
    fetch_nordvpn_exits = _rep_static.fetch_nordvpn_exits
    fetch_urlhaus = _rep_static.fetch_urlhaus
    fetch_threatfox = _rep_static.fetch_threatfox
    fetch_abuseipdb_public = _rep_static.fetch_abuseipdb_public
    fetch_wwuyi_unreachable = _rep_static.fetch_wwuyi_unreachable
    fetch_wwuyi_blocked = _rep_static.fetch_wwuyi_blocked
    STATIC_LIST_SCORES = _rep_static.STATIC_LIST_SCORES
    _REP_STATIC_BUNDLE = True
except Exception:
    fetch_cins_badguys = None
    fetch_et_compromised = None
    fetch_feodo = None
    fetch_dan_tor = None
    fetch_tor_bulk = None
    fetch_blocklist_de = None
    fetch_tor_exits = None
    fetch_spamhaus_drop = None
    fetch_dc_asn = None
    fetch_vpn_asn = None
    fetch_resproxy_asn = None
    fetch_firehol_abusers = None
    fetch_firehol_level1 = None
    fetch_firehol_level2 = None
    fetch_c2_tracker = None
    fetch_botscout = None
    fetch_sslproxies = None
    fetch_socks_proxy = None
    fetch_dshield = None
    fetch_x4bnet_vpn = None
    fetch_binarydefense = None
    fetch_greensnow = None
    fetch_blocklist_de_ssh = None
    fetch_blocklist_de_apache = None
    fetch_bruteforceblocker = None
    fetch_dataplane_vncrfb = None
    fetch_blackhole_monster = None
    fetch_myipms_blacklist = None
    fetch_ipnoise = None
    fetch_ipsum_list = None
    fetch_drb_c2 = None
    fetch_nordvpn_exits = None
    fetch_urlhaus = None
    fetch_threatfox = None
    fetch_abuseipdb_public = None
    fetch_wwuyi_unreachable = None
    fetch_wwuyi_blocked = None
    STATIC_LIST_SCORES = {}


_REP_FREEIPAPI_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_free = _load_pcb_plugin("rep_freeipapi")
    freeipapi_lookup_sync = _rep_free.freeipapi_lookup_sync
    FREEIPAPI_CAP = _rep_free.CAP
    _REP_FREEIPAPI_BUNDLE = True
except Exception:
    freeipapi_lookup_sync = None
    FREEIPAPI_CAP = 3000


_REP_HACKMYIP_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_hack = _load_pcb_plugin("rep_hackmyip")
    hackmyip_lookup_sync = _rep_hack.hackmyip_lookup_sync
    _REP_HACKMYIP_BUNDLE = True
except Exception:
    hackmyip_lookup_sync = None

_REP_SCAMALYTICS_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_scam = _load_pcb_plugin("rep_scamalytics")
    scamalytics_lookup_sync = _rep_scam.scamalytics_lookup_sync
    SCAMALYTICS_CAP = _rep_scam.CAP
    _REP_SCAMALYTICS_BUNDLE = True
except Exception:
    scamalytics_lookup_sync = None
    SCAMALYTICS_CAP = 1500


_REP_IPLOCATION_BUNDLE = False
try:
    from checks_bundle import load_plugin as _load_pcb_plugin
    _rep_iloc = _load_pcb_plugin("rep_iplocation")
    iplocation_lookup_sync = _rep_iloc.iplocation_lookup_sync
    IPLOCATION_CAP = _rep_iloc.CAP
    _REP_IPLOCATION_BUNDLE = True
except Exception:
    iplocation_lookup_sync = None
    IPLOCATION_CAP = 3000


async def fetch_text_list(url: str, timeout: float = STATIC_LIST_TIMEOUT) -> set[str]:
    """Fetch a static list; any failure returns an empty set (fail-open).

    ``timeout`` 为整包抓取上限；超大列表（如 abuseipdb_public ≈8MB）可
    单独放宽，避免慢网在统一 15s 内被截断吞成空（fail-open 成 0 覆盖）。
    """
    out: set[str] = set()
    try:
        text = await asyncio.to_thread(
            lambda: fetch_with_mirror(
                url, timeout, headers={"User-Agent": UA},
                max_bytes=STATIC_LIST_MAX,
            ).decode("utf-8", errors="replace")
        )
    except Exception as exc:
        logging.debug("fetch_text_list %s: %s", url, err_name(exc))
        logging.warning("fetch_text_list failed open for %s: %s", url, err_name(exc))
        return out
    stripped = text.lstrip()
    if text and (stripped[:1] in ("<", "{", "[") or
                 "<html" in text[:512].lower()):
        # 网关/边缘把错误页以 200 原样吐出（HTML/JSON/重定向页），逐行解析
        # 会静默滤成空表——显式告警，避免「想拉 15 万条实得 0」被吞掉。
        logging.warning(
            "fetch_text_list non-list content for %s (%.0f bytes, "
            "first char %r): treating as empty",
            url, len(text), stripped[:1],
        )
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        out.add(line)
    return out


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
        "bruteforceblocker": IpSet(),
        "dataplane_vncrfb": IpSet(),
        "drb_c2": IpSet(),
        "nordvpn_exits": IpSet(),
        "blackhole_monster": IpSet(),
        "myipms_blacklist": IpSet(),
        "ipnoise": IpSet(),
        "blocklist_de_apache": IpSet(),
        "danmeuk_tor": IpSet(),
        "tor_bulk": IpSet(),
        "urlhaus": IpSet(),
        "threatfox": IpSet(),
        "firehol_level1": IpSet(),
        "firehol_level2": IpSet(),
        "binarydefense": IpSet(),
        "c2_tracker": IpSet(),
        "botscout": IpSet(),
        "greensnow": IpSet(),
        "sslproxies": IpSet(),
        "socks_proxy": IpSet(),
        "vpn_ips": IpSet(),
        "dshield": IpSet(),
        "abuseipdb_public": IpSet(),
        "wwuyi_unreachable": IpSet(),
        "wwuyi_blocked": IpSet(),
    }
    mapping = []
    if "abuse_list" in sources and fetch_firehol_abusers is not None:
        mapping.append(("abuse_list", fetch_firehol_abusers()))
    if "tor_exit" in sources and fetch_tor_exits is not None:
        mapping.append(("tor_exit", fetch_tor_exits()))
    if "spamhaus" in sources and fetch_spamhaus_drop is not None:
        mapping.append(("spamhaus", fetch_spamhaus_drop()))
    if "cins" in sources and fetch_cins_badguys is not None:
        mapping.append(("cins", fetch_cins_badguys()))
    if "et_compromised" in sources and fetch_et_compromised is not None:
        mapping.append(("et_compromised", fetch_et_compromised()))
    if "feodo" in sources and fetch_feodo is not None:
        mapping.append(("feodo", fetch_feodo()))
    if "blocklist_de" in sources and fetch_blocklist_de is not None:
        mapping.append(("blocklist_de", fetch_blocklist_de()))
    if "blocklist_de_ssh" in sources and fetch_blocklist_de_ssh is not None:
        mapping.append(("blocklist_de_ssh", fetch_blocklist_de_ssh()))
    if "bruteforceblocker" in sources and fetch_bruteforceblocker is not None:
        mapping.append(("bruteforceblocker", fetch_bruteforceblocker()))
    if "dataplane_vncrfb" in sources and fetch_dataplane_vncrfb is not None:
        mapping.append(("dataplane_vncrfb", fetch_dataplane_vncrfb()))
    if "drb_c2" in sources and fetch_drb_c2 is not None:
        mapping.append(("drb_c2", fetch_drb_c2()))
    if "nordvpn_exits" in sources and fetch_nordvpn_exits is not None:
        mapping.append(("nordvpn_exits", fetch_nordvpn_exits()))
    if "blackhole_monster" in sources and fetch_blackhole_monster is not None:
        mapping.append(("blackhole_monster", fetch_blackhole_monster()))
    if "myipms_blacklist" in sources and fetch_myipms_blacklist is not None:
        mapping.append(("myipms_blacklist", fetch_myipms_blacklist()))
    if "ipnoise" in sources and fetch_ipnoise is not None:
        mapping.append(("ipnoise", fetch_ipnoise()))
    if "blocklist_de_apache" in sources and fetch_blocklist_de_apache is not None:
        mapping.append(("blocklist_de_apache", fetch_blocklist_de_apache()))
    if "danmeuk_tor" in sources and fetch_dan_tor is not None:
        mapping.append(("danmeuk_tor", fetch_dan_tor()))
    if "tor_bulk" in sources and fetch_tor_bulk is not None:
        mapping.append(("tor_bulk", fetch_tor_bulk()))
    if "urlhaus" in sources and fetch_urlhaus is not None:
        mapping.append(("urlhaus", fetch_urlhaus()))
    if "threatfox" in sources and fetch_threatfox is not None:
        mapping.append(("threatfox", fetch_threatfox()))
    if "firehol_level1" in sources and fetch_firehol_level1 is not None:
        mapping.append(("firehol_level1", fetch_firehol_level1()))
    if "firehol_level2" in sources and fetch_firehol_level2 is not None:
        mapping.append(("firehol_level2", fetch_firehol_level2()))
    if "binarydefense" in sources and fetch_binarydefense is not None:
        mapping.append(("binarydefense", fetch_binarydefense()))
    if "c2_tracker" in sources and fetch_c2_tracker is not None:
        mapping.append(("c2_tracker", fetch_c2_tracker()))
    if "botscout" in sources and fetch_botscout is not None:
        mapping.append(("botscout", fetch_botscout()))
    if "greensnow" in sources and fetch_greensnow is not None:
        mapping.append(("greensnow", fetch_greensnow()))
    if "sslproxies" in sources and fetch_sslproxies is not None:
        mapping.append(("sslproxies", fetch_sslproxies()))
    if "socks_proxy" in sources and fetch_socks_proxy is not None:
        mapping.append(("socks_proxy", fetch_socks_proxy()))
    if "vpn_ips" in sources and fetch_x4bnet_vpn is not None:
        mapping.append(("vpn_ips", fetch_x4bnet_vpn()))
    if "dshield" in sources and fetch_dshield is not None:
        mapping.append(("dshield", fetch_dshield()))
    if "abuseipdb_public" in sources and fetch_abuseipdb_public is not None:
        mapping.append(("abuseipdb_public", fetch_abuseipdb_public()))
    if "wwuyi_unreachable" in sources and fetch_wwuyi_unreachable is not None:
        mapping.append(("wwuyi_unreachable", fetch_wwuyi_unreachable()))
    if "wwuyi_blocked" in sources and fetch_wwuyi_blocked is not None:
        mapping.append(("wwuyi_blocked", fetch_wwuyi_blocked()))
    if "dc_asn" in sources and fetch_dc_asn is not None:
        mapping.append(("dc_asn", fetch_dc_asn()))
    if "vpn_asn" in sources and fetch_vpn_asn is not None:
        mapping.append(("vpn_asn", fetch_vpn_asn()))
    if "resproxy_asn" in sources and fetch_resproxy_asn is not None:
        mapping.append(("resproxy_asn", fetch_resproxy_asn()))
    results = await asyncio.gather(
        *(task for _name, task in mapping), return_exceptions=True
    )
    for (name, _task), res in zip(mapping, results):
        if isinstance(res, Exception):
            logging.warning("static list source %s failed: %s",
                            name, err_name(res))
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
    deadline: float | None = None,
) -> dict:
    """Run ``fn(ip)`` over unique IPs with a concurrency semaphore + pacing.

    ``deadline``（``time.monotonic()`` 绝对时刻）为墙钟止损：超过后不再
    新开探测任务，已提交任务正常收尾。补齐 D-42 遗漏的 reputation 相位
    ——geo/abuse 已有 deadline，rep 的循环分批此前只受 per-call 超时约束，
    缓存大面积失效时会把后处理拖过 120min job 硬杀。

    返回 ``{ip: signal}``：``signal is None`` 表示**成功响应但无信号**
    （如 greynoise 对干净 IP 返回 404/clean、ip2location 非代理），与
    **抛异常的失败**语义不同——只有失败才重试，无信号不重试（R238：此前
    二者混同，导致干净 IP 每轮被重查且无法负缓存）。
    """
    items = list(dict.fromkeys(ips))
    if cap > 0:
        items = items[:cap]
    if deadline is not None:
        remaining = [ip for ip in items
                     if time.monotonic() < deadline]
        if len(remaining) != len(items):
            print(
                f"Warning: batch_sync truncated {len(items) - len(remaining)} "
                "IPs by deadline before first launch",
                file=sys.stderr,
            )
        items = remaining
    sem = asyncio.Semaphore(workers)
    out: dict = {}
    failed: list[str] = []

    async def work(ip: str) -> None:
        async with sem:
            if deadline is not None and time.monotonic() >= deadline:
                return
            try:
                res = await asyncio.to_thread(fn, ip)
                ok = True
            except Exception as exc:
                logging.debug("batch_sync: %s failed: %s", ip, err_name(exc))
                res = None
                ok = False
            if deadline is not None and time.monotonic() >= deadline:
                failed.append(ip)
                return
            if ok:
                # None=成功响应但无信号：记录（供负缓存）但不重试
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
        if deadline is not None and time.monotonic() >= deadline:
            break
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
        abuser = parse_abuser_score(signal.get("abuser_score"))
        if abuser is not None and abuser >= ABUSER_SCORE_THRESHOLD:
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
            # 文档契约为 +5（与 consensus 的 _mobile_clean_bonus 一致），
            # legacy 直用口径不再单独给 +10。
            bonus += 5
        return max(0, min(100, 100 - penalty + bonus))
    if name == "ipdata":
        security = signal.get("security") or {}
        penalty = sum(
            amt for flag, amt in IPDATA_FLAG_PENALTIES.items()
            if security.get(flag)
        )
        penalty += _as_int(signal.get("threat_score"))
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
        abuser = parse_abuser_score(signal.get("company_abuser_score"))
        if abuser is None:
            abuser = parse_abuser_score(signal.get("asn_abuser_score"))
        if abuser is not None and abuser >= ABUSER_SCORE_THRESHOLD:
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
        # OTX reputation：负值=恶意、正值=洁净（官方信誉为 -3..+3，负号幅值
        # 越大越脏）。罚分按负侧幅值计，正/零声誉不罚——与 _flag_opinions 的
        # listed 语义一致（此前把正声誉当脏、负声誉当净是符号反转）。
        rep = _as_int(signal.get("reputation"))
        pulses = _as_int(signal.get("pulse_count"))
        bad = min(max(0, -rep) * 5, 80)
        penalty = bad + min(pulses * 2, 20)
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
    if name == "stopforumspam":
        if not signal.get("is_abuse"):
            return None
        return 50
    if name == "maltiverse":
        cls = signal.get("classification")
        if cls == "malicious":
            penalty = 60
        elif cls == "suspicious":
            penalty = 35
        elif (signal.get("is_cnc") or signal.get("is_distributing_malware")
              or signal.get("is_iot_threat") or signal.get("is_known_scanner")
              or signal.get("recent_blacklist")):
            penalty = 40
        elif (signal.get("is_tor_node") or signal.get("is_open_proxy")
              or signal.get("is_vpn_node")):
            penalty = 25
        else:
            return None
        return max(0, min(100, 100 - penalty))
    if name == "iplocation":
        penalty = 30 if signal.get("is_proxy") else 0
        return max(0, min(100, 100 - penalty))
    if name in _DNSBL_LISTED_SOURCES:
        if not signal.get("is_listed"):
            return None
        return max(0, min(100, 100 - FLAG_PENALTIES.get("listed", 30)))
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
            "bruteforceblocker": "is_abuse",
            "dataplane_vncrfb": "is_abuse",
            "drb_c2": "is_abuse",
            "nordvpn_exits": "is_vpn",
            "blackhole_monster": "is_abuse",
            "myipms_blacklist": "is_abuse",
            "ipnoise": "is_abuse",
            "blocklist_de_apache": "is_abuse",
            "danmeuk_tor": "is_tor",
            "tor_bulk": "is_tor",
            "urlhaus": "is_abuse",
            "threatfox": "is_abuse",
            "firehol_level1": "is_listed",
            "firehol_level2": "is_listed",
            "binarydefense": "is_abuse",
            "c2_tracker": "is_abuse",
            "botscout": "is_abuse",
            "greensnow": "is_abuse",
            "sslproxies": "is_proxy",
            "socks_proxy": "is_proxy",
            "vpn_ips": "is_vpn",
            "dshield": "is_abuse",
            "abuseipdb_public": "is_abuse",
            "wwuyi_unreachable": "is_listed",
            "wwuyi_blocked": "is_listed",
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


def _as_int(value, default: int = 0):
    """int 安全强转：保留数值/数字字符串语义，非数值/异常类型回退 default
    （缓存投毒韧性：字符串"abc"不再抛 ValueError，也不致放大罚分）。"""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value == int(value) else default
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


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
        if _as_int(signal.get("pulse_count")) > 0 or \
           _as_int(signal.get("reputation")) < 0:
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
    if name == "stopforumspam":
        opinions = {}
        if signal.get("is_abuse"):
            opinions["abuse"] = True
        if signal.get("torexit"):
            opinions["tor"] = True
        return opinions
    if name == "maltiverse":
        opinions = {}
        if signal.get("is_tor_node"):
            opinions["tor"] = True
        if signal.get("is_vpn_node"):
            opinions["vpn"] = True
        if signal.get("is_open_proxy"):
            opinions["proxy"] = True
        if signal.get("classification") in ("malicious", "suspicious") or any(
            signal.get(k) for k in (
                "is_cnc", "is_distributing_malware", "is_iot_threat",
                "is_known_scanner", "is_mining_pool", "recent_blacklist")
        ):
            opinions["abuse"] = True
        return opinions
    if name == "iplocation":
        return {"proxy": True} if signal.get("is_proxy") else {}
    if name in _DNSBL_LISTED_SOURCES:
        return {"listed": True} if signal.get("is_listed") else {}
    if name == "abuseipdb_public":
        return {"abuse": True} if signal.get("is_abuse") else {}
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
    if name == "wwuyi_unreachable":
        return {"listed": True} if signal.get("is_listed") else {}
    if name == "wwuyi_blocked":
        return {"listed": True} if signal.get("is_listed") else {}
    if name == "feodo":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "et_compromised":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "blocklist_de":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "blocklist_de_ssh":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "bruteforceblocker":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "dataplane_vncrfb":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "drb_c2":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "nordvpn_exits":
        return {"vpn": True} if signal.get("is_vpn") else {}
    if name == "blackhole_monster":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "myipms_blacklist":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "ipnoise":
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
    if name == "firehol_level2":
        return {"listed": True} if signal.get("is_listed") else {}
    if name == "binarydefense":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "c2_tracker":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "botscout":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "greensnow":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "sslproxies":
        return {"proxy": True} if signal.get("is_proxy") else {}
    if name == "socks_proxy":
        return {"proxy": True} if signal.get("is_proxy") else {}
    if name == "vpn_ips":
        return {"vpn": True} if signal.get("is_vpn") else {}
    if name == "dshield":
        return {"abuse": True} if signal.get("is_abuse") else {}
    if name == "greynoise":
        opinions = {}
        if signal.get("is_abuse"):
            opinions["abuse"] = True
        else:
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
        # 负声誉=恶意（见 source_score 同名段注释），正/零声誉不罚。
        rep = _as_int(signal.get("reputation"))
        pulses = _as_int(signal.get("pulse_count"))
        return min(max(0, -rep) * 5, 80) + max(0, min(pulses * 2, 20))
    for key in ("risk_score", "fraud_score", "score", "risk", "threat_score"):
        value = signal.get(key)
        # bool 是 int 子类：缓存投毒塞入 ``true`` 不得被当作 1 分风险罚分，
        # 与 _as_int 的 bool 防御一致。
        if isinstance(value, bool):
            continue
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
    proxy/vpn/tor/abuse/listed/hosting/bot/noise/crawler/scraper/anonymous
    则不加成（可能为恶意出口）。
    """
    if flags.get("mobile") is True and not any(
        flags.get(f) for f in ("proxy", "vpn", "tor", "listed", "abuse",
                               "hosting", "bot", "noise", "crawler",
                               "scraper", "anonymous")
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
    # 空字典是 R238 负缓存哨兵（成功但无信号）：既非 None 也无数值，
    # 必须排除出 responding，否则会被误记为「响应的源」而虚增 source 数。
    responding = sorted(
        (n for n, s in signals.items()
         if isinstance(s, dict) and s and weights.get(n, 0) > 0)
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
        # 跳过 None 与空字典（R238 负缓存哨兵），空信号不得进入共识。
        if signal:
            signals[source] = signal
    if include_ipapi and geo_item.get("countryCode"):
        signals["ip-api"] = geo_item
    return signals


def derive_risk(
    signals: dict, abuse: dict | None, weights: dict
) -> str:
    return reputation_risk(compute_reputation(signals, abuse, weights)) or "low"


async def run_abuse(
    results: dict, ipinfo: dict, args: argparse.Namespace,
    deadline: float | None = None,
) -> dict:
    """按出口 IP 查询滥用分；``deadline``（monotonic 绝对时刻）墙钟止损，
    顺序循环超龄即截断（防滥用 API 卡死把整个相位拖到 CI 硬杀）。"""
    if args.abuse_service == "none" or not args.abuse_key or abuse_lookup_sync is None:
        return {}
    exit_ips = sorted(
        {info["exit_ip"] for info in ipinfo.values() if info.get("exit_ip")}
    )
    by_ip: dict[str, dict] = {}
    cut_by_deadline = False
    for ip in exit_ips:
        if deadline is not None and time.monotonic() >= deadline:
            cut_by_deadline = True
            break
        try:
            by_ip[ip] = await asyncio.to_thread(
                abuse_lookup_sync, ip, args.abuse_service, args.abuse_key
            )
        except Exception as exc:
            logging.debug("abuse lookup %s: %s", ip, err_name(exc))
        await asyncio.sleep(0.3)
    if cut_by_deadline and len(by_ip) < len(exit_ips):
        print(
            "Warning: abuse scores truncated by time deadline; "
            f"returning partial results ({len(by_ip)}/{len(exit_ips)})",
            file=sys.stderr,
        )
    abuse_map: dict[str, dict] = {}
    for key, info in ipinfo.items():
        item = by_ip.get(info.get("exit_ip"))
        if item:
            entry = dict(item)
            entry["risk"] = derive_risk({}, item, args.reputation_weights)
            abuse_map[key] = entry
    return abuse_map


# R233：缓存的**每 IP 字典以信誉数据源名为键**（实测 ``reputation_cache.json``
# 407227 处，另有一份同名的陈旧副本 19871 处——R238 查明其无生产者无消费者，
# 已删除），是本次实测中**最大的一处泄漏面**（占信誉族 1067304 处的 40%）。
#
# 去身份只做在**序列化边界**（出 ``save_rep_cache`` / 进 ``load_rep_cache``），
# **不动内存缓存的键**：内存侧 ``entry[name] = ...`` 及其读路径（按 name 命中
# 缓存、按 ``SOURCE_PACING[name]`` 取节流）全部保持真名，逻辑零风险；只有落到
# 磁盘的产物是 ``rsrc_*``。下次 load 时按同一映射还原，round-trip 无损。
#
# 还原走一次性构建的反查表（62 项），避免每键一次线性扫描——407k 键下线性
# 反查是 2500 万次字符串比较，不可接受。
_REP_PUBLIC_UNSEAL = None
try:
    _REP_PUBLIC_UNSEAL = getattr(
        _load_pcb_plugin("leak_guard"), "reputation_source_from_id", None)
except Exception:
    _REP_PUBLIC_UNSEAL = None


def _rep_source_of_id(pid):
    """``rsrc_*`` → 信誉数据源名（**算法还原**，不查表）。"""
    if _REP_PUBLIC_UNSEAL is None:
        return None
    try:
        return _REP_PUBLIC_UNSEAL(pid)
    except Exception:
        return None

#: 模块默认缓存路径（用于判定「调用方是否重定向过」）。
_DEFAULT_REP_CACHE_FILE = REP_CACHE_FILE


def _rep_cache_write_path() -> Path:
    """缓存**写/读**落点，三态判定（R233）。

    1. 有 PCB 包 → ``REP_CACHE_FILE``：键已去身份，落进入库目录也安全；
    2. 无包但 ``REP_CACHE_FILE`` **已被重定向**（测试的临时目录等）→ 就地写：
       调用方明确指定了非发布位置，无泄漏风险；
    3. 无包且是默认路径 → ``.cache/``：``data/quality/`` 入库，明文源名写
       进去就是泄漏，而缓存纯为优化，改落点不损正确性。
    """
    if REP_PUBLIC_ID is not None:
        return REP_CACHE_FILE
    if REP_CACHE_FILE != _DEFAULT_REP_CACHE_FILE:
        return REP_CACHE_FILE
    return _local_rep_cache_file()


def _local_rep_cache_file() -> Path:
    """无 PCB 包时的缓存落点：仓库根 ``.cache/``（已 gitignore，不发布）。

    选它而不是 ``data/raw/``：后者**确实被 git 跟踪**（含 1111/SG.txt 等
    历史文件），且 ``commit_data.sh`` 的 EXCL 只挡自动提交，挡不住手动
    ``git add``。``.cache/`` 在 ``data/`` 之外，发布链路完全够不着。
    """
    d = Path(__file__).resolve().parent.parent / ".cache"
    d.mkdir(parents=True, exist_ok=True)
    return d / "reputation_cache.json"


def load_rep_cache() -> dict:
    """Load the reputation signal cache; corrupt/missing files read as empty.

    R233：磁盘上的键是不透明 ``rsrc_*``，此处还原成内存侧惯用的源名。
    """
    try:
        path = _rep_cache_write_path()
    except OSError:
        path = REP_CACHE_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        proxies = data.get("proxies") or {}
        out = {}
        for ip, e in proxies.items():
            if not isinstance(e, dict):
                continue
            out[ip] = {(_rep_source_of_id(k) or k): v for k, v in e.items()}
        return out
    except (OSError, ValueError, TypeError):
        return {}


def save_rep_cache(cache: dict) -> None:
    """写盘前把每 IP 字典的源名键换成不透明 id（R233）。

    **无 PCB 包时拒绝写盘**（fail-safe，不 fail-open）：``REP_CACHE_FILE`` 位于
    ``data/quality/`` 且**入库**，若无包则 ``rep_public_id`` 原样返回名字，
    于是明文源名会被写进已发布产物——这正是 R233 要消除的泄漏。缓存只是
    优化，跳过写入只损失下次查询速度，不损正确性，故宁可跳过。
    """
    idder = REP_PUBLIC_ID
    target = _rep_cache_write_path()
    if idder is None:
        # 无包 = 无法去身份。落点由 ``_rep_cache_write_path`` 决定：默认路径
        # 会被挪到不入库的 ``.cache/``，以免明文源名进已发布 data/quality/。
        # 早先「直接跳过写盘」会把缓存机制整个关掉、连带 8 个缓存用例红——
        # 教训：fail-safe 要**换落点**，不是停功能。
        write_json(target, keyed_json(cache))
        return
    out = {}
    for ip, e in cache.items():
        if not isinstance(e, dict):
            out[ip] = e
            continue
        out[ip] = {(rep_public_id(k) or k): v for k, v in e.items()}
    write_json(target, keyed_json(out))


ABUSE_STALE_TTL = 86400  # abuse.json 回退最大年龄（秒）；<=0 表示不限制


def load_abuse_file(now: float | None = None, ttl: int = ABUSE_STALE_TTL) -> dict:
    """Persisted abuse scores ``{key: entry}`` as a fallback.

    预算耗尽跳过/截断滥用相位时，用最近一次 ``abuse.json`` 兜底（滥用分在
    ``compute_reputation`` 中具最高优先级，缺失会静默降级为共识分）。
    文件缺失/损坏/超龄（> ``ttl``）→ ``{}``。
    """
    try:
        if now is None:
            now = time.time()
        if ttl and ttl > 0 and now - ABUSE_FILE.stat().st_mtime > ttl:
            return {}
        data = json.loads(ABUSE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    proxies = data.get("proxies") if isinstance(data, dict) else None
    if not isinstance(proxies, dict):
        return {}
    return {k: v for k, v in proxies.items() if isinstance(v, dict)}


def merge_abuse_fallback(fresh: dict, cached: dict, valid_keys) -> dict:
    """Fill ``valid_keys`` missing in ``fresh`` from ``cached`` abuse scores."""
    merged = dict(fresh)
    for key, entry in cached.items():
        if key in valid_keys and key not in merged:
            merged[key] = entry
    return merged


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
    data = src_entry.get("data")
    if not isinstance(data, dict):
        return None
    # 负缓存哨兵空字典用更短 TTL，限制「干净→恶意」的检测时延。
    effective_ttl = ttl if data else min(ttl, NEG_CACHE_TTL)
    if (src_entry.get("ts") or 0) + effective_ttl < now:
        return None
    return data


async def lookup_all_risk(
    ips: list, args: argparse.Namespace, asn_map: dict | None = None,
    deadline: float | None = None,
) -> dict:
    """Query all enabled reputation sources; ``{ip: {source: signal}}``.

    Per-IP API source signals are served from ``REP_CACHE_FILE`` when still
    fresh (``--rep-cache-ttl``); missing/expired IPs are re-queried, and an
    expired entry whose refresh fails falls back to the last cached signal
    instead of being dropped. Static-list signals (abuse/ASN lists) are
    re-computed every run. ``deadline`` 为 wall-clock 止损（monotonic 绝对
    时刻），透传给各缓存批量查询的 ``batch_sync``，超龄后不再新开查询。
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
        """Fill from fresh cache; stale entries are re-queried but kept as a
        fallback (used if the refresh fails) instead of being dropped.

        R238 负缓存：成功响应但无信号（``signal is None``，如 greynoise 对
        干净 IP）存 ``data: {}`` 哨兵，TTL 内不再重查；空字典在读取与兜底
        时都被视为「已知无信号」，不进入 ``risk_data``（不改变共识投票面）。
        """
        t0 = time.monotonic()
        need = []
        fallback = {}
        for ip in uniq:
            sig = cached_signal(cache, ip, name, now, cache_ttl)
            if sig is not None:
                if sig:
                    put(name, ip, sig)
                continue
            src_entry = cache.get(ip, {}).get(name)
            if isinstance(src_entry, dict) and \
               isinstance(src_entry.get("data"), dict) and src_entry["data"]:
                fallback[ip] = src_entry["data"]
            need.append(ip)
        # cap 压力（首轮回填/缓存大面积失效）下优先查询「从未有过信号」的
        # IP（无兜底：跳过即本轮完全无该源覆盖）；过期但有旧信号的 IP 保
        # 底仍在（fallback 注入、下轮补查），放到队尾等截断时被优先让位。
        need.sort(key=lambda ip: ip in fallback)
        res = await batch_sync(
            need, fn, cap=cap, workers=workers, delay=delay, deadline=deadline
        )
        for ip, sig in res.items():
            entry = cache.setdefault(ip, {})
            if sig is None:
                entry[name] = {"ts": now, "data": {}}
                continue
            put(name, ip, sig)
            entry[name] = {"ts": now, "data": sig}
        for ip, sig in fallback.items():
            if ip not in res:
                put(name, ip, sig)
        if need:
            attempted = len(need)
            truncated = 0
            if cap > 0 and len(need) > cap:
                attempted = cap
                truncated = len(need) - cap
            text = (
                f"Reputation source {name}: {time.monotonic() - t0:.1f}s "
                f"({len(need)} need, {attempted} queried, "
                f"{len(res)} resolved, {len(fallback)} fallback)"
            )
            if truncated:
                text += f", cap-truncated {truncated}"
            print(text)

    pacing = SOURCE_PACING
    api_tasks = []
    if "netcoffee" in sources and netcoffee_lookup_sync is not None:
        w, d = pacing.get("netcoffee", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("netcoffee", netcoffee_lookup_sync, workers=w, delay=d))
    if "ncgy" in sources and ncgy_lookup_sync is not None:
        w, d = pacing.get("ncgy", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ncgy", ncgy_lookup_sync, workers=w, delay=d))
    if "ipdata" in sources and ipdata_lookup_sync is not None:
        api_tasks.append(cached_batch(
            "ipdata", ipdata_lookup_sync, cap=IPDATA_CAP, workers=2, delay=0.8
        ))
    if "getipintel" in sources and getipintel_lookup_sync is not None:
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
    if "ipapi_is" in sources and ipapi_is_lookup_sync is not None:
        w, d = pacing.get("ipapi_is", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ipapi_is", ipapi_is_lookup_sync, workers=w, delay=d))
    if "ipquery" in sources and ipquery_lookup_sync is not None:
        w, d = pacing.get("ipquery", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ipquery", ipquery_lookup_sync, workers=w, delay=d))
    if "ffraud" in sources and ffraud_lookup_sync is not None:
        w, d = pacing.get("ffraud", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ffraud", ffraud_lookup_sync, workers=w, delay=d))
    if "whatismyip" in sources and whatismyip_lookup_sync is not None:
        w, d = pacing.get("whatismyip", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("whatismyip", whatismyip_lookup_sync, workers=w, delay=d))
    if "blackbox" in sources and blackbox_lookup_sync is not None:
        w, d = pacing.get("blackbox", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("blackbox", blackbox_lookup_sync, workers=w, delay=d))
    if "otx" in sources and otx_lookup_sync is not None:
        w, d = pacing.get("otx", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("otx", otx_lookup_sync, workers=w, delay=d))
    if "proxycheck" in sources and proxycheck_lookup_sync is not None:
        w, d = pacing.get("proxycheck", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("proxycheck", proxycheck_lookup_sync, workers=w, delay=d))
    if "ip2location" in sources and ip2location_lookup_sync is not None:
        w, d = pacing.get("ip2location", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ip2location", ip2location_lookup_sync, workers=w, delay=d))
    if "ipwhois" in sources and ipwhois_lookup_sync is not None:
        w, d = pacing.get("ipwhois", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("ipwhois", ipwhois_lookup_sync, workers=w, delay=d))
    if "freeipapi" in sources and freeipapi_lookup_sync is not None:
        w, d = pacing.get("freeipapi", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "freeipapi", freeipapi_lookup_sync, cap=FREEIPAPI_CAP, workers=w, delay=d))
    if "hackmyip" in sources and hackmyip_lookup_sync is not None:
        w, d = pacing.get("hackmyip", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "hackmyip", hackmyip_lookup_sync, workers=w, delay=d))
    if "stopforumspam" in sources and stopforumspam_lookup_sync is not None:
        w, d = pacing.get("stopforumspam", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "stopforumspam", stopforumspam_lookup_sync,
            cap=STOPFORUMSPAM_CAP, workers=w, delay=d))
    if "maltiverse" in sources and maltiverse_lookup_sync is not None:
        w, d = pacing.get("maltiverse", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "maltiverse", maltiverse_lookup_sync,
            cap=MALTIVERSE_CAP, workers=w, delay=d))
    if "scamalytics" in sources and scamalytics_lookup_sync is not None:
        w, d = pacing.get("scamalytics", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "scamalytics", scamalytics_lookup_sync, cap=SCAMALYTICS_CAP, workers=w, delay=d))
    if "iplocation" in sources and iplocation_lookup_sync is not None:
        w, d = pacing.get("iplocation", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "iplocation", iplocation_lookup_sync, cap=IPLOCATION_CAP, workers=w, delay=d))
    if "greynoise" in sources and greynoise_lookup_sync is not None:
        w, d = pacing.get("greynoise", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch("greynoise", greynoise_lookup_sync, workers=w, delay=d))
    if "dnsbl" in sources and dnsbl_lookup_sync is not None:
        w, d = pacing.get("dnsbl", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "dnsbl", dnsbl_lookup_sync, cap=DNSBL_ZEN_CAP, workers=w, delay=d))
    if "spamcop" in sources and spamcop_lookup_sync is not None:
        w, d = pacing.get("spamcop", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "spamcop", spamcop_lookup_sync, cap=SPAMCOP_CAP, workers=w, delay=d))
    if "dronebl" in sources and dronebl_lookup_sync is not None:
        w, d = pacing.get("dronebl", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "dronebl", dronebl_lookup_sync, cap=DRONEBL_CAP, workers=w, delay=d))
    if "spamrats" in sources and spamrats_lookup_sync is not None:
        w, d = pacing.get("spamrats", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "spamrats", spamrats_lookup_sync, cap=SPAMRATS_CAP, workers=w, delay=d))
    if "sorbs" in sources and sorbs_lookup_sync is not None:
        w, d = pacing.get("sorbs", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "sorbs", sorbs_lookup_sync, cap=SORBS_CAP, workers=w, delay=d))
    if "uceprotect" in sources and uceprotect_lookup_sync is not None:
        w, d = pacing.get("uceprotect", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "uceprotect", uceprotect_lookup_sync, cap=UCEPROTECT_CAP,
            workers=w, delay=d))
    if "psbl" in sources and psbl_lookup_sync is not None:
        w, d = pacing.get("psbl", (REP_WORKERS, REP_DELAY))
        api_tasks.append(cached_batch(
            "psbl", psbl_lookup_sync, cap=PSBL_CAP,
            workers=w, delay=d))
    if api_tasks:
        await asyncio.gather(*api_tasks)
    if "ipsum" in sources and fetch_ipsum_list is not None:
        ipsum_set = await fetch_ipsum_list()
        for ip in uniq:
            if ip in ipsum_set:
                put("ipsum", ip, {"is_listed": True})
    static = await fetch_static_lists(sources)
    rep_static = {
        k: len(v) for k, v in static.items()
        if k in sources
    }
    if rep_static and any(rep_static.values()):
        print(
            "Reputation static lists: "
            + ", ".join(f"{k}={n}" for k, n in sorted(rep_static.items()))
        )
    elif rep_static:
        # 已启用静态源全为零尺寸：可能为合法空列表，也可能是拉取失败
        # fail-open（镜像不可达被吞成空）——两者均打印 all empty。
        print("Reputation static lists: all empty")
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
        if ip in static["bruteforceblocker"]:
            put("bruteforceblocker", ip, {"is_abuse": True})
        if ip in static["dataplane_vncrfb"]:
            put("dataplane_vncrfb", ip, {"is_abuse": True})
        if ip in static["drb_c2"]:
            put("drb_c2", ip, {"is_abuse": True})
        if ip in static["nordvpn_exits"]:
            put("nordvpn_exits", ip, {"is_vpn": True})
        if ip in static["blackhole_monster"]:
            put("blackhole_monster", ip, {"is_abuse": True})
        if ip in static["myipms_blacklist"]:
            put("myipms_blacklist", ip, {"is_abuse": True})
        if ip in static["ipnoise"]:
            put("ipnoise", ip, {"is_abuse": True})
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
        if ip in static["firehol_level2"]:
            put("firehol_level2", ip, {"is_listed": True})
        if ip in static["binarydefense"]:
            put("binarydefense", ip, {"is_abuse": True})
        if ip in static["c2_tracker"]:
            put("c2_tracker", ip, {"is_abuse": True})
        if ip in static["botscout"]:
            put("botscout", ip, {"is_abuse": True})
        if ip in static["greensnow"]:
            put("greensnow", ip, {"is_abuse": True})
        if ip in static["sslproxies"]:
            put("sslproxies", ip, {"is_proxy": True})
        if ip in static["socks_proxy"]:
            put("socks_proxy", ip, {"is_proxy": True})
        if ip in static["abuseipdb_public"]:
            put("abuseipdb_public", ip, {"is_abuse": True})
        if ip in static["wwuyi_unreachable"]:
            put("wwuyi_unreachable", ip, {"is_listed": True})
        if ip in static["wwuyi_blocked"]:
            put("wwuyi_blocked", ip, {"is_listed": True})
        asn = (asn_map or {}).get(ip)
        if not asn:
            continue
        if asn in static["dc_asn"]:
            put("dc_asn", ip, {"is_hosting": True, "asn": asn})
        if asn in static["vpn_asn"]:
            put("vpn_asn", ip, {"is_vpn": True, "asn": asn})
        if asn in static["resproxy_asn"]:
            put("resproxy_asn", ip, {"is_proxy": True, "asn": asn})
    if cache_ttl and cache:
        # 过期条目不删除：保留作为刷新失败时的兜底信号，仅受
        # REP_CACHE_MAX 上限约束（按每个 IP 最近一次信号时间裁最旧）。
        if len(cache) > REP_CACHE_MAX:
            def last_ts(item) -> float:
                _ip, entry = item
                ts = 0.0
                for src_entry in entry.values():
                    if isinstance(src_entry, dict):
                        ts = max(ts, src_entry.get("ts") or 0)
                return ts
            pruned = dict(sorted(
                cache.items(), key=last_ts, reverse=True
            )[:REP_CACHE_MAX])
        else:
            pruned = cache
        save_rep_cache(pruned)
    return risk_data

