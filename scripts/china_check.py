#!/usr/bin/env python3
"""Mainland-China reachability checks for the alive proxy pool.

独立 CI（``china-check.yml``）运行：对 ``data/valid/all.txt`` 全量（约 1.9 万行，
``--source data/valid/all.txt --limit 0``）做大陆连通性检测，产出一致结论后写回：
（本地缺省仍走 ``all_rep.txt`` 按信誉降序取前 250 的小样本）

- ``data/quality/china.json``  — 逐条检测明细（keyed，``{"proxies": {...}}``；
  含合成 verdict、证据分级 ``level`` 与连续可达轮数 ``streak``）
- ``data/valid/all_cn.txt``  — 全量大陆可达清单（源为 ``data/valid/all.txt`` 全量存活池，
  仅含本轮判定 reachable 的行（严格活清单，历史累积 ``-CN`` 不再自动纳入）；回退 all_ltd.txt；
  按大陆实测延迟升序；应用层确认行追加 ``-CNH``）
- ``data/valid/all_cn_http.txt`` — 应用层（HTTP）确认子集：本轮 level=http 或历史
  已带 ``-CNH`` 的行
- ``data/valid/all_cn_stable.txt`` — 跨轮稳定子集：连续 ≥2 轮 reachable 且
  历史翻转 ≤1（flip 判定排除慢性抖动源）
  （strict，不含历史兜底）
- ``data/valid/all.txt`` / ``all_ltd.txt`` — 可达者追加 ``-CN`` 备注

检测分层（均为无账号/免登录）：

- L2 itdog.cn 批量实测（主源，全量）：`batch_http` 每任务 5 目标 × 18 节点
  （电信/联通/移动各 6，池子 ~80/ISP，跨省等距采样），经 WebSocket 收结果，
  TCP 连通即判可达；节点返回 http_code>0 时计应用层确认（level=http）——
  TLS 端口上明文探测会收到 CF 的 400 响应，同样证明完整数据往返无 TCP 层干扰。
- L2 itdog batch_tcping 补测（降级通道）：batch_http 对某目标失败/被限时，
  改用 `batch_tcping` 纯 TCPING 复测——节点池大得多（每 ISP ~75-88 个，
  默认取 6×3=18 节点），结果记为独立多节点源 ``itdog_tcping``。
- L2 单节点实测（并发）：`check-host.cc`（呼和浩特阿里云 1 节点，需控速）+
  `xxapi.cn`（北京节点，免 key）+ `jkapi.com/zz_tcping`（浙江宁波电信，
  免 key）——两只免额单节点源独力即可双确认（single_ok≥2→reachable），
  check-host 的 250/h 配额不再是可达判定的瓶颈。
- L3 多节点复核（串行小样本）：`ping.pe`（约 13 个大陆节点，≥7/13 可达即判可达）；
  `tcptest.cn`（免费 REST，~146 大陆节点取子集做 TCP 探测，结果按节点成功率
  判定）；可选 `tcpping.cn`（多运营商，需 ``TCPPING_CN_TOKEN``，缺 key 自动跳过）。
- 已评估并放弃：`api.hostmonit.com/check_port`（已 404）；`ping.chinaz.com`
  （表单 POST 仅返回渲染壳页，结果经混淆 JS 加载，反爬成本过高）；
  `tcping.cn`（PoW + 私有 WS 授权，纯 Python 无法收结果）。

保守判定逻辑（merge_verdict）：
  多节点源（pingpe/itdog/itdog_tcping/tcpping）任一 ok → reachable；
  单节点源 ≥2 个 ok → reachable；仅 1 个 ok → uncertain；
  check_host / xxapi / jkapi 单节点源 ≥2 个 fail → unreachable；
  pingpe/itdog fail + 任一其他源 fail → unreachable。
  证据分级（level）：任一成功源给出应用层确认 → "http"，仅传输层 → "tcp"。

跨轮稳定性：写 china.json 前读取上一轮结果，per-key 维护连续可达轮数
``streak``；采样置顶上轮 reachable（续保复检，防覆盖波动把稳定 CN 键
翻出池），其次上轮 uncertain（升格候选）优先复检。

纯标准库（urllib / json / threading / concurrent.futures）。运行时告警不计入
判定，仅记录 ``skipped``；单源失败不误判。
"""

import argparse
import base64
import hashlib
import http.cookiejar
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from common import (
    CHINA_FILE,
    DEFAULT_SOURCE,
    REP_RANK_FILE,
    UA,
    VALID_ALL_CN_FILE,
    VALID_ALL_CN_HTTP_FILE,
    VALID_ALL_CN_STABLE_FILE,
    VALID_ALL_FILE,
    VALID_ALL_LTD_FILE,
    VALID_DIR,
    has_token,
    line_to_key,
    merge_note_tokens,
    parse_ltd_line,
    read_json,
    request_follow,
    rewrite_latency,
    clear_note_buckets,
    cn_display_ms,
    cn_l2_ms,
    cn_mainland_ok,
    CN_LATENCY_CAP_MS,
    _rewrite_cn_speed,
    write_json,
    write_text_if_changed,
    _note,
)
from china_itdog import (
    ITDOG_BATCH_SIZE,
    ITDOG_CONCURRENCY,
    ITDOG_NODES_PER_ISP,
    ITDOG_PACING,
    ITDOG_TASK_TIMEOUT,
    ITDOG_TCPING_NODES_PER_ISP,
    ITDOG_TCPING_URL,
    _WebSocket,
    itdog_batch_run,
)

FALLBACK_SOURCE = DEFAULT_SOURCE

LIMIT_DEFAULT = 250
PINGPE_LIMIT_DEFAULT = 300
PINGPE_CONCURRENCY = 6  # ping.pe L3 有界并发（每键端到端 ~20-40s，串行太慢）
PINGPE_SLOT_GAP = 2.0  # 单 worker 键间最小间隔（对上游礼貌）
WORKERS_DEFAULT = 56  # L2 免额单节点源并发（基准 1000 键：48w≈108s / 64w≈86s / 无 429；取中保守）
TIMEOUT_DEFAULT = 10
POLL_DEADLINE = 75.0
POLL_INTERVAL = 3.0

# check-host.cc —— 呼和浩特（阿里云 AS37963），每目标仅 1 大陆节点
CHECKHOST_URL = "https://api.check-host.cc/tcp"
CHECKHOST_REPORT_URL = "https://api.check-host.cc/report/{uuid}"
CHECKHOST_NODE = "CN-HOH-Alibaba"
CH_WINDOW_SEC = 10.0
CH_PER_WINDOW = 5  # 匿名限速 5/10s
CH_HOUR_CAP = 250

# xxapi.cn —— 北京服务器（免 key）
XXAPI_URL = "https://v2.xxapi.cn/api/tcping"

# jkapi.com（无铭 API）zz_tcping —— 浙江宁波电信 1 节点（免 key，纯文本报告）。
# 单节点大陆实测，返回平均延迟 ms；目标不可达返回「所有测试均失败」。
# 与 xxapi 同属免费无限额单节点源，二者联手即可绕开 check-host 的 250/h 配额
# 独立完成双源确认（merge_verdict 单节点源 ≥2 ok → reachable）。
JKAPI_URL = "https://jkapi.com/api/zz_tcping"
JKAPI_TIMEOUT = 8.0  # 拉低单次超时上限：免额源不应拖慢整池 L2

# ping.pe —— 约 13 个大陆节点，需走 antiflood + start_token 流程
PINGPE_URL = "https://tcp.ping.pe/{host}"
PINGPE_START_URL = "https://tcp.ping.pe/ajax_startTask_v1.php"
PINGPE_RESULTS_URL = "https://tcp.ping.pe/ajax_getPingResults_v2.php"
PINGPE_ORIGIN = "https://tcp.ping.pe"
PINGPE_CN_MAJORITY = 7  # ≥7/13 大陆节点可达即判可达
ITDOG_MIN_RATIO = 0.5   # itdog 系列单源确认所需的最小节点成功率（防单节点假阳性）
PINGPE_MIN_REPORTED = 5  # 报告节点不足 → inconclusive，避免误判

# tcpping.cn —— 多运营商，需站长签发的 token（缺则跳过）
TCPPING_URL = "https://tcpping.cn/ping_api"

# tcptest.cn —— 免费大陆多节点 TCP 探测（REST），无需 key/token：
# POST /api/v1/tasks 建任务（type=tcping，target=ip:port），轮询任务状态后
# 拉取逐节点结果。节点池 ~146 个（全国各运营商），为强多节点确认源。
TCPTEST_URL = "https://www.tcptest.cn/api/v1"
TCPTEST_NODES = 10      # 每任务采样的节点数（跨省跨运营商均衡）
TCPTEST_LIMIT_DEFAULT = 150  # 每轮复核的键数上限（免费源节流）
TCPTEST_CONCURRENCY = 8  # 有界并发（每键端到端 ~2-6s）
TCPTEST_POLL_DEADLINE = 30.0
TCPTEST_REQ_TIMEOUT = 12
MULTI_MIN_NODES = 5  # 多节点源至少报告 5 个节点才可作强确认（防限流残缺样本退化）

# ip.net.coffee —— 免费大陆多节点 ICMP ping（REST，GET+轮询），无需 key：
# GET /api/ping/start?host=IP&user_ip=unknown&node=n01..n20 → 命中缓存直返
# results；未命中返回 request_id，轮询 GET /api/ping/result/{rid} 直到各节点
# 就绪。节点 ~18 个（n01/n08 常离线自动跳过），每节点 4 发 ICMP。
# 注意：仅测主机存活（ICMP），不测 TCP 端口 —— 作为多节点源单独确认可达，
# 端口层结论仍以 tcptest/itdog 等 TCP 源为准（ratio 大节点优势消除单点抖动）。
COFFEE_URL = "https://ip.net.coffee/api"
COFFEE_NODES = 10      # 每键请求的节点数（从固定池里取）
COFFEE_POOL = [f"n{i:02d}" for i in range(1, 21)]
COFFEE_CONCURRENCY = 24  # 有界并发（空闲量大，ICMP 单键 ~0.1-1s）
COFFEE_POLL_DEADLINE = 20.0
COFFEE_REQ_TIMEOUT = 12
COFFEE_MIN_RATIO = 0.5  # 节点成功率达 50% 即可单独判可达（多节点 ICMP 优势）

# pingloc.com —— 免费大陆多节点 ping/tcp_ping（纯 HTTP + SSE，零鉴权），无 key：
# GET /api/v1/node/items 拿节点列表 → POST /api/v1/task/create 建任务拿 token →
# GET /api/v1/task/exec?token=... 收 SSE 流式逐节点结果（error_code 0=成功）。
# 注意 tcp_ping 固定端口 80（UI 无自定义端口，传 port 键会被忽略）。
PINGLOC_URL = "https://www.pingloc.com/api/v1"
PINGLOC_REQ_TIMEOUT = 15
PINGLOC_NODE_TIMEOUT = 20.0

# antping.com —— 免费大陆多节点 ping/tcp（JWT + WebSocket 推送），无 key：
# GET /geek/network-tools-service/auth/publicKey 拿 JWT → 连 wss://antping.com/ws/
# 发 {"token":jwt,"code":3|4,"data":"ip[:port]","dns":"","retry":false,
#     "network":"1,2,3,4,5"}（3=ping 4=tcp-ppin；network 1电信2联通3移动4多线5海外）
# → 收 code:200 帧,每节点一条;可达 = status==200 且 speed>0。全部节点免费测。
ANTPING_URL = "https://antping.com/geek"
ANTPING_WS = "wss://antping.com/ws/"
ANTPING_REQ_TIMEOUT = 12
ANTPING_WS_IDLE = 30.0

# tcping.cn —— 免费大陆多节点 tcping（SHA-256 PoW + WS 鉴权），无 key：
# GET /api/probe/page 拿挑战 {r,s,ts,d(=difficulty)} → 纯 Python 算
# request_hash=sha256(cl)/yc(9轮)/bc(pow-salt) → 暴力搜 nonce 使
# sha256(f"{r}\n{salt}\n{request_hash}\n{nonce}") 前 d 位为 0 →
# POST /api/probe/task（body 含 r/ts/p/nonce）拿 {k,r,u} → 连 wss:{u} 发
# {"k":..,"r":..} → 收 hello/start/result/complete 逐节点结果（rtt_avg）。
TCPINGCN_URL = "https://www.tcping.cn"
TCPINGCN_REQ_TIMEOUT = 15
TCPINGCN_POW_DIFFICULTY = 15
TCPINGCN_WS_IDLE = 40.0

# ping.chinaz.com —— 免费大陆多节点 ping（服务端渲染 token + WS），无 key：
# GET https://ping.chinaz.com/<host> 拿壳页（let token=...; serverList 53 节点）
# → 连 wss://tooldata.chinaz.com/pingwebsocket 发 {"keyword":host,"token":token}
# → 收 code:1 单节点结果帧(timeMs/tTL)，code:10002 帧即结束。
CHINAZ_URL = "https://ping.chinaz.com"
CHINAZ_WS = "wss://tooldata.chinaz.com/pingwebsocket"
CHINAZ_REQ_TIMEOUT = 15
CHINAZ_WS_IDLE = 40.0
# ping.chinaz 的结果流不随完成发送 10002 结束帧：实测 51~53 节点约在
# WS 打开后 ~5s 内全部到齐，剩余 ~35s 全是静默（每键白等 40s 上限）。
# 静默 SETTLE 秒后即收尾，把每键端到端从 ~41s 压到结果跨度 + SETTLE（~12s）。
CHINAZ_WS_SETTLE = 6.0
CHINAZ_MIN_RATIO = 0.4  # 51~53 节点可能个别缺席，放宽阈值

# itdog.cn —— 无账号批量 HTTP 探活（每任务约 5 目标 × 3 节点，需走 WebSocket 收结果）

CN_TOKEN = "CN"


class RateLimited(RuntimeError):
    pass


class RateLimiter:
    """滑动窗口限速器（check-host 匿名配额小，必须控速）。"""

    def __init__(self, window: float, per_window: int, hour_cap: int):
        self.window = window
        self.per_window = per_window
        self.hour_cap = hour_cap
        self._lock = threading.Lock()
        self._times: list[float] = []
        self._hour_count = 0
        self._hour_start: float = 0.0

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._times = [t for t in self._times if now - t < self.window]
                hour_ago = now - 3600
                if self._hour_start < hour_ago:
                    self._hour_count = 0
                    self._hour_start = now
                if self.hour_cap and self._hour_count >= self.hour_cap:
                    raise RateLimited("hourly cap reached")
                if len(self._times) < self.per_window:
                    self._times.append(now)
                    self._hour_count += 1
                    return
                wait = self.window - (now - self._times[0])
            time.sleep(max(wait, 0.05))


# ------------------------------------------------------------ 解析函数（纯）

def parse_check_host_report(payload) -> dict:
    """``/report/<uuid>`` → ``{"status", "ok", "ms", "error"}``。"""
    if not isinstance(payload, dict):
        return {"status": "error", "ok": False, "ms": None, "error": "bad payload"}
    data = payload.get("data")
    if not isinstance(data, dict):
        return {"status": "error", "ok": False, "ms": None, "error": "no data"}
    checks = (data.get(CHECKHOST_NODE) or {}).get("checks") or []
    if not checks:
        return {"status": "pending", "ok": False, "ms": None, "error": ""}
    c = checks[0]
    if c.get("status") == 1:
        return {"status": "ok", "ok": True, "ms": c.get("connectiontime"), "error": ""}
    return {
        "status": "fail",
        "ok": False,
        "ms": None,
        "error": str(c.get("errortext") or "unreachable")[:120],
    }


def parse_jkapi(text: str) -> dict:
    """``jkapi.com zz_tcping`` 纯文本报告 → ``{"status", "ok", "ms", "error"}``。

    成功报告形如::

        === TCPing测试报告 ===
        目标地址: 223.5.5.5 (223.5.5.5)
        目标端口: 443
        最快延迟: 9.65 ms
        ...
        平均延迟: 10.95 ms
        测试节点:浙江宁波电信

    目标不可达统一返回「所有测试均失败，请检查目标可用性」。
    """
    if "TCPing测试报告" in text:
        m = re.search(r"平均延迟:\s*([0-9.]+)\s*ms", text)
        if m:
            return {"status": "ok", "ok": True, "ms": float(m.group(1)), "error": ""}
        return {"status": "inconclusive", "ok": False, "ms": None,
                "error": "report without avg latency"}
    if "所有测试均失败" in text:
        return {"status": "fail", "ok": False, "ms": None, "error": "unreachable"}
    return {"status": "inconclusive", "ok": False, "ms": None,
            "error": "unrecognized text"}


def jkapi_check(ip: str, port: str, timeout: float) -> dict:
    """jkapi 单节点实测（浙江宁波电信，免 key）。不抛未捕获异常。"""
    url = f"{JKAPI_URL}?host={ip}&port={port}"
    try:
        status, _, resp = request_follow(
            url, {"User-Agent": UA}, min(timeout, JKAPI_TIMEOUT)
        )
    except urllib.error.HTTPError as e:
        return {"status": "rate_limited" if e.code == 429 else "error",
                "ok": False, "ms": None, "error": f"http {e.code}"}
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None, "error": str(e)[:120]}
    if status != 200:
        return {"status": "error", "ok": False, "ms": None, "error": f"http {status}"}
    return parse_jkapi(resp.decode("utf-8", "replace"))


def parse_xxapi(payload) -> dict:
    """``xxapi.cn`` → ``{"status", "ok", "ms", "error"}``。"""
    if isinstance(payload, dict):
        if payload.get("code") == 200:
            data = payload.get("data") or {}
            ping = data.get("ping")
            if isinstance(ping, str):
                m = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*ms?\s*$", ping.strip())
                if m:
                    return {"status": "ok", "ok": True, "ms": float(m.group(1)), "error": ""}
                if ping.strip():
                    return {
                        "status": "fail",
                        "ok": False,
                        "ms": None,
                        "error": ping.strip()[:120],
                    }
            elif isinstance(ping, (int, float)):
                return {"status": "ok", "ok": True, "ms": float(ping), "error": ""}
    return {"status": "error", "ok": False, "ms": None, "error": "bad payload"}


def parse_pingpe_page(html: str) -> dict:
    """从 ping.pe 页面提取 antiflood cookie、start token 与大陆节点 id。"""
    cookie = None
    m = re.search(r'document\.cookie\s*=\s*"antiflood=([0-9a-fA-F]+)', html)
    if m:
        cookie = m.group(1)
    token = None
    m = re.search(r'var\s+taskStartToken\s*=\s*"([^"]+)"', html)
    if m:
        token = m.group(1)
    cn_ids = sorted(set(re.findall(r"data-pinger-id='(CN_[^']+)'", html)))
    if not cn_ids:
        cn_ids = sorted(set(re.findall(r"id='ping-(CN_[^']+)-tr'", html)))
    return {"cookie": cookie, "token": token, "cn_ids": cn_ids, "has_page": bool(token)}


def parse_pingpe_results(payload, cn_ids: list[str]) -> dict:
    """聚合大陆节点结果：``result`` 单位为微秒，0=成功、1=失败、>1=成功+延迟。"""
    data = payload.get("data", []) if isinstance(payload, dict) else []
    expected = set(cn_ids)
    reported = []
    for item in data:
        nid = item.get("node_id", "")
        if not isinstance(nid, str):
            continue
        if nid.startswith("CN_") and (not expected or nid in expected):
            reported.append(item)
    ok = 0
    latencies = []
    for item in reported:
        result = item.get("result")
        if isinstance(result, bool):
            success = result
        elif isinstance(result, (int, float)):
            if result == 1:
                success = False
            else:
                success = True
                if result > 0:
                    latencies.append(float(result) / 1000.0)
        else:
            continue
        if success:
            ok += 1
    ms = round(sum(latencies) / len(latencies), 1) if latencies else None
    return {"reported": len(reported), "ok": ok, "ms": ms}


def pingpe_verdict(agg: dict) -> dict:
    """大陆节点多数可达 → 判可达；报告不足 → inconclusive。"""
    reported = agg["reported"]
    if reported < PINGPE_MIN_REPORTED:
        return {"status": "inconclusive", "ok": False, "error": "too few nodes reported"}
    ok = agg["ok"] >= PINGPE_CN_MAJORITY or (
        agg["ok"] > 0 and agg["ok"] / reported >= 0.6
    )
    return {
        "status": "ok" if ok else "fail",
        "ok": ok,
        "error": "" if ok else "majority of CN nodes unreachable",
    }


def parse_tcpping(payload) -> dict:
    """``tcpping.cn /ping_api`` 多节点结果（best-effort，格式随站点演进）。"""
    def find_nodes(obj):
        if isinstance(obj, list):
            return obj
        if isinstance(obj, dict):
            for key in ("nodes", "results", "data", "list"):
                v = obj.get(key)
                if isinstance(v, list):
                    return v
            for key in ("nodes", "results", "data", "list"):
                v = obj.get(key)
                if isinstance(v, dict):
                    result = find_nodes(v)
                    if result:
                        return result
        return []

    nodes = find_nodes(payload)
    total = 0
    ok = 0
    lats = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        status = n.get("status") or n.get("code") or n.get("state")
        failed = isinstance(status, str) and status.lower() in (
            "0", "fail", "failed", "error", "timeout", "offline"
        )
        total += 1
        if failed:
            continue
        ok += 1
        try:
            lat = float(n.get("ms") or n.get("delay") or n.get("time") or n.get("latency"))
        except (TypeError, ValueError):
            lat = 0.0
        if lat > 0:
            lats.append(lat)
    if total == 0:
        return {"status": "error", "ok": False, "ms": None, "error": "empty result"}
    reachable = ok >= total * 0.6
    return {
        "status": "ok" if reachable else "fail",
        "ok": reachable,
        "ms": round(sum(lats) / len(lats), 1) if lats else None,
        "error": "" if reachable else f"{ok}/{total} nodes reachable",
        "total": total,
    }


# ------------------------------------------------------------ 探测 I/O（网络）

def check_host_check(ip: str, port: str, limiter: RateLimiter, timeout: float, api_key: str) -> dict:
    try:
        limiter.acquire()
    except RateLimited:
        return {"status": "rate_limited", "ok": False, "ms": None, "error": "hourly cap"}
    hdrs = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": UA,
    }
    if api_key:
        hdrs["Authorization"] = f"Bearer {api_key}"
    body = json.dumps({"target": ip, "port": int(port), "region": ["CN"]}).encode()
    try:
        status, _, resp = request_follow(CHECKHOST_URL, hdrs, timeout, method="POST", data=body)
    except urllib.error.HTTPError as e:
        return {"status": "rate_limited" if e.code == 429 else "error",
                "ok": False, "ms": None, "error": f"http {e.code}"}
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None, "error": str(e)[:120]}
    if status == 429:
        return {"status": "rate_limited", "ok": False, "ms": None, "error": "rate limited"}
    if status != 200:
        return {"status": "error", "ok": False, "ms": None, "error": f"http {status}"}
    try:
        payload = json.loads(resp.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {"status": "error", "ok": False, "ms": None, "error": "bad json"}
    uuid = payload.get("uuid") or payload.get("request_id")
    if not uuid:
        return {"status": "error", "ok": False, "ms": None, "error": "no uuid"}
    deadline = time.monotonic() + POLL_DEADLINE
    last = None
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        try:
            status, _, resp = request_follow(
                CHECKHOST_REPORT_URL.format(uuid=uuid),
                {"Accept": "application/json", "User-Agent": UA},
                timeout,
            )
            if status != 200:
                continue
            payload = json.loads(resp.decode("utf-8", "replace"))
        except Exception as exc:
            logging.debug("check-host poll: %s", exc)
            continue
        last = parse_check_host_report(payload)
        if last["status"] in ("ok", "fail"):
            return last
    return last or {"status": "timeout", "ok": False, "ms": None, "error": "poll timeout"}


def xxapi_check(ip: str, port: str, timeout: float) -> dict:
    url = f"{XXAPI_URL}?address={ip}&port={port}"
    try:
        status, _, resp = request_follow(url, {"User-Agent": UA, "Accept": "application/json"}, timeout)
    except urllib.error.HTTPError as e:
        return {"status": "rate_limited" if e.code == 429 else "error",
                "ok": False, "ms": None, "error": f"http {e.code}"}
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None, "error": str(e)[:120]}
    if status != 200:
        return {"status": "error", "ok": False, "ms": None, "error": f"http {status}"}
    try:
        payload = json.loads(resp.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {"status": "error", "ok": False, "ms": None, "error": "bad json"}
    return parse_xxapi(payload)


def pingpe_check(ip: str, port: str, timeout: float) -> dict:
    base = PINGPE_URL.format(host=f"{ip}:{port}")
    hdrs = {"User-Agent": UA}
    try:
        _, _, body = request_follow(base, hdrs, timeout)
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None, "error": str(e)[:120], "count": 0, "ok_count": 0}
    html = body.decode("utf-8", "replace")
    parsed = parse_pingpe_page(html)
    cookie = parsed["cookie"]
    if not parsed["has_page"] and cookie:
        try:
            _, _, body = request_follow(
                base + "?browsercheck=ok",
                {**hdrs, "Cookie": f"antiflood={cookie}"},
                timeout,
            )
            re_parsed = parse_pingpe_page(body.decode("utf-8", "replace"))
            if re_parsed["has_page"]:
                parsed = re_parsed
        except Exception as exc:
            logging.debug("ping.pe fetch: %s", exc)
    token = parsed["token"]
    if not token:
        return {"status": "error", "ok": False, "ms": None, "error": "no start token", "count": 0, "ok_count": 0}
    form = urllib.parse.urlencode({"query": f"{ip}:{port}", "start_token": token}).encode()
    shdrs = {
        "User-Agent": UA,
        "Origin": PINGPE_ORIGIN,
        "Referer": base,
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if cookie:
        shdrs["Cookie"] = f"antiflood={cookie}"
    stream_id = None
    for _ in range(3):
        try:
            _, _, body = request_follow(PINGPE_START_URL, shdrs, timeout, method="POST", data=form)
            payload = json.loads(body.decode("utf-8", "replace"))
        except Exception as e:
            return {"status": "error", "ok": False, "ms": None, "error": str(e)[:120], "count": 0, "ok_count": 0}
        if isinstance(payload, dict) and payload.get("ok"):
            stream_id = (payload.get("data") or {}).get("stream_id")
            break
        time.sleep(5)
    if not stream_id:
        return {"status": "error", "ok": False, "ms": None, "error": "no stream_id", "count": 0, "ok_count": 0}
    cn_ids = parsed["cn_ids"]
    deadline = time.monotonic() + POLL_DEADLINE
    polls = 0
    last_agg = None
    while time.monotonic() < deadline:
        polls += 1
        url = f"{PINGPE_RESULTS_URL}?type=tcp&totalPolls={polls}&stream_id={stream_id}"
        try:
            _, _, body = request_follow(
                url, {"User-Agent": UA, **({"Cookie": f"antiflood={cookie}"} if cookie else {})}, timeout
            )
            payload = json.loads(body.decode("utf-8", "replace"))
        except Exception as exc:
            logging.debug("ping.pe results poll: %s", exc)
            time.sleep(POLL_INTERVAL)
            continue
        last_agg = parse_pingpe_results(payload, cn_ids)
        reported = last_agg["reported"]
        expected = len(cn_ids) or reported
        if expected and reported >= expected:
            break
        if payload.get("state", {}).get("outstandingNodeCount") == 0 and reported:
            break
        time.sleep(POLL_INTERVAL)
    if last_agg is None:
        return {"status": "error", "ok": False, "ms": None, "error": "no results", "count": 0, "ok_count": 0}
    verdict = pingpe_verdict(last_agg)
    return {
        "status": verdict["status"],
        "ok": verdict["ok"],
        "ms": last_agg["ms"],
        "error": verdict["error"],
        "count": last_agg["reported"],
        "ok_count": last_agg["ok"],
    }


def tcpping_check(ip: str, port: str, token: str, timeout: float) -> dict:
    if not token:
        return {"status": "skipped", "ok": False, "ms": None, "error": "no token"}
    url = f"{TCPPING_URL}?url={ip}&port={port}&token={urllib.parse.quote(token)}"
    try:
        status, _, resp = request_follow(url, {"User-Agent": UA, "Accept": "application/json"}, timeout)
    except urllib.error.HTTPError as e:
        return {"status": "error", "ok": False, "ms": None, "error": f"http {e.code}"}
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None, "error": str(e)[:120]}
    if status != 200:
        return {"status": "error", "ok": False, "ms": None, "error": f"http {status}"}
    try:
        payload = json.loads(resp.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {"status": "error", "ok": False, "ms": None, "error": "bad json"}
    return parse_tcpping(payload)


# ------------------------------------------------------------ tcptest.cn 多节点源

_tcptest_nodes_cache: tuple[float, list[dict]] | None = None


def tcptest_fetch_nodes(
    timeout: float, max_nodes: int = 800, force: bool = False
) -> list[dict]:
    """拉取 tcptest.cn 在线节点列表（带页游标翻页），进程内缓存。

    返回 ``[{uuid, name, operator, city, display_location, ...}]``，仅含
    ``enabled=true`` 且 ``runtime_state=online`` 的节点；失败返回 []。
    """
    global _tcptest_nodes_cache
    if not force and _tcptest_nodes_cache is not None:
        return _tcptest_nodes_cache[1]
    nodes: list[dict] = []
    after = "0"
    seen = 0
    while seen < max_nodes:
        url = f"{TCPTEST_URL}/nodes?after={after}&limit=500"
        try:
            status, _, resp = request_follow(
                url, {"User-Agent": UA, "Accept": "application/json"}, timeout
            )
        except Exception as e:
            logging.debug("tcptest nodes: %s", e)
            break
        if status != 200:
            logging.debug("tcptest nodes http %s", status)
            break
        try:
            payload = json.loads(resp.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            break
        batch = payload.get("nodes", [])
        nodes.extend(batch)
        seen += len(batch)
        if payload.get("has_more") and payload.get("next_cursor"):
            after = str(payload["next_cursor"])
            if str(after) == "0":
                break
        else:
            break
    online = [
        n for n in nodes
        if n.get("enabled") and n.get("runtime_state") == "online"
    ]
    _tcptest_nodes_cache = (time.monotonic(), online)
    return online


def tcptest_pick_nodes(nodes: list[dict], count: int) -> list[str]:
    """按运营商均衡采样 ``count`` 个节点的 uuid（跨省跨 ISP，避免扎堆）。"""
    if not nodes:
        return []
    by_isp: dict[str, list[dict]] = {}
    for n in nodes:
        isp = n.get("operator") or "?"
        by_isp.setdefault(isp, []).append(n)
    picked: list[str] = []
    used = set()
    order = sorted(by_isp.items(), key=lambda kv: len(kv[1]), reverse=True)
    while len(picked) < count and sum(len(v) for _, v in order) > 0:
        for _, bucket in order:
            if not bucket:
                continue
            n = bucket.pop(0)
            uid = n.get("uuid")
            if not uid or uid in used:
                continue
            used.add(uid)
            picked.append(uid)
            if len(picked) >= count:
                break
    return picked


def tcptest_check(ip: str, port: str, timeout: float, node_uuids: list[str]) -> dict:
    """tcptest.cn 单键 TCP 多点探测：建任务 → 轮询 → 逐节点结果聚合。

    返回与 itdog_aggregate 同构的 source_result：
    ``{status, ok, ms, error, level, ok_nodes, nodes, ratio}``。
    节点成功 = 直连 TCP 握手成功（``success==true`` 且 ``connected==true``），
    ``ms`` 取成功节点最小 RTT。整个探测为传输层 → ``level="tcp"``。
    """
    if not node_uuids:
        return {"status": "error", "ok": False, "ms": None,
                "error": "no nodes", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    target = f"[{ip}]:{port}" if ":" in ip and not ip.startswith("[") else f"{ip}:{port}"
    body = {
        "type": "tcping",
        "target": target,
        "node_filter": {"node_uuids": node_uuids[:TCPTEST_NODES]},
    }
    try:
        status, _, resp = request_follow(
            f"{TCPTEST_URL}/tasks",
            {"User-Agent": UA, "Accept": "application/json",
             "Content-Type": "application/json"},
            TCPTEST_REQ_TIMEOUT, method="POST",
            data=json.dumps(body).encode("utf-8"),
        )
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if status == 429:
        return {"status": "rate_limited", "ok": False, "ms": None,
                "error": "rate limited", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if status not in (200, 201, 202):
        return {"status": "error", "ok": False, "ms": None,
                "error": f"create task http {status}", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    try:
        task = json.loads(resp.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {"status": "error", "ok": False, "ms": None,
                "error": "bad task json", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    tid = task.get("id")
    if not tid:
        return {"status": "error", "ok": False, "ms": None,
                "error": "no task id", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    deadline = time.monotonic() + TCPTEST_POLL_DEADLINE
    total = task.get("expected_results") or len(node_uuids)
    while time.monotonic() < deadline:
        try:
            status, _, resp = request_follow(
                f"{TCPTEST_URL}/tasks/{tid}",
                {"User-Agent": UA, "Accept": "application/json"},
                TCPTEST_REQ_TIMEOUT,
            )
        except Exception:
            time.sleep(1.0)
            continue
        if status != 200:
            break
        try:
            state = json.loads(resp.decode("utf-8", "replace")).get("state")
        except json.JSONDecodeError:
            break
        if state in ("succeeded", "failed", "cancelled"):
            break
        time.sleep(1.0)
    try:
        status, _, resp = request_follow(
            f"{TCPTEST_URL}/tasks/{tid}/results",
            {"User-Agent": UA, "Accept": "application/json"},
            TCPTEST_REQ_TIMEOUT,
        )
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if status != 200:
        return {"status": "error", "ok": False, "ms": None,
                "error": f"results http {status}", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    try:
        results = json.loads(resp.decode("utf-8", "replace")).get("results", [])
    except json.JSONDecodeError:
        return {"status": "error", "ok": False, "ms": None,
                "error": "bad results json", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    real = [r for r in results if isinstance(r, dict)]
    ok = [
        r for r in real
        if r.get("success") is True
        and (r.get("data") or {}).get("connected") is True
    ]
    nodes = len(real) or len(node_uuids) or (total or len(node_uuids))
    if not real:
        nodes = total or len(node_uuids)
    if ok:
        mss = [r["data"].get("avg_ms") or r["data"].get("duration_ms")
               for r in ok
               if isinstance(r.get("data"), dict)]
        valids = [m for m in mss if isinstance(m, (int, float)) and m > 0]
        return {
            "status": "ok", "ok": True,
            "ms": round(min(valids), 1) if valids else None,
            "error": "", "level": "tcp",
            "ok_nodes": len(ok), "nodes": nodes,
            "ratio": round(len(ok) / nodes, 3),
        }
    return {
        "status": "fail", "ok": False, "ms": None,
        "error": f"unreachable ({len(real)} nodes)",
        "level": None, "ok_nodes": 0, "nodes": nodes, "ratio": 0.0,
    }


def coffee_check(ip: str, timeout: float, nodes: list[str] | None = None) -> dict:
    """ip.net.coffee 单键多节点 ICMP 探测（GET + 轮询）。

    返回 source_result 同构字典：``{status, ok, ms, error, level, ok_nodes,
    nodes, ratio}``。节点成功 = 该节点至少 1 发 ICMP 应答（``["OK", ...]``），
    ``ms`` 取成功节点最小 RTT。仅 ICMP 主机存活 → ``level="icmp"``。
    """
    node_ids = nodes or COFFEE_POOL
    qs = "&".join(f"node={n}" for n in node_ids)
    url = f"{COFFEE_URL}/ping/start?host={ip}&user_ip=unknown&{qs}"
    try:
        status, _, resp = request_follow(
            url, {"User-Agent": UA, "Accept": "application/json"}, COFFEE_REQ_TIMEOUT
        )
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if status == 429:
        return {"status": "rate_limited", "ok": False, "ms": None,
                "error": "rate limited", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if status != 200:
        return {"status": "error", "ok": False, "ms": None,
                "error": f"start http {status}", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    try:
        payload = json.loads(resp.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {"status": "error", "ok": False, "ms": None,
                "error": "bad start json", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    results = payload.get("results")
    if payload.get("cached") and isinstance(results, dict):
        return _coffee_aggregate(results)
    rid = payload.get("request_id")
    if not rid:
        return {"status": "error", "ok": False, "ms": None,
                "error": "no request_id", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    deadline = time.monotonic() + COFFEE_POLL_DEADLINE
    while time.monotonic() < deadline:
        time.sleep(2.0)
        try:
            status, _, resp = request_follow(
                f"{COFFEE_URL}/ping/result/{rid}",
                {"User-Agent": UA, "Accept": "application/json"}, COFFEE_REQ_TIMEOUT
            )
        except Exception:
            continue
        if status != 200:
            continue
        try:
            payload = json.loads(resp.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            continue
        results = payload.get("results")
        if isinstance(results, dict) and any(v is not None for v in results.values()):
            return _coffee_aggregate(results)
    return {"status": "error", "ok": False, "ms": None,
            "error": "poll timeout", "level": None,
            "ok_nodes": 0, "nodes": 0, "ratio": None}


def _coffee_aggregate(results: dict) -> dict:
    """聚合 coffee 结果：results = {node: [[["OK", ms, ip], ...]]}。"""
    ok_nodes = 0
    ms_values: list[float] = []
    for node, rounds in results.items():
        if not isinstance(rounds, list) or not rounds:
            continue
        node_ok = False
        for probe in rounds[0]:
            if isinstance(probe, (list, tuple)) and probe and probe[0] == "OK":
                node_ok = True
                if len(probe) > 1 and isinstance(probe[1], (int, float)) and probe[1] > 0:
                    ms_values.append(probe[1])
                break
        if node_ok:
            ok_nodes += 1
    nodes = len([n for n in results if isinstance(results[n], list) and results[n]])
    if ok_nodes:
        return {
            "status": "ok", "ok": True,
            "ms": round(min(ms_values), 1) if ms_values else None,
            "error": "", "level": "icmp",
            "ok_nodes": ok_nodes, "nodes": nodes,
            "ratio": round(ok_nodes / nodes, 3) if nodes else None,
        }
    return {
        "status": "fail", "ok": False, "ms": None,
        "error": f"icmp unreachable ({nodes} nodes)", "level": None,
        "ok_nodes": 0, "nodes": nodes, "ratio": 0.0 if nodes else None,
    }


def pingloc_check(ip: str, timeout: float, method: str = "ping") -> dict:
    """pingloc.com 单键多节点探测（纯 HTTP + SSE，零鉴权）。

    ``method``: "ping"（ICMP）或 "tcp_ping"（固定端口 80 的 TCP）。返回
    source_result 同构字典；节点成功 = SSE 回调 ``error_code==0`` 且有
    ``latency``。应用层/tcp 层分别给 ``level``；``ms`` 取成功节点最小 RTT。
    """
    try:
        status, _, resp = request_follow(
            f"{PINGLOC_URL}/node/items",
            {"User-Agent": UA, "Accept": "application/json"},
            timeout,
        )
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if status != 200:
        return {"status": "error", "ok": False, "ms": None,
                "error": f"nodes http {status}", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    try:
        payload = json.loads(resp.decode("utf-8", "replace"))
        nodes = payload.get("data", []) if isinstance(payload, dict) else []
    except (json.JSONDecodeError, TypeError):
        return {"status": "error", "ok": False, "ms": None,
                "error": "bad nodes json", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if not nodes:
        return {"status": "error", "ok": False, "ms": None,
                "error": "no pingloc nodes", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    try:
        status, _, resp = request_follow(
            f"{PINGLOC_URL}/task/create",
            {"User-Agent": UA, "Accept": "application/json",
             "Content-Type": "application/json"},
            timeout, method="POST",
            data=json.dumps({
                "host": ip, "method": method, "dns": "",
                "isp": [], "is_continue": False,
            }).encode("utf-8"),
        )
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if status != 200:
        return {"status": "error", "ok": False, "ms": None,
                "error": f"create http {status}", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    try:
        payload = json.loads(resp.decode("utf-8", "replace"))
        data = payload.get("data") if isinstance(payload, dict) else None
        token = data.get("token") if isinstance(data, dict) else None
    except (json.JSONDecodeError, TypeError, AttributeError):
        return {"status": "error", "ok": False, "ms": None,
                "error": "bad create json", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if not token:
        return {"status": "error", "ok": False, "ms": None,
                "error": "no token", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    try:
        req = urllib.request.Request(
            f"{PINGLOC_URL}/task/exec?token={urllib.parse.quote(token)}",
            headers={"User-Agent": UA, "Accept": "text/event-stream"},
        )
        with urllib.request.urlopen(req, timeout=timeout + PINGLOC_NODE_TIMEOUT) as resp:
            chunks = b""
            while True:
                got = resp.read(65536)
                if not got:
                    break
                chunks += got
            sse = chunks.decode("utf-8", "replace")
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    ok_nodes = 0
    totals = 0
    ms_values: list[float] = []
    for block in sse.split("\n\n"):
        payload = None
        for line in block.splitlines():
            if line.startswith("data:"):
                payload = line[5:].strip()
        if not payload:
            continue
        try:
            ev = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if ev.get("error_code") == 0 and isinstance(ev.get("latency"), (int, float)):
            totals += 1
            ok_nodes += 1
            if ev.get("latency", 0) > 0:
                ms_values.append(ev["latency"])
        elif "callback" in block and ev.get("error_code") is not None:
            totals += 1
    nodes = totals or len(nodes)
    if ok_nodes:
        return {
            "status": "ok", "ok": True,
            "ms": round(min(ms_values), 1) if ms_values else None,
            "error": "", "level": "tcp" if method == "tcp_ping" else "icmp",
            "ok_nodes": ok_nodes, "nodes": nodes,
            "ratio": round(ok_nodes / nodes, 3),
        }
    return {
        "status": "fail", "ok": False, "ms": None,
        "error": f"unreachable ({nodes} nodes)", "level": None,
        "ok_nodes": 0, "nodes": nodes, "ratio": 0.0,
    }


def antping_check(ip: str, port: str, timeout: float) -> dict:
    """antping.com 单键多节点探测（JWT + WebSocket）。

    code 3 = PING（ICMP）、4 = TCP-PING（IP:port）。全部网络分组免费可测。
    节点成功 = ``status==200 且 speed>0``；``ms`` 取成功节点最小 speed。
    """
    try:
        status, _, resp = request_follow(
            f"{ANTPING_URL}/network-tools-service/auth/publicKey",
            {"User-Agent": UA, "app-id": "2", "Accept": "application/json",
             "Referer": "https://antping.com/ping"},
            ANTPING_REQ_TIMEOUT,
        )
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if status != 200:
        return {"status": "error", "ok": False, "ms": None,
                "error": f"auth http {status}", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    try:
        jwt = json.loads(resp.decode("utf-8", "replace")).get("data")
    except json.JSONDecodeError:
        return {"status": "error", "ok": False, "ms": None,
                "error": "bad auth json", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if not jwt:
        return {"status": "error", "ok": False, "ms": None,
                "error": "no jwt", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    code = 4 if port else 3
    target = f"{ip}:{port}" if port else ip
    try:
        ws = _WebSocket(ANTPING_WS, timeout=ANTPING_WS_IDLE)
        ws.send_text(json.dumps({
            "token": jwt, "code": code, "data": target,
            "dns": "", "retry": False, "network": "1,2,3,4,5",
        }, ensure_ascii=False))
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    results: list[dict] = []
    deadline = time.monotonic() + ANTPING_WS_IDLE
    while time.monotonic() < deadline:
        try:
            ws.settimeout(max(1.0, deadline - time.monotonic()))
            kind, msg = ws.read()
        except Exception as e:
            break
        if kind in ("err", "close", "closed"):
            break
        if kind == "timeout":
            break
        if not isinstance(msg, dict):
            continue
        data = msg.get("data")
        if isinstance(data, dict) and data.get("cmd") == code:
            results.append(data)
    ws.close()
    ok = [r for r in results if r.get("status") == 200 and (r.get("speed") or 0) > 0]
    nodes = len(results) or 1
    if ok:
        mss = [r["speed"] for r in ok if r.get("speed")]
        return {
            "status": "ok", "ok": True,
            "ms": round(min(mss), 1), "error": "",
            "level": "tcp" if code == 4 else "icmp",
            "ok_nodes": len(ok), "nodes": nodes,
            "ratio": round(len(ok) / nodes, 3),
        }
    return {
        "status": "fail", "ok": False, "ms": None,
        "error": f"unreachable ({nodes} nodes)", "level": None,
        "ok_nodes": 0, "nodes": nodes, "ratio": 0.0,
    }


def tcpingcn_check(ip: str, port: str, timeout: float) -> dict:
    """tcping.cn 单键多节点 TCP 探测（SHA-256 PoW + WS 鉴权，纯 Python）。

    PoW 是标准 SHA-256（与前端逐字节一致，difficulty 15 ~0.3-0.5s），无 wasm/
    无 JS 依赖。节点成功 = ``rtt_avg>0``。传输层 → ``level="tcp"``。
    """
    cookie = _tcpingcn_page_cookie()
    try:
        page = _tcpingcn_get(f"{TCPINGCN_URL}/api/probe/page", cookie=cookie)
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if not isinstance(page, dict):
        return {"status": "error", "ok": False, "ms": None,
                "error": "bad page json", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    r, s, ts = page.get("r"), page.get("s"), page.get("ts")
    d = page.get("d") or TCPINGCN_POW_DIFFICULTY
    if not all((r, s, ts)):
        return {"status": "error", "ok": False, "ms": None,
                "error": "no challenge", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    u = {"type": "tcping", "host": ip, "port": int(port or 0),
         "scope": "global", "region": "all", "ip_type": 1,
         "dns_server": "", "dns_record_type": "", "slow": False}
    request_hash = _tcpcn_b64url_sha256(_tcpcn_cl(u))
    p = _tcpcn_yc(r, s, u, ts, request_hash)
    salt = _tcpcn_bc(r, s, request_hash)
    try:
        nonce, _ = _tcpcn_pow_solve(r, salt, request_hash, d)
    except RuntimeError as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    u2 = dict(u, r=r, ts=int(ts), p=p, nonce=nonce,
              via="0", user_agent="", method="", referer="", cookie="")
    try:
        task = _tcpingcn_post(f"{TCPINGCN_URL}/api/probe/task", u2, cookie=cookie)
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if not isinstance(task, dict) or not task.get("k") or not task.get("u"):
        return {"status": "error", "ok": False, "ms": None,
                "error": "no task", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    ws_url = f"wss://www.tcping.cn{task['u']}"
    try:
        ws = _WebSocket(ws_url, timeout=TCPINGCN_WS_IDLE)
        ws.send_text(json.dumps({"k": task["k"], "r": task["r"]}))
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    rows: list[dict] = []
    deadline = time.monotonic() + TCPINGCN_WS_IDLE
    while time.monotonic() < deadline:
        try:
            ws.settimeout(max(1.0, deadline - time.monotonic()))
            kind, msg = ws.read()
        except Exception as e:
            break
        if kind in ("err", "close", "closed"):
            break
        if kind == "timeout":
            break
        if not isinstance(msg, dict):
            continue
        if msg.get("event") == "result":
            data = msg.get("data") or {}
            if isinstance(data, dict):
                rows.append(data)
        elif msg.get("event") == "complete":
            break
    ws.close()
    ok = [r for r in rows if (r.get("rtt_avg") or 0) > 0]
    nodes = len(rows)
    if ok:
        mss = [r["rtt_avg"] for r in ok if r.get("rtt_avg")]
        return {
            "status": "ok", "ok": True,
            "ms": round(min(mss), 1), "error": "",
            "level": "tcp", "ok_nodes": len(ok), "nodes": nodes,
            "ratio": round(len(ok) / nodes, 3) if nodes else None,
        }
    return {
        "status": "fail", "ok": False, "ms": None,
        "error": f"unreachable ({nodes} nodes)", "level": None,
        "ok_nodes": 0, "nodes": nodes, "ratio": 0.0 if nodes else None,
    }


def _tcpingcn_page_cookie() -> str:
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.open(urllib.request.Request(
        f"{TCPINGCN_URL}/ping", headers={"User-Agent": UA}), timeout=TCPINGCN_REQ_TIMEOUT)
    return "; ".join(f"{c.name}={c.value}" for c in cj)


def _tcpingcn_get(url: str, cookie: str = "") -> object:
    headers = {"User-Agent": UA, "Accept": "application/json",
               "Referer": f"{TCPINGCN_URL}/ping"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=TCPINGCN_REQ_TIMEOUT) as resp:
        return json.loads(resp.read())


def _tcpingcn_post(url: str, body: dict, cookie: str = "") -> object:
    headers = {"User-Agent": UA, "Accept": "application/json",
               "Referer": f"{TCPINGCN_URL}/ping",
               "Content-Type": "application/json",
               "Origin": TCPINGCN_URL, "X-Requested-With": "XMLHttpRequest"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TCPINGCN_REQ_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}")


def _tcpcn_b64url_sha256(s: str) -> str:
    return base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()\
        .replace("+", "-").replace("/", "_").rstrip("=")


def _tcpcn_f2(typ: str, host: str) -> str:
    h = host.strip()
    if typ == "http":
        return h
    h = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", h)
    h = re.sub(r"^[^@/]*@", "", h)
    return re.split(r"[/?#]", h)[0].rstrip("/")


def _tcpcn_d2(o: dict) -> dict:
    i = dict(o)
    i["type"] = str(i.get("type", "")).strip().lower()
    i["host"] = _tcpcn_f2(i.get("type"), o.get("host", ""))
    i["region"] = str(i.get("region", "")).strip().lower()
    i["method"] = str(i.get("method", "")).strip().upper()
    i["dns_server"] = str(i.get("dns_server", "")).strip()
    i["dns_record_type"] = str(i.get("dns_record_type", "")).strip().upper()
    i["via"] = str(i.get("via", "")).strip()
    return i


def _tcpcn_cl(o: dict) -> str:
    i = _tcpcn_d2(o)
    return "\n".join([
        i["type"] or "", i["host"] or "", str(o.get("port") or 0),
        o.get("scope") or "", i["region"] or "", str(o.get("ip_type") or 0),
        i.get("user_agent") or "", i["method"] or "", i.get("referer") or "",
        i.get("cookie") or "", i["dns_server"] or "",
        i["dns_record_type"] or "", i["via"] or str(o.get("node_id") or 0),
    ])


def _tcpcn_yc(r: str, s: str, u: dict, ts: int, request_hash: str) -> str:
    f = request_hash or _tcpcn_b64url_sha256(_tcpcn_cl(u))
    v = f"{r}|{s}|{f}|{ts}"
    out = []
    for w in range(9):
        x = _tcpcn_b64url_sha256(f"tcping.cn:browser-proof:v2|{w}|{v}")
        v = f"{x}|{v[::-1]}"
        if w in (2, 5, 8):
            out.append(x)
    return "".join(out)


def _tcpcn_bc(r: str, s: str, request_hash: str) -> str:
    return _tcpcn_b64url_sha256(f"tcping.cn:pow-salt:v1|{r}|{s}|{request_hash}")


def _tcpcn_pow_solve(challenge_id, salt, request_hash, difficulty) -> tuple[str, float]:
    c = f"{challenge_id}\n{salt}\n{request_hash}\n"
    nbits = int(difficulty or TCPINGCN_POW_DIFFICULTY)
    t0 = time.monotonic()
    for e in range(5_000_000):
        hb = hashlib.sha256((c + str(e)).encode()).digest()
        if _tcpcn_check_zero_bits(hb, nbits):
            return str(e), time.monotonic() - t0
    raise RuntimeError("pow timeout")


def _tcpcn_check_zero_bits(hb: bytes, nbits: int) -> bool:
    full, rem = divmod(nbits, 8)
    for b in hb[:full]:
        if b != 0:
            return False
    if rem:
        return hb[full] >> (8 - rem) == 0
    return True


def chinaz_check(ip: str, port: str, timeout: float) -> dict:
    """ping.chinaz.com 单键多节点 ping（服务端渲染 token + WS，零登录）。

    壳页 GET 拿 token + serverList；仅发 1 条 WS 注册消息；code:1 帧为单节点
    结果（timeMs/tTL）。节点成功 = ``timeMs`` 可解析数值。ICMP → level="icmp"。
    ``port`` 参数在 chinaz 无效（该工具只做 ping），保留为接口一致。
    """
    try:
        status, headers, resp = request_follow(
            f"{CHINAZ_URL}/{ip}",
            {"User-Agent": UA}, timeout,
        )
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    if status != 200:
        return {"status": "error", "ok": False, "ms": None,
                "error": f"page http {status}", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    html = resp.decode("utf-8", "replace")
    m = re.search(r'let\s+token\s*=\s*"([^"]+)"', html)
    if not m:
        return {"status": "error", "ok": False, "ms": None,
                "error": "no token", "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    token = m.group(1)
    try:
        ws = _WebSocket(CHINAZ_WS, timeout=CHINAZ_WS_IDLE)
        ws.send_text(json.dumps({"keyword": ip, "token": token}))
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None,
                "error": str(e)[:120], "level": None,
                "ok_nodes": 0, "nodes": 0, "ratio": None}
    ok_nodes = 0
    totals = 0
    ms_values: list[float] = []
    deadline = time.monotonic() + CHINAZ_WS_IDLE
    max_wait = min(CHINAZ_WS_SETTLE, CHINAZ_WS_IDLE)
    while time.monotonic() < deadline:
        ws.settimeout(min(max_wait, max(0.1, deadline - time.monotonic())))
        try:
            kind, msg = ws.read()
        except Exception as e:
            break
        if kind in ("err", "close", "closed"):
            break
        if kind == "timeout":
            # 静默超阈值（SETTLE）→ 结果流已放完，早退收尾
            break
        if not isinstance(msg, dict):
            continue
        code = msg.get("code")
        if code == 1:
            totals += 1
            try:
                tms = float(msg.get("timeMs"))
                if tms > 0:
                    ok_nodes += 1
                    ms_values.append(tms)
            except (TypeError, ValueError):
                pass
        elif code == 10002:
            break
    ws.close()
    nodes = totals
    if ok_nodes:
        return {
            "status": "ok", "ok": True,
            "ms": round(min(ms_values), 1), "error": "",
            "level": "icmp", "ok_nodes": ok_nodes, "nodes": nodes,
            "ratio": round(ok_nodes / nodes, 3) if nodes else None,
        }
    return {
        "status": "fail", "ok": False, "ms": None,
        "error": f"unreachable ({nodes} nodes)", "level": None,
        "ok_nodes": 0, "nodes": nodes, "ratio": 0.0 if nodes else None,
    }


# ------------------------------------------------------------ 判定合成

def merge_verdict(sources: dict) -> dict:
    """跨源合成大陆可达性判定。

    - 至少 2 个独立方法确认 → reachable
    - 仅 1 个方法确认（非多节点源）→ uncertain（单点不可靠）
    - 多节点源（ping.pe / itdog / itdog_tcping / tcpping）单独确认 → reachable，
      但**要求该源节点成功率达阈值**（itdog 系列按 ``ratio``≥0.5；
      ping.pe/tcpping 内部已是多数/60% 规则，视作满足）；比率过低的单源
      判定 → uncertain（单节点假阳性抑制）
    - 单节点源（check_host/xxapi/jkapi）≥2 个失败 → unreachable
    - 多节点源失败且所有单节点源也失败 → unreachable
    - 有确认源但也有失败源（冲突）→ uncertain（保守）
    - 全部为错误/跳过 → skipped（不误判）
    - ``level``：证据分级——任一成功源给出应用层（HTTP）确认 → "http"，
      仅传输层（TCP）确认 → "tcp"，无成功源 → None

    比率字段约定：``ratio`` 存在且 < ``ITDOG_MIN_RATIO`` 视为"弱确认"，
    不独立支撑 reachable；缺失（如单节点源）按 1.0 处理。
    """
    ok_sources = [name for name, r in sources.items() if r.get("ok")]
    fail_sources = [name for name, r in sources.items() if r["status"] == "fail"]
    ms_values = [
        r["ms"] for r in sources.values()
        if r.get("ok") and isinstance(r.get("ms"), (int, float)) and r["ms"] > 0
    ]
    ms = round(min(ms_values), 1) if ms_values else None
    # 证据分级：任一成功源给出应用层确认 → "http"；仅传输层 → "tcp"
    if any(sources[s].get("level") == "http" for s in ok_sources):
        level = "http"
    elif ok_sources:
        level = "tcp"
    else:
        level = None

    multi_ok = [s for s in ok_sources if s in (
        "pingpe", "itdog", "tcpping", "itdog_tcping", "tcptest", "coffee",
        "pingloc", "antping", "tcpingcn", "chinaz")]
    single_ok = [s for s in ok_sources if s in ("check_host", "xxapi", "jkapi")]

    def strong_valid(source: str) -> bool:
        """该多节点源是否能独立支撑 reachable（成功率+最低报告节点数达标）。"""
        ratio = sources[source].get("ratio")
        if ratio is None:
            return True  # pingpe/tcpping 内部已实施多数/60% 规则
        if (sources[source].get("nodes") or 0) < MULTI_MIN_NODES:
            return False  # 残缺样本（限流/连接中断）不作强确认，防退化为单点假阳性
        if source == "coffee":
            return ratio >= COFFEE_MIN_RATIO
        if source == "chinaz":
            return ratio >= CHINAZ_MIN_RATIO
        return ratio >= ITDOG_MIN_RATIO

    strong_multi = [s for s in multi_ok if strong_valid(s)]

    if len(strong_multi) >= 1:
        basis = ok_sources[:]
        return {"verdict": "reachable", "basis": basis, "ms": ms, "level": level}
    if len(single_ok) >= 2:
        basis = ok_sources[:]
        return {"verdict": "reachable", "basis": basis, "ms": ms, "level": level}
    # 多节点源只有弱确认（如 itdog 仅 1/18 节点可达）→ 不能单独定论
    if multi_ok:
        basis = ok_sources[:]
        return {"verdict": "uncertain", "basis": basis, "ms": ms, "level": level}
    if ok_sources:
        basis = ok_sources[:]
        return {"verdict": "uncertain", "basis": basis, "ms": ms, "level": level}
    # 单节点源（大陆境内自备服务器实测）≥2 个不约而同 fail → 足够置信判 unreachable
    single_failed = [s for s in fail_sources if s in ("check_host", "xxapi", "jkapi")]
    if len(single_failed) >= 2:
        return {"verdict": "unreachable", "basis": fail_sources, "ms": None, "level": None}
    multi_failed = [s for s in fail_sources if s in (
        "itdog", "itdog_tcping", "pingpe", "tcptest", "coffee",
        "pingloc", "antping", "tcpingcn", "chinaz")]
    if len(multi_failed) >= 2 or (len(multi_failed) >= 1 and len(single_failed) >= 1):
        return {"verdict": "unreachable", "basis": fail_sources, "ms": None, "level": None}
    if fail_sources:
        return {"verdict": "uncertain", "basis": fail_sources, "ms": None, "level": None}
    return {"verdict": "skipped", "basis": [], "ms": None, "level": None}


def needs_probe(entries: dict, key: str) -> bool:
    """仅对仍未定论的键继续投递多节点源：uncertain/无判定才扫；
    reachable/unreachable 已定论，避免浪费免费源配额反复探测死键。"""
    return merge_verdict(entries.get(key, {}))["verdict"] in ("uncertain", "skipped")


def has_cn_note(line: str) -> bool:
    return has_token(_note(line), "CN")


def annotate_cn(line: str) -> str:
    return merge_note_tokens(line, "CN")


# ------------------------------------------------------------ 数据装载与写出

def load_sample(source: Path, limit: int) -> tuple[list, Path]:
    """返回 ``([(line, key, ip, port, cc), ...], used_path)``，按信誉降序截取。"""
    path = source if source.exists() else FALLBACK_SOURCE
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    out = []
    for line in lines:
        parsed = parse_ltd_line(line)
        if not parsed:
            continue
        key, ip, port, cc = parsed
        out.append((line, key, ip, port, cc))
    if limit and limit > 0:
        out = out[:limit]
    return out, path


def build_entry(item, sources: dict) -> dict:
    _, key, ip, port, cc = item
    merged = merge_verdict(sources)
    return {
        "ip": ip,
        "port": port,
        "cc": cc,
        "verdict": merged["verdict"],
        "basis": merged["basis"],
        "ms": merged["ms"],
        "level": merged.get("level"),
        "sources": sources,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def load_cn_pool() -> str:
    """全量存活池文本（``all_cn.txt`` 生成源）：优先 ``data/valid/all.txt``，缺则回退 all_ltd.txt。"""
    path = VALID_ALL_FILE
    if not path.exists():
        path = VALID_ALL_LTD_FILE
    return path.read_text(encoding="utf-8") if path.exists() else ""


def annotate_cnh(line: str) -> str:
    """给行追加 ``-CNH``（应用层 HTTP 确认），幂等。"""
    return merge_note_tokens(line, "CNH")


STREAK_GAP_TOLERANCE_S = 6 * 3600  # 连续轮时间窗：基线观测早于此视为中断。
# GitHub schedule 实测每 ~2.5-4h 才实际起一轮（cron 队列抖动 + 同 workflow
# 去重），3h 容差会被反复击穿、每一轮都把 streak 清零 → stable 永远攒不起来
# （实测 02:56→06:37 相隔 3h40m 即全体重置）。6h 容差吸收调度抖动：轮间
# 间隔可容忍跳过一到两班，同时仍能在长时间停更时如实降温。
FLIP_FORGIVE_STREAK = 4  # 连续可达达此轮数后清零 flip（稳定恢复赦免历史抖动）
STABLE_MAX_FLIP = 1  # stable 准入：历史翻转次数上限（排除慢性抖动源）
# CN 清单延迟语义（common.cn_display_ms / cn_l2_ms）：每行展示大陆视角读数，
# 绝不让 L3 复核源的 1ms 噪声冒充真实延迟。CN 清单保持完整（全可达集），
# --cn-latency-cap 只用于信息性 cn_mainland 打标，不砍清单。


def apply_streak(
    entries: dict, prev_entries: dict, now: float | None = None
) -> None:
    """就地写入连续可达轮数 ``streak``、最近可达时间 ``last_ok_ts`` 与翻转
    计数 ``flip``。

    reachable 且上一轮也 reachable、且上一轮观测距今 ≤
    STREAK_GAP_TOLERANCE_S → 上一轮 streak+1；否则从 1 起算。其余 verdict
    清零并清除 last_ok_ts。

    ``flip``：上一轮与本轮 reachable 状态相反则 +1，否则沿用上一轮计数；
    连续可达达 FLIP_FORGIVE_STREAK 轮后清零（稳定恢复即赦免历史抖动）。
    stable 准入要求 flip ≤ STABLE_MAX_FLIP，排除"可达↔不可达"慢性振荡源。

    时间窗判定用于对抗 china.json 被并发工作流短暂回滚（lost-update）：
    基线落后数小时时不再误把连续可达清零。无 last_ok_ts 的旧格式按紧邻
    一轮处理，保持向后兼容。
    """
    if now is None:
        now = time.time()
    now = int(now)
    for key, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        prev = prev_entries.get(key) if isinstance(prev_entries, dict) else None
        prev_reachable = (
            isinstance(prev, dict) and prev.get("verdict") == "reachable"
        )
        cur_reachable = entry.get("verdict") == "reachable"
        prev_flip = prev.get("flip") if isinstance(prev, dict) else None
        flip = prev_flip if isinstance(prev_flip, int) and prev_flip > 0 else 0
        if isinstance(prev, dict) and prev_reachable != cur_reachable:
            flip += 1
        if cur_reachable:
            base = 0
            if prev_reachable:
                ts = prev.get("last_ok_ts")
                fresh = (
                    not isinstance(ts, (int, float))
                    or ts <= 0
                    or (now - ts) <= STREAK_GAP_TOLERANCE_S
                )
                if fresh:
                    ps = prev.get("streak")
                    base = ps if isinstance(ps, int) and ps > 0 else 1
            entry["streak"] = base + 1
            entry["last_ok_ts"] = now
            if entry["streak"] >= FLIP_FORGIVE_STREAK:
                flip = 0
        else:
            entry["streak"] = 0
            entry.pop("last_ok_ts", None)
        entry["flip"] = flip


def _sort_by_ms(lines: list[str], cn_ms: dict | None) -> list[str]:
    """``cn_ms`` 提供时按大陆延迟升序稳定排序；缺失排最后。"""
    if not cn_ms:
        return lines
    indexed = list(enumerate(lines))
    indexed.sort(
        key=lambda item: (
            cn_ms.get(line_to_key(item[1]), float("inf")),
            item[0],
        )
    )
    return [line for _i, line in indexed]


def generate_all_cn(
    pool_text: str,
    reachable_keys: set,
    cn_ms: dict | None = None,
    http_keys: set | None = None,
    strict: bool = False,
    fallback_keys: set | None = None,
) -> tuple[str, int]:
    """大陆可达清单：本次判可达的行（源为全量池文本）。

    - ``http_keys``：应用层（HTTP）确认的 key 集合，对应行追加 ``-CNH``
    - ``strict=True``：保留参数以兼容调用方（行为与假等同，均已不收历史兜底）
    - ``fallback_keys``：**历史兜底集合**——上一轮可达、本轮仅因源配额/抖动
      落入 uncertain（而非被 ≥2 失败源证伪）的键。CN 全量清单维持
      ≥ MIN_CN_POOL（用户硬约束，避免单次调度/源异常把可达池削到 1 万以下）；
      这些键本就是近期稳定可达，清单语义为"可达集合快照"，非本轮活体确认，
      故保留既诚实又守规模。兜底行仍经大陆延迟/速度重写，与当期一致。
    - ``cn_ms``（``key -> 大陆实测毫秒``）提供时：
      * 行内延迟 token **替换为大陆实测 RTT**——CN 清单里 ``ms`` 的语义
        即"大陆使用者连接该节点的延迟"，而非海外 runner 的 TLS 延迟；
      * 行内速度 token **替换为大陆视角估算** ``≈XMB/s``（大陆 RTT 推算
        的单流参考上限与海外实测取小）。测不到大陆延迟的节点速度不得而知，
        删除速度 token，避免海外测速冒充大陆体验——同一行内 ``MB/s``
        的语义随清单而定（CN 清单=大陆视角）；
      * 按大陆延迟升序输出（对大陆使用者比海外延迟更有参考意义）；
        未测到延迟的行排在最后，同延迟保持原池顺序。
      缺省 ``None`` 时保持原池顺序、不改写延迟。
    """
    keep = set(reachable_keys)
    if fallback_keys:
        keep |= set(fallback_keys)
    lines = []
    for line in pool_text.splitlines():
        if not line.strip():
            continue
        key = line_to_key(line)
        if not key:
            continue
        if key in keep:
            out = annotate_cn(line)
            if http_keys and key in http_keys:
                out = annotate_cnh(out)
            if cn_ms:
                out = rewrite_latency(out, cn_ms.get(key))
                out = _rewrite_cn_speed(out, cn_ms)
            lines.append(out)
    lines = _sort_by_ms(lines, cn_ms)
    return "\n".join(lines) + ("\n" if lines else ""), len(lines)


def generate_cn_subset(
    pool_text: str,
    keep,
    cn_ms: dict | None = None,
) -> tuple[str, int]:
    """按谓词过滤全量池文本，保持行原文；``keep(key, line)`` 为真则保留。

    排序规则同 :func:`generate_all_cn`（``cn_ms`` 升序，缺失垫底）；
    ``cn_ms`` 提供时同样将行内延迟替换为大陆实测 RTT（CN 视图语义），
    并将速度替换为大陆视角估算（``≈XMB/s``，见 :func:`generate_all_cn`）。
    """
    lines = []
    for line in pool_text.splitlines():
        if not line.strip():
            continue
        key = line_to_key(line)
        if not key:
            continue
        if keep(key, line):
            out = line
            if cn_ms:
                out = rewrite_latency(out, cn_ms.get(key))
                out = _rewrite_cn_speed(out, cn_ms)
            lines.append(out)
    lines = _sort_by_ms(lines, cn_ms)
    return "\n".join(lines) + ("\n" if lines else ""), len(lines)


# 大陆清单健康下限：清单须保持完整（正常水平 ≥1 万可达键）。
MIN_CN_POOL = 10000
# 大陆延迟的最小可信读数：互联网真实 RTT 一向 ≥ ~2ms（同机房直连也难低于
# 个位数），≤2ms 即是 L3 复核源 1ms 噪声（antping 等）漏网的信号。
CN_MIN_CREDIBLE_MS = 2.0


def cn_health_report(cn_text: str) -> dict[str, int]:
    """清单自检：``{count, no_ms, junk_ms}``。

    - ``count``：总行数（完整池规模）；
    - ``no_ms``：无 ms token 的行数（漏重写信令）；
    - ``junk_ms``：ms ≤ CN_MIN_CREDIBLE_MS 的行数（噪声侵入信令）。

    供主流程在落地后即时自检并告警，防止"清单被裁 / 1ms 假延迟回归"。
    """
    count = no_ms = junk_ms = 0
    for line in cn_text.splitlines():
        if not line.strip():
            continue
        count += 1
        m = next(
            (t[:-2] for t in line.split("-") if t.endswith("ms")),
            None,
        )
        if not m or not m.replace(".", "").isdigit():
            no_ms += 1
        elif float(m) <= CN_MIN_CREDIBLE_MS:
            junk_ms += 1
    return {"count": count, "no_ms": no_ms, "junk_ms": junk_ms}


def check_cn_health(cn_text: str, min_count: int = MIN_CN_POOL) -> dict[str, int]:
    """落地即自检：不达标打告警（失败即暴露，不静默）。返回报告。"""
    report = cn_health_report(cn_text)
    if report["count"] < min_count:
        print(
            f"WARNING: all_cn.txt too small ({report['count']} < {min_count}) — "
            f"pool shrank or reachability collapsed; check pool/verdicts",
            file=sys.stderr,
        )
    if report["junk_ms"]:
        print(
            f"WARNING: {report['junk_ms']} lines with ms <= "
            f"{CN_MIN_CREDIBLE_MS:g}ms (L3 noise leaked into CN lists)",
            file=sys.stderr,
        )
    if report["no_ms"]:
        print(
            f"WARNING: {report['no_ms']} lines missing ms token "
            f"(reachable keys without any credible mainland reading)",
            file=sys.stderr,
        )
    return report


def annotate_cn_files(reachable_keys: set) -> None:
    """给 all.txt / all_ltd.txt 同步当期 -CN：可达 → 追加；不可达 → 撤销。

    历史实现只增不减导致过期 -CN 累积（曾达 13817 条而真可达仅 112）。
    改为以当期可达集为准的严格交战：key 在可达集内且未带 -CN 则补，
    否则若带 -CN/-CNH 则清除（与 annotate_classify 同策略，幂等）。
    """
    for name in ("all.txt", "all_ltd.txt"):
        path = VALID_DIR / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        changed = False
        out = []
        for line in text.splitlines():
            if not line:
                continue
            key = line_to_key(line)
            if key and key in reachable_keys:
                if not has_cn_note(line) and merge_note_tokens(line, "CN") != line:
                    out.append(merge_note_tokens(line, "CN"))
                    changed = True
                    continue
            elif has_cn_note(line) and clear_note_buckets(line, "cn") != line:
                out.append(clear_note_buckets(line, "cn"))
                changed = True
                continue
            out.append(line)
        if changed:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
            tmp.replace(path)


# ------------------------------------------------------------ 主流程

def _run_pingpe_slots(
    candidates: list, entries: dict, timeout: float,
    tcpping_token: str, concurrency: int,
) -> None:
    """L3 ping.pe 多节点复核：串行→有界并发。每键端到端 ~20-40s（AJAX 启动
    + 轮询），串行 40 键 ≈ 26min；并发受控后同槽位耗时 ~7min，覆盖翻倍而
    不增加对上游的访问总量。并发数默认 `PINGPE_CONCURRENCY`。"""

    def work(item) -> None:
        _, key, ip, port, _ = item
        try:
            entries[key]["pingpe"] = pingpe_check(ip, port, timeout)
            tcpping = tcpping_check(ip, port, tcpping_token, timeout)
            if tcpping["status"] != "skipped":
                entries[key]["tcpping"] = tcpping
        except Exception as exc:
            logging.debug("pingpe failed for %s: %s", key, exc)
            entries.setdefault(key, {})["pingpe"] = {
                "status": "error", "ok": False, "ms": None, "error": str(exc)[:120]}
        time.sleep(PINGPE_SLOT_GAP)

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(work, item) for item in candidates]
        for fut in futures:
            fut.result()


def _run_tcptest_slots(
    candidates: list, entries: dict, timeout: float,
    node_uuids: list[str], concurrency: int,
) -> None:
    """tcptest.cn 多节点 TCP 复核（免费 REST，端到端 ~2-6s/键）。节点列表
    进程内缓存，只取一次；每键在 concurrency 有界并发下建任务并轮询结果。"""

    def work(item) -> None:
        _, key, ip, port, _ = item
        try:
            entries[key]["tcptest"] = tcptest_check(ip, port, timeout, node_uuids)
        except Exception as exc:
            logging.debug("tcptest failed for %s: %s", key, exc)
            entries.setdefault(key, {})["tcptest"] = {
                "status": "error", "ok": False, "ms": None, "error": str(exc)[:120]}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(work, item) for item in candidates]
        for fut in futures:
            fut.result()


def _run_coffee_slots(
    candidates: list, entries: dict, timeout: float, concurrency: int
) -> None:
    """ip.net.coffee 多节点 ICMP 复核（免费 GET+轮询，空闲量大、单键快）。
    每键在 concurrency 有界并发下探测主机存活，作为附加多节点确认源。"""

    def work(item) -> None:
        _, key, ip, _, _ = item
        try:
            entries[key]["coffee"] = coffee_check(ip, timeout)
            if entries[key]["coffee"].get("status") == "error":
                # 快速冲掉偶发超时：再试一次
                entries[key]["coffee"] = coffee_check(ip, timeout, COFFEE_POOL[:6])
        except Exception as exc:
            logging.debug("coffee failed for %s: %s", key, exc)
            entries.setdefault(key, {})["coffee"] = {
                "status": "error", "ok": False, "ms": None, "error": str(exc)[:120]}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(work, item) for item in candidates]
        for fut in futures:
            fut.result()


def _run_ws_source_slots(
    candidates: list, entries: dict, timeout: float, source: str, concurrency: int
) -> None:
    """JWT/WS 或 PoW/WS 类源的多键并发复核（antping / tcpingcn / chinaz）。

    每个源按 ``candidates`` 前段投递；只写 ``entries[key][source]``。"""
    fn = {
        "antping": lambda ip, port: antping_check(ip, port, timeout),
        "tcpingcn": lambda ip, port: tcpingcn_check(ip, port, timeout),
        "chinaz": lambda ip, port: chinaz_check(ip, "", timeout),
    }[source]

    def work(item) -> None:
        _, key, ip, port, _ = item
        try:
            entries[key][source] = fn(ip, port)
        except Exception as exc:
            logging.debug("%s failed for %s: %s", source, key, exc)
            entries.setdefault(key, {})[source] = {
                "status": "error", "ok": False, "ms": None, "error": str(exc)[:120]}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(work, item) for item in candidates]
        for fut in futures:
            fut.result()


def _run_pingloc_slots(
    candidates: list, entries: dict, timeout: float, concurrency: int
) -> None:
    """pingloc.com 纯 HTTP+SSE 多节点复核（ICMP ping；其 tcp_ping 固定端口 80，
    与代理真实端口不符，故只用作 ICMP 主机存活确认）。"""

    def work(item) -> None:
        _, key, ip, _, _ = item
        try:
            entries[key]["pingloc"] = pingloc_check(ip, timeout, method="ping")
        except Exception as exc:
            logging.debug("pingloc failed for %s: %s", key, exc)
            entries.setdefault(key, {})["pingloc"] = {
                "status": "error", "ok": False, "ms": None, "error": str(exc)[:120]}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(work, item) for item in candidates]
        for fut in futures:
            fut.result()


def run_measurements(sample, args) -> tuple[dict, set, set]:
    """L2 分两段并发（xxapi 全池免额候选 → check_host 稀缺配额只投决策键）、itdog
    批量、L3 串行复核；返回 (entries, reachable_keys, uncertain_keys)。"""
    entries: dict = {}
    ch_limiter = RateLimiter(CH_WINDOW_SEC, CH_PER_WINDOW, CH_HOUR_CAP)
    _t0 = time.monotonic()

    def l2_xxapi(item):
        """免额单节点源（xxapi 北京 + jkapi 宁波电信）全池扫描，先建立候选集。

        L2 是并发受限（aggregate QPS），非逐键串行瓶颈：两个源放进同池最多干到
        池大小并发请求，切换 task 粒度并不增量。赶时间应加池（WORKERS_DEFAULT=48
        实测两源均无 429），保键级数据一致性仍用逐键两源落盘。"""
        _, key, ip, port, _ = item
        out = {}
        for name, fn in (("xxapi", xxapi_check), ("jkapi", jkapi_check)):
            try:
                out[name] = fn(ip, port, args.timeout)
            except Exception as exc:
                logging.debug("l2 %s failed for %s: %s", name, key, exc)
                out[name] = {"status": "error", "ok": False, "ms": None,
                             "error": str(exc)[:120]}
        return key, out

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(l2_xxapi, item) for item in sample]
        for future in futures:
            key, sources = future.result()
            entries[key] = sources

    def l2_check_host(item):
        """稀缺配额源（check-host 呼和浩特节点 ~250/h）二次确认。"""
        _, key, ip, port, _ = item
        try:
            return key, {
                "check_host": check_host_check(ip, port, ch_limiter, args.timeout, args.api_key)
            }
        except Exception as exc:
            logging.debug("l2 check_host failed for %s: %s", key, exc)
            return key, {"check_host": {"status": "error", "ok": False, "ms": None, "error": str(exc)[:120]}}

    # check_host 配额有限（CH_HOUR_CAP ≈ 250/h），只投递「确认/救回」不投「定罪」：
    # - xxapi/jkapi 都已 ok → 双免额单节点源已独立确认可达，稀配额直接让位
    # - 任一已有 fail → 保守维持 uncertain（不浪费配额去补强失败证据，同旧策略）
    # 预算留给恰好 1 ok（补足到 2 即翻正）与纯临时性错误者。
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        def _needs_ch(entry: dict) -> bool:
            x = entry.get("xxapi") or {}
            j = entry.get("jkapi") or {}
            if x.get("status") == "ok" and j.get("status") == "ok":
                return False
            if x.get("status") == "fail" or j.get("status") == "fail":
                return False
            return True

        futures = [
            pool.submit(l2_check_host, item)
            for item in sample
            if _needs_ch(entries.get(item[1], {}))
        ]
        for future in futures:
            key, sources = future.result()
            entries[key].update(sources)
    print(
        f"L1 sweep: {time.monotonic() - _t0:.1f}s",
        file=sys.stderr,
    )

    if not args.skip_itdog:
        # itdog 批量代价高（批任务端到端慢），只投仍未定论的键；已由
        # 双免额单节点源定论的键（≥2 ok / ≥2 fail）跳过其复核。
        _itdog_cands = [item for item in sample if needs_probe(entries, item[1])]
        try:
            for key, res in itdog_batch_run(_itdog_cands, args).items():
                entries.setdefault(key, {})["itdog"] = res
        except Exception as exc:
            logging.debug("itdog batch failed: %s", exc)
            print(f"itdog batch failed (skipped): {exc}", file=sys.stderr)
        # batch_http 失败/被限的 key 用 batch_tcping 补测（节点池更大，纯 TCP）
        if not getattr(args, "skip_itdog_tcping", False):
            pending = [
                item for item in _itdog_cands
                if entries.get(item[1], {}).get("itdog", {}).get("status")
                in ("error", "rate_limited")
            ]
            # 若主通道连节点列表都没取到（上游被墙/验证码墙的整站性失败），
            # tcping 同站同墙，兜底只会再空转一轮——直接跳过。注意只统计
            # 本轮真正过 itdog 的键（无 itdog 记录的已定论键不得算作成功），
            # 且要求至少出现过 1 次 ok（全 fail 也是被投毒站点的特征——真活的
            # 大陆可达键不可能整批 0 ok，全 fail 时同站的 tcping 一样是死路）。
            node_fetch_ok = any(
                entries.get(key, {}).get("itdog", {}).get("status") == "ok"
                for _, key, _, _, _ in _itdog_cands
            ) if _itdog_cands else False
            if pending and node_fetch_ok:
                print(
                    f"itdog_tcping fallback: {len(pending)} targets",
                    file=sys.stderr,
                )
                try:
                    for key, res in itdog_batch_run(
                        pending,
                        args,
                        page_url=ITDOG_TCPING_URL,
                        nodes_per_isp=getattr(args, "itdog_tcping_nodes", 0)
                        or ITDOG_TCPING_NODES_PER_ISP,
                    ).items():
                        entries.setdefault(key, {})["itdog_tcping"] = res
                except Exception as exc:
                    logging.debug("itdog_tcping fallback failed: %s", exc)
                    print(f"itdog_tcping fallback failed (skipped): {exc}",
                          file=sys.stderr)
    print(
        f"itdog phases: {time.monotonic() - _t0:.1f}s",
        file=sys.stderr,
    )

    # tcptest.cn 多节点 TCP 复核（免费 REST，节点列表进程内缓存）：只投
    # 「当前尚未被判可达」的键，先于 ping.pe（贵）跑，确认过的键会让位。
    # --tcptest-limit -1 表示全池未定键全覆盖（uncertain/错误健全部扫过，
    # 让每个键都有资格走向 reachable 或 unreachable 定论）。
    tcptest_nodes = []
    tcptest_uuids = []
    if getattr(args, "tcptest_limit", 0) != 0:
        tcptest_nodes = tcptest_fetch_nodes(min(args.timeout, 20))
        tcptest_uuids = tcptest_pick_nodes(
            tcptest_nodes, getattr(args, "tcptest_nodes", TCPTEST_NODES)
        )
    if tcptest_uuids:
        tcptest_candidates = [
            item for item in sample if needs_probe(entries, item[1])
        ]
        limit = getattr(args, "tcptest_limit", 0)
        if limit is None or limit < 0:
            limit = len(tcptest_candidates)
        _run_tcptest_slots(
            tcptest_candidates[:limit],
            entries,
            args.timeout,
            tcptest_uuids,
            getattr(args, "tcptest_concurrency", TCPTEST_CONCURRENCY),
        )
        print(
            f"tcptest review: {time.monotonic() - _t0:.1f}s "
            f"({len(tcptest_candidates)} targets, {len(tcptest_uuids)} nodes)",
            file=sys.stderr,
        )
    else:
        print(
            "tcptest review: skipped (no nodes or limit=0)",
            file=sys.stderr,
        )

    # ip.net.coffee 多节点 ICMP 复核（免费、空闲量大）：全池未定键横扫，
    # 为主机存活提供独立多节点证据（端口层以 tcptest/itdog 等 TCP 源为准）。
    coffee_limit = getattr(args, "coffee_limit", 0)
    if coffee_limit != 0:
        coffee_candidates = [
            item for item in sample if needs_probe(entries, item[1])
        ]
        if coffee_limit is None or coffee_limit < 0:
            coffee_limit = len(coffee_candidates)
        _run_coffee_slots(
            coffee_candidates[:coffee_limit],
            entries,
            args.timeout,
            getattr(args, "coffee_concurrency", COFFEE_CONCURRENCY),
        )
        print(
            f"coffee review: {time.monotonic() - _t0:.1f}s "
            f"({len(coffee_candidates)} targets)",
            file=sys.stderr,
        )
    else:
        print("coffee review: skipped (limit=0)", file=sys.stderr)

    def _pending_cands():
        return [
            item for item in sample if needs_probe(entries, item[1])
        ]

    # 新增四源多节点复核（全部无 key、大陆多节点）：pingloc（HTTP+SSE）、
    # antping（JWT+WS）、tcpingcn（PoW+WS 纯 TCP）、chinaz（token+WS 纯 ICMP）。
    # 各自按 --<name>-limit 投递（默认 -1=全部未定键，0=跳过）；均为多节点源，
    # 达标即可独立判 reachable，整站失败也可与单节点源联动判 unreachable。

    pingloc_limit = getattr(args, "pingloc_limit", 0)
    if pingloc_limit != 0:
        cands = _pending_cands()
        if pingloc_limit is None or pingloc_limit < 0:
            pingloc_limit = len(cands)
        _run_pingloc_slots(
            cands[:pingloc_limit], entries, args.timeout,
            getattr(args, "pingloc_concurrency", 8),
        )
        print(f"pingloc review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("pingloc review: skipped (limit=0)", file=sys.stderr)

    antping_limit = getattr(args, "antping_limit", 0)
    if antping_limit != 0:
        cands = _pending_cands()
        if antping_limit is None or antping_limit < 0:
            antping_limit = len(cands)
        _run_ws_source_slots(
            cands[:antping_limit], entries, args.timeout, "antping",
            getattr(args, "antping_concurrency", 8),
        )
        print(f"antping review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("antping review: skipped (limit=0)", file=sys.stderr)

    tcpingcn_limit = getattr(args, "tcpingcn_limit", 0)
    if tcpingcn_limit != 0:
        cands = _pending_cands()
        if tcpingcn_limit is None or tcpingcn_limit < 0:
            tcpingcn_limit = len(cands)
        _run_ws_source_slots(
            cands[:tcpingcn_limit], entries, args.timeout, "tcpingcn",
            getattr(args, "tcpingcn_concurrency", 6),
        )
        print(f"tcpingcn review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("tcpingcn review: skipped (limit=0)", file=sys.stderr)

    chinaz_limit = getattr(args, "chinaz_limit", 0)
    if chinaz_limit != 0:
        cands = _pending_cands()
        if chinaz_limit is None or chinaz_limit < 0:
            chinaz_limit = len(cands)
        _run_ws_source_slots(
            cands[:chinaz_limit], entries, args.timeout, "chinaz",
            getattr(args, "chinaz_concurrency", 6),
        )
        print(f"chinaz review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("chinaz review: skipped (limit=0)", file=sys.stderr)

    # ping.pe 多节点复核（串行、贵）只投「当前尚未被 itdog/单节点源确认可达」
    # 的键：已由 itdog 多点达标判 reachable 的不再浪费名额，把有限槽位让给
    # 仍待定（uncertain / skipped / 缺二看）的键 —— 多节点源能独立定论，
    # 优先给它派活能最大化「翻正」概率。顺序仍保持 sample 优先级排序。
    pingpe_candidates = [
        item for item in sample if needs_probe(entries, item[1])
    ]
    _run_pingpe_slots(
        pingpe_candidates[: args.pingpe_limit],
        entries,
        args.timeout,
        getattr(args, "tcpping_token", ""),
        getattr(args, "pingpe_concurrency", PINGPE_CONCURRENCY),
    )
    print(
        f"pingpe review: {time.monotonic() - _t0:.1f}s",
        file=sys.stderr,
    )

    reachable = set()
    uncertain = set()
    for item in sample:
        line, key, ip, port, cc = item
        sources = entries[key]
        merged = merge_verdict(sources)
        entries[key] = build_entry(item, sources)
        entries[key]["verdict"] = merged["verdict"]
        entries[key]["basis"] = merged["basis"]
        entries[key]["ms"] = merged["ms"]
        entries[key]["level"] = merged.get("level")
        if merged["verdict"] == "reachable":
            reachable.add(key)
        elif merged["verdict"] == "uncertain":
            uncertain.add(key)
    return entries, reachable, uncertain


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="china_check.py",
        description="大陆连通性检测（itdog 批量 + check-host.cc + xxapi.cn + jkapi.com + ping.pe [+ tcpping.cn]）",
    )
    parser.add_argument("--source", type=Path, default=REP_RANK_FILE,
                        help=f"输入清单（默认 {REP_RANK_FILE.name}，缺失回退 all_ltd.txt）")
    parser.add_argument("--limit", type=int, default=LIMIT_DEFAULT,
                        help=f"按信誉降序采样条数（0=全部；默认 {LIMIT_DEFAULT}）")
    parser.add_argument("--pingpe-limit", type=int, default=PINGPE_LIMIT_DEFAULT,
                        help=f"ping.pe 多节点复核条数（有界并发小样本；默认 {PINGPE_LIMIT_DEFAULT}）")
    parser.add_argument("--pingpe-concurrency", type=int, default=PINGPE_CONCURRENCY,
                        help=f"ping.pe 并发复核数（默认 {PINGPE_CONCURRENCY}）")
    parser.add_argument("--tcptest-limit", type=int, default=TCPTEST_LIMIT_DEFAULT,
                        help=f"tcptest.cn 多节点复核条数（默认 {TCPTEST_LIMIT_DEFAULT}；0=跳过；-1=全部未定键）")
    parser.add_argument("--tcptest-concurrency", type=int, default=TCPTEST_CONCURRENCY,
                        help=f"tcptest.cn 并发复核数（默认 {TCPTEST_CONCURRENCY}）")
    parser.add_argument("--tcptest-nodes", type=int, default=TCPTEST_NODES,
                        help=f"tcptest.cn 每键采样节点数（默认 {TCPTEST_NODES}）")
    parser.add_argument("--coffee-limit", type=int, default=0,
                        help="ip.net.coffee 单节点复核条数（0=跳过；-1=全部未定键）")
    parser.add_argument("--coffee-concurrency", type=int, default=COFFEE_CONCURRENCY,
                        help=f"ip.net.coffee 并发复核数（默认 {COFFEE_CONCURRENCY}）")
    parser.add_argument("--pingloc-limit", type=int, default=0,
                        help="pingloc.com 多节点复核条数（0=跳过；-1=全部未定键）")
    parser.add_argument("--pingloc-concurrency", type=int, default=8,
                        help="pingloc.com 并发复核数（默认 8）")
    parser.add_argument("--antping-limit", type=int, default=0,
                        help="antping.com 多节点复核条数（0=跳过；-1=全部未定键）")
    parser.add_argument("--antping-concurrency", type=int, default=8,
                        help="antping.com 并发复核数（默认 8）")
    parser.add_argument("--tcpingcn-limit", type=int, default=0,
                        help="tcping.cn 多节点复核条数（0=跳过；-1=全部未定键）")
    parser.add_argument("--tcpingcn-concurrency", type=int, default=6,
                        help="tcping.cn 并发复核数（默认 6）")
    parser.add_argument("--chinaz-limit", type=int, default=0,
                        help="ping.chinaz.com 多节点复核条数（0=跳过；-1=全部未定键）")
    parser.add_argument("--chinaz-concurrency", type=int, default=6,
                        help="ping.chinaz.com 并发复核数（默认 6）")
    parser.add_argument("--workers", type=int, default=WORKERS_DEFAULT,
                        help=f"L2 并发上限（默认 {WORKERS_DEFAULT}）")
    parser.add_argument("-t", "--timeout", type=float, default=TIMEOUT_DEFAULT,
                        help=f"单次 HTTP 超时秒数（默认 {TIMEOUT_DEFAULT}）")
    parser.add_argument("--api-key", default="",
                        help="check-host.cc API key（默认读 CHINA_CHECK_API_KEY，可选）")
    parser.add_argument("--tcpping-token", default="",
                        help="tcpping.cn token（默认读 TCPPING_CN_TOKEN，缺则跳过）")
    parser.add_argument("--itdog-nodes", type=int, default=ITDOG_NODES_PER_ISP,
                        help=f"itdog 每大陆运营商取 N 节点（跨省等距采样；默认 {ITDOG_NODES_PER_ISP} → 共 {ITDOG_NODES_PER_ISP * 3}）")
    parser.add_argument("--itdog-batch-size", type=int, default=ITDOG_BATCH_SIZE,
                        help=f"itdog 每任务目标数（上限 {ITDOG_BATCH_SIZE}；默认 {ITDOG_BATCH_SIZE}）")
    parser.add_argument("--itdog-concurrency", type=int, default=ITDOG_CONCURRENCY,
                        help=f"itdog 并发任务数（默认 {ITDOG_CONCURRENCY}）")
    parser.add_argument("--itdog-pacing", type=float, default=ITDOG_PACING,
                        help=f"itdog 任务启动最小间隔秒（默认 {ITDOG_PACING}）")
    parser.add_argument("--itdog-timeout", type=float, default=ITDOG_TASK_TIMEOUT,
                        help=f"itdog 单任务收结果上限秒（默认 {ITDOG_TASK_TIMEOUT}）")
    parser.add_argument("--skip-itdog", action="store_true",
                        help="跳过 itdog 批量探活（快速冒烟用）")
    parser.add_argument("--skip-itdog-tcping", action="store_true",
                        help="跳过 batch_tcping 补测（batch_http 失败时的大节点池降级）")
    parser.add_argument("--itdog-tcping-nodes", type=int, default=ITDOG_TCPING_NODES_PER_ISP,
                        help=f"batch_tcping 每运营商取 N 节点（默认 {ITDOG_TCPING_NODES_PER_ISP} → 共 {ITDOG_TCPING_NODES_PER_ISP * 3}）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只输出计划，不做任何网络请求与写盘")
    parser.add_argument("--skip-pingpe", action="store_true",
                        help="跳过 ping.pe 多节点复核（本地快速冒烟用）")
    parser.add_argument("--cn-latency-cap", type=float, default=CN_LATENCY_CAP_MS,
                        help=f"CN 清单大陆视角 RTT 门槛（默认 {CN_LATENCY_CAP_MS}ms；inf 关闭）")
    args = parser.parse_args(argv)

    api_key = args.api_key or os_environ("CHINA_CHECK_API_KEY")
    tcpping_token = args.tcpping_token or os_environ("TCPPING_CN_TOKEN")
    args.api_key = api_key
    args.tcpping_token = tcpping_token

    # 上一轮结果须在 write_json 覆盖 china.json 之前读取：
    # 用于 streak 连续可达计数与复检优先级（reachable 续保 > uncertain 升格）
    prev_data = read_json(CHINA_FILE)
    prev_entries = (
        prev_data.get("proxies", prev_data)
        if isinstance(prev_data, dict) else {}
    )
    if not isinstance(prev_entries, dict):
        prev_entries = {}

    sample, used = load_sample(args.source, args.limit)
    if not sample:
        print(f"no sample lines from {used} (limit={args.limit})", file=sys.stderr)
        return 2
    # 上一轮 uncertain 的键稳定排序置顶（组内保持信誉降序），优先复检
    # 上一轮 reachable（续保）优先，其次 uncertain（升格候选）最优先复检；
    # check_host 稀缺配额按此顺序投递，防止覆盖波动把稳定 CN 键翻出池。
    def _was_uncertain(item) -> int:
        prev = prev_entries.get(item[1])
        if isinstance(prev, dict):
            if prev.get("verdict") == "reachable":
                return 0
            if prev.get("verdict") == "uncertain":
                return 1
        return 2
    sample.sort(key=_was_uncertain)
    print(f"sample: {len(sample)} from {used}", file=sys.stderr)

    if args.dry_run:
        print("dry-run: no network, no writes", file=sys.stderr)
        return 0

    if args.skip_pingpe:
        args.pingpe_limit = 0

    entries, reachable, uncertain = run_measurements(sample, args)

    apply_streak(entries, prev_entries)
    stable_keys = {
        k for k, e in entries.items()
        if isinstance(e, dict)
        and e.get("streak", 0) >= 2
        and e.get("flip", 0) <= STABLE_MAX_FLIP
    }
    http_keys = {
        k for k, e in entries.items()
        if isinstance(e, dict) and e.get("level") == "http"
    }
    flappers = sum(
        1 for e in entries.values()
        if isinstance(e, dict) and e.get("flip", 0) > STABLE_MAX_FLIP
    )
    for e in entries.values():
        if isinstance(e, dict):
            e["cn_mainland"] = cn_mainland_ok(cn_l2_ms(e), args.cn_latency_cap)
    cn_ms_covered = sum(
        1 for e in entries.values()
        if isinstance(e, dict) and cn_l2_ms(e) is not None
    )
    print(
        f"reachable: {len(reachable)} uncertain: {len(uncertain)} "
        f"http-verified: {len(http_keys)} stable(>=2 runs): {len(stable_keys)} "
        f"flappers: {flappers} cn-l2-ms: {cn_ms_covered}/{len(entries)}",
        file=sys.stderr,
    )
    write_json(
        CHINA_FILE,
        {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "proxies": entries,
        },
    )

    all_pool_text = load_cn_pool()
    # CN 清单展示用大陆延迟图：优先可信大陆探测（xxapi/jkapi/check_host），
    # 无读数时回退 entry 合并 ms —— 绝不让 L3 复核源的 1ms 噪声冒充真实延迟。
    cn_ms = {
        key: cn_display_ms(entry)
        for key, entry in entries.items()
        if isinstance(entry, dict) and cn_display_ms(entry) is not None
    }
    # 历史兜底：上一轮可达、本轮落入 uncertain（非被 ≥2 失败源证伪）的键。
    # 维持 CN 全量清单 ≥ MIN_CN_POOL（用户硬约束），吸收源配额/调度抖动导致
    # 单轮确认率回落的波动，不让"没来得及确认"变成"清单缩水"。
    fallback_keys = {
        k
        for k, p in prev_entries.items()
        if (
            isinstance(p, dict)
            and p.get("verdict") == "reachable"
            and k not in entries
        ) or (
            isinstance(p, dict)
            and p.get("verdict") == "reachable"
            and isinstance(entries.get(k), dict)
            and entries[k].get("verdict") == "uncertain"
        )
    }
    # 兜底键未复测，无当轮读数：从其上一轮 entry 补大陆延迟（历史同源读数，
    # 比海外 TLS 更贴近大陆视角；实在无读数则保持"不伪饰、删除速度"）。
    if fallback_keys:
        for k in fallback_keys:
            if k not in cn_ms:
                m = prev_entries[k]
                if isinstance(m, dict):
                    v = cn_display_ms(m)
                    if v is not None:
                        cn_ms[k] = v
    cn_text, cn_count = generate_all_cn(
        all_pool_text, reachable, cn_ms, http_keys=http_keys,
        fallback_keys=fallback_keys,
    )
    if cn_text:
        write_text_if_changed(VALID_ALL_CN_FILE, cn_text)
    http_text, http_count = generate_cn_subset(
        all_pool_text,
        lambda k, l: k in http_keys or has_token(_note(l), "CNH"),
        cn_ms,
    )
    if http_text:
        write_text_if_changed(VALID_ALL_CN_HTTP_FILE, http_text)
    stable_text, stable_count = generate_cn_subset(
        all_pool_text,
        lambda k, l: k in stable_keys,
        cn_ms,
    )
    if stable_text:
        write_text_if_changed(VALID_ALL_CN_STABLE_FILE, stable_text)
    annotate_cn_files(reachable)
    cn_report = check_cn_health(cn_text)
    print(
        f"all_cn.txt: {cn_count} lines; all_cn_http.txt: {http_count}; "
        f"all_cn_stable.txt: {stable_count}; china.json: {len(entries)} entries; "
        f"health: count={cn_report['count']} no_ms={cn_report['no_ms']} "
        f"junk_ms(<=2ms)={cn_report['junk_ms']}",
        file=sys.stderr,
    )
    return 0


def os_environ(name: str) -> str:
    import os

    return os.environ.get(name, "")


if __name__ == "__main__":
    sys.exit(main())
