#!/usr/bin/env python3
"""Mainland-China reachability checks for the alive proxy pool.

独立 CI（``china-check.yml``）运行：对 ``data/valid/all.txt`` 全量（约 1.9 万行，
``--source data/valid/all.txt --limit 0``）做大陆连通性检测，产出一致结论后写回：
（本地缺省仍走 ``all_rep.txt`` 按信誉降序取前 250 的小样本）

- ``data/valid/china.json``  — 逐条检测明细（keyed，``{"proxies": {...}}``）
- ``data/valid/all_cn.txt``  — 大陆可达清单（仅含判定 reachable 或已带 ``-CN`` 的行）
- ``data/valid/all.txt`` / ``all_ltd.txt`` — 可达者追加 ``-CN`` 备注

检测分层（均为无账号/免登录）：

- L1 启发式（零网络）：行备注已带 ``CF``（Cloudflare 边缘 tls 代理）即视为大陆可达，
  这类代理走 CF 边缘节点，不依赖源站回程。
- L2 itdog.cn 批量实测（主源，全量）：`batch_http` 每任务 5 目标 × 3 节点
  （电信/联通/移动各 1），经 WebSocket 收结果，TCP 连通即判可达。
- L2 单节点实测（并发）：`check-host.cc`（呼和浩特阿里云 1 节点，需控速）+ `xxapi.cn`
  （北京节点，免 key）。二者均判失败 → unreachable；任一成功 → reachable；单方失败 → uncertain。
- L3 多节点复核（串行小样本）：`ping.pe`（约 13 个大陆节点，多数可达即判可达）；
  可选 `tcpping.cn`（多运营商，需 ``TCPPING_CN_TOKEN``，缺 key 自动跳过）。

纯标准库（urllib / json / threading / concurrent.futures）。运行时告警不计入
判定，仅记录 ``skipped``；单源失败不误判。
"""

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from download_proxies import OUT_DIR
from quality_check import keyed_json, line_to_key, parse_ltd_line, write_json

VALID_DIR = OUT_DIR / "valid"
REP_RANK_FILE = VALID_DIR / "all_rep.txt"
FALLBACK_SOURCE = VALID_DIR / "all_ltd.txt"
CHINA_FILE = VALID_DIR / "china.json"
ALL_CN_FILE = VALID_DIR / "all_cn.txt"

LIMIT_DEFAULT = 250
PINGPE_LIMIT_DEFAULT = 40
WORKERS_DEFAULT = 8
TIMEOUT_DEFAULT = 10
POLL_DEADLINE = 75.0
POLL_INTERVAL = 3.0

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

# check-host.cc —— 呼和浩特（阿里云 AS37963），每目标仅 1 大陆节点
CHECKHOST_URL = "https://api.check-host.cc/tcp"
CHECKHOST_REPORT_URL = "https://api.check-host.cc/report/{uuid}"
CHECKHOST_NODE = "CN-HOH-Alibaba"
CH_WINDOW_SEC = 10.0
CH_PER_WINDOW = 5  # 匿名限速 6/10s，留余量
CH_HOUR_CAP = 250

# xxapi.cn —— 北京服务器（免 key）
XXAPI_URL = "https://v2.xxapi.cn/api/tcping"

# ping.pe —— 约 13 个大陆节点，需走 antiflood + start_token 流程
PINGPE_URL = "https://tcp.ping.pe/{host}"
PINGPE_START_URL = "https://tcp.ping.pe/ajax_startTask_v1.php"
PINGPE_RESULTS_URL = "https://tcp.ping.pe/ajax_getPingResults_v2.php"
PINGPE_ORIGIN = "https://tcp.ping.pe"
PINGPE_CN_MAJORITY = 7  # ≥7/13 大陆节点可达即判可达
PINGPE_MIN_REPORTED = 5  # 报告节点不足 → inconclusive，避免误判

# tcpping.cn —— 多运营商，需站长签发的 token（缺则跳过）
TCPPING_URL = "https://tcpping.cn/ping_api"

# itdog.cn —— 无账号批量 HTTP 探活（每任务约 5 目标 × 3 节点，需走 WebSocket 收结果）
ITDOG_BATCH_URL = "https://www.itdog.cn/batch_http/"
ITDOG_WS_BASE = "wss://www.itdog.cn/websockets"
ITDOG_TOKEN = "What this is is no longer important."
ITDOG_BATCH_SIZE = 5  # itdog 每任务仅返回前 5 个目标的记录
ITDOG_NODES_PER_ISP = 1  # 电信/联通/移动各取前 N 节点（默认 1 → 共 3）
ITDOG_CONCURRENCY = 8
ITDOG_PACING = 0.5  # 两次任务启动的最小间隔（秒），全局节流
ITDOG_TASK_TIMEOUT = 45.0  # 单任务收结果上限
ITDOG_WS_IDLE = 20.0  # WS 单次 recv 空闲超时
ITDOG_ISP_GROUPS = ("中国电信", "中国联通", "中国移动")

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

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._times = [t for t in self._times if now - t < self.window]
                if self.hour_cap and self._hour_count >= self.hour_cap:
                    raise RateLimited("hourly cap reached")
                if len(self._times) < self.per_window:
                    self._times.append(now)
                    self._hour_count += 1
                    return
                wait = self.window - (now - self._times[0])
            time.sleep(max(wait, 0.05))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_follow(
    url: str,
    headers: dict,
    timeout: float = TIMEOUT_DEFAULT,
    method: str = "GET",
    data: bytes | None = None,
):
    """手动跟随重定向的 HTTP 请求，返回 ``(status, headers, body)``。

    不依赖 urllib 默认跳转，以便在 ping.pe 的 303 往返中保持 Cookie 头。
    """
    current = url
    opener = urllib.request.build_opener(_NoRedirect)
    for _ in range(6):
        req = urllib.request.Request(current, data=data, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                loc = e.headers.get("Location")
                if not loc:
                    raise
                current = urllib.parse.urljoin(current, loc)
                if e.code in (301, 302, 303) and method == "POST":
                    method = "GET"
                    data = None
                continue
            raise
    raise RuntimeError("too many redirects")


# ---------------------------------------------------------------- 启发式 L1

def _note(line: str) -> str:
    """``#`` 后、国家码之后的备注段（不含 CC，避免把 ``#CN``/``#CF`` 国家码误判为备注）。"""
    parsed = parse_ltd_line(line)
    if not parsed:
        return ""
    addr, rest = line.rsplit("#", 1)
    i = 0
    while i < len(rest) and not ("A" <= rest[i] <= "Z"):
        i += 1
    cc = "ALL" if rest[i:].startswith("ALL-") else rest[i : i + 2]
    return rest[i + len(cc):]


def is_cf_heuristic(line: str) -> bool:
    """行备注已带 ``-CF``（Cloudflare 边缘）即判定大陆可达（零网络）。"""
    return bool(re.search(r"(?:^|-)CF(?:$|-)", _note(line)))


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
                if isinstance(obj.get(key), (list, dict)):
                    return find_nodes(obj[key])
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
        except Exception:
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
        except Exception:
            pass
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
        if payload.get("ok"):
            stream_id = payload.get("data", {}).get("stream_id")
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
        except Exception:
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


# ------------------------------------------------------- itdog.cn 批量探活

def itdog_md5_16(s: str) -> str:
    """itdog WebSocket 路径签名（MD5 中段 16 位）。"""
    return hashlib.md5(s.encode()).hexdigest()[8:24]


def itdog_parse_nodes(html: str, per_isp: int) -> list[str]:
    """从 batch_http 页面 optgroup 提取各大陆运营商节点 id（每组前 ``per_isp`` 个）。"""
    ids: list[str] = []
    for label in ITDOG_ISP_GROUPS:
        m = re.search(r'<optgroup label="%s">(.*?)</optgroup>' % label, html, re.S)
        if not m:
            continue
        opts = re.findall(r'<option[^>]*value="([^"]+)"', m.group(1))
        ids.extend(opts[:per_isp])
    return ids


def itdog_fetch_nodes(per_isp: int) -> list[str]:
    """拉取当前节点列表（节点 id 会轮换，必须每次运行现取）。"""
    hdrs = {"User-Agent": UA, "Referer": "https://www.itdog.cn/"}
    for _ in range(2):
        try:
            _, _, body = request_follow(ITDOG_BATCH_URL, hdrs, 20)
            ids = itdog_parse_nodes(body.decode("utf-8", "replace"), per_isp)
            if ids:
                return ids
        except Exception:
            pass
        time.sleep(2)
    return []


def itdog_parse_submit(html: str) -> tuple[str | None, str]:
    """解析提交响应 → ``(task_id, err)``；无 task_id 时给出原因（captcha / no task）。"""
    tid = re.search(r"task_id='([^']+)'", html)
    if tid:
        return tid.group(1), ""
    if "clicaptcha" in html or "验证码" in html:
        return None, "captcha"
    return None, "no task_id"


def itdog_submit_task(targets: list[str], node_ids: list[str]) -> tuple[str | None, str]:
    """POST 一个批量任务（host 以 CRLF 连接，itdog 对 LF 会拒绝）。"""
    data = urllib.parse.urlencode({
        "host": "\r\n".join(targets),
        "node_id": ",".join(node_ids),
        "cidr_filter": "false",
        "gateway": "first",
        "port": "80",
    }).encode()
    hdrs = {
        "User-Agent": UA,
        "Origin": "https://www.itdog.cn",
        "Referer": "https://www.itdog.cn/batch_http/",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        status, _, resp = request_follow(ITDOG_BATCH_URL, hdrs, 20, method="POST", data=data)
    except urllib.error.HTTPError as e:
        return None, f"http {e.code}"
    except Exception as e:
        return None, str(e)[:120]
    if status != 200:
        return None, f"http {status}"
    return itdog_parse_submit(resp.decode("utf-8", "replace"))


class _WebSocket:
    """极简 WebSocket 客户端（只读文本帧，纯标准库）。"""

    def __init__(self, url: str, timeout: float = ITDOG_WS_IDLE):
        m = re.match(r"wss://([^/]+)(/.*)$", url)
        if not m:
            raise ValueError(f"bad ws url: {url}")
        host, path = m.group(1), m.group(2)
        key = base64.b64encode(os.urandom(16)).decode()
        ctx = ssl.create_default_context()
        self.sock = socket.create_connection((host, 443), timeout=timeout)
        self.sock = ctx.wrap_socket(self.sock, server_hostname=host)
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"Origin: https://{host}\r\nUser-Agent: {UA}\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("closed during handshake")
            data += chunk
        head, _, self.buf = data.partition(b"\r\n\r\n")
        if b"101" not in head.splitlines()[0]:
            raise RuntimeError(head.splitlines()[0].decode("utf-8", "replace")[:80])
        self.sock.settimeout(timeout)

    def settimeout(self, timeout: float) -> None:
        self.sock.settimeout(timeout)

    def send_text(self, payload) -> None:
        if isinstance(payload, str):
            payload = payload.encode()
        mask = os.urandom(4)
        ln = len(payload)
        if ln < 126:
            head = bytes([0x81, 0x80 | ln])
        elif ln < 65536:
            head = bytes([0x81, 0x80 | 126]) + struct.pack(">H", ln)
        else:
            head = bytes([0x81, 0x80 | 127]) + struct.pack(">Q", ln)
        head += mask
        self.sock.sendall(head + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def _send(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        ln = len(payload)
        if ln < 126:
            head = bytes([0x80 | opcode, 0x80 | ln])
        elif ln < 65536:
            head = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", ln)
        else:
            head = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", ln)
        head += mask
        self.sock.sendall(head + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    @staticmethod
    def _decode(buf: bytes) -> tuple[dict | None, bytes]:
        if len(buf) < 2:
            return None, buf
        b1, b2 = buf[0], buf[1]
        opcode = b1 & 0x0F
        ln = b2 & 0x7F
        idx = 2
        if ln == 126:
            if len(buf) < 4:
                return None, buf
            ln = struct.unpack(">H", buf[2:4])[0]
            idx = 4
        elif ln == 127:
            if len(buf) < 10:
                return None, buf
            ln = struct.unpack(">Q", buf[2:10])[0]
            idx = 10
        if b2 >> 7:
            if len(buf) < idx + 4:
                return None, buf
            mask = buf[idx:idx + 4]
            idx += 4
        if len(buf) < idx + ln:
            return None, buf
        payload = buf[idx:idx + ln]
        if b2 >> 7:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return {"opcode": opcode, "payload": payload}, buf[idx + ln:]

    def read(self) -> tuple[str, dict | None]:
        """返回 ``(kind, msg)``：rec=节点记录、done=任务完成、close/closed/err/timeout=异常。"""
        while True:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                return ("timeout", None)
            except (ConnectionError, ssl.SSLError, OSError) as e:
                return ("err", {"error": str(e)[:80]})
            if not chunk:
                return ("closed", None)
            self.buf += chunk
            while True:
                frame, self.buf = self._decode(self.buf)
                if frame is None:
                    break
                op = frame["opcode"]
                if op == 8:
                    return ("close", None)
                if op == 9:
                    self._send(10, frame["payload"])
                    continue
                if op == 1:
                    try:
                        msg = json.loads(frame["payload"].decode("utf-8", "replace"))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if not isinstance(msg, dict):
                        continue
                    if msg.get("type") == "finished":
                        return ("done", msg)
                    if msg.get("task_num") is not None:
                        return ("rec", msg)
                    return ("evt", msg)

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass


def itdog_collect(task_id: str, expected: int, timeout: float) -> list[dict]:
    """连接 WS 收集记录，直到完成/收齐/超时。

    注意：itdog 每任务仅接受一次 WS 连接（重连返回 403），且连接需在提交后
    尽快建立，故首连失败时短退避重试，但中途断开不再重连。
    """
    path = f"/{task_id}/{itdog_md5_16(task_id + ITDOG_TOKEN)}"
    url = ITDOG_WS_BASE + path
    records: list[dict] = []
    t0 = time.monotonic()
    ws = None
    connected = False
    try:
        for attempt in range(3):
            if time.monotonic() - t0 > timeout:
                break
            try:
                ws = _WebSocket(url)
                ws.send_text(json.dumps({"task_id": task_id}))
                connected = True
                break
            except Exception:
                time.sleep(1.0)
        if connected:
            while time.monotonic() - t0 < timeout:
                kind, msg = ws.read()
                if kind in ("rec", "evt") and isinstance(msg, dict):
                    records.append(msg)
                elif kind == "done":
                    break
                elif kind in ("close", "closed", "err", "timeout"):
                    break
                if len(records) >= expected:
                    break
    except Exception:
        pass
    finally:
        if ws:
            ws.close()
    return records


def itdog_rec_ok(rec: dict) -> tuple[bool | None, float | None]:
    """单节点记录 → ``(可达, ms)``。

    - http_code>0 → 可达
    - connect_time 介于 5ms 与 9s → TCP 连通但非 HTTP 端口，仍判可达
    - connect_time≈0（拒绝）或 ≈10s（超时）→ 不可达
    - node_error / 无字段 → None（不确定）
    """
    if rec.get("type") == "node_error":
        return None, None
    try:
        ct = float(rec.get("connect_time") or 0)
    except (TypeError, ValueError):
        ct = 0.0
    code = rec.get("http_code")
    if isinstance(code, (int, float)) and code > 0:
        return True, (ct * 1000 if 0.005 < ct < 9.0 else None)
    if 0.005 < ct < 9.0:
        return True, ct * 1000
    return False, None


def itdog_aggregate(records: list[dict], n_targets: int) -> dict:
    """按 task_num 聚合节点结果 → ``{task_num: source_result}``。"""
    out: dict = {}
    for tn in range(1, n_targets + 1):
        recs = [r for r in records if r.get("task_num") == tn]
        real = [r for r in recs if r.get("type") != "node_error"]
        if not real:
            out[tn] = {"status": "error", "ok": False, "ms": None,
                       "error": "no records" if not recs else "node_error"}
            continue
        oks = [(r, itdog_rec_ok(r)) for r in real]
        good = [(r, ok) for r, ok in oks if ok[0] is True]
        if good:
            mss = [ms for _, (_, ms) in good if ms]
            out[tn] = {"status": "ok", "ok": True,
                       "ms": round(min(mss), 1) if mss else None, "error": ""}
        else:
            out[tn] = {"status": "fail", "ok": False, "ms": None,
                       "error": f"unreachable ({len(real)} nodes)"}
    return out


def itdog_task(batch: list[tuple[str, str]], node_ids: list[str], args) -> dict:
    """单批（≤5 目标）：提交 → 收记录 → 聚合；失败重试并降级。"""
    keys = [k for k, _ in batch]
    target_strs = [t for _, t in batch]
    last_err = ""
    for attempt in range(3):
        task_id, err = itdog_submit_task(target_strs, node_ids)
        if task_id:
            expected = len(batch) * len(node_ids)
            records = itdog_collect(task_id, expected, args.itdog_timeout)
            agg = itdog_aggregate(records, len(batch))
            return {
                key: dict(agg.get(i) or {"status": "error", "ok": False, "ms": None, "error": "missing"})
                for i, key in enumerate(keys, start=1)
            }
        last_err = err
        time.sleep(15 if err == "captcha" else 2)
    status = "rate_limited" if last_err == "captcha" else "error"
    return {key: {"status": status, "ok": False, "ms": None, "error": last_err or "submit failed"}
            for key in keys}


_pace_lock = threading.Lock()
_pace_next = [0.0]


def _pace(interval: float) -> None:
    """全局最小任务启动间隔（itdog 端有节流，全量硬跑需控速）。"""
    with _pace_lock:
        now = time.monotonic()
        wait = _pace_next[0] - now
        _pace_next[0] = max(now, _pace_next[0]) + interval
    if wait > 0:
        time.sleep(wait)


def itdog_batch_run(sample, args) -> dict:
    """对非 CF 启发式目标分批跑 itdog，返回 ``{key: source_result}``。"""
    targets: list[tuple[str, str]] = []
    seen: set = set()
    for item in sample:
        line, key, ip, port, _ = item
        if is_cf_heuristic(line) or key in seen:
            continue
        seen.add(key)
        targets.append((key, f"{ip}:{port}"))
    if not targets:
        return {}
    node_ids = itdog_fetch_nodes(args.itdog_nodes)
    if not node_ids:
        return {key: {"status": "error", "ok": False, "ms": None, "error": "no itdog nodes"}
                for key, _ in targets}
    batch_size = max(1, min(args.itdog_batch_size, ITDOG_BATCH_SIZE))
    batches = [targets[i:i + batch_size] for i in range(0, len(targets), batch_size)]
    results: dict = {}
    state = {"fails": 0, "tripped": False}
    state_lock = threading.Lock()

    def mark(ok: bool) -> None:
        with state_lock:
            if ok:
                state["fails"] = 0
            else:
                state["fails"] += 1
                if state["fails"] >= 8:
                    state["tripped"] = True

    def run(batch):
        _pace(args.itdog_pacing)
        with state_lock:
            tripped = state["tripped"]
        if tripped:
            return {key: {"status": "error", "ok": False, "ms": None, "error": "itdog breaker"}
                    for key, _ in batch}
        res = itdog_task(batch, node_ids, args)
        mark(any(r["status"] in ("ok", "fail") for r in res.values()))
        return res

    with ThreadPoolExecutor(max_workers=args.itdog_concurrency) as pool:
        futures = [pool.submit(run, batch) for batch in batches]
        for fut in futures:
            results.update(fut.result())
    return results


# ------------------------------------------------------------ 判定合成

def merge_verdict(sources: dict, cf: bool) -> dict:
    """跨源合成大陆可达性判定。

    - 任一来源成功 → reachable（cf 启发式时 basis 标注 heuristic）
    - check_host 与 xxapi 均失败 → unreachable
    - 多节点源（ping.pe / itdog）失败且另有单节点源失败 → unreachable
    - 仅单方失败 → uncertain
    - 全部为错误/跳过 → skipped（不误判）
    """
    ok_sources = [name for name, r in sources.items() if r.get("ok")]
    fail_sources = [name for name, r in sources.items() if r["status"] == "fail"]
    ms_values = [
        r["ms"] for r in sources.values()
        if r.get("ok") and isinstance(r.get("ms"), (int, float)) and r["ms"] > 0
    ]
    ms = round(min(ms_values), 1) if ms_values else None

    if ok_sources:
        if not any(name.startswith("heuristic") for name in ok_sources):
            return {"verdict": "reachable", "basis": ok_sources, "ms": ms}
        return {"verdict": "reachable", "basis": ok_sources + ["heuristic"], "ms": ms}
    if cf:
        return {"verdict": "reachable", "basis": ["heuristic"], "ms": None}
    if "check_host" in fail_sources and "xxapi" in fail_sources:
        return {"verdict": "unreachable", "basis": fail_sources, "ms": None}
    if "pingpe" in fail_sources and any(s in fail_sources for s in ("check_host", "xxapi", "itdog")):
        return {"verdict": "unreachable", "basis": fail_sources, "ms": None}
    if "itdog" in fail_sources and any(s in fail_sources for s in ("check_host", "xxapi", "pingpe")):
        return {"verdict": "unreachable", "basis": fail_sources, "ms": None}
    if fail_sources:
        return {"verdict": "uncertain", "basis": fail_sources, "ms": None}
    return {"verdict": "skipped", "basis": [], "ms": None}


def has_cn_note(line: str) -> bool:
    return bool(re.search(r"(?:^|-)CN(?:$|-)", _note(line)))


def annotate_cn(line: str) -> str:
    if has_cn_note(line):
        return line
    return line + "-CN"


# ------------------------------------------------------------ 数据装载与写出

def load_sample(source: Path, limit: int):
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
    cf = is_cf_heuristic(item[0])
    merged = merge_verdict(sources, cf)
    return {
        "ip": ip,
        "port": port,
        "cc": cc,
        "cf_heuristic": cf,
        "verdict": merged["verdict"],
        "basis": merged["basis"],
        "ms": merged["ms"],
        "sources": sources,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def generate_all_cn(all_ltd_text: str, reachable_keys: set) -> tuple[str, int]:
    """大陆可达清单：本次判可达或历史已带 ``-CN`` 的行。"""
    lines = []
    for line in all_ltd_text.splitlines():
        if not line.strip():
            continue
        key = line_to_key(line)
        if not key:
            continue
        if key in reachable_keys or has_cn_note(line):
            lines.append(annotate_cn(line))
    return "\n".join(lines) + ("\n" if lines else ""), len(lines)


def annotate_cn_files(reachable_keys: set) -> None:
    """给 all.txt / all_ltd.txt 追加 ``-CN``（幂等，已带则跳过）。"""
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
            if key and key in reachable_keys and not has_cn_note(line):
                out.append(line + "-CN")
                changed = True
            else:
                out.append(line)
        if changed:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
            tmp.replace(path)


# ------------------------------------------------------------ 主流程

def run_measurements(sample, args) -> tuple[dict, set, set]:
    """L2 并发单节点、itdog 批量、L3 串行复核；返回 (entries, reachable_keys, uncertain_keys)。"""
    entries: dict = {}
    ch_limiter = RateLimiter(CH_WINDOW_SEC, CH_PER_WINDOW, CH_HOUR_CAP)

    def l2(item):
        _, key, ip, port, _ = item
        sources = {
            "check_host": check_host_check(ip, port, ch_limiter, args.timeout, args.api_key),
            "xxapi": xxapi_check(ip, port, args.timeout),
        }
        return key, sources

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(l2, item) for item in sample]
        for future in futures:
            key, sources = future.result()
            entries[key] = sources

    if not args.skip_itdog:
        for key, res in itdog_batch_run(sample, args).items():
            entries.setdefault(key, {})["itdog"] = res

    for item in sample[: args.pingpe_limit]:
        _, key, ip, port, _ = item
        pingpe = pingpe_check(ip, port, args.timeout)
        entries[key]["pingpe"] = pingpe
        tcpping = tcpping_check(ip, port, args.tcpping_token, args.timeout)
        if tcpping["status"] != "skipped":
            entries[key]["tcpping"] = tcpping
        time.sleep(2.0)

    reachable = set()
    uncertain = set()
    for item in sample:
        line, key, ip, port, cc = item
        sources = entries[key]
        cf = is_cf_heuristic(line)
        merged = merge_verdict(sources, cf)
        entries[key] = build_entry(item, sources)
        entries[key]["verdict"] = merged["verdict"]
        entries[key]["basis"] = merged["basis"]
        entries[key]["ms"] = merged["ms"]
        if merged["verdict"] == "reachable":
            reachable.add(key)
        elif merged["verdict"] == "uncertain":
            uncertain.add(key)
    return entries, reachable, uncertain


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="china_check.py",
        description="大陆连通性检测（启发式 CF + itdog 批量 + check-host.cc + xxapi.cn + ping.pe [+ tcpping.cn]）",
    )
    parser.add_argument("--source", type=Path, default=REP_RANK_FILE,
                        help=f"输入清单（默认 {REP_RANK_FILE.name}，缺失回退 all_ltd.txt）")
    parser.add_argument("--limit", type=int, default=LIMIT_DEFAULT,
                        help=f"按信誉降序采样条数（0=全部；默认 {LIMIT_DEFAULT}）")
    parser.add_argument("--pingpe-limit", type=int, default=PINGPE_LIMIT_DEFAULT,
                        help=f"ping.pe 多节点复核条数（串行小样本；默认 {PINGPE_LIMIT_DEFAULT}）")
    parser.add_argument("--workers", type=int, default=WORKERS_DEFAULT,
                        help=f"L2 并发上限（默认 {WORKERS_DEFAULT}）")
    parser.add_argument("-t", "--timeout", type=float, default=TIMEOUT_DEFAULT,
                        help=f"单次 HTTP 超时秒数（默认 {TIMEOUT_DEFAULT}）")
    parser.add_argument("--api-key", default="",
                        help="check-host.cc API key（默认读 CHINA_CHECK_API_KEY，可选）")
    parser.add_argument("--tcpping-token", default="",
                        help="tcpping.cn token（默认读 TCPPING_CN_TOKEN，缺则跳过）")
    parser.add_argument("--itdog-nodes", type=int, default=ITDOG_NODES_PER_ISP,
                        help=f"itdog 每大陆运营商取前 N 节点（默认 {ITDOG_NODES_PER_ISP} → 共 3）")
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
    parser.add_argument("--dry-run", action="store_true",
                        help="只输出计划，不做任何网络请求与写盘")
    parser.add_argument("--skip-pingpe", action="store_true",
                        help="跳过 ping.pe 多节点复核（本地快速冒烟用）")
    args = parser.parse_args(argv)

    api_key = args.api_key or os_environ("CHINA_CHECK_API_KEY")
    tcpping_token = args.tcpping_token or os_environ("TCPPING_CN_TOKEN")
    args.api_key = api_key
    args.tcpping_token = tcpping_token

    sample, used = load_sample(args.source, args.limit)
    if not sample:
        print(f"no sample lines from {used} (limit={args.limit})", file=sys.stderr)
        return 2
    print(f"sample: {len(sample)} from {used}", file=sys.stderr)
    cf_count = sum(1 for item in sample if is_cf_heuristic(item[0]))
    print(f"cf heuristic: {cf_count}", file=sys.stderr)

    if args.dry_run:
        print("dry-run: no network, no writes", file=sys.stderr)
        return 0

    if args.skip_pingpe:
        args.pingpe_limit = 0

    entries, reachable, uncertain = run_measurements(sample, args)

    print(f"reachable: {len(reachable)} uncertain: {len(uncertain)}", file=sys.stderr)
    write_json(CHINA_FILE, keyed_json(entries))

    all_ltd_path = VALID_DIR / "all_ltd.txt"
    all_ltd_text = all_ltd_path.read_text(encoding="utf-8") if all_ltd_path.exists() else ""
    cn_text, cn_count = generate_all_cn(all_ltd_text, reachable)
    if cn_text:
        ALL_CN_FILE.write_text(cn_text, encoding="utf-8")
    annotate_cn_files(reachable)
    print(f"all_cn.txt: {cn_count} lines; china.json: {len(entries)} entries", file=sys.stderr)
    return 0


def os_environ(name: str) -> str:
    import os

    return os.environ.get(name, "")


if __name__ == "__main__":
    sys.exit(main())
