#!/usr/bin/env python3
"""Mainland-China reachability checks for the alive proxy pool.

独立 CI（``china-check.yml``）运行：对 ``data/valid/all.txt`` 全量（约 1.9 万行，
``--source data/valid/all.txt --limit 0``）做大陆连通性检测，产出一致结论后写回：
（本地缺省仍走 ``all_rep.txt`` 按信誉降序取前 250 的小样本）

- ``data/valid/china.json``  — 逐条检测明细（keyed，``{"proxies": {...}}``）
- ``data/valid/all_cn.txt``  — 全量大陆可达清单（源为 ``data/valid/all.txt`` 全量存活池，
  仅含判定 reachable 或已带 ``-CN`` 的行；回退 all_ltd.txt）
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
    DEFAULT_SOURCE,
    REP_RANK_FILE,
    UA,
    VALID_DIR,
    has_token,
    is_cf_heuristic,
    keyed_json,
    line_to_key,
    parse_ltd_line,
    request_follow,
    write_json,
    write_text_if_changed,
    _note,
)
from china_itdog import *

FALLBACK_SOURCE = DEFAULT_SOURCE
CHINA_FILE = VALID_DIR / "china.json"
ALL_CN_FILE = VALID_DIR / "all_cn.txt"

LIMIT_DEFAULT = 250
PINGPE_LIMIT_DEFAULT = 40
WORKERS_DEFAULT = 8
TIMEOUT_DEFAULT = 10
POLL_DEADLINE = 75.0
POLL_INTERVAL = 3.0

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
    return has_token(_note(line), "CN")


def annotate_cn(line: str) -> str:
    if has_cn_note(line):
        return line
    return line + "-CN"


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


def load_cn_pool() -> str:
    """全量存活池文本（``all_cn.txt`` 生成源）：优先 ``data/valid/all.txt``，缺则回退 all_ltd.txt。"""
    path = VALID_DIR / "all.txt"
    if not path.exists():
        path = VALID_DIR / "all_ltd.txt"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def generate_all_cn(pool_text: str, reachable_keys: set) -> tuple[str, int]:
    """大陆可达清单：本次判可达或历史已带 ``-CN`` 的行（源为全量池文本）。"""
    lines = []
    for line in pool_text.splitlines():
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

    all_pool_text = load_cn_pool()
    cn_text, cn_count = generate_all_cn(all_pool_text, reachable)
    if cn_text:
        write_text_if_changed(ALL_CN_FILE, cn_text)
    annotate_cn_files(reachable)
    print(f"all_cn.txt: {cn_count} lines; china.json: {len(entries)} entries", file=sys.stderr)
    return 0


def os_environ(name: str) -> str:
    import os

    return os.environ.get(name, "")


if __name__ == "__main__":
    sys.exit(main())
