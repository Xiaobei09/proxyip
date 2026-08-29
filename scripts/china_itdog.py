#!/usr/bin/env python3
"""itdog.cn 批量大陆可达性探测（WebSocket 收结果）。

从 ``china_check`` 拆出的独立模块：抓取电信/联通/移动节点 → 提交批量
HTTP 任务 → 经 ``wss://www.itdog.cn`` 轮询收集记录 → 聚合成源判定。
仅依赖 ``common`` 的 ``UA``/``request_follow``。目标集为去重后的全量
存活池（含 Cloudflare 边缘行，它们恰是当代池子主体——CF 只是 basis
标注，是否大陆可达仍须多点节点确认，这正是 itdog 的职责）。
"""

import base64
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import struct
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from common import UA, request_follow

ITDOG_BATCH_URL = "https://www.itdog.cn/batch_http/"
ITDOG_TCPING_URL = "https://www.itdog.cn/batch_tcping/"
ITDOG_WS_BASE = "wss://www.itdog.cn/websockets"
ITDOG_TOKEN = "What this is is no longer important."
ITDOG_BATCH_SIZE = 5  # itdog 每任务仅返回前 5 个目标的记录
ITDOG_NODES_PER_ISP = 6  # 电信/联通/移动各取 N 节点（默认 6 → 共 18，池子 ~80/ISP）
ITDOG_TCPING_NODES_PER_ISP = 6  # batch_tcping 节点池大（每 ISP ~75-88），取 6 → 共 18
ITDOG_CONCURRENCY = 8
ITDOG_PACING = 0.5  # 两次任务启动的最小间隔（秒），全局节流
ITDOG_TASK_TIMEOUT = 45.0  # 单任务收结果上限
ITDOG_WS_IDLE = 20.0  # WS 单次 recv 空闲超时
ITDOG_ISP_GROUPS = ("中国电信", "中国联通", "中国移动")

def itdog_md5_16(s: str) -> str:
    """itdog WebSocket 路径签名（MD5 中段 16 位）。"""
    return hashlib.md5(s.encode()).hexdigest()[8:24]


def itdog_parse_nodes(html: str, per_isp: int) -> list[str]:
    """从 batch_http 页面 optgroup 提取各大陆运营商节点 id。

    每组按等距 stride 采样 ``per_isp`` 个（节点列表大致按省份排序，
    等距取样可覆盖南北方而非只取列表头部），不足则全取。
    """
    ids: list[str] = []
    for label in ITDOG_ISP_GROUPS:
        m = re.search(r'<optgroup label="%s">(.*?)</optgroup>' % label, html, re.S)
        if not m:
            continue
        opts = re.findall(r'<option[^>]*value="([^"]+)"', m.group(1))
        stride = max(1, len(opts) // per_isp) if per_isp > 0 else 1
        ids.extend(opts[::stride][:per_isp])
    return ids


def itdog_fetch_nodes(per_isp: int, page_url: str = ITDOG_BATCH_URL) -> list[str]:
    """拉取当前节点列表（节点 id 会轮换，必须每次运行现取）。"""
    hdrs = {"User-Agent": UA, "Referer": "https://www.itdog.cn/"}
    for _ in range(2):
        try:
            _, _, body = request_follow(page_url, hdrs, 20)
            ids = itdog_parse_nodes(body.decode("utf-8", "replace"), per_isp)
            if ids:
                return ids
        except Exception as exc:
            logging.debug("itdog fetch nodes: %s", exc)
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


def itdog_submit_task(
    targets: list[str], node_ids: list[str], page_url: str = ITDOG_BATCH_URL
) -> tuple[str | None, str]:
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
        "Referer": page_url,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        status, _, resp = request_follow(page_url, hdrs, 20, method="POST", data=data)
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
        except Exception as exc:
            logging.debug("ws close: %s", exc)


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
            except Exception as exc:
                logging.debug("itdog ws connect: %s", exc)
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
    except Exception as exc:
        logging.debug("itdog ws poll: %s", exc)
    finally:
        if ws:
            ws.close()
    return records


def itdog_rec_ok(rec: dict) -> tuple[bool | None, float | None, str | None]:
    """单节点记录 → ``(可达, ms, level)``。

    - http_code>0 → 可达，level="http"（应用层确认）
    - connect_time 介于 5ms 与 9s → TCP 连通但非 HTTP 端口，仍判可达，
      level="tcp"（仅传输层）
    - connect_time≈0（拒绝）或 ≈10s（超时）→ 不可达
    - node_error / 无字段 → (None, None, None)（不确定）
    """
    if rec.get("type") == "node_error":
        return None, None, None
    # batch_tcping 记录：``result`` 为 TCP 耗时毫秒字符串，"-1"/无效 = 失败，
    # 无 http_code（纯 TCPING，level 恒为 "tcp"）
    if "result" in rec and "connect_time" not in rec:
        try:
            ms = float(rec.get("result"))
        except (TypeError, ValueError):
            return False, None, None
        if ms > 0:
            return True, ms, "tcp"
        return False, None, None
    try:
        ct = float(rec.get("connect_time") or 0)
    except (TypeError, ValueError):
        ct = 0.0
    code = rec.get("http_code")
    if isinstance(code, (int, float)) and code > 0:
        return True, (ct * 1000 if 0.005 < ct < 9.0 else None), "http"
    if 0.005 < ct < 9.0:
        return True, ct * 1000, "tcp"
    return False, None, None


def itdog_aggregate(records: list[dict], n_targets: int) -> dict:
    """按 task_num 聚合节点结果 → ``{task_num: source_result}``。

    ``level`` 反映证据强度：任一成功节点拿到 http_code → ``"http"``，
    仅 TCP 连通 → ``"tcp"``。

    ``ok_nodes``/``nodes``/``ratio``：成功节点数与总节点数及比值——
    供 merge_verdict 做"单节点假阳性"抑制（例如仅 1/18 大陆节点可达
    不应独立支撑 reachable 判定）。
    """
    out: dict = {}
    for tn in range(1, n_targets + 1):
        recs = [r for r in records if r.get("task_num") == tn]
        real = [r for r in recs if r.get("type") != "node_error"]
        if not real:
            out[tn] = {"status": "error", "ok": False, "ms": None,
                       "error": "no records" if not recs else "node_error",
                       "level": None, "ok_nodes": 0, "nodes": 0,
                       "ratio": None}
            continue
        oks = [(r, itdog_rec_ok(r)) for r in real]
        good = [(r, ok) for r, ok in oks if ok[0] is True]
        if good:
            mss = [ms for _, (_, ms, _lv) in good if ms]
            level = "http" if any(lv == "http" for _, (_o, _m, lv) in good) else "tcp"
            out[tn] = {
                "status": "ok", "ok": True,
                "ms": round(min(mss), 1) if mss else None, "error": "",
                "level": level,
                "ok_nodes": len(good), "nodes": len(real),
                "ratio": round(len(good) / len(real), 3),
            }
        else:
            out[tn] = {"status": "fail", "ok": False, "ms": None,
                       "error": f"unreachable ({len(real)} nodes)",
                       "level": None, "ok_nodes": 0, "nodes": len(real),
                       "ratio": 0.0}
    return out


def itdog_task(
    batch: list[tuple[str, str]],
    node_ids: list[str],
    args,
    page_url: str = ITDOG_BATCH_URL,
) -> dict:
    """单批（≤5 目标）：提交 → 收记录 → 聚合；失败重试并降级。"""
    keys = [k for k, _ in batch]
    target_strs = [t for _, t in batch]
    last_err = ""
    for attempt in range(3):
        task_id, err = itdog_submit_task(target_strs, node_ids, page_url)
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


def itdog_batch_run(
    sample,
    args,
    page_url: str = ITDOG_BATCH_URL,
    nodes_per_isp: int | None = None,
) -> dict:
    """按去重后的全量存活池分批跑 itdog，返回 ``{key: source_result}``。

    ``page_url``/``nodes_per_isp`` 用于 batch_tcping 降级通道（更大节点池，
    纯 TCPING）；缺省走 batch_http。
    """
    targets: list[tuple[str, str]] = []
    seen: set = set()
    for item in sample:
        line, key, ip, port, _ = item
        if key in seen:
            continue
        seen.add(key)
        targets.append((key, f"{ip}:{port}"))
    if not targets:
        return {}
    node_ids = itdog_fetch_nodes(nodes_per_isp or args.itdog_nodes, page_url)
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
        with state_lock:
            tripped = state["tripped"]
        if tripped:
            return {key: {"status": "error", "ok": False, "ms": None, "error": "itdog breaker"}
                    for key, _ in batch}
        _pace(args.itdog_pacing)
        res = itdog_task(batch, node_ids, args, page_url)
        mark(any(r["status"] in ("ok", "fail") for r in res.values()))
        return res

    with ThreadPoolExecutor(max_workers=args.itdog_concurrency) as pool:
        futures = [pool.submit(run, batch) for batch in batches]
        for fut in futures:
            results.update(fut.result())
    return results
