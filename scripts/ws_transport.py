#!/usr/bin/env python3
"""极简 WebSocket 客户端（只读文本帧，纯标准库）。

从 CN 探测模块拆出的通用传输层：握手/掩码发送/帧重组/缓冲上限，
不含任何站点私有协议细节（URL、签名、任务语义一律由调用方以参数传入）。
``origin`` 为空时沿用默认 ``https://{ws-host}``；部分校验 Origin 白名单
的站点需显式传入页源，否则握手后即关。
"""

import base64
import json
import logging
import os
import re
import socket
import ssl
import struct

from common import UA, err_name

WS_MAX_HEAD = 32 * 1024  # 握手响应头上限（防上游冲刷无 EOF 导致无界累积）
WS_MAX_BUF = 4 * 1024 * 1024  # 帧重组缓冲上限（防坏帧长/滴灌撑爆内存）
WS_IDLE = 20.0  # WS 单次 recv 空闲超时


def _err(e: Exception) -> str:
    """异常类型名（不带 ``str(e)``：URLError 的 str 含完整 URL 与 token）。"""
    return err_name(e)


class _WebSocket:
    """极简 WebSocket 客户端（只读文本帧，纯标准库）。

    ``origin`` 为空时沿用默认 ``https://{ws-host}``；部分站点校验 Origin
    白名单，需显式传入页源（否则握手后即关）。
    """

    def __init__(self, url: str, timeout: float = WS_IDLE,
                 origin: str | None = None):
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
            f"Origin: {origin or 'https://' + host}\r\nUser-Agent: {UA}\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("closed during handshake")
            data += chunk
            if len(data) > WS_MAX_HEAD:
                raise RuntimeError("oversized ws handshake")
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
        """返回 ``(kind, msg)``：rec=流记录、done=任务完成、close/closed/err/timeout=异常。"""
        while True:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                return ("timeout", None)
            except (ConnectionError, ssl.SSLError, OSError) as e:
                return ("err", {"error": _err(e)})
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
            if len(self.buf) > WS_MAX_BUF:
                return ("err", {"error": "ws buffer overflow"})

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception as exc:
            logging.debug("ws close: %s", _err(exc))
