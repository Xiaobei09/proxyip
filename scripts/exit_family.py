#!/usr/bin/env python3
"""Actual exit IP address-family (IPv4/IPv6) detection for the alive proxy pool.

独立 CI（``exit-family.yml``）运行：对 ``data/valid/all.txt``（全量存活池，缺省；
可用 ``--source`` 覆盖）逐条探测真实出口的 IP 家族，按家族分离保存：

- ``data/valid/all_ipv4.txt``  — 出口为 IPv4 的代理清单（双栈代理同时计入）
- ``data/valid/all_ipv6.txt``  — 出口为 IPv6 的代理清单（双栈代理同时计入）
- ``data/valid/exit_family.json`` — 逐条检测明细（keyed，``{"proxies": {...}}``）

并在 ``all.txt`` / ``all_ltd.txt`` 对应行追加 ``-V4`` / ``-V6`` / ``-DS`` 备注
（幂等，与 ``quality_check`` 已有的 ``DS``/``V6`` token 约定一致）。

探测方法按 ``index.json`` 记录的代理方法分流：

- ``tls``（Cloudflare 边缘）：直连 TLS + SNI → ``cloudflare.com/cdn-cgi/trace``，
  取回显 ``ip=`` 判 v4/v6（这类代理无法 CONNECT 到任意主机）
- ``connect``（标准 HTTP CONNECT 代理）：经隧道双回显 ``api.ipify.org``(v4) 与
  ``api6.ipify.org``(v6)，成功者分别判定对应家族

家族判定：仅 v4 → ``ipv4``；仅 v6 → ``ipv6``；双通 → ``dual``；探测全失败 →
``unknown``（不入任何分离清单）。纯标准库，ThreadPoolExecutor 并发。

交叉验证：若 ``data/upstream_meta.json`` 存在（由 ``download_proxies.py`` 从上游
``all.json`` 生成），逐条对照上游记录的真实出口 ``clientIp``，在
``exit_family.json`` 中写入 ``upstream_client_ip`` / ``upstream_family`` /
``upstream_match`` 字段并输出命中统计；文件缺失时静默跳过，不降级实时探测。
"""

import argparse
import json
import re
import socket
import ssl
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from download_proxies import OUT_DIR
from quality_check import (
    build_request,
    keyed_json,
    line_to_key,
    load_methods,
    parse_headers,
    parse_ltd_line,
    write_json,
)

VALID_DIR = OUT_DIR / "valid"
DEFAULT_SOURCE = VALID_DIR / "all.txt"
ALL_V4_FILE = VALID_DIR / "all_ipv4.txt"
ALL_V6_FILE = VALID_DIR / "all_ipv6.txt"
EXIT_FAMILY_FILE = VALID_DIR / "exit_family.json"
UPSTREAM_META_FILE = OUT_DIR / "upstream_meta.json"

WORKERS_DEFAULT = 16
TIMEOUT_DEFAULT = 10

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

TRACE_HOST = "cloudflare.com"
TRACE_PATH = "/cdn-cgi/trace"

ECHO_V4_HOST = "api.ipify.org"
ECHO_V6_HOST = "api6.ipify.org"
ECHO_PORT = 80

_SSL_CTX = ssl.create_default_context()

FAMILY_TOKENS = {"ipv4": "V4", "ipv6": "V6", "dual": "DS"}


# ------------------------------------------------------------ 同步 socket I/O

def _read_until(sock: socket.socket, delim: bytes, cap: int) -> bytes:
    data = b""
    while delim not in data and len(data) < cap:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


def read_http_response_sync(sock: socket.socket, cap: int):
    """同步版 HTTP 响应读取 → ``(status, headers, body)``。"""
    raw = _read_until(sock, b"\r\n\r\n", 65536)
    if b"\r\n\r\n" not in raw:
        return None, {}, raw
    head, body = raw.split(b"\r\n\r\n", 1)
    status, headers = parse_headers(head)
    if status is None:
        return None, headers, body
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body += _read_chunked_sync(sock, cap, len(body))
    else:
        clen = headers.get("content-length")
        want = min(int(clen), cap) if clen else cap
        while len(body) < want:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
    return status, headers, body[:cap]


def _read_chunked_sync(sock: socket.socket, cap: int, start: int) -> bytes:
    body = b""
    while len(body) + start < cap:
        head = _read_until(sock, b"\r\n", 64)
        if b"\r\n" not in head:
            return body
        size = int(head.split(b";", 1)[0].strip() or b"0", 16)
        if size == 0:
            _read_until(sock, b"\r\n", 16)
            return body
        remain = size
        while remain > 0:
            chunk = sock.recv(min(remain, 65536))
            if not chunk:
                return body
            body += chunk
            remain -= len(chunk)
        sock.recv(2)
    return body


def request_tls_sni(ip: str, port: str, host: str, path: str, timeout: float):
    """直连 TLS（``host`` 为 SNI）→ 返回 ``(status, headers, body)``。"""
    raw = None
    try:
        raw = socket.create_connection((ip, int(port)), timeout=timeout)
        with _SSL_CTX.wrap_socket(raw, server_hostname=host) as sock:
            sock.settimeout(timeout)
            sock.sendall(build_request("GET", path, host))
            return read_http_response_sync(sock, 8192)
    except (OSError, ssl.SSLError, ValueError, socket.timeout):
        return None, {}, b""
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass


def connect_tunnel(ip: str, port: str, host: str, target_port: int, timeout: float):
    """建立 CONNECT 隧道，成功返回已就绪的 socket，失败返回 None。"""
    try:
        raw = socket.create_connection((ip, int(port)), timeout=timeout)
    except (OSError, ValueError):
        return None
    try:
        raw.settimeout(timeout)
        req = (
            f"CONNECT {host}:{target_port} HTTP/1.1\r\n"
            f"Host: {host}:{target_port}\r\n"
            f"User-Agent: {UA}\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n"
        ).encode("ascii")
        raw.sendall(req)
        head = _read_until(raw, b"\r\n\r\n", 8192)
        status, _headers = parse_headers(head)
        if status != 200:
            raw.close()
            return None
        return raw
    except (OSError, socket.timeout):
        try:
            raw.close()
        except OSError:
            pass
        return None


def connect_echo(ip: str, port: str, host: str, timeout: float) -> str | None:
    """CONNECT 隧道内 GET ``host/``，返回响应体（出口 IP 文本）或 None。"""
    sock = connect_tunnel(ip, port, host, ECHO_PORT, timeout)
    if sock is None:
        return None
    try:
        sock.sendall(build_request("GET", "/", host))
        status, _headers, body = read_http_response_sync(sock, 2048)
        if status != 200:
            return None
        text = body.decode("utf-8", "replace").strip()
        return text if re.match(r"^[0-9A-Fa-f:.:]+$", text) else None
    except (OSError, socket.timeout):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ------------------------------------------------------------ 解析与判定

def parse_trace(body: bytes) -> dict:
    """``cdn-cgi/trace`` 响应（``key=value`` 每行）→ dict。"""
    out: dict = {}
    for line in body.decode("utf-8", "replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def classify_family(v4: str | None, v6: str | None) -> str:
    if v4 and v6:
        return "dual"
    if v4:
        return "ipv4"
    if v6:
        return "ipv6"
    return "unknown"


def tls_exit(ip: str, port: str, timeout: float) -> dict:
    """CF 边缘代理出口：trace 回显 ``ip=`` 判家族。"""
    status, _headers, body = request_tls_sni(ip, port, TRACE_HOST, TRACE_PATH, timeout)
    if status != 200 or not body:
        return {"status": "error", "family": "unknown", "ip": None}
    exit_ip = parse_trace(body).get("ip") or ""
    if ":" in exit_ip:
        return {"status": "ok", "family": "ipv6", "ip": exit_ip}
    if exit_ip:
        return {"status": "ok", "family": "ipv4", "ip": exit_ip}
    return {"status": "no_ip", "family": "unknown", "ip": None}


def connect_exit(ip: str, port: str, timeout: float) -> dict:
    """CONNECT 代理出口：v4 + v6 双回显。"""
    v4 = connect_echo(ip, port, ECHO_V4_HOST, timeout)
    v6 = connect_echo(ip, port, ECHO_V6_HOST, timeout)
    return {
        "status": "ok",
        "family": classify_family(v4, v6),
        "exit_v4": v4,
        "exit_v6": v6,
    }


def check_one(item, methods: dict, timeout: float):
    line, key, ip, port, cc = item
    method = methods.get(key, "tls")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = {
        "line": line,
        "ip": ip,
        "port": port,
        "cc": cc,
        "method": method,
        "ts": ts,
    }
    if method == "connect":
        res = connect_exit(ip, port, timeout)
        base.update(
            family=res["family"],
            exit_v4=res["exit_v4"],
            exit_v6=res["exit_v6"],
        )
    else:
        res = tls_exit(ip, port, timeout)
        base.update(
            family=res["family"],
            exit_v4=res["ip"] if res["family"] == "ipv4" else None,
            exit_v6=res["ip"] if res["family"] == "ipv6" else None,
        )
    return key, base


# ------------------------------------------------------------ 备注与分离

def _note(line: str) -> str:
    """``#`` 后、国家码之后的备注段（不含 CC）。"""
    parsed = parse_ltd_line(line)
    if not parsed:
        return ""
    addr, rest = line.rsplit("#", 1)
    i = 0
    while i < len(rest) and not ("A" <= rest[i] <= "Z"):
        i += 1
    return rest[i + 2:]


def has_family_note(line: str) -> bool:
    return bool(re.search(r"(?:^|-)(V4|V6|DS)(?:$|-)", _note(line)))


def annotate_family(line: str, family: str) -> str:
    tok = FAMILY_TOKENS.get(family)
    if not tok:
        return line
    if re.search(rf"(?:^|-){tok}(?:$|-)", _note(line)):
        return line
    return line + "-" + tok


def split_by_family(results: dict) -> tuple[list, list]:
    """``{key: {line, family}}`` → ``(v4_lines, v6_lines)``，双栈双入。"""
    v4: list = []
    v6: list = []
    for res in results.values():
        fam = res["family"]
        out = annotate_family(res["line"], fam)
        if fam in ("ipv4", "dual"):
            v4.append(out)
        if fam in ("ipv6", "dual"):
            v6.append(out)
    return v4, v6


# ------------------------------------------------------------ 数据装载与写出

def load_sample(source: Path, limit: int) -> list:
    lines = [l for l in source.read_text(encoding="utf-8").splitlines() if l.strip()]
    out = []
    for line in lines:
        parsed = parse_ltd_line(line)
        if not parsed:
            continue
        key, ip, port, cc = parsed
        out.append((line, key, ip, port, cc))
    if limit and limit > 0:
        out = out[:limit]
    return out


def load_upstream_meta(path: Path | None = None) -> dict:
    """读入上游 ``all.json`` 生成的元数据表（keyed by ip）。缺失/损坏 → ``{}``。"""
    path = path or UPSTREAM_META_FILE
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def cross_check(results: dict, upstream: dict) -> None:
    """把上游真实出口 ``clientIp`` 并入每条结果（原地修改）作交叉验证。

    命中上游的条目写入 ``upstream_client_ip`` / ``upstream_family`` /
    ``upstream_match``（探测与上游家族均为已知值时才比较，否则置 ``None``）；
    未命中写入 ``upstream_absent: true``。
    """
    for res in results.values():
        meta = upstream.get(res["ip"])
        if not isinstance(meta, dict):
            res["upstream_absent"] = True
            continue
        client_ip = meta.get("clientIp")
        up_family = meta.get("family")
        res["upstream_client_ip"] = client_ip
        res["upstream_family"] = up_family
        res["upstream_absent"] = False
        if res["family"] != "unknown" and up_family in ("ipv4", "ipv6"):
            res["upstream_match"] = res["family"] == up_family
        else:
            res["upstream_match"] = None


def write_lines(path: Path, lines: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    tmp.replace(path)


def annotate_source_files(families: dict, source: Path) -> None:
    """给 all.txt / all_ltd.txt 幂等追加家族 token。"""
    targets = [VALID_DIR / "all.txt", VALID_DIR / "all_ltd.txt"]
    if source != VALID_DIR / "all.txt" and source != VALID_DIR / "all_ltd.txt":
        targets.append(source)
    for path in targets:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        out = []
        changed = False
        for line in text.splitlines():
            if not line:
                continue
            fam = families.get(line_to_key(line))
            new = annotate_family(line, fam) if fam else line
            if new != line:
                changed = True
            out.append(new)
        if changed:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
            tmp.replace(path)


# ------------------------------------------------------------ 主流程

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="exit_family.py",
        description="实际出口 IP 家族（IPv4/IPv6）检测与分离保存",
    )
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE,
                        help=f"输入清单（默认 {DEFAULT_SOURCE.name}，全量存活池）")
    parser.add_argument("--limit", type=int, default=0,
                        help="只检测前 N 条（0=全部，默认 0）")
    parser.add_argument("--workers", type=int, default=WORKERS_DEFAULT,
                        help=f"并发上限（默认 {WORKERS_DEFAULT}）")
    parser.add_argument("-t", "--timeout", type=float, default=TIMEOUT_DEFAULT,
                        help=f"单次连接超时秒数（默认 {TIMEOUT_DEFAULT}）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只输出计划，不做任何网络请求与写盘")
    args = parser.parse_args(argv)

    sample = load_sample(args.source, args.limit)
    if not sample:
        print(f"no sample lines from {args.source} (limit={args.limit})", file=sys.stderr)
        return 2
    methods = load_methods()
    method_counts = {}
    for item in sample:
        m = methods.get(item[1], "tls")
        method_counts[m] = method_counts.get(m, 0) + 1
    print(f"sample: {len(sample)} from {args.source}", file=sys.stderr)
    print(f"methods: {method_counts}", file=sys.stderr)

    if args.dry_run:
        print("dry-run: no network, no writes", file=sys.stderr)
        return 0

    results: dict = {}
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(check_one, item, methods, args.timeout) for item in sample]
        for future in futures:
            key, res = future.result()
            with lock:
                results[key] = res

    families = {key: res["family"] for key, res in results.items()}
    v4_lines, v6_lines = split_by_family(results)
    upstream = load_upstream_meta()
    cross_check(results, upstream)
    entries = {
        key: {k: v for k, v in res.items() if k != "line"}
        for key, res in results.items()
    }
    write_json(EXIT_FAMILY_FILE, keyed_json(entries))
    write_lines(ALL_V4_FILE, v4_lines)
    write_lines(ALL_V6_FILE, v6_lines)
    annotate_source_files(families, args.source)

    from collections import Counter

    fam_counts = Counter(families.values())
    print(f"family: {dict(fam_counts)}", file=sys.stderr)
    print(f"all_ipv4.txt: {len(v4_lines)} lines; all_ipv6.txt: {len(v6_lines)} lines",
          file=sys.stderr)
    if upstream:
        compared = sum(1 for r in results.values() if not r.get("upstream_absent"))
        matched = sum(1 for r in results.values() if r.get("upstream_match") is True)
        mismatched = sum(1 for r in results.values() if r.get("upstream_match") is False)
        absent = sum(1 for r in results.values() if r.get("upstream_absent"))
        print(f"upstream cross-check: {compared} compared, {matched} match / "
              f"{mismatched} mismatch, {absent} absent", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
