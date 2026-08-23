#!/usr/bin/env python3
"""Actual exit IP address-family (IPv4/IPv6) detection for the alive proxy pool.

独立 CI（``exit-family.yml``）运行：对 ``data/valid/all.txt``（全量存活池，缺省；
可用 ``--source`` 覆盖）逐条探测真实出口的 IP 家族，按家族分离保存：

- ``data/valid/all_ipv4.txt``  — 出口为 IPv4 的代理清单（双栈代理同时计入）
- ``data/valid/all_ipv6.txt``  — 出口为 IPv6 的代理清单（双栈代理同时计入）
- ``data/quality/exit_family.json`` — 逐条检测明细（keyed，``{"proxies": {...}}``）

并在 ``all.txt`` / ``all_ltd.txt`` 对应行追加 ``-V4`` / ``-V6`` / ``-DS`` 备注
（幂等，与 ``quality_check`` 已有的 ``DS``/``V6`` token 约定一致）。

所有代理使用 TLS（Cloudflare 边缘）方法，逐条做 **双栈出口探测**：
分别请求仅 IPv4（``ipv4.icanhazip.com``，仅 A 记录）与仅 IPv6
（``ipv6.icanhazip.com``，仅 AAAA 记录）的回显服务——走得通即证明代理
具备对应家族的**出口能力**，两者皆通判 ``dual``。回显为纯 IP 文本；
若两者均失败，尝试通用目标 ``cloudflare.com/cdn-cgi/trace`` 兜底。
注意：入口 socket 家族（AF_INET/AF_INET6）无法反映出口家族——它只约束
客户端→代理一跳，代理→目标的家族由代理端解析决定（CF 边缘代理尤其如此，
出口由 Worker fetch() 决定、与入口无关）。

家族判定：仅 v4 → ``ipv4``；仅 v6 → ``ipv6``；双通 → ``dual``；探测全失败 →
``unknown``（不入任何分离清单）。纯标准库，ThreadPoolExecutor 并发。

交叉验证：若 ``data/quality/upstream_meta.json`` 存在（由 ``download_proxies.py`` 从上游
``all.json`` 生成），逐条对照上游记录的真实出口 ``clientIp``，在
``exit_family.json`` 中写入 ``upstream_client_ip`` / ``upstream_family`` /
``upstream_match`` 字段并输出命中统计；文件缺失时静默跳过，不降级实时探测。
"""

import argparse
import ipaddress
import json
import socket
import ssl
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from common import (
    EXIT_FAMILY_FILE,
    UPSTREAM_META_FILE,
    VALID_ALL_FILE,
    VALID_ALL_IPV4_FILE,
    VALID_ALL_IPV6_FILE,
    VALID_ALL_LTD_FILE,
    _SSL_CTX,
    build_request,
    clear_note_buckets,
    has_token,
    keyed_json,
    merge_note_tokens,
    line_to_key,
    load_methods,
    load_sample,
    parse_headers,
    write_json,
    write_text_if_changed,
    _note,
)

DEFAULT_SOURCE = VALID_ALL_FILE

WORKERS_DEFAULT = 16
TIMEOUT_DEFAULT = 10

TRACE_HOST = "cloudflare.com"
TRACE_PATH = "/cdn-cgi/trace"

# 双栈出口探测目标：固定家族的 IP 回显服务（仅 A / 仅 AAAA 记录）。
# 代理能连通对应目标 = 具备该家族的出口能力；两者皆通 → dual。
# 注意：不能靠入口 socket 家族（AF_INET/AF_INET6）判断——那只约束客户端→代理
# 这一跳，代理→目标的出口家族由代理端对同一目标的解析决定，天然单一家族。
EXIT_V4_HOST = "ipv4.icanhazip.com"   # 仅 A 记录
EXIT_V6_HOST = "ipv6.icanhazip.com"   # 仅 AAAA 记录
EXIT_ECHO_PATH = "/"                  # 返回纯 IP 文本（非 CF trace 格式）

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


def read_http_response_sync(sock: socket.socket, cap: int) -> tuple[int | None, dict, bytes]:
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
        try:
            want = min(int(clen), cap) if clen else cap
        except (ValueError, TypeError):
            want = cap
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
        try:
            size = int(head.split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            return body
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


def request_tls_sni(
    ip: str, port: str, host: str, path: str, timeout: float,
    family: int | None = None,
) -> tuple[int | None, dict, bytes]:
    """直连 TLS（``host`` 为 SNI）→ 返回 ``(status, headers, body)``。

    *family* 可指定 ``socket.AF_INET`` / ``socket.AF_INET6`` 强制走对应栈。
    """
    raw = None
    try:
        if family is not None:
            raw = socket.socket(family, socket.SOCK_STREAM)
            raw.settimeout(timeout)
            raw.connect((ip, int(port)))
        else:
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


# ------------------------------------------------------------ 解析与判定

def parse_trace(body: bytes) -> dict:
    """``cdn-cgi/trace`` 响应（``key=value`` 每行）→ dict。"""
    out: dict = {}
    for line in body.decode("utf-8", "replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def shared_exit_counts(results: dict) -> dict[str, int]:
    """统计每个出口 IP 被多少条代理共享（``{出口IP: 条数}``）。

    同一出口被大量入口复用 = 机房农场/同机多端口：对使用者是单点故障
    与连坐风控风险，供 ``shared_exit`` 字段与摘要输出。
    """
    counts: dict[str, int] = {}
    for res in results.values():
        if not isinstance(res, dict):
            continue
        for ip in {res.get("exit_v4"), res.get("exit_v6")} - {None}:
            counts[ip] = counts.get(ip, 0) + 1
    return counts


def classify_family(v4: str | None, v6: str | None) -> str:
    """按回显字面量的实际地址族归类（不信域名，信 IP 本身）。

    防御两类异常：
    - 回显服务未按家族区分 / 代理固定上游 → 两次探测返回**同一地址**，
      此时按该地址的真实家族归单栈，避免假 dual；
    - 某次探测意外返回了另一族的字面量（中间设备劫持等）→ 仍按字面量
      版本号统计，不依赖"哪个域名应该返回什么"的假设。
    """
    if v4 and v6 and v4 == v6:
        return "ipv6" if ":" in v4 else "ipv4"
    has_v4 = (v4 and ":" not in v4) or (v6 and ":" not in v6)
    has_v6 = (v4 and ":" in v4) or (v6 and ":" in v6)
    if has_v4 and has_v6:
        return "dual"
    if has_v6:
        return "ipv6"
    if has_v4:
        return "ipv4"
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


def _extract_exit_ip(body: bytes) -> str | None:
    """从响应体提取出口 IP：CF trace ``ip=`` 优先，纯 IP 文本回退。

    判定加固：候选字面量必须能被 :mod:`ipaddress` 解析为**全局公网**地址
    （``is_global``）——私网（RFC1918）、环回、CGNAT（100.64/10）、基准
    测试段（198.18/15，fake-ip DNS 特征）、链路本地等一律视为探测失败，
    防止透明代理/fake-ip 环境把假地址误标成真实出口家族。
    """
    ip = parse_trace(body).get("ip") or ""
    if not ip:
        text = body.decode("utf-8", "replace").strip()
        if text and "\n" not in text and len(text) <= 45 and ("." in text or ":" in text):
            ip = text
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return ip if addr.is_global else None


def _probe_one(ip: str, port: str, host: str, path: str, timeout: float,
               family: int | None = None) -> str | None:
    """单次探测：返回出口 IP 字符串，失败返回 ``None``。"""
    status, _headers, body = request_tls_sni(ip, port, host, path, timeout, family)
    if status != 200 or not body:
        return None
    return _extract_exit_ip(body)


def check_one(item, methods: dict, timeout: float) -> dict:
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
    # --- 双栈出口探测：分别请求仅 v4 / 仅 v6 目标（入口家族无关） ---
    exit_v4 = _probe_one(ip, port, EXIT_V4_HOST, EXIT_ECHO_PATH, timeout)
    exit_v6 = _probe_one(ip, port, EXIT_V6_HOST, EXIT_ECHO_PATH, timeout)
    # Fallback: if neither specific probe succeeded, try generic
    if not exit_v4 and not exit_v6:
        generic = _probe_one(ip, port, TRACE_HOST, TRACE_PATH, timeout)
        if generic:
            if ":" in generic:
                exit_v6 = generic
            else:
                exit_v4 = generic
    family = classify_family(exit_v4, exit_v6)
    base.update(
        family=family,
        exit_v4=exit_v4,
        exit_v6=exit_v6,
    )
    return key, base


# ------------------------------------------------------------ 备注与分离

def has_family_note(line: str) -> bool:
    return any(has_token(_note(line), t) for t in ("V4", "V6", "DS"))


def annotate_family(line: str, family: str) -> str:
    tok = FAMILY_TOKENS.get(family)
    if not tok:
        return line
    # 家族为互斥桶：权威探测结果直接替换旧值
    return merge_note_tokens(clear_note_buckets(line, "family"), tok)


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

def load_upstream_meta(path: Path | None = None) -> dict:
    """读入上游 ``all.json`` 生成的元数据表（keyed by ip）。缺失/损坏 → ``{}``。

    新版以 ``{"proxies": {ip: meta}}`` 包裹（与其余 keyed JSON 统一），
    旧版裸 dict 兼容读取。
    """
    path = path or UPSTREAM_META_FILE
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    wrapped = data.get("proxies")
    if isinstance(wrapped, dict):
        return wrapped
    return data


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
    write_text_if_changed(path, "\n".join(lines) + ("\n" if lines else ""))


def annotate_source_files(families: dict, source: Path) -> None:
    """给 all.txt / all_ltd.txt 幂等追加家族 token。"""
    targets = [VALID_ALL_FILE, VALID_ALL_LTD_FILE]
    if source != VALID_ALL_FILE and source != VALID_ALL_LTD_FILE:
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
    shared = shared_exit_counts(results)
    for res in results.values():
        mx = max(
            (shared.get(ip, 0) for ip in (res.get("exit_v4"), res.get("exit_v6")) if ip),
            default=1,
        )
        if mx > 1:
            res["shared_exit"] = mx
    # keyed 写入，值只保留探测/交叉验证字段（line/ip/port/cc 均可由 key 推导，不落盘）
    keep = (
        "method", "ts", "family", "exit_v4", "exit_v6", "shared_exit",
        "upstream_client_ip", "upstream_family", "upstream_absent", "upstream_match",
    )
    entries = {
        key: {k: res[k] for k in keep if k in res}
        for key, res in results.items()
    }
    write_json(EXIT_FAMILY_FILE, keyed_json(entries))
    write_lines(VALID_ALL_IPV4_FILE, v4_lines)
    write_lines(VALID_ALL_IPV6_FILE, v6_lines)
    annotate_source_files(families, args.source)

    from collections import Counter

    fam_counts = Counter(families.values())
    print(f"family: {dict(fam_counts)}", file=sys.stderr)
    print(f"all_ipv4.txt: {len(v4_lines)} lines; all_ipv6.txt: {len(v6_lines)} lines",
          file=sys.stderr)
    shared_keys = [k for k, r in results.items() if r.get("shared_exit")]
    top_shared = sorted(shared.items(), key=lambda kv: -kv[1])[:3]
    print(
        f"shared exits: {len(shared_keys)}/{len(results)} entries on reused IPs; "
        f"top: {top_shared}",
        file=sys.stderr,
    )
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
