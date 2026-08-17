#!/usr/bin/env python3
"""Shared path constants and small helpers used across all scripts.

Holds the ``data/`` layout constants and the tiny line/HTTP/JSON helpers that
the entry-point scripts used to import from each other (``download_proxies``
for paths, ``quality_check`` for helpers, ``china_check`` for
``request_follow``/``is_cf_heuristic``).
``common`` imports nothing from the other scripts, so every script can depend
on it without creating import cycles.
"""

import asyncio
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------- data 布局

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw"
COUNTRIES_DIR = ROOT / "data" / "countries"
PORTS_DIR = ROOT / "data" / "ports"
SETS_DIR = ROOT / "data" / "sets"
OUT_DIR = ROOT / "data"
VALID_DIR = OUT_DIR / "valid"
DIFF_DIR = OUT_DIR / "diff"

HISTORY_FILE = ROOT / "data" / "history.jsonl"
VALID_HISTORY_FILE = VALID_DIR / "history.jsonl"
INDEX_FILE = VALID_DIR / "index.json"
SPEED_FILE = VALID_DIR / "speed.json"
IPINFO_FILE = VALID_DIR / "ipinfo.json"
STREAMING_FILE = VALID_DIR / "streaming.json"
ABUSE_FILE = VALID_DIR / "abuse.json"
QUALITY_META_FILE = VALID_DIR / "quality_meta.json"
REPUTATION_FILE = VALID_DIR / "reputation.json"
REP_RANK_FILE = VALID_DIR / "all_rep.txt"
REP_CACHE_FILE = VALID_DIR / "reputation_cache.json"
REP_CACHE_TTL = 7 * 24 * 3600
DEFAULT_SOURCE = VALID_DIR / "all_ltd.txt"

MAX_HISTORY_RECORDS = 1000
MAX_DIFF_FILES = 50
PER_COUNTRY_LIMIT = 20

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
)

# ---------------------------------------------------------------- 通用助手


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ltd_line(line: str) -> tuple[str, str, str, str] | None:
    """``ip:port#<flag><cc>-...`` -> ``(key, ip, port, cc)`` or ``None``.

    The pseudo-country ``ALL`` (unknown entry country, 3 letters) is kept
    intact instead of collapsing to ``AL`` so it never collides with Albania.
    """
    line = line.strip()
    if not line or "#" not in line:
        return None
    addr, rest = line.rsplit("#", 1)
    i = 0
    while i < len(rest) and not ("A" <= rest[i] <= "Z"):
        i += 1
    if rest[i:].startswith("ALL") and (rest[i + 3:i + 4] in ("", "-")):
        cc = "ALL"
    else:
        cc = rest[i : i + 2]
    if (len(cc) != 2 and cc != "ALL") or not cc.isalpha() or ":" not in addr:
        return None
    ip, port = addr.rsplit(":", 1)
    if not port.isdigit():
        return None
    return f"{addr}#{cc}", ip, port, cc


def line_to_key(line: str) -> str | None:
    parsed = parse_ltd_line(line)
    return parsed[0] if parsed else None


def parse_line(line: str) -> tuple[str, str, str, str, str] | None:
    """``ip:port#<cc>-<note>`` -> ``(key, ip, port, cc, note)`` or ``None``.

    统一解析入口：地址、国家码与备注段一次取齐；``key`` 由
    ``parse_ltd_line`` 生成（``ip:port#<cc>``），``note`` 为 ``#`` 后、
    国家码之后的备注段（不含 CC）。
    """
    parsed = parse_ltd_line(line)
    if not parsed:
        return None
    key, ip, port, cc = parsed
    return key, ip, port, cc, _note(line)


def load_methods() -> dict:
    """``entry`` -> ``"tls"`` from ``index.json``."""
    if not INDEX_FILE.exists():
        return {}
    try:
        data = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return {k: v[1] for k, v in data.get("proxies", {}).items()}


def build_request(method: str, path: str, host: str) -> bytes:
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {UA}",
        "Accept: */*",
        "Accept-Language: en-US,en;q=0.9",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii", errors="replace")


def parse_headers(raw: bytes) -> tuple[int | None, dict]:
    """``(status_code, headers)`` from a raw HTTP header block."""
    lines = raw.split(b"\r\n")
    match = re.match(rb"HTTP/\d\.\d\s+(\d{3})", lines[0]) if lines else None
    status = int(match.group(1)) if match else None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.decode("latin-1").strip().lower()] = value.decode(
            "latin-1"
        ).strip()
    return status, headers


def write_json(path: Path, data: dict) -> None:
    content = json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_text_if_changed(path: Path, content: str) -> bool:
    """原子写 ``content``；与现文件字节相同时跳过。返回是否真正写入。

    稳定数据不产生无意义重写（git 按内容去重，这里主要省 IO 并让本地
    工作区与 CI 提交步的 diff 只反映真实变化）。
    """
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
    return True


def keyed_json(entries: dict) -> dict:
    return {"proxies": entries}


# ------------------------------------------------------- 重定向跟随请求

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_follow(
    url: str,
    headers: dict,
    timeout: float = 10,
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


def has_token(note: str, token: str) -> bool:
    """备注段是否含独立 ``token``（以段首或 ``-`` 为界，如 ``-CF``/``-CN``/``-V4``）。"""
    return bool(re.search(rf"(?:^|-){re.escape(token)}(?:$|-)", note))


def is_cf_heuristic(line: str) -> bool:
    """行备注已带 ``-CF``（Cloudflare 边缘）即判定大陆可达（零网络）。"""
    return has_token(_note(line), "CF")



