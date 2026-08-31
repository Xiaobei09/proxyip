#!/usr/bin/env python3
"""Shared path constants, regex patterns, and small helpers used across all
scripts.

Holds the ``data/`` layout constants, the tiny line/HTTP/JSON helpers that
the entry-point scripts used to import from each other (``download_proxies``
for paths, ``quality_check`` for helpers, ``china_check`` for
``request_follow``), the common regex patterns
(``EXIT_REGION_RE``, ``LATENCY_RE``, ``SPEED_RE``), and shared I/O
utilities (``read_json``, ``load_sample``, ``collect_txt_files``,
``annotate_files``).

``common`` imports nothing from the other scripts, so every script can depend
on it without creating import cycles.
"""

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------- data 布局

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
DIFF_DIR = DATA_DIR / "diff"
DOWNLOAD_DIR = DATA_DIR / "download"
COUNTRIES_DIR = DOWNLOAD_DIR / "countries"
PORTS_DIR = DOWNLOAD_DIR / "ports"
SETS_DIR = DOWNLOAD_DIR / "sets"
VALID_DIR = DATA_DIR / "valid"
QUALITY_DIR = DATA_DIR / "quality"
OUTPUT_DIR = DATA_DIR / "output"
OUT_DIR = DOWNLOAD_DIR  # backward compat alias

ALL_FILE = DOWNLOAD_DIR / "all.txt"
ALL_LTD_FILE = DOWNLOAD_DIR / "all_ltd.txt"
UPSTREAM_META_FILE = QUALITY_DIR / "upstream_meta.json"
SOURCE_STATS_FILE = QUALITY_DIR / "source_stats.json"
SOURCE_HISTORY_FILE = QUALITY_DIR / "source_history.json"
SOURCE_HISTORY_MAX = 14   # 保留最近几轮的上游源覆盖快照
IP_SOURCES_FILE = QUALITY_DIR / "ip_sources.json"
HISTORY_FILE = QUALITY_DIR / "history.jsonl"

IPINFO_FILE = QUALITY_DIR / "ipinfo.json"
STREAMING_FILE = QUALITY_DIR / "streaming.json"
ABUSE_FILE = QUALITY_DIR / "abuse.json"
QUALITY_META_FILE = QUALITY_DIR / "quality_meta.json"
REPUTATION_FILE = QUALITY_DIR / "reputation.json"
EXTERNAL_CHECK_FILE = QUALITY_DIR / "external_check.json"
REP_CACHE_FILE = QUALITY_DIR / "reputation_cache.json"
CHINA_FILE = QUALITY_DIR / "china.json"
EXIT_FAMILY_FILE = QUALITY_DIR / "exit_family.json"

VALID_HISTORY_FILE = VALID_DIR / "history.jsonl"
INDEX_FILE = VALID_DIR / "index.json"
SPEED_FILE = VALID_DIR / "speed.json"
REP_RANK_FILE = VALID_DIR / "all_rep.txt"
VALID_ALL_FILE = VALID_DIR / "all.txt"
VALID_ALL_LTD_FILE = VALID_DIR / "all_ltd.txt"
VALID_ALL_CN_FILE = VALID_DIR / "all_cn.txt"
VALID_ALL_CN_HTTP_FILE = VALID_DIR / "all_cn_http.txt"
VALID_ALL_CN_STABLE_FILE = VALID_DIR / "all_cn_stable.txt"
VALID_ALL_IPV4_FILE = VALID_DIR / "all_ipv4.txt"
VALID_ALL_IPV6_FILE = VALID_DIR / "all_ipv6.txt"
VALID_META_FILE = VALID_DIR / "meta.json"

REP_CACHE_TTL = 7 * 24 * 3600
DEFAULT_SOURCE = VALID_DIR / "all.txt"

MAX_HISTORY_RECORDS = 1000
MAX_DIFF_FILES = 50
PER_COUNTRY_LIMIT = 20

EXTERNAL_CHECK_URL = "https://api.090227.xyz/check"
EXT_CHECK_FILE = VALID_DIR / "ext_check.json"

# ---------------------------------------------------------------- 外部 API 多源配置
EXT_API_SOURCES = [
    {
        "name": "090227",
        "url": "https://api.090227.xyz/check",
        "param_key": "proxyip",
        "timeout": 10,
    },
    {
        "name": "cmliu",
        "url": "https://Check.ProxyIP.CMLiussss.net/check",
        "param_key": "proxyip",
        "timeout": 10,
    },
    {
        "name": "toicf",
        "url": "https://pr-apis.ekt.me/probe",
        "param_key": "candidate",
        "timeout": 15,
    },
]

# ---------------------------------------------------------------- ip-api 共享常量
IPAPI_BATCH_URL = "http://ip-api.com/batch"
IPAPI_BATCH_SIZE = 100
IPAPI_BATCH_DELAY = 1.2

# ---------------------------------------------------------------- 共享正则
EXIT_REGION_RE = re.compile(r"^(.*#[^A-Z]*[A-Z]+)")
LATENCY_RE = re.compile(r"-(\d+)ms")
SPEED_RE = re.compile(r"(\d+(?:\.\d+)?)MB/s")

# ---------------------------------------------------------------- SSL 上下文
_SSL_CTX = ssl.create_default_context()

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
)

# ---------------------------------------------------------------- 通用助手


def now_ts() -> str:
    """Return current UTC timestamp in ISO-8601 format (``YYYY-MM-DDTHH:MM:SSZ``)."""
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
    """Extract the ``ip:port#CC`` key from a proxy line, or ``None``."""
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
    """Return ``{key: method}`` mapping from ``index.json`` (e.g. ``"tls"``)."""
    if not INDEX_FILE.exists():
        return {}
    try:
        data = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return {k: v[1] for k, v in data.get("proxies", {}).items()
            if isinstance(v, (list, tuple)) and len(v) > 1}


def build_request(method: str, path: str, host: str) -> bytes:
    """Build a raw HTTP/1.1 request line + headers as bytes."""
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
    """Atomically write ``data`` as compact JSON (skip if content unchanged)."""
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
    """Wrap proxy entries in ``{"proxies": entries}`` format."""
    return {"proxies": entries}


# ------------------------------------------------------- 共享 JSON / 文件读写


def read_json(path: Path) -> dict:
    """Read a JSON file; return ``{}`` on missing / broken / OS errors."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def load_speed_keys(path: Path | None = None) -> set[str]:
    """speed.json 的 key 集合（本轮全链路验证通过的代理）。"""
    proxies = read_json(path or SPEED_FILE).get("proxies", {})
    return (
        {k for k in proxies if isinstance(k, str)}
        if isinstance(proxies, dict)
        else set()
    )


def load_uptime_keys(
    min_pct: int = 80, path: Path | None = None
) -> set[str]:
    """uptime.json 中 7d 存活率 ≥ ``min_pct`` 的 key 集合。"""
    proxies = read_json(path or QUALITY_DIR / "uptime.json").get("proxies", {})
    out: set[str] = set()
    if isinstance(proxies, dict):
        for k, v in proxies.items():
            if (
                isinstance(k, str)
                and isinstance(v, dict)
                and isinstance(v.get("pct7"), int)
                and v["pct7"] >= min_pct
            ):
                out.add(k)
    return out


def load_china_stable_keys(path: Path | None = None) -> set[str]:
    """china.json 中跨轮稳定 key 集合：连续 ≥2 轮 reachable 且翻转 ≤1。

    与 china_check 的 stable 准入保持一致（flip 判定排除慢性抖动源）。
    """
    proxies = read_json(path or CHINA_FILE).get("proxies", {})
    out: set[str] = set()
    if isinstance(proxies, dict):
        for k, v in proxies.items():
            if (
                isinstance(k, str)
                and isinstance(v, dict)
                and v.get("verdict") == "reachable"
                and isinstance(v.get("streak"), int)
                and v["streak"] >= 2
                and isinstance(v.get("flip", 0), int)
                and v.get("flip", 0) <= 1
            ):
                out.add(k)
    return out


def load_sample(source: Path, limit: int) -> list:
    """Return ``[(line, key, ip, port, cc), ...]`` truncated to ``limit``."""
    try:
        lines = [l for l in source.read_text(encoding="utf-8").splitlines() if l.strip()]
    except (OSError, UnicodeDecodeError):
        return []
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


def collect_txt_files(valid_dir: Path) -> list[Path]:
    """Collect all proxy txt files to annotate (shared layout)."""
    files: list[Path] = []
    for name in ("all.txt", "all_ltd.txt"):
        p = valid_dir / name
        if p.exists():
            files.append(p)
    for sub in ("countries", "sets"):
        d = valid_dir / sub
        if d.is_dir():
            files.extend(sorted(d.glob("*/all.txt")))
            files.extend(sorted(d.glob("*/ltd.txt")))
    ports_dir = valid_dir / "ports"
    if ports_dir.is_dir():
        files.extend(sorted(ports_dir.glob("*.txt")))
    return files


def annotate_files(
    files: list[Path],
    china_sets: tuple[set[str], set[str]],
    family_map: dict[str, str],
    rep_map: dict[str, int],
    ip_type_map: dict[str, str],
    exit_map: dict[str, str] | None = None,
    uptime_map: dict[str, int] | None = None,
) -> int:
    """Annotate all files with suffixes + classification, return lines changed.

    ``china_sets`` 为 ``(cn_set, cnh_set)``，见 annotate_classify._build_china_sets。

    Imports ``fill_and_classify`` lazily from ``annotate_classify`` to avoid
    import cycles when this module is loaded at startup.
    """
    from annotate_classify import fill_and_classify

    total_changed = 0
    # 同一线会出现在 root/countries/sets/ports/ltd 多个视图，缓存去重
    cache: dict[str, str] = {}
    for path in files:
        text = path.read_text(encoding="utf-8")
        out_lines = []
        changed = 0
        for line in text.splitlines():
            if not line:
                continue
            if line not in cache:
                cache[line] = fill_and_classify(
                    line, china_sets, family_map, rep_map,
                    ip_type_map, exit_map, uptime_map,
                )
            new_line = cache[line]
            if new_line != line:
                changed += 1
            out_lines.append(new_line)
        if changed:
            write_text_if_changed(path, "\n".join(out_lines) + "\n")
            total_changed += changed
            print(f"  {path.name}: {changed} lines updated")
    return total_changed


# ------------------------------------------------------- 共享注解 / 分类函数


def insert_exit_region(line: str, exit_region: str) -> str:
    """Insert ``→<exit>`` right after the entry country code (idempotent)."""
    if not exit_region or "→" in line:
        return line
    m = EXIT_REGION_RE.match(line)
    if not m:
        return line
    return line[: m.end(1)] + "→" + exit_region + line[m.end(1) :]


def upsert_exit_region(line: str, exit_region: str) -> str:
    """Insert **or replace** the ``→<exit>`` marker (stale exits get updated)."""
    if not exit_region:
        return line
    if "→" not in line:
        return insert_exit_region(line, exit_region)
    m = EXIT_REGION_RE.match(line)
    if not m:
        return line
    head = line[: m.end(1)]
    rest = line[m.end(1) :]
    arrow_end = rest.find("-")
    if arrow_end < 0:
        arrow_seg, tail = rest, ""
    else:
        arrow_seg, tail = rest[:arrow_end], rest[arrow_end:]
    return f"{head}→{exit_region}{tail}"


# ------------------------------------------------------- 出口国多源汇聚
# →CC 标记的数据源优先级（高→低）。所有需要出口国的工作流必须经由此构建器，
# 禁止各自只读单一 JSON（历史上 reorg/annotate 只认 ipinfo.country_match，
# 覆盖率不足 1%）。


def build_exit_ip_map(
    external_check: dict | None = None,
    family_data: dict | None = None,
) -> dict[str, str]:
    """``{行键: 出口 IP}``，与 quality_check.resolve_exit_ips 同优先级：

    外部探测回显（``external_check.exit_geo.ip``）> exit_family 实测
    （``exit_v4``/``exit_v6``）。两者皆无则不含该键。
    """
    result: dict[str, str] = {}
    for key, info in (external_check or {}).get("proxies", {}).items():
        ip = (info.get("exit_geo") if isinstance(info, dict) else None) or {}
        ip = ip.get("ip") if isinstance(ip, dict) else None
        if isinstance(ip, str) and ip:
            result[key] = ip
    for key, info in (family_data or {}).get("proxies", {}).items():
        if key in result or not isinstance(info, dict):
            continue
        ip = info.get("exit_v4") or info.get("exit_v6")
        if isinstance(ip, str) and ip:
            result[key] = ip
    return result


def _norm_cc(v) -> str:
    """2 位字母国家码规范化；非法输入返回空串。"""
    return v.upper() if isinstance(v, str) and len(v) == 2 and v.isalpha() else ""


def build_exit_cc_map(
    ipinfo: dict | None = None,
    external_check: dict | None = None,
    upstream_meta: dict | None = None,
    family_data: dict | None = None,
) -> dict[str, str]:
    """汇聚多源出口国观测为 ``{key: exit_cc}``，高优先级者胜。

    1. ``external_check.json`` —— 外部探测接口直接回显的出口地理
       （``probe_results.ipv4.exit.country/countryCode``）
    2. ``upstream_meta.json`` —— 自有 CF Worker 观测到的代理出口国。
       键为裸出口 IP 时经 ``build_exit_ip_map`` 解析到行键；
       若直接为行键则原样使用（兼容）
    3. ``ipinfo.json`` —— ``country_code``（ip-api 地理）。历史轮次可能是
       入口 IP 的地理，故仅作末位兜底
    （流媒体解锁国作为第 3 源已随解锁检查一并移除。）
    """
    result: dict[str, str] = {}

    def put(key: str, cc) -> None:
        cc = _norm_cc(cc)
        if cc and key not in result:
            result[key] = cc

    for key, info in (external_check or {}).get("proxies", {}).items():
        geo = info.get("exit_geo") if isinstance(info, dict) else None
        if isinstance(geo, dict):
            put(key, geo.get("country") or geo.get("countryCode"))

    # upstream_meta：{出口IP或行键: country}
    upstream_cc: dict[str, str] = {}
    for key, info in (upstream_meta or {}).get("proxies", {}).items():
        cc = info.get("country") if isinstance(info, dict) else None
        cc = _norm_cc(cc)
        if cc:
            upstream_cc[key] = cc
    if upstream_cc:
        for key, cc in upstream_cc.items():
            put(key, cc)  # 行键直命中（兼容）
        exit_ips = build_exit_ip_map(external_check, family_data)
        for key, ip in exit_ips.items():
            put(key, upstream_cc.get(ip))

    for key, info in (ipinfo or {}).get("proxies", {}).items():
        put(key, info.get("country_code") if isinstance(info, dict) else None)
    return result


def classify_ip(geo: dict) -> str:
    """Return ``DC``/``MOB``/``PROXY``/``RES`` from ip-api geo dict."""
    if geo.get("hosting"):
        return "DC"
    if geo.get("mobile"):
        return "MOB"
    if geo.get("proxy"):
        return "PROXY"
    return "RES"


# ------------------------------------------------------- 重定向跟随请求

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


RAW_GITHUB_PREFIX = "https://raw.githubusercontent.com/"


def mirror_urls(url: str) -> list[str]:
    """Candidate mainland-reachable mirrors for a raw.githubusercontent.com URL.

    raw.githubusercontent.com is blocked from mainland China, so local runs
    there cannot fetch sources without a proxy.  Returns equivalent mirror
    URLs (gh-proxy.com prefix proxy, jsDelivr CDN, gitmirror) in try order;
    non-GitHub-raw URLs have no mirrors and yield ``[]``.
    """
    if not url.startswith(RAW_GITHUB_PREFIX):
        return []
    path = url[len(RAW_GITHUB_PREFIX):]
    parts = path.split("/", 3)
    out = ["https://gh-proxy.com/" + url]
    if len(parts) == 4:
        user, repo, branch, rest = parts
        out.append(f"https://cdn.jsdelivr.net/gh/{user}/{repo}@{branch}/{rest}")
    out.append("https://raw.gitmirror.com/" + path)
    return out


def fetch_with_mirror(
    url: str,
    timeout: float,
    headers: dict | None = None,
) -> bytes:
    """Fetch bytes trying ``url`` first, then its mirrors; last error re-raised.

    Mirrors only exist for raw.githubusercontent.com URLs, so elsewhere this
    is a plain single-attempt fetch with identical error behaviour.
    """
    candidates = [url] + mirror_urls(url)
    last_exc: Exception = RuntimeError(f"no fetch candidates for {url}")
    for candidate in candidates:
        req = urllib.request.Request(
            candidate, headers=headers or {"User-Agent": UA}
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
    raise last_exc


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
    cc = "ALL" if rest[i:].startswith("ALL") and (rest[i + 3:i + 4] in ("", "-")) else rest[i : i + 2]
    return rest[i + len(cc):]


def has_token(note: str, token: str) -> bool:
    """备注段是否含独立 ``token``（以段首或 ``-`` 为界，如 ``-CF``/``-CN``/``-V4``）。"""
    return bool(re.search(rf"(?:^|-){re.escape(token)}(?:$|-)", note))


def note_tier(line: str) -> str | None:
    """行的速度档 token（``fast``/``mid``/``slow``），无档位返回 ``None``。

    不同国家/机房的实测速度天然分层（同一"good"里美西与欧东可差一个
    数量级），供 build_good 产 ``good_<tier>`` 变体与 ``tiers/`` 目录。
    """
    b = _parse_note_segs(_note(line))
    return b.get("tier") if isinstance(b, dict) else None


def rewrite_latency(line: str, ms: float | int | None) -> str:
    """将行内延迟 token 替换为 ``ms``（四舍五入取整）；无 token 或 ms 缺失原样返回。

    用途：CN 系列清单把海外 TLS 延迟替换为大陆实测 RTT——同一行内
    ``ms`` 的语义随清单而定（CN 清单=大陆视角，其他=海外视角），
    避免大陆使用者把海外延迟误当自己的连接体验。
    """
    if not ms or not isinstance(ms, (int, float)) or ms <= 0:
        return line
    new = f"-{int(round(ms))}ms"
    out, n = LATENCY_RE.subn(new, line, count=1)
    return out if n else line


# ------------------------------------------------------- CN 视角速度估算
# CN 清单的 ``MB/s`` 必须语义一致=大陆视角。免费大陆拨测（itdog/ping.pe/
# tcpping.cn/check-host）只给 TCP 建连延迟、不提供吞吐量，故无法实测大陆
# 速度——任何数值都必然是估算。为避免把海外 runner 实测速度冒充大陆体验
# （两者路径不同，数值无代表性），CN 清单改用显式标记 ``≈XMB/s`` 的估算
# 上限：以大陆 RTT 为参照推算单流 TCP 吞吐参考值，再与海外实测速度取小
# （不号称超过节点真实出口带宽），其余情形删除速度 token 而非保留误导值。

CN_SPEED_REF_MS = 60.0   # 参考 RTT（毫秒），对应 CN_SPEED_BASE_CAP
CN_SPEED_BASE_CAP = 8.0  # cn_ms≈60ms 时的估算上限（MB/s）
CN_SPEED_FLOOR = 0.4     # 估算下限（MB/s），防极端高延迟给出夸张小值

# CN 清单延迟门槛（单一事实来源，china_check 与 build_good 共用）：
# 可达 ≠ 大陆——大陆节点实测 jkapi/xxapi 扫描的可达池中位 ~218ms，大头是
# 海外/边缘机房（大陆节点能 TCP 连通而已）。CN 清单 ``ms`` 语义 = 大陆使用者
# 实测延迟，故 CN 清单每行只应展示大陆视角读数。注意：此门槛与 cn_mainland
# 打标只是"信息性/可选"——CN 清单保持完整（全可达集≥1万），不加 gating 精简。
# 默认 150 仅用于打标参考（纯度档 100≈319、150≈808 供人了解规模），不砍清单。
CN_LATENCY_CAP_MS = 150.0

# 可作大陆延迟证据的探测源：xxapi（北京）/ jkapi（宁波）/ check_host（呼市）
# 三处大陆视角。L3 复核源（tcptest/antping/pingpe/tcpingcn/chinaz/coffee）的
# ms 语义不一、常回 1ms 噪声，只适合佐证可达，不够格当大陆延迟证据。
_CHINA_VANTAGE_SOURCES = ("xxapi", "jkapi", "check_host")

# chinaz 为 **纯 ICMP ping**（proxyip 不可达的"到 IP 边缘路由"延迟，常说 1~8ms，
# 与真实代理/隧道延迟无关，反直觉地极小）。绝不用它冒充大陆延迟；回退时剔除。
_CN_ICMP_ONLY_SOURCES = ("chinaz",)


def cn_l2_ms(entry) -> float | None:
    """大陆视角探测的最小 ok RTT（xxapi/jkapi/check_host）。

    取三者中状态 ok 且 ms>0 的最小值；无 sources 的旧条目回退 entry["ms"]；
    全无读数返回 None（无法证明大陆性）。"""
    if not isinstance(entry, dict):
        return None
    sources = entry.get("sources")
    if not isinstance(sources, dict):
        ms = entry.get("ms")
        return ms if isinstance(ms, (int, float)) and ms > 0 else None
    best = None
    for src in _CHINA_VANTAGE_SOURCES:
        r = sources.get(src)
        if isinstance(r, dict) and r.get("status") == "ok":
            m = r.get("ms")
            if isinstance(m, (int, float)) and m > 0:
                best = m if best is None else min(best, m)
    return best


def _cn_fallback_ms(entry, sources: dict) -> float | None:
    """无大陆 L2 读数时的回退延迟：在**非 ICMP** 的 ok 源中取最小可信 RTT。

    排除 chinaz 等纯 ICMP 源——其 1~8ms 只是到国内 IP 边缘的 ping 假象，
    远低于真实代理/隧道延迟，用它会产出 ``US-2ms`` 之类失真行。仅传输层以外
    的 TCP/TLS 源（tcptest/coffee/tcpingcn 等）才是真实代理延迟的上界证据。
    """
    best = None
    for name, r in sources.items():
        if name in _CN_ICMP_ONLY_SOURCES:
            continue
        if (isinstance(r, dict) and r.get("status") == "ok"
                and isinstance(r.get("ms"), (int, float))
                and r["ms"] >= 2.0):
            best = r["ms"] if best is None else min(best, r["ms"])
    return best


def cn_display_ms(entry) -> float | None:
    """CN 清单展示用大陆延迟：优先可信大陆探测（cn_l2_ms），无读数时在
    **非 ICMP** ok 源中取最小可信 RTT（过滤 1~8ms ICMP 噪声），再回退 entry
    合并 ms。避免 1ms/2ms 冒充真实延迟；真伪都查不到返回 None。"""
    if not isinstance(entry, dict):
        return None
    ms = cn_l2_ms(entry)
    if ms is not None and ms >= 2.0:
        return ms
    best = None
    sources = entry.get("sources")
    if isinstance(sources, dict):
        best = _cn_fallback_ms(entry, sources)
    if best is not None:
        return best
    m = entry.get("ms")
    # 回退 entry 合并 ms 时同样拒绝 ≤2ms（strict > 2.0）：该值可能是被
    # ICMP/噪声源污染的合并结果（唯一 ok 是 chinaz 2ms 时 entry.ms 也被
    # 算成 2），宁缺勿假——真实大陆代理延迟不可能低到 2ms。
    return m if isinstance(m, (int, float)) and m > 2.0 else None


def cn_mainland_ok(ms, cap: float | None = None) -> bool:
    """大陆视角 RTT 是否落在大陆簇（≤ cap）。无数值/非正按非大陆。"""
    if cap is None or cap == float("inf"):
        cap = CN_LATENCY_CAP_MS
    return bool(
        isinstance(ms, (int, float))
        and ms > 0
        and ms <= cap
    )


def entry_cn_mainland(entry, cap: float | None = None) -> bool:
    """条目级大陆性判定：取可信大陆探测 ms 再套门槛。"""
    return cn_mainland_ok(cn_l2_ms(entry), cap)

_CN_SPEED_RAW_RE = re.compile(r"-(\d+(?:\.\d+)?)MB/s")


def _rewrite_cn_speed(line: str, cn_ms: dict | None) -> str:
    """CN 视图专用：把海外实测速度替换为大陆视角估算上限 ``≈XMB/s``。

    - 无海外速度 → 删除该 token（无数据来源，宁缺勿假）
    - 无大陆 RTT → 速度语义不明，删除（不再展示海外值）
    - 有两者 → ``min(海外实测, 以 cn_ms 推算的单流参考上限)``，标记 ``≈``
    """
    if "#" not in line:
        return line
    m = _CN_SPEED_RAW_RE.search(line)
    if not m:
        return line
    mbps = float(m.group(1))
    key = line_to_key(line)
    cn_rtt = (
        cn_ms.get(key)
        if isinstance(cn_ms, dict) and isinstance(cn_ms.get(key), (int, float))
        else None
    )
    if not cn_rtt or cn_rtt <= 0:
        return _CN_SPEED_RAW_RE.sub("", line, count=1)
    cap = max(CN_SPEED_FLOOR, CN_SPEED_BASE_CAP * (CN_SPEED_REF_MS / cn_rtt))
    est = round(min(mbps, cap), 1)
    return _CN_SPEED_RAW_RE.sub(f"-≈{est}MB/s", line, count=1)


# ------------------------------------------------------- 备注段规范（唯一出口）
# 所有工作流追加/清理备注必须经由 normalize_note，禁止各自 ``line += "-TOK"``
# 拼接——否则多 CI 并发写同一文件时段序漂移、旧 token 无限堆叠
# （历史上出现过 "...-GPT-CF-77-mid-GPT-CF-70-DC-fast-GPT-CF-62" 四层快照）。

_NOTE_STREAMING_RE = re.compile(r"^(?:D\+|YT|MX|PV|GPT|NF\([^)]*\))$")
_NOTE_TYPE_TOKENS = {"DC", "RES", "MOB", "PROXY"}
_NOTE_TIER_TOKENS = {"fast", "mid", "slow"}
_NOTE_FAMILY_TOKENS = {"V4", "V6", "DS"}
_NOTE_SCORE_RE = re.compile(r"^\d{1,3}$")
_NOTE_UPTIME_RE = re.compile(r"^U\d{1,3}$")
_NOTE_LAT_RE = re.compile(r"^\d+ms$")
_NOTE_SPEED_RE = re.compile(r"^\d+(?:\.\d+)?MB/s$")


def normalize_note(line: str) -> str:
    """解析备注段并按规范顺序重建（幂等，全仓库唯一的后缀处理器）。

    规范顺序：`入口CC[→出口CC] - 延迟 - 速度 - 流媒体(并集去重) - 类型 -
    - 速度档 - 家族 - CN/CNH - 信誉分 - 未知段(保序垫底)`。
    单值桶（类型/档位/家族/分数）取最右（最新）；流媒体桶取并集；CNH 蕴含 CN。
    未识别的行原样返回。
    """
    return _rebuild_note(line)


def _is_known_note_token(s: str) -> bool:
    """是否任一受管 token（用于空格复合段的拆分判定）。"""
    return bool(
        _NOTE_LAT_RE.match(s) or _NOTE_SPEED_RE.match(s)
        or _NOTE_STREAMING_RE.match(s) or s in _NOTE_TYPE_TOKENS
        or s in _NOTE_TIER_TOKENS or s in _NOTE_FAMILY_TOKENS
        or s in ("CN", "CNH") or _NOTE_SCORE_RE.match(s)
        or _NOTE_UPTIME_RE.match(s)
    )


def _flatten_segs(segs: list[str]) -> list[str]:
    """拆开旧版空格分隔的流媒体复合段（如 ``D+ MX GPT``）。

    仅当段内所有空白分隔的子 token 均为受管 token 时才展开，
    否则原样保留（避免误碎未知段）。
    """
    flat: list[str] = []
    for s in segs:
        if (" " in s) and all(_is_known_note_token(p) for p in s.split()):
            flat.extend(p for p in s.split() if p)
        else:
            flat.append(s)
    return flat


def _parse_note_segs(note: str) -> dict | None:
    segs = [s for s in note.split("-") if s]
    if not segs:
        return None
    lead = segs[0]
    segs = _flatten_segs(segs[1:])
    b: dict = {
        "lead": lead, "lat": None, "spd": None, "stream": [], "typ": None,
        "tier": None, "fam": None, "cn": False, "cnh": False,
        "score": None, "uptime": None, "other": [],
    }
    for s in segs:
        if _NOTE_LAT_RE.match(s):
            b["lat"] = s
        elif _NOTE_SPEED_RE.match(s):
            b["spd"] = s
        elif _NOTE_STREAMING_RE.match(s):
            if s not in b["stream"]:
                b["stream"].append(s)
        elif s in _NOTE_TYPE_TOKENS:
            b["typ"] = s
        elif s in _NOTE_TIER_TOKENS:
            b["tier"] = s
        elif s in _NOTE_FAMILY_TOKENS:
            b["fam"] = s
        elif s == "CN":
            b["cn"] = True
        elif s == "CNH":
            b["cnh"] = True
        elif _NOTE_SCORE_RE.match(s):
            b["score"] = s
        elif _NOTE_UPTIME_RE.match(s):
            b["uptime"] = s
        else:
            if s == "CF":
                continue  # 已废弃的死标记：池子全为 CF 边缘端口，恒真无信息量，归一化时丢弃
            b["other"].append(s)
    return b


def _render_note(head: str, b: dict) -> str:
    parts = [p for p in (
        b["lead"], b["lat"], b["spd"], *b["stream"],
        b["typ"], b["tier"], b["fam"],
        "CN" if (b["cn"] or b["cnh"]) else None,
        "CNH" if b["cnh"] else None, b["score"], b["uptime"],
    ) if p]
    parts.extend(b["other"])
    return f"{head}#{'-'.join(parts)}"


_NOTE_BUCKET_KEYS = ("type", "tier", "family", "score", "streaming", "cn", "uptime")
_BUCKET_TO_KEY = {
    "type": "typ", "tier": "tier", "family": "fam", "score": "score",
    "streaming": "stream",
}


def _rebuild_note(line: str, clear: tuple = ()) -> str:
    if "#" not in line:
        return line
    head, note = line.split("#", 1)
    b = _parse_note_segs(note)
    if b is None:
        return line
    # 既无延迟也无任何受管 token → 非验证池行（如裸 `#US`），不动
    if b["lat"] is None and not any(
        (b["spd"], b["stream"], b["typ"], b["tier"], b["fam"],
         b["cn"], b["cnh"], b["score"], b["uptime"])
    ):
        return line
    for bucket in clear:
        key = _BUCKET_TO_KEY.get(bucket, bucket)
        if key == "stream":
            b["stream"] = []
        elif key in ("cn",):
            b["cn"] = b["cnh"] = False
        elif isinstance(b.get(key), bool):
            b[key] = False
        elif key in b:
            b[key] = None
    return _render_note(head, b)


def clear_note_buckets(line: str, *buckets: str) -> str:
    """删除给定互斥桶（type/tier/family/score/streaming/cn）的既有 token。

    权威数据源写入前先清桶再追加（merge_note_tokens），避免新旧值并存。
    """
    return _rebuild_note(line, clear=tuple(buckets))


def merge_note_tokens(line: str, *tokens: str) -> str:
    """先规范再幂等追加 token —— 各工作流追加备注的唯一入口。"""
    out = normalize_note(line)
    for tok in tokens:
        if not tok:
            continue
        note = out.split("#", 1)[-1]
        if not has_token(note, tok):
            out += "-" + tok
    return normalize_note(out)



