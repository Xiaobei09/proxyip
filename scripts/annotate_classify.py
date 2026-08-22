#!/usr/bin/env python3
"""Fill missing suffixes and add node classification tokens to proxy lines.

Reads JSON data files (ipinfo.json, reputation.json, china.json,
exit_family.json, streaming.json) from ``data/quality/`` and annotates all
``data/valid/*.txt`` files with missing exit-country markers (→CC) and suffixes
(CN, V4/V6, streaming, reputation) and classification tokens (IP type,
speed tier).

Output line format:
  ip:port#<flag><CC>[→<exit>]-<latency>ms[-<speed>MB/s][-<note>]-<type>-<tier>

where ``<type>`` is ``DC``/``RES``/``MOB``/``PROXY`` and ``<tier>`` is
``fast``/``mid``/``slow``.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    SPEED_RE,
    DATA_DIR,
    clear_note_buckets,
    has_token,
    insert_exit_region,
    merge_note_tokens,
    normalize_note,
    parse_line,
    read_json,
    collect_txt_files,
    annotate_files,
)
from quality_streaming import streaming_tokens


IP_TYPES = frozenset({"DC", "RES", "MOB", "PROXY"})
FAMILY_TOKENS = frozenset({"V4", "V6", "DS"})


def speed_tier(note: str) -> str:
    """Parse speed from note, return ``fast``/``mid``/``slow``/``unknown``."""
    m = SPEED_RE.search(note)
    if not m:
        return "unknown"
    mbps = float(m.group(1))
    if mbps >= 5:
        return "fast"
    if mbps >= 1:
        return "mid"
    return "slow"


def _build_china_set(data: dict) -> set[str]:
    """``china.json`` → set of keys with ``verdict == "reachable"``."""
    result = set()
    for key, entry in data.get("proxies", {}).items():
        if entry.get("verdict") == "reachable":
            result.add(key)
    return result


def _build_family_map(data: dict) -> dict[str, str]:
    """``exit_family.json`` → ``{key: family}``."""
    return {
        k: v.get("family", "")
        for k, v in data.get("proxies", {}).items()
        if v.get("family")
    }


def _build_streaming_map(data: dict) -> dict[str, dict]:
    """``streaming.json`` → ``{key: streaming_dict}``."""
    return {
        k: v
        for k, v in data.get("proxies", {}).items()
        if v
    }


def _build_ip_type_map(data: dict) -> dict[str, str]:
    """``ipinfo.json`` → ``{key: ip_type}``."""
    return {
        k: v.get("ip_type", "")
        for k, v in data.get("proxies", {}).items()
        if v.get("ip_type")
    }


def _build_rep_map(data: dict) -> dict[str, int]:
    """``reputation.json`` → ``{key: score}``."""
    return {
        k: v.get("score", 0)
        for k, v in data.get("proxies", {}).items()
        if v.get("score") is not None
    }


def _build_exit_map(
    ipinfo: dict,
    external_check: dict | None = None,
    upstream_meta: dict | None = None,
) -> dict[str, str]:
    """多源汇聚 ``{key: exit_cc}``（出口国家观测，优先级从高到低）：

    1. ``external_check.json`` —— 外部探测接口直接返回的出口地理
       （``probe_results.ipv4.exit.country``）；
    2. ``ipinfo.json`` —— 出口 IP 的 ip-api 地理（``country_code``）；
    3. ``upstream_meta.json`` —— 我们自己的 CF Worker 观测到的代理出口
       （``clientIp`` 所在国家，覆盖面最大，1.5w+ 键）。
    """
    result: dict[str, str] = {}

    def _cc_of(v) -> str:
        if not isinstance(v, dict):
            return ""
        cc = v.get("country") or ""
        if isinstance(cc, dict):
            cc = cc.get("code") or ""
        return cc.upper() if isinstance(cc, str) and len(cc) == 2 and cc.isalpha() else ""

    for key, info in external_check.get("proxies", {}).items() if external_check else []:
        cc = _cc_of((info or {}).get("exit_geo"))
        if cc:
            result[key] = cc
    for key, info in (ipinfo.get("proxies", {}) or {}).items():
        if not isinstance(info, dict):
            continue
        cc = info.get("country_code") or ""
        if isinstance(cc, str) and len(cc) == 2 and cc.isalpha() and key not in result:
            result[key] = cc.upper()
    for key, info in upstream_meta.get("proxies", {}).items() if upstream_meta else []:
        cc = _cc_of(info)
        if cc:
            result.setdefault(key, cc)
    return result


def fill_and_classify(
    line: str,
    china_set: set[str],
    family_map: dict[str, str],
    streaming_map: dict[str, dict],
    rep_map: dict[str, int],
    ip_type_map: dict[str, str],
    exit_map: dict[str, str] | None = None,
) -> str:
    """Fill missing suffixes and append classification tokens.

    All ``has_token`` checks use ``out`` (the evolving line) rather than the
    original ``note``, so tokens appended during the same call are detected
    and duplicates are prevented.
    """
    parsed = parse_line(line)
    if not parsed:
        return line

    key, _ip, _port, _cc, _note = parsed
    # 先经全仓库唯一规范器清洗历史堆叠段，再判重追加
    out = normalize_note(line)

    # --- suffix filling ---

    # exit country marker (→CC) — inserted right after entry CC, idempotent
    if exit_map:
        exit_cc = exit_map.get(key)
        if exit_cc:
            out = insert_exit_region(out, exit_cc)

    # CN token
    if key in china_set and not has_token(out, "CN"):
        out += "-CN"

    # V4 / V6 / DS（互斥桶：先清后设，权威源替换旧值）
    family = family_map.get(key, "")
    if family:
        fam_token = {"ipv4": "V4", "ipv6": "V6", "dual": "DS"}.get(family, "")
        if fam_token and not any(has_token(out, t) for t in FAMILY_TOKENS):
            out += "-" + fam_token
        elif fam_token:
            out = merge_note_tokens(clear_note_buckets(out, "family"), fam_token)

    # streaming tokens
    st = streaming_map.get(key)
    if st:
        stoks = streaming_tokens(st)
        if stoks:
            for tok in stoks.split():
                if not has_token(out, tok):
                    out += "-" + tok

    # reputation score (only if not already present)
    rep_score = rep_map.get(key)
    if rep_score is not None:
        score_str = str(rep_score)
        if not has_token(out.split("#", 1)[-1], score_str):
            out = merge_note_tokens(clear_note_buckets(out, "score"), score_str)

    # --- classification tokens ---

    # IP type（互斥桶：先清后设）
    ip_type = ip_type_map.get(key, "")
    if ip_type and ip_type in IP_TYPES:
        out = merge_note_tokens(clear_note_buckets(out, "type"), ip_type)

    # speed tier（由延迟/速度重算，互斥桶先清后设）
    tier = speed_tier(out)
    if tier != "unknown":
        out = merge_note_tokens(clear_note_buckets(out, "tier"), tier)

    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--data-dir",
        type=Path,
        default=DATA_DIR,
        help="data/ root (default: repo-root/data)",
    )
    args = ap.parse_args(argv)
    valid_dir = args.data_dir / "valid"
    quality_dir = args.data_dir / "quality"

    # load data
    ipinfo = read_json(quality_dir / "ipinfo.json")
    rep_data = read_json(quality_dir / "reputation.json")
    china_data = read_json(quality_dir / "china.json")
    family_data = read_json(quality_dir / "exit_family.json")
    streaming_data = read_json(quality_dir / "streaming.json")
    external_check = read_json(quality_dir / "external_check.json")
    upstream_meta = read_json(quality_dir / "upstream_meta.json")

    # build maps
    china_set = _build_china_set(china_data)
    family_map = _build_family_map(family_data)
    streaming_map = _build_streaming_map(streaming_data)
    rep_map = _build_rep_map(rep_data)
    ip_type_map = _build_ip_type_map(ipinfo)
    exit_map = _build_exit_map(ipinfo, external_check, upstream_meta)

    print(
        f"Maps: cn={len(china_set)} family={len(family_map)} "
        f"streaming={len(streaming_map)} rep={len(rep_map)} "
        f"ip_type={len(ip_type_map)} exit={len(exit_map)}"
    )

    # collect and annotate
    files = collect_txt_files(valid_dir)
    if not files:
        print("No txt files found")
        return 0

    total = annotate_files(
        files, china_set, family_map, streaming_map, rep_map, ip_type_map,
        exit_map,
    )
    print(f"Done: {len(files)} files, {total} lines updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
