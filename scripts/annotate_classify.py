#!/usr/bin/env python3
"""Fill missing suffixes and add node classification tokens to proxy lines.

Reads JSON data files (ipinfo.json, reputation.json, china.json,
exit_family.json) from ``data/quality/`` and annotates all
``data/valid/*.txt`` files with missing exit-country markers (→CC) and suffixes
(CN, V4/V6, reputation) and classification tokens (IP type,
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
    build_exit_cc_map,
    clear_note_buckets,
    has_token,
    upsert_exit_region,
    merge_note_tokens,
    normalize_note,
    parse_line,
    read_json,
    collect_txt_files,
    annotate_files,
    write_text_if_changed,
)


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


def _build_china_sets(data: dict) -> tuple[set[str], set[str]]:
    """``china.json`` → ``(cn_set, cnh_set)``。

    - ``cn_set``：verdict == ``reachable``（-CN 归属，此集合内的行得 -CN）
    - ``cnh_set``：level == ``http``（应用层确认，-CNH，不论 verdict）
    """
    cn_set: set[str] = set()
    cnh_set: set[str] = set()
    for key, entry in data.get("proxies", {}).items():
        if not isinstance(entry, dict):
            continue
        if entry.get("verdict") == "reachable":
            cn_set.add(key)
        if entry.get("level") == "http":
            cnh_set.add(key)
    return cn_set, cnh_set


def _build_family_map(data: dict) -> dict[str, str]:
    """``exit_family.json`` → ``{key: family}``."""
    return {
        k: v.get("family", "")
        for k, v in data.get("proxies", {}).items()
        if v.get("family")
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
    family_data: dict | None = None,
) -> dict[str, str]:
    """多源出口国汇聚（见 common.build_exit_cc_map 的优先级文档）。"""
    return build_exit_cc_map(ipinfo, external_check, upstream_meta, family_data)


def fill_and_classify(
    line: str,
    china_sets: tuple[set[str], set[str]],
    family_map: dict[str, str],
    rep_map: dict[str, int],
    ip_type_map: dict[str, str],
    exit_map: dict[str, str] | None = None,
    uptime_map: dict[str, int] | None = None,
) -> str:
    """Fill missing suffixes and append classification tokens.

    ``china_sets`` = ``(cn_set, cnh_set)``：-CN 严格只给当期 verdict 为
    reachable 的 key；其余一律撤销（含历史累积的失效 -CN）；-CNH 按应用层
    HTTP 确认集保留。其余 token 的 ``has_token`` 检查使用 ``out``（演进的
    行）而非原始 ``note``，避免同调用内重复追加。
    """
    parsed = parse_line(line)
    if not parsed:
        return line

    key, _ip, _port, _cc, _note = parsed
    # 先经全仓库唯一规范器清洗历史堆叠段，再判重追加
    out = normalize_note(line)

    # --- suffix filling ---

    # exit country marker (→CC) — upsert：观测变化时刷新陈旧出口国
    if exit_map:
        exit_cc = exit_map.get(key)
        if exit_cc:
            out = upsert_exit_region(out, exit_cc)

    # CN token（互斥桶：以当期可达判定为准，先清后设）。
    # 历史实现只增不减——可达集随轮变动却从不移除失效的 -CN，
    # 导致 all.txt 累积上万条过期标志（当前仅 112/13817 真可达）。
    # 这里严格交战：不在当期 reachable 即撤销 -CN（及蕴含其上的 -CNH）；
    # 应用层 HTTP 确认（-CNH）单独按 cnh_set 保留，不受 verdict 牵连。
    cn_set, cnh_set = china_sets
    out = clear_note_buckets(out, "cn")
    if key in cn_set:
        out = merge_note_tokens(out, "CN")
    if key in cnh_set:
        out = merge_note_tokens(out, "CNH")

    # V4 / V6 / DS（互斥桶：先清后设，权威源替换旧值）
    family = family_map.get(key, "")
    if family:
        fam_token = {"ipv4": "V4", "ipv6": "V6", "dual": "DS"}.get(family, "")
        if fam_token and not any(has_token(out, t) for t in FAMILY_TOKENS):
            out += "-" + fam_token
        elif fam_token:
            out = merge_note_tokens(clear_note_buckets(out, "family"), fam_token)

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

    # uptime%（7d 存活率，取整；无观测则不加）。互斥桶：同一行只保留
    # 最新一次探测的 U<NN>，旧值随 normalize_note 自动淘汰。
    if uptime_map:
        pct = uptime_map.get(key)
        if pct is not None:
            out = merge_note_tokens(out, f"U{pct}")

    return out


def reconcile_ports(valid_dir: Path) -> int:
    """把 ``ports/*.txt`` 行集约束到 ``all.txt`` 全量存活集之内。

    历史轮次可能遗留已在 ``all.txt`` 离场的节点（非 CF 端口/下架代理）写进
    端口分桶；每轮按 ``all.txt``（权威全集）剔除，保证下游按端口取用不会
    拿到大师清单之外的陈旧行。返回剔除行数。
    """
    all_txt = valid_dir / "all.txt"
    if not all_txt.exists():
        return 0
    all_keys = {
        line.split("#", 1)[0]
        for line in all_txt.read_text(encoding="utf-8").splitlines()
        if line
    }
    if not all_keys:
        return 0
    removed = 0
    for port_txt in sorted((valid_dir / "ports").glob("*.txt")):
        lines = port_txt.read_text(encoding="utf-8").splitlines()
        kept = [
            line for line in lines
            if not line or line.split("#", 1)[0] in all_keys
        ]
        if len(kept) != len(lines):
            removed += len(lines) - len(kept)
            text = "\n".join(kept) + ("\n" if kept else "")
            write_text_if_changed(port_txt, text)
    return removed


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
    external_check = read_json(quality_dir / "external_check.json")
    upstream_meta = read_json(quality_dir / "upstream_meta.json")
    uptime_data = read_json(quality_dir / "uptime.json")

    # build maps
    cn_set, cnh_set = _build_china_sets(china_data)
    family_map = _build_family_map(family_data)
    rep_map = _build_rep_map(rep_data)
    ip_type_map = _build_ip_type_map(ipinfo)
    uptime_map = {
        k: v["pct7"]
        for k, v in (uptime_data.get("proxies") or {}).items()
        if isinstance(v, dict) and v.get("pct7") is not None
    }
    exit_map = _build_exit_map(
        ipinfo, external_check, upstream_meta, family_data
    )

    print(
        f"Maps: cn={len(cn_set)} cnh={len(cnh_set)} family={len(family_map)} "
        f"rep={len(rep_map)} "
        f"ip_type={len(ip_type_map)} exit={len(exit_map)} "
        f"uptime={len(uptime_map)}"
    )

    # collect and annotate
    files = collect_txt_files(valid_dir)
    if not files:
        print("No txt files found")
        return 0

    total = annotate_files(
        files, (cn_set, cnh_set), family_map, rep_map, ip_type_map,
        exit_map, uptime_map,
    )
    stale = reconcile_ports(valid_dir)
    print(f"Done: {len(files)} files, {total} lines updated, {stale} stale port lines removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
