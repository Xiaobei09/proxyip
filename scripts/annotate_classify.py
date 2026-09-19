#!/usr/bin/env python3
"""Fill missing suffixes and add node classification tokens to proxy lines.

Reads JSON data files (ipinfo.json, reputation.json, china.json,
exit_family.json, external_check.json, upstream_meta.json, uptime.json)
from ``data/quality/`` and annotates all
``data/valid/*.txt`` files with missing exit-country markers (→CC) and suffixes
(CN, V4/V6, reputation) and classification tokens (IP type,
speed tier).

Output line format:
  ip:port#<flag><CC>[→<exit>]-<latency>ms[-<speed>MB/s][-<note>]-<type>-<tier>

where ``<type>`` is ``DC``/``RES``/``MOB``/``PROXY`` and ``<tier>`` is
``fast``/``mid``/``slow``.
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
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
    parse_ltd_line,
    read_json,
    collect_txt_files,
    annotate_files,
    write_text_if_changed,
)


IP_TYPES = frozenset({"DC", "RES", "MOB", "PROXY"})
FAMILY_MAP = {"ipv4": "V4", "ipv6": "V6", "dual": "DS"}


def speed_tier(note: str) -> str:
    """Parse speed from note, return ``fast``/``mid``/``slow``/``unknown``.

    ``≈XMB/s``（大陆估算 token，CN 视图）不算实测速度——拒绝给出档位，
    否则估算会被当成实测档位消费（与 R50/R65/R67 的 ≈ 拒绝防护同族；
    当前生产输入为 all.txt（无 ≈），此处系防御性收紧共享 SPEED_RE）。
    """
    m = SPEED_RE.search(note)
    if not m:
        return "unknown"
    if m.start() > 0 and note[m.start() - 1] == "≈":
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
    """``exit_family.json`` → ``{key: family}``（垃圾条目跳过）。"""
    return {
        k: v.get("family", "")
        for k, v in data.get("proxies", {}).items()
        if isinstance(v, dict) and v.get("family")
    }


def _build_ip_type_map(data: dict) -> dict[str, str]:
    """``ipinfo.json`` → ``{key: ip_type}``（垃圾条目跳过）。"""
    return {
        k: v.get("ip_type", "")
        for k, v in data.get("proxies", {}).items()
        if isinstance(v, dict) and v.get("ip_type")
    }


def _build_rep_map(data: dict) -> dict[str, int]:
    """``reputation.json`` → ``{key: score}``（无分/垃圾条目跳过，
    与 build_good.build_rep_map 同口径，防脏缓存击垮注解链）。"""
    return {
        k: v.get("score", 0)
        for k, v in data.get("proxies", {}).items()
        if isinstance(v, dict) and v.get("score") is not None
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
    HTTP 确认集保留、**粘性**（反映最近一次确认，非逐轮新鲜；`common` 渲染
    CNH 恒蕴含 CN，故弱确认键在池行中仍带 -CN-CNH 但不会进入 all_cn 清单）。
    其余 token 的 ``has_token`` 检查使用 ``out``（演进的
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

    # V4 / V6 / DS（互斥桶：先清后设，权威源替换旧值）。
    # 权威源对某 key 显式记为 unknown（探测全失败）时清桶——宁可未知
    # 也不冒称单栈/双栈，防止旧轮 token 残留误导下游切换。整体无 family
    # 数据（family_map 缺该 key）时保持既有 token 不动（无侵入语义）。
    fav = family_map.get(key)
    if fav:
        fam_token = FAMILY_MAP.get(fav, "")
        if fam_token:
            out = merge_note_tokens(clear_note_buckets(out, "family"), fam_token)
        else:
            out = clear_note_buckets(out, "family")

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


def _key_of(text: str) -> set[str]:
    return {line.split("#", 1)[0] for line in text.splitlines() if line}


def _key_of_non_all(text: str) -> set[str]:
    """``all.txt`` 中入口国**已归属**（非 ``#ALL`` 哨兵）行的 ``ip:port`` 键集。

    ``data-spec`` 规定 ``#ALL``（入口未知）只出现在 ``all.txt``/``all_ltd.txt``、
    不进入 ``countries/``（``validate_proxies`` 按此跳过）；分国家键集 1:1 校验
    必须剔除它，否则会把合法哨兵误报为 ``missing`` 漂移（R218 ``normalize_country``
    产出 ``#ALL`` 后于 CI 暴露 ``countries sum 18410 != all.txt 18411``）。
    """
    keys: set[str] = set()
    for line in text.splitlines():
        if not line:
            continue
        parsed = parse_ltd_line(line)
        if parsed and parsed[3] == "ALL":
            continue
        keys.add(line.split("#", 1)[0])
    return keys


def verify_country_split(valid_dir: Path) -> dict:
    """R208 漂移防护：``countries/*/all.txt`` 行键集必须与 ``all.txt`` 大师清单中
    **入口国可归属的行**（已剔除 ``#ALL`` 哨兵）**恰好 1:1**（reconcile_views 只向下
    裁剪、不补缺行；若上游工作流在注解步之后又改了 ``all.txt`` 行集，分目录会带出
    超集/缺集，跨工作流数据流断裂就在此处）。

    返回 ``{"master", "countries", "missing", "excess", "dup_endpoints", "phantom"}``；
    ``missing`` = 大师有而分目录缺（新键待 validate 重切分），``excess`` =
    分目录有而大师无（死代残留漏裁）。两者任非空即跨工作流漂移。
    ``dup_endpoints`` = 同一 ``ip:port`` 出现在 ≥2 个国家目录（入口国标注矛盾，
    如同端点被标注 ``#SG`` 与 ``#CO``）：属数据质量告警，不影响键集 1:1。
    ``phantom`` = 同键在分目录的行数**多于**大师（``master`` 行数 >0 时的重复行）：
    ``reconcile_views`` 只按 ``ip:port`` 键裁剪，同键幻影重复行永远剪不掉，
    是行级永久漂移源（``excess`` 覆盖不到，因该键本身在大师中存在）。
    """
    all_txt = valid_dir / "all.txt"
    if not all_txt.exists():
        return {"master": 0, "countries": 0, "missing": [], "excess": [],
                "dup_endpoints": 0, "phantom": 0}
    all_text = all_txt.read_text(encoding="utf-8")
    master = _key_of_non_all(all_text)
    master_counts: Counter[str] = Counter()
    for line in all_text.splitlines():
        if line and line.split("#", 1)[0] in master:
            master_counts[line.split("#", 1)[0]] += 1
    cdir = valid_dir / "countries"
    seen: set[str] = set()
    country_counts: Counter[str] = Counter()
    endpoint_cc: dict[str, set[str]] = defaultdict(set)
    if cdir.is_dir():
        for d in sorted(cdir.glob("*")):
            if d.is_dir() and (d / "all.txt").exists():
                text = (d / "all.txt").read_text(encoding="utf-8")
                seen |= _key_of(text)
                cc = d.name
                for line in text.splitlines():
                    if line:
                        key = line.split("#", 1)[0]
                        country_counts[key] += 1
                        endpoint_cc[key].add(cc)
    dup_endpoints = sum(
        1 for eps in endpoint_cc.values() if len(eps) > 1
    )
    phantom = sorted(
        key for key, n in country_counts.items()
        if n > master_counts.get(key, 0) > 0
    )
    return {
        "master": len(master),
        "countries": len(seen),
        "missing": sorted(master - seen)[:5],
        "excess": sorted(seen - master)[:5],
        "dup_endpoints": dup_endpoints,
        "phantom": len(phantom),
    }


def reconcile_views(valid_dir: Path, backfill: bool = True) -> int:
    """把全部数据视图约束到 ``all.txt`` 权威活池之内。

    历史轮次会向 ports/countries/sets 的 ``all``/``ltd`` 视图泄漏已离开
    ``all.txt`` 的节点（死代/非 CF 端口）；每轮按 ``all.txt``（大师清单）
    剔除越界行。注意只对 master 修剪：entry/exit 归类迁移会让 ``ltd``
    与所在目录 ``all`` 的归属口径不同，那些键仍是活节点，不可因归属
    分歧删除。返回剔除行数。

    缺失方向回填（R313）：master 新增行若缺失于所属国家分裂则按 master
    字节原样补入（延迟升序）。背景是多写者快照 race 的结构性解——
    reachability/quality 重写 master 不写分裂、只有 validate 全量重建；
    reconcile 此前只修剪不回填，缺失累积成门禁死锁（R289）。键已存在
    （注释漂移）不重复；``#ALL`` 与不可解析行跳过；sets/（精选子集，
    归属需定义表判定）与 ports/（未观测漂移，最小 blast radius）不在
    此列，下次 validate 自然重写。

    ``backfill=False`` 时跳过国家分裂回填（CN-32）：download 树是扁平
    ``<CC>.txt`` 布局，``download_proxies.reconcile_download_tree`` 若把
    本函数用于 download 树，回填会写出 valid 式 ``<CC>/all.txt`` 目录、
    进而炸掉下轮 ``write_outputs`` 残留清理（``stale.unlink()`` 遇目录抛
    IsADirectoryError，2026-09-19 更新链连续失败实证）。download 树每轮
    全量重写，只需修剪。
    """
    all_txt = valid_dir / "all.txt"
    if not all_txt.exists():
        return 0
    master = _key_of(all_txt.read_text(encoding="utf-8"))
    if not master:
        return 0
    removed = 0

    def prune(path: Path) -> None:
        nonlocal removed
        if not path.exists():
            return
        lines = path.read_text(encoding="utf-8").splitlines()
        kept = [
            line for line in lines
            if line and line.split("#", 1)[0] in master
        ]
        if len(kept) != len(lines):
            removed += len(lines) - len(kept)
            if not kept:
                # 越界行全数剔除 → 清空不落盘（避免 0 字节残留）
                if path.exists():
                    path.unlink()
            else:
                write_text_if_changed(path, "\n".join(kept) + "\n")

    def _lat(line: str) -> float:
        m = re.search(r"-(\d+(?:\.\d+)?)ms", line)
        return float(m.group(1)) if m else float("inf")

    def backfill_countries() -> int:
        """master 行补入缺失的国家分裂；返回补入行数。"""
        want: dict[str, dict[str, str]] = {}
        for line in all_txt.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            parsed = parse_ltd_line(line)
            if not parsed or parsed[3] == "ALL":
                continue
            want.setdefault(parsed[3], {})[line.split("#", 1)[0]] = line
        added = 0
        cdir = valid_dir / "countries"
        for cc in sorted(want):
            path = cdir / cc / "all.txt"
            have = (
                path.read_text(encoding="utf-8").splitlines()
                if path.exists() else []
            )
            have_keys = {ln.split("#", 1)[0] for ln in have if ln}
            missing = [ln for k, ln in want[cc].items() if k not in have_keys]
            if not missing:
                continue
            merged = sorted(have + missing, key=_lat)
            path.parent.mkdir(parents=True, exist_ok=True)
            write_text_if_changed(path, "\n".join(merged) + "\n")
            added += len(missing)
        if added:
            print(f"reconcile: backfilled {added} lines into countries splits")
        return added

    for port_txt in sorted((valid_dir / "ports").glob("*.txt")):
        prune(port_txt)

    for sub in ("countries", "sets"):
        for path in sorted((valid_dir / sub).glob("*/*.txt")):
            prune(path)

    for name in ("all_ltd.txt", "all_verified.txt", "all_stable.txt"):
        prune(valid_dir / name)
    for path in sorted(valid_dir.glob("all_*.txt")):
        if path.name != "all.txt":
            prune(path)
    if backfill:
        backfill_countries()
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
    stale = reconcile_views(valid_dir)
    print(f"Done: {len(files)} files, {total} lines updated, {stale} stale view lines removed")
    split = verify_country_split(valid_dir)
    if split["missing"] or split["excess"]:
        print(
            f"ERROR: countries split drifted from all.txt "
            f"(master={split['master']} countries={split['countries']} "
            f"missing={split['missing'][:3]} excess={split['excess'][:3]})"
            " — 阻断提交，待 validate 重切分自愈",
            file=sys.stderr,
        )
        return 1
    if split["dup_endpoints"]:
        print(
            f"WARN: {split['dup_endpoints']} ip:port 出现在多个国家目录"
            "（入口国标注矛盾，如 #SG 与 #CO），不阻断但请留意",
            file=sys.stderr,
        )
    if split["phantom"]:
        print(
            f"WARN: {split['phantom']} 个 ip:port 在分目录行数多于 all.txt"
            "（同键幻影重复行，reconcile_views 按键裁剪剪不掉），不阻断但请留意",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
