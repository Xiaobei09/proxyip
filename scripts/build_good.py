#!/usr/bin/env python3
"""Build comprehensive-best (综合最优) ``good.txt`` lists from quality data.

Filters the annotated valid pools to proxies that simultaneously satisfy:

1. CN-reachable      — ``china.json`` verdict == ``reachable``, or the line
   already carries a historical ``-CN`` annotation (same rule as
   ``all_cn.txt``)
2. reputation >= 80  — present in ``reputation.json`` with a score of at
   least 80
3. not high risk     — ``reputation.json`` risk != ``high``

Survivors are ranked by a composite, reputation-weighted score::

    score = round(0.6 * rep + 0.2 * latency_score + 0.2 * speed_score)

where ``latency_score`` maps <=100ms to 100 and >=1500ms to 0 linearly
(missing latency counts 0), and ``speed_score = min(MB/s / 5, 1) * 100``
(missing speed counts 0). Ties break by latency asc then key asc.

Latency prefers the mainland-measured value from ``china.json`` (``ms``,
what a mainland user actually experiences); the overseas TLS latency from
the line notes is only the fallback when no CN measurement exists.

Outputs keep the annotated source lines verbatim:

- ``data/valid/all_good.txt``            (global policy group)
- ``data/valid/countries/<CC>/good.txt`` (per-country groups)
- ``data/valid/sets/<name>/good.txt``    (country-set groups)
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    CHINA_FILE,
    DATA_DIR,
    EXIT_FAMILY_FILE,
    LATENCY_RE,
    REPUTATION_FILE,
    SPEED_RE,
    
    line_to_key,
    load_china_stable_keys,
    load_speed_keys,
    load_uptime_keys,
    note_tier,
    parse_line,
    read_json,
    write_text_if_changed,
)

LATENCY_BEST_MS = 100
LATENCY_WORST_MS = 1500
SPEED_FULL_MBPS = 5.0

MIN_REP_SCORE = 80

WEIGHT_REP = 0.6
WEIGHT_LATENCY = 0.2
WEIGHT_SPEED = 0.2


def parse_metrics(line: str) -> tuple[int | None, float | None]:
    """Extract ``(latency_ms, speed_mbps)`` from an annotated line."""
    lat_match = LATENCY_RE.search(line)
    speed_match = SPEED_RE.search(line)
    ms = int(lat_match.group(1)) if lat_match else None
    mbps = float(speed_match.group(1)) if speed_match else None
    return ms, mbps


def latency_score(ms: int | None) -> float:
    """Linear map: <=100ms -> 100, >=1500ms -> 0; missing -> 0."""
    if ms is None:
        return 0.0
    if ms <= LATENCY_BEST_MS:
        return 100.0
    if ms >= LATENCY_WORST_MS:
        return 0.0
    span = LATENCY_WORST_MS - LATENCY_BEST_MS
    return (LATENCY_WORST_MS - ms) / span * 100.0


def speed_score(mbps: float | None) -> float:
    """``min(mbps / 5, 1) * 100``; missing -> 0."""
    if mbps is None:
        return 0.0
    return min(mbps / SPEED_FULL_MBPS, 1.0) * 100.0


def composite_score(rep: int, ms: int | None, mbps: float | None) -> int:
    """Reputation-weighted composite score (0-100)."""
    return round(
        WEIGHT_REP * rep
        + WEIGHT_LATENCY * latency_score(ms)
        + WEIGHT_SPEED * speed_score(mbps)
    )


def build_rep_map(data: dict) -> dict[str, dict]:
    """``reputation.json`` -> ``{key: {"score": int, "risk": str}}``."""
    result: dict[str, dict] = {}
    for key, entry in data.get("proxies", {}).items():
        if not isinstance(entry, dict):
            continue
        score = entry.get("score")
        if score is None:
            continue
        result[key] = {"score": int(score), "risk": entry.get("risk", "")}
    return result


def build_china_set(data: dict) -> set[str]:
    """``china.json`` -> set of keys with ``verdict == "reachable"``."""
    result: set[str] = set()
    for key, entry in data.get("proxies", {}).items():
        if isinstance(entry, dict) and entry.get("verdict") == "reachable":
            result.add(key)
    return result


def build_cn_ms_map(data: dict) -> dict[str, float]:
    """``china.json`` -> ``{key: mainland-measured ms}`` (numeric only)."""
    result: dict[str, float] = {}
    for key, entry in data.get("proxies", {}).items():
        if isinstance(entry, dict) and isinstance(entry.get("ms"), (int, float)):
            result[key] = entry["ms"]
    return result


def is_cn_reachable(key: str | None, line: str, china_set: set[str]) -> bool:
    """CN-reachable per repo convention: judged ``reachable`` this run only.

    不在当期 `china.json` 可达集内的行即使历史带 ``-CN`` 也不收——
    与 all_cn.txt 同策略（过期 -CN 不再兜底），消除失效标志残留。
    参数 ``line`` 保留以兼容调用方签名。
    """
    return key in china_set


def filter_rank(
    text: str,
    china_set: set[str],
    rep_map: dict[str, dict],
    cn_ms: dict[str, float] | None = None,
) -> list[str]:
    """Filter pool lines by entry criteria and rank by composite score.

    Lines failing the criteria are dropped; survivors keep their annotated
    form verbatim, ordered by ``(score desc, latency asc, key asc)``.
    Latency uses the mainland-measured ``cn_ms`` value when available and
    falls back to the overseas TLS latency parsed from the line.
    """
    ranked: list[tuple[int, int, str, str]] = []
    for line in text.splitlines():
        if not line:
            continue
        key = line_to_key(line)
        if not key or not is_cn_reachable(key, line, china_set):
            continue
        rep = rep_map.get(key)
        if not rep or rep["risk"] == "high" or rep["score"] < MIN_REP_SCORE:
            continue
        overseas_ms, mbps = parse_metrics(line)
        ms = (
            round(cn_ms[key])
            if cn_ms and key in cn_ms
            else overseas_ms
        )
        score = composite_score(rep["score"], ms, mbps)
        ranked.append((score, ms if ms is not None else LATENCY_WORST_MS, key, line))
    ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
    return [line for _s, _ms, _k, line in ranked]


TIER_TOKENS = ("fast", "mid", "slow")


def _line_mbps(line: str) -> float:
    m = SPEED_RE.search(line)
    return float(m.group(1)) if m else -1.0


def top_slice(lines: list[str], frac: float = 0.25,
              min_samples: int = 8) -> tuple[list[str], float | None]:
    """按**组内**实测速度取前 ``frac`` 分位的行，返回 ``(行列表, 阈值MB/s)``。

    动机：不同国家/机房供给差距巨大，全局档位（≥5MB/s=fast）会让弱供给
    国家全军覆没——某国最快的线也可能被标 slow。``good_top.txt`` 保证每个
    组都暴露自己的最快一档（相对最优），与绝对档位互补。
    有效速度样本少于 ``min_samples`` 时视为无统计意义，返回空。
    """
    vals = sorted(v for v in map(_line_mbps, lines) if v >= 0)
    if len(vals) < min_samples:
        return [], None
    thr = vals[max(0, int(len(vals) * (1 - frac)) - 1)]
    picked = [ln for ln in lines if _line_mbps(ln) >= thr]
    return picked, thr


def write_good_file(path: Path, lines: list[str]) -> int:
    content = "\n".join(lines) + "\n" if lines else ""
    write_text_if_changed(path, content)
    return len(lines)


def exit_identity(
    key: str, family_proxies: dict
) -> str:
    """出口身份：实测出口 IP 优先（exit_v4/exit_v6），否则入口 /24。

    CF 中转代理的入口恒为 CF 边缘——同农场节点往往共享 /24，用入口
    网段兜底分组仍能聚合同源节点；有实测出口时按出口精确去重。
    """
    fam = family_proxies.get(key, {}) or {}
    ident = fam.get("exit_v4") or fam.get("exit_v6")
    if isinstance(ident, str) and ident:
        return f"exit/{ident}"
    ip = key.split("#", 1)[0].rsplit(":", 1)[0]
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"ip24/{'.'.join(parts[:3])}.0/24"
    return f"ip/{ip}"


def build_diverse_lines(
    pool_text: str, family_proxies: dict, rep_map: dict
) -> list[str]:
    """每出口身份只保留综合分最高的一条，返回按分数降序的行列表。

    避免整池被同一农场/同一出口连坐（shared_exit 聚簇）：消费方拿到
    ``all_diverse.txt`` 即得到出口层面互不重复的最大覆盖组合。
    """
    groups: dict[str, list[tuple[int, str]]] = {}
    for ln in pool_text.splitlines():
        parsed = parse_line(ln)
        if not parsed:
            continue
        key = parsed[0]
        rep = rep_map.get(key, {})
        ms, mbps = parse_metrics(ln)
        score = composite_score(int(rep.get("score") or 0), ms, mbps)
        ident = exit_identity(key, family_proxies)
        groups.setdefault(ident, []).append((score, ln))
    ranked: list[tuple[int, str]] = []
    for cands in groups.values():
        best = max(cands, key=lambda t: (t[0], t[1]))
        ranked.append(best)
    ranked.sort(key=lambda t: -t[0])
    return [ln for _s, ln in ranked]


def write_good_files(
    valid_dir: Path,
    china_set: set[str],
    rep_map: dict[str, dict],
    cn_ms: dict[str, float] | None = None,
) -> dict[str, int]:
    """Write all_good.txt + per-country/set good.txt; return per-file counts.

    每份 good 清单同步产出：

    - ``_verified``（speed.json 全链路验证）与 ``_stable``（china.json
      streak≥2 且 flip≤1 跨轮稳定）可靠性变体；
    - ``good_<tier>.txt`` 速度档变体（fast/mid/slow，来自行备注档位 token）
      ——不同国家实测速度天然分层，档位文件让消费者按带宽需求直达；
    - 同内容镜像进细分目录 ``data/valid/tiers/<tier>/``：
      全局组写 ``all.txt``，国家组写 ``<CC>.txt``，集合组写
      ``sets/<name>.txt``——目录导航式消费入口（空档位整目录跳过）。
    """
    stats: dict[str, int] = {}
    speed_keys = load_speed_keys()
    stable_keys = load_china_stable_keys()
    uptime_keys = load_uptime_keys()
    tier_lines: dict[str, list[tuple[str, Path]]] = {t: [] for t in TIER_TOKENS}

    def emit(base: Path, lines: list[str], tier_name: str | None = None) -> int:
        n = write_good_file(base, lines)
        for suffix, keys in (
            ("_verified", speed_keys),
            ("_stable", stable_keys),
            ("_uptime", uptime_keys),
        ):
            vpath = base.with_name(f"{base.stem}{suffix}.txt")
            vlines = [ln for ln in lines if (k := line_to_key(ln)) and k in keys]
            if vlines:
                write_text_if_changed(vpath, "\n".join(vlines) + "\n")
            elif vpath.exists():
                vpath.unlink()
        # 组内相对最优：good_top.txt（前 25% 分位，按组内实测速度）
        tlines, thr = top_slice(lines)
        tpath = base.with_name(f"{base.stem}_top.txt")
        if tlines:
            write_text_if_changed(tpath, "\n".join(tlines) + "\n")
        elif tpath.exists():
            tpath.unlink()
        if tier_name is not None and tlines:
            stats[f"top:{tier_name}"] = len(tlines)
        # 速度档变体：<base_stem>_<tier>.txt（与所在目录同级的扁平入口）
        for tier in TIER_TOKENS:
            tlines = [ln for ln in lines if note_tier(ln) == tier]
            tpath = base.with_name(f"{base.stem}_{tier}.txt")
            if tlines:
                write_text_if_changed(tpath, "\n".join(tlines) + "\n")
            elif tpath.exists():
                tpath.unlink()
            if tier_name is not None:
                tier_lines[tier].append(("\n".join(tlines) + "\n" if tlines else "",
                                         tier_name))
        return n

    all_pool = valid_dir / "all.txt"
    if all_pool.exists():
        stats["all_good"] = emit(
            valid_dir / "all_good.txt",
            filter_rank(
                all_pool.read_text(encoding="utf-8"), china_set, rep_map, cn_ms
            ),
            tier_name="all",
        )

    for sub in ("countries", "sets"):
        root = valid_dir / sub
        if not root.is_dir():
            continue
        for group_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            pool = group_dir / "all.txt"
            if not pool.exists():
                continue
            name = f"{sub}/{group_dir.name}"
            rel = (f"sets/{group_dir.name}" if sub == "sets"
                   else f"{group_dir.name}")
            stats[name] = emit(
                group_dir / "good.txt",
                filter_rank(
                    pool.read_text(encoding="utf-8"), china_set, rep_map, cn_ms
                ),
                tier_name=rel,
            )

    # 细分目录：tiers/<tier>/{all.txt,<CC>.txt,sets/<name>.txt}
    # 先清理陈旧产物（组消失/档位清空后残留），再写当前代内容

    tiers_root = valid_dir / "tiers"
    for tier, parts in tier_lines.items():
        content_by_rel = {rel: body for body, rel in parts if body}
        tdir = tiers_root / tier
        if tdir.is_dir():
            keep = {f"{rel}.txt" for rel in content_by_rel}
            for old in tdir.rglob("*.txt"):
                if old.relative_to(tdir).as_posix() not in keep:
                    old.unlink()
            for dead in sorted(tdir.rglob("*"), reverse=True):
                if dead.is_dir() and not any(dead.iterdir()):
                    dead.rmdir()
            if not any(tdir.iterdir()):
                tdir.rmdir()
        if not content_by_rel:
            continue
        total = sum(body.count("\n") for body in content_by_rel.values())
        stats[f"tiers/{tier}"] = total
        for rel, body in content_by_rel.items():
            write_text_if_changed(tiers_root / tier / f"{rel}.txt", body)
    return stats


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

    china_set = build_china_set(read_json(quality_dir / CHINA_FILE.name))
    cn_ms = build_cn_ms_map(read_json(quality_dir / CHINA_FILE.name))
    rep_map = build_rep_map(read_json(quality_dir / REPUTATION_FILE.name))
    print(f"Maps: cn={len(china_set)} cn_ms={len(cn_ms)} rep={len(rep_map)}")

    stats = write_good_files(valid_dir, china_set, rep_map, cn_ms)

    # 出口多样性视图：每出口身份一条，按综合分降序
    all_pool = valid_dir / "all.txt"
    if all_pool.exists():
        family_proxies = read_json(
            quality_dir / EXIT_FAMILY_FILE.name
        ).get("proxies", {})
        diverse = build_diverse_lines(
            all_pool.read_text(encoding="utf-8"), family_proxies, rep_map
        )
        stats["all_diverse"] = write_good_file(valid_dir / "all_diverse.txt", diverse)
    total = sum(stats.values())
    for name in sorted(stats):
        print(f"  {name}.txt: {stats[name]}")
    print(f"Done: {len(stats)} files, {total} proxies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
