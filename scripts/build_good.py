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
    LATENCY_RE,
    REPUTATION_FILE,
    SPEED_FILE,
    SPEED_RE,
    has_token,
    line_to_key,
    load_china_stable_keys,
    load_speed_keys,
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
    """CN-reachable per repo convention: judged ``reachable`` this run, or
    carrying a historical ``-CN`` annotation (same rule as ``all_cn.txt``).
    """
    return key in china_set or has_token(line, "CN")


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


def write_good_file(path: Path, lines: list[str]) -> int:
    content = "\n".join(lines) + "\n" if lines else ""
    write_text_if_changed(path, content)
    return len(lines)


def write_good_files(
    valid_dir: Path,
    china_set: set[str],
    rep_map: dict[str, dict],
    cn_ms: dict[str, float] | None = None,
) -> dict[str, int]:
    """Write all_good.txt + per-country/set good.txt; return per-file counts.

    每份 good 清单同步产出 ``_verified``（speed.json 全链路验证）与
    ``_stable``（china.json streak≥2 跨轮稳定）可靠性变体。
    """
    stats: dict[str, int] = {}
    speed_keys = load_speed_keys()
    stable_keys = load_china_stable_keys()

    def emit(base: Path, lines: list[str]) -> int:
        n = write_good_file(base, lines)
        for suffix, keys in (("_verified", speed_keys), ("_stable", stable_keys)):
            vpath = base.with_name(f"{base.stem}{suffix}.txt")
            vlines = [ln for ln in lines if (k := line_to_key(ln)) and k in keys]
            if vlines:
                write_text_if_changed(vpath, "\n".join(vlines) + "\n")
            elif vpath.exists():
                vpath.unlink()
        return n

    all_pool = valid_dir / "all.txt"
    if all_pool.exists():
        stats["all_good"] = emit(
            valid_dir / "all_good.txt",
            filter_rank(
                all_pool.read_text(encoding="utf-8"), china_set, rep_map, cn_ms
            ),
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
            stats[name] = emit(
                group_dir / "good.txt",
                filter_rank(
                    pool.read_text(encoding="utf-8"), china_set, rep_map, cn_ms
                ),
            )
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
    total = sum(stats.values())
    for name in sorted(stats):
        print(f"  {name}.txt: {stats[name]}")
    print(f"Done: {len(stats)} files, {total} proxies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
