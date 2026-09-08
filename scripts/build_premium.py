#!/usr/bin/env python3
"""Build premium (高端优质) ``premium.txt`` lists from quality data.

Filters the annotated valid pools to proxies that simultaneously satisfy:

1. CN-reachable      — ``china.json`` verdict == ``reachable``
2. reputation >= 95  — present in ``reputation.json`` with a score of at
   least 95
3. real residential   — ``ipinfo.json`` ``ip_type == "RES"``
4. not high risk     — ``reputation.json`` risk != ``high``

Survivors are ranked by a composite, reputation-weighted score::

    score = round(0.6 * rep + 0.2 * latency_score + 0.2 * speed_score)

where ``latency_score`` maps <=100ms to 100 and >=1500ms to 0 linearly
(missing latency counts 0), and ``speed_score = min(MB/s / 5, 1) * 100``
(missing speed counts 0). Ties break by latency asc then key asc.

Latency prefers the mainland-measured value from ``china.json`` (``ms``,
what a mainland user actually experiences); the overseas TLS latency from
the line notes is only the fallback when no CN measurement exists.

Every ``premium`` list only contains CN-reachable lines (a ``-CN``-only list
by construction), so all outputs render the **CN view**: inline latency is
the mainland-measured ``china.json`` reading and the speed token is rewritten
to the ``≈XMB/s`` mainland-side estimate (``common._rewrite_cn_speed``), the
same semantics as ``all_cn.txt``. Without ``cn_ms`` data the lines are kept
verbatim.

Outputs are the CN-viewed annotated lines:

- ``data/valid/all_premium.txt``            (global policy group)
- ``data/valid/all_premium_v4.txt`` / ``_v6`` / ``_46`` (exit-family split)
- ``data/valid/countries/<CC>/premium.txt`` (per-country groups)
- ``data/valid/countries/<CC>/premium_v4.txt`` / ``_v6`` / ``_46``
- ``data/valid/sets/<name>/premium.txt``    (country-set groups)
- ``data/valid/sets/<name>/premium_v4.txt`` / ``_v6`` / ``_46``

Exit family prefers ``exit_family.json``; without an entry it falls back to
the line notes ``-V4``/``-V6``/``-DS`` (same rule as the ``v4``/``v6``/``46``
group files). Untagged lines appear only in the unsplit list.
"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_good import (
    LATENCY_WORST_MS,
    composite_score,
    parse_metrics,
    to_cn_view,
    write_good_file,
)
from common import (
    CHINA_FILE,
    DATA_DIR,
    EXIT_FAMILY_FILE,
    IPINFO_FILE,
    REPUTATION_FILE,
    cn_display_ms,
    has_token,
    line_to_key,
    load_china_stable_keys,
    load_speed_keys,
    load_uptime_keys,
    note_tier,
    parse_line,
    read_json,
    write_json,
    write_text_if_changed,
)

MIN_REP_SCORE = 95

FAMILY_BRANCHES = ("v4", "v6", "46")
_FAMILY_BRANCH_TO_NAME = {"ipv4": "v4", "ipv6": "v6", "dual": "46"}


def build_ip_type_map(data: dict) -> dict[str, str]:
    """``ipinfo.json`` -> ``{key: ip_type}``（DC/RES/MOB/PROXY）。"""
    result: dict[str, str] = {}
    for key, entry in data.get("proxies", {}).items():
        if not isinstance(entry, dict):
            continue
        ip_type = entry.get("ip_type")
        if isinstance(ip_type, str) and ip_type:
            result[key] = ip_type
    return result


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
    """``china.json`` -> 当期全可达集。"""
    result: set[str] = set()
    for key, entry in data.get("proxies", {}).items():
        if isinstance(entry, dict) and entry.get("verdict") == "reachable":
            result.add(key)
    return result


def build_cn_ms_map(data: dict) -> dict[str, float]:
    """``china.json`` -> ``{key: 大陆实测 ms}``（优先可信探测，过滤噪声）。"""
    result: dict[str, float] = {}
    for key, entry in data.get("proxies", {}).items():
        ms = cn_display_ms(entry)
        if ms is not None:
            result[key] = ms
    return result


def is_cn_reachable(key: str | None, china_set: set[str]) -> bool:
    """CN-reachable per repo convention: judged ``reachable`` this run only."""
    return key in china_set


def build_family_map(data: dict) -> dict[str, str]:
    """``exit_family.json`` -> ``{key: family}`` (ipv4/ipv6/dual)."""
    result: dict[str, str] = {}
    for key, entry in data.get("proxies", {}).items():
        if not isinstance(entry, dict):
            continue
        fam = entry.get("family")
        if fam in _FAMILY_BRANCH_TO_NAME:
            result[key] = fam
    return result


def family_of(key: str | None, line: str, family_map: dict[str, str]) -> str | None:
    """出口家族：优先 ``exit_family.json``，缺失时按行内 ``-V4``/``-V6``/``-DS`` 兜底。

    返回 ``ipv4``/``ipv6``/``dual`` 之一，无法判定时 ``None``。
    """
    fam = family_map.get(key) if key else None
    if fam in _FAMILY_BRANCH_TO_NAME:
        return fam
    parsed = parse_line(line)
    note = parsed[4] if parsed else ""
    if has_token(note, "DS"):
        return "dual"
    if has_token(note, "V4") and has_token(note, "V6"):
        return "dual"
    if has_token(note, "V4"):
        return "ipv4"
    if has_token(note, "V6"):
        return "ipv6"
    return None


def filter_rank(
    text: str,
    china_set: set[str],
    rep_map: dict[str, dict],
    ip_type_map: dict[str, str],
    cn_ms: dict[str, float] | None = None,
) -> list[str]:
    """Filter pool lines by premium criteria and rank by composite score.

    Criteria: CN reachable + rep>=95 + ip_type==RES + not high risk.
    Lines failing the criteria are dropped; survivors keep their annotated
    form verbatim, ordered by ``(score desc, latency asc, key asc)``.
    """
    ranked: list[tuple[int, int, str, str]] = []
    for line in text.splitlines():
        if not line:
            continue
        key = line_to_key(line)
        if not key or not is_cn_reachable(key, china_set):
            continue
        rep = rep_map.get(key)
        if not rep or rep["risk"] == "high" or rep["score"] < MIN_REP_SCORE:
            continue
        if ip_type_map.get(key) != "RES":
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


def write_premium_files(
    valid_dir: Path,
    china_set: set[str],
    rep_map: dict[str, dict],
    ip_type_map: dict[str, str],
    cn_ms: dict[str, float] | None = None,
    family_map: dict[str, str] | None = None,
) -> dict[str, int]:
    """Write all_premium.txt + per-country/set premium.txt; return counts.

    每份 premium 清单都是仅含大陆可达行的 CN 列表，统一输出 **CN 视图**
    （大陆实测延迟 + ``≈XMB/s`` 大陆估算速度）。除基础清单外同步派生：

    - ``_verified``（speed.json 全链路验证）、``_stable``（china.json
      streak≥2）与 ``_uptime``（uptime.json 滚动可用率）可靠性变体；
    - ``_<tier>.txt`` 速度档变体（fast/mid/slow）；
    - 出口家族分支 ``_v4.txt``/``_v6.txt``/``_46.txt``（`exit_family.json`
      优先、行内 ``-V4``/``-V6``/``-DS`` 兜底），空家族不落盘并清理残留。
    """
    stats: dict[str, int] = {}
    speed_keys = load_speed_keys()
    stable_keys = load_china_stable_keys()
    uptime_keys = load_uptime_keys()
    family_map = family_map or {}

    def emit(base: Path, lines: list[str]) -> int:
        lines = to_cn_view(lines, cn_ms)
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
        for tier in TIER_TOKENS:
            tlines = [ln for ln in lines if note_tier(ln) == tier]
            tpath = base.with_name(f"{base.stem}_{tier}.txt")
            if tlines:
                write_text_if_changed(tpath, "\n".join(tlines) + "\n")
            elif tpath.exists():
                tpath.unlink()
        return n

    def emit_family(base: Path, lines: list[str]) -> None:
        """按出口家族派生 ``<stem>_v4/v6/46.txt`` 分支；空分支清理残留。"""
        branches: dict[str, list[str]] = {b: [] for b in FAMILY_BRANCHES}
        for ln in lines:
            fam = family_of(line_to_key(ln), ln, family_map)
            branch = _FAMILY_BRANCH_TO_NAME.get(fam or "")
            if branch in branches:
                branches[branch].append(ln)
        for branch, blines in branches.items():
            bpath = base.with_name(f"{base.stem}_{branch}.txt")
            if blines:
                emit(bpath, blines)
            else:
                stale = [bpath]
                stale += [bpath.with_name(f"{base.stem}_{branch}{s}.txt")
                          for s in ("_verified", "_stable", "_uptime")]
                stale += [bpath.with_name(f"{base.stem}_{branch}_{t}.txt")
                          for t in TIER_TOKENS]
                for p in stale:
                    if p.exists():
                        p.unlink()

    all_pool = valid_dir / "all.txt"
    if all_pool.exists():
        lines = filter_rank(
            all_pool.read_text(encoding="utf-8"), china_set, rep_map,
            ip_type_map, cn_ms,
        )
        stats["all_premium"] = emit(valid_dir / "all_premium.txt", lines)
        emit_family(valid_dir / "all_premium.txt", lines)

    for sub in ("countries", "sets"):
        root = valid_dir / sub
        if not root.is_dir():
            continue
        for group_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            pool = group_dir / "all.txt"
            if not pool.exists():
                continue
            name = f"{sub}/{group_dir.name}"
            lines = filter_rank(
                pool.read_text(encoding="utf-8"), china_set, rep_map,
                ip_type_map, cn_ms,
            )
            stats[name] = emit(group_dir / "premium.txt", lines)
            emit_family(group_dir / "premium.txt", lines)
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
    ip_type_map = build_ip_type_map(read_json(quality_dir / IPINFO_FILE.name))
    family_map = build_family_map(read_json(quality_dir / EXIT_FAMILY_FILE.name))
    print(f"Maps: cn={len(china_set)} cn_ms={len(cn_ms)} rep={len(rep_map)} ip_type={len(ip_type_map)} family={len(family_map)}")

    stats = write_premium_files(
        valid_dir, china_set, rep_map, ip_type_map, cn_ms, family_map,
    )
    total = sum(stats.values())
    for name in sorted(stats):
        print(f"  {name}.txt: {stats[name]}")
    write_json(
        quality_dir / "premium_meta.json",
        {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "file_count": len(stats),
            "proxy_count": total,
        },
    )
    print(f"Done: {len(stats)} files, {total} proxies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
