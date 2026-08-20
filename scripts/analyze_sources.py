#!/usr/bin/env python3
"""Analyze download source quality from existing data.

Reads ``data/quality/ip_sources.json`` (per-IP source attribution produced by
``download_proxies.py``) and cross-references it with validation results,
reputation scores, streaming unlock status, and China reachability data to
produce a per-source quality report.

Output: ``data/quality/source_quality.json``
"""

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    CHINA_FILE,
    EXIT_FAMILY_FILE,
    IP_SOURCES_FILE,
    OUTPUT_DIR,
    QUALITY_DIR,
    REPUTATION_FILE,
    SPEED_FILE,
    STREAMING_FILE,
    VALID_ALL_FILE,
    write_text_if_changed,
)

SOURCE_QUALITY_FILE = QUALITY_DIR / "source_quality.json"

# Lazy import to avoid circular dependency at module level
def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _parse_latency(line: str) -> float | None:
    """Extract latency in ms from a proxy line (e.g. ``-120ms``)."""
    import re
    m = re.search(r"-(\d+)ms", line)
    return float(m.group(1)) if m else None


def _parse_speed(line: str) -> float | None:
    """Extract speed in MB/s from a proxy line (e.g. ``-0.44MB/s``)."""
    import re
    m = re.search(r"(\d+(?:\.\d+)?)MB/s", line)
    return float(m.group(1)) if m else None


def _parse_cc(line: str) -> str | None:
    """Extract 2-letter country code from a proxy line."""
    if "#" not in line:
        return None
    rest = line.rsplit("#", 1)[1]
    i = 0
    while i < len(rest) and not ("A" <= rest[i] <= "Z"):
        i += 1
    if rest[i:].startswith("ALL") and (rest[i + 3:i + 4] in ("", "-")):
        return "ALL"
    cc = rest[i:i + 2]
    return cc if len(cc) == 2 and cc.isalpha() else None


def _parse_port(line: str) -> str | None:
    """Extract port from a proxy line."""
    addr = line.split("#", 1)[0]
    if ":" in addr:
        port = addr.rsplit(":", 1)[1]
        return port if port.isdigit() else None
    return None


def analyze(
    ip_sources: dict,
    valid_lines: list[str],
    rep_data: dict,
    streaming_data: dict,
    china_data: dict,
    family_data: dict,
    speed_data: dict,
) -> dict:
    """Compute per-source quality metrics."""
    valid_set = set(valid_lines)

    # Parse valid proxy lines
    valid_keys = set()
    latencies: dict[str, float] = {}
    speeds: dict[str, float] = {}
    countries: dict[str, str] = {}
    ports: dict[str, str] = {}
    for line in valid_lines:
        if "#" not in line:
            continue
        addr, rest = line.rsplit("#", 1)
        i = 0
        while i < len(rest) and not ("A" <= rest[i] <= "Z"):
            i += 1
        if rest[i:].startswith("ALL") and (rest[i + 3:i + 4] in ("", "-")):
            cc = "ALL"
        else:
            cc = rest[i:i + 2]
        if ":" not in addr or not cc:
            continue
        ip, port = addr.rsplit(":", 1)
        key = f"{ip}:{port}#{cc}"
        valid_keys.add(key)
        cc_val = _parse_cc(line)
        if cc_val:
            countries[key] = cc_val
        port_val = _parse_port(line)
        if port_val:
            ports[key] = port_val
        lat = _parse_latency(line)
        if lat is not None:
            latencies[key] = lat
        spd = _parse_speed(line)
        if spd is not None:
            speeds[key] = spd

    # Build per-source metrics
    sources: dict[str, dict] = {}
    source_counter = Counter(ip_sources.values())

    for source_label in sorted(source_counter.keys()):
        keys = [k for k, v in ip_sources.items() if v == source_label]
        total = len(keys)
        alive = sum(1 for k in keys if k in valid_keys)
        survival_rate = round(alive / total, 4) if total else 0

        # Latency
        src_latencies = [latencies[k] for k in keys if k in latencies]
        avg_latency = round(statistics.mean(src_latencies), 1) if src_latencies else None
        med_latency = round(statistics.median(src_latencies), 1) if src_latencies else None

        # Speed
        src_speeds = [speeds[k] for k in keys if k in speeds]
        avg_speed = round(statistics.mean(src_speeds), 2) if src_speeds else None
        med_speed = round(statistics.median(src_speeds), 2) if src_speeds else None

        # Reputation
        rep_scores = []
        rep_dist = {"low": 0, "medium": 0, "high": 0}
        for k in keys:
            rep = rep_data.get(k)
            if rep and isinstance(rep, dict) and "score" in rep:
                score = rep["score"]
                rep_scores.append(score)
                risk = rep.get("risk", "low")
                rep_dist[risk] = rep_dist.get(risk, 0) + 1
        avg_rep = round(statistics.mean(rep_scores), 1) if rep_scores else None

        # Streaming
        streaming_ok = 0
        for k in keys:
            s = streaming_data.get(k)
            if s and isinstance(s, dict):
                if any(
                    isinstance(v, dict) and v.get("status") == "ok"
                    for v in s.values()
                    if isinstance(v, dict)
                ):
                    streaming_ok += 1
        streaming_ok_rate = round(streaming_ok / alive, 4) if alive else 0

        # China reachability
        china_reachable = 0
        for k in keys:
            c = china_data.get(k)
            if c and isinstance(c, dict) and c.get("verdict") == "reachable":
                china_reachable += 1
        china_rate = round(china_reachable / alive, 4) if alive else 0

        # Exit family
        family_dist: dict[str, int] = {}
        for k in keys:
            f = family_data.get(k)
            if f and isinstance(f, dict):
                fam = f.get("family", "unknown")
                family_dist[fam] = family_dist.get(fam, 0) + 1

        # Country distribution
        country_dist = Counter()
        for k in keys:
            cc = countries.get(k)
            if cc and cc != "ALL":
                country_dist[cc] += 1

        # Port distribution
        port_dist = Counter()
        for k in keys:
            p = ports.get(k)
            if p:
                port_dist[p] += 1

        sources[source_label] = {
            "total": total,
            "alive": alive,
            "survival_rate": survival_rate,
            "avg_latency": avg_latency,
            "median_latency": med_latency,
            "avg_speed": avg_speed,
            "median_speed": med_speed,
            "avg_reputation": avg_rep,
            "reputation_dist": rep_dist,
            "streaming_ok_count": streaming_ok,
            "streaming_ok_rate": streaming_ok_rate,
            "china_reachable_count": china_reachable,
            "china_reachable_rate": china_rate,
            "family_dist": family_dist,
            "country_dist": dict(country_dist.most_common(20)),
            "port_dist": dict(port_dist.most_common(10)),
        }

    return {
        "ts": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_proxies": len(ip_sources),
        "total_alive": len(valid_keys),
        "sources": sources,
    }


def _format_report(data: dict) -> str:
    """Format a human-readable summary table."""
    lines = []
    lines.append(f"Source Quality Report  ({data['ts']})")
    lines.append(f"Total: {data['total_proxies']} proxies, {data['total_alive']} alive")
    lines.append("")
    header = (
        f"{'Source':<22} {'Total':>6} {'Alive':>6} {'Surv%':>6} "
        f"{'Lat(ms)':>8} {'Spd(MB)':>8} {'Rep':>5} "
        f"{'Strm%':>6} {'CN%':>6}"
    )
    lines.append(header)
    lines.append("-" * len(header))

    for label, m in sorted(
        data["sources"].items(), key=lambda x: x[1]["survival_rate"], reverse=True
    ):
        lat = f"{m['avg_latency']:.0f}" if m["avg_latency"] is not None else "-"
        spd = f"{m['avg_speed']:.2f}" if m["avg_speed"] is not None else "-"
        rep = f"{m['avg_reputation']:.0f}" if m["avg_reputation"] is not None else "-"
        lines.append(
            f"{label:<22} {m['total']:>6} {m['alive']:>6} "
            f"{m['survival_rate'] * 100:>5.1f}% "
            f"{lat:>8} {spd:>8} {rep:>5} "
            f"{m['streaming_ok_rate'] * 100:>5.1f}% "
            f"{m['china_reachable_rate'] * 100:>5.1f}%"
        )

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "data",
        help="Data root directory (default: data/)",
    )
    args = parser.parse_args(argv)
    data_dir = args.data_dir

    ip_sources_raw = _read_json(data_dir / "quality" / "ip_sources.json")
    ip_sources = ip_sources_raw.get("sources", ip_sources_raw)
    if not ip_sources:
        print("No ip_sources.json found or empty. Run download_proxies.py first.",
              file=sys.stderr)
        return 1

    valid_file = data_dir / "valid" / "all.txt"
    valid_lines = (
        valid_file.read_text(encoding="utf-8").splitlines()
        if valid_file.exists()
        else []
    )

    rep_data = _read_json(data_dir / "quality" / "reputation.json")
    rep_proxies = rep_data.get("proxies", rep_data)

    streaming_data = _read_json(data_dir / "quality" / "streaming.json")
    streaming_proxies = streaming_data.get("proxies", streaming_data)

    china_data = _read_json(data_dir / "quality" / "china.json")
    china_proxies = china_data.get("proxies", china_data)

    family_data = _read_json(data_dir / "quality" / "exit_family.json")
    family_proxies = family_data.get("proxies", family_data)

    speed_data = _read_json(data_dir / "valid" / "speed.json")
    speed_proxies = speed_data.get("proxies", speed_data)

    result = analyze(
        ip_sources, valid_lines, rep_proxies, streaming_proxies,
        china_proxies, family_proxies, speed_proxies,
    )

    out_file = data_dir / "quality" / "source_quality.json"
    write_text_if_changed(
        out_file,
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    print(f"Wrote {out_file}")

    report = _format_report(result)
    print(f"\n{report}")

    report_file = data_dir / "output" / "source_quality_report.txt"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    write_text_if_changed(report_file, report + "\n")
    print(f"\nReport saved to {report_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
