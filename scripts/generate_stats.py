#!/usr/bin/env python3
"""Generate repository statistics and a trend chart.

Reads ``data/history.jsonl`` and ``data/valid/history.jsonl`` and writes
``data/stats.json`` plus a dependency-free SVG trend chart to ``data/chart.svg``.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from download_proxies import HISTORY_FILE, OUT_DIR, ROOT

VALID_DIR = OUT_DIR / "valid"

MARGIN_L = 46
MARGIN_R = 46
MARGIN_T = 16
MARGIN_B = 34
WIDTH = 800
HEIGHT = 300

COLOR_UNIQUE = "#4c78a8"
COLOR_ALIVE = "#e45756"
GRID = "#e8e8e8"


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_history(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def build_svg(history: list[dict], valid_history: list[dict]) -> str:
    unique_series = [r.get("unique", 0) for r in history]
    alive_series = [r.get("alive", 0) for r in valid_history]

    plot_w = WIDTH - MARGIN_L - MARGIN_R
    plot_h = HEIGHT - MARGIN_T - MARGIN_B

    def points(series: list[int], color: str) -> str:
        if not series:
            return ""
        n = len(series)
        max_v = max(series) or 1
        pts = []
        for i, v in enumerate(series):
            x = MARGIN_L + (i / (n - 1) * plot_w if n > 1 else plot_w / 2)
            y = MARGIN_T + plot_h - (v / max_v * plot_h)
            pts.append(f"{x:.1f},{y:.1f}")
        return (
            f'<polyline fill="none" stroke="{color}" stroke-width="2" '
            f'stroke-linejoin="round" points="{" ".join(pts)}"/>'
        )

    def y_grid(max_v: int) -> str:
        if not max_v:
            return ""
        ticks = 4
        parts = []
        for i in range(ticks + 1):
            v = max_v * i / ticks
            y = MARGIN_T + plot_h - (v / max_v * plot_h)
            parts.append(
                f'<line x1="{MARGIN_L}" y1="{y:.1f}" x2="{WIDTH - MARGIN_R}" '
                f'y2="{y:.1f}" stroke="{GRID}" stroke-width="1"/>'
                f'<text x="{MARGIN_L - 6}" y="{y + 3:.1f}" font-size="9" '
                f'text-anchor="end" fill="#666">{int(v)}</text>'
            )
        return "".join(parts)

    svg = [
        '<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}">',
        f'<rect width="{WIDTH}" height="{HEIGHT}" fill="#ffffff"/>',
    ]

    if unique_series:
        svg.append(y_grid(max(unique_series)))
        svg.append(
            f'<line x1="{MARGIN_L}" y1="{MARGIN_T}" x2="{MARGIN_L}" '
            f'y2="{MARGIN_T + plot_h}" stroke="#999" stroke-width="1"/>'
            f'<line x1="{MARGIN_L}" y1="{MARGIN_T + plot_h}" x2="{WIDTH - MARGIN_R}" '
            f'y2="{MARGIN_T + plot_h}" stroke="#999" stroke-width="1"/>'
        )
        svg.append(points(unique_series, COLOR_UNIQUE))
        first_ts = history[0].get("ts", "")[:16].replace("T", " ")
        last_ts = history[-1].get("ts", "")[:16].replace("T", " ")
        svg.append(
            f'<text x="{MARGIN_L}" y="{HEIGHT - 12}" font-size="9" fill="#666">{first_ts}</text>'
            f'<text x="{WIDTH - MARGIN_R}" y="{HEIGHT - 12}" font-size="9" '
            f'text-anchor="end" fill="#666">{last_ts}</text>'
        )

    if alive_series:
        svg.append(points(alive_series, COLOR_ALIVE))

    legend_items = []
    if unique_series:
        legend_items.append(
            f'<line x1="14" y1="10" x2="34" y2="10" stroke="{COLOR_UNIQUE}" stroke-width="2"/>'
            f'<text x="38" y="13" font-size="10" fill="#333">unique</text>'
        )
    if alive_series:
        legend_items.append(
            f'<line x1="100" y1="10" x2="120" y2="10" stroke="{COLOR_ALIVE}" stroke-width="2"/>'
            f'<text x="124" y="13" font-size="10" fill="#333">alive</text>'
        )
    svg.append("".join(legend_items))

    svg.append("</svg>")
    return "\n".join(svg)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUT_DIR, help="Output directory")
    args = parser.parse_args(argv)

    history = load_history(HISTORY_FILE)
    valid_history = load_history(VALID_DIR / "history.jsonl")
    meta = read_json(VALID_DIR / "meta.json")

    latest = history[-1] if history else {}
    sets = latest.get("sets", {})
    alive_sets = meta.get("sets", {})
    alive = meta.get("alive", 0)
    checked = meta.get("checked", 0)

    stats = {
        "ts": now_ts(),
        "updated_at": latest.get("ts"),
        "unique": latest.get("unique", 0),
        "total": latest.get("total", 0),
        "countries": latest.get("countries", 0),
        "ports": latest.get("ports", 0),
        "sets": sets,
        "alive": alive,
        "alive_checked": checked,
        "alive_rate": round(alive / checked, 4) if checked else 0,
        "alive_countries": len(meta.get("per_country", {})),
        "alive_sets": alive_sets,
        "latency": meta.get("latency", {}),
        "history_records": len(history),
        "alive_history_records": len(valid_history),
    }

    args.out.mkdir(parents=True, exist_ok=True)
    stats_file = args.out / "stats.json"
    tmp = stats_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(stats_file)
    print(f"Wrote {stats_file}")

    chart = build_svg(history, valid_history)
    chart_file = args.out / "chart.svg"
    tmp = chart_file.with_suffix(".tmp")
    tmp.write_text(chart, encoding="utf-8")
    tmp.replace(chart_file)
    print(f"Wrote {chart_file}")

    print(
        f"unique={stats['unique']} alive={alive}/{checked} "
        f"latency_p90={stats['latency'].get('p90_ms')}ms"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
