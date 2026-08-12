#!/usr/bin/env python3
"""Generate repository statistics and a set of dependency-free SVG charts.

Reads ``data/history.jsonl`` and ``data/valid/history.jsonl`` plus
``data/valid/meta.json`` and writes ``data/stats.json`` together with:

- ``chart.svg``           unique / alive trend (line)
- ``chart_country.svg``   alive proxies per country (horizontal bars, top 15)
- ``chart_port.svg``      alive proxies per port (vertical bars)
- ``chart_alive_rate.svg`` alive rate (%) over time (line)
- ``chart_churn.svg``     added / removed per update (grouped bars)
- ``chart_combo.svg``     dual-axis composite trend (unique/alive + rate)
"""

import argparse
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

from download_proxies import HISTORY_FILE, OUT_DIR

VALID_DIR = OUT_DIR / "valid"

WIDTH = 800
HEIGHT = 300
MARGIN_L = 46
MARGIN_R = 46
MARGIN_T = 16
MARGIN_B = 34

GRID = "#e8e8e8"
AXIS = "#999"
TEXT = "#666"
TITLE = "#444"

COLOR_UNIQUE = "#4c78a8"
COLOR_ALIVE = "#e45756"
COLOR_RATE = "#f58518"
COLOR_ADDED = "#72b7b2"
COLOR_REMOVED = "#e45756"
COLOR_BAR = "#4c78a8"
COLOR_PORT = "#58508d"


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def esc(text: object) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def fmt_ts(ts: object) -> str:
    return str(ts)[:16].replace("T", " ") if ts else ""


def nice_step(span: float, count: int = 5) -> float:
    """Round "nice" tick step (1/2/2.5/5 x 10^n) covering ``span``."""
    if span <= 0:
        return 1.0
    raw = span / count
    magnitude = 10 ** math.floor(math.log10(raw))
    for s in (1, 2, 2.5, 5, 10):
        nice = magnitude * s
        if nice >= raw:
            return nice
    return magnitude * 10


def nice_ticks(max_v: float, count: int = 5) -> list[float]:
    """Round "nice" axis tick values covering ``max_v`` (from 0)."""
    if max_v <= 0:
        return [0]
    step = nice_step(max_v, count)
    ticks = []
    v = 0.0
    while v <= max_v + 1e-9:
        ticks.append(round(v, 10))
        v += step
    return ticks


def nice_bounds(
    lo: float, hi: float, count: int = 5
) -> tuple[float, float, list[float]]:
    """Zoomed axis range: round ``[lo, hi]`` out to nice ticks.

    Returns ``(lo_tick, hi_tick, ticks)``. A minimum span is enforced so flat
    series still render a sane axis.
    """
    if hi < lo:
        lo, hi = hi, lo
    if hi - lo <= 0:
        pad = max(1.0, abs(hi) * 0.01)
        lo, hi = hi - pad, hi + pad
    step = nice_step(hi - lo, count)
    lo_tick = math.floor(lo / step) * step
    ticks = []
    v = lo_tick
    while v <= hi + 1e-9:
        ticks.append(round(v, 10))
        v += step
    if ticks[-1] < hi:
        ticks.append(round(ticks[-1] + step, 10))
    if len(ticks) < 2:
        ticks.append(round(ticks[-1] + step, 10))
    return ticks[0], ticks[-1], ticks


def fmt_tick(v: float) -> str:
    if abs(v - round(v)) < 1e-9:
        return str(int(round(v)))
    return f"{v:.2f}".rstrip("0").rstrip(".")


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


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def svg_head(width: int, height: int) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>'
    )


def empty_svg(height: int = HEIGHT, text: str = "No data yet") -> str:
    return (
        svg_head(WIDTH, height)
        + f'<text x="{WIDTH / 2}" y="{height / 2}" font-size="13" '
        f'text-anchor="middle" fill="{TEXT}">{esc(text)}</text>'
        + "</svg>"
    )


def legend_svg(series: list[tuple]) -> str:
    x = 14
    parts = []
    for name, color, values, dash in series:
        if not values:
            continue
        sw = 18
        dash_attr = ' stroke-dasharray="4,3"' if dash else ""
        parts.append(
            f'<line x1="{x}" y1="10" x2="{x + sw}" y2="10" '
            f'stroke="{color}" stroke-width="2"{dash_attr}/>'
            f'<text x="{x + sw + 4}" y="13" font-size="10" fill="#333">{esc(name)}</text>'
        )
        x += sw + 4 + len(name) * 6.4 + 16
    return "".join(parts)


def plot_lines(
    series: list[tuple],
    *,
    y_min: float | None = None,
    y_max: float | None = None,
    right_ticks: list[tuple[float, str]] | None = None,
    x_labels: tuple[str, str] = ("", ""),
    height: int = HEIGHT,
    title: str | None = None,
) -> str:
    """Multi-series line chart.

    ``series`` is a list of ``(name, color, values, dash)`` tuples. Each
    series is normalized to its own width (points are index positions, not a
    shared timeline). Unless ``y_min``/``y_max`` are given the y-axis is
    zoomed to the data range (rounded to nice ticks) so small variations stay
    visible. ``right_ticks`` draws extra labels on the right axis for dual-axis
    charts (values are expressed in the same units as the y-axis).
    """
    active = [s for s in series if s[2]]
    if not active:
        return empty_svg(height=height)
    plot_w = WIDTH - MARGIN_L - MARGIN_R
    plot_h = height - MARGIN_T - MARGIN_B
    data = [v for _, _, vals, _ in active for v in vals]
    lo, hi, ticks = nice_bounds(
        min(data) if y_min is None else y_min,
        max(data) if y_max is None else y_max,
    )

    def xs(n: int) -> list[float]:
        if n <= 1:
            return [MARGIN_L + plot_w / 2]
        return [MARGIN_L + i / (n - 1) * plot_w for i in range(n)]

    def y(v: float) -> float:
        return MARGIN_T + plot_h * (1 - (v - lo) / (hi - lo))

    parts = [svg_head(WIDTH, height)]
    if title:
        parts.append(
            f'<text x="{WIDTH / 2}" y="{MARGIN_T}" font-size="10" '
            f'text-anchor="middle" fill="{TITLE}">{esc(title)}</text>'
        )
    if right_ticks:
        for v, label in right_ticks:
            yy = y(v)
            parts.append(
                f'<line x1="{MARGIN_L}" y1="{yy:.1f}" x2="{WIDTH - MARGIN_R}" '
                f'y2="{yy:.1f}" stroke="{GRID}"/>'
                f'<text x="{MARGIN_L - 6}" y="{yy + 3:.1f}" font-size="9" '
                f'text-anchor="end" fill="{TEXT}">{fmt_tick(v)}</text>'
                f'<text x="{WIDTH - MARGIN_R + 6}" y="{yy + 3:.1f}" '
                f'font-size="9" fill="{TEXT}">{esc(label)}</text>'
            )
    else:
        for v in ticks:
            yy = y(v)
            parts.append(
                f'<line x1="{MARGIN_L}" y1="{yy:.1f}" x2="{WIDTH - MARGIN_R}" '
                f'y2="{yy:.1f}" stroke="{GRID}"/>'
                f'<text x="{MARGIN_L - 6}" y="{yy + 3:.1f}" font-size="9" '
                f'text-anchor="end" fill="{TEXT}">{fmt_tick(v)}</text>'
            )
    parts.append(
        f'<line x1="{MARGIN_L}" y1="{MARGIN_T}" x2="{MARGIN_L}" '
        f'y2="{MARGIN_T + plot_h}" stroke="{AXIS}"/>'
        f'<line x1="{MARGIN_L}" y1="{MARGIN_T + plot_h}" x2="{WIDTH - MARGIN_R}" '
        f'y2="{MARGIN_T + plot_h}" stroke="{AXIS}"/>'
    )
    for name, color, values, dash in series:
        if not values:
            continue
        xpts = xs(len(values))
        pts = " ".join(
            f"{xpts[i]:.1f},{y(values[i]):.1f}" for i in range(len(values))
        )
        if len(values) == 1:
            px, py = xpts[0], y(values[0])
            parts.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="3" fill="{color}"/>')
        else:
            dash_attr = ' stroke-dasharray="4,3"' if dash else ""
            parts.append(
                f'<polyline fill="none" stroke="{color}" stroke-width="2"'
                f'{dash_attr} stroke-linejoin="round" points="{pts}"/>'
            )
    if x_labels[0] or x_labels[1]:
        parts.append(
            f'<text x="{MARGIN_L}" y="{height - 12}" font-size="9" fill="{TEXT}">'
            f"{esc(x_labels[0])}</text>"
            f'<text x="{WIDTH - MARGIN_R}" y="{height - 12}" font-size="9" '
            f'text-anchor="end" fill="{TEXT}">{esc(x_labels[1])}</text>'
        )
    parts.append(legend_svg(series))
    parts.append("</svg>")
    return "\n".join(parts)


def plot_hbars(
    items: list[tuple[str, int]],
    *,
    row_h: int = 18,
    color: str = COLOR_BAR,
    title: str | None = None,
) -> str:
    """Horizontal bar chart; ``items`` is ``(label, value)`` in display order."""
    n = len(items)
    if n == 0:
        return empty_svg()
    left = MARGIN_L
    right = WIDTH - MARGIN_R - 46
    max_v = max(v for _, v in items) or 1
    height = MARGIN_T + n * row_h + 8
    plot_w = right - left
    body_h = n * row_h

    parts = [svg_head(WIDTH, height)]
    if title:
        parts.append(
            f'<text x="{WIDTH / 2}" y="{MARGIN_T}" font-size="10" '
            f'text-anchor="middle" fill="{TITLE}">{esc(title)}</text>'
        )
    for v in nice_ticks(max_v):
        gx = left + v / max_v * plot_w
        parts.append(
            f'<line x1="{gx:.1f}" y1="{MARGIN_T}" x2="{gx:.1f}" '
            f'y2="{MARGIN_T + body_h}" stroke="{GRID}"/>'
        )
    for i, (label, value) in enumerate(items):
        y0 = MARGIN_T + i * row_h + 2
        bar_h = row_h - 8
        bw = max(1.0, value / max_v * plot_w)
        parts.append(
            f'<text x="{left - 6}" y="{y0 + 9:.1f}" font-size="9" '
            f'text-anchor="end" fill="{TEXT}">{esc(label)}</text>'
            f'<rect x="{left:.1f}" y="{y0:.1f}" width="{bw:.1f}" '
            f'height="{bar_h:.1f}" fill="{color}" rx="1.5"/>'
            f'<text x="{left + bw + 4:.1f}" y="{y0 + 9:.1f}" font-size="9" '
            f'fill="{TEXT}">{value}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts)


def plot_vbars(
    items: list[tuple[str, int]],
    *,
    color: str = COLOR_PORT,
    title: str | None = None,
) -> str:
    """Vertical bar chart; ``items`` is ``(label, value)``."""
    n = len(items)
    if n == 0:
        return empty_svg()
    plot_w = WIDTH - MARGIN_L - MARGIN_R
    plot_h = HEIGHT - MARGIN_T - MARGIN_B
    max_v = max(v for _, v in items) or 1
    slot = plot_w / n
    bar_w = max(14, min(80, slot * 0.55))

    parts = [svg_head(WIDTH, HEIGHT)]
    if title:
        parts.append(
            f'<text x="{WIDTH / 2}" y="{MARGIN_T}" font-size="10" '
            f'text-anchor="middle" fill="{TITLE}">{esc(title)}</text>'
        )
    for v in nice_ticks(max_v):
        yy = MARGIN_T + plot_h - v / max_v * plot_h
        parts.append(
            f'<line x1="{MARGIN_L}" y1="{yy:.1f}" x2="{WIDTH - MARGIN_R}" '
            f'y2="{yy:.1f}" stroke="{GRID}"/>'
            f'<text x="{MARGIN_L - 6}" y="{yy + 3:.1f}" font-size="9" '
            f'text-anchor="end" fill="{TEXT}">{fmt_tick(v)}</text>'
        )
    parts.append(
        f'<line x1="{MARGIN_L}" y1="{MARGIN_T}" x2="{MARGIN_L}" '
        f'y2="{MARGIN_T + plot_h}" stroke="{AXIS}"/>'
        f'<line x1="{MARGIN_L}" y1="{MARGIN_T + plot_h}" x2="{WIDTH - MARGIN_R}" '
        f'y2="{MARGIN_T + plot_h}" stroke="{AXIS}"/>'
    )
    for i, (label, value) in enumerate(items):
        cx = MARGIN_L + (i + 0.5) * slot
        bh = value / max_v * plot_h
        y0 = MARGIN_T + plot_h - bh
        parts.append(
            f'<rect x="{cx - bar_w / 2:.1f}" y="{y0:.1f}" width="{bar_w:.1f}" '
            f'height="{bh:.1f}" fill="{color}" rx="1.5"/>'
            f'<text x="{cx:.1f}" y="{y0 - 4:.1f}" font-size="9" '
            f'text-anchor="middle" fill="{TEXT}">{value}</text>'
            f'<text x="{cx:.1f}" y="{MARGIN_T + plot_h + 12}" font-size="9" '
            f'text-anchor="middle" fill="{TEXT}">{esc(label)}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts)


def plot_grouped_vbars(
    groups: list[str],
    series: list[tuple],
    *,
    title: str | None = None,
) -> str:
    """Grouped vertical bars; ``groups`` are x labels, ``series`` mirrors the
    ``(name, color, values, dash)`` layout of :func:`plot_lines`."""
    n = len(groups)
    if n == 0 or not any(vals for _, _, vals, _ in series):
        return empty_svg()
    plot_w = WIDTH - MARGIN_L - MARGIN_R
    plot_h = HEIGHT - MARGIN_T - MARGIN_B
    max_v = max((v for _, _, vals, _ in series for v in vals), default=0) or 1
    slot = plot_w / n
    k = len(series)
    bar_w = min(50, slot / (k + 0.5))

    parts = [svg_head(WIDTH, HEIGHT)]
    if title:
        parts.append(
            f'<text x="{WIDTH / 2}" y="{MARGIN_T}" font-size="10" '
            f'text-anchor="middle" fill="{TITLE}">{esc(title)}</text>'
        )
    for v in nice_ticks(max_v):
        yy = MARGIN_T + plot_h - v / max_v * plot_h
        parts.append(
            f'<line x1="{MARGIN_L}" y1="{yy:.1f}" x2="{WIDTH - MARGIN_R}" '
            f'y2="{yy:.1f}" stroke="{GRID}"/>'
            f'<text x="{MARGIN_L - 6}" y="{yy + 3:.1f}" font-size="9" '
            f'text-anchor="end" fill="{TEXT}">{fmt_tick(v)}</text>'
        )
    parts.append(
        f'<line x1="{MARGIN_L}" y1="{MARGIN_T}" x2="{MARGIN_L}" '
        f'y2="{MARGIN_T + plot_h}" stroke="{AXIS}"/>'
        f'<line x1="{MARGIN_L}" y1="{MARGIN_T + plot_h}" x2="{WIDTH - MARGIN_R}" '
        f'y2="{MARGIN_T + plot_h}" stroke="{AXIS}"/>'
    )
    for i in range(n):
        center = MARGIN_L + (i + 0.5) * slot
        for j, (name, color, vals, _) in enumerate(series):
            if i >= len(vals):
                continue
            value = vals[i]
            x0 = center + (j - (k - 1) / 2) * bar_w - bar_w / 2
            bh = value / max_v * plot_h
            y0 = MARGIN_T + plot_h - bh
            parts.append(
                f'<rect x="{x0:.1f}" y="{y0:.1f}" width="{bar_w:.1f}" '
                f'height="{bh:.1f}" fill="{color}" rx="1"/>'
            )
    first_x = MARGIN_L
    last_x = MARGIN_L + (n - 1) * slot
    parts.append(
        f'<text x="{first_x}" y="{MARGIN_T + plot_h + 12}" font-size="8" '
        f'fill="{TEXT}">{esc(fmt_ts(groups[0]))}</text>'
        f'<text x="{last_x}" y="{MARGIN_T + plot_h + 12}" font-size="8" '
        f'text-anchor="end" fill="{TEXT}">{esc(fmt_ts(groups[-1]))}</text>'
    )
    parts.append(legend_svg(series))
    parts.append("</svg>")
    return "\n".join(parts)


def build_trend(history: list[dict], valid_history: list[dict]) -> str:
    series = [
        ("unique", COLOR_UNIQUE, [r.get("unique", 0) for r in history], ""),
        ("alive", COLOR_ALIVE, [r.get("alive", 0) for r in valid_history], ""),
    ]
    labels = (fmt_ts(history[0].get("ts")) if history else "", fmt_ts(history[-1].get("ts")) if history else "")
    return plot_lines(series, x_labels=labels, title="Unique & Alive trend")


def build_country(meta: dict) -> str:
    per_country = meta.get("per_country", {})
    items = sorted(per_country.items(), key=lambda kv: kv[1], reverse=True)[:15]
    return plot_hbars(items, title="Alive proxies by country (top 15)")


def build_port(meta: dict) -> str:
    per_port = meta.get("per_port", {})
    items = [(p, per_port[p]) for p in sorted(per_port, key=lambda p: int(p))]
    return plot_vbars(items, title="Alive proxies by port")


def build_alive_rate(valid_history: list[dict]) -> str:
    values = []
    for r in valid_history:
        checked = r.get("checked", 0)
        values.append(round(r.get("alive", 0) / checked * 100, 1) if checked else 0)
    labels = (
        fmt_ts(valid_history[0].get("ts")) if valid_history else "",
        fmt_ts(valid_history[-1].get("ts")) if valid_history else "",
    )
    return plot_lines(
        [("alive rate", COLOR_RATE, values, "")],
        x_labels=labels,
        title="Alive rate (%) over time",
    )


def build_churn(history: list[dict]) -> str:
    groups = [r.get("ts", "") for r in history]
    series = [
        ("added", COLOR_ADDED, [r.get("added", 0) for r in history], ""),
        ("removed", COLOR_REMOVED, [r.get("removed", 0) for r in history], ""),
    ]
    return plot_grouped_vbars(groups, series, title="Added / removed per update")


def build_combo(history: list[dict], valid_history: list[dict]) -> str:
    unique = [r.get("unique", 0) for r in history]
    alive = [r.get("alive", 0) for r in valid_history]
    pct = []
    for r in valid_history:
        checked = r.get("checked", 0)
        pct.append(round(r.get("alive", 0) / checked * 100, 1) if checked else 0)
    counts = max(
        max(unique) if unique else 0,
        max(alive) if alive else 0,
        max(pct) if pct else 0,
    ) or 1
    scale = counts / 100
    series = [
        ("unique", COLOR_UNIQUE, unique, ""),
        ("alive", COLOR_ALIVE, alive, ""),
        ("alive rate", COLOR_RATE, [v * scale for v in pct], "dash"),
    ]
    data = [v for _, _, vals, _ in series for v in vals]
    if not data:
        return empty_svg()
    lo, hi, ticks = nice_bounds(min(data), max(data))
    right_ticks = [
        (t, f"{min(100.0, max(0.0, t / counts * 100)):.1f}%") for t in ticks
    ]
    labels = (
        fmt_ts(history[0].get("ts")) if history else "",
        fmt_ts(history[-1].get("ts")) if history else "",
    )
    return plot_lines(
        series,
        y_min=lo,
        y_max=hi,
        right_ticks=right_ticks,
        x_labels=labels,
        title="Unique / Alive / Alive rate",
    )


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

    stats_file = args.out / "stats.json"
    write_atomic(stats_file, json.dumps(stats, ensure_ascii=False, indent=2) + "\n")
    print(f"Wrote {stats_file}")

    charts = {
        "chart.svg": build_trend(history, valid_history),
        "chart_country.svg": build_country(meta),
        "chart_port.svg": build_port(meta),
        "chart_alive_rate.svg": build_alive_rate(valid_history),
        "chart_churn.svg": build_churn(history),
        "chart_combo.svg": build_combo(history, valid_history),
    }
    for name, content in charts.items():
        path = args.out / name
        write_atomic(path, content)
        print(f"Wrote {path}")

    print(
        f"unique={stats['unique']} alive={alive}/{checked} "
        f"latency_p90={stats['latency'].get('p90_ms')}ms"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
