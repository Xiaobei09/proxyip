#!/usr/bin/env python3
"""Generate repository statistics and a set of dependency-free SVG charts.

Reads ``data/history.jsonl`` and ``data/valid/history.jsonl`` plus
``data/valid/meta.json`` and writes ``data/stats.json`` together with:

- ``chart.svg``           unique / alive trend (time-aligned lines)
- ``chart_country.svg``   alive proxies per country (horizontal bars, top 15)
- ``chart_port.svg``      alive proxies per port (vertical bars)
- ``chart_alive_rate.svg`` alive rate + dead (dual-axis lines)
- ``chart_churn.svg``     added / removed per update (grouped bars)
- ``chart_combo.svg``     dual-axis composite trend (unique/alive + rate)
- ``chart_latency.svg``   latency distribution (vertical bars)
- ``chart_speed.svg``     download speed distribution (vertical bars, MB/s)
- ``chart_streaming.svg`` streaming unlock count per service (vertical bars)

Line charts share a real-time x axis (series lacking usable timestamps fall
back to index spacing), zoom each y-axis to its data range so small variations
stay visible, and attach hover tooltips via inline ``<title>`` elements.
"""

import argparse
import json
import math
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from common import OUT_DIR

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
COLOR_DEAD = "#8c564b"
COLOR_ADDED = "#72b7b2"
COLOR_REMOVED = "#e45756"
COLOR_BAR = "#4c78a8"
COLOR_PORT = "#58508d"
COLOR_LATENCY = "#bcbd22"
COLOR_SPEED = "#17becf"
COLOR_STREAMING = "#9b59b6"

MAX_HOVER_POINTS = 600
STALE_AFTER_S = 3 * 3600


@dataclass
class Series:
    """One line series: timestamps aligned 1:1 with values.

    ``axis`` is ``"l"`` (left) or ``"r"`` (right, dual-axis chart).
    """

    name: str
    color: str
    ts: list[str]
    values: list[float]
    dash: str = ""
    axis: str = "l"


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


def to_epoch(ts: object) -> float | None:
    if not ts:
        return None
    s = str(ts).strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def fmt_ago(seconds: float) -> str:
    """Human-readable age, e.g. ``"35m ago"`` / ``"2h 15m ago"``."""
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        mins = minutes % 60
        return f"{hours}h {mins}m ago" if mins else f"{hours}h ago"
    return f"{hours // 24}d ago"


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


def render_title(title: str, height: int = HEIGHT) -> str:
    return (
        f'<text x="{WIDTH / 2}" y="{MARGIN_T}" font-size="10" '
        f'text-anchor="middle" fill="{TITLE}">{esc(title)}</text>'
    )


def legend_svg(series: list[Series]) -> str:
    x = 14
    parts = []
    for s in series:
        if not s.values:
            continue
        sw = 18
        dash_attr = ' stroke-dasharray="4,3"' if s.dash else ""
        parts.append(
            f'<line x1="{x}" y1="10" x2="{x + sw}" y2="10" '
            f'stroke="{s.color}" stroke-width="2"{dash_attr}/>'
            f'<text x="{x + sw + 4}" y="13" font-size="10" fill="#333">{esc(s.name)}</text>'
        )
        x += sw + 4 + len(s.name) * 6.4 + 16
    return "".join(parts)


def time_labels(
    series: list[Series], use_time: bool
) -> list[tuple[float, str, str]]:
    """Return ``(x, anchor, text)`` x-axis labels.

    Shows the first and last data point timestamps plus up to three evenly
    spaced intermediate ones, each snapped to the nearest real data point.
    """
    texts: list[str] = []
    seen: set[str] = set()
    for s in series:
        for t in s.ts:
            if t and t not in seen:
                seen.add(t)
                texts.append(t)
    if not texts:
        return []
    plot_w = WIDTH - MARGIN_L - MARGIN_R

    if not use_time:
        return [
            (MARGIN_L, "start", fmt_ts(texts[0])),
            (WIDTH - MARGIN_R, "end", fmt_ts(texts[-1])),
        ]

    epochs = [to_epoch(t) for t in texts]
    t0, t1 = min(epochs), max(epochs)
    span = t1 - t0

    def x_of(e: float) -> float:
        return MARGIN_L + (e - t0) / span * plot_w

    if span <= 0:
        return [(MARGIN_L + plot_w / 2, "middle", fmt_ts(texts[0]))]

    picked = {texts[0], texts[-1]}
    items = [
        (x_of(epochs[0]), "start", fmt_ts(texts[0])),
        (x_of(epochs[-1]), "end", fmt_ts(texts[-1])),
    ]
    for frac in (0.25, 0.5, 0.75):
        target = t0 + span * frac
        nearest = min(range(len(epochs)), key=lambda i: abs(epochs[i] - target))
        t = texts[nearest]
        if t in picked:
            continue
        picked.add(t)
        x = x_of(epochs[nearest])
        if all(abs(x - ex) >= 66 for ex, _, _ in items):
            items.append((x, "middle", fmt_ts(t)))
    return sorted(items, key=lambda it: it[0])


def plot_lines(
    series: list[Series],
    *,
    y_min: float | None = None,
    y_max: float | None = None,
    left_unit: str = "",
    right_unit: str = "",
    height: int = HEIGHT,
    title: str | None = None,
) -> str:
    """Multi-series line chart with per-axis zoom and a shared time x axis.

    All series are positioned on one time axis spanning the earliest to the
    latest timestamp across every series; series lacking usable timestamps fall
    back to index spacing. ``axis="r"`` series are scaled against their own
    zoomed range and labeled on the right margin (dual-axis). Data points get a
    hover tooltip via inline ``<title>`` when the total point count is modest.
    """
    active = [s for s in series if s.values]
    if not active:
        return empty_svg(height=height)
    plot_w = WIDTH - MARGIN_L - MARGIN_R
    plot_h = height - MARGIN_T - MARGIN_B

    left = [s for s in active if s.axis == "l"]
    right = [s for s in active if s.axis == "r"]
    if not left:
        left, right = active, []

    l_lo, l_hi, l_ticks = nice_bounds(
        min(v for s in left for v in s.values) if y_min is None else y_min,
        max(v for s in left for v in s.values) if y_max is None else y_max,
    )
    if right:
        r_lo, r_hi, r_ticks = nice_bounds(
            min(v for s in right for v in s.values),
            max(v for s in right for v in s.values),
        )
    else:
        r_lo, r_hi, r_ticks = 0.0, 1.0, []

    def y_of(axis: str, v: float) -> float:
        lo, hi = (l_lo, l_hi) if axis == "l" else (r_lo, r_hi)
        return MARGIN_T + plot_h * (1 - (v - lo) / (hi - lo))

    use_time = True
    epochs_all: list[float] = []
    for s in active:
        for t in s.ts:
            e = to_epoch(t)
            if e is None:
                use_time = False
                break
            epochs_all.append(e)
        if not use_time:
            break
    if use_time and len(set(epochs_all)) < 2:
        use_time = False
    t0 = min(epochs_all) if use_time else 0.0
    t1 = max(epochs_all) if use_time else 0.0
    span = t1 - t0 if use_time else 0.0

    def x_for(ts_list: list[str], n: int) -> list[float]:
        if n <= 1:
            return [MARGIN_L + plot_w / 2]
        if not use_time:
            return [MARGIN_L + i / (n - 1) * plot_w for i in range(n)]
        out = []
        for t in ts_list:
            e = to_epoch(t)
            frac = (e - t0) / span
            out.append(MARGIN_L + max(0.0, min(1.0, frac)) * plot_w)
        return out

    parts = [svg_head(WIDTH, height)]
    if title:
        parts.append(render_title(title, height))

    for v in l_ticks:
        yy = y_of("l", v)
        parts.append(
            f'<line x1="{MARGIN_L}" y1="{yy:.1f}" x2="{WIDTH - MARGIN_R}" '
            f'y2="{yy:.1f}" stroke="{GRID}"/>'
            f'<text x="{MARGIN_L - 6}" y="{yy + 3:.1f}" font-size="9" '
            f'text-anchor="end" fill="{TEXT}">{fmt_tick(v)}{left_unit}</text>'
        )
    if right:
        for v in r_ticks:
            yy = y_of("r", v)
            parts.append(
                f'<text x="{WIDTH - 8}" y="{yy + 3:.1f}" font-size="9" '
                f'text-anchor="end" fill="{TEXT}">{fmt_tick(v)}{right_unit}</text>'
            )
        parts.append(
            f'<line x1="{WIDTH - MARGIN_R}" y1="{MARGIN_T}" '
            f'x2="{WIDTH - MARGIN_R}" y2="{MARGIN_T + plot_h}" stroke="{AXIS}"/>'
        )
    parts.append(
        f'<line x1="{MARGIN_L}" y1="{MARGIN_T}" x2="{MARGIN_L}" '
        f'y2="{MARGIN_T + plot_h}" stroke="{AXIS}"/>'
        f'<line x1="{MARGIN_L}" y1="{MARGIN_T + plot_h}" x2="{WIDTH - MARGIN_R}" '
        f'y2="{MARGIN_T + plot_h}" stroke="{AXIS}"/>'
    )

    total_pts = sum(len(s.values) for s in active)
    hover = total_pts <= MAX_HOVER_POINTS
    for s in active:
        xpts = x_for(s.ts, len(s.values))
        ypts = [y_of(s.axis, v) for v in s.values]
        pts = " ".join(f"{xpts[i]:.1f},{ypts[i]:.1f}" for i in range(len(s.values)))
        if len(s.values) == 1:
            parts.append(
                f'<circle cx="{xpts[0]:.1f}" cy="{ypts[0]:.1f}" r="3" fill="{s.color}"/>'
            )
        else:
            dash_attr = ' stroke-dasharray="4,3"' if s.dash else ""
            parts.append(
                f'<polyline fill="none" stroke="{s.color}" stroke-width="2"'
                f'{dash_attr} stroke-linejoin="round" points="{pts}"/>'
            )
        if hover:
            for i in range(len(s.values)):
                tip = f"{s.name}: {s.values[i]:g}"
                ts_txt = fmt_ts(s.ts[i]) if i < len(s.ts) else ""
                if ts_txt:
                    tip = f"{ts_txt} · {tip}"
                parts.append(
                    f'<circle cx="{xpts[i]:.1f}" cy="{ypts[i]:.1f}" r="4" '
                    f'fill="transparent"><title>{esc(tip)}</title></circle>'
                )

    for x, anchor, text in time_labels(active, use_time):
        parts.append(
            f'<text x="{x:.1f}" y="{height - 12}" font-size="9" '
            f'text-anchor="{anchor}" fill="{TEXT}">{esc(text)}</text>'
        )
    parts.append(legend_svg(active))
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
        parts.append(render_title(title, height))
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
        parts.append(render_title(title, HEIGHT))
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
    series: list[Series],
    *,
    title: str | None = None,
) -> str:
    """Grouped vertical bars; ``groups`` are x labels, one bar per series."""
    n = len(groups)
    if n == 0 or not any(s.values for s in series):
        return empty_svg()
    plot_w = WIDTH - MARGIN_L - MARGIN_R
    plot_h = HEIGHT - MARGIN_T - MARGIN_B
    max_v = max((v for s in series for v in s.values), default=0) or 1
    slot = plot_w / n
    k = len(series)
    bar_w = min(50, slot / (k + 0.5))

    parts = [svg_head(WIDTH, HEIGHT)]
    if title:
        parts.append(render_title(title, HEIGHT))
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
        for j, s in enumerate(series):
            if i >= len(s.values):
                continue
            value = s.values[i]
            x0 = center + (j - (k - 1) / 2) * bar_w - bar_w / 2
            bh = value / max_v * plot_h
            y0 = MARGIN_T + plot_h - bh
            parts.append(
                f'<rect x="{x0:.1f}" y="{y0:.1f}" width="{bar_w:.1f}" '
                f'height="{bh:.1f}" fill="{s.color}" rx="1"/>'
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
        Series(
            "unique", COLOR_UNIQUE,
            [r.get("ts", "") for r in history],
            [r.get("unique", 0) for r in history],
        ),
        Series(
            "alive", COLOR_ALIVE,
            [r.get("ts", "") for r in valid_history],
            [r.get("alive", 0) for r in valid_history],
        ),
    ]
    return plot_lines(series, title="Unique & Alive trend")


def build_country(meta: dict) -> str:
    per_country = meta.get("per_country", {})
    items = sorted(per_country.items(), key=lambda kv: kv[1], reverse=True)[:15]
    return plot_hbars(items, title="Alive proxies by country (top 15)")


def build_port(meta: dict) -> str:
    per_port = meta.get("per_port", {})
    items = [(p, per_port[p]) for p in sorted(per_port, key=lambda p: int(p))]
    return plot_vbars(items, title="Alive proxies by port")


def build_alive_rate(valid_history: list[dict]) -> str:
    ts = [r.get("ts", "") for r in valid_history]
    rate = []
    dead = []
    for r in valid_history:
        checked = r.get("checked", 0)
        rate.append(round(r.get("alive", 0) / checked * 100, 1) if checked else 0)
        dead.append(r.get("dead", 0))
    series = [
        Series("alive rate", COLOR_RATE, ts, rate, axis="l"),
        Series("dead", COLOR_DEAD, ts, dead, axis="r"),
    ]
    return plot_lines(series, left_unit="%", title="Alive rate (%) & dead")


def build_churn(history: list[dict]) -> str:
    groups = [r.get("ts", "") for r in history]
    series = [
        Series("added", COLOR_ADDED, groups, [r.get("added", 0) for r in history]),
        Series("removed", COLOR_REMOVED, groups, [r.get("removed", 0) for r in history]),
    ]
    return plot_grouped_vbars(groups, series, title="Added / removed per update")


def build_combo(history: list[dict], valid_history: list[dict]) -> str:
    u_ts = [r.get("ts", "") for r in history]
    v_ts = [r.get("ts", "") for r in valid_history]
    pct = []
    for r in valid_history:
        checked = r.get("checked", 0)
        pct.append(round(r.get("alive", 0) / checked * 100, 1) if checked else 0)
    series = [
        Series("unique", COLOR_UNIQUE, u_ts, [r.get("unique", 0) for r in history]),
        Series("alive", COLOR_ALIVE, v_ts, [r.get("alive", 0) for r in valid_history]),
        Series("alive rate", COLOR_RATE, v_ts, pct, dash="dash", axis="r"),
    ]
    return plot_lines(
        series, right_unit="%", title="Unique / Alive / Alive rate"
    )


def build_latency(meta: dict) -> str:
    dist = meta.get("latency_dist", {})
    if not dist:
        return empty_svg(text="No latency data yet")
    return plot_vbars(
        list(dist.items()), color=COLOR_LATENCY, title="Alive proxies by latency (ms)"
    )


def build_speed(meta: dict) -> str:
    dist = meta.get("speed_dist", {})
    if not dist:
        return empty_svg(text="No speed data yet")
    return plot_vbars(
        list(dist.items()), color=COLOR_SPEED, title="Alive proxies by speed (MB/s)"
    )


def build_streaming(quality_meta: dict) -> str:
    streaming = quality_meta.get("streaming", {})
    items = [
        (name, streaming.get(name, {}).get("ok", 0))
        for name in ("netflix", "disney", "youtube", "max", "prime", "openai")
    ]
    if not any(v for _, v in items):
        return empty_svg(text="No streaming data yet")
    return plot_vbars(items, color=COLOR_STREAMING, title="Streaming unlock count")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUT_DIR, help="Output directory")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=OUT_DIR,
        help="Directory with inputs (history.jsonl, valid/); default: data/",
    )
    args = parser.parse_args(argv)

    now = datetime.now(timezone.utc).timestamp()
    data_dir = args.data_dir
    history = load_history(data_dir / "history.jsonl")
    valid_history = load_history(data_dir / "valid" / "history.jsonl")
    meta = read_json(data_dir / "valid" / "meta.json")
    quality_meta = read_json(data_dir / "valid" / "quality_meta.json")

    latest = history[-1] if history else {}
    sets = latest.get("sets", {})
    alive_sets = meta.get("sets", {})
    alive = meta.get("alive", 0)
    checked = meta.get("checked", 0)

    updated_epoch = to_epoch(latest.get("ts"))
    age_s = (now - updated_epoch) if updated_epoch is not None else None
    stale = age_s is not None and age_s > STALE_AFTER_S

    stats = {
        "ts": now_ts(),
        "updated_at": latest.get("ts"),
        "age_s": age_s,
        "updated_ago": fmt_ago(age_s) if age_s is not None else "-",
        "stale": bool(stale),
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
        "latency_dist": meta.get("latency_dist", {}),
        "speed": meta.get("speed", {}),
        "speed_dist": meta.get("speed_dist", {}),
        "streaming": quality_meta.get("streaming", {}),
        "streaming_ok": quality_meta.get("streaming_ok", 0),
        "ip_type": quality_meta.get("by_type", {}),
        "family": quality_meta.get("family", {}),
        "dual_stack": quality_meta.get("dual_stack", 0),
        "country_mismatch": quality_meta.get("country_mismatch", 0),
        "history_records": len(history),
        "alive_history_records": len(valid_history),
    }

    stats_file = args.out / "stats.json"
    write_atomic(stats_file, json.dumps(stats, ensure_ascii=False, indent=2) + "\n")
    print(f"Wrote {stats_file}")

    badge = {
        "schemaVersion": 1,
        "label": "status",
        "message": "stale" if stale else "fresh",
        "color": "red" if stale else "brightgreen",
    }
    badge_file = args.out / "badge.json"
    write_atomic(badge_file, json.dumps(badge) + "\n")
    print(f"Wrote {badge_file}")

    charts = {
        "chart.svg": build_trend(history, valid_history),
        "chart_country.svg": build_country(meta),
        "chart_port.svg": build_port(meta),
        "chart_alive_rate.svg": build_alive_rate(valid_history),
        "chart_churn.svg": build_churn(history),
        "chart_combo.svg": build_combo(history, valid_history),
        "chart_latency.svg": build_latency(meta),
        "chart_speed.svg": build_speed(meta),
        "chart_streaming.svg": build_streaming(quality_meta),
    }
    for name, content in charts.items():
        path = args.out / name
        write_atomic(path, content)
        print(f"Wrote {path}")

    p90 = stats["latency"].get("p90_ms")
    print(
        f"unique={stats['unique']} alive={alive}/{checked} "
        f"latency_p90={'-' if p90 is None else p90}ms"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
