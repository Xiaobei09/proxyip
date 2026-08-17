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
- ``chart_streaming.svg`` streaming ok/blocked/error per service (stacked bars)
- ``chart_sets.svg``      alive proxies per named set (horizontal bars)
- ``chart_cn.svg``        mainland-China reachability verdicts (horizontal bars)
- ``chart_family.svg``    actual exit IP family distribution (horizontal bars)
- ``chart_rep.svg``       reputation score distribution (vertical bars)

Line charts share a real-time x axis (series lacking usable timestamps fall
back to index spacing), zoom each y-axis to its data range so small variations
stay visible, and attach hover tooltips via inline ``<title>`` elements
(evenly sampled on dense series to keep output small).
"""

import argparse
import json
import math
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from common import OUT_DIR, now_ts

WIDTH = 800
HEIGHT = 300
MARGIN_L = 46
MARGIN_R = 46
MARGIN_T = 16
MARGIN_B = 34

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


def fmt_c(v: float) -> str:
    """Compact coordinate: drop the trailing ``.0`` for integer values."""
    if abs(v - round(v)) < 1e-9:
        return str(int(round(v)))
    return f"{v:.1f}"


def sample_indices(n: int, cap: int = 20) -> list[int]:
    """Evenly sample up to ``cap`` indices from ``range(n)``.

    First and last points are always kept so dense line series stay compact
    while hover tooltips remain available across the whole span.
    """
    if n <= cap:
        return list(range(n))
    out = {0, n - 1}
    for i in range(1, cap - 1):
        out.add(round(i * (n - 1) / (cap - 1)))
    return sorted(out)


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
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


CSS_STYLE = (
    "<style>"
    "text{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}"
    ".g{stroke:#e8e8e8;stroke-width:1}"
    ".a{stroke:#999;stroke-width:1}"
    ".t{font-size:9px;fill:#666}"
    ".m{font-size:9px;text-anchor:middle;fill:#666}"
    ".e{font-size:9px;text-anchor:end;fill:#666}"
    ".l{font-size:10px;fill:#333}"
    ".tt{font-size:11px;font-weight:600;text-anchor:middle;fill:#444}"
    "</style>"
)


def svg_head(width: int, height: int) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>'
        + CSS_STYLE
    )


def empty_svg(height: int = HEIGHT, text: str = "No data yet") -> str:
    return (
        svg_head(WIDTH, height)
        + f'<text class="m" x="{WIDTH / 2}" y="{height / 2}" font-size="13">'
        f"{esc(text)}</text>"
        + "</svg>"
    )


def render_title(title: str, height: int = HEIGHT) -> str:
    return f'<text class="tt" x="{WIDTH / 2}" y="{MARGIN_T}">{esc(title)}</text>'


def legend_svg(series: list[Series]) -> str:
    x = 14
    parts = []
    for s in series:
        if not s.values:
            continue
        sw = 18
        dash_attr = ' stroke-dasharray="4,3"' if s.dash else ""
        last = s.values[-1]
        parts.append(
            f'<line x1="{x}" y1="10" x2="{x + sw}" y2="10" '
            f'stroke="{s.color}" stroke-width="2"{dash_attr}/>'
            f'<text class="l" x="{x + sw + 4}" y="13">'
            f"{esc(s.name)} {last:g}</text>"
        )
        x += sw + 4 + len(f"{s.name} {last:g}") * 6.4 + 16
        x = float(f"{x:.1f}")
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
            f'<line class="g" x1="{MARGIN_L}" y1="{fmt_c(yy)}" '
            f'x2="{WIDTH - MARGIN_R}" y2="{fmt_c(yy)}"/>'
            f'<text class="e" x="{MARGIN_L - 6}" y="{fmt_c(yy + 3)}">'
            f"{fmt_tick(v)}{left_unit}</text>"
        )
    if right:
        for v in r_ticks:
            yy = y_of("r", v)
            parts.append(
                f'<text class="e" x="{WIDTH - 8}" y="{fmt_c(yy + 3)}">'
                f"{fmt_tick(v)}{right_unit}</text>"
            )
        parts.append(
            f'<line class="a" x1="{WIDTH - MARGIN_R}" y1="{MARGIN_T}" '
            f'x2="{WIDTH - MARGIN_R}" y2="{MARGIN_T + plot_h}"/>'
        )
    parts.append(
        f'<line class="a" x1="{MARGIN_L}" y1="{MARGIN_T}" x2="{MARGIN_L}" '
        f'y2="{MARGIN_T + plot_h}"/>'
        f'<line class="a" x1="{MARGIN_L}" y1="{MARGIN_T + plot_h}" x2="{WIDTH - MARGIN_R}" '
        f'y2="{MARGIN_T + plot_h}"/>'
    )

    total_pts = sum(len(s.values) for s in active)
    hover = total_pts <= MAX_HOVER_POINTS
    for s in active:
        xpts = x_for(s.ts, len(s.values))
        ypts = [y_of(s.axis, v) for v in s.values]
        pts = " ".join(f"{fmt_c(xpts[i])},{fmt_c(ypts[i])}" for i in range(len(s.values)))
        if len(s.values) == 1:
            parts.append(
                f'<circle cx="{fmt_c(xpts[0])}" cy="{fmt_c(ypts[0])}" r="3" fill="{s.color}"/>'
            )
        else:
            dash_attr = ' stroke-dasharray="4,3"' if s.dash else ""
            parts.append(
                f'<polyline fill="none" stroke="{s.color}" stroke-width="2"'
                f'{dash_attr} stroke-linejoin="round" points="{pts}"/>'
            )
        if hover:
            for i in sample_indices(len(s.values)):
                tip = f"{s.name}: {s.values[i]:g}"
                ts_txt = fmt_ts(s.ts[i]) if i < len(s.ts) else ""
                if ts_txt:
                    tip = f"{ts_txt} · {tip}"
                parts.append(
                    f'<circle cx="{fmt_c(xpts[i])}" cy="{fmt_c(ypts[i])}" r="4" '
                    f'fill="transparent"><title>{esc(tip)}</title></circle>'
                )
        if len(s.values) > 1:
            lx, ly = xpts[-1], ypts[-1]
            parts.append(
                f'<text class="t" x="{fmt_c(lx - 4)}" y="{fmt_c(ly - 4)}" '
                f'text-anchor="end" fill="{s.color}">{s.values[-1]:g}</text>'
            )

    for x, anchor, text in time_labels(active, use_time):
        cls = {"start": "t", "middle": "m", "end": "e"}.get(anchor, "t")
        parts.append(
            f'<text class="{cls}" x="{fmt_c(x)}" y="{height - 12}">'
            f"{esc(text)}</text>"
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
            f'<line class="g" x1="{fmt_c(gx)}" y1="{MARGIN_T}" '
            f'x2="{fmt_c(gx)}" y2="{MARGIN_T + body_h}"/>'
        )
    for i, (label, value) in enumerate(items):
        y0 = MARGIN_T + i * row_h + 2
        bar_h = row_h - 8
        bw = max(1.0, value / max_v * plot_w)
        parts.append(
            f'<text class="e" x="{left - 6}" y="{fmt_c(y0 + 9)}">'
            f"{esc(label)}</text>"
            f'<rect x="{fmt_c(left)}" y="{fmt_c(y0)}" width="{fmt_c(bw)}" '
            f'height="{fmt_c(bar_h)}" fill="{color}" rx="1.5"/>'
            f'<text class="t" x="{fmt_c(left + bw + 4)}" y="{fmt_c(y0 + 9)}">'
            f"{value}</text>"
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
            f'<line class="g" x1="{MARGIN_L}" y1="{fmt_c(yy)}" '
            f'x2="{WIDTH - MARGIN_R}" y2="{fmt_c(yy)}"/>'
            f'<text class="e" x="{MARGIN_L - 6}" y="{fmt_c(yy + 3)}">'
            f"{fmt_tick(v)}</text>"
        )
    parts.append(
        f'<line class="a" x1="{MARGIN_L}" y1="{MARGIN_T}" x2="{MARGIN_L}" '
        f'y2="{MARGIN_T + plot_h}"/>'
        f'<line class="a" x1="{MARGIN_L}" y1="{MARGIN_T + plot_h}" x2="{WIDTH - MARGIN_R}" '
        f'y2="{MARGIN_T + plot_h}"/>'
    )
    for i, (label, value) in enumerate(items):
        cx = MARGIN_L + (i + 0.5) * slot
        bh = value / max_v * plot_h
        y0 = MARGIN_T + plot_h - bh
        parts.append(
            f'<rect x="{fmt_c(cx - bar_w / 2)}" y="{fmt_c(y0)}" '
            f'width="{fmt_c(bar_w)}" height="{fmt_c(bh)}" fill="{color}" rx="1.5"/>'
            f'<text class="m" x="{fmt_c(cx)}" y="{fmt_c(y0 - 4)}">{value}</text>'
            f'<text class="m" x="{fmt_c(cx)}" y="{MARGIN_T + plot_h + 12}">'
            f"{esc(label)}</text>"
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
            f'<line class="g" x1="{MARGIN_L}" y1="{fmt_c(yy)}" '
            f'x2="{WIDTH - MARGIN_R}" y2="{fmt_c(yy)}"/>'
            f'<text class="e" x="{MARGIN_L - 6}" y="{fmt_c(yy + 3)}">'
            f"{fmt_tick(v)}</text>"
        )
    parts.append(
        f'<line class="a" x1="{MARGIN_L}" y1="{MARGIN_T}" x2="{MARGIN_L}" '
        f'y2="{MARGIN_T + plot_h}"/>'
        f'<line class="a" x1="{MARGIN_L}" y1="{MARGIN_T + plot_h}" x2="{WIDTH - MARGIN_R}" '
        f'y2="{MARGIN_T + plot_h}"/>'
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
                f'<rect x="{fmt_c(x0)}" y="{fmt_c(y0)}" '
                f'width="{fmt_c(bar_w)}" height="{fmt_c(bh)}" fill="{s.color}" rx="1"/>'
            )
    first_x = MARGIN_L
    last_x = MARGIN_L + (n - 1) * slot
    parts.append(
        f'<text class="t" x="{first_x}" y="{MARGIN_T + plot_h + 12}">'
        f"{esc(fmt_ts(groups[0]))}</text>"
        f'<text class="e" x="{fmt_c(last_x)}" y="{MARGIN_T + plot_h + 12}">'
        f"{esc(fmt_ts(groups[-1]))}</text>"
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


def plot_stacked_vbars(
    groups: list[str],
    layers: list[Series],
    *,
    title: str | None = None,
) -> str:
    """Vertical stacked bars; each ``Series`` is one layer (bottom to top)."""
    n = len(groups)
    if n == 0 or not any(s.values for s in layers):
        return empty_svg()
    plot_w = WIDTH - MARGIN_L - MARGIN_R
    plot_h = HEIGHT - MARGIN_T - MARGIN_B
    totals = [
        sum(s.values[i] for s in layers if i < len(s.values)) for i in range(n)
    ]
    max_v = max(totals, default=0) or 1
    slot = plot_w / n
    bar_w = max(14, min(80, slot * 0.55))

    parts = [svg_head(WIDTH, HEIGHT)]
    if title:
        parts.append(render_title(title, HEIGHT))
    for v in nice_ticks(max_v):
        yy = MARGIN_T + plot_h - v / max_v * plot_h
        parts.append(
            f'<line class="g" x1="{MARGIN_L}" y1="{fmt_c(yy)}" '
            f'x2="{WIDTH - MARGIN_R}" y2="{fmt_c(yy)}"/>'
            f'<text class="e" x="{MARGIN_L - 6}" y="{fmt_c(yy + 3)}">'
            f"{fmt_tick(v)}</text>"
        )
    parts.append(
        f'<line class="a" x1="{MARGIN_L}" y1="{MARGIN_T}" x2="{MARGIN_L}" '
        f'y2="{MARGIN_T + plot_h}"/>'
        f'<line class="a" x1="{MARGIN_L}" y1="{MARGIN_T + plot_h}" x2="{WIDTH - MARGIN_R}" '
        f'y2="{MARGIN_T + plot_h}"/>'
    )
    for i in range(n):
        cx = MARGIN_L + (i + 0.5) * slot
        y_top = MARGIN_T + plot_h
        for s in layers:
            value = s.values[i] if i < len(s.values) else 0
            bh = value / max_v * plot_h
            y0 = y_top - bh
            parts.append(
                f'<rect x="{fmt_c(cx - bar_w / 2)}" y="{fmt_c(y0)}" '
                f'width="{fmt_c(bar_w)}" height="{fmt_c(bh)}" fill="{s.color}" rx="1"/>'
            )
            y_top = y0
        total = totals[i]
        parts.append(
            f'<text class="m" x="{fmt_c(cx)}" y="{fmt_c(y_top - 4)}">{total}</text>'
            f'<text class="m" x="{fmt_c(cx)}" y="{MARGIN_T + plot_h + 12}">'
            f"{esc(groups[i])}</text>"
        )
    parts.append(legend_svg(layers))
    parts.append("</svg>")
    return "\n".join(parts)


def build_streaming(quality_meta: dict) -> str:
    streaming = quality_meta.get("streaming", {})
    names = ("netflix", "disney", "youtube", "max", "prime", "openai")
    if not any(streaming.get(n, {}).get("ok", 0) for n in names):
        return empty_svg(text="No streaming data yet")
    layers = [
        Series(
            "ok", "#72b7b2", list(names),
            [streaming.get(n, {}).get("ok", 0) for n in names],
        ),
        Series(
            "blocked", "#e45756", list(names),
            [streaming.get(n, {}).get("blocked", 0) for n in names],
        ),
        Series(
            "error", "#9c9c9c", list(names),
            [streaming.get(n, {}).get("error", 0) for n in names],
        ),
    ]
    return plot_stacked_vbars(
        list(names), layers, title="Streaming unlock (ok / blocked / error)"
    )


def build_sets(meta: dict) -> str:
    sets_data = meta.get("sets", {})
    items = sorted(sets_data.items(), key=lambda kv: kv[1], reverse=True)
    if not items:
        return empty_svg(text="No set data yet")
    return plot_hbars(items, row_h=15, color=COLOR_PORT, title="Alive proxies by set")


def _count_by(china_data: dict, field: str) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for v in china_data.get("proxies", {}).values():
        if not isinstance(v, dict):
            continue
        key = v.get(field)
        if key is None:
            continue
        counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)


def build_cn(china_data: dict) -> str:
    items = _count_by(china_data, "verdict")
    if not items:
        return empty_svg(text="No CN data yet")
    return plot_hbars(items, color=COLOR_SPEED, title="Mainland China reachability")


def build_family(family_data: dict) -> str:
    items = _count_by(family_data, "family")
    if not items:
        return empty_svg(text="No family data yet")
    return plot_hbars(items, color=COLOR_ALIVE, title="Exit IP family distribution")


def build_rep(rep_data: dict) -> str:
    buckets: dict[int, int] = {}
    for v in rep_data.get("proxies", {}).values():
        if not isinstance(v, dict):
            continue
        score = v.get("score")
        if score is None:
            continue
        b = int(score) // 10 * 10
        buckets[b] = buckets.get(b, 0) + 1
    if not buckets:
        return empty_svg(text="No reputation data yet")
    items = [
        (f"{lo}-{lo + 9}", buckets.get(lo, 0))
        for lo in sorted(buckets)
    ]
    return plot_vbars(items, color=COLOR_STREAMING, title="Reputation score distribution")


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
    china_data = read_json(data_dir / "valid" / "china.json")
    family_data = read_json(data_dir / "valid" / "exit_family.json")
    rep_data = read_json(data_dir / "valid" / "reputation.json")

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
        "chart_sets.svg": build_sets(meta),
        "chart_cn.svg": build_cn(china_data),
        "chart_family.svg": build_family(family_data),
        "chart_rep.svg": build_rep(rep_data),
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
