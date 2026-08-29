#!/usr/bin/env python3
"""Generate repository statistics and a set of dependency-free SVG charts.

Reads ``data/quality/history.jsonl`` and ``data/valid/history.jsonl`` plus
``data/valid/meta.json`` and writes ``data/output/stats.json`` together with:

- ``chart_combo.svg``        proxy count & alive rate (dual-axis lines)
- ``chart_country.svg``      alive proxies per country (horizontal bars, top 15)
- ``chart_port.svg``         alive proxies per port (vertical bars)
- ``chart_churn.svg``        added / removed per update (grouped bars)
- ``chart_latency_speed.svg`` latency & speed distribution (dual-panel bars)
- ``chart_sets.svg``         alive proxies per named set (horizontal bars)
- ``chart_cn.svg``           mainland-China reachability verdicts (horizontal bars)
- ``chart_family.svg``       actual exit IP family distribution (horizontal bars)
- ``chart_exit.svg``         exit country top 15 (four-source →CC observations)
- ``chart_entry_audit.svg``  entry CC label audit verdicts (tag mismatch rate)
- ``chart_ip_type.svg``      IP type distribution (DC/RES/MOB/PROXY)
- ``chart_source_avail.svg`` IP source coverage + sources-per-proxy (composite)
- ``chart_source_stats.svg`` per-download-source IP count & overlap (stacked bars)
- ``chart_rep.svg``          reputation score distribution (vertical bars)

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

from common import DATA_DIR, OUTPUT_DIR, now_ts, read_json, write_text_if_changed

SPEED_NOTE_RE = __import__("re").compile(r"(\d+(?:\.\d+)?)MB/s")

WIDTH = 800
HEIGHT = 300
MARGIN_L = 46
MARGIN_R = 46
MARGIN_T = 24
MARGIN_B = 34

COLOR_UNIQUE = "#4c78a8"
COLOR_ALIVE = "#54a24b"
COLOR_RATE = "#f58518"
COLOR_DEAD = "#8c564b"
COLOR_ADDED = "#72b7b2"
COLOR_REMOVED = "#e45756"
COLOR_BAR = "#4c78a8"
COLOR_PORT = "#58508d"
COLOR_LATENCY = "#b07d2e"
COLOR_SPEED = "#1a7a8a"
COLOR_STREAMING = "#9b59b6"
COLOR_SOURCE = "#2ecc71"
COLOR_OK = "#72b7b2"
COLOR_BLOCKED = "#e45756"
COLOR_ERROR = "#9c9c9c"

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


CSS_STYLE = (
    "<style>"
    "text{font-family:system-ui,-apple-system,'Segoe UI',Roboto,"
    "'PingFang SC','Microsoft YaHei','Noto Sans CJK SC',sans-serif}"
    ".g{stroke:#e8e8e8;stroke-width:1}"
    ".a{stroke:#999;stroke-width:1}"
    ".t{font-size:10px;fill:#666}"
    ".m{font-size:10px;text-anchor:middle;fill:#666}"
    ".e{font-size:10px;text-anchor:end;fill:#666}"
    ".l{font-size:11px;fill:#333}"
    ".tt{font-size:14px;font-weight:600;text-anchor:middle;fill:#444}"
    ".em{font-size:13px;text-anchor:middle;fill:#999}"
    "</style>"
)


def svg_head(width: int, height: int) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>'
        + CSS_STYLE
    )


def empty_svg(height: int = HEIGHT, text: str = "暂无数据") -> str:
    return (
        svg_head(WIDTH, height)
        + f'<text class="em" x="{WIDTH / 2}" y="{height / 2}">'
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
            f'<line x1="{x}" y1="20" x2="{x + sw}" y2="20" '
            f'stroke="{s.color}" stroke-width="2"{dash_attr}/>'
            f'<text class="l" x="{x + sw + 4}" y="23">'
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


def build_country(meta: dict) -> str:
    per_country = meta.get("per_country", {})
    items = sorted(per_country.items(), key=lambda kv: kv[1], reverse=True)[:15]
    return plot_hbars(items, title="各国家存活代理 Top15")


def build_port(meta: dict) -> str:
    per_port = meta.get("per_port", {})
    items = [(p, per_port[p]) for p in sorted(per_port, key=lambda p: int(p))]
    if not items:
        return empty_svg(text="暂无按端口数据")
    return plot_vbars(items, title="按端口统计存活代理")


def build_churn(history: list[dict]) -> str:
    groups = [r.get("ts", "") for r in history]
    series = [
        Series("新增", COLOR_ADDED, groups, [r.get("added", 0) for r in history]),
        Series("移除", COLOR_REMOVED, groups, [r.get("removed", 0) for r in history]),
    ]
    return plot_grouped_vbars(groups, series, title="每次更新 新增 / 移除")


def build_combo(history: list[dict], valid_history: list[dict]) -> str:
    u_ts = [r.get("ts", "") for r in history]
    v_ts = [r.get("ts", "") for r in valid_history]
    pct = []
    for r in valid_history:
        checked = r.get("checked", 0)
        pct.append(round(r.get("alive", 0) / checked * 100, 1) if checked else 0)
    series = [
        Series("去重", COLOR_UNIQUE, u_ts, [r.get("unique", 0) for r in history]),
        Series("存活", COLOR_ALIVE, v_ts, [r.get("alive", 0) for r in valid_history]),
        Series("死亡", COLOR_DEAD, v_ts, [r.get("dead", 0) for r in valid_history], dash="dash"),
        Series("存活率", COLOR_RATE, v_ts, pct, dash="dot", axis="r"),
    ]
    return plot_lines(
        series, right_unit="%", title="代理总量与存活率"
    )


def build_latency_speed(meta: dict) -> str:
    lat = meta.get("latency_dist", {})
    spd = meta.get("speed_dist", {})
    if not lat and not spd:
        return empty_svg(text="暂无延迟/速度数据")
    panel_h = 180
    total_h = panel_h * 2 + MARGIN_T + MARGIN_B
    parts = [svg_head(WIDTH, total_h)]
    parts.append(f'<text class="tt" x="{WIDTH / 2}" y="{MARGIN_T}">'
                 "Latency (ms) &amp; speed (MB/s)</text>")
    for idx, (dist, color, label) in enumerate([
        (lat, COLOR_LATENCY, "Latency (ms)"),
        (spd, COLOR_SPEED, "Speed (MB/s)"),
    ]):
        if not dist:
            continue
        y_off = MARGIN_T + 20 + idx * panel_h
        plot_w = WIDTH - MARGIN_L - MARGIN_R
        n = len(dist)
        if n == 0:
            continue
        slot = plot_w / n
        vals = list(dist.values())
        mx = max(vals) if vals else 1
        if mx == 0:
            mx = 1
        bw = max(14, min(80, slot * 0.55))
        ph = panel_h - MARGIN_T - 8
        parts.append(f'<text class="tt" x="{WIDTH / 2}" y="{y_off}">{esc(label)}</text>')
        plot_y = y_off + 8
        for i, (k, v) in enumerate(dist.items()):
            cx = MARGIN_L + slot * i + slot / 2
            bh = max(2, v / mx * ph)
            by = plot_y + ph - bh
            parts.append(
                f'<rect x="{cx - bw / 2}" y="{by}" width="{bw}" '
                f'height="{bh}" fill="{color}" rx="1.5">'
                f"<title>{esc(k)}: {v}</title></rect>"
            )
            parts.append(
                f'<text class="m" x="{cx}" y="{by - 3}">{v}</text>'
            )
            parts.append(
                f'<text class="m" x="{cx}" y="{plot_y + ph + 12}">{esc(k)}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


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


def build_sets(meta: dict) -> str:
    sets_data = meta.get("sets", {})
    items = sorted(sets_data.items(), key=lambda kv: kv[1], reverse=True)
    if not items:
        return empty_svg(text="暂无子集数据")
    return plot_hbars(items, row_h=15, color=COLOR_PORT, title="按子集统计存活代理")


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


VERDICT_ZH = {
    "reachable": "可达",
    "uncertain": "不确定",
    "unreachable": "不可达",
    "pending": "待测",
}


def build_cn(china_data: dict) -> str:
    items = _count_by(china_data, "verdict")
    if not items:
        return empty_svg(text="暂无大陆可达性数据")
    labels = [
        (f"{VERDICT_ZH.get(cc, cc)} ({cc})", n) if cc in VERDICT_ZH
        else (cc, n)
        for cc, n in items
    ]
    return plot_hbars(
        labels, color=COLOR_SPEED, title="中国大陆可达性判定"
    )


def build_family(family_data: dict) -> str:
    items = _count_by(family_data, "family")
    if not items:
        return empty_svg(text="暂无出口族数据")
    return plot_hbars(items, color=COLOR_ALIVE, title="出口 IP 族分布")


def build_exit_cc(quality_dir: Path) -> str:
    """出口国分布 Top15（common.build_exit_cc_map 三源汇聚，→CC 观测）。"""
    from common import build_exit_cc_map

    m = build_exit_cc_map(
        read_json(quality_dir / "ipinfo.json"),
        read_json(quality_dir / "external_check.json"),
        read_json(quality_dir / "upstream_meta.json"),
        read_json(quality_dir / "exit_family.json"),
    )
    counts: dict[str, int] = {}
    for cc in m.values():
        counts[cc] = counts.get(cc, 0) + 1
    items = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:15]
    if not items:
        return empty_svg(text="暂无出口国数据")
    return plot_hbars(
        items, color=COLOR_PORT,
        title=f"出口国 Top15（共观测 {len(m)}）",
    )


def build_entry_audit(audit_data: dict) -> str:
    """入口国家标签审计 verdict 分布（audit_entry_cc.py 产出）。"""
    summary = audit_data.get("summary", {})
    total = audit_data.get("total", 0)
    items = sorted(summary.items(), key=lambda kv: kv[1], reverse=True)
    if not items:
        return empty_svg(text="暂无入口标签审计数据")
    mism = summary.get("tag_mismatch", 0)
    return plot_hbars(
        items, color=COLOR_LATENCY,
        title=f"入口国家标签审计（不匹配 {mism}/{total} "
              f"= {mism / max(total, 1) * 100:.1f}%）",
    )


def build_ip_type(quality_meta: dict) -> str:
    """IP 类型分布（DC/RES/MOB/PROXY）。"""
    items = sorted(quality_meta.get("by_type", {}).items(),
                   key=lambda kv: kv[1], reverse=True)
    if not items:
        return empty_svg(text="暂无 IP 类型数据")
    return plot_hbars(items, color=COLOR_STREAMING, title="IP 类型分布")


def collect_cn_summary(china_data: dict, valid_dir: Path) -> dict:
    """CN 池规模：``reachable`` = china.json 当前判定（真相）；
    ``http``/``stable``/``served`` = 实际落盘文件行数。

    注意 china_check 对空子集「不写盘」，重启/横波动后旧子集文件可能
    短暂残留（设计使然，守住既定清单）；stats 因此以文件行数为口径，
    让消费者看到真正可下载的规模，而非可能被清空的规则计值。
    """
    reachable = sum(
        1
        for v in (china_data.get("proxies") or {}).values()
        if isinstance(v, dict) and v.get("verdict") == "reachable"
    )
    def _lines(*parts: str) -> int:
        p = valid_dir.joinpath(*parts)
        if not p.exists():
            return 0
        with p.open(encoding="utf-8") as fh:
            return sum(1 for _ in fh)

    return {
        "reachable": reachable,
        "http": _lines("all_cn_http.txt"),
        "stable": _lines("all_cn_stable.txt"),
        "served": _lines("all_cn.txt"),
        "ts": china_data.get("ts"),
    }


def collect_country_speed(valid_dir: Path) -> dict[str, dict]:
    """各国速度分布：从 countries/<CC>/all.txt 行内 MB/s 聚合。

    返回 ``{CC: {n, p25, p50, p75, max, spread}}``，``spread`` 为四分位
    差距 ``(p75-p25)/p50``（百分比，衡量同国内部速度分化程度；样本 <5
    的国家跳过）。这是对"不同国家差距大、同国却趋同"的直接量化——
    同国趋同主要源于 CDN 本地化 + 小窗口采样，深测(deep_speed)可拉开。
    """
    import statistics

    out: dict[str, dict] = {}
    cdir = valid_dir / "countries"
    if not cdir.is_dir():
        return out
    for cc_dir in sorted(cdir.iterdir()):
        pool = cc_dir / "all.txt"
        if not cc_dir.is_dir() or not pool.exists():
            continue
        vals = []
        for ln in pool.read_text(encoding="utf-8").splitlines():
            m = SPEED_NOTE_RE.search(ln)
            if m:
                vals.append(float(m.group(1)))
        if len(vals) < 5:
            continue
        vals.sort()
        q = statistics.quantiles(vals, n=4)
        p50 = q[1]
        spread = round((q[2] - q[0]) / p50 * 100) if p50 > 0 else 0
        out[cc_dir.name] = {
            "n": len(vals),
            "p25": round(q[0], 2),
            "p50": round(p50, 2),
            "p75": round(q[2], 2),
            "max": round(vals[-1], 2),
            "spread_pct": spread,
        }
    return out


def build_country_speed(country_speed: dict[str, dict]) -> str:
    """中位速度 Top-20 国家（横条，标签含 p25–p75 区间与样本数）。"""
    items = sorted(
        country_speed.items(), key=lambda kv: kv[1]["p50"], reverse=True
    )[:20]
    if not items:
        return empty_svg(text="暂无速度数据")
    # 真实 MB/s 直出（不再缩放 ×0.01）：条宽按最大值等比例，尾部数值即真实速度
    bars = [(f"{cc}", round(d["p50"], 2)) for cc, d in items]
    svg = plot_hbars(bars, color=COLOR_SPEED,
                     title="各国中位速度（MB/s）")
    # 追加区间注释行：在标题下方列出前 5 国的 IQR
    notes = " · ".join(
        f"{cc} 样本{d['n']} 中位区间[{d['p25']}-{d['p75']}]"
        for cc, d in items[:5]
    )
    return svg.replace(
        "</svg>",
        f'<text class="l" x="8" y="13">{esc(notes)}</text></svg>'
    )


def build_speed_spread(country_speed: dict[str, dict]) -> str:
    """同国内部分化 Top-20：四分位差 (p75-p25)/p50 百分比。"""
    items = sorted(
        ((cc, d) for cc, d in country_speed.items() if d["spread_pct"] > 0),
        key=lambda kv: kv[1]["spread_pct"], reverse=True,
    )[:20]
    if not items:
        return empty_svg(text="暂无同国分化数据")
    bars = [(f"{cc} 样本{d['n']}", d["spread_pct"]) for cc, d in items]
    return plot_hbars(bars, color=COLOR_BAR,
                      title="同国内速度分化（四分位差/中位数 %）")


def build_source_avail(rep_data: dict) -> str:
    """Combined chart: per-source coverage + sources-per-proxy distribution."""
    proxies = rep_data.get("proxies", {})
    if not proxies:
        return empty_svg(text="暂无信誉源数据")

    source_counts: dict[str, int] = {}
    depth_counts: dict[int, int] = {}
    for v in proxies.values():
        if not isinstance(v, dict):
            continue
        srcs = v.get("sources") or []
        for s in srcs:
            source_counts[s] = source_counts.get(s, 0) + 1
        depth_counts[len(srcs)] = depth_counts.get(len(srcs), 0) + 1

    if not source_counts:
        return empty_svg(text="暂无信誉源数据")

    src_items = sorted(source_counts.items(), key=lambda x: -x[1])
    depth_items = [(str(k), v) for k, v in sorted(depth_counts.items())]

    total_h = 310
    src_h = MARGIN_T + len(src_items) * 18 + 8
    gap = 12

    parts = [svg_head(WIDTH, total_h)]
    max_sv = max(v for _, v in src_items) or 1
    plot_w = WIDTH - MARGIN_L - MARGIN_R - 46

    parts.append(
        f'<text class="tt" x="{WIDTH / 2}" y="12">IP source coverage</text>'
    )

    y_off = 20
    for i, (label, value) in enumerate(src_items):
        y0 = y_off + i * 18 + 2
        bw = max(1.0, value / max_sv * plot_w)
        parts.append(
            f'<text class="e" x="{MARGIN_L - 6}" y="{fmt_c(y0 + 9)}">'
            f"{esc(label)}</text>"
            f'<rect x="{fmt_c(MARGIN_L)}" y="{fmt_c(y0)}" width="{fmt_c(bw)}" '
            f'height="10" fill="{COLOR_SOURCE}" rx="1.5"/>'
            f'<text class="t" x="{fmt_c(MARGIN_L + bw + 4)}" y="{fmt_c(y0 + 9)}">'
            f"{value}</text>"
        )

    y_off += len(src_items) * 18 + gap + 6
    parts.append(
        f'<text class="tt" x="{WIDTH / 2}" y="{y_off}">Sources per proxy</text>'
    )
    y_off += 8

    if depth_items:
        max_dv = max(v for _, v in depth_items) or 1
        n = len(depth_items)
        slot = plot_w / n
        bar_w = max(14, min(80, slot * 0.55))
        dp_h = total_h - y_off - MARGIN_B

        for v in nice_ticks(max_dv):
            yy = y_off + dp_h - v / max_dv * dp_h
            parts.append(
                f'<line class="g" x1="{MARGIN_L}" y1="{fmt_c(yy)}" '
                f'x2="{WIDTH - MARGIN_R}" y2="{fmt_c(yy)}"/>'
                f'<text class="e" x="{MARGIN_L - 6}" y="{fmt_c(yy + 3)}">'
                f"{fmt_tick(v)}</text>"
            )
        parts.append(
            f'<line class="a" x1="{MARGIN_L}" y1="{y_off}" x2="{MARGIN_L}" '
            f'y2="{y_off + dp_h}"/>'
            f'<line class="a" x1="{MARGIN_L}" y1="{y_off + dp_h}" '
            f'x2="{WIDTH - MARGIN_R}" y2="{y_off + dp_h}"/>'
        )
        for i, (label, value) in enumerate(depth_items):
            cx = MARGIN_L + (i + 0.5) * slot
            bh = value / max_dv * dp_h
            y0 = y_off + dp_h - bh
            parts.append(
                f'<rect x="{fmt_c(cx - bar_w / 2)}" y="{fmt_c(y0)}" '
                f'width="{fmt_c(bar_w)}" height="{fmt_c(bh)}" '
                f'fill="{COLOR_SOURCE}" rx="1.5"/>'
                f'<text class="m" x="{fmt_c(cx)}" y="{fmt_c(y0 - 4)}">{value}</text>'
                f'<text class="m" x="{fmt_c(cx)}" y="{y_off + dp_h + 12}">'
                f"{esc(label)}</text>"
            )

    parts.append("</svg>")
    return "\n".join(parts)


def build_source_stats(source_stats: dict) -> str:
    """Stacked horizontal bar chart: per-download-source unique vs overlap IPs."""
    sources = source_stats.get("sources", {})
    if not sources:
        return empty_svg(text="暂无信誉源统计")

    items = sorted(sources.items(), key=lambda kv: -kv[1].get("total", 0))
    n = len(items)
    if n == 0:
        return empty_svg(text="暂无信誉源统计")

    row_h = 22
    total_h = MARGIN_T + n * row_h + 12
    plot_w = WIDTH - MARGIN_L - MARGIN_R - 56
    max_total = max(v.get("total", 0) for _, v in items) or 1

    parts = [svg_head(WIDTH, total_h)]
    parts.append(
        f'<text class="tt" x="{WIDTH / 2}" y="12">'
        "Download source IP stats</text>"
    )

    for i, (label, v) in enumerate(items):
        total = v.get("total", 0)
        unique = v.get("unique", 0)
        overlap = v.get("overlap", 0)
        y0 = MARGIN_T + i * row_h + 2
        bar_h = row_h - 8

        # Unique segment (green)
        uw = max(1.0, unique / max_total * plot_w) if unique else 0
        # Overlap segment (red), stacked after unique
        ow = max(1.0, overlap / max_total * plot_w) if overlap else 0

        segs = ""
        x = MARGIN_L
        if unique:
            segs += (
                f'<rect x="{fmt_c(x)}" y="{fmt_c(y0)}" width="{fmt_c(uw)}" '
                f'height="{fmt_c(bar_h)}" fill="{COLOR_ALIVE}" rx="1.5"/>'
            )
            x += uw
        if overlap:
            segs += (
                f'<rect x="{fmt_c(x)}" y="{fmt_c(y0)}" width="{fmt_c(ow)}" '
                f'height="{fmt_c(bar_h)}" fill="{COLOR_BLOCKED}" rx="1.5"/>'
            )
            x += ow

        # Label + count
        count_text = f"{total}"
        if overlap:
            count_text += f" ({overlap} dup)"
        parts.append(
            f'<text class="e" x="{MARGIN_L - 6}" y="{fmt_c(y0 + 9)}">'
            f"{esc(label)}</text>"
            f"{segs}"
            f'<text class="t" x="{fmt_c(x + 4)}" y="{fmt_c(y0 + 9)}">'
            f"{count_text}</text>"
        )

    parts.append("</svg>")
    return "\n".join(parts)


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
        return empty_svg(text="暂无信誉分数据")
    items = [
        (f"{lo}-{lo + 9}", buckets.get(lo, 0))
        for lo in sorted(buckets)
    ]
    return plot_vbars(items, color=COLOR_STREAMING, title="信誉评分分布")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUTPUT_DIR, help="Output directory")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DATA_DIR,
        help="Directory with inputs (quality/, valid/); default: data/",
    )
    args = parser.parse_args(argv)

    now = datetime.now(timezone.utc).timestamp()
    data_dir = args.data_dir
    history = load_history(data_dir / "quality" / "history.jsonl")
    valid_history = load_history(data_dir / "valid" / "history.jsonl")
    meta = read_json(data_dir / "valid" / "meta.json")
    quality_meta = read_json(data_dir / "quality" / "quality_meta.json")
    china_data = read_json(data_dir / "quality" / "china.json")
    family_data = read_json(data_dir / "quality" / "exit_family.json")
    family_counts = dict(_count_by(family_data, "family"))
    entry_audit = read_json(data_dir / "quality" / "entry_audit.json")
    rep_data = read_json(data_dir / "quality" / "reputation.json")
    source_stats = read_json(data_dir / "quality" / "source_stats.json")
    country_speed = collect_country_speed(data_dir / "valid")
    cs_file = args.out / "country_speed.json"
    write_text_if_changed(cs_file, json.dumps(country_speed, ensure_ascii=False,
                                             sort_keys=True) + "\n")
    print(f"Wrote {cs_file} ({len(country_speed)} countries)")

    latest = history[-1] if history else (valid_history[-1] if valid_history else {})
    sets = latest.get("sets", {})
    alive_sets = meta.get("sets", {})
    alive = meta.get("alive", 0)
    checked = meta.get("checked", 0)

    updated_epoch = to_epoch(latest.get("ts"))
    age_s = (now - updated_epoch) if updated_epoch is not None else None
    stale = age_s is not None and age_s > STALE_AFTER_S

    unique = latest.get("unique") or latest.get("total", 0)
    cn_summary = collect_cn_summary(china_data, data_dir / "valid")
    stats = {
        "ts": now_ts(),
        "updated_at": latest.get("ts"),
        "age_s": age_s,
        "updated_ago": fmt_ago(age_s) if age_s is not None else "-",
        "stale": bool(stale),
        "unique": unique,
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
        "ip_type": quality_meta.get("by_type", {}),
        "family": dict(family_counts),
        "dual_stack": family_counts.get("dual", 0),
        "country_mismatch": quality_meta.get("country_mismatch", 0),
        "history_records": len(history),
        "alive_history_records": len(valid_history),
        "cn_reachable": cn_summary["reachable"],
        "cn_http": cn_summary["http"],
        "cn_stable": cn_summary["stable"],
        "cn_served": cn_summary["served"],
        "cn_ts": cn_summary["ts"],
    }

    stats_file = args.out / "stats.json"
    write_text_if_changed(stats_file, json.dumps(stats, ensure_ascii=False, indent=2) + "\n")
    print(f"Wrote {stats_file}")

    badge = {
        "schemaVersion": 1,
        "label": "status",
        "message": "stale" if stale else "fresh",
        "color": "red" if stale else "brightgreen",
    }
    badge_file = args.out / "badge.json"
    write_text_if_changed(badge_file, json.dumps(badge) + "\n")
    print(f"Wrote {badge_file}")

    charts = {
        "chart_combo.svg": build_combo(history, valid_history),
        "chart_country.svg": build_country(meta),
        "chart_port.svg": build_port(meta),
        "chart_churn.svg": build_churn(history),
        "chart_latency_speed.svg": build_latency_speed(meta),
        "chart_sets.svg": build_sets(meta),
        "chart_cn.svg": build_cn(china_data),
        "chart_family.svg": build_family(family_data),
        "chart_exit.svg": build_exit_cc(data_dir / "quality"),
        "chart_entry_audit.svg": build_entry_audit(entry_audit),
        "chart_ip_type.svg": build_ip_type(quality_meta),
        "chart_country_speed.svg": build_country_speed(country_speed),
        "chart_speed_spread.svg": build_speed_spread(country_speed),
        "chart_source_avail.svg": build_source_avail(rep_data),
        "chart_source_stats.svg": build_source_stats(source_stats),
        "chart_rep.svg": build_rep(rep_data),
    }
    for name, content in charts.items():
        path = args.out / name
        write_text_if_changed(path, content)
        print(f"Wrote {path}")

    p90 = stats["latency"].get("p90_ms")
    print(
        f"unique={stats['unique']} alive={alive}/{checked} "
        f"latency_p90={'-' if p90 is None else p90}ms"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
