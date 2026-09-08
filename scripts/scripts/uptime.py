#!/usr/bin/env python3
"""Rolling per-node uptime tracking.

Maintains ``data/quality/node_seen.json`` — for every proxy alive in the
latest quality round, record presence per run date (UTC). Prunes history
older than ``WINDOW_DAYS``. Emits ``data/quality/uptime.json`` with 7d /
30d availability percentages:

    {"proxies": {"<key>": {"pct7": 95, "pct30": 88,
                            "hits7": 20, "hits30": 66,
                            "last_seen": "2026-08-23"}},
     "runs7": 21, "runs30": 75, "ts": "..."}

``runsN`` = number of distinct quality-run dates inside the window and
serves as the denominator: a node present in every round scores 100.

Run after ``quality_check.py`` in the quality chain, before commit.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import QUALITY_DIR, read_json, write_text_if_changed  # noqa: E402

NODE_SEEN_FILE = QUALITY_DIR / "node_seen.json"
UPTIME_FILE = QUALITY_DIR / "uptime.json"

WINDOW_DAYS = 45


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def prune_days(days: dict[str, int], today: str) -> dict[str, int]:
    """Drop run-date counters older than WINDOW_DAYS."""
    cutoff_d = (
        datetime.strptime(today, "%Y-%m-%d").date().toordinal() - WINDOW_DAYS
    )
    out: dict[str, int] = {}
    for d, n in days.items():
        try:
            if datetime.strptime(d, "%Y-%m-%d").date().toordinal() >= cutoff_d:
                out[d] = n
        except ValueError:
            continue
    return out


def merge_seen(
    seen: dict, alive_keys: list[str], today: str
) -> tuple[dict[str, list[str]], dict[str, int]]:
    """Merge this round's alive keys into presence lists + run counters."""
    days: dict[str, int] = dict(seen.get("runs", {}))
    days[today] = days.get(today, 0) + 1
    days = prune_days(days, today)
    valid_dates = set(days)

    proxies: dict[str, list[str]] = {}
    keep = set(alive_keys)
    for key, dates in (seen.get("proxies") or {}).items():
        lst = sorted({d for d in dates if d in valid_dates})
        if key in keep:
            lst = sorted(set(lst) | {today})
        if lst:
            proxies[key] = lst
    # keys never seen before but alive now
    for key in keep:
        if key not in proxies:
            proxies[key] = [today]
    return proxies, days


def uptime_stats(
    proxies: dict[str, list[str]], days: dict[str, int]
) -> dict:
    """Compute pct7/pct30 from presence lists × run-date counters."""
    today_ord = max(
        (datetime.strptime(d, "%Y-%m-%d").date().toordinal() for d in days),
        default=0,
    )

    def runs_in(window: int) -> int:
        n = 0
        for d in days:
            do = datetime.strptime(d, "%Y-%m-%d").date().toordinal()
            if today_ord - do < window:
                n += days[d]
        return n

    runs7, runs30 = runs_in(7), runs_in(30)

    def hits_in(dates: list[str], window: int) -> int:
        return sum(
            1
            for d in dates
            if today_ord - datetime.strptime(d, "%Y-%m-%d").date().toordinal()
            < window
        )

    out: dict = {
        "proxies": {},
        "runs7": runs7,
        "runs30": runs30,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    for key, dates in proxies.items():
        h7, h30 = hits_in(dates, 7), hits_in(dates, 30)
        entry = {
            "pct7": round(h7 * 100 / runs7) if runs7 else None,
            "pct30": round(h30 * 100 / runs30) if runs30 else None,
            "hits7": h7,
            "hits30": h30,
            "last_seen": max(dates),
        }
        out["proxies"][key] = entry
    return out


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--alive-file",
        type=Path,
        default=QUALITY_DIR / "ipinfo.json",
        help="JSON whose proxies are this round's alive keys "
        "(default: data/quality/ipinfo.json)",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=QUALITY_DIR,
        help="Directory for node_seen.json / uptime.json",
    )
    args = ap.parse_args(argv)

    alive_data = read_json(args.alive_file)
    alive_keys = [
        k for k, v in (alive_data.get("proxies") or alive_data).items()
        if isinstance(v, dict)
    ]
    seen_path = args.out_dir / "node_seen.json"
    seen = read_json(seen_path) or {}
    proxies, days = merge_seen(seen, alive_keys, _today())
    stats = uptime_stats(proxies, days)

    write_text_if_changed(
        seen_path,
        json.dumps({"runs": days, "proxies": proxies}, ensure_ascii=False)
        + "\n",
    )
    write_text_if_changed(
        args.out_dir / "uptime.json",
        json.dumps(stats, ensure_ascii=False, indent=1) + "\n",
    )

    pcts = [v["pct7"] for v in stats["proxies"].values() if v["pct7"] is not None]
    avg = round(sum(pcts) / len(pcts)) if pcts else 0
    print(
        f"uptime: nodes={len(stats['proxies'])} runs7={stats['runs7']} "
        f"runs30={stats['runs30']} avg_pct7={avg}%"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
