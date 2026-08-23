#!/usr/bin/env python3
"""Pool health watchdog with webhook alerting.

Compares the latest round against recent history and fires alerts when:

- **pool crash**  — alive count dropped > ``POOL_DROP_PCT`` (default 30%)
                    vs the median of the previous day's rounds;
- **CN collapse** — china.json reachable count dropped > ``CN_DROP_PCT``
                    (default 50%) vs the previous round's snapshot stored
                    in the alert state file;
- **stale data**  — newest history record older than ``STALE_HOURS``
                    (default 8h).

Delivery: POSTs JSON to the URL in ``$ALERT_WEBHOOK_URL`` (Discord uses
``{"content": ...}``, Slack ``{"text": ...}`` — both are sent). Without
the env var, alerts only print to stderr. State (last CN count) persists
in ``data/quality/alert_state.json`` so cross-run drops are detectable.

Exit code is always 0 unless ``--strict`` (alerts → exit 1 for CI gating).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import CHINA_FILE, QUALITY_DIR, read_json  # noqa: E402

HISTORY_FILE = QUALITY_DIR / "history.jsonl"
VALID_HISTORY_FILE = QUALITY_DIR.parent / "valid" / "history.jsonl"
STATE_FILE = QUALITY_DIR / "alert_state.json"

POOL_DROP_PCT = 30
CN_DROP_PCT = 50
STALE_HOURS = 8


def _now() -> datetime:
    return datetime.now(timezone.utc)


def load_history(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return sorted(out, key=lambda r: r.get("ts", ""))


def _median(nums: list[float]) -> float:
    s = sorted(nums)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def check_pool(history: list[dict], drop_pct: float = POOL_DROP_PCT) -> str | None:
    """Alive-count crash vs median of previous rounds (~最近 24 轮)。"""
    pts = [r for r in history if isinstance(r.get("alive"), int)]
    base_nums = [r["alive"] for r in pts[:-1]]
    if len(base_nums) < 2:
        return None
    med = _median(base_nums[-24:])
    if med <= 0:
        return None
    cur = pts[-1]["alive"]
    drop = (med - cur) / med * 100
    if drop >= drop_pct:
        return (
            f"pool crash: alive {cur} vs median {int(med)} "
            f"(-{drop:.0f}%) at {pts[-1].get('ts')}"
        )
    return None


def _ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return _now()


def check_stale(history: list[dict], hours: float = STALE_HOURS) -> str | None:
    """Newest record too old → pipeline silently broken."""
    if not history:
        return "no history records at all"
    age_h = (_now() - _ts(history[-1].get("ts", ""))).total_seconds() / 3600
    if age_h > hours:
        return f"stale data: last record {age_h:.1f}h ago (> {hours}h)"
    return None


def check_cn(state: dict, cn_file: Path, drop_pct: float = CN_DROP_PCT) -> tuple[str | None, dict]:
    """Reachable-count collapse vs persisted previous-round snapshot."""
    proxies = read_json(cn_file).get("proxies", {})
    cur = sum(
        1
        for v in proxies.values()
        if isinstance(v, dict) and v.get("verdict") == "reachable"
    )
    new_state = dict(state or {})
    new_state["cn_reachable"] = cur
    new_state["cn_ts"] = _now().strftime("%Y-%m-%dT%H:%M:%SZ")
    prev = (state or {}).get("cn_reachable")
    if isinstance(prev, int) and prev > 20:
        drop = (prev - cur) / prev * 100
        if drop >= drop_pct:
            return f"CN collapse: reachable {cur} vs {prev} (-{drop:.0f}%)", new_state
    return None, new_state


def notify(alerts: list[str]) -> bool:
    """POST to webhook; returns delivered flag. Always prints to stderr."""
    msg = "[proxyip] ALERT\n" + "\n".join(f"- {a}" for a in alerts)
    print(msg, file=sys.stderr)
    url = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
    if not url:
        return False
    body = json.dumps({"content": msg, "text": msg}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15):
            return True
    except OSError as exc:
        print(f"webhook delivery failed: {exc}", file=sys.stderr)
        return False


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", type=Path, default=None,
                    help="repo root containing data/ (default: auto)")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when any alert fired")
    args = ap.parse_args(argv)

    root = args.data_dir or Path(__file__).resolve().parent.parent

    history = load_history(root / "data" / "valid" / "history.jsonl")
    if not history:
        history = load_history(root / "data" / "quality" / "history.jsonl")

    state = read_json(root / "data" / "quality" / "alert_state.json")
    alerts: list[str] = []

    a = check_pool(history)
    if a:
        alerts.append(a)
    a = check_stale(history)
    if a:
        alerts.append(a)
    a, new_state = check_cn(
        state or {}, root / "data" / "quality" / CHINA_FILE.name
    )
    if a:
        alerts.append(a)

    if alerts:
        notify(alerts)
    write_state(new_state, root / "data" / "quality" / "alert_state.json")
    print(f"health: {'ALERT ' + str(len(alerts)) if alerts else 'ok'}")
    return 1 if args.strict and alerts else 0


def write_state(state: dict, path: Path | None = None) -> None:
    (path or STATE_FILE).write_text(
        json.dumps(state, ensure_ascii=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    sys.exit(main())
