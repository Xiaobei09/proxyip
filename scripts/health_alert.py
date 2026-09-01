#!/usr/bin/env python3
"""Pool health watchdog with webhook alerting.

Compares the latest round against recent history and fires alerts when:

- **pool crash**  — alive count dropped > ``POOL_DROP_PCT`` (default 30%)
                    vs the median of the previous day's rounds;
- **CN collapse** — china.json reachable count dropped > ``CN_DROP_PCT``
                    (default 50%) vs the previous round's snapshot stored
                    in the alert state file;
- **source collapse** — an upstream source's unique-count dropped > ``SOURCE_DROP_PCT``
                    (default 55%) vs the median of its last 8 rounds, from
                    ``data/quality/source_history.json``;
- **stale data**  — newest history record older than ``STALE_HOURS``
                    (default 8h).

Delivery: POSTs JSON to the URL in ``$ALERT_WEBHOOK_URL`` (Discord uses
``{"content": ...}``, Slack ``{"text": ...}`` — both are sent). Without
the env var, alerts only print to stderr. State (last CN count) persists
in ``data/quality/alert_state.json`` so cross-run drops are detectable.

Exit code is always 0 unless ``--strict`` (alerts → exit 1 for CI gating).
"""

from __future__ import annotations

import hashlib
import json
import os
import statistics
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import CHINA_FILE, QUALITY_DIR, read_json, deadline_open  # noqa: E402

HISTORY_FILE = QUALITY_DIR / "history.jsonl"
VALID_HISTORY_FILE = QUALITY_DIR.parent / "valid" / "history.jsonl"
STATE_FILE = QUALITY_DIR / "alert_state.json"

POOL_DROP_PCT = 30
CN_DROP_PCT = 50
CN_MIN_BASELINE = 20    # CN 上一轮基准 ≥ 此值才评估塌方
CN_STALE_HOURS = 12     # china.json 超过此年龄且曾有可达样本 → CN 链疑似静默停机
EXIT_FAMILY_HOURS = 12      # exit_family.json 超龄 → exit-family 链疑似停机
EXIT_FAMILY_MIN_ENTRIES = 100
QUALITY_META_HOURS = 12     # quality_meta.json 超龄 → 质量链疑似静默停机
GOOD_META_HOURS = 12        # good_meta.json 超龄 → build-good 链疑似静默停机
VALID_LISTS_HOURS = 5       # valid/meta.json 超龄 → validate(update) 链停机
COUNTRY_DROP_PCT = 60   # 单国 alive 相对上一轮下降阈值（防小样本抖动）
COUNTRY_MIN_BASELINE = 60
STALE_HOURS = 8
ALERT_REPEAT_COOLDOWN_S = 6 * 3600  # 相同告警组合的重复投递冷却
SOURCE_DROP_PCT = 55       # 上游源 unique 相对近 8 轮中位数下降超此百分比触发
SOURCE_MIN_SAMPLES = 8     # 至少积累这么多历史点才评估
SOURCE_MIN_SIZE = 500      # 历史中位数 ≥ 此规模的源才告警（过滤小源噪音）
SOURCE_LOOKBACK = 8        # 取最近几轮作基准


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
    if isinstance(prev, int) and prev > CN_MIN_BASELINE:
        drop = (prev - cur) / prev * 100
        if drop >= drop_pct:
            return f"CN collapse: reachable {cur} vs {prev} (-{drop:.0f}%)", new_state
    return None, new_state


def check_cn_stale(
    cn_file: Path, hours: float = CN_STALE_HOURS, min_reachable: int = CN_MIN_BASELINE
) -> str | None:
    """china.json 时效告警：CN 专链静默失败时总体数据仍新鲜、check_cn
    快照对比恒等，只有此检查能暴露 ''CN 数据已停止刷新''。"""
    data = read_json(cn_file) or {}
    ts = data.get("ts")
    proxies = data.get("proxies") or {}
    reachable = sum(
        1
        for v in proxies.values()
        if isinstance(v, dict) and v.get("verdict") == "reachable"
    )
    if not isinstance(ts, str) or reachable < min_reachable:
        return None
    age_h = (_now() - _ts(ts)).total_seconds() / 3600
    if age_h > hours:
        return f"CN data stale: china.json {age_h:.1f}h old (> {hours}h)"
    return None


def check_artifact_stale(
    label: str,
    path: Path,
    hours: float,
    min_entries: int = 0,
    require_proxies: bool = True,
    ts_field: str = "ts",
) -> str | None:
    """任一产物 JSON 的时效告警（label 给出可读名）。

    ``require_proxies=True`` 限 keyed 产物（``proxies`` 容器条目数 ≥
    ``min_entries`` 才评估，防空跑误报）；summary 型产物（如
    ``quality_meta.json``，无 proxies 容器）传 ``require_proxies=False``，
    仅按年龄评估。
    """
    data = read_json(path) or {}
    ts = data.get(ts_field)
    if not isinstance(ts, str):
        return None
    if require_proxies:
        proxies = data.get("proxies") or {}
        if len(proxies) < min_entries:
            return None
    age_h = (_now() - _ts(ts)).total_seconds() / 3600
    if age_h > hours:
        return f"{label} stale: {path.name} {age_h:.1f}h old (> {hours}h)"
    return None


def check_countries(
    state: dict, meta_path: Path,
    drop_pct: float = COUNTRY_DROP_PCT,
    min_baseline: int = COUNTRY_MIN_BASELINE,
) -> tuple[str | None, dict]:
    """单国 alive 数相对上一轮快照骤降告警（区域性断网/上游掉源）。

    上一轮基准 < ``min_baseline`` 的国家忽略；meta 缺失时静默。
    """
    meta = read_json(meta_path) or {}
    cur = {
        cc: int(c)
        for cc, c in (meta.get("per_country") or {}).items()
        if isinstance(c, (int, float))
    }
    new_state = dict(state or {})
    # meta 缺失/无数据时不覆盖历史快照，也不做对比评估（避免瞬时空窗
    # 误报"所有国家全灭"；池级断供由 check_pool 兜底）
    if not cur:
        return None, new_state
    new_state["countries"] = {
        cc: int(c) for cc, c in sorted(cur.items())
    }
    alerts = []
    prev = (state or {}).get("countries") or {}
    for cc, before in prev.items():
        if before < min_baseline:
            continue
        after = cur.get(cc, 0)
        drop = (before - after) / before * 100
        if drop >= drop_pct:
            alerts.append(
                f"country {cc} collapsed {before}->{after} (-{drop:.0f}%)"
            )
    return ("\n".join(alerts) if alerts else None), new_state


def check_sources(
    path: Path,
    drop_pct: float = SOURCE_DROP_PCT,
    min_samples: int = SOURCE_MIN_SAMPLES,
    min_size: int = SOURCE_MIN_SIZE,
    lookback: int = SOURCE_LOOKBACK,
) -> str | None:
    """上游源 unique 覆盖率骤降告警（相对近 ``lookback`` 轮中位数）。

    累积点数不足 / 源规模太小 / 数据缺失时静默。
    """
    data = read_json(path) or {}
    runs = data.get("runs") or []
    if len(runs) < min_samples:
        return None
    series: dict[str, list[int]] = {}
    for run in runs:
        for label, count in (run.get("counts") or {}).items():
            series.setdefault(label, []).append(int(count))
    alerts = []
    for label, vals in series.items():
        if len(vals) < min_samples:
            continue
        window = vals[-lookback:]
        if len(window) < 2:
            continue
        baseline = window[:-1]
        med = statistics.median(baseline) if baseline else 0
        if med < min_size:
            continue
        last = window[-1]
        if last < med * (100 - drop_pct) / 100:
            drop = (med - last) / med * 100
            alerts.append(
                f"source {label} collapsed {med}->{last} (-{drop:.0f}%)"
            )
    return "\n".join(alerts) if alerts else None


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
        with deadline_open(req, 15):
            return True
    except OSError as exc:
        print(f"webhook delivery failed: {exc}", file=sys.stderr)
        return False


def _alert_fingerprint(alerts: list[str]) -> str:
    return hashlib.md5(
        "|".join(sorted(alerts)).encode("utf-8")
    ).hexdigest()


def _suppress_repeat(state: dict, alerts: list[str]) -> bool:
    """同一告警组合在冷却窗口内不再重复投递（防长时间故障刷屏 webhook）。"""
    last_at = state.get("last_alert_at")
    if not isinstance(last_at, (int, float)):
        return False
    if state.get("last_alert_hash") != _alert_fingerprint(alerts):
        return False
    return (time.time() - last_at) < ALERT_REPEAT_COOLDOWN_S


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
    a, new_state = check_countries(
        new_state, root / "data" / "valid" / "meta.json"
    )
    if a:
        alerts.append(a)
    a = check_sources(root / "data" / "quality" / "source_history.json")
    if a:
        alerts.append(a)
    a = check_cn_stale(root / "data" / "quality" / CHINA_FILE.name)
    if a:
        alerts.append(a)
    a = check_artifact_stale(
        "exit-family",
        root / "data" / "quality" / "exit_family.json",
        hours=EXIT_FAMILY_HOURS,
        min_entries=EXIT_FAMILY_MIN_ENTRIES,
    )
    if a:
        alerts.append(a)
    a = check_artifact_stale(
        "quality-meta",
        root / "data" / "quality" / "quality_meta.json",
        hours=QUALITY_META_HOURS,
        require_proxies=False,
    )
    if a:
        alerts.append(a)
    a = check_artifact_stale(
        "good-lists",
        root / "data" / "quality" / "good_meta.json",
        hours=GOOD_META_HOURS,
        require_proxies=False,
    )
    if a:
        alerts.append(a)
    a = check_artifact_stale(
        "valid-lists",
        root / "data" / "valid" / "meta.json",
        hours=VALID_LISTS_HOURS,
        require_proxies=False,
    )
    if a:
        alerts.append(a)

    if alerts:
        if _suppress_repeat(state or {}, alerts):
            print("health: alerts unchanged, suppressed repeat", file=sys.stderr)
        else:
            notify(alerts)
            new_state["last_alert_hash"] = _alert_fingerprint(alerts)
            new_state["last_alert_at"] = time.time()
    update_badge(root, alerts)
    write_state(new_state, root / "data" / "quality" / "alert_state.json")
    print(f"health: {'ALERT ' + str(len(alerts)) if alerts else 'ok'}")
    return 1 if args.strict and alerts else 0


def update_badge(root: Path, alerts: list[str]) -> None:
    """有告警时把 ``data/output/badge.json`` 标红（同 job 内 stats 已先渲染）。

    README 的 Status 徽章由此直接显示停机原因；无告警时不改动
    （保持 generate_stats 的 fresh/stale 判定）。
    """
    if not alerts:
        return
    msg = alerts[0].split(":")[0].strip()
    write_data_json(
        root / "data" / "output" / "badge.json",
        {"schemaVersion": 1, "label": "status", "message": msg, "color": "red"},
    )


def write_data_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def write_state(state: dict, path: Path | None = None) -> None:
    (path or STATE_FILE).write_text(
        json.dumps(state, ensure_ascii=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    sys.exit(main())
