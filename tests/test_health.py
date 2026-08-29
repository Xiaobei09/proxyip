"""Tests for health_alert.py — pool watchdog rules."""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from health_alert import (  # noqa: E402
    check_cn,
    check_pool,
    check_sources,
    check_stale,
    load_history,
)


def _ts(hours_ago: float) -> str:
    return (
        datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


class TestCheckPool(unittest.TestCase):
    def test_no_alert_on_steady(self):
        hist = [
            {"ts": _ts(3), "alive": 10000},
            {"ts": _ts(2), "alive": 9900},
            {"ts": _ts(1), "alive": 9950},
        ]
        self.assertIsNone(check_pool(hist))

    def test_alert_on_crash(self):
        hist = [
            {"ts": _ts(3), "alive": 10000},
            {"ts": _ts(2), "alive": 10000},
            {"ts": _ts(1), "alive": 5000},   # -50%
        ]
        alert = check_pool(hist)
        self.assertIsNotNone(alert)
        self.assertIn("pool crash", alert)

    def test_needs_two_baseline_points(self):
        self.assertIsNone(check_pool([{"ts": _ts(1), "alive": 10}]))


class TestCheckStale(unittest.TestCase):
    def test_fresh_ok(self):
        self.assertIsNone(check_stale([{"ts": _ts(1)}]))

    def test_old_record_alerts(self):
        alert = check_stale([{"ts": _ts(20)}])
        self.assertIsNotNone(alert)
        self.assertIn("stale", alert)

    def test_empty_history(self):
        self.assertIn("no history", check_stale([]))


class TestCheckCn(unittest.TestCase):
    def make_file(self, tmp, n_reachable, n_blocked=0):
        proxies = {}
        for i in range(n_reachable):
            proxies[f"{i}:443#US"] = {"verdict": "reachable"}
        for i in range(n_blocked):
            proxies[f"b{i}:443#US"] = {"verdict": "blocked"}
        p = Path(tmp) / "china.json"
        p.write_text(json.dumps({"proxies": proxies}))
        return p

    def test_no_collapse(self):
        with tempfile.TemporaryDirectory() as td:
            alert, state = check_cn({}, self.make_file(td, 100))
            self.assertIsNone(alert)
            self.assertEqual(state["cn_reachable"], 100)

    def test_collapse_alert(self):
        with tempfile.TemporaryDirectory() as td:
            alert, state = check_cn(
                {"cn_reachable": 100}, self.make_file(td, 30)
            )
            self.assertIsNotNone(alert)
            self.assertIn("CN collapse", alert)
            # 状态仍要推进到当前值，避免重复误报
            self.assertEqual(state["cn_reachable"], 30)

    def test_small_pool_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            alert, _ = check_cn({"cn_reachable": 10}, self.make_file(td, 1))
            self.assertIsNone(alert)  # prev ≤ 20 不触发


class TestCheckSources(unittest.TestCase):
    def _runs(self, series):
        return [
            {"ts": _ts(i), "counts": c} for i, c in enumerate(series)
        ]

    def test_no_alert_when_source_small(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.json"
            p.write_text(json.dumps({"runs": self._runs([{"A": 60}] * 10)}))
            self.assertIsNone(check_sources(p))

    def test_collapse_alert(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.json"
            p.write_text(
                json.dumps(
                    {"runs": self._runs([{"A": 8000}] * 9 + [{"A": 2000}])}
                )
            )
            alert = check_sources(p)
        self.assertIsNotNone(alert)
        self.assertIn("A", alert)
        self.assertIn("-75%", alert)

    def test_recovery_no_alert(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.json"
            p.write_text(
                json.dumps(
                    {"runs": self._runs([{"A": 8000}] * 6 + [{"A": 9000}, {"A": 8500}])}
                )
            )
            self.assertIsNone(check_sources(p))

    def test_insufficient_samples(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.json"
            p.write_text(json.dumps({"runs": self._runs([{"A": 8000}] * 3)}))
            self.assertIsNone(check_sources(p))

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(check_sources(Path(td) / "nope.json"))


class TestLoadHistory(unittest.TestCase):
    def test_skips_bad_lines_and_sorts(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.jsonl"
            p.write_text(
                '{"ts":"2026-08-23T02:00:00Z","alive":5}\n'
                "not-json\n"
                '{"ts":"2026-08-23T01:00:00Z","alive":7}\n'
            )
            recs = load_history(p)
            self.assertEqual([r["alive"] for r in recs], [7, 5])


if __name__ == "__main__":
    unittest.main()
