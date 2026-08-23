"""Tests for uptime.py — rolling per-node availability."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from uptime import merge_seen, prune_days, uptime_stats  # noqa: E402


class TestPruneDays(unittest.TestCase):
    def test_old_dates_dropped(self):
        days = {"2026-08-23": 1, "2026-06-01": 1, "bad": 1}
        out = prune_days(days, "2026-08-23")
        self.assertEqual(out, {"2026-08-23": 1})

    def test_empty(self):
        self.assertEqual(prune_days({}, "2026-08-23"), {})


class TestMergeSeen(unittest.TestCase):
    SEEN = {
        "runs": {"2026-08-20": 1},
        "proxies": {
            "a:443#US": ["2026-08-20"],
            "gone:443#US": ["2026-01-01"],   # 太老 → 清掉
        },
    }

    def test_merge_and_prune(self):
        proxies, days = merge_seen(self.SEEN, ["a:443#US", "new:443#JP"],
                                   "2026-08-23")
        self.assertEqual(days["2026-08-20"], 1)
        self.assertEqual(days["2026-08-23"], 1)
        # a 连续两轮在场
        self.assertEqual(proxies["a:443#US"], ["2026-08-20", "2026-08-23"])
        # 过期记录被清理，不再保留幽灵键
        self.assertNotIn("gone:443#US", proxies)
        # 新节点从今天开始计数
        self.assertEqual(proxies["new:443#JP"], ["2026-08-23"])


class TestUptimeStats(unittest.TestCase):
    def test_full_attendance_is_100(self):
        stats = uptime_stats(
            {"a:443#US": ["2026-08-22", "2026-08-23"]},
            {"2026-08-22": 1, "2026-08-23": 1},
        )
        self.assertEqual(stats["runs7"], 2)
        self.assertEqual(stats["proxies"]["a:443#US"]["pct7"], 100)

    def test_missed_round_scores_lower(self):
        stats = uptime_stats(
            {"b:443#US": ["2026-08-23"]},          # 缺 08-22 那轮
            {"2026-08-22": 1, "2026-08-23": 1},
        )
        self.assertEqual(stats["proxies"]["b:443#US"]["pct7"], 50)
        self.assertEqual(stats["proxies"]["b:443#US"]["hits7"], 1)

    def test_30d_window_uses_all_counters(self):
        dates = {f"2026-07-{d:02d}": 1 for d in range(25, 32)}
        dates.update({f"2026-08-{d:02d}": 1 for d in range(1, 24)})
        hits30 = sum(1 for _ in dates) - 6  # 窗口外 7 月上旬不计
        stats = uptime_stats(
            {"c:443#US": [d for d in dates][: len(dates) - 6]}, dates
        )
        self.assertEqual(stats["runs30"], len(dates))
        entry = stats["proxies"]["c:443#US"]
        self.assertEqual(entry["hits30"], hits30)

    def test_no_runs_yields_none_pct(self):
        stats = uptime_stats({"x:1#US": ["2026-08-23"]}, {})
        self.assertIsNone(stats["proxies"]["x:1#US"]["pct7"])


class TestMainEndToEnd(unittest.TestCase):
    def test_main_writes_outputs(self):
        import uptime
        with tempfile.TemporaryDirectory() as td:
            qdir = Path(td)
            (qdir / "ipinfo.json").write_text(json.dumps(
                {"proxies": {"1.1.1.1:443#US": {"ip_type": "DC"}}}))
            rc = uptime.main([
                "--alive-file", str(qdir / "ipinfo.json"),
                "--out-dir", str(qdir),
            ])
            self.assertEqual(rc, 0)
            stats = json.loads((qdir / "uptime.json").read_text())
            self.assertIn("1.1.1.1:443#US", stats["proxies"])
            seen = json.loads((qdir / "node_seen.json").read_text())
            self.assertIn("1.1.1.1:443#US", seen["proxies"])


if __name__ == "__main__":
    unittest.main()
