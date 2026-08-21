"""Tests for build_good.py scoring, filtering and output layout."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import build_good as bg


class TestParseMetrics(unittest.TestCase):
    def test_latency_and_speed(self):
        ms, mbps = bg.parse_metrics("1.2.3.4:443#US-130ms-1.86MB/s-CF-99")
        self.assertEqual(ms, 130)
        self.assertAlmostEqual(mbps, 1.86)

    def test_missing_metrics(self):
        self.assertEqual(bg.parse_metrics("1.2.3.4:443#US"), (None, None))

    def test_latency_only(self):
        self.assertEqual(bg.parse_metrics("1.2.3.4:443#US-80ms"), (80, None))


class TestScores(unittest.TestCase):
    def test_latency_score_boundaries(self):
        self.assertEqual(bg.latency_score(None), 0.0)
        self.assertEqual(bg.latency_score(50), 100.0)
        self.assertEqual(bg.latency_score(100), 100.0)
        self.assertEqual(bg.latency_score(1500), 0.0)
        self.assertEqual(bg.latency_score(2000), 0.0)

    def test_latency_score_linear(self):
        # midpoint between 100 and 1500 -> 50
        self.assertAlmostEqual(bg.latency_score(800), 50.0)

    def test_speed_score(self):
        self.assertEqual(bg.speed_score(None), 0.0)
        self.assertEqual(bg.speed_score(0.0), 0.0)
        self.assertAlmostEqual(bg.speed_score(2.5), 50.0)
        self.assertEqual(bg.speed_score(5.0), 100.0)
        self.assertEqual(bg.speed_score(33.0), 100.0)

    def test_composite_reputation_weighted(self):
        # 0.6*100 + 0.2*100 + 0.2*100 = 100
        self.assertEqual(bg.composite_score(100, 80, 5.0), 100)
        # reputation only, no metrics: 0.6*100 = 60
        self.assertEqual(bg.composite_score(100, None, None), 60)
        # 0.6*80 + 0.2*50 + 0.2*0 = 58
        self.assertEqual(bg.composite_score(80, 800, None), 58)


class TestMaps(unittest.TestCase):
    def test_build_rep_map(self):
        data = {"proxies": {
            "1.2.3.4:443#US": {"score": 88, "risk": "low"},
            "5.6.7.8:443#JP": {"risk": "medium"},
            "6.6.6.6:443#DE": "garbage",
        }}
        m = bg.build_rep_map(data)
        self.assertEqual(m, {"1.2.3.4:443#US": {"score": 88, "risk": "low"}})

    def test_build_china_set(self):
        data = {"proxies": {
            "1.2.3.4:443#US": {"verdict": "reachable"},
            "5.6.7.8:443#JP": {"verdict": "unreachable"},
            "6.6.6.6:443#DE": {"verdict": "uncertain"},
        }}
        self.assertEqual(bg.build_china_set(data), {"1.2.3.4:443#US"})

    def test_is_cn_reachable_token_fallback(self):
        china = {"1.2.3.4:443#US"}
        # judged reachable this run
        self.assertTrue(bg.is_cn_reachable(
            "1.2.3.4:443#US", "1.2.3.4:443#US-80ms", china))
        # historical -CN annotation, absent from current verdicts
        self.assertTrue(bg.is_cn_reachable(
            "5.6.7.8:443#JP", "5.6.7.8:443#JP-80ms-CN-V6", china))
        # neither
        self.assertFalse(bg.is_cn_reachable(
            "6.6.6.6:443#DE", "6.6.6.6:443#DE-80ms-V6", china))
        self.assertFalse(bg.is_cn_reachable(None, "", china))


class TestFilterRank(unittest.TestCase):
    LINES = (
        "9.9.9.9:443#US-500ms-2.00MB/s-CN-90\n"
        "1.1.1.1:443#US-100ms-5.00MB/s-CN-90\n"
        "5.5.5.5:443#JP-60ms-10.0MB/s-95\n"          # not CN reachable
        "2.2.2.2:443#HK-50ms-8.00MB/s-CN-40\n"       # rep below 80
        "3.3.3.3:443#SG-70ms-1.00MB/s-CN-99-risky\n" # risk high below
    )

    def setUp(self):
        self.china = {"9.9.9.9:443#US", "1.1.1.1:443#US",
                      "2.2.2.2:443#HK", "3.3.3.3:443#SG"}
        self.rep = {
            "9.9.9.9:443#US": {"score": 90, "risk": "low"},
            "1.1.1.1:443#US": {"score": 90, "risk": "low"},
            "2.2.2.2:443#HK": {"score": 40, "risk": "low"},
            "3.3.3.3:443#SG": {"score": 99, "risk": "high"},
            "5.5.5.5:443#JP": {"score": 95, "risk": "low"},
        }

    def test_filters_and_orders(self):
        out = bg.filter_rank(self.LINES, self.china, self.rep)
        # 1.1.1.1: 0.6*90+0.2*100+0.2*100=94; 9.9.9.9: 54+20+8=82;
        # 2.2.2.2 dropped (rep 40 < 80); JP dropped (no CN); SG dropped (high)
        self.assertEqual(
            [l.split("#")[0] for l in out],
            ["1.1.1.1:443", "9.9.9.9:443"],
        )

    def test_rep_score_threshold_boundary(self):
        lines = (
            "8.0.0.1:443#US-100ms-CN-80\n"
            "8.0.0.2:443#US-100ms-CN-79\n"
        )
        china = {f"8.0.0.{i}:443#US" for i in (1, 2)}
        rep = {
            "8.0.0.1:443#US": {"score": 80, "risk": "low"},
            "8.0.0.2:443#US": {"score": 79, "risk": "low"},
        }
        out = bg.filter_rank(lines, china, rep)
        self.assertEqual([l.split(":")[0] for l in out], ["8.0.0.1"])

    def test_tie_breaks_by_latency_then_key(self):
        lines = (
            "9.0.0.2:443#US-300ms-CN-90\n"
            "9.0.0.1:443#US-300ms-CN-90\n"
            "9.0.0.3:443#US-200ms-CN-90\n"
        )
        china = {f"9.0.0.{i}:443#US" for i in (1, 2, 3)}
        rep = {f"9.0.0.{i}:443#US": {"score": 90, "risk": "low"}
               for i in (1, 2, 3)}
        out = bg.filter_rank(lines, china, rep)
        self.assertEqual(
            [l.split(":")[0] for l in out],
            ["9.0.0.3", "9.0.0.1", "9.0.0.2"],
        )

    def test_historical_cn_token_accepted(self):
        lines = "7.7.7.7:443#DE-120ms-3.00MB/s-CN-V6-88\n"
        # key absent from current china verdicts, line carries -CN
        out = bg.filter_rank(lines, set(),
                             {"7.7.7.7:443#DE": {"score": 88, "risk": "low"}})
        self.assertEqual(len(out), 1)

    def test_lines_kept_verbatim(self):
        line = "1.1.1.1:443#🇺🇸US-100ms-5.00MB/s-CN-V6-GPT-90"
        out = bg.filter_rank(line, {"1.1.1.1:443#US"},
                             {"1.1.1.1:443#US": {"score": 90, "risk": "low"}})
        self.assertEqual(out, [line])

    def test_empty_inputs(self):
        self.assertEqual(bg.filter_rank("", set(), {}), [])

    def test_cn_ms_overrides_inline_latency(self):
        lines = (
            "1.0.0.1:443#US-50ms-5.00MB/s-CN-90\n"    # 海外快，大陆慢
            "2.0.0.2:443#US-900ms-5.00MB/s-CN-90\n"   # 海外慢，大陆快
        )
        china = {"1.0.0.1:443#US", "2.0.0.2:443#US"}
        rep = {
            "1.0.0.1:443#US": {"score": 90, "risk": "low"},
            "2.0.0.2:443#US": {"score": 90, "risk": "low"},
        }
        # 无 cn_ms：按行内海外延迟排序，1.0.0.1 在前
        out = bg.filter_rank(lines, china, rep)
        self.assertEqual([l.split(":")[0] for l in out], ["1.0.0.1", "2.0.0.2"])
        # 有 cn_ms：大陆实测延迟参与评分，2.0.0.2 反超
        cn_ms = {"1.0.0.1:443#US": 800.0, "2.0.0.2:443#US": 60.0}
        out = bg.filter_rank(lines, china, rep, cn_ms)
        self.assertEqual([l.split(":")[0] for l in out], ["2.0.0.2", "1.0.0.1"])


class TestWriteGoodFiles(unittest.TestCase):
    POOL = (
        "1.1.1.1:443#US-100ms-5.00MB/s-CN-90\n"
        "2.2.2.2:443#US-400ms-1.00MB/s-CN-70\n"
        "5.5.5.5:443#JP-60ms-9.00MB/s-95\n"
    )
    CHINA = {"1.1.1.1:443#US", "2.2.2.2:443#US"}
    REP = {
        "1.1.1.1:443#US": {"score": 90, "risk": "low"},
        "2.2.2.2:443#US": {"score": 85, "risk": "low"},
    }

    def test_layout_and_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            (valid / "countries" / "US").mkdir(parents=True)
            (valid / "sets" / "hot").mkdir(parents=True)
            (valid / "countries" / "XX").mkdir()   # no all.txt -> skipped
            (valid / "all.txt").write_text(self.POOL, encoding="utf-8")
            (valid / "countries" / "US" / "all.txt").write_text(
                self.POOL, encoding="utf-8")
            (valid / "sets" / "hot" / "all.txt").write_text(
                self.POOL, encoding="utf-8")

            stats = bg.write_good_files(valid, self.CHINA, self.REP)
            self.assertEqual(stats["all_good"], 2)
            self.assertEqual(stats["countries/US"], 2)
            self.assertEqual(stats["sets/hot"], 2)
            self.assertNotIn("countries/XX", stats)

            good = (valid / "all_good.txt").read_text(encoding="utf-8")
            self.assertEqual(good.splitlines()[0].split("#")[0], "1.1.1.1:443")
            self.assertEqual(len(good.splitlines()), 2)
            self.assertTrue((valid / "countries" / "US" / "good.txt").exists())
            self.assertTrue((valid / "sets" / "hot" / "good.txt").exists())

    def test_verified_stable_variants(self):
        import common

        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            valid.mkdir(parents=True)
            (valid / "all.txt").write_text(self.POOL, encoding="utf-8")
            orig = common.SPEED_FILE, common.CHINA_FILE
            common.SPEED_FILE = Path(tmp) / "speed.json"
            common.CHINA_FILE = Path(tmp) / "china.json"
            try:
                common.SPEED_FILE.write_text(
                    json.dumps({"proxies": {"1.1.1.1:443#US": {}}}),
                    encoding="utf-8",
                )
                common.CHINA_FILE.write_text(
                    json.dumps(
                        {
                            "proxies": {
                                "2.2.2.2:443#US": {
                                    "verdict": "reachable",
                                    "streak": 2,
                                }
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                bg.write_good_files(valid, self.CHINA, self.REP)
            finally:
                common.SPEED_FILE, common.CHINA_FILE = orig

            ver = (valid / "all_good_verified.txt").read_text(encoding="utf-8")
            self.assertEqual(
                [l.split("#")[0] for l in ver.splitlines()], ["1.1.1.1:443"]
            )
            sta = (valid / "all_good_stable.txt").read_text(encoding="utf-8")
            self.assertEqual(
                [l.split("#")[0] for l in sta.splitlines()], ["2.2.2.2:443"]
            )

    def test_idempotent_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            valid.mkdir(parents=True)
            (valid / "all.txt").write_text(self.POOL, encoding="utf-8")
            bg.write_good_files(valid, self.CHINA, self.REP)
            first = (valid / "all_good.txt").read_bytes()
            mtime = (valid / "all_good.txt").stat().st_mtime_ns
            bg.write_good_files(valid, self.CHINA, self.REP)
            self.assertEqual((valid / "all_good.txt").read_bytes(), first)
            self.assertEqual(
                (valid / "all_good.txt").stat().st_mtime_ns, mtime)

    def test_missing_quality_data_yields_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            valid.mkdir(parents=True)
            (valid / "all.txt").write_text(self.POOL, encoding="utf-8")
            stats = bg.write_good_files(valid, set(), {})
            self.assertEqual(stats["all_good"], 0)
            self.assertEqual((valid / "all_good.txt").read_text(), "")


if __name__ == "__main__":
    unittest.main()
