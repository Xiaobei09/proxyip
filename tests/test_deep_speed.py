"""Tests for deep_speed.py: aggregation, target registry, CLI validation."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import deep_speed as ds


class TestAggregate(unittest.TestCase):
    def test_mixed_samples(self):
        out = ds.aggregate([1.5, None, 2.0])
        self.assertEqual(out["agg_mbps"], 3.5)
        self.assertEqual(out["streams_ok"], 2)
        self.assertEqual(out["streams_total"], 3)
        self.assertEqual(out["samples"], [1.5, None, 2.0])

    def test_all_failed(self):
        out = ds.aggregate([None, None])
        self.assertEqual(out["agg_mbps"], 0)
        self.assertEqual(out["streams_ok"], 0)


class TestTargets(unittest.TestCase):
    def test_registry_has_cf_and_non_cf(self):
        """必须同时提供 CF 本地化路径与非 CF 目标（暴露国际 transit）。"""
        self.assertIn("cdnjs", ds.TARGETS)
        self.assertIn("ovh", ds.TARGETS)

    def test_cli_rejects_unknown_target(self):
        with self.assertRaises(SystemExit):
            ds.main(["--cc", "US", "--targets", "nope"])

    def test_cli_requires_source_or_cc(self):
        with self.assertRaises(SystemExit):
            ds.main([])


class TestSummarize(unittest.TestCase):
    def _run(self, results, target, top=10):
        import io
        buf = io.StringIO()
        old = sys.stderr
        sys.stderr = buf
        try:
            ds.summarize(results, target, top)
        finally:
            sys.stderr = old
        return buf.getvalue()

    def test_sorted_desc_and_top_cut(self):
        out = self._run(
            {"a": {"cdn": {"agg_mbps": 1.0, "streams_ok": 1}},
             "b": {"cdn": {"agg_mbps": 9.0, "streams_ok": 1}},
             "c": {"cdn": {"agg_mbps": 5.0, "streams_ok": 1}}},
            "cdn", top=2,
        )
        self.assertLess(out.index("9.00"), out.index("5.00"))
        self.assertNotIn("1.00", out)

    def test_empty_reports_no_success(self):
        self.assertIn("no successful probes", self._run({}, "cdn"))

    def test_zero_streams_excluded(self):
        out = self._run(
            {"x": {"cdn": {"agg_mbps": 99.0, "streams_ok": 0}}}, "cdn"
        )
        self.assertIn("no successful probes", out)


if __name__ == "__main__":
    unittest.main()
