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


if __name__ == "__main__":
    unittest.main()
