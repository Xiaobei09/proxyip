"""Tests for export_json.py and all_diverse (exit dedup) builders."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from export_json import line_to_obj  # noqa: E402


class TestLineToObj(unittest.TestCase):
    def test_full_annotation(self):
        o = line_to_obj(
            "1.2.3.4:443#🇺🇸US→LAX-120ms-0.44MB/s-CN-V6-DC-fast-72-U92"
        )
        self.assertEqual(o["ip"], "1.2.3.4")
        self.assertEqual(o["port"], 443)
        self.assertEqual(o["cc"], "US")
        self.assertEqual(o["flag"], "🇺🇸")
        self.assertEqual(o["exit"], "LAX")
        self.assertEqual(o["latency_ms"], 120)
        self.assertEqual(o["speed_mbps"], 0.44)
        self.assertEqual(o["family"], "V6")
        self.assertTrue(o["cn"])
        self.assertEqual(o["type"], "DC")
        self.assertEqual(o["tier"], "fast")
        self.assertEqual(o["rep"], 72)
        self.assertEqual(o["uptime7"], 92)

    def test_minimal_line(self):
        o = line_to_obj("5.6.7.8:8443#JP-200ms")
        self.assertIsNone(o["exit"])
        self.assertIsNone(o["family"])
        self.assertFalse(o["cn"])
        self.assertIsNone(o["rep"])

    def test_invalid_line(self):
        self.assertIsNone(line_to_obj("garbage"))


class TestDiverse(unittest.TestCase):
    POOL = (
        "1.1.1.1:443#🇺🇸US-100ms-5.00MB/s\n"
        "1.1.1.77:443#🇺🇸US-100ms-5.00MB/s\n"   # 同入口 /24 农场
        "9.9.9.9:443#🇬🇧GB-100ms-5.00MB/s\n"
    )

    def test_same_farm_dedup_by_ip24(self):
        from build_good import build_diverse_lines
        out = build_diverse_lines(self.POOL, {}, {})
        self.assertEqual(len(out), 2)
        self.assertIn("9.9.9.9", " ".join(out))

    def test_measured_exit_groups_win_over_ip24(self):
        from build_good import build_diverse_lines
        fam = {"proxies": {
            "1.1.1.1:443#US": {"exit_v4": "8.8.8.8"},
            "9.9.9.9:443#GB": {"exit_v4": "8.8.8.8"},   # 同实测出口
            "5.5.5.5:443#DE": {"exit_v4": "8.8.4.4"},
        }}
        rep = {"9.9.9.9:443#GB": {"score": 90}}
        out = build_diverse_lines(self.POOL, fam, rep)
        self.assertEqual(len(out), 2)
        # 实测出口同组时优先按出口聚合，保留综合分最高的那条
        self.assertIn("9.9.9.9", out[0])

    def test_sorted_by_score_desc(self):
        from build_good import build_diverse_lines
        pool = (
            "1.1.1.1:443#🇺🇸US-900ms-0.10MB/s\n"
            "9.9.9.9:443#🇬🇧GB-100ms-5.00MB/s\n"
        )
        rep = {
            "1.1.1.1:443#US": {"score": 30},
            "9.9.9.9:443#GB": {"score": 95},
        }
        out = build_diverse_lines(pool, {}, rep)
        self.assertTrue(out[0].startswith("9.9.9.9"))

    def test_exit_identity_fallbacks(self):
        from build_good import exit_identity
        self.assertEqual(
            exit_identity("1.2.3.4:443#US", {}), "ip24/1.2.3.0/24"
        )
        self.assertEqual(
            exit_identity(
                "k:443#US", {"k:443#US": {"exit_v4": "5.5.5.5"}}
            ),
            "exit/5.5.5.5",
        )


if __name__ == "__main__":
    unittest.main()
