import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import export_json as ej


class TestLineToObj(unittest.TestCase):
    def test_full_line_all_fields(self):
        line = "1.2.3.4:443#🇺🇸US→LAX-108ms-4.20MB/s-V6-DC-77-U82"
        o = ej.line_to_obj(line)
        self.assertEqual(o["key"], "1.2.3.4:443#US")
        self.assertEqual(o["ip"], "1.2.3.4")
        self.assertEqual(o["port"], 443)
        self.assertEqual(o["cc"], "US")
        self.assertEqual(o["flag"], "🇺🇸")
        self.assertEqual(o["exit"], "LAX")
        self.assertEqual(o["latency_ms"], 108)
        self.assertEqual(o["speed_mbps"], 4.2)
        self.assertEqual(o["family"], "V6")
        self.assertEqual(o["type"], "DC")
        self.assertEqual(o["tier"], None)  # 无档位 token
        self.assertEqual(o["rep"], 77)
        self.assertEqual(o["uptime7"], 82)
        self.assertFalse(o["cn"])

    def test_obj_has_contract_keys(self):
        """R283：下游契约 E——all.json 条目键名向后兼容（只增不改不删）。
        生产键缺失即回归失败。"""
        o = ej.line_to_obj(
            "1.2.3.4:443#🇺🇸US→LAX-108ms-4.20MB/s-V6-DC-77-U82")
        for k in ("ip", "port", "cc", "latency_ms", "speed_mbps",
                  "family", "rep", "key"):
            self.assertIn(k, o)

    def test_exit_without_uptime(self):
        line = "4.4.4.4:443#🇯🇵JP→TYO-55ms-DC-CN-30"
        o = ej.line_to_obj(line)
        self.assertEqual(o["exit"], "TYO")
        self.assertEqual(o["uptime7"], None)
        self.assertTrue(o["cn"])

    def test_estimate_speed_ignored(self):
        """≈ 大陆估算 token 不认作实测速度（R78 同族语义）。"""
        o = ej.line_to_obj("1.2.3.4:443#US-90ms-≈1.86MB/s")
        self.assertIsNone(o["speed_mbps"])
        self.assertEqual(o["latency_ms"], 90)

    def test_bad_speed_token_ignored(self):
        o = ej.line_to_obj("1.2.3.4:443#US-88ms-abcMB/s")
        self.assertIsNone(o["speed_mbps"])

    def test_family_missing_is_none(self):
        o = ej.line_to_obj("1.2.3.4:443#US-150ms")
        self.assertIsNone(o["family"])
        self.assertIsNone(o["uptime7"])

    def test_cn_tokens_variants(self):
        for tok in ("CN", "CN4", "CN6", "CN46", "CNH"):
            with self.subTest(tok=tok):
                o = ej.line_to_obj(f"1.2.3.4:443#US-100ms-{tok}")
                self.assertTrue(o["cn"])

    def test_tier_type_family_first_token(self):
        o = ej.line_to_obj("1.2.3.4:443#US-130ms-fast-DC-V4-60")
        self.assertEqual(o["tier"], "fast")
        self.assertEqual(o["type"], "DC")
        self.assertEqual(o["family"], "V4")
        self.assertEqual(o["rep"], 60)

    def test_unparseable_line_none(self):
        self.assertIsNone(ej.line_to_obj("not-a-proxy-line"))

    def test_no_exit_segment(self):
        o = ej.line_to_obj("1.2.3.4:443#US-100ms-DC")
        self.assertIsNone(o["exit"])
        self.assertEqual(o["type"], "DC")


class TestMain(unittest.TestCase):
    def test_missing_source_skips(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(ej.main(["--data-dir", td]), 0)

    def test_writes_compact_json(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "valid").mkdir()
            (d / "valid" / "all.txt").write_text(
                "1.2.3.4:443#US-100ms-1.00MB/s\nbad\n",
                encoding="utf-8",
            )
            self.assertEqual(ej.main(["--data-dir", td]), 0)
            out = json.loads((d / "valid" / "all.json").read_text(encoding="utf-8"))
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]["ip"], "1.2.3.4")


if __name__ == "__main__":
    unittest.main()