"""normalize_note / merge_note_tokens —— 全仓库统一备注规范器的行为契约。"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from common import merge_note_tokens, normalize_note


class TestNormalizeNote(unittest.TestCase):
    def test_canonical_order(self):
        self.assertEqual(
            normalize_note(
                "1.1.1.1:443#🇺🇸US→US-17ms-22.70MB/s-CN-V6-mid-fast-DC-GPT-CF-69"
            ),
            "1.1.1.1:443#🇺🇸US→US-17ms-22.70MB/s-GPT-DC-CF-fast-V6-CN-69",
        )

    def test_collapses_historical_snapshots(self):
        """多轮 CI 堆叠的 (streaming-type-tier-score) 快照收敛为一组。"""
        stacked = (
            "1.2.3.4:443#🇺🇸US→US-21ms-25.23MB/s-CN-V6-GPT-CF-77"
            "-mid-GPT-CF-70-DC-fast-GPT-CF-62-RES-GPT-CF-70"
        )
        self.assertEqual(
            normalize_note(stacked),
            "1.2.3.4:443#🇺🇸US→US-21ms-25.23MB/s-GPT-RES-CF-fast-V6-CN-70",
        )

    def test_rightmost_wins_single_value_buckets(self):
        # 类型 DC→RES、档位 mid→fast、分数 62→70：均取最右
        line = "1.2.3.4:443#🇺🇸US-50ms-1.00MB/s-DC-mid-RES-fast-62-70"
        self.assertEqual(
            normalize_note(line),
            "1.2.3.4:443#🇺🇸US-50ms-1.00MB/s-RES-fast-70",
        )

    def test_family_rightmost(self):
        line = "1.2.3.4:443#🇺🇸US-50ms-V4-V6"
        self.assertEqual(normalize_note(line), "1.2.3.4:443#🇺🇸US-50ms-V6")

    def test_streaming_union_dedup(self):
        line = "1.2.3.4:443#🇺🇸US-50ms-GPT-YT-GPT-NF(US)"
        self.assertEqual(
            normalize_note(line),
            "1.2.3.4:443#🇺🇸US-50ms-GPT-YT-NF(US)",
        )

    def test_cnh_implies_cn(self):
        line = "1.2.3.4:443#🇯🇵JP→SG-50ms-2.00MB/s-CNH"
        self.assertEqual(
            normalize_note(line),
            "1.2.3.4:443#🇯🇵JP→SG-50ms-2.00MB/s-CN-CNH",
        )

    def test_no_emoji_lead_preserved(self):
        self.assertEqual(
            normalize_note("1.2.3.4:80#US-1ms-CN"),
            "1.2.3.4:80#US-1ms-CN",
        )

    def test_bare_cc_untouched(self):
        for note in ("US", "ALL", "🇺🇸US"):
            line = f"1.2.3.4:443#{note}"
            self.assertEqual(normalize_note(line), line)

    def test_unknown_segments_kept_at_end(self):
        line = "1.2.3.4:443#🇺🇸US-50ms-CN-XYZ"
        self.assertEqual(normalize_note(line), f"{line}")

    def test_idempotent_on_messy_real_lines(self):
        messy = (
            "137.220.38.195:443#🇺🇸US→US-18ms-39.33MB/s-CN-V6-GPT-CF-74"
            "-mid-GPT-CF-76-DC-fast-GPT-CF-73-RES-GPT-CF-75"
        )
        once = normalize_note(messy)
        self.assertEqual(once, normalize_note(once))


class TestMergeNoteTokens(unittest.TestCase):
    def test_append_missing_tokens_normalized(self):
        out = merge_note_tokens(
            "5.6.7.8:443#🇺🇸US-27ms-27.78MB/s-DC-mid-V6-fast-GPT-CF-77",
            "CN", "V6", "80",
        )
        self.assertEqual(
            out,
            "5.6.7.8:443#🇺🇸US-27ms-27.78MB/s-GPT-DC-CF-fast-V6-CN-80",
        )

    def test_idempotent(self):
        line = "5.6.7.8:443#🇺🇸US-27ms-27.78MB/s-DC-fast-V6-77"
        once = merge_note_tokens(line, "CN", "CNH")
        self.assertEqual(once, merge_note_tokens(once, "CN", "CNH"))
        self.assertEqual(once.count("V6"), 1)


if __name__ == "__main__":
    unittest.main()
