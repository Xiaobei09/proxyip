import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from audit_entry_cc import CF_ASN, classify, is_literal_ip


class TestIsLiteralIp(unittest.TestCase):
    def test_v4_v6_domain(self):
        self.assertTrue(is_literal_ip("1.2.3.4"))
        self.assertTrue(is_literal_ip("2606:4700::1"))
        self.assertFalse(is_literal_ip("example.com"))
        self.assertFalse(is_literal_ip(""))


class TestClassify(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(classify("US", {"cc": "US", "asn": 1234}, None), "ok")

    def test_ok_with_drift(self):
        self.assertEqual(
            classify("US", {"cc": "US", "asn": 1234}, "EG"), "ok_with_drift"
        )

    def test_tag_mismatch(self):
        self.assertEqual(
            classify("US", {"cc": "JP", "asn": 1234}, "JP"), "tag_mismatch"
        )

    def test_cf_fronted_wins_over_mismatch(self):
        self.assertEqual(
            classify("US", {"cc": "JP", "asn": CF_ASN}, "JP"), "cf_fronted"
        )

    def test_entry_unknown(self):
        for geo in (None, {}, {"cc": None, "asn": 1}):
            self.assertEqual(classify("US", geo, None), "entry_unknown")


if __name__ == "__main__":
    unittest.main()
