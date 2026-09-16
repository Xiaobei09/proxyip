import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from audit_entry_cc import CF_ASN, audit, classify, is_literal_ip


class TestIsLiteralIp(unittest.TestCase):
    def test_v4_v6_domain(self):
        self.assertTrue(is_literal_ip("1.2.3.4"))
        self.assertTrue(is_literal_ip("2606:4700::1"))
        self.assertTrue(is_literal_ip("[2606:4700::1]"))
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


class TestAudit(unittest.TestCase):
    def _qfile(self, qdir: Path, name: str, data: dict) -> None:
        (qdir / name).write_text(json.dumps(data), encoding="utf-8")

    def test_audit_end_to_end(self):
        """真实流：解析 all.txt → domain_entry 不入查列表；入境 IP 按 geo 表归类；
        ?? 未知→ entry_unknown + 写入 quality/entry_audit.json。"""
        from audit_entry_cc import audit as run_audit

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            qdir = base / "quality"
            qdir.mkdir(parents=True)
            (base / "valid").mkdir(parents=True)
            src = base / "valid" / "all.txt"
            src.write_text(
                "5.5.5.5:443#US-10ms\n"
                "1.1.1.1:443#US-10ms\n"
                "2.2.2.2:443#US-10ms\n"
                "cf.example.com:443#US-10ms\n",
                encoding="utf-8",
            )
            geo = {"1.1.1.1": {"cc": "US", "asn": 1234},
                   "2.2.2.2": {"cc": "US", "asn": CF_ASN}}
            with mock.patch("audit_entry_cc.lookup_geo", return_value=geo) as lg:
                report = run_audit(src, qdir, timeout=10, delay=0)
            lg.assert_called_once()
            self.assertEqual(report["total"], 4)
            self.assertIn("ok", report["proxies"]["1.1.1.1:443#US"]["verdict"])
            self.assertEqual(report["proxies"]["2.2.2.2:443#US"]["asn"], CF_ASN)
            self.assertEqual(
                report["proxies"]["cf.example.com:443#US"]["verdict"],
                "domain_entry",
            )
            self.assertEqual(report["summary"].get("domain_entry"), 1)
            self.assertEqual(report["summary"].get("cf_fronted"), 1)
            self.assertEqual(report["summary"].get("entry_unknown"), 1)
            self.assertEqual(report["proxies"]
                             ["5.5.5.5:443#US"]["entry_geo"], None)
            self.assertEqual(report["proxies"]
                             ["5.5.5.5:443#US"]["entry_ip"], "5.5.5.5")

    def test_main_writes_entry_audit(self):
        """main() 把 report 落到 quality/entry_audit.json（workflow 消费物）。
        缺 ipinfo/external/upstream/exit_family 用空 {}（read_json 容错）。"""
        from audit_entry_cc import main as run_main

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            (base / "valid").mkdir(parents=True)
            (base / "quality").mkdir(parents=True)
            (base / "valid" / "all.txt").write_text(
                "1.1.1.1:443#US-10ms\n2.2.2.2:443#US-10ms\n",
                encoding="utf-8",
            )
            with mock.patch("audit_entry_cc.lookup_geo", return_value={}):
                rc = run_main(["--data-dir", str(base)])
            self.assertEqual(rc, 0)
            out = json.loads(
                (base / "quality" / "entry_audit.json").read_text(encoding="utf-8")
            )
            self.assertEqual(out["total"], 2)
            self.assertIn("entry_unknown", out["summary"])


if __name__ == "__main__":
    unittest.main()
