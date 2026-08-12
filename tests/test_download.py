"""Tests for download_proxies.py pure functions."""

import io
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import download_proxies as dp


class TestIsValidIP(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(dp.is_valid_ip("1.2.3.4"))
        self.assertTrue(dp.is_valid_ip("10.0.0.1"))

    def test_invalid(self):
        for bad in ("", "  ", "abc", "1.2.3", "256.1.1.1", "1.2.3.4:5", "not.an.ip"):
            self.assertFalse(dp.is_valid_ip(bad))

    def test_strips_whitespace(self):
        self.assertTrue(dp.is_valid_ip("  1.2.3.4  "))


class TestIPSortKey(unittest.TestCase):
    def test_numeric_ipv4_order(self):
        self.assertLess(dp.ip_sort_key("1.2.3.4:80#US"), dp.ip_sort_key("10.0.0.1:80#US"))
        self.assertLess(dp.ip_sort_key("1.2.3.4:80#US"), dp.ip_sort_key("2.0.0.1:80#US"))
        self.assertLess(dp.ip_sort_key("9.9.9.9:80#US"), dp.ip_sort_key("10.0.0.1:80#US"))

    def test_same_ip_ignores_port_and_country(self):
        self.assertEqual(
            dp.ip_sort_key("1.2.3.4:80#US"), dp.ip_sort_key("1.2.3.4:443#JP")
        )

    def test_non_ipv4_falls_back_to_string(self):
        self.assertLess(dp.ip_sort_key("aa:1#X"), dp.ip_sort_key("bb:1#X"))


class TestExtract(unittest.TestCase):
    def _zip(self, files: dict[str, str]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return buf.getvalue()

    def test_extracts_ipv4_by_port_country(self):
        data = self._zip(
            {
                "443/US.txt": "1.1.1.1\n2.2.2.2\n",
                "443/JP.txt": "3.3.3.3\nnot-an-ip\n",
                "443/ALL.txt": "4.4.4.4\n",
                "ignore.txt": "1.2.3.4\n",
            }
        )
        by_port = dp.extract(data)
        self.assertEqual(set(by_port), {"443"})
        self.assertEqual(by_port["443"]["US"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(by_port["443"]["JP"], ["3.3.3.3"])
        self.assertEqual(by_port["443"]["ALL"], ["4.4.4.4"])

    def test_skips_invalid_and_dedupes(self):
        data = self._zip({"80/DE.txt": "1.1.1.1\n1.1.1.1\nx\n"})
        by_port = dp.extract(data)
        self.assertEqual(by_port["80"]["DE"], ["1.1.1.1"])


class TestWriteOutputs(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.__class__.__module__)
        self.orig = {k: getattr(dp, k) for k in ("RAW_DIR", "COUNTRIES_DIR", "PORTS_DIR", "SETS_DIR", "OUT_DIR")}

    def tearDown(self):
        for k, v in self.orig.items():
            setattr(dp, k, v)

    def test_outputs_dedup_and_counts(self):
        import tempfile

        base = Path(tempfile.mkdtemp(prefix="dp_"))
        for k in self.orig:
            setattr(dp, k, base / k.lower())
        dp.OUT_DIR.mkdir(parents=True, exist_ok=True)
        by_port = {
            "443": {"US": ["1.1.1.1", "2.2.2.2"], "JP": ["3.3.3.3"]},
            "80": {"US": ["9.9.9.9"]},
        }
        stats, all_entries = dp.write_outputs(by_port, per_country_limit=1)
        self.assertEqual(stats["__total__"], 4)
        self.assertEqual(stats["__unique__"], 4)
        self.assertEqual(stats["__countries__"], 2)
        self.assertEqual(stats["__ports__"], 2)
        us_lines = (dp.COUNTRIES_DIR / "US.txt").read_text().splitlines()
        self.assertEqual(us_lines, ["1.1.1.1:443#US", "2.2.2.2:443#US", "9.9.9.9:80#US"])
        # all.txt ip-sorted
        self.assertEqual(all_entries, ["1.1.1.1:443#US", "2.2.2.2:443#US", "3.3.3.3:443#JP", "9.9.9.9:80#US"])
        # per-country limit ltd
        ltd = (dp.OUT_DIR / "all_ltd.txt").read_text().splitlines()
        self.assertEqual(ltd, ["1.1.1.1:443#US", "3.3.3.3:443#JP"])

    def test_no_ltd_when_limit_zero(self):
        import tempfile

        base = Path(tempfile.mkdtemp(prefix="dp_"))
        for k in self.orig:
            setattr(dp, k, base / k.lower())
        dp.OUT_DIR.mkdir(parents=True, exist_ok=True)
        by_port = {"443": {"US": ["1.1.1.1", "2.2.2.2"]}}
        dp.write_outputs(by_port, per_country_limit=0)
        self.assertFalse((dp.OUT_DIR / "all_ltd.txt").exists())
        self.assertFalse((dp.SETS_DIR / "europe_ltd.txt").exists())


class TestHistoryRecord(unittest.TestCase):
    def test_record_fields(self):
        stats = {"__total__": 10, "__unique__": 8, "__countries__": 3, "__ports__": 2, "__sets__": {}}
        rec = dp.build_history_record(stats, added=2, removed=1)
        self.assertEqual(rec["total"], 10)
        self.assertEqual(rec["unique"], 8)
        self.assertEqual(rec["added"], 2)
        self.assertEqual(rec["removed"], 1)
        self.assertIn("ts", rec)


if __name__ == "__main__":
    unittest.main()
