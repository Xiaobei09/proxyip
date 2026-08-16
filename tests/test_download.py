"""Tests for download_proxies.py pure functions."""

import io
import json
import sys
import unittest
import unittest.mock
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


class TestExtractJson(unittest.TestCase):
    def _json(self, entries: list[dict]) -> bytes:
        return json.dumps({"generated_at": "2026-08-15T00:00:00Z", "data": entries}).encode()

    def test_expands_ports_and_uses_meta_country(self):
        payload = self._json([
            {"ip": "1.1.1.1", "port": [443, 8443],
             "meta": {"country": "US", "clientIp": "2603:c020::1", "asn": 13335}},
            {"ip": "2.2.2.2", "port": [443],
             "meta": {"country": "JP", "clientIp": "2.2.2.2", "asn": 2516}},
            {"ip": "not-an-ip", "port": [443], "meta": {"country": "US"}},
            {"ip": "3.3.3.3", "port": ["443"],
             "meta": {"country": "DE"}},
            {"ip": "4.4.4.4", "port": [443],
             "meta": {"country": "DE"}},
        ])
        by_port, meta = dp.extract_json(payload)
        self.assertEqual(by_port["443"]["US"], ["1.1.1.1"])
        self.assertEqual(by_port["8443"]["US"], ["1.1.1.1"])
        self.assertEqual(by_port["443"]["JP"], ["2.2.2.2"])
        self.assertEqual(by_port["443"]["DE"], ["4.4.4.4"])
        self.assertEqual(meta["1.1.1.1"]["family"], "ipv6")
        self.assertEqual(meta["2.2.2.2"]["family"], "ipv4")
        self.assertEqual(meta["1.1.1.1"]["asn"], 13335)
        self.assertNotIn("not-an-ip", meta)

    def test_dedupes_across_duplicate_entries(self):
        payload = self._json([
            {"ip": "1.1.1.1", "port": [443], "meta": {"country": "US"}},
            {"ip": "1.1.1.1", "port": [443], "meta": {"country": "US"}},
        ])
        by_port, meta = dp.extract_json(payload)
        self.assertEqual(by_port["443"]["US"], ["1.1.1.1"])
        self.assertEqual(len(meta), 1)

    def test_meta_skips_colo_when_missing(self):
        payload = self._json([
            {"ip": "1.1.1.1", "port": [443], "meta": {"country": "US", "clientIp": "1.1.1.1"}},
        ])
        _, meta = dp.extract_json(payload)
        self.assertIsNone(meta["1.1.1.1"]["colo_iata"])

    def test_raises_when_no_data_list(self):
        with self.assertRaises(ValueError):
            dp.extract_json(b'{"generated_at": "x"}')


class TestLoadSource(unittest.TestCase):
    def setUp(self):
        import tempfile
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("443/US.txt", "1.1.1.1\n")
        self.zip_bytes = buf.getvalue()
        self.json_bytes = json.dumps(
            {"data": [{"ip": "2.2.2.2", "port": [443],
                       "meta": {"country": "JP", "clientIp": "2.2.2.2"}}]}
        ).encode()
        self.tmp = Path(tempfile.mkdtemp(prefix="dp_"))

    def test_default_prefers_all_json(self):
        with unittest.mock.patch.object(dp, "download", return_value=self.json_bytes) as m:
            by_port, meta = dp.load_source(dp.SOURCE_URL, timeout=30)
        m.assert_called_once_with(dp.ALL_JSON_URL, timeout=30)
        self.assertEqual(by_port["443"]["JP"], ["2.2.2.2"])
        self.assertEqual(meta["2.2.2.2"]["family"], "ipv4")

    def test_default_falls_back_to_zip(self):
        calls = {"n": 0}

        def fake_download(url, timeout):
            calls["n"] += 1
            if url == dp.ALL_JSON_URL:
                raise OSError("boom")
            return self.zip_bytes

        with unittest.mock.patch.object(dp, "download", side_effect=fake_download):
            by_port, meta = dp.load_source(dp.SOURCE_URL, timeout=30)
        self.assertEqual(calls["n"], 3)  # all.json x2 + zip fallback
        self.assertEqual(by_port["443"]["US"], ["1.1.1.1"])
        self.assertIsNone(meta)

    def test_explicit_json_url(self):
        with unittest.mock.patch.object(dp, "download", return_value=self.json_bytes) as m:
            by_port, meta = dp.load_source("https://example.com/x.json", timeout=30)
        m.assert_called_once_with("https://example.com/x.json", timeout=30)
        self.assertEqual(meta["2.2.2.2"]["family"], "ipv4")

    def test_explicit_zip_url(self):
        with unittest.mock.patch.object(dp, "download", return_value=self.zip_bytes) as m:
            by_port, meta = dp.load_source("https://example.com/x.zip", timeout=30)
        m.assert_called_once_with("https://example.com/x.zip", timeout=30)
        self.assertIsNone(meta)


class TestWriteUpstreamMeta(unittest.TestCase):
    def test_writes_atomic_file(self):
        import tempfile

        base = Path(tempfile.mkdtemp(prefix="dp_"))
        with unittest.mock.patch.object(dp, "OUT_DIR", base):
            dp.write_upstream_meta({"1.1.1.1": {"family": "ipv6"}})
        data = json.loads((base / "upstream_meta.json").read_text())
        self.assertEqual(data["1.1.1.1"]["family"], "ipv6")
        self.assertFalse((base / "upstream_meta.json.tmp").exists())


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
