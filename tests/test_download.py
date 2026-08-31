"""Tests for download_proxies.py pure functions."""

import io
import json
import sys
import unittest
import unittest.mock
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import common
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
        self.orig = {k: getattr(dp, k) for k in ("RAW_DIR", "COUNTRIES_DIR", "PORTS_DIR", "SETS_DIR", "ALL_FILE", "ALL_LTD_FILE")}

    def tearDown(self):
        for k, v in self.orig.items():
            setattr(dp, k, v)

    def test_outputs_dedup_and_counts(self):
        import tempfile

        base = Path(tempfile.mkdtemp(prefix="dp_"))
        for k in self.orig:
            if k in ("ALL_FILE", "ALL_LTD_FILE"):
                setattr(dp, k, base / k.lower().replace("_file", ".txt"))
            else:
                setattr(dp, k, base / k.lower())
        dp.ALL_FILE.parent.mkdir(parents=True, exist_ok=True)
        by_port = {
            "443": {"US": ["1.1.1.1", "2.2.2.2"], "JP": ["3.3.3.3"]},
            "8443": {"US": ["9.9.9.9"]},
        }
        stats, all_entries = dp.write_outputs(by_port, per_country_limit=1)
        self.assertEqual(stats["__total__"], 4)
        self.assertEqual(stats["__unique__"], 4)
        self.assertEqual(stats["__countries__"], 2)
        self.assertEqual(stats["__ports__"], 2)
        us_lines = (dp.COUNTRIES_DIR / "US.txt").read_text().splitlines()
        self.assertEqual(us_lines, ["1.1.1.1:443#US", "2.2.2.2:443#US", "9.9.9.9:8443#US"])
        # all.txt ip-sorted
        self.assertEqual(all_entries, ["1.1.1.1:443#US", "2.2.2.2:443#US", "3.3.3.3:443#JP", "9.9.9.9:8443#US"])
        # per-country limit ltd
        ltd = (dp.ALL_LTD_FILE).read_text().splitlines()
        self.assertEqual(ltd, ["1.1.1.1:443#US", "3.3.3.3:443#JP"])

    def test_non_cf_edge_ports_dropped(self):
        import tempfile

        base = Path(tempfile.mkdtemp(prefix="dp_"))
        for k in self.orig:
            if k in ("ALL_FILE", "ALL_LTD_FILE"):
                setattr(dp, k, base / k.lower().replace("_file", ".txt"))
            else:
                setattr(dp, k, base / k.lower())
        dp.ALL_FILE.parent.mkdir(parents=True, exist_ok=True)
        by_port = {
            "443": {"US": ["1.1.1.1"]},
            "8080": {"US": ["7.7.7.7"]},
            "999": {"DE": ["8.8.8.8"]},
        }
        stats, all_entries = dp.write_outputs(by_port, per_country_limit=0)
        self.assertNotIn("8080", stats)
        self.assertEqual(len(all_entries), 1)
        self.assertEqual(all_entries, ["1.1.1.1:443#US"])

    def test_no_ltd_when_limit_zero(self):
        import tempfile

        base = Path(tempfile.mkdtemp(prefix="dp_"))
        for k in self.orig:
            if k in ("ALL_FILE", "ALL_LTD_FILE"):
                setattr(dp, k, base / k.lower().replace("_file", ".txt"))
            else:
                setattr(dp, k, base / k.lower())
        dp.ALL_FILE.parent.mkdir(parents=True, exist_ok=True)
        by_port = {"443": {"US": ["1.1.1.1", "2.2.2.2"]}}
        dp.write_outputs(by_port, per_country_limit=0)
        self.assertFalse(dp.ALL_LTD_FILE.exists())
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

        with unittest.mock.patch.object(dp, "download", side_effect=fake_download), \
                unittest.mock.patch.object(dp.time, "sleep"):
            by_port, meta = dp.load_source(dp.SOURCE_URL, timeout=30)
        self.assertEqual(calls["n"], 4)  # all.json x3 + zip fallback
        self.assertEqual(by_port["443"]["US"], ["1.1.1.1"])
        self.assertIsNone(meta)

    def test_json_succeeds_after_two_retries(self):
        calls = {"n": 0}

        def fake_download(url, timeout):
            calls["n"] += 1
            if calls["n"] < 3:
                raise OSError("boom")
            return self.json_bytes

        with unittest.mock.patch.object(dp, "download", side_effect=fake_download), \
                unittest.mock.patch.object(dp.time, "sleep"):
            by_port, meta = dp.load_source(dp.SOURCE_URL, timeout=30)
        self.assertEqual(calls["n"], 3)
        self.assertIsNotNone(meta)

    def test_both_sources_exhausted_raises(self):
        calls = {"n": 0}

        def fake_download(url, timeout):
            calls["n"] += 1
            raise OSError("boom")

        with unittest.mock.patch.object(dp, "download", side_effect=fake_download), \
                unittest.mock.patch.object(dp.time, "sleep"):
            with self.assertRaises(OSError):
                dp.load_source(dp.SOURCE_URL, timeout=30)
        self.assertEqual(calls["n"], 6)  # all.json x3 + zip x3

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
        meta_file = base / "upstream_meta.json"
        with unittest.mock.patch.object(dp, "UPSTREAM_META_FILE", meta_file):
            dp.write_upstream_meta({"1.1.1.1": {"family": "ipv6"}})
        data = json.loads(meta_file.read_text())
        self.assertEqual(data["proxies"]["1.1.1.1"]["family"], "ipv6")
        self.assertFalse(meta_file.with_suffix(".json.tmp").exists())


class TestHistoryRecord(unittest.TestCase):
    def test_record_fields(self):
        stats = {"__total__": 10, "__unique__": 8, "__countries__": 3, "__ports__": 2, "__sets__": {}}
        rec = dp.build_history_record(stats, added=2, removed=1)
        self.assertEqual(rec["total"], 10)
        self.assertEqual(rec["unique"], 8)
        self.assertEqual(rec["added"], 2)
        self.assertEqual(rec["removed"], 1)
        self.assertIn("ts", rec)


class TestNormalizeCountry(unittest.TestCase):
    def test_iso2(self):
        self.assertEqual(dp.normalize_country("us"), "US")
        self.assertEqual(dp.normalize_country("US-abc"), "US")
        self.assertEqual(dp.normalize_country(""), "ALL")

    def test_chinese(self):
        self.assertEqual(dp.normalize_country("香港"), "HK")
        self.assertEqual(dp.normalize_country("日本-1"), "JP")
        self.assertEqual(dp.normalize_country("美国"), "US")

    def test_airport(self):
        self.assertEqual(dp.normalize_country("NRT"), "JP")
        self.assertEqual(dp.normalize_country("SIN"), "SG")
        self.assertEqual(dp.normalize_country("HGH"), "CN")

    def test_emoji_flag(self):
        self.assertEqual(dp.normalize_country("\U0001F1FA\U0001F1F8US"), "US")

    def test_unmappable(self):
        self.assertEqual(dp.normalize_country("zzz"), "ALL")
        self.assertEqual(dp.normalize_country("东京"), "ALL")


class TestExtractPlain(unittest.TestCase):
    def test_ip_port_with_notes(self):
        content = (
            "1.2.3.4:443#US\n"
            "2.2.2.2:2053#\u9999\u6e2f\n"
            "3.3.3.3:8443\n"
            "not-an-ip:443#DE\n"
            "4.4.4.4:80#US\n"
        ).encode("utf-8")
        by_port = dp.extract_plain(content)
        self.assertEqual(by_port["443"]["US"], ["1.2.3.4"])
        self.assertEqual(by_port["2053"]["HK"], ["2.2.2.2"])
        self.assertEqual(by_port["8443"]["ALL"], ["3.3.3.3"])
        self.assertEqual(by_port["80"]["US"], ["4.4.4.4"])

    def test_dedupes_and_sorts(self):
        by_port = dp.extract_plain(b"1.1.1.1:443#US\n1.1.1.1:443#US\n2.2.2.2:443#US\n")
        self.assertEqual(by_port["443"]["US"], ["1.1.1.1", "2.2.2.2"])


class TestExtractBareIPs(unittest.TestCase):
    def test_bare_and_tagged(self):
        by_port = dp.extract_bare_ips(
            b"1.2.3.4\n2.2.2.2#HK\n3.3.3.3#SG\n4.4.4.4:443\n", port="443"
        )
        self.assertEqual(by_port["443"]["ALL"], ["1.2.3.4"])
        self.assertEqual(by_port["443"]["HK"], ["2.2.2.2"])
        self.assertEqual(by_port["443"]["SG"], ["3.3.3.3"])

    def test_default_port_443(self):
        by_port = dp.extract_bare_ips(b"1.2.3.4\n")
        self.assertIn("443", by_port)


class TestExtractCsv(unittest.TestCase):
    def test_rows_with_airport_regions(self):
        content = (
            "IP,端口,地区,延迟\n"
            "3.112.19.134,443,NRT,1283\n"
            '"[104.17.122.112]",8443,SIN,100\n'
            "5.6.7.8,443,US,50\n"
        )
        by_port = dp.extract_csv_ports(content)
        self.assertEqual(by_port["443"]["JP"], ["3.112.19.134"])
        self.assertEqual(by_port["8443"]["SG"], ["104.17.122.112"])
        self.assertEqual(by_port["443"]["US"], ["5.6.7.8"])

    def test_skips_header_and_garbage(self):
        by_port = dp.extract_csv_ports("IP,端口,地区,延迟\nbad,443,US,1\n")
        self.assertEqual(by_port, {})


class TestMergeByPort(unittest.TestCase):
    def test_merges_dedupes_sorts(self):
        base = {"443": {"US": ["1.1.1.1"]}}
        extra = {"443": {"US": ["2.2.2.2", "1.1.1.1"], "JP": ["3.3.3.3"]},
                 "80": {"US": ["4.4.4.4"]}}
        merged = dp.merge_by_port(base, extra)
        self.assertEqual(merged["443"]["US"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(merged["443"]["JP"], ["3.3.3.3"])
        self.assertEqual(merged["80"]["US"], ["4.4.4.4"])

    def test_skips_all_dup_of_known_country(self):
        base = {"443": {"US": ["1.1.1.1"]}}
        extra = {"443": {"ALL": ["1.1.1.1", "2.2.2.2"]}}
        merged = dp.merge_by_port(base, extra)
        self.assertEqual(merged["443"]["ALL"], ["2.2.2.2"])
        self.assertNotIn("1.1.1.1", merged["443"]["ALL"])

    def test_keeps_all_for_unknown_port(self):
        base = {"443": {"US": ["1.1.1.1"]}}
        extra = {"8443": {"ALL": ["1.1.1.1"]}}
        merged = dp.merge_by_port(base, extra)
        self.assertEqual(merged["8443"]["ALL"], ["1.1.1.1"])


class TestLookupAndEnrich(unittest.TestCase):
    class _Resp:
        def __init__(self, data):
            self._data = data

        def read(self):
            return self._data

    def _fake_urlopen(self, payload):
        body = json.dumps(payload).encode()

        class _Ctx:
            def __enter__(self):
                return TestLookupAndEnrich._Resp(body)

            def __exit__(self, *exc):
                return False

        return _Ctx()

    def test_lookup_countries(self):
        payload = [
            {"status": "success", "query": "1.1.1.1", "countryCode": "US"},
            {"status": "success", "query": "2.2.2.2", "countryCode": "HK"},
            {"status": "fail", "query": "3.3.3.3"},
        ]
        with unittest.mock.patch.object(
            dp.urllib.request, "urlopen", return_value=self._fake_urlopen(payload)
        ):
            result = dp.lookup_countries(["1.1.1.1", "2.2.2.2", "3.3.3.3"], 10, 0.0)
        self.assertEqual(result, {"1.1.1.1": "US", "2.2.2.2": "HK"})

    def test_lookup_failure_returns_empty(self):
        with unittest.mock.patch.object(
            dp.urllib.request, "urlopen", side_effect=OSError("boom")
        ):
            result = dp.lookup_countries(["1.1.1.1"], 10, 0.0)
        self.assertEqual(result, {})

    def test_enrich_moves_only_extra_all_ips(self):
        by_port = {
            "443": {"ALL": ["1.1.1.1", "2.2.2.2"], "JP": ["9.9.9.9"]},
            "8443": {"ALL": ["3.3.3.3"]},
        }
        payload = [
            {"status": "success", "query": "1.1.1.1", "countryCode": "US"},
            {"status": "success", "query": "3.3.3.3", "countryCode": "HK"},
        ]
        with unittest.mock.patch.object(
            dp.urllib.request, "urlopen", return_value=self._fake_urlopen(payload)
        ):
            moved = dp.enrich_countries(
                by_port, {"1.1.1.1", "3.3.3.3"}, timeout=10, delay=0.0
            )
        self.assertEqual(moved, 2)
        self.assertEqual(by_port["443"]["US"], ["1.1.1.1"])
        self.assertEqual(by_port["443"]["ALL"], ["2.2.2.2"])
        self.assertEqual(by_port["8443"]["HK"], ["3.3.3.3"])
        self.assertNotIn("ALL", by_port["8443"])

    def test_enrich_noop_without_extra_ips(self):
        by_port = {"443": {"ALL": ["1.1.1.1"]}}
        self.assertEqual(dp.enrich_countries(by_port, set(), timeout=10), 0)
        self.assertEqual(by_port["443"]["ALL"], ["1.1.1.1"])


class TestWriteOutputsAll(unittest.TestCase):
    def test_all_entries_in_all_ports_ltd_not_countries_sets(self):
        import tempfile

        base = Path(tempfile.mkdtemp(prefix="dp_"))
        orig = {k: getattr(dp, k) for k in
                ("RAW_DIR", "COUNTRIES_DIR", "PORTS_DIR", "SETS_DIR", "ALL_FILE", "ALL_LTD_FILE")}
        try:
            for k in orig:
                if k in ("ALL_FILE", "ALL_LTD_FILE"):
                    setattr(dp, k, base / k.lower().replace("_file", ".txt"))
                else:
                    setattr(dp, k, base / k.lower())
            dp.ALL_FILE.parent.mkdir(parents=True, exist_ok=True)
            by_port = {"443": {"US": ["1.1.1.1"], "ALL": ["2.2.2.2", "9.9.9.9"]}}
            _, all_entries = dp.write_outputs(by_port, per_country_limit=1)
            self.assertIn("1.1.1.1:443#US", all_entries)
            self.assertIn("2.2.2.2:443#ALL", all_entries)
            self.assertIn("9.9.9.9:443#ALL", all_entries)
            self.assertEqual(
                (dp.COUNTRIES_DIR / "US.txt").read_text().splitlines(),
                ["1.1.1.1:443#US"],
            )
            self.assertFalse((dp.COUNTRIES_DIR / "ALL.txt").exists())
            self.assertEqual(
                set((dp.PORTS_DIR / "443.txt").read_text().splitlines()),
                {"1.1.1.1:443#US", "2.2.2.2:443#ALL", "9.9.9.9:443#ALL"},
            )
            ltd = dp.ALL_LTD_FILE.read_text().splitlines()
            self.assertIn("1.1.1.1:443#US", ltd)
            self.assertIn("2.2.2.2:443#ALL", ltd)
            north_america = (dp.SETS_DIR / "north_america.txt").read_text().splitlines()
            self.assertEqual(north_america, ["1.1.1.1:443#US"])
        finally:
            for k, v in orig.items():
                setattr(dp, k, v)


class TestLoadExtras(unittest.TestCase):
    def test_parallel_fetch_with_failure_and_postmerge_all(self):
        def fake_fetch(url, timeout):
            if url == "http://bad/cf.txt":
                raise OSError("boom")
            if url == "http://x/plain.txt":
                return b"1.1.1.1:443#US\n2.2.2.2:8443\n"
            if url == "http://x/ips.txt":
                return b"3.3.3.3\n1.1.1.1\n"
            if url == "http://x/csv.txt":
                return b"IP,port,region,ms\n4.4.4.4,443,US,10\n"
            raise AssertionError(url)

        with unittest.mock.patch.object(dp, "fetch", side_effect=fake_fetch):
            by_port, extra_all_ips, source_ip_sets = dp.load_extras(
                [("plain", "http://x/plain.txt"),
                 ("ip", "http://x/ips.txt"),
                 ("csv", "http://x/csv.txt"),
                 ("plain", "http://bad/cf.txt")],
                timeout=10,
            )
        self.assertEqual(set(by_port), {"443", "8443"})
        self.assertEqual(set(by_port["443"]), {"US", "ALL"})
        self.assertEqual(by_port["443"]["ALL"], ["3.3.3.3"])
        self.assertEqual(extra_all_ips, {"3.3.3.3", "2.2.2.2"})
        self.assertEqual(by_port["8443"]["ALL"], ["2.2.2.2"])
        self.assertIn("http://x/plain.txt", source_ip_sets)
        self.assertIn("http://x/ips.txt", source_ip_sets)
        self.assertIn("http://x/csv.txt", source_ip_sets)
        self.assertNotIn("http://bad/cf.txt", source_ip_sets)


class TestWriteSourceAttribution(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.base = Path(tempfile.mkdtemp(prefix="dp_src_"))
        self.orig_ip_sources_file = dp.IP_SOURCES_FILE
        dp.IP_SOURCES_FILE = self.base / "ip_sources.json"

    def tearDown(self):
        dp.IP_SOURCES_FILE = self.orig_ip_sources_file

    def test_main_and_extra_sources(self):
        by_port = {
            "443": {"US": ["1.1.1.1", "2.2.2.2"], "JP": ["3.3.3.3"]},
            "8443": {"US": ["1.1.1.1"]},
        }
        main_ips = {"1.1.1.1", "3.3.3.3"}
        source_ip_sets = {
            "http://x/fdip.txt": {"2.2.2.2"},
        }
        dp.write_source_attribution(by_port, main_ips, source_ip_sets)
        data = json.loads(dp.IP_SOURCES_FILE.read_text())
        sources = data["sources"]
        self.assertEqual(sources["1.1.1.1:443#US"], "main")
        self.assertEqual(sources["2.2.2.2:443#US"], "fdip")
        self.assertEqual(sources["3.3.3.3:443#JP"], "main")
        self.assertEqual(sources["1.1.1.1:8443#US"], "main")

    def test_multi_source_label(self):
        by_port = {"443": {"US": ["1.1.1.1"]}}
        main_ips: set[str] = set()
        source_ip_sets = {
            "http://x/a.txt": {"1.1.1.1"},
            "http://x/b.txt": {"1.1.1.1"},
        }
        dp.write_source_attribution(by_port, main_ips, source_ip_sets)
        data = json.loads(dp.IP_SOURCES_FILE.read_text())
        self.assertEqual(data["sources"]["1.1.1.1:443#US"], "multi")

    def test_unknown_source(self):
        by_port = {"443": {"US": ["1.1.1.1"]}}
        main_ips: set[str] = set()
        source_ip_sets: dict[str, set[str]] = {}
        dp.write_source_attribution(by_port, main_ips, source_ip_sets)
        data = json.loads(dp.IP_SOURCES_FILE.read_text())
        self.assertEqual(data["sources"]["1.1.1.1:443#US"], "unknown")

    def test_empty_by_port(self):
        dp.write_source_attribution({}, set(), {})
        data = json.loads(dp.IP_SOURCES_FILE.read_text())
        self.assertEqual(data["sources"], {})

    def test_label_from_url_stem(self):
        by_port = {"443": {"US": ["1.1.1.1"]}}
        main_ips: set[str] = set()
        source_ip_sets = {
            "https://raw.githubusercontent.com/x/BestProxy/proxy.txt": {"1.1.1.1"},
        }
        dp.write_source_attribution(by_port, main_ips, source_ip_sets)
        data = json.loads(dp.IP_SOURCES_FILE.read_text())
        self.assertEqual(data["sources"]["1.1.1.1:443#US"], "proxy")


class TestProxyMirrorSources(unittest.TestCase):
    def test_mirror_sources_parse_ipport_lines(self):
        by_port = dp.extract_plain(b"1.2.3.4:8080\n5.6.7.8:443\n")
        self.assertEqual(by_port["8080"]["ALL"], ["1.2.3.4"])
        self.assertEqual(by_port["443"]["ALL"], ["5.6.7.8"])

    def test_source_label_mapping(self):
        self.assertEqual(dp.source_label("https://x/a.txt"), "a")
        self.assertEqual(dp.source_label("https://x/proxies/http.txt"), "http")

    def test_ipdb_api_source_labels(self):
        self.assertEqual(
            dp.source_label("https://ipdb.api.030101.xyz/?type=proxy"),
            "ipdb_proxy",
        )
        self.assertEqual(
            dp.source_label("https://ipdb.api.030101.xyz/?type=bestproxy"),
            "ipdb_bestproxy",
        )

    def test_load_extras_with_url(self):
        url = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"

        def fake_fetch(u, timeout):
            self.assertEqual(u, url)
            return b"9.9.9.9:3128\n"

        with unittest.mock.patch.object(dp, "fetch", side_effect=fake_fetch):
            by_port, extra_all, source_ip_sets = dp.load_extras(
                [("plain", url)], timeout=5)
        self.assertEqual(by_port["3128"]["ALL"], ["9.9.9.9"])
        self.assertIn("9.9.9.9", source_ip_sets[url])


if __name__ == "__main__":
    unittest.main()


class TestMirrorUrls(unittest.TestCase):
    def test_raw_url_yields_ordered_mirrors(self):
        url = "https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestProxy/proxy.txt"
        mirrors = common.mirror_urls(url)
        self.assertEqual(mirrors, [
            "https://gh-proxy.com/" + url,
            "https://cdn.jsdelivr.net/gh/ymyuuu/IPDB@master/BestProxy/proxy.txt",
            "https://raw.gitmirror.com/ymyuuu/IPDB/master/BestProxy/proxy.txt",
        ])

    def test_non_raw_url_has_no_mirrors(self):
        self.assertEqual(common.mirror_urls("https://zip.cm.edu.kg/all.json"), [])
        self.assertEqual(common.mirror_urls("https://example.com/raw.githubusercontent.com/x"), [])

    def test_fetch_with_mirror_falls_back(self):
        calls = []

        class FakeResp:
            def read(self):
                return b"mirror-data"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(req, timeout=None):
            calls.append(req.full_url)
            if len(calls) == 1:
                raise OSError("blocked")
            return FakeResp()

        with unittest.mock.patch.object(common.urllib.request, "urlopen", fake_urlopen):
            data = common.fetch_with_mirror(
                "https://raw.githubusercontent.com/u/r/main/f.txt", timeout=5
            )
        self.assertEqual(data, b"mirror-data")
        self.assertEqual(calls[0], "https://raw.githubusercontent.com/u/r/main/f.txt")
        self.assertTrue(calls[1].startswith("https://gh-proxy.com/"))

    def test_fetch_with_mirror_reraises_last_error(self):
        import common as _c

        def always_fail(req, timeout=None):
            raise OSError("down")

        with unittest.mock.patch.object(_c.urllib.request, "urlopen", always_fail):
            with self.assertRaises(OSError):
                _c.fetch_with_mirror(
                    "https://raw.githubusercontent.com/u/r/main/f.txt", timeout=5
                )
