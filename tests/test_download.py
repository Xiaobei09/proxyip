"""Tests for download_proxies.py pure functions."""

import io
import json
import sys
import time
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

    def test_json_extra_falls_back_to_all_without_country(self):
        payload = self._json([
            {"ip": "1.1.1.1", "port": [443], "meta": {"country": "US"}},
            {"ip": "5.5.5.5", "port": [443]},                 # 无国家 → ALL
            {"ip": "6.6.6.6", "port": [2053], "meta": {}},    # 空 meta → ALL
        ])
        by_port = dp.extract_json_extra(payload)
        self.assertEqual(by_port["443"]["US"], ["1.1.1.1"])
        self.assertEqual(by_port["443"]["ALL"], ["5.5.5.5"])
        self.assertEqual(by_port["2053"]["ALL"], ["6.6.6.6"])

    def test_json_extra_tolerant_malformed(self):
        self.assertEqual(dp.extract_json_extra(b'{"generated_at": "x"}'), {})
        self.assertEqual(dp.extract_json_extra(b"not json"), {})
        self.assertEqual(dp.extract_json_extra(b'{"data": [{"ip": "bad"}]}'), {})


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
        # 扩充的常见机场码
        self.assertEqual(dp.normalize_country("KUL"), "MY")
        self.assertEqual(dp.normalize_country("BKK"), "TH")
        self.assertEqual(dp.normalize_country("DXB"), "AE")
        self.assertEqual(dp.normalize_country("SYD"), "AU")
        self.assertEqual(dp.normalize_country("LHR"), "GB")
        self.assertEqual(dp.normalize_country("JFK"), "US")
        self.assertEqual(dp.normalize_country("YYZ"), "CA")

    def test_emoji_flag(self):
        self.assertEqual(dp.normalize_country("\U0001F1FA\U0001F1F8US"), "US")

    def test_unmappable(self):
        self.assertEqual(dp.normalize_country("zzz"), "ALL")
        self.assertEqual(dp.normalize_country("东京"), "ALL")

    def test_speed_prefixed_notes(self):
        # Wwuyi123/CF-Proxyip 的 ``IP#速度(MB/s)地区`` 注释：以前全落 ALL，
        # 现在应直接提取地区，减少 ip-api 往返。
        self.assertEqual(dp.normalize_country("256.85(MB/s)HK香港"), "HK")
        self.assertEqual(dp.normalize_country("222.32(MB/s)日本"), "JP")
        self.assertEqual(dp.normalize_country("1024.2(MB/s)新加坡"), "SG")
        self.assertEqual(dp.normalize_country("43.70(MB/s)JP日本"), "JP")
        self.assertEqual(dp.normalize_country("36.90(MB/s)HK香港"), "HK")

    def test_speed_prefixed_iso2(self):
        self.assertEqual(dp.normalize_country("88.3(MB/s)US"), "US")
        self.assertEqual(dp.normalize_country("256.85(MB/s)HK"), "HK")
        # 带单位但无括号
        self.assertEqual(dp.normalize_country("50.2MB/sHKSAR"), "HK")
        # 大小写/不同单位
        self.assertEqual(dp.normalize_country("218.3(Mbps)日本"), "JP")
        self.assertEqual(dp.normalize_country("88.3(MB/s)US(US)"), "US")

    def test_speed_prefixed_keeps_prior_paths(self):
        # 带数字的注释不应破坏既有无数字路径
        self.assertEqual(dp.normalize_country("us"), "US")
        self.assertEqual(dp.normalize_country("香港"), "HK")
        self.assertEqual(dp.normalize_country("NRT"), "JP")
        self.assertEqual(dp.normalize_country("zzz"), "ALL")

    def test_all_sentinel_not_country(self):
        # ``#ALL`` 是"无国家"哨兵，绝不能被 [A-Z]{2}$ 误判成 LL 桶
        self.assertEqual(dp.normalize_country("ALL"), "ALL")
        self.assertEqual(dp.normalize_country("all"), "ALL")
        self.assertEqual(dp.normalize_country("all-abc"), "ALL")
        self.assertEqual(dp.normalize_country("ALL-1"), "ALL")
        by = dp.extract_plain(b"1.2.3.5:443#ALL\n")
        self.assertEqual(by["443"].get("LL"), None)
        self.assertEqual(len(by["443"].get("ALL", [])), 1)


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
            if url == "http://x/data.json":
                return json.dumps({"data": [
                    {"ip": "5.5.5.5", "port": [443], "meta": {"country": "JP"}},
                    {"ip": "6.6.6.6", "port": [2053]},  # 无 meta → ALL
                ]}).encode()
            raise AssertionError(url)

        with unittest.mock.patch.object(dp, "fetch", side_effect=fake_fetch):
            by_port, extra_all_ips, source_ip_sets = dp.load_extras(
                [("plain", "http://x/plain.txt"),
                 ("ip", "http://x/ips.txt"),
                 ("csv", "http://x/csv.txt"),
                 ("json", "http://x/data.json"),
                 ("plain", "http://bad/cf.txt")],
                timeout=10,
            )
        self.assertEqual(set(by_port), {"443", "8443", "2053"})
        self.assertEqual(set(by_port["443"]), {"US", "ALL", "JP"})
        self.assertEqual(by_port["443"]["ALL"], ["3.3.3.3"])
        self.assertEqual(by_port["443"]["JP"], ["5.5.5.5"])
        self.assertEqual(by_port["2053"]["ALL"], ["6.6.6.6"])
        self.assertEqual(extra_all_ips, {"3.3.3.3", "2.2.2.2", "6.6.6.6"})
        self.assertEqual(by_port["8443"]["ALL"], ["2.2.2.2"])
        self.assertIn("http://x/plain.txt", source_ip_sets)
        self.assertIn("http://x/ips.txt", source_ip_sets)
        self.assertIn("http://x/csv.txt", source_ip_sets)
        self.assertIn("http://x/data.json", source_ip_sets)
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

    def test_ipdb_proxy_and_bestproxy_sources_registered(self):
        # 同源族（ymyuuu/IPDB 非 CF 反代池）的 proxy + bestproxy 都应默认启用，
        # 扩大覆盖与可用性，且各带可读标签。
        urls = [u for _kind, u in dp.EXTRA_SOURCES]
        self.assertIn("https://ipdb.api.030101.xyz/?type=proxy", urls)
        self.assertIn("https://ipdb.api.030101.xyz/?type=bestproxy", urls)
        self.assertEqual(
            dp.source_label("https://ipdb.api.030101.xyz/?type=bestproxy"),
            "ipdb_bestproxy",
        )

    def test_cf_country_scoped_and_leilao_sources_registered(self):
        # bestproxy&country=true（IP#CC 格式、非 CF 反代）+ LeilaoMi 精选池
        # 均为非 CF ASN，默认启用以提升覆盖，且各带可读标签。
        urls = [u for _kind, u in dp.EXTRA_SOURCES]
        self.assertIn("https://ipdb.api.030101.xyz/?type=bestproxy&country=true", urls)
        self.assertIn(
            "https://raw.githubusercontent.com/LeilaoMi/cf-proxyip-us/main/docs/all.txt",
            urls,
        )
        self.assertEqual(
            dp.source_label("https://ipdb.api.030101.xyz/?type=bestproxy&country=true"),
            "ipdb_bestproxy_cc",
        )
        self.assertEqual(
            dp.source_label(
                "https://raw.githubusercontent.com/LeilaoMi/cf-proxyip-us/main/docs/all.txt"
            ),
            "leilao_cfproxy",
        )

    def test_country_code_noted_lines_parse_as_bare_ips(self):
        # bestproxy&country=true 采用 ip#CC 元数据标记（无端口），必须经
        # extract_bare_ips 解析成功并去掉 #CC 后缀，而非落入 plain/port 分支。
        by_port = dp.extract_bare_ips(b"47.242.218.87#HK\n132.226.16.97#SG\n")
        total = sum(len(v) for c in by_port.values() for v in c.values())
        self.assertEqual(total, 2)

    def test_non_cf_cloud_pools_excluded(self):
        # 策略：代理源只收「自称 CF 第三方反代 proxyip」。非 CF 云池
        # （阿里/谷歌/Edge 等 BestAli/BestGC/BestEDG）不得入池。
        urls = [u for _kind, u in dp.EXTRA_SOURCES]
        for u in (
            "https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestAli/bestaliv4.txt",
            "https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestGC/bestgcv4.txt",
            "https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestGC/bestgcv6.txt",
            "https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestEDG/bestedgv4.txt",
        ):
            self.assertNotIn(u, urls)

    def test_all_mirrors_are_disambiguated_by_host(self):
        # 不同 all.json 镜像必须得到不同标签，避免 stats/归属互覆
        a = dp.source_label("https://mirror-a.com/all.json")
        b = dp.source_label("https://mirror-b.com/all.json")
        self.assertNotEqual(a, b)
        self.assertEqual(a, "mirror-a/all")
        self.assertEqual(b, "mirror-b/all")
        # 同主机 all.json 与 all.zip 标签一致（冗余互换），跨主机才需区分
        self.assertEqual(
            dp.source_label("https://mirror-a.com/all.zip"), "mirror-a/all"
        )
        # 带上 githubusercontent 路径段来源
        self.assertTrue(
            dp.source_label("https://raw.githubusercontent.com/x/y/main/all.json")
        )

    def test_non_generic_labels_unchanged(self):
        self.assertEqual(dp.source_label("https://x/fdip.txt"), "fdip")

    def test_generic_http_pools_excluded(self):
        # 策略：代理源只收「自称 CF 第三方反代 proxyip」。通用 HTTP/SOCKS
        # 代理池（monosans/zevtyardt/.../clarketm/sunny9577/jetkai/roosterkid/
        # ShiftyTr）不得入池。
        urls = [u for _kind, u in dp.EXTRA_SOURCES]
        for u in (
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt",
            "https://raw.githubusercontent.com/Syscallh00k/proxy-list/main/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/master/HTTPS_RAW.txt",
            "https://raw.githubusercontent.com/ShiftyTr/proxy-list/master/http.txt",
        ):
            self.assertNotIn(u, urls)

    def test_all_extra_sources_are_cf_proxyip_kind(self):
        # 策略总闸：EXTRA_SOURCES 任何一项的端口来源都必须是 CF 反代池。
        # kind 仅允许 ip（裸 IP→443）/plain（ip:443#CC）/csv（443 端口优选榜单）。
        for kind, url in dp.EXTRA_SOURCES:
            self.assertIn(kind, ("ip", "plain", "csv"))

    def test_five_cf_proxyip_sources_registered(self):
        # 新一批 A 类：Wwuyi123/CF-Proxyip（3 文件）与 wanwushequ/ProxyIP
        # 地区优选榜（US/JP），均裸 IP 入 443 桶，各带可读标签。
        urls = [u for _kind, u in dp.EXTRA_SOURCES]
        for u, label in (
            ("https://raw.githubusercontent.com/Wwuyi123/CF-Proxyip/main/proxyip.txt",
             "wwuyi_proxyip"),
            ("https://raw.githubusercontent.com/Wwuyi123/CF-Proxyip/main/proxyip_with_country.txt",
             "wwuyi_proxyip_cc"),
            ("https://raw.githubusercontent.com/Wwuyi123/CF-Proxyip/main/ips/all_ips.txt",
             "wwuyi_all"),
            ("https://raw.githubusercontent.com/wanwushequ/ProxyIP/main/US.txt",
             "wanwu_us"),
            ("https://raw.githubusercontent.com/wanwushequ/ProxyIP/main/JP.txt",
             "wanwu_jp"),
        ):
            self.assertIn(u, urls)
            self.assertEqual(dp.source_label(u), label)

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


class TestFetchExtraRetry(unittest.TestCase):
    def test_succeeds_after_transient_failure(self):
        calls = {"n": 0}

        def flaky(url, timeout):
            calls["n"] += 1
            if calls["n"] < 3:
                raise TimeoutError("transient")
            return b"1.2.3.4\n"

        with unittest.mock.patch.object(dp, "fetch", side_effect=flaky):
            out = dp._fetch_extra_retry("http://x/ip", 10, attempts=3)
        self.assertEqual(out, b"1.2.3.4\n")
        self.assertEqual(calls["n"], 3)

    def test_raises_after_attempts_exhausted(self):
        calls = {"n": 0}

        def down(url, timeout):
            calls["n"] += 1
            raise OSError("down")

        with unittest.mock.patch.object(dp, "fetch", side_effect=down):
            with self.assertRaises(OSError):
                dp._fetch_extra_retry("http://x/ip", 10, attempts=2)
        self.assertEqual(calls["n"], 2)

    def test_no_retry_on_success(self):
        with unittest.mock.patch.object(
            dp, "fetch", return_value=b"9.9.9.9\n"
        ):
            out = dp._fetch_extra_retry("http://x/ip", 10, attempts=3)
        self.assertEqual(out, b"9.9.9.9\n")


class TestMainResilience(unittest.TestCase):
    def test_primary_fails_extras_keep_pool(self):
        extra_pool = {"443": {"US": ["1.1.1.1"]}}
        wo = unittest.mock.Mock(return_value=(
            {
                "__total__": 1, "__unique__": 1, "__countries__": 1,
                "__ports__": 1, "__sets__": {}, "443": 1,
            },
            ["1.1.1.1:443#US"],
        ))
        patchers = [
            unittest.mock.patch.object(
                dp, "load_source", side_effect=OSError("primary down")
            ),
            unittest.mock.patch.object(
                dp, "load_extras",
                return_value=(extra_pool, {"1.1.1.1"}, {"https://x/ip": {"1.1.1.1"}}),
            ),
            unittest.mock.patch.object(dp, "enrich_countries", return_value=0),
            unittest.mock.patch.object(dp, "write_outputs", wo),
            unittest.mock.patch.object(dp, "write_source_attribution"),
            unittest.mock.patch.object(dp, "_append_source_history"),
            unittest.mock.patch.object(
                dp, "_build_source_stats", return_value={
                    "main (zip.cm.edu.kg)": {"total": 0, "unique": 0, "overlap": 0},
                }
            ),
            unittest.mock.patch.object(dp, "write_text_if_changed"),
            unittest.mock.patch.object(dp, "load_previous_all", return_value=[]),
            unittest.mock.patch.object(dp, "write_diff", return_value=(1, 0)),
            unittest.mock.patch.object(dp, "append_history"),
            unittest.mock.patch.object(dp, "print_stats"),
            unittest.mock.patch.object(dp, "write_upstream_meta"),
        ]
        for p in patchers:
            p.start()
        try:
            rc = dp.main(["--no-extra-sources"])
        finally:
            for p in patchers:
                p.stop()

        self.assertEqual(rc, 0)
        wo.assert_called_once()
        called_by_port = wo.call_args[0][0]
        self.assertEqual(called_by_port["443"]["US"], ["1.1.1.1"])

    def test_both_fail_refuses_to_truncate(self):
        wo = unittest.mock.Mock()
        patchers = [
            unittest.mock.patch.object(
                dp, "load_source", side_effect=OSError("primary down")
            ),
            unittest.mock.patch.object(
                dp, "load_extras", return_value=({}, set(), {})
            ),
            unittest.mock.patch.object(dp, "enrich_countries", return_value=0),
            unittest.mock.patch.object(dp, "write_outputs", wo),
            unittest.mock.patch.object(dp, "write_source_attribution"),
            unittest.mock.patch.object(dp, "_append_source_history"),
            unittest.mock.patch.object(
                dp, "_build_source_stats", return_value={
                    "main (zip.cm.edu.kg)": {"total": 0, "unique": 0, "overlap": 0},
                }
            ),
            unittest.mock.patch.object(dp, "write_text_if_changed"),
            unittest.mock.patch.object(dp, "load_previous_all", return_value=[]),
            unittest.mock.patch.object(dp, "write_diff", return_value=(0, 0)),
            unittest.mock.patch.object(dp, "append_history"),
            unittest.mock.patch.object(dp, "print_stats"),
            unittest.mock.patch.object(dp, "write_upstream_meta"),
        ]
        for p in patchers:
            p.start()
        try:
            rc = dp.main(["--no-extra-sources"])
        finally:
            for p in patchers:
                p.stop()

        self.assertEqual(rc, 1)
        wo.assert_not_called()


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

    def test_fetch_with_mirror_hang_is_capped_by_deadline(self):
        import common as _c

        class NeverEndingResp:
            def read(self):
                while True:  # 永不返回：模拟只发 200 头、body 无限阻塞的上游
                    time.sleep(0.05)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(req, timeout=None):
            return NeverEndingResp()

        with unittest.mock.patch.object(_c.urllib.request, "urlopen", fake_urlopen):
            t0 = time.monotonic()
            with self.assertRaises(TimeoutError):
                _c.fetch_with_mirror(
                    "https://raw.githubusercontent.com/u/r/main/f.txt", timeout=0.3
                )
            elapsed = time.monotonic() - t0
        # 整体截止必须兜住 read() 无限阻塞，而不依赖 socket 超时（0.3s + 缓冲）。
        # 3 个 mirror candidate 每个 ~1.3s 截止，总耗时须远小于"无限挂死"。
        self.assertLess(elapsed, 8.0)

    def test_deadline_open_context_manager_caps_hang(self):
        import common as _c

        class NeverEndingResp:
            def read(self):
                while True:
                    time.sleep(0.05)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(req, timeout=None):
            return NeverEndingResp()

        with unittest.mock.patch.object(_c.urllib.request, "urlopen", fake_urlopen):
            t0 = time.monotonic()
            with self.assertRaises(TimeoutError):
                with _c.deadline_open(
                    _c.urllib.request.Request("https://zip.example/all.json"), 0.3
                ) as resp:
                    resp.read()
            elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 4.0)
