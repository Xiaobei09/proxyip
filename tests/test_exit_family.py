"""Tests for exit_family.py pure functions."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import exit_family as ef


V6_IP = "2a0a:4cc0:80:2315:a4cc:d3ff:fe19:8f6f"
V4_IP = "192.155.85.13"


class TestParseTrace(unittest.TestCase):
    def test_parses_trace(self):
        body = b"fl=1\nip=1.2.3.4\nloc=US\ntls=TLSv1.3\n"
        trace = ef.parse_trace(body)
        self.assertEqual(trace["ip"], "1.2.3.4")
        self.assertEqual(trace["loc"], "US")
        self.assertEqual(trace["fl"], "1")

    def test_empty(self):
        self.assertEqual(ef.parse_trace(b""), {})


class TestClassify(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(ef.classify_family("1.2.3.4", None), "ipv4")
        self.assertEqual(ef.classify_family(None, V6_IP), "ipv6")
        self.assertEqual(ef.classify_family("1.2.3.4", V6_IP), "dual")
        self.assertEqual(ef.classify_family(None, None), "unknown")


class TestTlsExit(unittest.TestCase):
    def test_v6_exit(self):
        with mock.patch.object(ef, "request_tls_sni", return_value=(200, {}, f"ip={V6_IP}\nloc=AT\n".encode())):
            res = ef.tls_exit("1.2.3.4", "443", 10)
        self.assertEqual(res["family"], "ipv6")
        self.assertEqual(res["ip"], V6_IP)

    def test_v4_exit(self):
        with mock.patch.object(ef, "request_tls_sni", return_value=(200, {}, f"ip={V4_IP}\n".encode())):
            self.assertEqual(ef.tls_exit("1.2.3.4", "443", 10)["family"], "ipv4")

    def test_no_ip(self):
        with mock.patch.object(ef, "request_tls_sni", return_value=(200, {}, b"fl=1\n")):
            self.assertEqual(ef.tls_exit("1.2.3.4", "443", 10)["family"], "unknown")

    def test_connection_fail(self):
        with mock.patch.object(ef, "request_tls_sni", return_value=(None, {}, b"")):
            self.assertEqual(ef.tls_exit("1.2.3.4", "443", 10)["family"], "unknown")


class TestConnectExit(unittest.TestCase):
    def test_dual(self):
        def echo(ip, port, host, timeout):
            return V4_IP if host == ef.ECHO_V4_HOST else V6_IP

        with mock.patch.object(ef, "connect_echo", side_effect=echo):
            res = ef.connect_exit("1.2.3.4", "80", 10)
        self.assertEqual(res["family"], "dual")
        self.assertEqual(res["exit_v4"], V4_IP)
        self.assertEqual(res["exit_v6"], V6_IP)

    def test_v4_only(self):
        def echo(ip, port, host, timeout):
            return V4_IP if host == ef.ECHO_V4_HOST else None

        with mock.patch.object(ef, "connect_echo", side_effect=echo):
            self.assertEqual(ef.connect_exit("1.2.3.4", "80", 10)["family"], "ipv4")

    def test_v6_only(self):
        def echo(ip, port, host, timeout):
            return None if host == ef.ECHO_V4_HOST else V6_IP

        with mock.patch.object(ef, "connect_echo", side_effect=echo):
            self.assertEqual(ef.connect_exit("1.2.3.4", "80", 10)["family"], "ipv6")

    def test_unknown(self):
        with mock.patch.object(ef, "connect_echo", return_value=None):
            self.assertEqual(ef.connect_exit("1.2.3.4", "80", 10)["family"], "unknown")


class TestCheckOne(unittest.TestCase):
    def test_tls_method(self):
        with mock.patch.object(
            ef, "tls_exit", return_value={"status": "ok", "family": "ipv6", "ip": V6_IP}
        ):
            item = ("1.2.3.4:443#US", "1.2.3.4:443#US", "1.2.3.4", "443", "US")
            key, res = ef.check_one(item, {"1.2.3.4:443#US": "tls"}, 10)
        self.assertEqual(res["method"], "tls")
        self.assertEqual(res["family"], "ipv6")
        self.assertEqual(res["exit_v6"], V6_IP)
        self.assertIsNone(res["exit_v4"])
        self.assertIn("ts", res)

    def test_connect_method(self):
        with mock.patch.object(
            ef, "connect_exit",
            return_value={"status": "ok", "family": "dual", "exit_v4": V4_IP, "exit_v6": V6_IP},
        ):
            item = ("5.6.7.8:8080#US", "5.6.7.8:8080#US", "5.6.7.8", "8080", "US")
            key, res = ef.check_one(item, {"5.6.7.8:8080#US": "connect"}, 10)
        self.assertEqual(res["method"], "connect")
        self.assertEqual(res["family"], "dual")
        self.assertEqual(res["exit_v4"], V4_IP)

    def test_default_tls_when_unknown(self):
        with mock.patch.object(
            ef, "tls_exit", return_value={"status": "ok", "family": "ipv4", "ip": V4_IP}
        ):
            item = ("9.9.9.9:443#US", "9.9.9.9:443#US", "9.9.9.9", "443", "US")
            key, res = ef.check_one(item, {}, 10)
        self.assertEqual(res["method"], "tls")
        self.assertEqual(res["family"], "ipv4")


class TestNotes(unittest.TestCase):
    def test_has_family_note(self):
        self.assertTrue(ef.has_family_note("1.2.3.4:80#US-1ms-CN-V4"))
        self.assertTrue(ef.has_family_note("1.2.3.4:80#US-1ms-DS"))
        self.assertFalse(ef.has_family_note("1.2.3.4:80#US-1ms-CN"))
        self.assertFalse(ef.has_family_note("1.2.3.4:80#\U0001F1FA\U0001F1F8US-1ms"))

    def test_all_line_note(self):
        line = "9.9.9.9:80#ALL-120ms-0.44MB/s-V4"
        self.assertEqual(ef._note(line), "-120ms-0.44MB/s-V4")
        self.assertTrue(ef.has_family_note(line))
        self.assertEqual(
            ef.annotate_family("9.9.9.9:80#ALL-120ms", "ipv4"),
            "9.9.9.9:80#ALL-120ms-V4",
        )

    def test_annotate_family(self):
        self.assertEqual(ef.annotate_family("1.2.3.4:80#US-1ms", "ipv4"),
                         "1.2.3.4:80#US-1ms-V4")
        self.assertEqual(ef.annotate_family("1.2.3.4:80#US-1ms-V4", "ipv4"),
                         "1.2.3.4:80#US-1ms-V4")
        self.assertEqual(ef.annotate_family("1.2.3.4:80#US-1ms", "dual"),
                         "1.2.3.4:80#US-1ms-DS")
        self.assertEqual(ef.annotate_family("1.2.3.4:80#US-1ms", "unknown"),
                         "1.2.3.4:80#US-1ms")


class TestSplit(unittest.TestCase):
    def setUp(self):
        self.results = {
            "1.1.1.1:80#US": {"line": "1.1.1.1:80#US-1ms", "family": "ipv4"},
            "2.2.2.2:80#US": {"line": "2.2.2.2:80#US-2ms", "family": "ipv6"},
            "3.3.3.3:80#US": {"line": "3.3.3.3:80#US-3ms", "family": "dual"},
            "4.4.4.4:80#US": {"line": "4.4.4.4:80#US-4ms", "family": "unknown"},
        }

    def test_dual_in_both(self):
        v4, v6 = ef.split_by_family(self.results)
        self.assertEqual(len(v4), 2)
        self.assertEqual(len(v6), 2)
        self.assertIn("3.3.3.3:80#US-3ms-DS", v4)
        self.assertIn("3.3.3.3:80#US-3ms-DS", v6)

    def test_unknown_excluded(self):
        v4, v6 = ef.split_by_family(self.results)
        for lines in (v4, v6):
            self.assertFalse(any("4.4.4.4" in l for l in lines))

    def test_annotated_output(self):
        v4, _ = ef.split_by_family(self.results)
        self.assertIn("1.1.1.1:80#US-1ms-V4", v4)


class TestLoadSample(unittest.TestCase):
    def _path(self, name):
        return Path(tempfile.mkdtemp(prefix="ef_")) / name

    def test_load_respects_limit(self):
        path = self._path("exit_family_sample.txt")
        path.write_text(
            "1.1.1.1:80#US-1ms\n2.2.2.2:80#US-2ms\n3.3.3.3:80#US-3ms\n",
            encoding="utf-8",
        )
        sample = ef.load_sample(path, limit=2)
        self.assertEqual(len(sample), 2)
        self.assertEqual(sample[0][1], "1.1.1.1:80#US")

    def test_skips_bad_lines(self):
        path = self._path("exit_family_sample_bad.txt")
        path.write_text("garbage\n4.4.4.4:80#US-4ms\n", encoding="utf-8")
        sample = ef.load_sample(path, limit=0)
        self.assertEqual([s[1] for s in sample], ["4.4.4.4:80#US"])


class TestUpstreamMeta(unittest.TestCase):
    def setUp(self):
        self._base = Path(tempfile.mkdtemp(prefix="efm_"))
        self.meta_file = self._base / "upstream_meta_test.json"

    def _write(self, data):
        self.meta_file.write_text(json.dumps(data), encoding="utf-8")

    def tearDown(self):
        self.meta_file.unlink(missing_ok=True)
        self._base.rmdir()

    def test_missing_file_returns_empty(self):
        self.meta_file.unlink(missing_ok=True)
        self.assertEqual(ef.load_upstream_meta(self.meta_file), {})

    def test_corrupt_file_returns_empty(self):
        self.meta_file.write_text("{not json", encoding="utf-8")
        self.assertEqual(ef.load_upstream_meta(self.meta_file), {})

    def test_non_dict_returns_empty(self):
        self.meta_file.write_text("[1,2]", encoding="utf-8")
        self.assertEqual(ef.load_upstream_meta(self.meta_file), {})

    def test_loads_map(self):
        self._write({"1.1.1.1": {"clientIp": "2603:c020::1", "family": "ipv6"}})
        data = ef.load_upstream_meta(self.meta_file)
        self.assertEqual(data["1.1.1.1"]["family"], "ipv6")

    def test_loads_wrapped_map(self):
        self._write({"proxies": {"1.1.1.1": {"family": "ipv6"}}})
        data = ef.load_upstream_meta(self.meta_file)
        self.assertEqual(data["1.1.1.1"]["family"], "ipv6")


class TestCrossCheck(unittest.TestCase):
    def _res(self, ip, family):
        return {"line": f"{ip}:443#US", "ip": ip, "family": family}

    def test_match_and_mismatch(self):
        upstream = {
            "1.1.1.1": {"clientIp": "2603:c020::1", "family": "ipv6"},
            "2.2.2.2": {"clientIp": "2.2.2.2", "family": "ipv4"},
        }
        results = {
            "1.1.1.1:443#US": self._res("1.1.1.1", "ipv6"),
            "2.2.2.2:443#US": self._res("2.2.2.2", "ipv6"),
            "3.3.3.3:443#US": self._res("3.3.3.3", "ipv4"),
        }
        ef.cross_check(results, upstream)
        self.assertIs(results["1.1.1.1:443#US"]["upstream_match"], True)
        self.assertEqual(results["1.1.1.1:443#US"]["upstream_client_ip"], "2603:c020::1")
        self.assertIs(results["2.2.2.2:443#US"]["upstream_match"], False)
        self.assertIs(results["3.3.3.3:443#US"]["upstream_absent"], True)
        self.assertNotIn("upstream_match", results["3.3.3.3:443#US"])

    def test_unknown_probe_skips_comparison(self):
        upstream = {"1.1.1.1": {"clientIp": "2603:c020::1", "family": "ipv6"}}
        results = {"1.1.1.1:443#US": self._res("1.1.1.1", "unknown")}
        ef.cross_check(results, upstream)
        self.assertIs(results["1.1.1.1:443#US"]["upstream_match"], None)
        self.assertIs(results["1.1.1.1:443#US"]["upstream_absent"], False)


if __name__ == "__main__":
    unittest.main()
