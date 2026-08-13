"""Tests for quality_check.py pure functions."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import quality_check as qc


class TestParseEntry(unittest.TestCase):
    def test_parses_ltd_line(self):
        self.assertEqual(
            qc.parse_ltd_line("1.2.3.4:443#\U0001F1FA\U0001F1F8US-8ms-5.86MB/s"),
            ("1.2.3.4:443#US", "1.2.3.4", "443", "US"),
        )

    def test_parses_line_without_flag(self):
        self.assertEqual(
            qc.parse_ltd_line("1.2.3.4:443#US-8ms"),
            ("1.2.3.4:443#US", "1.2.3.4", "443", "US"),
        )

    def test_rejects_bad_lines(self):
        self.assertIsNone(qc.parse_ltd_line(""))
        self.assertIsNone(qc.parse_ltd_line("garbage"))
        self.assertIsNone(qc.parse_ltd_line("1.2.3.4:443"))
        self.assertIsNone(qc.parse_ltd_line("1.2.3.4:abc#US-1ms"))

    def test_line_to_key(self):
        self.assertEqual(
            qc.line_to_key("5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-80ms-1.25MB/s"),
            "5.6.7.8:8443#JP",
        )
        self.assertIsNone(qc.line_to_key(""))


class TestParseHeaders(unittest.TestCase):
    def test_parses_status_and_headers(self):
        raw = b"HTTP/1.1 301 Moved\r\nLocation: https://x/?country=DE\r\ncontent-length: 0\r\n\r\n"
        status, headers = qc.parse_headers(raw)
        self.assertEqual(status, 301)
        self.assertEqual(headers["location"], "https://x/?country=DE")
        self.assertEqual(headers["content-length"], "0")

    def test_bad_status(self):
        status, headers = qc.parse_headers(b"garbage\r\n")
        self.assertIsNone(status)
        self.assertEqual(headers, {})


class TestServiceParsers(unittest.TestCase):
    def test_netflix_ok(self):
        res = qc.parse_netflix(200, {}, b'{"data":{"countryCode":"US"}}')
        self.assertEqual(res, {"status": "ok", "region": "US"})

    def test_netflix_blocked(self):
        res = qc.parse_netflix(404, {}, b"Not Available in your region")
        self.assertEqual(res["status"], "blocked")

    def test_netflix_error(self):
        self.assertEqual(qc.parse_netflix(500, {}, b"")["status"], "error")

    def test_disney_ok_with_region(self):
        res = qc.parse_disney(200, {}, b'{"countryCode":"JP"}')
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["region"], "JP")

    def test_disney_ok_without_region(self):
        self.assertEqual(qc.parse_disney(200, {}, b"<html>app</html>"),
                         {"status": "ok", "region": None})

    def test_disney_blocked(self):
        self.assertEqual(qc.parse_disney(403, {}, b"")["status"], "blocked")

    def test_youtube_ok(self):
        res = qc.parse_youtube(200, {}, b'var ytcfg = {"countryCode":"JP"};')
        self.assertEqual(res, {"status": "ok", "region": "JP"})

    def test_youtube_blocked(self):
        self.assertEqual(qc.parse_youtube(403, {}, b"")["status"], "blocked")

    def test_max_ok_from_location(self):
        res = qc.parse_max(
            301, {"location": "https://www.max.com/en-de?country=DE"}, b""
        )
        self.assertEqual(res, {"status": "ok", "region": "DE"})

    def test_max_blocked(self):
        self.assertEqual(qc.parse_max(503, {}, b"")["status"], "blocked")

    def test_prime_ok_from_location(self):
        res = qc.parse_prime(
            302,
            {"location": "https://www.primevideo.com/?country=US&foo=1"},
            b"",
        )
        self.assertEqual(res, {"status": "ok", "region": "US"})

    def test_prime_ok_from_body(self):
        res = qc.parse_prime(200, {}, b'{"currentTerritory":"SG"}')
        self.assertEqual(res, {"status": "ok", "region": "SG"})

    def test_prime_blocked(self):
        self.assertEqual(qc.parse_prime(503, {}, b"")["status"], "blocked")

    def test_openai_ok(self):
        res = qc.parse_openai(200, {}, b"ip=1.2.3.4\nloc=US\ncolo=LAX\n")
        self.assertEqual(res, {"status": "ok", "region": "US"})

    def test_openai_blocked(self):
        self.assertEqual(qc.parse_openai(403, {}, b"")["status"], "blocked")

    def test_openai_error(self):
        self.assertEqual(qc.parse_openai(500, {}, b"")["status"], "error")


class TestGroupChunks(unittest.TestCase):
    def test_chunking(self):
        self.assertEqual(qc.group_chunks(list(range(250)), 100), [
            list(range(100)), list(range(100, 200)), list(range(200, 250)),
        ])

    def test_empty(self):
        self.assertEqual(qc.group_chunks([], 100), [])


class TestIpTypeAndRisk(unittest.TestCase):
    def test_classify_ip(self):
        self.assertEqual(qc.classify_ip({"hosting": True}), "DC")
        self.assertEqual(qc.classify_ip({"mobile": True}), "MOB")
        self.assertEqual(qc.classify_ip({"proxy": True}), "PROXY")
        self.assertEqual(qc.classify_ip({}), "RES")

    def test_derive_risk_keyless(self):
        self.assertEqual(
            qc.derive_risk({"proxy": True, "hosting": True}, None), "high"
        )
        self.assertEqual(
            qc.derive_risk({"proxy": True, "hosting": False}, None), "medium"
        )
        self.assertEqual(
            qc.derive_risk({"proxy": False, "hosting": False}, None), "low"
        )

    def test_derive_risk_from_score(self):
        self.assertEqual(
            qc.derive_risk({}, {"score": 90}), "high"
        )
        self.assertEqual(
            qc.derive_risk({}, {"score": 50}), "medium"
        )
        self.assertEqual(
            qc.derive_risk({}, {"score": 10}), "low"
        )


class TestBuildIpinfo(unittest.TestCase):
    def test_dual_stack_and_match(self):
        results = {
            "1.2.3.4:443#US": {
                "key": "1.2.3.4:443#US", "cc": "US",
                "v4": "9.9.9.9", "v6": "2606:4700::1",
            }
        }
        geo = {
            "9.9.9.9": {
                "status": "success", "country": "United States",
                "countryCode": "US", "regionName": "California",
                "as": "AS1 X", "asn": "AS1", "org": "Org",
                "isp": "Isp", "proxy": False, "hosting": True,
                "mobile": False,
            }
        }
        info = qc.build_ipinfo_map(results, geo, {})["1.2.3.4:443#US"]
        self.assertEqual(info["exit_ip"], "9.9.9.9")
        self.assertEqual(info["family"], "dual")
        self.assertTrue(info["dual_stack"])
        self.assertTrue(info["country_match"])
        self.assertEqual(info["ip_type"], "DC")
        self.assertEqual(info["risk"], "medium")

    def test_mismatch_country(self):
        results = {
            "1.2.3.4:443#JP": {
                "key": "1.2.3.4:443#JP", "cc": "JP",
                "v4": "8.8.8.8", "v6": None,
            }
        }
        geo = {"8.8.8.8": {"status": "success", "countryCode": "US"}}
        info = qc.build_ipinfo_map(results, geo, {})["1.2.3.4:443#JP"]
        self.assertFalse(info["country_match"])
        self.assertEqual(info["family"], "ipv4")


class TestAnnotation(unittest.TestCase):
    def test_streaming_tokens(self):
        streaming = {
            "netflix": {"status": "ok", "region": "US"},
            "disney": {"status": "ok", "region": None},
            "youtube": {"status": "ok", "region": "JP"},
            "max": {"status": "blocked"},
            "prime": {"status": "ok", "region": None},
            "openai": {"status": "ok", "region": "US"},
        }
        self.assertEqual(
            qc.streaming_tokens(streaming), "NF(US) D+ YT PV GPT"
        )

    def test_streaming_tokens_empty(self):
        streaming = {name: {"status": "blocked"} for name in qc.SERVICES}
        self.assertEqual(qc.streaming_tokens(streaming), "")

    def test_type_tokens(self):
        self.assertEqual(
            qc.type_tokens({"ip_type": "RES", "family": "dual"}), "RES DS"
        )
        self.assertEqual(
            qc.type_tokens({"ip_type": "MOB", "family": "ipv6"}), "MOB V6"
        )
        self.assertEqual(qc.type_tokens({"ip_type": "", "family": "ipv4"}), "")

    def test_build_annotation(self):
        self.assertEqual(
            qc.build_annotation("NF(US) D+ YT GPT", "DC"), "NF(US) D+ YT GPT-DC"
        )
        self.assertEqual(qc.build_annotation("", "CF"), "CF")
        self.assertEqual(qc.build_annotation("", ""), "")

    def test_annotate_text(self):
        annotations = {
            "1.2.3.4:443#US": "NF(US)-DC",
            "5.6.7.8:8443#JP": "GPT-CF",
        }
        text = (
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-120ms-0.44MB/s\n"
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-80ms\n"
            "9.9.9.9:443#\U0001F1FA\U0001F1F8US-50ms\n"
        )
        out, changed = qc.annotate_text(text, annotations)
        self.assertTrue(changed)
        lines = out.splitlines()
        self.assertTrue(lines[0].endswith("-NF(US)-DC"))
        self.assertTrue(lines[1].endswith("-GPT-CF"))
        self.assertFalse(lines[2].endswith("-"))


class TestFinalize(unittest.TestCase):
    def test_netflix_native(self):
        results = {
            "1.2.3.4:443#US": {
                "key": "1.2.3.4:443#US",
                "streaming": {"netflix": {"status": "ok", "region": "US"}},
            },
            "5.6.7.8:8443#JP": {
                "key": "5.6.7.8:8443#JP",
                "streaming": {"netflix": {"status": "ok", "region": "US"}},
            },
        }
        ipinfo = {
            "1.2.3.4:443#US": {"country_code": "US"},
            "5.6.7.8:8443#JP": {"country_code": "JP"},
        }
        streaming = qc.finalize_streaming(results, ipinfo)
        self.assertTrue(streaming["1.2.3.4:443#US"]["netflix"]["native"])
        self.assertFalse(streaming["5.6.7.8:8443#JP"]["netflix"]["native"])


if __name__ == "__main__":
    unittest.main()
