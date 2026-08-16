"""Tests for quality_check.py pure functions."""

import asyncio
import json
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
        w = qc.REPUTATION_WEIGHTS
        self.assertEqual(
            qc.derive_risk({"ip-api": {"proxy": True, "hosting": True}},
                           None, w), "medium"
        )
        self.assertEqual(
            qc.derive_risk({"ip-api": {"proxy": True, "hosting": False}},
                           None, w), "low"
        )
        self.assertEqual(
            qc.derive_risk({"ip-api": {"proxy": False, "hosting": False}},
                           None, w), "low"
        )
        self.assertEqual(
            qc.derive_risk({"netcoffee": {"trust_score": 20}}, None, w), "high"
        )
        self.assertEqual(
            qc.derive_risk({"netcoffee": {"trust_score": 50}}, None, w),
            "medium"
        )
        self.assertEqual(
            qc.derive_risk({"netcoffee": {"trust_score": 90}}, None, w), "low"
        )

    def test_derive_risk_from_score(self):
        w = qc.REPUTATION_WEIGHTS
        self.assertEqual(qc.derive_risk({}, {"score": 90}, w), "high")
        self.assertEqual(qc.derive_risk({}, {"score": 50}, w), "medium")
        self.assertEqual(qc.derive_risk({}, {"score": 10}, w), "low")


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
        self.assertEqual(info["risk"], "low")
        self.assertEqual(info["reputation"], 90)
        self.assertEqual(info["reputation_source"], "ip-api")
        self.assertTrue(info["geo_checked"])

    def test_reputation_netcoffee_wins(self):
        results = {
            "1.2.3.4:443#US": {
                "key": "1.2.3.4:443#US", "cc": "US",
                "v4": "9.9.9.9", "v6": None,
            }
        }
        geo = {"9.9.9.9": {"status": "success", "countryCode": "US"}}
        nc = {"9.9.9.9": {"netcoffee": {"trust_score": 42,
                                         "is_datacenter": True}}}
        info = qc.build_ipinfo_map(results, geo, {}, nc)["1.2.3.4:443#US"]
        self.assertEqual(info["reputation"], 61)
        self.assertEqual(info["reputation_source"], "multi")
        self.assertEqual(info["risk"], "medium")
        self.assertEqual(info["risk_flags"]["netcoffee"]["trust_score"], 42)

    def test_no_geo_no_reputation(self):
        results = {
            "1.2.3.4:443#US": {
                "key": "1.2.3.4:443#US", "cc": "US",
                "v4": "9.9.9.9", "v6": None,
            }
        }
        info = qc.build_ipinfo_map(results, {}, {})["1.2.3.4:443#US"]
        self.assertNotIn("reputation", info)
        self.assertFalse(info["geo_checked"])
        self.assertEqual(info["risk"], "low")

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


class TestReputation(unittest.TestCase):
    W = qc.REPUTATION_WEIGHTS

    def test_abuse_takes_precedence(self):
        signals = {
            "netcoffee": {"trust_score": 5, "is_abuser": True},
            "ip-api": {"proxy": True, "hosting": True},
        }
        self.assertEqual(qc.compute_reputation(signals, {"score": 90}, self.W), 10)

    def test_trust_score_direct(self):
        self.assertEqual(
            qc.compute_reputation({"netcoffee": {"trust_score": 63}},
                                  None, self.W), 63
        )

    def test_trust_score_clamped(self):
        self.assertEqual(
            qc.compute_reputation({"netcoffee": {"trust_score": 150}},
                                  None, self.W), 100
        )
        self.assertEqual(
            qc.compute_reputation({"netcoffee": {"trust_score": -5}},
                                  None, self.W), 0
        )

    def test_netcoffee_flag_penalty(self):
        nc = {"netcoffee": {"is_abuser": True, "is_tor": True, "is_vpn": True}}
        self.assertEqual(qc.compute_reputation(nc, None, self.W), 0)
        nc = {"netcoffee": {"is_datacenter": True}}
        self.assertEqual(qc.compute_reputation(nc, None, self.W), 85)

    def test_source_score_per_source(self):
        self.assertEqual(
            qc.source_score("netcoffee", {"trust_score": 63}), 63)
        self.assertEqual(
            qc.source_score("netcoffee", {"is_datacenter": True}), 85)
        self.assertEqual(
            qc.source_score("ncgy", {"is_tor": True, "is_anonymous": True}), 45)
        self.assertEqual(qc.source_score("ncgy", {"is_vpn": True}), 75)
        self.assertEqual(
            qc.source_score("ip-api", {"proxy": True, "hosting": True}), 65)
        self.assertEqual(
            qc.source_score("ip-api", {"proxy": False, "hosting": False}), 100)
        self.assertEqual(
            qc.source_score(
                "ipdata", {"security": {"tor": True}, "threat_score": 30}), 25)
        self.assertEqual(qc.source_score("torlist", {"is_tor": True}), 25)
        self.assertIsNone(qc.source_score("torlist", {"is_tor": False}))
        self.assertEqual(
            qc.source_score("getipintel", {"probability": 0.3}), 70)
        self.assertIsNone(qc.source_score("getipintel", {"probability": -3}))
        self.assertEqual(
            qc.source_score("ipapi_is", {"is_tor": True, "is_vpn": True}), 25)
        self.assertIsNone(qc.source_score("bogus", {}))

    def test_weighted_merge(self):
        signals = {"netcoffee": {"trust_score": 80},
                   "ncgy": {"is_vpn": True}}
        score, sources = qc.weighted_reputation(signals, self.W)
        self.assertEqual(score, 78)
        self.assertEqual(set(sources), {"netcoffee", "ncgy"})

    def test_weighted_merge_renormalizes(self):
        signals = {"netcoffee": {"trust_score": 50}}
        score, sources = qc.weighted_reputation(signals, self.W)
        self.assertEqual(score, 50)
        self.assertEqual(sources, ["netcoffee"])

    def test_no_signals(self):
        self.assertIsNone(qc.compute_reputation({}, None, self.W))
        self.assertEqual(qc.weighted_reputation({}, self.W), (None, []))

    def test_ipapi_only(self):
        self.assertEqual(
            qc.compute_reputation(
                {"ip-api": {"proxy": True, "hosting": True}}, None, self.W), 65
        )
        self.assertIsNone(qc.compute_reputation({}, None, self.W))

    def test_reputation_risk_boundaries(self):
        self.assertEqual(qc.reputation_risk(0), "high")
        self.assertEqual(qc.reputation_risk(29), "high")
        self.assertEqual(qc.reputation_risk(30), "medium")
        self.assertEqual(qc.reputation_risk(74), "medium")
        self.assertEqual(qc.reputation_risk(75), "low")
        self.assertEqual(qc.reputation_risk(100), "low")
        self.assertIsNone(qc.reputation_risk(None))

    def test_build_reputation_map(self):
        results = {
            "1.2.3.4:443#US": {
                "key": "1.2.3.4:443#US", "ip": "1.2.3.4",
                "method": "connect", "streaming": {},
            },
            "5.6.7.8:8443#JP": {
                "key": "5.6.7.8:8443#JP", "ip": "5.6.7.8",
                "method": "tls", "tls": True, "streaming": {},
            },
        }
        ipinfo = {
            "1.2.3.4:443#US": {
                "reputation": 40, "reputation_source": "multi",
                "risk_sources": ["netcoffee", "ncgy"],
            },
        }
        risk_data = {"5.6.7.8": {"netcoffee": {"trust_score": 70}}}
        rep = qc.build_reputation_map(results, ipinfo, risk_data, self.W)
        self.assertEqual(rep["1.2.3.4:443#US"]["score"], 40)
        self.assertEqual(rep["1.2.3.4:443#US"]["source"], "multi")
        self.assertEqual(
            rep["1.2.3.4:443#US"]["sources"], ["netcoffee", "ncgy"])
        self.assertEqual(rep["1.2.3.4:443#US"]["risk"], "medium")
        self.assertEqual(rep["5.6.7.8:8443#JP"]["score"], 70)
        self.assertEqual(rep["5.6.7.8:8443#JP"]["source"], "netcoffee")
        self.assertEqual(rep["5.6.7.8:8443#JP"]["sources"], ["netcoffee"])

    def test_netcoffee_lookup_parsing(self):
        payload = (
            b'{"trust_score":61,"is_datacenter":true,"is_vpn":false,'
            b'"is_proxy":false,"is_tor":false,"is_abuser":false,'
            b'"is_mobile":false,"is_crawler":false,"isResidential":false}'
        )

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return payload

        def fake_urlopen(req, timeout=0):
            self.assertIn("iprisk/1.2.3.4", req.full_url)
            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.netcoffee_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out["trust_score"], 61)
        self.assertTrue(out["is_datacenter"])
        self.assertFalse(out["is_vpn"])

    def test_netcoffee_lookup_empty(self):
        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return b"{}"

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            self.assertIsNone(qc.netcoffee_lookup_sync("1.2.3.4"))
        finally:
            qc.urllib.request.urlopen = orig

    def test_ncgy_lookup_parsing(self):
        payload = (
            b'{"ip":"1.2.3.4","proxy":{"is_proxy":true,"is_vpn":false,'
            b'"is_tor":false,"is_hosting":true,"is_cdn":false,'
            b'"is_school":false,"is_anonymous":true}}'
        )

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return payload

        def fake_urlopen(req, timeout=0):
            self.assertIn("nc.gy", req.full_url)
            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.ncgy_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertTrue(out["is_proxy"])
        self.assertTrue(out["is_hosting"])
        self.assertTrue(out["is_anonymous"])
        self.assertFalse(out["is_vpn"])

    def test_ncgy_lookup_clean_none(self):
        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return (
                        b'{"ip":"1.2.3.4","proxy":{"is_proxy":false,'
                        b'"is_vpn":false,"is_tor":false,"is_hosting":false,'
                        b'"is_cdn":false,"is_school":false,'
                        b'"is_anonymous":false}}'
                    )

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            self.assertIsNone(qc.ncgy_lookup_sync("1.2.3.4"))
        finally:
            qc.urllib.request.urlopen = orig

    def test_getipintel_lookup(self):
        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return b"0.25"

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.getipintel_lookup_sync("1.2.3.4", "a@b.com")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out, {"probability": 0.25})

    def test_getipintel_error_none(self):
        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return b"-5"

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            self.assertIsNone(qc.getipintel_lookup_sync("1.2.3.4", "a@b.com"))
        finally:
            qc.urllib.request.urlopen = orig

    def test_netcoffee_enriched_fields(self):
        payload = (
            b'{"trust_score":61,"is_datacenter":true,"company_type":"hosting",'
            b'"asn_kind":"hosting","abuser_score":"0.35 (High)"}'
        )

        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.netcoffee_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out["company_type"], "hosting")
        self.assertEqual(out["asn_kind"], "hosting")
        self.assertEqual(out["abuser_score"], 0.35)

    def test_ipapi_is_enriched_fields(self):
        payload = (
            b'{"is_datacenter":false,"is_vpn":true,"is_abuser":false,'
            b'"company":{"type":"hosting","abuser_score":"0.50 (Medium)"},'
            b'"asn":{"type":"hosting","abuser_score":"0.20 (Medium)"}}'
        )

        def fake_urlopen(req, timeout=0):
            self.assertIn("api.ipapi.is", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.ipapi_is_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertTrue(out["is_vpn"])
        self.assertEqual(out["company_type"], "hosting")
        self.assertEqual(out["asn_type"], "hosting")
        self.assertEqual(out["company_abuser_score"], 0.50)
        self.assertEqual(out["asn_abuser_score"], 0.20)

    def test_ipquery_lookup_parsing(self):
        payload = (
            b'{"risk":{"is_mobile":false,"is_vpn":true,"is_tor":false,'
            b'"is_proxy":false,"is_datacenter":true,"risk_score":35},'
            b'"isp":{"asn":"AS15169","org":"Google LLC","isp":"Google"}}'
        )

        def fake_urlopen(req, timeout=0):
            self.assertIn("api.ipquery.io/1.2.3.4", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.ipquery_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertTrue(out["is_vpn"])
        self.assertTrue(out["is_datacenter"])
        self.assertEqual(out["risk_score"], 35)
        self.assertEqual(out["asn"], "AS15169")

    def test_ffraud_lookup_parsing(self):
        payload = (
            b'{"fraud_score":0,"risk":"none","proxy":false,"vpn":false,'
            b'"tor":false,"hosting":true,"is_abuser":false,'
            b'"recent_abuse":false,"connection_type":"Residential"}'
        )

        def fake_urlopen(req, timeout=0):
            self.assertIn("api.ffraud.com", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.ffraud_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out["fraud_score"], 0)
        self.assertTrue(out["is_hosting"])
        self.assertEqual(out["connection_type"], "Residential")

    def test_whatismyip_lookup_parsing(self):
        payload = (
            b'{"data":{"security":{"isVpn":false,"isProxy":true,"isTor":false,'
            b'"isHosting":false,"isBlacklisted":true,"score":40},'
            b'"network":{"connectionType":"Residential"}}}'
        )

        def fake_urlopen(req, timeout=0):
            self.assertIn("whatismyip.ai", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.whatismyip_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertTrue(out["is_proxy"])
        self.assertTrue(out["is_blacklisted"])
        self.assertEqual(out["score"], 40)
        self.assertEqual(out["connection_type"], "Residential")

    def test_parse_abuser_score(self):
        self.assertEqual(qc.parse_abuser_score("0.0039 (Low)"), 0.0039)
        self.assertEqual(qc.parse_abuser_score("42"), 42.0)
        self.assertEqual(qc.parse_abuser_score(0.5), 0.5)
        self.assertIsNone(qc.parse_abuser_score("n/a"))

    def test_norm_asn(self):
        self.assertEqual(qc.norm_asn("AS15169"), "AS15169")
        self.assertEqual(qc.norm_asn("15169"), "AS15169")
        self.assertEqual(qc.norm_asn("AS15169,Google LLC,US"), "AS15169")
        self.assertIsNone(qc.norm_asn("Google LLC"))

    def test_source_score_new_sources(self):
        self.assertEqual(qc.source_score("ipquery", {"risk_score": 20}), 80)
        self.assertEqual(qc.source_score("ipquery", {"is_vpn": True}), 70)
        self.assertEqual(
            qc.source_score("ipquery", {"is_datacenter": True, "asn": "AS1"}),
            85,
        )
        self.assertIsNone(qc.source_score("ipquery", {"asn": ""}))
        self.assertEqual(
            qc.source_score("ffraud", {"fraud_score": 0, "is_hosting": True}),
            85,
        )
        self.assertEqual(qc.source_score("ffraud", {"is_abuser": True}), 80)
        self.assertIsNone(qc.source_score("ffraud", {}))
        self.assertEqual(qc.source_score("whatismyip", {"score": 40}), 60)
        self.assertEqual(qc.source_score("whatismyip", {"is_tor": True}), 55)
        self.assertIsNone(qc.source_score("whatismyip", {}))
        self.assertEqual(qc.source_score("abuse_list", {"is_abuse": True}), 60)
        self.assertIsNone(qc.source_score("abuse_list", {"is_abuse": False}))
        self.assertEqual(qc.source_score("dc_asn", {"is_hosting": True}), 85)
        self.assertIsNone(qc.source_score("dc_asn", {}))
        self.assertEqual(qc.source_score("vpn_asn", {"is_vpn": True}), 70)
        self.assertEqual(
            qc.source_score("resproxy_asn", {"is_proxy": True}), 75)

    def test_source_score_enriched_penalties(self):
        self.assertEqual(
            qc.source_score("netcoffee", {"company_type": "hosting"}), 85)
        self.assertEqual(
            qc.source_score("netcoffee", {"abuser_score": 0.5}), 80)
        self.assertEqual(
            qc.source_score("netcoffee", {"abuser_score": 0.0039}), 100)
        self.assertEqual(
            qc.source_score("ipapi_is", {"company_type": "hosting"}), 85)
        self.assertEqual(
            qc.source_score("ipapi_is", {"company_abuser_score": 0.5}), 80)

    def test_collect_signals_clean_geo_includes_ipapi(self):
        signals = qc.collect_signals(
            "9.9.9.9",
            {"status": "success", "countryCode": "US"},
            {},
            qc.REPUTATION_WEIGHTS,
        )
        self.assertIn("ip-api", signals)

    def test_collect_signals_no_geo_excludes_ipapi(self):
        signals = qc.collect_signals(
            "9.9.9.9", {}, {}, qc.REPUTATION_WEIGHTS
        )
        self.assertNotIn("ip-api", signals)

    def test_static_sources_in_defaults(self):
        for name in ("ipquery", "ffraud", "whatismyip", "ipapi_is",
                     "dc_asn", "abuse_list", "vpn_asn", "resproxy_asn"):
            self.assertIn(name, qc.DEFAULT_REP_SOURCES)
            self.assertGreater(qc.REPUTATION_WEIGHTS.get(name, 0), 0)


class TestIpSet(unittest.TestCase):
    def test_exact_ip(self):
        s = qc.IpSet(["1.2.3.4", "5.6.7.8/32"])
        self.assertIn("1.2.3.4", s)
        self.assertIn("5.6.7.8", s)

    def test_cidr_containment(self):
        s = qc.IpSet(["10.0.0.0/24", "2001:db8::/32"])
        self.assertIn("10.0.0.1", s)
        self.assertIn("10.0.0.255", s)
        self.assertNotIn("10.0.1.1", s)
        self.assertIn("2001:db8::1", s)
        self.assertNotIn("2001:db9::1", s)

    def test_skips_comments_and_garbage(self):
        s = qc.IpSet(["# comment", "; skip", "not-an-ip", "1.2.3.4"])
        self.assertIn("1.2.3.4", s)
        self.assertEqual(len(s), 1)

    def test_bad_ip_returns_false(self):
        s = qc.IpSet(["1.2.3.4"])
        self.assertNotIn("not-an-ip", s)


class TestStaticLists(unittest.TestCase):
    def _patch_urlopen(self, text):
        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return text.encode()

            return FakeResp()

        return fake_urlopen

    def test_fetch_asn_list_finds_asn_column(self):
        text = (
            "slug,name,jurisdiction,asn,protocols\n"
            "airvpn,AirVPN,Italy,,WireGuard\n"
            "nord,NordVPN,Panama,AS212238,WireGuard\n"
        )
        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = self._patch_urlopen(text)
        try:
            out = asyncio.run(qc.fetch_asn_list("http://x/asn.csv"))
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out, {"AS212238"})

    def test_fetch_asn_list_first_col_fallback(self):
        text = "asn,name\nAS15169,Google\nAS8075,Microsoft\n"
        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = self._patch_urlopen(text)
        try:
            out = asyncio.run(qc.fetch_asn_list("http://x/asn.csv"))
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out, {"AS15169", "AS8075"})

    def test_fetch_static_lists_fail_open(self):
        def boom(req, timeout=0):
            raise OSError("network down")

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = boom
        try:
            out = asyncio.run(qc.fetch_static_lists(["abuse_list", "dc_asn"]))
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(len(out["abuse_list"]), 0)
        self.assertEqual(out["dc_asn"], set())


class TestReputationFiles(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())
        self._rep_file, self._rank_file = (
            qc.REPUTATION_FILE,
            qc.REP_RANK_FILE,
        )
        qc.REPUTATION_FILE = self.tmp / "reputation.json"
        qc.REP_RANK_FILE = self.tmp / "all_rep.txt"

    def tearDown(self):
        qc.REPUTATION_FILE = self._rep_file
        qc.REP_RANK_FILE = self._rank_file

    def test_write_reputation_files_sorted(self):
        text = (
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms-1.00MB/s\n"
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-50ms-2.00MB/s\n"
            "9.9.9.9:443#\U0001F1FA\U0001F1F8US-30ms-3.00MB/s\n"
        )
        annotations = {"1.2.3.4:443#US": "DC-90", "5.6.7.8:8443#JP": "DC-40",
                       "9.9.9.9:443#US": "DC-90"}
        rep_map = {
            "9.9.9.9:443#US": {"score": 90, "risk": "low", "source": "netcoffee"},
            "1.2.3.4:443#US": {"score": 90, "risk": "low", "source": "netcoffee"},
            "5.6.7.8:8443#JP": {"score": 40, "risk": "medium",
                                "source": "ip-api"},
        }
        qc.write_reputation_files(text, annotations, rep_map)
        ranked = qc.REP_RANK_FILE.read_text(encoding="utf-8").splitlines()
        self.assertTrue(ranked[0].startswith("9.9.9.9:443"))
        self.assertTrue(ranked[1].startswith("1.2.3.4:443"))
        self.assertTrue(ranked[2].startswith("5.6.7.8:8443"))
        self.assertTrue(ranked[0].endswith("-DC-90"))
        data = json.loads(qc.REPUTATION_FILE.read_text(encoding="utf-8"))
        self.assertEqual(len(data["proxies"]), 3)
        keys = list(data["proxies"])
        self.assertEqual(keys[0], "1.2.3.4:443#US")
        self.assertEqual(keys[1], "9.9.9.9:443#US")
        self.assertEqual(data["proxies"]["5.6.7.8:8443#JP"]["score"], 40)

    def test_write_reputation_files_unscored_last(self):
        text = (
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms\n"
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-50ms\n"
        )
        rep_map = {"5.6.7.8:8443#JP": {"score": 80, "risk": "low",
                                        "source": "netcoffee"}}
        qc.write_reputation_files(text, {}, rep_map)
        lines = qc.REP_RANK_FILE.read_text(encoding="utf-8").splitlines()
        self.assertTrue(lines[0].startswith("5.6.7.8:8443"))
        self.assertTrue(lines[1].startswith("1.2.3.4:443"))


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
