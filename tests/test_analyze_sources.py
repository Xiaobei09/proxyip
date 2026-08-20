"""Tests for analyze_sources.py pure functions."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import analyze_sources as asrc


class TestParseLatency(unittest.TestCase):
    def test_extracts_ms(self):
        self.assertEqual(asrc._parse_latency("1.2.3.4:443#US-120ms-0.44MB/s"), 120.0)

    def test_no_latency(self):
        self.assertIsNone(asrc._parse_latency("1.2.3.4:443#US"))

    def test_large_latency(self):
        self.assertEqual(asrc._parse_latency("1.2.3.4:443#US-9999ms"), 9999.0)


class TestParseSpeed(unittest.TestCase):
    def test_extracts_mb(self):
        self.assertAlmostEqual(
            asrc._parse_speed("1.2.3.4:443#US-120ms-10.82MB/s"), 10.82
        )

    def test_no_speed(self):
        self.assertIsNone(asrc._parse_speed("1.2.3.4:443#US-120ms"))

    def test_zero_speed(self):
        self.assertEqual(asrc._parse_speed("1.2.3.4:443#US-0MB/s"), 0.0)


class TestParseCc(unittest.TestCase):
    def test_standard(self):
        self.assertEqual(asrc._parse_cc("1.2.3.4:443#US-120ms"), "US")

    def test_all_pseudo(self):
        self.assertEqual(asrc._parse_cc("1.2.3.4:443#ALL-120ms"), "ALL")

    def test_no_hash(self):
        self.assertIsNone(asrc._parse_cc("1.2.3.4:443"))


class TestParsePort(unittest.TestCase):
    def test_standard(self):
        self.assertEqual(asrc._parse_port("1.2.3.4:443#US"), "443")

    def test_non_standard_port(self):
        self.assertEqual(asrc._parse_port("1.2.3.4:8443#US"), "8443")


class TestAnalyze(unittest.TestCase):
    def test_basic_metrics(self):
        ip_sources = {
            "1.1.1.1:443#US": "main",
            "2.2.2.2:443#JP": "extra",
            "3.3.3.3:443#DE": "main",
        }
        valid_lines = [
            "1.1.1.1:443#🇺🇸US-100ms-1.5MB/s",
            "3.3.3.3:443#🇩🇪DE-200ms-0.8MB/s",
        ]
        result = asrc.analyze(
            ip_sources, valid_lines,
            rep_data={}, streaming_data={}, china_data={},
            family_data={}, speed_data={},
        )
        self.assertEqual(result["total_proxies"], 3)
        self.assertEqual(result["total_alive"], 2)

        main = result["sources"]["main"]
        self.assertEqual(main["total"], 2)
        self.assertEqual(main["alive"], 2)
        self.assertAlmostEqual(main["survival_rate"], 1.0)
        self.assertAlmostEqual(main["avg_latency"], 150.0)

        extra = result["sources"]["extra"]
        self.assertEqual(extra["total"], 1)
        self.assertEqual(extra["alive"], 0)
        self.assertAlmostEqual(extra["survival_rate"], 0.0)

    def test_reputation_integration(self):
        ip_sources = {"1.1.1.1:443#US": "main"}
        valid_lines = ["1.1.1.1:443#🇺🇸US-100ms"]
        rep_data = {"1.1.1.1:443#US": {"score": 85, "risk": "low"}}
        result = asrc.analyze(
            ip_sources, valid_lines,
            rep_data=rep_data, streaming_data={}, china_data={},
            family_data={}, speed_data={},
        )
        main = result["sources"]["main"]
        self.assertEqual(main["avg_reputation"], 85.0)
        self.assertEqual(main["reputation_dist"]["low"], 1)

    def test_streaming_integration(self):
        ip_sources = {"1.1.1.1:443#US": "main"}
        valid_lines = ["1.1.1.1:443#🇺🇸US-100ms"]
        streaming_data = {
            "1.1.1.1:443#US": {
                "netflix": {"status": "ok", "region": "US"},
                "disney": {"status": "blocked"},
            }
        }
        result = asrc.analyze(
            ip_sources, valid_lines,
            rep_data={}, streaming_data=streaming_data, china_data={},
            family_data={}, speed_data={},
        )
        main = result["sources"]["main"]
        self.assertEqual(main["streaming_ok_count"], 1)
        self.assertAlmostEqual(main["streaming_ok_rate"], 1.0)

    def test_china_reachability(self):
        ip_sources = {"1.1.1.1:443#US": "main"}
        valid_lines = ["1.1.1.1:443#🇺🇸US-100ms"]
        china_data = {"1.1.1.1:443#US": {"verdict": "reachable"}}
        result = asrc.analyze(
            ip_sources, valid_lines,
            rep_data={}, streaming_data={}, china_data=china_data,
            family_data={}, speed_data={},
        )
        main = result["sources"]["main"]
        self.assertEqual(main["china_reachable_count"], 1)
        self.assertAlmostEqual(main["china_reachable_rate"], 1.0)

    def test_exit_family(self):
        ip_sources = {
            "1.1.1.1:443#US": "main",
            "2.2.2.2:443#JP": "main",
        }
        valid_lines = [
            "1.1.1.1:443#🇺🇸US-100ms",
            "2.2.2.2:443#🇯🇵JP-200ms",
        ]
        family_data = {
            "1.1.1.1:443#US": {"family": "ipv4"},
            "2.2.2.2:443#JP": {"family": "ipv6"},
        }
        result = asrc.analyze(
            ip_sources, valid_lines,
            rep_data={}, streaming_data={}, china_data={},
            family_data=family_data, speed_data={},
        )
        main = result["sources"]["main"]
        self.assertEqual(main["family_dist"]["ipv4"], 1)
        self.assertEqual(main["family_dist"]["ipv6"], 1)

    def test_empty_inputs(self):
        result = asrc.analyze({}, [], {}, {}, {}, {}, {})
        self.assertEqual(result["total_proxies"], 0)
        self.assertEqual(result["sources"], {})


class TestFormatReport(unittest.TestCase):
    def test_contains_header_and_sources(self):
        data = {
            "ts": "2026-01-01T00:00:00Z",
            "total_proxies": 100,
            "total_alive": 90,
            "sources": {
                "main": {
                    "total": 80, "alive": 75, "survival_rate": 0.9375,
                    "avg_latency": 200.0, "avg_speed": 1.5, "avg_reputation": 80.0,
                    "streaming_ok_rate": 0.9, "china_reachable_rate": 0.05,
                    "reputation_dist": {}, "family_dist": {}, "country_dist": {},
                    "port_dist": {}, "median_latency": 180.0, "median_speed": 1.2,
                    "streaming_ok_count": 68, "china_reachable_count": 4,
                },
            },
        }
        report = asrc._format_report(data)
        self.assertIn("Source Quality Report", report)
        self.assertIn("main", report)
        self.assertIn("93.8%", report)


if __name__ == "__main__":
    unittest.main()
