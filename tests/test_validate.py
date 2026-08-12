"""Tests for validate_proxies.py pure functions."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import validate_proxies as vp


class TestParseEntries(unittest.TestCase):
    def test_parses_valid_lines(self):
        lines = ["1.2.3.4:443#US", "  5.6.7.8:8080#JP  ", ""]
        entries = vp.parse_entries(lines)
        self.assertEqual(entries, [("1.2.3.4", "443", "US"), ("5.6.7.8", "8080", "JP")])

    def test_skips_bad_lines(self):
        lines = ["no-at-sign", "1.2.3.4:abc#US", "1.2.3.4#US", "1.2.3.4:443", "x#y#z"]
        self.assertEqual(vp.parse_entries(lines), [])

    def test_multi_hash_line_rejected(self):
        self.assertEqual(vp.parse_entries(["1.2.3.4:443#HK#extra"]), [])


class TestBucketLatency(unittest.TestCase):
    def test_histogram_edges(self):
        dist = vp.bucket_latency([50, 99.9, 100, 199.9, 200, 299.9, 300, 499.9, 500, 999.9, 1000, 5000])
        self.assertEqual(
            dist,
            {
                "0-100": 2,
                "100-200": 2,
                "200-300": 2,
                "300-500": 2,
                "500-1000": 2,
                "1000+": 2,
            },
        )

    def test_empty(self):
        self.assertEqual(
            vp.bucket_latency([]),
            {"0-100": 0, "100-200": 0, "200-300": 0, "300-500": 0, "500-1000": 0, "1000+": 0},
        )


class TestWriteIndex(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vp_"))
        self.orig = (vp.VALID_DIR, vp.INDEX_FILE)
        vp.VALID_DIR = self.tmp
        vp.INDEX_FILE = self.tmp / "index.json"

    def tearDown(self):
        vp.VALID_DIR, vp.INDEX_FILE = self.orig

    def test_writes_ordered_compact(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.5),
            "2.0.0.1:8443#JP": ("2.0.0.1", "8443", "JP", "connect", 80.1),
        }
        vp.write_index(["2.0.0.1:8443#JP", "1.0.0.1:443#US"], alive)
        data = json.loads(vp.INDEX_FILE.read_text())
        self.assertEqual(
            data,
            {"proxies": {"2.0.0.1:8443#JP": [80.1, "connect"], "1.0.0.1:443#US": [120.5, "tls"]}},
        )

    def test_skips_rewrite_when_unchanged(self):
        alive = {"1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.5)}
        vp.write_index(["1.0.0.1:443#US"], alive)
        m1 = vp.INDEX_FILE.stat().st_mtime_ns
        vp.write_index(["1.0.0.1:443#US"], alive)
        m2 = vp.INDEX_FILE.stat().st_mtime_ns
        self.assertEqual(m1, m2)


class TestWriteValidOutputs(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vp_"))
        self.orig = (vp.VALID_DIR, vp.INDEX_FILE)
        vp.VALID_DIR = self.tmp
        vp.INDEX_FILE = self.tmp / "index.json"

    def tearDown(self):
        vp.VALID_DIR, vp.INDEX_FILE = self.orig

    def test_outputs_ordered_by_latency(self):
        alive = {
            "2.0.0.1:8443#JP": ("2.0.0.1", "8443", "JP", "connect", 300.0),
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0),
            "3.0.0.1:80#US": ("3.0.0.1", "80", "US", "tls", 50.0),
        }
        vp.write_valid_outputs(alive, per_country_limit=1)
        self.assertEqual(
            (vp.VALID_DIR / "all.txt").read_text().splitlines(),
            ["3.0.0.1:80#US", "1.0.0.1:443#US", "2.0.0.1:8443#JP"],
        )
        self.assertEqual(
            (vp.VALID_DIR / "countries" / "US.txt").read_text().splitlines(),
            ["3.0.0.1:80#US", "1.0.0.1:443#US"],
        )
        # index matches all.txt order
        self.assertEqual(
            list(json.loads(vp.INDEX_FILE.read_text())["proxies"]),
            ["3.0.0.1:80#US", "1.0.0.1:443#US", "2.0.0.1:8443#JP"],
        )

    def test_all_ltd_per_country_cap(self):
        alive = {
            f"{i}.0.0.1:443#US": (f"{i}.0.0.1", "443", "US", "tls", float(i))
            for i in range(1, 6)
        }
        alive["9.0.0.1:443#JP"] = ("9.0.0.1", "443", "JP", "tls", 1.0)
        vp.write_valid_outputs(alive, per_country_limit=2)
        ltd = (vp.VALID_DIR / "all_ltd.txt").read_text().splitlines()
        self.assertEqual(len(ltd), 3)
        us = [e for e in ltd if e.endswith("#US")]
        self.assertEqual(len(us), 2)


if __name__ == "__main__":
    unittest.main()
