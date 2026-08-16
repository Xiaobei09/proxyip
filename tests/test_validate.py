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


class TestSpeedHelpers(unittest.TestCase):
    def test_flag_of(self):
        self.assertEqual(vp.flag_of("US"), "\U0001F1FA\U0001F1F8")
        self.assertEqual(vp.flag_of("jp"), "\U0001F1EF\U0001F1F5")
        self.assertEqual(vp.flag_of("USA"), "")
        self.assertEqual(vp.flag_of(""), "")

    def test_compute_speed(self):
        self.assertEqual(vp.compute_speed(500 * 1024 * 1024, 1.0), 500.0)
        self.assertEqual(vp.compute_speed(1024 * 1024, 2.0), 0.5)
        self.assertIsNone(vp.compute_speed(1000, 1.0))
        self.assertIsNone(vp.compute_speed(1024 * 1024, 0))

    def test_bucket_speed(self):
        dist = vp.bucket_speed([0.2, 0.49, 0.5, 0.9, 1, 1.9, 2, 4.9, 5, 10])
        self.assertEqual(
            dist,
            {
                "0-0.5": 2,
                "0.5-1": 2,
                "1-2": 2,
                "2-5": 2,
                "5+": 2,
            },
        )
        self.assertEqual(vp.bucket_speed([]), {"0-0.5": 0, "0.5-1": 0, "1-2": 0, "2-5": 0, "5+": 0})

    def test_fmt_entry(self):
        self.assertEqual(
            vp.fmt_entry("1.2.3.4", "443", "US", 120.5, 0.44),
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-120ms-0.44MB/s",
        )
        self.assertEqual(
            vp.fmt_entry("1.2.3.4", "443", "JP", 80.2, None),
            "1.2.3.4:443#\U0001F1EF\U0001F1F5JP-80ms",
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
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.5, 0.44),
            "2.0.0.1:8443#JP": ("2.0.0.1", "8443", "JP", "connect", 80.1, 1.2),
        }
        vp.write_index(["2.0.0.1:8443#JP", "1.0.0.1:443#US"], alive)
        data = json.loads(vp.INDEX_FILE.read_text())
        self.assertEqual(
            data,
            {"proxies": {"2.0.0.1:8443#JP": [80.1, "connect"], "1.0.0.1:443#US": [120.5, "tls"]}},
        )

    def test_skips_rewrite_when_unchanged(self):
        alive = {"1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.5, 0.44)}
        vp.write_index(["1.0.0.1:443#US"], alive)
        m1 = vp.INDEX_FILE.stat().st_mtime_ns
        vp.write_index(["1.0.0.1:443#US"], alive)
        m2 = vp.INDEX_FILE.stat().st_mtime_ns
        self.assertEqual(m1, m2)


class TestWriteValidOutputs(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vp_"))
        self.orig = (vp.VALID_DIR, vp.INDEX_FILE, vp.SPEED_FILE)
        vp.VALID_DIR = self.tmp
        vp.INDEX_FILE = self.tmp / "index.json"
        vp.SPEED_FILE = self.tmp / "speed.json"

    def tearDown(self):
        vp.VALID_DIR, vp.INDEX_FILE, vp.SPEED_FILE = self.orig

    def test_outputs_ordered_by_latency(self):
        alive = {
            "2.0.0.1:8443#JP": ("2.0.0.1", "8443", "JP", "connect", 300.0, 0.5),
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 1.0),
            "3.0.0.1:80#US": ("3.0.0.1", "80", "US", "tls", 50.0, 0.3),
        }
        vp.write_valid_outputs(alive, per_country_limit=1)
        lines = (vp.VALID_DIR / "all.txt").read_text().splitlines()
        self.assertEqual(
            [line.split("#", 1)[0] for line in lines],
            ["3.0.0.1:80", "1.0.0.1:443", "2.0.0.1:8443"],
        )
        self.assertIn("\U0001F1FA\U0001F1F8US-50ms-0.30MB/s", lines[0])
        us_dir = vp.VALID_DIR / "countries" / "US"
        self.assertEqual(
            [line.split("#", 1)[0] for line in (us_dir / "all.txt").read_text().splitlines()],
            ["3.0.0.1:80", "1.0.0.1:443"],
        )
        self.assertEqual(
            [line.split("#", 1)[0] for line in (us_dir / "ltd.txt").read_text().splitlines()],
            ["1.0.0.1:443"],
        )
        self.assertFalse((vp.VALID_DIR / "countries" / "US.txt").exists())
        # index matches all.txt order
        self.assertEqual(
            list(json.loads(vp.INDEX_FILE.read_text())["proxies"]),
            ["3.0.0.1:80#US", "1.0.0.1:443#US", "2.0.0.1:8443#JP"],
        )

    def test_all_ltd_per_country_cap(self):
        alive = {
            f"{i}.0.0.1:443#US": (f"{i}.0.0.1", "443", "US", "tls", float(i), None)
            for i in range(1, 6)
        }
        alive["9.0.0.1:443#JP"] = ("9.0.0.1", "443", "JP", "tls", 1.0, None)
        vp.write_valid_outputs(alive, per_country_limit=2)
        ltd = (vp.VALID_DIR / "all_ltd.txt").read_text().splitlines()
        self.assertEqual(len(ltd), 3)
        us = [e for e in ltd if e.split("#", 1)[1].startswith("\U0001F1FA\U0001F1F8US")]
        self.assertEqual(len(us), 2)

    def test_ltd_ordered_by_speed(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 10.0, 0.2),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 100.0, 5.0),
        }
        vp.write_valid_outputs(alive, per_country_limit=2)
        ltd = (vp.VALID_DIR / "all_ltd.txt").read_text().splitlines()
        self.assertEqual(len(ltd), 2)
        self.assertTrue(ltd[0].startswith("2.0.0.1:443#"), ltd)
        self.assertIn("5.00MB/s", ltd[0])

    def test_ltd_omits_speed_when_none(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 80.0, None),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 90.0, 1.0),
        }
        vp.write_valid_outputs(alive, per_country_limit=2)
        ltd = (vp.VALID_DIR / "all_ltd.txt").read_text().splitlines()
        self.assertEqual(len(ltd), 2)
        no_speed = [e for e in ltd if "MB/s" not in e]
        self.assertEqual(len(no_speed), 1)
        self.assertTrue(no_speed[0].endswith("ms"), no_speed[0])

    def test_all_cc_kept_in_all_but_not_countries(self):
        alive = {
            "1.0.0.1:443#ALL": ("1.0.0.1", "443", "ALL", "tls", 100.0, 0.5),
            "2.0.0.1:8443#US": ("2.0.0.1", "8443", "US", "tls", 80.0, 1.0),
        }
        vp.write_valid_outputs(alive, per_country_limit=1)
        self.assertFalse((vp.VALID_DIR / "countries" / "ALL").exists())
        self.assertFalse((vp.VALID_DIR / "countries" / "ALL.txt").exists())
        all_lines = (vp.VALID_DIR / "all.txt").read_text().splitlines()
        self.assertTrue(any(line.startswith("1.0.0.1:443#ALL") for line in all_lines))
        ltd = (vp.VALID_DIR / "all_ltd.txt").read_text().splitlines()
        self.assertTrue(any(line.startswith("1.0.0.1:443#ALL") for line in ltd))

    def test_sets_written_as_directories(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 0.5),
            "2.0.0.1:8443#JP": ("2.0.0.1", "8443", "JP", "tls", 80.0, 1.0),
        }
        vp.write_valid_outputs(alive, per_country_limit=1)
        hot = vp.VALID_DIR / "sets" / "hot"
        self.assertEqual(
            {p.name for p in (vp.VALID_DIR / "sets").iterdir()},
            {name for name in {**vp.COUNTRY_SETS, **vp.SMALL_SETS}},
        )
        self.assertEqual(
            [line.split("#", 1)[0] for line in (hot / "all.txt").read_text().splitlines()],
            ["2.0.0.1:8443", "1.0.0.1:443"],
        )
        self.assertEqual(
            [line.split("#", 1)[0] for line in (hot / "ltd.txt").read_text().splitlines()],
            ["2.0.0.1:8443", "1.0.0.1:443"],
        )
        self.assertFalse((vp.VALID_DIR / "sets" / "hot.txt").exists())
        self.assertFalse((vp.VALID_DIR / "sets" / "hot_ltd.txt").exists())

    def test_stale_flat_files_and_dirs_removed(self):
        (vp.VALID_DIR / "countries").mkdir(parents=True)
        (vp.VALID_DIR / "sets").mkdir(parents=True)
        (vp.VALID_DIR / "countries" / "US.txt").write_text("stale\n")
        stale_dir = vp.VALID_DIR / "countries" / "XX"
        stale_dir.mkdir()
        (stale_dir / "all.txt").write_text("stale\n")
        (vp.VALID_DIR / "sets" / "old.txt").write_text("stale\n")
        stale_set = vp.VALID_DIR / "sets" / "old"
        stale_set.mkdir()
        (stale_set / "all.txt").write_text("stale\n")
        alive = {"1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 0.5)}
        vp.write_valid_outputs(alive, per_country_limit=1)
        self.assertFalse((vp.VALID_DIR / "countries" / "US.txt").exists())
        self.assertFalse(stale_dir.exists())
        self.assertFalse((vp.VALID_DIR / "sets" / "old.txt").exists())
        self.assertFalse(stale_set.exists())
        self.assertTrue((vp.VALID_DIR / "countries" / "US" / "all.txt").exists())

    def test_speed_json(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 80.0, 0.2),
            "2.0.0.1:443#JP": ("2.0.0.1", "443", "JP", "tls", 90.0, 5.0),
            "3.0.0.1:443#DE": ("3.0.0.1", "443", "DE", "tls", 70.0, None),
        }
        vp.write_valid_outputs(alive, per_country_limit=0)
        data = json.loads(vp.SPEED_FILE.read_text())
        self.assertEqual(
            list(data["proxies"]),
            ["2.0.0.1:443#JP", "1.0.0.1:443#US"],
        )
        self.assertEqual(data["proxies"]["2.0.0.1:443#JP"], 5.0)


if __name__ == "__main__":
    unittest.main()
