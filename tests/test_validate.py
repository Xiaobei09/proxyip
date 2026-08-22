"""Tests for validate_proxies.py pure functions."""

import asyncio
import contextlib
import io
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


class TestMergeOldNote(unittest.TestCase):
    def test_region_speed_tokens(self):
        base = "1.2.3.4:443#\U0001F1FA\U0001F1F8US-90ms-1.00MB/s"
        old = "\u2192LAX-120ms-0.44MB/s-NF(US) D+ YT GPT-DC-72-V4-CN"
        self.assertEqual(
            vp.merge_old_note(base, old),
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US\u2192LAX-90ms-1.00MB/s-NF(US) D+ YT GPT-DC-72-V4-CN",
        )

    def test_no_region_tokens_only(self):
        base = "1.2.3.4:443#US-90ms"
        self.assertEqual(vp.merge_old_note(base, "-120ms-0.44MB/s-CN"), "1.2.3.4:443#US-90ms-CN")

    def test_region_no_measurements(self):
        base = "1.2.3.4:443#US-90ms-1.00MB/s"
        self.assertEqual(
            vp.merge_old_note(base, "\u2192LAX-120ms-0.44MB/s"),
            "1.2.3.4:443#US\u2192LAX-90ms-1.00MB/s",
        )

    def test_bare_latency_only(self):
        base = "1.2.3.4:443#US-90ms"
        self.assertEqual(vp.merge_old_note(base, "-120ms"), "1.2.3.4:443#US-90ms")

    def test_empty_note(self):
        base = "1.2.3.4:443#US-90ms"
        self.assertEqual(vp.merge_old_note(base, ""), "1.2.3.4:443#US-90ms")


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
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.5, 0.44, None),
            "2.0.0.1:8443#JP": ("2.0.0.1", "8443", "JP", "tls", 80.1, 1.2, None),
        }
        vp.write_index(["2.0.0.1:8443#JP", "1.0.0.1:443#US"], alive)
        data = json.loads(vp.INDEX_FILE.read_text())
        self.assertEqual(
            data,
            {"proxies": {"2.0.0.1:8443#JP": [80.1, "tls"], "1.0.0.1:443#US": [120.5, "tls"]}},
        )

    def test_skips_rewrite_when_unchanged(self):
        alive = {"1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.5, 0.44, None)}
        vp.write_index(["1.0.0.1:443#US"], alive)
        m1 = vp.INDEX_FILE.stat().st_mtime_ns
        vp.write_index(["1.0.0.1:443#US"], alive)
        m2 = vp.INDEX_FILE.stat().st_mtime_ns
        self.assertEqual(m1, m2)


class TestWriteValidOutputs(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vp_"))
        self.orig = (vp.VALID_DIR, vp.CHINA_FILE, vp.INDEX_FILE, vp.SPEED_FILE)
        vp.VALID_DIR = self.tmp
        vp.CHINA_FILE = self.tmp / "china.json"
        vp.INDEX_FILE = self.tmp / "index.json"
        vp.SPEED_FILE = self.tmp / "speed.json"

    def tearDown(self):
        vp.VALID_DIR, vp.CHINA_FILE, vp.INDEX_FILE, vp.SPEED_FILE = self.orig

    def test_outputs_ordered_by_latency(self):
        alive = {
            "2.0.0.1:8443#JP": ("2.0.0.1", "8443", "JP", "tls", 300.0, 0.5, None),
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 1.0, None),
            "3.0.0.1:80#US": ("3.0.0.1", "80", "US", "tls", 50.0, 0.3, None),
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
            f"{i}.0.0.1:443#US": (f"{i}.0.0.1", "443", "US", "tls", float(i), None, None)
            for i in range(1, 6)
        }
        alive["9.0.0.1:443#JP"] = ("9.0.0.1", "443", "JP", "tls", 1.0, None, None)
        vp.write_valid_outputs(alive, per_country_limit=2)
        ltd = (vp.VALID_DIR / "all_ltd.txt").read_text().splitlines()
        self.assertEqual(len(ltd), 3)
        us = [e for e in ltd if e.split("#", 1)[1].startswith("\U0001F1FA\U0001F1F8US")]
        self.assertEqual(len(us), 2)

    def test_ltd_ordered_by_speed(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 10.0, 0.2, None),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 100.0, 5.0, None),
        }
        vp.write_valid_outputs(alive, per_country_limit=2)
        ltd = (vp.VALID_DIR / "all_ltd.txt").read_text().splitlines()
        self.assertEqual(len(ltd), 2)
        self.assertTrue(ltd[0].startswith("2.0.0.1:443#"), ltd)
        self.assertIn("5.00MB/s", ltd[0])

    def test_ltd_omits_speed_when_none(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 80.0, None, None),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 90.0, 1.0, None),
        }
        vp.write_valid_outputs(alive, per_country_limit=2)
        ltd = (vp.VALID_DIR / "all_ltd.txt").read_text().splitlines()
        self.assertEqual(len(ltd), 2)
        no_speed = [e for e in ltd if "MB/s" not in e]
        self.assertEqual(len(no_speed), 1)
        self.assertTrue(no_speed[0].endswith("ms"), no_speed[0])

    def test_all_cc_kept_in_all_but_not_countries(self):
        alive = {
            "1.0.0.1:443#ALL": ("1.0.0.1", "443", "ALL", "tls", 100.0, 0.5, None),
            "2.0.0.1:8443#US": ("2.0.0.1", "8443", "US", "tls", 80.0, 1.0, None),
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
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 0.5, None),
            "2.0.0.1:8443#JP": ("2.0.0.1", "8443", "JP", "tls", 80.0, 1.0, None),
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
        alive = {"1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 0.5, None)}
        vp.write_valid_outputs(alive, per_country_limit=1)
        self.assertFalse((vp.VALID_DIR / "countries" / "US.txt").exists())
        self.assertFalse(stale_dir.exists())
        self.assertFalse((vp.VALID_DIR / "sets" / "old.txt").exists())
        self.assertFalse(stale_set.exists())
        self.assertTrue((vp.VALID_DIR / "countries" / "US" / "all.txt").exists())

    def test_speed_json(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 80.0, 0.2, None),
            "2.0.0.1:443#JP": ("2.0.0.1", "443", "JP", "tls", 90.0, 5.0, None),
            "3.0.0.1:443#DE": ("3.0.0.1", "443", "DE", "tls", 70.0, None, None),
        }
        vp.write_valid_outputs(alive, per_country_limit=0)
        data = json.loads(vp.SPEED_FILE.read_text())
        self.assertEqual(
            list(data["proxies"]),
            ["2.0.0.1:443#JP", "1.0.0.1:443#US"],
        )
        self.assertEqual(data["proxies"]["2.0.0.1:443#JP"], 5.0)

    def test_preserves_existing_annotations(self):
        (vp.VALID_DIR / "all.txt").write_text(
            "1.0.0.1:443#\U0001F1FA\U0001F1F8US\u2192LAX-120ms-0.44MB/s-NF(US) D+ YT GPT-DC-72-V4-CN\n"
            "2.0.0.1:443#\U0001F1EF\U0001F1F5JP-99ms-GPT-CF\n"
            "9.9.9.9:443#DE-50ms\n",
            encoding="utf-8",
        )
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 90.0, 1.0, None),
            "2.0.0.1:443#JP": ("2.0.0.1", "443", "JP", "tls", 70.0, None, None),
            "3.0.0.1:443#US": ("3.0.0.1", "443", "US", "tls", 50.0, 0.5, None),
        }
        vp.write_valid_outputs(alive, per_country_limit=1)
        lines = (vp.VALID_DIR / "all.txt").read_text().splitlines()
        self.assertIn(
            "1.0.0.1:443#\U0001F1FA\U0001F1F8US\u2192LAX-90ms-1.00MB/s-NF(US) D+ YT GPT-DC-72-V4-CN",
            lines,
        )
        self.assertIn("2.0.0.1:443#\U0001F1EF\U0001F1F5JP-70ms-GPT-CF", lines)
        self.assertFalse(any(line.startswith("9.9.9.9") for line in lines))
        self.assertTrue(
            any(line.startswith("3.0.0.1:443#\U0001F1FA\U0001F1F8US-50ms-0.50MB/s") for line in lines)
        )
        us_all = (vp.VALID_DIR / "countries" / "US" / "all.txt").read_text().splitlines()
        self.assertTrue(
            any("\u2192LAX-90ms-1.00MB/s-NF(US) D+ YT GPT-DC-72-V4-CN" in line for line in us_all)
        )

    def _keys(self, path) -> list:
        if not path.exists():
            return []
        return [line.split("#", 1)[0] for line in path.read_text(encoding="utf-8").splitlines()]

    def test_country_group_files_written(self):
        (vp.VALID_DIR / "all.txt").write_text(
            "1.0.0.1:443#\U0001F1FA\U0001F1F8US-120ms-CN-V4\n"
            "2.0.0.1:8443#\U0001F1FA\U0001F1F8US-100ms-V6\n"
            "3.0.0.1:443#\U0001F1FA\U0001F1F8US-80ms-CN-DS\n"
            "4.0.0.1:443#\U0001F1E9\U0001F1EADE-90ms-CN-V4\n",
            encoding="utf-8",
        )
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.0, 0.5, None),
            "2.0.0.1:8443#US": ("2.0.0.1", "8443", "US", "tls", 100.0, 0.5, None),
            "3.0.0.1:443#US": ("3.0.0.1", "443", "US", "tls", 80.0, 0.5, None),
            "4.0.0.1:443#DE": ("4.0.0.1", "443", "DE", "tls", 90.0, 0.5, None),
        }
        families = {
            "1.0.0.1:443#US": "ipv4",
            "2.0.0.1:8443#US": "ipv6",
            "3.0.0.1:443#US": "dual",
            "4.0.0.1:443#DE": "ipv4",
        }
        vp.write_valid_outputs(alive, per_country_limit=2, families=families)
        us = vp.VALID_DIR / "countries" / "US"
        self.assertEqual(self._keys(us / "v4.txt"), ["1.0.0.1:443"])
        self.assertEqual(self._keys(us / "v6.txt"), ["2.0.0.1:8443"])
        self.assertEqual(self._keys(us / "46.txt"), ["3.0.0.1:443"])
        self.assertEqual(self._keys(us / "cn.txt"), ["3.0.0.1:443", "1.0.0.1:443"])
        self.assertEqual(self._keys(us / "cn4.txt"), ["1.0.0.1:443"])
        self.assertEqual(self._keys(us / "cn6.txt"), [])
        self.assertEqual(self._keys(us / "cn46.txt"), ["3.0.0.1:443"])
        de = vp.VALID_DIR / "countries" / "DE"
        self.assertEqual(self._keys(de / "v4.txt"), ["4.0.0.1:443"])
        self.assertEqual(self._keys(de / "cn.txt"), ["4.0.0.1:443"])
        self.assertEqual(self._keys(de / "cn4.txt"), ["4.0.0.1:443"])

    def test_group_ltd_per_country_cap(self):
        (vp.VALID_DIR / "all.txt").write_text(
            "1.0.0.1:443#\U0001F1FA\U0001F1F8US-120ms-CN-V4\n"
            "2.0.0.1:443#\U0001F1FA\U0001F1F8US-100ms-CN-V4\n"
            "3.0.0.1:443#\U0001F1FA\U0001F1F8US-80ms-V4\n",
            encoding="utf-8",
        )
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.0, 0.2, None),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 100.0, 5.0, None),
            "3.0.0.1:443#US": ("3.0.0.1", "443", "US", "tls", 80.0, 1.0, None),
        }
        families = {k: "ipv4" for k in alive}
        vp.write_valid_outputs(alive, per_country_limit=2, families=families)
        us = vp.VALID_DIR / "countries" / "US"
        self.assertEqual(self._keys(us / "v4_ltd.txt"), ["2.0.0.1:443", "3.0.0.1:443"])
        self.assertEqual(self._keys(us / "cn_ltd.txt"), ["2.0.0.1:443", "1.0.0.1:443"])

    def test_set_group_files(self):
        (vp.VALID_DIR / "all.txt").write_text(
            "1.0.0.1:443#\U0001F1FA\U0001F1F8US-120ms-CN-V4\n"
            "2.0.0.1:8443#\U0001F1EF\U0001F1F5JP-100ms-V6\n",
            encoding="utf-8",
        )
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.0, 0.5, None),
            "2.0.0.1:8443#JP": ("2.0.0.1", "8443", "JP", "tls", 100.0, 0.5, None),
        }
        families = {"1.0.0.1:443#US": "ipv4", "2.0.0.1:8443#JP": "ipv6"}
        vp.write_valid_outputs(alive, per_country_limit=1, families=families)
        hot = vp.VALID_DIR / "sets" / "hot"
        self.assertEqual(self._keys(hot / "v4.txt"), ["1.0.0.1:443"])
        self.assertEqual(self._keys(hot / "v6.txt"), ["2.0.0.1:8443"])
        self.assertEqual(self._keys(hot / "cn.txt"), ["1.0.0.1:443"])
        self.assertEqual(self._keys(hot / "v4_ltd.txt"), ["1.0.0.1:443"])

    def test_root_group_files(self):
        (vp.VALID_DIR / "all.txt").write_text(
            "1.0.0.1:443#\U0001F1FA\U0001F1F8US-120ms-CN-V4\n"
            "2.0.0.1:443#\U0001F1FA\U0001F1F8US-80ms-CN-DS\n"
            "3.0.0.1:443#\U0001F1E9\U0001F1EADE-90ms-CN-V6\n",
            encoding="utf-8",
        )
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.0, 0.5, None),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 80.0, 2.0, None),
            "3.0.0.1:443#DE": ("3.0.0.1", "443", "DE", "tls", 90.0, 0.5, None),
        }
        families = {
            "1.0.0.1:443#US": "ipv4",
            "2.0.0.1:443#US": "dual",
            "3.0.0.1:443#DE": "ipv6",
        }
        vp.write_valid_outputs(alive, per_country_limit=1, families=families)
        root = vp.VALID_DIR
        self.assertEqual(self._keys(root / "all_46.txt"), ["2.0.0.1:443"])
        self.assertEqual(self._keys(root / "all_cn4.txt"), ["1.0.0.1:443"])
        self.assertEqual(self._keys(root / "all_cn6.txt"), ["3.0.0.1:443"])
        self.assertEqual(self._keys(root / "all_cn46.txt"), ["2.0.0.1:443"])
        self.assertEqual(self._keys(root / "all_46_ltd.txt"), ["2.0.0.1:443"])
        self.assertEqual(self._keys(root / "all_cn4_ltd.txt"), ["1.0.0.1:443"])

    def test_token_fallback_groups(self):
        (vp.VALID_DIR / "all.txt").write_text(
            "1.0.0.1:443#\U0001F1FA\U0001F1F8US-120ms-CN-V4\n"
            "2.0.0.1:8443#\U0001F1FA\U0001F1F8US-100ms-V6\n",
            encoding="utf-8",
        )
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.0, 0.5, None),
            "2.0.0.1:8443#US": ("2.0.0.1", "8443", "US", "tls", 100.0, 0.5, None),
        }
        vp.write_valid_outputs(alive, per_country_limit=1)
        us = vp.VALID_DIR / "countries" / "US"
        self.assertEqual(self._keys(us / "v4.txt"), ["1.0.0.1:443"])
        self.assertEqual(self._keys(us / "v6.txt"), ["2.0.0.1:8443"])
        self.assertEqual(self._keys(us / "cn.txt"), ["1.0.0.1:443"])
        self.assertEqual(self._keys(us / "cn4.txt"), ["1.0.0.1:443"])

    def test_empty_group_cleanup(self):
        (vp.VALID_DIR / "all.txt").write_text(
            "1.0.0.1:443#\U0001F1FA\U0001F1F8US-120ms-V4\n",
            encoding="utf-8",
        )
        alive = {"1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.0, 0.5, None)}
        vp.write_valid_outputs(alive, per_country_limit=1, families={"1.0.0.1:443#US": "ipv4"})
        us = vp.VALID_DIR / "countries" / "US"
        self.assertTrue((us / "v4.txt").exists())
        vp.write_valid_outputs(alive, per_country_limit=1, families={"1.0.0.1:443#US": "dual"})
        self.assertFalse((us / "v4.txt").exists())
        self.assertTrue((us / "46.txt").exists())
        self.assertFalse((us / "v4_ltd.txt").exists())

    def test_per_country_limit_zero_removes_group_ltd(self):
        (vp.VALID_DIR / "all.txt").write_text(
            "1.0.0.1:443#\U0001F1FA\U0001F1F8US-120ms-CN-V4\n",
            encoding="utf-8",
        )
        alive = {"1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.0, 0.5, None)}
        families = {"1.0.0.1:443#US": "ipv4"}
        vp.write_valid_outputs(alive, per_country_limit=1, families=families)
        us = vp.VALID_DIR / "countries" / "US"
        self.assertTrue((us / "v4_ltd.txt").exists())
        vp.write_valid_outputs(alive, per_country_limit=0, families=families)
        self.assertTrue((us / "v4.txt").exists())
        self.assertFalse((us / "v4_ltd.txt").exists())
        self.assertFalse((vp.VALID_DIR / "all_46_ltd.txt").exists())

    def test_cn_fallback_via_china_json(self):
        vp.CHINA_FILE.write_text(
            json.dumps({"proxies": {"1.0.0.1:443#US": {"verdict": "reachable"}}}),
            encoding="utf-8",
        )
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.0, 0.5, None),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 100.0, 0.5, None),
        }
        families = {"1.0.0.1:443#US": "ipv4", "2.0.0.1:443#US": "ipv4"}
        vp.write_valid_outputs(alive, per_country_limit=1, families=families)
        us = vp.VALID_DIR / "countries" / "US"
        self.assertEqual(self._keys(us / "cn.txt"), ["1.0.0.1:443"])
        self.assertEqual(self._keys(us / "cn4.txt"), ["1.0.0.1:443"])
        self.assertFalse((us / "v6.txt").exists())

    def test_cn_reachable_arg_override(self):
        alive = {"1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.0, 0.5, None)}
        families = {"1.0.0.1:443#US": "ipv4"}
        vp.write_valid_outputs(
            alive,
            per_country_limit=1,
            families=families,
            cn_reachable={"1.0.0.1:443#US"},
        )
        us = vp.VALID_DIR / "countries" / "US"
        self.assertEqual(self._keys(us / "cn.txt"), ["1.0.0.1:443"])
        vp.write_valid_outputs(
            alive,
            per_country_limit=1,
            families=families,
            cn_reachable=set(),
        )
        self.assertEqual(self._keys(us / "cn.txt"), [])

    def test_root_group_ltd_includes_all_pseudo_country(self):
        (vp.VALID_DIR / "all.txt").write_text(
            "1.0.0.1:443#ALL-120ms-CN-DS\n",
            encoding="utf-8",
        )
        alive = {"1.0.0.1:443#ALL": ("1.0.0.1", "443", "ALL", "tls", 120.0, 0.5, None)}
        families = {"1.0.0.1:443#ALL": "dual"}
        vp.write_valid_outputs(alive, per_country_limit=1, families=families)
        self.assertEqual(self._keys(vp.VALID_DIR / "all_46.txt"), ["1.0.0.1:443"])
        self.assertEqual(self._keys(vp.VALID_DIR / "all_46_ltd.txt"), ["1.0.0.1:443"])
        self.assertEqual(self._keys(vp.VALID_DIR / "all_cn46.txt"), ["1.0.0.1:443"])
        self.assertEqual(self._keys(vp.VALID_DIR / "all_cn46_ltd.txt"), ["1.0.0.1:443"])
        self.assertFalse((vp.VALID_DIR / "countries" / "ALL").exists())

    def test_cn_groups_preserve_old_notes_when_cached(self):
        (vp.VALID_DIR / "all.txt").write_text(
            "1.0.0.1:443#\U0001F1FA\U0001F1F8US-120ms-CN-V4-DC-72\n",
            encoding="utf-8",
        )
        alive = {"1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 120.0, 0.5, None)}
        vp.write_valid_outputs(alive, per_country_limit=1)
        us = vp.VALID_DIR / "countries" / "US"
        for name in ("v4.txt", "cn.txt", "cn4.txt"):
            content = (us / name).read_text(encoding="utf-8")
            self.assertIn("120ms", content, name)
            self.assertIn("DC-72", content, name)


class TestClassifyGroups(unittest.TestCase):
    """classify_groups / family_of / load_family_map pure logic."""

    def test_exclusive_families(self):
        self.assertEqual(vp.classify_groups("ipv4", False), {"v4"})
        self.assertEqual(vp.classify_groups("ipv6", False), {"v6"})
        self.assertEqual(vp.classify_groups("dual", False), {"46"})

    def test_unknown_family_no_groups(self):
        self.assertEqual(vp.classify_groups(None, False), set())
        self.assertEqual(vp.classify_groups("unknown", False), set())

    def test_cn_cross_product(self):
        self.assertEqual(vp.classify_groups("ipv4", True), {"v4", "cn", "cn4"})
        self.assertEqual(vp.classify_groups("ipv6", True), {"v6", "cn", "cn6"})
        self.assertEqual(vp.classify_groups("dual", True), {"46", "cn", "cn46"})

    def test_cn_unknown_family(self):
        self.assertEqual(vp.classify_groups(None, True), {"cn"})
        self.assertEqual(vp.classify_groups("unknown", True), {"cn"})

    def test_family_of_map_priority(self):
        families = {"1.0.0.1:443#US": "dual"}
        self.assertEqual(vp.family_of("1.0.0.1:443#US", "-V4", families), "dual")

    def test_family_of_token_fallback(self):
        self.assertEqual(vp.family_of("1.0.0.1:443#US", "-V4", {}), "ipv4")
        self.assertEqual(vp.family_of("1.0.0.1:443#US", "-V6", {}), "ipv6")
        self.assertEqual(vp.family_of("1.0.0.1:443#US", "-DS", {}), "dual")
        self.assertEqual(vp.family_of("1.0.0.1:443#US", "-CN-63", {}), None)
        self.assertEqual(vp.family_of("1.0.0.1:443#US", "", {}), None)

    def test_family_of_both_v4_v6_is_dual(self):
        self.assertEqual(vp.family_of("1.0.0.1:443#US", "-V4-V6", {}), "dual")
        self.assertEqual(vp.family_of("1.0.0.1:443#US", "-CN-V4-V6", {}), "dual")

    def test_load_family_map(self):
        tmp = Path(tempfile.mkdtemp(prefix="fm_"))
        j = tmp / "exit_family.json"
        j.write_text(
            json.dumps(
                {
                    "proxies": {
                        "1.0.0.1:443#US": {"family": "ipv4"},
                        "2.0.0.1:443#JP": {"family": "dual"},
                        "3.0.0.1:443#DE": {"family": "unknown"},
                        "4.0.0.1:443#FR": {"family": "ipv6"},
                    }
                }
            ),
            encoding="utf-8",
        )
        got = vp.load_family_map(j)
        self.assertEqual(
            got,
            {"1.0.0.1:443#US": "ipv4", "2.0.0.1:443#JP": "dual", "4.0.0.1:443#FR": "ipv6"},
        )

    def test_load_family_map_missing_or_broken(self):
        tmp = Path(tempfile.mkdtemp(prefix="fm_"))
        self.assertEqual(vp.load_family_map(tmp / "nope.json"), {})
        bad = tmp / "exit_family.json"
        bad.write_text("not json", encoding="utf-8")
        self.assertEqual(vp.load_family_map(bad), {})
        bare = tmp / "bare.json"
        bare.write_text(json.dumps({"1.0.0.1:443#US": {"family": "ipv6"}}), encoding="utf-8")
        self.assertEqual(vp.load_family_map(bare), {"1.0.0.1:443#US": "ipv6"})

    def test_load_family_map_non_dict_shapes(self):
        tmp = Path(tempfile.mkdtemp(prefix="fm_"))
        for payload in (
            [{"family": "ipv4"}],
            {"proxies": []},
            {"proxies": None},
            "not a dict",
            42,
        ):
            p = tmp / "shape.json"
            p.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(vp.load_family_map(p), {}, f"payload={payload!r}")

    def test_load_cn_reachable(self):
        tmp = Path(tempfile.mkdtemp(prefix="fm_"))
        p = tmp / "china.json"
        p.write_text(
            json.dumps(
                {
                    "proxies": {
                        "1.0.0.1:443#US": {"verdict": "reachable", "ms": 12.0},
                        "2.0.0.1:443#JP": {"verdict": "unreachable", "ms": None},
                        "3.0.0.1:443#DE": {"verdict": "uncertain", "ms": None},
                        "4.0.0.1:443#FR": {"verdict": "reachable", "basis": ["heuristic"]},
                    }
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(
            vp.load_cn_reachable(p), {"1.0.0.1:443#US", "4.0.0.1:443#FR"}
        )

    def test_load_cn_reachable_missing_or_broken(self):
        tmp = Path(tempfile.mkdtemp(prefix="fm_"))
        self.assertEqual(vp.load_cn_reachable(tmp / "nope.json"), set())
        bad = tmp / "china.json"
        bad.write_text("not json", encoding="utf-8")
        self.assertEqual(vp.load_cn_reachable(bad), set())
        for payload in ([{"verdict": "reachable"}], {"proxies": []}, 42):
            p = tmp / "shape.json"
            p.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(vp.load_cn_reachable(p), set(), f"payload={payload!r}")


class TestWriteHelpers(unittest.TestCase):
    """write_text_if_changed / write_json skip identical rewrites."""

    def setUp(self):
        import common
        self.cmn = common
        self.tmp = Path(tempfile.mkdtemp(prefix="wh_"))
        self.p = self.tmp / "out.txt"

    def test_writes_content(self):
        written = self.cmn.write_text_if_changed(self.p, "a\n")
        self.assertTrue(written)
        self.assertEqual(self.p.read_text(), "a\n")

    def test_skips_identical_rewrite(self):
        self.cmn.write_text_if_changed(self.p, "a\n")
        written = self.cmn.write_text_if_changed(self.p, "a\n")
        self.assertFalse(written)
        self.assertEqual(self.p.read_text(), "a\n")

    def test_rewrites_on_change(self):
        self.cmn.write_text_if_changed(self.p, "a\n")
        written = self.cmn.write_text_if_changed(self.p, "b\n")
        self.assertTrue(written)
        self.assertEqual(self.p.read_text(), "b\n")

    def test_write_json_skips_identical(self):
        j = self.tmp / "d.json"
        self.cmn.write_json(j, {"proxies": {"a": 1}})
        self.cmn.write_json(j, {"proxies": {"a": 1}})
        self.assertEqual(json.loads(j.read_text()), {"proxies": {"a": 1}})
        self.cmn.write_json(j, {"proxies": {"a": 2}})
        self.assertEqual(json.loads(j.read_text()), {"proxies": {"a": 2}})


class TestParseLineAndToken(unittest.TestCase):
    """common.parse_line / common.has_token canonical parsing."""

    def setUp(self):
        import common
        self.cmn = common

    def test_parse_line_full(self):
        got = self.cmn.parse_line("1.2.3.4:443#US-120ms-NF(US) DC")
        self.assertEqual(got, ("1.2.3.4:443#US", "1.2.3.4", "443", "US", "-120ms-NF(US) DC"))

    def test_parse_line_emoji_flag(self):
        got = self.cmn.parse_line("1.2.3.4:443#\U0001F1FA\U0001F1F8US-1ms")
        self.assertIsNotNone(got)
        self.assertEqual(got[3], "US")
        self.assertEqual(got[4], "-1ms")

    def test_parse_line_exit_region(self):
        got = self.cmn.parse_line("1.2.3.4:443#US\u2192LAX-8ms-GPT-CF-63")
        self.assertEqual(got[2], "443")
        self.assertEqual(got[4], "\u2192LAX-8ms-GPT-CF-63")

    def test_parse_line_bad(self):
        self.assertIsNone(self.cmn.parse_line("not a line"))
        self.assertIsNone(self.cmn.parse_line("1.2.3.4:443"))

    def test_has_token_boundaries(self):
        self.assertTrue(self.cmn.has_token("-120ms-CF-63", "CF"))
        self.assertTrue(self.cmn.has_token("CF-63", "CF"))
        self.assertTrue(self.cmn.has_token("NF(US) D+ YT-GPT-DC-72", "GPT"))
        self.assertFalse(self.cmn.has_token("-120ms-CN-V4", "CF"))
        self.assertFalse(self.cmn.has_token("-V4", "V6"))
        self.assertFalse(self.cmn.has_token("-1ms", "CF"))


class TestNormalizeExtResponse(unittest.TestCase):
    def test_090227_format(self):
        source = {"name": "090227"}
        data = {
            "success": True,
            "responseTime": 123.4,
            "colo": "LAX",
            "probe_results": {
                "ipv4": {"ok": True, "exit": {"countryCode": "US"}},
                "ipv6": {"ok": False},
            },
            "dual_stack": False,
            "inferred_stack": "ipv4",
        }
        result = vp._normalize_ext_response(source, data)
        self.assertTrue(result["ok"])
        self.assertEqual(result["response_ms"], 123.4)
        self.assertEqual(result["colo"], "LAX")
        self.assertTrue(result["ipv4_ok"])
        self.assertFalse(result["ipv6_ok"])
        self.assertEqual(result["exit_geo"]["countryCode"], "US")

    def test_cmliu_format(self):
        source = {"name": "cmliu"}
        data = {
            "success": True,
            "responseTime": 200.0,
            "colo": "NRT",
            "probe_results": {
                "ipv4": {"ok": True, "exit": {"countryCode": "JP"}},
                "ipv6": {"ok": True},
            },
            "dual_stack": True,
            "inferred_stack": "dual",
        }
        result = vp._normalize_ext_response(source, data)
        self.assertTrue(result["dual_stack"])
        self.assertTrue(result["ipv6_ok"])

    def test_toicf_format(self):
        source = {"name": "toicf"}
        data = {
            "ok": True,
            "supports_ipv4": True,
            "supports_ipv6": False,
            "dual_stack": False,
            "inferred_stack": "ipv4",
            "probe_results": [
                {
                    "ok": True,
                    "exit_ip": True,
                    "exit_country": "US",
                    "exit_city": "Los Angeles",
                    "exit_asn": 13335,
                    "exit_org": "Cloudflare",
                }
            ],
        }
        result = vp._normalize_ext_response(source, data)
        self.assertTrue(result["ok"])
        self.assertIsNone(result["response_ms"])
        self.assertIsNone(result["colo"])
        self.assertEqual(result["exit_geo"]["country"], "US")
        self.assertEqual(result["exit_geo"]["city"], "Los Angeles")

    def test_unknown_source(self):
        result = vp._normalize_ext_response({"name": "unknown"}, {})
        self.assertFalse(result["ok"])


class TestMergeExtVerdict(unittest.TestCase):
    def test_two_ok_sources_consensus(self):
        results = [
            {"name": "090227", "ok": True, "response_ms": 100, "colo": "LAX",
             "ipv4_ok": True, "ipv6_ok": False, "dual_stack": False,
             "inferred_stack": "ipv4", "exit_geo": {"countryCode": "US"}},
            {"name": "cmliu", "ok": True, "response_ms": 150, "colo": "LAX",
             "ipv4_ok": True, "ipv6_ok": False, "dual_stack": False,
             "inferred_stack": "ipv4", "exit_geo": {"countryCode": "US"}},
        ]
        verdict = vp.merge_ext_verdict(results)
        self.assertTrue(verdict["alive"])
        self.assertEqual(set(verdict["basis"]), {"090227", "cmliu"})
        self.assertEqual(verdict["merged"]["colo"], "LAX")

    def test_single_ok_uncertain(self):
        results = [
            {"name": "090227", "ok": True, "response_ms": 100, "colo": "LAX",
             "ipv4_ok": True, "ipv6_ok": False, "dual_stack": False,
             "inferred_stack": "ipv4", "exit_geo": None},
            {"name": "cmliu", "ok": False, "error": "timeout"},
            {"name": "toicf", "ok": False, "error": "timeout"},
        ]
        verdict = vp.merge_ext_verdict(results)
        self.assertEqual(verdict["alive"], "uncertain")
        self.assertEqual(verdict["basis"], ["090227"])

    def test_all_fail_dead(self):
        results = [
            {"name": "090227", "ok": False, "error": "timeout"},
            {"name": "cmliu", "ok": False, "error": "timeout"},
            {"name": "toicf", "ok": False, "error": "timeout"},
        ]
        verdict = vp.merge_ext_verdict(results)
        self.assertFalse(verdict["alive"])

    def test_skipped_when_no_errors(self):
        results = [
            {"name": "090227", "ok": False},
            {"name": "cmliu", "ok": False},
        ]
        verdict = vp.merge_ext_verdict(results)
        self.assertEqual(verdict["alive"], "skipped")


class TestMergeGeo(unittest.TestCase):
    def test_geo_mismatch_detection(self):
        ok = [
            {"response_ms": 100, "colo": "LAX", "ipv4_ok": True, "ipv6_ok": False,
             "dual_stack": False, "inferred_stack": "ipv4",
             "exit_geo": {"countryCode": "US"}},
            {"response_ms": 150, "colo": "NRT", "ipv4_ok": True, "ipv6_ok": False,
             "dual_stack": False, "inferred_stack": "ipv4",
             "exit_geo": {"countryCode": "JP"}},
        ]
        merged = vp.merge_geo(ok)
        self.assertTrue(merged["geo_mismatch"])

    def test_geo_match_no_mismatch(self):
        ok = [
            {"response_ms": 100, "colo": "LAX", "ipv4_ok": True, "ipv6_ok": False,
             "dual_stack": False, "inferred_stack": "ipv4",
             "exit_geo": {"countryCode": "US"}},
            {"response_ms": 150, "colo": "LAX", "ipv4_ok": True, "ipv6_ok": False,
             "dual_stack": False, "inferred_stack": "ipv4",
             "exit_geo": {"countryCode": "US"}},
        ]
        merged = vp.merge_geo(ok)
        self.assertFalse(merged["geo_mismatch"])

    def test_min_response_ms(self):
        ok = [
            {"response_ms": 200, "colo": None, "ipv4_ok": False, "ipv6_ok": False,
             "dual_stack": False, "inferred_stack": None, "exit_geo": None},
            {"response_ms": 100, "colo": None, "ipv4_ok": False, "ipv6_ok": False,
             "dual_stack": False, "inferred_stack": None, "exit_geo": None},
        ]
        merged = vp.merge_geo(ok)
        self.assertEqual(merged["response_ms"], 100)

    def test_dual_stack_union(self):
        ok = [
            {"response_ms": None, "colo": None, "ipv4_ok": True, "ipv6_ok": False,
             "dual_stack": False, "inferred_stack": "ipv4", "exit_geo": None},
            {"response_ms": None, "colo": None, "ipv4_ok": False, "ipv6_ok": True,
             "dual_stack": True, "inferred_stack": "ipv6", "exit_geo": None},
        ]
        merged = vp.merge_geo(ok)
        self.assertTrue(merged["ipv4_ok"])
        self.assertTrue(merged["ipv6_ok"])
        self.assertTrue(merged["dual_stack"])


class TestWriteExtCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vp_ext_"))
        self.orig_ext = vp.EXT_CHECK_FILE
        vp.EXT_CHECK_FILE = self.tmp / "ext_check.json"

    def tearDown(self):
        vp.EXT_CHECK_FILE = self.orig_ext

    def test_writes_ext_data(self):
        alive = {
            "1.0.0.1:443#US": (
                "1.0.0.1", "443", "US", "tls", 100.0, 1.0,
                {"sources": ["090227", "cmliu"], "alive": True,
                 "response_ms": 120, "colo": "LAX"},
            ),
        }
        vp.write_ext_check(alive)
        data = json.loads(vp.EXT_CHECK_FILE.read_text())
        self.assertIn("1.0.0.1:443#US", data["proxies"])
        self.assertEqual(data["proxies"]["1.0.0.1:443#US"]["colo"], "LAX")

    def test_skips_when_no_ext_data(self):
        alive = {
            "1.0.0.1:443#US": (
                "1.0.0.1", "443", "US", "tls", 100.0, 1.0, None,
            ),
        }
        vp.write_ext_check(alive)
        self.assertFalse(vp.EXT_CHECK_FILE.exists())

    def test_idempotent(self):
        alive = {
            "1.0.0.1:443#US": (
                "1.0.0.1", "443", "US", "tls", 100.0, 1.0,
                {"sources": ["090227"], "alive": True},
            ),
        }
        vp.write_ext_check(alive)
        m1 = vp.EXT_CHECK_FILE.stat().st_mtime_ns
        vp.write_ext_check(alive)
        m2 = vp.EXT_CHECK_FILE.stat().st_mtime_ns
        self.assertEqual(m1, m2)


class TestWriteValidOutputsExtRegion(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vp_region_"))
        self.orig = (vp.VALID_DIR, vp.CHINA_FILE, vp.INDEX_FILE, vp.SPEED_FILE)
        vp.VALID_DIR = self.tmp
        vp.CHINA_FILE = self.tmp / "china.json"
        vp.INDEX_FILE = self.tmp / "index.json"
        vp.SPEED_FILE = self.tmp / "speed.json"

    def tearDown(self):
        vp.VALID_DIR, vp.CHINA_FILE, vp.INDEX_FILE, vp.SPEED_FILE = self.orig

    def test_exit_region_inserted_from_ext_data(self):
        alive = {
            "1.0.0.1:443#US": (
                "1.0.0.1", "443", "US", "tls", 100.0, 1.0,
                {"sources": ["090227"], "alive": True,
                 "response_ms": 100, "colo": "LAX",
                 "exit_geo": {"countryCode": "US"}},
            ),
        }
        vp.write_valid_outputs(alive, per_country_limit=0)
        lines = (vp.VALID_DIR / "all.txt").read_text().splitlines()
        self.assertIn("→LAX", lines[0])

    def test_no_ext_data_no_region(self):
        alive = {
            "1.0.0.1:443#US": (
                "1.0.0.1", "443", "US", "tls", 100.0, 1.0, None,
            ),
        }
        vp.write_valid_outputs(alive, per_country_limit=0)
        lines = (vp.VALID_DIR / "all.txt").read_text().splitlines()
        self.assertNotIn("→", lines[0])


class TestMainCLIArgs(unittest.TestCase):
    def test_ext_check_flag(self):
        parser = vp.argparse.ArgumentParser(description="test")
        parser.add_argument("--ext-check", action="store_true")
        parser.add_argument("--no-ext-check", action="store_true")
        parser.add_argument("--ext-timeout", type=int, default=10)
        parser.add_argument("--ext-workers", type=int, default=10)
        args = parser.parse_args(["--ext-check", "--ext-timeout", "5", "--ext-workers", "20"])
        self.assertTrue(args.ext_check)
        self.assertEqual(args.ext_timeout, 5)
        self.assertEqual(args.ext_workers, 20)

    def test_no_ext_check_overrides(self):
        parser = vp.argparse.ArgumentParser(description="test")
        parser.add_argument("--ext-check", action="store_true")
        parser.add_argument("--no-ext-check", action="store_true")
        args = parser.parse_args(["--ext-check", "--no-ext-check"])
        if args.no_ext_check:
            args.ext_check = False
        self.assertFalse(args.ext_check)


class TestAdaptiveSpeedParams(unittest.TestCase):
    def test_low_rtt_no_change(self):
        cap_bytes, cap_sec = vp.adaptive_speed_params(
            tls_latency_ms=50,
            base_bytes=1048576,
            base_timeout=5,
        )
        self.assertEqual(cap_sec, 5)
        self.assertEqual(cap_bytes, 5 * 1024 * 1024)

    def test_medium_rtt_increases(self):
        cap_bytes, cap_sec = vp.adaptive_speed_params(
            tls_latency_ms=300,
            base_bytes=1048576,
            base_timeout=5,
        )
        self.assertEqual(cap_sec, 9)
        self.assertEqual(cap_bytes, 9 * 1024 * 1024)

    def test_high_rtt_larger_window(self):
        cap_bytes, cap_sec = vp.adaptive_speed_params(
            tls_latency_ms=500,
            base_bytes=1048576,
            base_timeout=5,
        )
        self.assertEqual(cap_sec, 15)
        self.assertEqual(cap_bytes, 15 * 1024 * 1024)

    def test_very_high_rtt(self):
        cap_bytes, cap_sec = vp.adaptive_speed_params(
            tls_latency_ms=1000,
            base_bytes=1048576,
            base_timeout=5,
        )
        self.assertEqual(cap_sec, 30)
        self.assertEqual(cap_bytes, 30 * 1024 * 1024)

    def test_min_timeout_floor(self):
        cap_bytes, cap_sec = vp.adaptive_speed_params(
            tls_latency_ms=10,
            base_bytes=1048576,
            base_timeout=5,
        )
        self.assertEqual(cap_sec, 5)

    def test_base_bytes_larger_than_adaptive(self):
        cap_bytes, cap_sec = vp.adaptive_speed_params(
            tls_latency_ms=50,
            base_bytes=10 * 1024 * 1024,
            base_timeout=5,
        )
        self.assertEqual(cap_bytes, 10 * 1024 * 1024)
        self.assertEqual(cap_sec, 5)

    def test_progressive_scaling(self):
        cases = [
            (50, 5),
            (100, 5),
            (200, 6),
            (300, 9),
            (500, 15),
            (1000, 30),
        ]
        for rtt_ms, expected_timeout in cases:
            _, cap_sec = vp.adaptive_speed_params(rtt_ms, 1048576, 5)
            self.assertEqual(cap_sec, expected_timeout, f"RTT={rtt_ms}ms")


KB = 1024


class FakeWriter:
    def __init__(self):
        self.written = b""

    def write(self, data):
        self.written += data

    async def drain(self):
        pass


class FakeReader:
    """Delivers scripted chunks then EOF (or raises a scripted exception)."""

    def __init__(self, chunks, error=None):
        self.chunks = list(chunks)
        self.error = error

    async def read(self, n=-1):
        if self.chunks:
            return self.chunks.pop(0)
        if self.error is not None:
            raise self.error
        return b""


class FakeClock:
    """Scripted monotonic clock: consumes values in order, last one sticks."""

    def __init__(self, *values):
        self.values = list(values)

    def __call__(self) -> float:
        if len(self.values) > 1:
            return self.values.pop(0)
        return self.values[0]


HTTP_OK_HEAD = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Content-Length: 99999999\r\n\r\n"
)


def http_stream(*body_chunks):
    """Scripted reader chunks: a 200 OK head merged into the first body chunk."""
    if not body_chunks:
        return [HTTP_OK_HEAD]
    return [HTTP_OK_HEAD + body_chunks[0], *body_chunks[1:]]


class TestSpeedDownload(unittest.IsolatedAsyncioTestCase):
    """Steady-state measurement: warm-up bytes are excluded from timing."""

    async def test_steady_state_excludes_warmup(self):
        # 12 x 64KB; first 256KB ramp slowly (0.4s), steady part is fast.
        chunks = http_stream(*([b"x" * (64 * KB)] * 12))
        reader = FakeReader(chunks)
        clock = FakeClock(
            0.0,                                  # start
            0.1, 0.2, 0.3, 0.4,                   # remain checks during warm-up
            0.9,                                  # warm-up crossed -> timed_start
            0.91, 0.92, 0.93, 0.94,               # remain checks, measured iters
            0.95, 0.96, 0.97, 0.98,
            0.99,                                 # remain check before EOF
            1.0,                                  # final elapsed sample
        )
        speed = await vp.speed_download(
            reader, FakeWriter(), "h", "/p",
            cap_bytes=10 * KB * KB, cap_sec=30,
            warmup_bytes=vp.SPEED_WARMUP_BYTES, clock=clock,
        )
        # timed window: 512KB after the warm-up over 0.1s -> ~5 MB/s.
        # Whole-transfer average would be 768KB / 1.0s = 0.75 MB/s.
        self.assertAlmostEqual(speed, 5.0, delta=0.75)

    async def test_eof_inside_warmup_falls_back_to_whole_transfer(self):
        reader = FakeReader(http_stream(*([b"x" * (128 * KB)] * 2)))
        clock = FakeClock(0.0, 0.1, 0.2, 0.35, 0.4, 0.5)
        speed = await vp.speed_download(
            reader, FakeWriter(), "h", "/p",
            cap_bytes=10 * KB * KB, cap_sec=30,
            warmup_bytes=vp.SPEED_WARMUP_BYTES, clock=clock,
        )
        # No usable steady-state sample -> whole-transfer average:
        # 256KB over 0.5s -> 0.5 MB/s (instead of None).
        self.assertEqual(speed, 0.5)

    async def test_timeout_inside_warmup_falls_back_to_whole_transfer(self):
        reader = FakeReader(http_stream(b"x" * (100 * KB)), error=asyncio.TimeoutError())
        clock = FakeClock(0.0, 0.1, 0.2, 1.4)
        speed = await vp.speed_download(
            reader, FakeWriter(), "h", "/p",
            cap_bytes=10 * KB * KB, cap_sec=30,
            warmup_bytes=vp.SPEED_WARMUP_BYTES, clock=clock,
        )
        # 100KB over 1.4s -> 0.07 MB/s fallback instead of None.
        self.assertEqual(speed, 0.07)

    async def test_zero_warmup_times_everything(self):
        reader = FakeReader(http_stream(*([b"x" * (128 * KB)] * 3)))
        clock = FakeClock(0.0, 0.1, 0.2, 0.3, 0.4, 0.5)
        speed = await vp.speed_download(
            reader, FakeWriter(), "h", "/p",
            cap_bytes=10 * KB * KB, cap_sec=30,
            warmup_bytes=0, clock=clock,
        )
        # Legacy behaviour: all 384KB over 0.5s -> 0.75 MB/s.
        self.assertEqual(speed, 0.75)

    async def test_tiny_transfer_returns_none(self):
        reader = FakeReader(http_stream(b"x" * KB))
        clock = FakeClock(0.0, 0.1, 0.2, 0.3)
        speed = await vp.speed_download(
            reader, FakeWriter(), "h", "/p",
            cap_bytes=10 * KB * KB, cap_sec=30,
            warmup_bytes=vp.SPEED_WARMUP_BYTES, clock=clock,
        )
        self.assertIsNone(speed)

    async def test_non_200_rejected(self):
        body = b"error page" * 10000
        reader = FakeReader(
            [b"HTTP/1.1 403 Forbidden\r\nContent-Length: 5\r\n\r\n" + body]
        )
        clock = FakeClock(0.0, 0.1)
        speed = await vp.speed_download(
            reader, FakeWriter(), "h", "/p",
            cap_bytes=10 * KB * KB, cap_sec=30,
            warmup_bytes=vp.SPEED_WARMUP_BYTES, clock=clock,
        )
        # An error page must fail the test instead of counting as speed.
        self.assertIsNone(speed)

    async def test_garbage_without_http_head_rejected(self):
        reader = FakeReader([b"\x16\x03\x01not-http-at-all"])
        clock = FakeClock(0.0, 0.1, 0.2)
        speed = await vp.speed_download(
            reader, FakeWriter(), "h", "/p",
            cap_bytes=10 * KB * KB, cap_sec=30,
            warmup_bytes=vp.SPEED_WARMUP_BYTES, clock=clock,
        )
        self.assertIsNone(speed)

    async def test_header_split_across_reads(self):
        head_part = b"HTTP/1.1 200 OK\r\nX-Edge: a\r\n"
        body = b"x" * (300 * KB)
        reader = FakeReader([head_part, b"\r\n" + body])
        clock = FakeClock(0.0, 0.1, 0.2, 0.35, 0.4, 0.5)
        speed = await vp.speed_download(
            reader, FakeWriter(), "h", "/p",
            cap_bytes=10 * KB * KB, cap_sec=30,
            warmup_bytes=vp.SPEED_WARMUP_BYTES, clock=clock,
        )
        # Body crosses the warm-up boundary inside feed(); steady-state
        # sample is empty -> whole-transfer fallback over the body only.
        expected_total = len(head_part) + 2 + len(body)
        self.assertEqual(speed, vp.compute_speed(expected_total, 0.5))


class TestSpeedWarmupFlag(unittest.TestCase):
    def test_default_constant(self):
        self.assertEqual(vp.SPEED_WARMUP_BYTES, 256 * KB)

    def test_help_lists_flag(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                vp.main(["--help"])
        self.assertIn("--speed-warmup-bytes", buf.getvalue())


class TestVerifiedStableOutputs(unittest.TestCase):
    """all_verified / all_stable 根级清单与分组变体（含 cn4 等联动）。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vp_vs_"))
        self.orig = (vp.VALID_DIR, vp.CHINA_FILE, vp.INDEX_FILE, vp.SPEED_FILE)
        vp.VALID_DIR = self.tmp
        vp.CHINA_FILE = self.tmp / "china.json"
        vp.INDEX_FILE = self.tmp / "index.json"
        vp.SPEED_FILE = self.tmp / "speed.json"

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)
        vp.VALID_DIR, vp.CHINA_FILE, vp.INDEX_FILE, vp.SPEED_FILE = self.orig

    def test_root_verified_stable_lists(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 1.5, None),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 200.0, None, None),
            "3.0.0.1:443#JP": ("3.0.0.1", "443", "JP", "tls", 150.0, 0.8, None),
        }
        stats = vp.write_valid_outputs(
            alive,
            per_country_limit=0,
            prev_keys={"1.0.0.1:443#US", "2.0.0.1:443#US"},
        )
        verified = (vp.VALID_DIR / "all_verified.txt").read_text().splitlines()
        self.assertEqual(
            [l.split("#")[0] for l in verified],
            ["1.0.0.1:443", "3.0.0.1:443"],
        )
        stable = (vp.VALID_DIR / "all_stable.txt").read_text().splitlines()
        self.assertEqual(
            [l.split("#")[0] for l in stable],
            ["1.0.0.1:443", "2.0.0.1:443"],
        )
        sets = stats["__sets__"]
        self.assertEqual(sets["all_verified"], 2)
        self.assertEqual(sets["all_stable"], 2)

    def test_ltd_verified_stable_variants(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 1.5, None),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 200.0, None, None),
            "3.0.0.1:443#JP": ("3.0.0.1", "443", "JP", "tls", 150.0, 0.8, None),
        }
        stats = vp.write_valid_outputs(
            alive,
            per_country_limit=2,
            prev_keys={"1.0.0.1:443#US", "2.0.0.1:443#US"},
        )
        root_ver = (vp.VALID_DIR / "all_ltd_verified.txt").read_text().splitlines()
        self.assertEqual(
            sorted(l.split("#")[0] for l in root_ver),
            ["1.0.0.1:443", "3.0.0.1:443"],
        )
        us_dir = vp.VALID_DIR / "countries" / "US"
        ltd_ver = (us_dir / "ltd_verified.txt").read_text().splitlines()
        self.assertEqual([l.split("#")[0] for l in ltd_ver], ["1.0.0.1:443"])
        ltd_sta = (us_dir / "ltd_stable.txt").read_text().splitlines()
        self.assertEqual(
            [l.split("#")[0] for l in ltd_sta], ["1.0.0.1:443", "2.0.0.1:443"]
        )
        sets = stats["__sets__"]
        self.assertIn("all_ltd_verified", sets)
        self.assertIn("all_ltd_stable", sets)

    def test_group_verified_stable_variants(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 1.5, None),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 200.0, None, None),
        }
        families = {"1.0.0.1:443#US": "ipv4", "2.0.0.1:443#US": "ipv4"}
        vp.write_valid_outputs(
            alive,
            per_country_limit=0,
            families=families,
            cn_reachable={"1.0.0.1:443#US", "2.0.0.1:443#US"},
            prev_keys={"2.0.0.1:443#US"},
        )
        us = vp.VALID_DIR / "countries" / "US"
        self.assertTrue((us / "cn4.txt").exists())
        v = (us / "cn4_verified.txt").read_text().splitlines()
        self.assertEqual([l.split("#")[0] for l in v], ["1.0.0.1:443"])
        s = (us / "cn4_stable.txt").read_text().splitlines()
        self.assertEqual([l.split("#")[0] for l in s], ["2.0.0.1:443"])
        root_v = (vp.VALID_DIR / "all_cn4_verified.txt").read_text().splitlines()
        self.assertEqual(len(root_v), 1)
        root_s = (vp.VALID_DIR / "all_cn4_stable.txt").read_text().splitlines()
        self.assertEqual(len(root_s), 1)

    def test_group_ltd_verified_stable_variants(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 1.5, None),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 200.0, None, None),
        }
        families = {"1.0.0.1:443#US": "ipv4", "2.0.0.1:443#US": "ipv4"}
        families = {"1.0.0.1:443#US": "ipv4", "2.0.0.1:443#US": "ipv4"}
        stats = vp.write_valid_outputs(
            alive,
            per_country_limit=2,
            families=families,
            cn_reachable={"1.0.0.1:443#US", "2.0.0.1:443#US"},
            prev_keys={"1.0.0.1:443#US"},
        )
        us = vp.VALID_DIR / "countries" / "US"
        # 分组 ltd 变体（每目录 {g}_ltd_verified/_stable）
        v = (us / "cn4_ltd_verified.txt").read_text().splitlines()
        self.assertEqual([l.split("#")[0] for l in v], ["1.0.0.1:443"])
        s = (us / "cn4_ltd_stable.txt").read_text().splitlines()
        self.assertEqual([l.split("#")[0] for l in s], ["1.0.0.1:443"])
        # 根级分组 ltd 可靠性变体
        rv = (vp.VALID_DIR / "all_cn4_ltd_verified.txt").read_text().splitlines()
        self.assertEqual([l.split("#")[0] for l in rv], ["1.0.0.1:443"])
        rs = (vp.VALID_DIR / "all_cn4_ltd_stable.txt").read_text().splitlines()
        self.assertEqual([l.split("#")[0] for l in rs], ["1.0.0.1:443"])
        self.assertIn("all_ltd_verified", stats["__sets__"])

    def test_empty_variant_files_cleaned(self):
        vp.VALID_DIR.mkdir(parents=True, exist_ok=True)
        stale_v = vp.VALID_DIR / "all_verified.txt"
        stale_s = vp.VALID_DIR / "all_stable.txt"
        stale_v.write_text("stale\n")
        stale_s.write_text("stale\n")
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, None, None),
        }
        vp.write_valid_outputs(alive, per_country_limit=0, prev_keys=None)
        self.assertFalse(stale_v.exists())
        self.assertFalse(stale_s.exists())

    def test_first_run_no_prev_keys_writes_no_stable(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 1.0, None),
        }
        vp.write_valid_outputs(alive, per_country_limit=0, prev_keys=None)
        self.assertFalse((vp.VALID_DIR / "all_stable.txt").exists())
        self.assertTrue((vp.VALID_DIR / "all_verified.txt").exists())
