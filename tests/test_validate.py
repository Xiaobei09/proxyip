"""Tests for validate_proxies.py pure functions."""

import asyncio
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from unittest import mock

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


class TestQuickPrefilter(unittest.TestCase):
    def setUp(self):
        self.entries = [
            ("1.2.3.4", "443", "US"),      # 上一轮未存活 → 预连通候选
            ("5.6.7.8", "8080", "JP"),     # 上一轮存活 → 全检
            ("9.9.9.9", "8443", "DE"),     # 上一轮未存活 → 预连通候选
            ("2.2.2.2", "443", "FR"),      # 上一轮存活 → 全检
        ]

    def test_candidate_classification(self):
        prev = {"5.6.7.8:8080", "2.2.2.2:443"}
        cands, normal = vp.classify_quick_candidates(self.entries, prev)
        self.assertEqual(cands, [("1.2.3.4", "443", "US"), ("9.9.9.9", "8443", "DE")])
        self.assertEqual(normal, [("5.6.7.8", "8080", "JP"), ("2.2.2.2", "443", "FR")])

    def test_empty_prev_all_candidates(self):
        cands, normal = vp.classify_quick_candidates(self.entries, set())
        self.assertEqual(len(cands), len(self.entries))
        self.assertEqual(normal, [])

    def test_all_prev_no_candidates(self):
        prev = {f"{e[0]}:{e[1]}" for e in self.entries}
        cands, normal = vp.classify_quick_candidates(self.entries, prev)
        self.assertEqual(cands, [])
        self.assertEqual(len(normal), len(self.entries))

    def test_ipv6_entry_encodes_port(self):
        entries = [("2001:db8::1", "8443", "US")]
        cands, _ = vp.classify_quick_candidates(entries, set())
        self.assertEqual(cands, entries)
        cands, _ = vp.classify_quick_candidates(entries, {"2001:db8::1:8443"})
        self.assertEqual(cands, [])


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

    def test_fmt_entry_roundtrip_contract_r109(self):
        """R109数据格式：fmt_entry 产出恒满足契约 A 精度（ms 整数/速度两位）。"""
        import re
        from common import parse_ltd_line
        for latency in (0, 8.4, 8.5, 120.5, 999.9):
            for speed in (None, 0.445, 5.864, 100.0):
                with self.subTest(latency=latency, speed=speed):
                    line = vp.fmt_entry("1.2.3.4", "443", "US", latency, speed)
                    parsed = parse_ltd_line(line)
                    self.assertIsNotNone(parsed, line)
                    self.assertEqual(parsed[0], "1.2.3.4:443#US")
                    note = line.split("#", 1)[1]
                    self.assertRegex(note, r"-\d+ms($|-)")
                    if speed is None:
                        self.assertNotIn("MB/s", note)
                    else:
                        self.assertRegex(note, r"-\d+\.\d{2}MB/s$")


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

    def test_base_already_has_exit_region_no_double_arrow(self):
        base = "1.2.3.4:443#\U0001F1FA\U0001F1F8US\u2192LAX-90ms-1.00MB/s"
        old = "\u2192US-120ms-0.44MB/s-RES-72-V4-CN"
        self.assertEqual(
            vp.merge_old_note(base, old),
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US\u2192LAX-90ms-1.00MB/s-RES-72-V4-CN",
        )

    def test_base_region_same_as_old_region(self):
        base = "1.2.3.4:443#US\u2192US-90ms-1.00MB/s"
        old = "\u2192US-120ms-0.44MB/s-DC-60"
        self.assertEqual(
            vp.merge_old_note(base, old),
            "1.2.3.4:443#US\u2192US-90ms-1.00MB/s-DC-60",
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

    def test_sets_cover_previously_missing_countries(self):
        """R291：SK/CO/MO/KG/OM/BH 曾被集合定义遗漏（sets/ 缺 23 端点，
        与 R289 countries/ 漂移同类）；R293 追加工 Africa 缺口 NA（新入池）。
        定义修复后，合成条目必须落入对应集合分裂
       （europe/asia/south_america/middle_east/africa）。"""
        alive = {
            "1.0.0.1:443#SK": ("1.0.0.1", "443", "SK", "tls", 100.0, 0.5, None),
            "1.0.0.2:443#CO": ("1.0.0.2", "443", "CO", "tls", 100.0, 0.5, None),
            "1.0.0.3:443#MO": ("1.0.0.3", "443", "MO", "tls", 100.0, 0.5, None),
            "1.0.0.4:443#KG": ("1.0.0.4", "443", "KG", "tls", 100.0, 0.5, None),
            "1.0.0.5:443#OM": ("1.0.0.5", "443", "OM", "tls", 100.0, 0.5, None),
            "1.0.0.6:443#BH": ("1.0.0.6", "443", "BH", "tls", 100.0, 0.5, None),
            "1.0.0.7:443#NA": ("1.0.0.7", "443", "NA", "tls", 100.0, 0.5, None),
        }
        vp.write_valid_outputs(alive, per_country_limit=1)
        sets = vp.VALID_DIR / "sets"
        expect = {
            "europe": "1.0.0.1:443",
            "south_america": "1.0.0.2:443",
            "asia": "1.0.0.3:443",
            "middle_east": "1.0.0.5:443",
            "africa": "1.0.0.7:443",
        }
        for name, key in expect.items():
            lines = (sets / name / "all.txt").read_text(
                encoding="utf-8").splitlines()
            self.assertIn(key, [ln.split("#", 1)[0] for ln in lines], name)
        asia_lines = (sets / "asia" / "all.txt").read_text(
            encoding="utf-8").splitlines()
        asia_keys = [ln.split("#", 1)[0] for ln in asia_lines]
        self.assertIn("1.0.0.4:443", asia_keys)
        self.assertIn("1.0.0.6:443", asia_keys)

    def test_set_definitions_match_docs(self):
        """R292：集合定义与 docs/data-spec.md 集合表逐字对等（国家＋计数）。

        R291 修定义时同步了文档；此锁防任一侧单边改动（如只改代码
        忘改计数，或文档先行）。全 10 集合比对。"""
        import re
        from pathlib import Path
        doc = (Path(__file__).resolve().parent.parent / "docs"
               / "data-spec.md").read_text(encoding="utf-8")
        for name, countries in {**vp.COUNTRY_SETS, **vp.SMALL_SETS}.items():
            m = re.search(
                r"`" + name + r"` \| ([A-Z ]+)（(\d+)）", doc)
            self.assertIsNotNone(m, f"data-spec.md 缺集合 {name}")
            self.assertEqual(
                sorted(m.group(1).split()), sorted(countries), name)
            self.assertEqual(int(m.group(2)), len(countries), name)

    def test_set_definitions_hygiene(self):
        """R293：集合定义卫生——无重复/畸形码；地理集合字母序，
        精选集合（hot/cn_common/hk_us_jp_sg_tw_kr）为刻意优先级序，
        豁免排序但仍禁重复。"""
        geo = set(vp.COUNTRY_SETS) - {"hot"}
        for name, countries in {**vp.COUNTRY_SETS, **vp.SMALL_SETS}.items():
            with self.subTest(set=name):
                self.assertEqual(len(countries), len(set(countries)))
                for cc in countries:
                    self.assertRegex(cc, r"^[A-Z]{2}$")
                if name in geo:
                    self.assertEqual(countries, sorted(countries))

    def test_sets_empty_not_written_and_residue_removed(self):
        # 空命名集合（所含国家全部缺席）不得产出 0 字节/单换行残留：
        # 旧实现写 \"\\n\"，且此类文件在 data/valid（守卫覆盖）但未及写入端。
        (vp.VALID_DIR / "sets" / "africa").mkdir(parents=True)
        (vp.VALID_DIR / "sets" / "africa" / "all.txt").write_text("\n")
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 0.5, None),
            "2.0.0.1:443#JP": ("2.0.0.1", "443", "JP", "tls", 80.0, 1.0, None),
        }
        vp.write_valid_outputs(alive, per_country_limit=1)
        self.assertFalse((vp.VALID_DIR / "sets" / "africa" / "all.txt").exists())
        self.assertFalse((vp.VALID_DIR / "sets" / "africa" / "ltd.txt").exists())
        self.assertTrue((vp.VALID_DIR / "sets" / "hot" / "all.txt").exists())
        self.assertTrue((vp.VALID_DIR / "all.txt").exists())

    def test_empty_alive_no_residue_all_txt(self):
        # 全池轮空时 all.txt 不写 \"\\n\" 残留（直接清理）
        (vp.VALID_DIR).mkdir(parents=True, exist_ok=True)
        (vp.VALID_DIR / "all.txt").write_text("\n")
        vp.write_valid_outputs({}, per_country_limit=1)
        self.assertFalse((vp.VALID_DIR / "all.txt").exists())

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

    def test_family_of_unknown_map_not_fall_back_to_token(self):
        """权威源显式 unknown 时不得用行内旧 token 兜底（R165/R166）。"""
        families = {"1.0.0.1:443#US": "unknown"}
        self.assertIsNone(vp.family_of("1.0.0.1:443#US", "-V6", families))

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


class TestAppendHistory(unittest.TestCase):
    """history.jsonl 契约：compact 单行、5 字段投影、窗口截断、原子写。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vp_hist_"))
        self.orig = vp.VALID_HISTORY_FILE
        vp.VALID_HISTORY_FILE = self.tmp / "history.jsonl"

    def tearDown(self):
        vp.VALID_HISTORY_FILE = self.orig

    def test_writes_compact_projected_fields(self):
        vp.append_history({
            "ts": "2026-09-16T00:00:00Z", "total": 100, "checked": 95,
            "alive": 70, "dead": 25, "elapsed_s": 9.1,
        })
        lines = vp.VALID_HISTORY_FILE.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertNotIn(" ", lines[0])  # compact separators
        rec = json.loads(lines[0])
        self.assertEqual(rec, {"ts": "2026-09-16T00:00:00Z", "total": 100,
                               "checked": 95, "alive": 70, "dead": 25})
        self.assertNotIn("elapsed_s", rec)

    def test_truncates_to_window(self):
        for i in range(vp.MAX_HISTORY_RECORDS + 5):
            vp.append_history({"ts": "t%d" % i, "total": i, "checked": i,
                               "alive": i, "dead": 0})
        lines = vp.VALID_HISTORY_FILE.read_text().splitlines()
        self.assertEqual(len(lines), vp.MAX_HISTORY_RECORDS)
        first = json.loads(lines[0])
        self.assertEqual(first["ts"], "t%d" % (5))

    def test_appends_to_existing(self):
        vp.append_history({"ts": "a", "total": 1, "checked": 1,
                           "alive": 1, "dead": 0})
        vp.append_history({"ts": "b", "total": 2, "checked": 2,
                           "alive": 2, "dead": 0})
        self.assertEqual(len(vp.VALID_HISTORY_FILE.read_text().splitlines()), 2)


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
    def test_probe_dict_schema_format(self):
        source = {"name": "S1", "schema": "probe_dict"}
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

    def test_probe_dict_schema_second_source(self):
        source = {"name": "S2", "schema": "probe_dict"}
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

    def test_probe_list_schema_format(self):
        source = {"name": "S3", "schema": "probe_list"}
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
        for src in ({"name": "unknown"},
                     {"name": "S9", "schema": "no_such_schema"}):
            with self.subTest(src=src):
                result = vp._normalize_ext_response(src, {})
                self.assertFalse(result["ok"])

    def test_string_success_is_not_ok_r169(self):
        """R169验证正确性：与 probe 侧同契约（字符串布尔非显式 True 不算
        成功；两链同源同判，防 update/quality 链分叉）。"""
        for name in ("S1", "S2"):
            for bad in ("false", "true", 1, 0, None):
                result = vp._normalize_ext_response({"name": name, "schema": "probe_dict"}, {
                    "success": bad, "probe_results": {}})
                self.assertIs(result["ok"], False, (name, bad))
            result = vp._normalize_ext_response({"name": name, "schema": "probe_dict"}, {
                "success": True, "probe_results": {}})
            self.assertIs(result["ok"], True)

    def test_non_bool_success_logs_debug_r170(self):
        """R170可用性：非布尔 success 判否时留 debug 痕迹（排障可观测；
        缺键与真布尔保持静默）。"""
        with self.assertLogs("root", level="DEBUG") as logs:
            vp._normalize_ext_response({"name": "S1", "schema": "probe_dict"}, {
                "success": "false", "probe_results": {}})
        self.assertTrue(any("not bool" in m for m in logs.output))
        with self.assertNoLogs("root", level="DEBUG"):
            vp._normalize_ext_response({"name": "S1", "schema": "probe_dict"}, {
                "success": True, "probe_results": {}})
            vp._normalize_ext_response({"name": "S1", "schema": "probe_dict"}, {})

    def test_ext_warn_needed_r171(self):
        """R171用户侧体验：ext 开启＋无源才 warn（显式关闭/有源皆静默）。"""
        self.assertTrue(vp.ext_check_warn_needed(True, []))
        self.assertFalse(vp.ext_check_warn_needed(False, []))
        self.assertFalse(vp.ext_check_warn_needed(True, [{"name": "x"}]))
        self.assertFalse(vp.ext_check_warn_needed(False, [{"name": "x"}]))
        self.assertEqual(vp.ext_check_warn_needed(True),
                         vp.ext_check_warn_needed(True, vp.EXT_API_SOURCES))


class TestMergeExtVerdict(unittest.TestCase):
    def test_two_ok_sources_consensus(self):
        results = [
            {"name": "S1", "ok": True, "response_ms": 100, "colo": "LAX",
             "ipv4_ok": True, "ipv6_ok": False, "dual_stack": False,
             "inferred_stack": "ipv4", "exit_geo": {"countryCode": "US"}},
            {"name": "S2", "ok": True, "response_ms": 150, "colo": "LAX",
             "ipv4_ok": True, "ipv6_ok": False, "dual_stack": False,
             "inferred_stack": "ipv4", "exit_geo": {"countryCode": "US"}},
        ]
        verdict = vp.merge_ext_verdict(results)
        self.assertTrue(verdict["alive"])
        self.assertEqual(set(verdict["basis"]), {"S1", "S2"})
        self.assertEqual(verdict["merged"]["colo"], "LAX")

    def test_single_ok_uncertain(self):
        results = [
            {"name": "S1", "ok": True, "response_ms": 100, "colo": "LAX",
             "ipv4_ok": True, "ipv6_ok": False, "dual_stack": False,
             "inferred_stack": "ipv4", "exit_geo": None},
            {"name": "S2", "ok": False, "error": "timeout"},
            {"name": "S3", "ok": False, "error": "timeout"},
        ]
        verdict = vp.merge_ext_verdict(results)
        self.assertEqual(verdict["alive"], "uncertain")
        self.assertEqual(verdict["basis"], ["S1"])

    def test_all_fail_dead(self):
        results = [
            {"name": "S1", "ok": False, "error": "timeout"},
            {"name": "S2", "ok": False, "error": "timeout"},
            {"name": "S3", "ok": False, "error": "timeout"},
        ]
        verdict = vp.merge_ext_verdict(results)
        self.assertFalse(verdict["alive"])

    def test_skipped_when_no_errors(self):
        results = [
            {"name": "S1", "ok": False},
            {"name": "S2", "ok": False},
        ]
        verdict = vp.merge_ext_verdict(results)
        self.assertEqual(verdict["alive"], "skipped")

    def test_empty_results_skipped_r155(self):
        """R155验证正确性：E3无包空表链 []→skipped（零任务不断言死活，
        fail-open 语义在裁决层闭环）。"""
        verdict = vp.merge_ext_verdict([])
        self.assertEqual(verdict["alive"], "skipped")
        self.assertEqual(verdict["basis"], [])
        self.assertIsNone(verdict["merged"])


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
                {"sources": ["S1", "S2"], "alive": True,
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
                {"sources": ["S1"], "alive": True},
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
                {"sources": ["S1"], "alive": True,
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

    def test_no_adaptive_speed_visible_in_help_r145(self):
        """R145功能查找：--no-adaptive-speed 须可见（docs 已记载，help 曾隐藏）。"""
        import subprocess
        import sys
        from pathlib import Path
        proc = subprocess.run(
            [sys.executable, str(Path(vp.__file__).with_name("validate_proxies.py")),
             "--help"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--no-adaptive-speed", proc.stdout)


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

    def test_cn_group_variants_use_cn_latency_speed(self):
        alive = {
            "1.0.0.1:443#US": ("1.0.0.1", "443", "US", "tls", 100.0, 1.5, None),
            "2.0.0.1:443#US": ("2.0.0.1", "443", "US", "tls", 200.0, None, None),
        }
        families = {"1.0.0.1:443#US": "ipv4", "2.0.0.1:443#US": "ipv4"}
        with mock.patch(
            "validate_proxies.load_cn_ms",
            return_value={"1.0.0.1:443#US": 88.0, "2.0.0.1:443#US": 77.0},
        ):
            vp.write_valid_outputs(
                alive,
                per_country_limit=2,
                families=families,
                cn_reachable={"1.0.0.1:443#US", "2.0.0.1:443#US"},
                prev_keys={"1.0.0.1:443#US"},
            )
        us = vp.VALID_DIR / "countries" / "US"
        for name in ("cn4", "cn4_ltd", "cn4_verified", "cn4_stable",
                     "cn4_ltd_verified", "cn4_ltd_stable"):
            lines = (us / f"{name}.txt").read_text().splitlines()
            self.assertGreater(
                len(lines), 0, f"{name}.txt must keep CN entries after rewrite"
            )
            self.assertIn(
                "-88ms-", lines[0], f"{name}.txt must use CN latency (not overseas)"
            )
            self.assertIn(
                "≈", lines[0], f"{name}.txt must use CN-aware ≈ speed (not plain)"
            )
        self.assertIn(
            "-88ms-≈1.50MB/s", (us / "cn4_ltd.txt").read_text()
        )
        self.assertNotIn(
            "-100ms-", (us / "cn4.txt").read_text(), "Overseas TLS latency must be replaced"
        )

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


class TestExtractToicfExitGeo(unittest.TestCase):
    def test_first_ok_probe_with_exit_ip_wins(self):
        data = {"probe_results": [
            {"ok": False, "exit_ip": "9.9.9.9"},
            {"ok": True, "exit_ip": "8.8.8.8", "exit_country": "US",
             "exit_city": "LA", "exit_asn": 15169, "exit_org": "G"},
            {"ok": True, "exit_ip": "1.1.1.1", "exit_country": "AU"},
        ]}
        geo = vp._extract_list_probe_exit_geo(data)
        self.assertEqual(geo["countryCode"], "US")
        self.assertEqual(geo["city"], "LA")
        self.assertEqual(geo["asn"], 15169)

    def test_none_when_no_ok_probe_with_exit_ip(self):
        self.assertIsNone(vp._extract_list_probe_exit_geo(
            {"probe_results": [{"ok": False}, {"ok": True}]}
        ))
        self.assertIsNone(vp._extract_list_probe_exit_geo({}))
        self.assertIsNone(vp._extract_list_probe_exit_geo({"probe_results": []}))


class TestHistoryRecordShape(unittest.TestCase):
    def test_valid_history_record_fields_exact(self):
        meta = {"ts": "2026-09-16T00:00:00Z", "total": 100, "checked": 99,
                "alive": 95, "dead": 4}
        with tempfile.TemporaryDirectory() as td:
            hist = Path(td) / "history.jsonl"
            with mock.patch.object(vp, "VALID_HISTORY_FILE", hist):
                vp.append_history(meta)
            line = json.loads(hist.read_text().splitlines()[0])
        self.assertEqual(
            set(line),
            {"ts", "total", "checked", "alive", "dead"},
        )
        self.assertEqual(len(line), 5)


class TestValidateDryRunR183b(unittest.TestCase):
    """R183b用户侧体验：validate --dry-run 只计划不探测不写盘。

    全树此前仅 exit_family/china_check 有 dry-run（待验证⑤悬置项）。
    """

    def _source(self, tmp, lines):
        p = Path(tmp) / "all.txt"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    def test_plan_prints_and_skips_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = self._source(tmp, ["1.2.3.4:443#US", "5.6.7.8:80#JP"])
            err = io.StringIO()
            with mock.patch.object(vp, "check_entries",
                                   side_effect=AssertionError("must not probe")), \
                 mock.patch.object(vp, "write_valid_outputs",
                                   side_effect=AssertionError("must not write")), \
                 contextlib.redirect_stderr(err):
                rc = vp.main(["--source", str(src), "--dry-run"])
            self.assertEqual(rc, 0)
            out = err.getvalue()
            self.assertIn("dry-run: no network, no writes", out)
            self.assertIn("dry-run plan: entries=2", out)
            self.assertIn("ext_check=off", out)

    def test_limit_applies_to_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = self._source(tmp, ["1.2.3.4:443#US", "5.6.7.8:80#JP",
                                     "9.9.9.9:443#DE"])
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = vp.main(["--source", str(src), "--dry-run", "--limit", "2"])
            self.assertEqual(rc, 0)
            self.assertIn("dry-run plan: entries=2", err.getvalue())

    def test_missing_source_still_errors(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = vp.main(["--source", "/nonexistent/all.txt", "--dry-run"])
        self.assertEqual(rc, 1)
