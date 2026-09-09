"""Tests for build_premium.py scoring, filtering and output layout."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import build_premium as bp
from common import line_to_key


class TestBuildIpTypeMap(unittest.TestCase):
    def test_basic(self):
        data = {"proxies": {
            "1.2.3.4:443#US": {"ip_type": "RES", "geo_checked": True},
            "5.6.7.8:443#JP": {"ip_type": "DC", "geo_checked": True},
            "9.9.9.9:443#DE": "garbage",
        }}
        m = bp.build_ip_type_map(data)
        self.assertEqual(m, {"1.2.3.4:443#US": "RES", "5.6.7.8:443#JP": "DC"})

    def test_unchecked_geo_excluded(self):
        # ip-api 缺失/失败时 classify_ip({}) 默认 RES 是未知而非实测住宅，
        # 不得放进 premium 住宅子集
        data = {"proxies": {
            "1.2.3.4:443#US": {"ip_type": "RES", "geo_checked": False},
            "5.6.7.8:443#JP": {"ip_type": "DC"},   # 未写 geo_checked
        }}
        self.assertEqual(bp.build_ip_type_map(data), {})

    def test_missing_ip_type(self):
        data = {"proxies": {"1.2.3.4:443#US": {"geo_checked": True}}}
        self.assertEqual(bp.build_ip_type_map(data), {})


class TestBuildRepMap(unittest.TestCase):
    def test_basic(self):
        data = {"proxies": {
            "1.2.3.4:443#US": {"score": 96, "risk": "low"},
            "5.6.7.8:443#JP": {"risk": "medium"},
        }}
        m = bp.build_rep_map(data)
        self.assertEqual(m, {"1.2.3.4:443#US": {"score": 96, "risk": "low"}})


class TestBuildFamilyMap(unittest.TestCase):
    FAMILY = {
        "proxies": {
            "1.1.1.1:443#US": {"family": "ipv4"},
            "2.2.2.2:443#JP": {"family": "dual"},
            "3.3.3.3:443#DE": {"family": "ipv6"},
            "4.4.4.4:443#FR": {"family": "weird"},
            "5.5.5.5:443#IT": "garbage",
        }
    }

    def test_basic(self):
        m = bp.build_family_map(self.FAMILY)
        self.assertEqual(m, {
            "1.1.1.1:443#US": "ipv4",
            "2.2.2.2:443#JP": "dual",
            "3.3.3.3:443#DE": "ipv6",
        })

    def test_empty(self):
        self.assertEqual(bp.build_family_map({}), {})


class TestFamilyOf(unittest.TestCase):
    def test_exit_family_preferred(self):
        fam = {"1.1.1.1:443#US": "ipv6"}
        line = "1.1.1.1:443#US-80ms-RES-V4-CN-96"
        self.assertEqual(bp.family_of("1.1.1.1:443#US", line, fam), "ipv6")

    def test_line_token_fallback(self):
        cases = [
            ("1.1.1.1:443#US-80ms-RES-V4-CN-96", {}, "ipv4"),
            ("2.2.2.2:443#US-80ms-RES-V6-CN-96", {}, "ipv6"),
            ("3.3.3.3:443#US-80ms-RES-DS-CN-96", {}, "dual"),
            ("4.4.4.4:443#US-80ms-RES-V4-V6-CN-96", {}, "dual"),
        ]
        for line, fam, want in cases:
            self.assertEqual(bp.family_of(line_to_key(line), line, fam), want)

    def test_untagged(self):
        self.assertIsNone(bp.family_of("9.9.9.9:443#US", "9.9.9.9:443#US-80ms-RES-CN-96", {}))

    def test_none_key(self):
        self.assertIsNone(bp.family_of(None, "9.9.9.9:443#US-80ms", {}))


class TestBuildChinaSet(unittest.TestCase):
    def test_reachable_only(self):
        data = {"proxies": {
            "1.2.3.4:443#US": {"verdict": "reachable"},
            "5.6.7.8:443#JP": {"verdict": "unreachable"},
        }}
        self.assertEqual(bp.build_china_set(data), {"1.2.3.4:443#US"})


class TestFilterRank(unittest.TestCase):
    LINES = (
        "9.9.9.9:443#US-500ms-2.00MB/s-RES-CN-96\n"
        "1.1.1.1:443#US-100ms-5.00MB/s-RES-CN-96\n"
        "5.5.5.5:443#JP-60ms-10.0MB/s-RES-97\n"          # not CN reachable
        "2.2.2.2:443#HK-50ms-8.00MB/s-RES-CN-94\n"       # rep below 95
        "3.3.3.3:443#SG-70ms-1.00MB/s-DC-CN-96\n"        # ip_type DC, not RES
        "4.4.4.4:443#DE-80ms-3.00MB/s-RES-CN-99-high\n"  # risk high
    )

    def setUp(self):
        self.china = {"9.9.9.9:443#US", "1.1.1.1:443#US",
                      "2.2.2.2:443#HK", "3.3.3.3:443#SG", "4.4.4.4:443#DE"}
        self.rep = {
            "9.9.9.9:443#US": {"score": 96, "risk": "low"},
            "1.1.1.1:443#US": {"score": 96, "risk": "low"},
            "2.2.2.2:443#HK": {"score": 94, "risk": "low"},
            "3.3.3.3:443#SG": {"score": 96, "risk": "low"},
            "4.4.4.4:443#DE": {"score": 99, "risk": "high"},
            "5.5.5.5:443#JP": {"score": 97, "risk": "low"},
        }
        self.ip_type = {
            "9.9.9.9:443#US": "RES",
            "1.1.1.1:443#US": "RES",
            "2.2.2.2:443#HK": "RES",
            "3.3.3.3:443#SG": "DC",
            "4.4.4.4:443#DE": "RES",
            "5.5.5.5:443#JP": "RES",
        }

    def test_filters_and_orders(self):
        out = bp.filter_rank(self.LINES, self.china, self.rep, self.ip_type)
        # 1.1.1.1: rep 96, RES, CN -> passes; score ~94
        # 9.9.9.9: rep 96, RES, CN -> passes; score ~62
        # Others dropped: JP(no CN), HK(rep<95), SG(ip_type!=RES), DE(high risk)
        keys = [l.split("#")[0] for l in out]
        self.assertEqual(keys, ["1.1.1.1:443", "9.9.9.9:443"])

    def test_rep_threshold_boundary(self):
        lines = (
            "8.0.0.1:443#US-100ms-RES-CN-95\n"
            "8.0.0.2:443#US-100ms-RES-CN-94\n"
        )
        china = {f"8.0.0.{i}:443#US" for i in (1, 2)}
        rep = {
            "8.0.0.1:443#US": {"score": 95, "risk": "low"},
            "8.0.0.2:443#US": {"score": 94, "risk": "low"},
        }
        ip_type = {
            "8.0.0.1:443#US": "RES",
            "8.0.0.2:443#US": "RES",
        }
        out = bp.filter_rank(lines, china, rep, ip_type)
        self.assertEqual([l.split(":")[0] for l in out], ["8.0.0.1"])

    def test_non_res_excluded(self):
        lines = "1.0.0.1:443#US-80ms-DC-CN-99\n"
        china = {"1.0.0.1:443#US"}
        rep = {"1.0.0.1:443#US": {"score": 99, "risk": "low"}}
        ip_type = {"1.0.0.1:443#US": "DC"}
        out = bp.filter_rank(lines, china, rep, ip_type)
        self.assertEqual(len(out), 0)

    def test_tie_breaks_by_latency_then_key(self):
        lines = (
            "9.0.0.2:443#US-300ms-RES-CN-95\n"
            "9.0.0.1:443#US-300ms-RES-CN-95\n"
            "9.0.0.3:443#US-200ms-RES-CN-95\n"
        )
        china = {f"9.0.0.{i}:443#US" for i in (1, 2, 3)}
        rep = {f"9.0.0.{i}:443#US": {"score": 95, "risk": "low"}
               for i in (1, 2, 3)}
        ip_type = {f"9.0.0.{i}:443#US": "RES" for i in (1, 2, 3)}
        out = bp.filter_rank(lines, china, rep, ip_type)
        self.assertEqual(
            [l.split(":")[0] for l in out],
            ["9.0.0.3", "9.0.0.1", "9.0.0.2"],
        )

    def test_empty_inputs(self):
        self.assertEqual(bp.filter_rank("", set(), {}, {}), [])


class TestWritePremiumFiles(unittest.TestCase):
    POOL = (
        "1.1.1.1:443#US-100ms-5.00MB/s-RES-CN-96\n"
        "2.2.2.2:443#US-400ms-1.00MB/s-DC-CN-85\n"
        "5.5.5.5:443#JP-60ms-9.00MB/s-RES-97\n"
    )
    CHINA = {"1.1.1.1:443#US", "2.2.2.2:443#US"}
    REP = {
        "1.1.1.1:443#US": {"score": 96, "risk": "low"},
        "2.2.2.2:443#US": {"score": 85, "risk": "low"},
    }
    IP_TYPE = {
        "1.1.1.1:443#US": "RES",
        "2.2.2.2:443#US": "DC",
    }

    def test_layout_and_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            (valid / "countries" / "US").mkdir(parents=True)
            (valid / "sets" / "hot").mkdir(parents=True)
            (valid / "all.txt").write_text(self.POOL, encoding="utf-8")
            (valid / "countries" / "US" / "all.txt").write_text(
                self.POOL, encoding="utf-8")
            (valid / "sets" / "hot" / "all.txt").write_text(
                self.POOL, encoding="utf-8")

            stats = bp.write_premium_files(
                valid, self.CHINA, self.REP, self.IP_TYPE)
            self.assertEqual(stats["all_premium"], 1)  # only 1.1.1.1 (RES + rep≥96 + CN)
            self.assertEqual(stats["countries/US"], 1)
            self.assertEqual(stats["sets/hot"], 1)

            prem = (valid / "all_premium.txt").read_text(encoding="utf-8")
            self.assertEqual(prem.splitlines()[0].split("#")[0], "1.1.1.1:443")
            self.assertEqual(len(prem.splitlines()), 1)
            self.assertTrue((valid / "countries" / "US" / "premium.txt").exists())
            self.assertTrue((valid / "sets" / "hot" / "premium.txt").exists())

    def test_idempotent_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            valid.mkdir(parents=True)
            (valid / "all.txt").write_text(self.POOL, encoding="utf-8")
            bp.write_premium_files(valid, self.CHINA, self.REP, self.IP_TYPE)
            first = (valid / "all_premium.txt").read_bytes()
            mtime = (valid / "all_premium.txt").stat().st_mtime_ns
            bp.write_premium_files(valid, self.CHINA, self.REP, self.IP_TYPE)
            self.assertEqual((valid / "all_premium.txt").read_bytes(), first)
            self.assertEqual(
                (valid / "all_premium.txt").stat().st_mtime_ns, mtime)

    def test_missing_quality_data_yields_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            valid.mkdir(parents=True)
            (valid / "all.txt").write_text(self.POOL, encoding="utf-8")
            stats = bp.write_premium_files(valid, set(), {}, {})
            self.assertEqual(stats["all_premium"], 0)
            self.assertEqual((valid / "all_premium.txt").read_text(), "")

    def test_family_branches_written_and_cleaned(self):
        POOL = (
            "1.1.1.1:443#US-80ms-5.00MB/s-RES-V4-CN-96\n"
            "1.1.1.2:443#US-80ms-5.00MB/s-RES-V6-CN-96\n"
            "1.1.1.3:443#US-80ms-5.00MB/s-RES-V4-V6-CN-96\n"
            "1.1.1.4:443#US-80ms-5.00MB/s-RES-CN-95\n"   # no family token
            "5.5.5.5:443#JP-60ms-9.00MB/s-RES-97\n"       # not CN
        )
        china = {f"1.1.1.{i}:443#US" for i in range(1, 5)}
        rep = {f"1.1.1.{i}:443#US": {"score": 96, "risk": "low"}
               for i in range(1, 5)}
        rep["1.1.1.4:443#US"] = {"score": 95, "risk": "low"}
        ip_type = {f"1.1.1.{i}:443#US": "RES" for i in range(1, 5)}
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            (valid / "countries" / "US").mkdir(parents=True)
            (valid / "sets" / "hot").mkdir(parents=True)
            (valid / "all.txt").write_text(POOL, encoding="utf-8")
            (valid / "countries" / "US" / "all.txt").write_text(
                POOL, encoding="utf-8")
            (valid / "sets" / "hot" / "all.txt").write_text(
                POOL, encoding="utf-8")

            bp.write_premium_files(valid, china, rep, ip_type)

            v4 = (valid / "all_premium_v4.txt").read_text(encoding="utf-8")
            self.assertEqual([l.split("#")[0] for l in v4.splitlines()],
                             ["1.1.1.1:443"])
            v6 = (valid / "all_premium_v6.txt").read_text(encoding="utf-8")
            self.assertEqual([l.split("#")[0] for l in v6.splitlines()],
                             ["1.1.1.2:443"])
            d46 = (valid / "all_premium_46.txt").read_text(encoding="utf-8")
            self.assertEqual([l.split("#")[0] for l in d46.splitlines()],
                             ["1.1.1.3:443"])
            # 无家族 token 的行只进基础清单
            base = (valid / "all_premium.txt").read_text(encoding="utf-8")
            self.assertEqual(len(base.splitlines()), 4)
            # 国家/集合目录同步派生家族分支
            self.assertTrue((valid / "countries" / "US" / "premium_v4.txt").exists())
            self.assertTrue((valid / "countries" / "US" / "premium_v6.txt").exists())
            self.assertTrue((valid / "countries" / "US" / "premium_46.txt").exists())
            self.assertTrue((valid / "sets" / "hot" / "premium_v4.txt").exists())

    def test_family_map_overrides_line_token(self):
        POOL = (
            "1.1.1.1:443#US-80ms-5.00MB/s-RES-V4-CN-96\n"
            "1.1.1.2:443#US-80ms-5.00MB/s-RES-V6-CN-96\n"
        )
        china = {"1.1.1.1:443#US", "1.1.1.2:443#US"}
        rep = {k: {"score": 96, "risk": "low"} for k in china}
        ip_type = {k: "RES" for k in china}
        fam = {"1.1.1.1:443#US": "ipv6", "1.1.1.2:443#US": "ipv4"}
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            valid.mkdir(parents=True)
            (valid / "all.txt").write_text(POOL, encoding="utf-8")
            bp.write_premium_files(valid, china, rep, ip_type, family_map=fam)
            v4 = (valid / "all_premium_v4.txt").read_text(encoding="utf-8")
            self.assertEqual([l.split("#")[0] for l in v4.splitlines()],
                             ["1.1.1.2:443"])
            v6 = (valid / "all_premium_v6.txt").read_text(encoding="utf-8")
            self.assertEqual([l.split("#")[0] for l in v6.splitlines()],
                             ["1.1.1.1:443"])

    def test_family_stale_files_cleaned(self):
        POOL = "1.1.1.1:443#US-80ms-5.00MB/s-RES-V4-CN-96\n"
        china = {"1.1.1.1:443#US"}
        rep = {"1.1.1.1:443#US": {"score": 96, "risk": "low"}}
        ip_type = {"1.1.1.1:443#US": "RES"}
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            valid.mkdir(parents=True)
            (valid / "all.txt").write_text(POOL, encoding="utf-8")
            bp.write_premium_files(valid, china, rep, ip_type)
            self.assertTrue((valid / "all_premium_v4.txt").exists())
            # 家族全部消失（池中无 V4/V6/DS）→ 旧分支文件被清理
            (valid / "all.txt").write_text("", encoding="utf-8")
            bp.write_premium_files(valid, set(), {}, {})
            self.assertFalse((valid / "all_premium_v4.txt").exists())
            self.assertFalse((valid / "all_premium_v4_verified.txt").exists())

    def test_cn_view_applied_to_all_outputs(self):
        POOL = (
            "1.1.1.1:443#US-100ms-5.00MB/s-RES-V4-CN-96\n"
            "1.1.1.2:443#US-400ms-1.00MB/s-RES-V6-CN-96\n"
        )
        china = {"1.1.1.1:443#US", "1.1.1.2:443#US"}
        rep = {k: {"score": 96, "risk": "low"} for k in china}
        ip_type = {k: "RES" for k in china}
        cn_ms = {"1.1.1.1:443#US": 234.0, "1.1.1.2:443#US": 35.0}
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            valid.mkdir(parents=True)
            (valid / "all.txt").write_text(POOL, encoding="utf-8")
            bp.write_premium_files(valid, china, rep, ip_type, cn_ms=cn_ms)
            base = (valid / "all_premium.txt").read_text(encoding="utf-8")
            base_lines = base.splitlines()
            self.assertIn("US-234ms-", base_lines[0])
            self.assertIn("≈", base_lines[0])
            self.assertIn("US-35ms-", base_lines[1])
            self.assertIn("≈", base_lines[1])
            # 家族分支同样 CN 视图
            v4 = (valid / "all_premium_v4.txt").read_text(encoding="utf-8")
            self.assertIn("≈", v4)
            v6 = (valid / "all_premium_v6.txt").read_text(encoding="utf-8")
            self.assertIn("≈", v6)

    def test_main_stamps_premium_meta(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            (data_dir / "valid").mkdir(parents=True)
            (data_dir / "quality").mkdir(parents=True)
            rc = bp.main(["--data-dir", str(data_dir)])
            self.assertEqual(rc, 0)
            meta = json.loads(
                (data_dir / "quality" / "premium_meta.json").read_text()
            )
            self.assertIn("file_count", meta)
            self.assertIn("proxy_count", meta)
            self.assertIsInstance(meta["ts"], str)
            self.assertGreater(len(meta["ts"]), 10)


if __name__ == "__main__":
    unittest.main()
