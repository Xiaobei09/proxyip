import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from annotate_classify import reconcile_views, verify_country_split
from annotate_classify import _build_rep_map, _build_family_map
from annotate_classify import _build_ip_type_map


class TestReconcileViews(unittest.TestCase):
    """``reconcile_views`` 须把所有视图约束到 ``all.txt`` 大师清单。

    历史轮次遗留的非 CF 端口/离场节点一旦不在 ``all.txt``，就在每轮
    注解时剔除；同目录 ``ltd`` 还须是本目录 ``all`` 的子集。
    """

    def _tree(self, all_lines, ports=None, countries=None, sets_dir=None):
        d = Path(tempfile.mkdtemp())
        valid = d / "valid"
        (valid / "ports").mkdir(parents=True)
        (valid / "countries" / "US").mkdir(parents=True)
        (valid / "sets" / "asia").mkdir(parents=True)
        (valid / "all.txt").write_text("\n".join(all_lines) + "\n", encoding="utf-8")
        for name, lines in (ports or {}).items():
            (valid / "ports" / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        for name, lines in (countries or {}).items():
            (valid / "countries" / "US" / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        for name, lines in (sets_dir or {}).items():
            (valid / "sets" / "asia" / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return d, valid

    def test_removes_phantom_lines_only(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#US", "3.3.3.3:85#US"],
            ports={"443.txt": ["1.1.1.1:443#US", "8.8.8.8:443#US"], "85.txt": ["9.9.9.9:85#US"]},
        )
        removed = reconcile_views(valid)
        self.assertEqual(removed, 2)
        self.assertEqual(
            (valid / "ports" / "443.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US\n",
        )
        # 越界行全数剔除 → 清空不落盘（不写 0 字节残留）
        self.assertFalse((valid / "ports" / "85.txt").exists())

    def test_key_compare_ignores_note_differences(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US-old"],
            ports={"443.txt": ["1.1.1.1:443#US-new"]},
        )
        self.assertEqual(reconcile_views(valid), 0)
        self.assertEqual(
            (valid / "ports" / "443.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US-new\n",
        )

    def test_country_all_pruned_to_master(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#US"],
            countries={
                "all.txt": ["1.1.1.1:443#US", "9.9.9.9:443#US"],
                "ltd.txt": ["1.1.1.1:443#US"],
            },
        )
        removed = reconcile_views(valid)
        self.assertEqual(removed, 1)
        self.assertEqual(
            (valid / "countries" / "US" / "all.txt").read_text(encoding="utf-8"),
            # R313 起回填缺失方向：越界行剔除后，master 缺失行按原字节补入
            "1.1.1.1:443#US\n2.2.2.2:443#US\n",
        )

    def test_country_ltd_kept_within_country_all(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#US"],
            countries={
                "all.txt": ["1.1.1.1:443#US"],
                "ltd.txt": ["1.1.1.1:443#US", "2.2.2.2:443#US"],
            },
        )
        removed = reconcile_views(valid)
        self.assertEqual(removed, 0)
        self.assertEqual(
            (valid / "countries" / "US" / "ltd.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US\n2.2.2.2:443#US\n",
        )

    def test_set_ltd_missing_from_master_pruned(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#HK"],
            sets_dir={
                "all.txt": ["1.1.1.1:443#US"],
                "ltd.txt": ["1.1.1.1:443#US", "2.2.2.2:443#HK", "9.9.9.9:443#US"],
            },
        )
        removed = reconcile_views(valid)
        self.assertEqual(removed, 1)
        self.assertEqual(
            (valid / "sets" / "asia" / "ltd.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US\n2.2.2.2:443#HK\n",
        )

    def test_verify_country_split_consistent(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#US"],
            countries={"all.txt": ["1.1.1.1:443#US", "2.2.2.2:443#US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual((r["master"], r["countries"]), (2, 2))
        self.assertEqual(r["missing"], [])
        self.assertEqual(r["excess"], [])
        self.assertEqual(r["dup_endpoints"], 0)

    def test_verify_country_split_all_sentinel_excluded(self):
        # ``#ALL``（入口未知）依 data-spec 只在 all.txt/all_ltd.txt、不进
        # countries/：大师键集须剔除 ALL，否则合法哨兵被误报 missing。
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#ALL→US"],
            countries={"all.txt": ["1.1.1.1:443#US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual((r["master"], r["countries"]), (1, 1))
        self.assertEqual(r["missing"], [])
        self.assertEqual(r["excess"], [])

    def test_verify_country_split_phantom_duplicate_detected(self):
        # 同键在分目录行数 > 大师（入口国标注不同的重复行）：reconcile_views
        # 按键裁剪剪不掉 → phantom 计 1，键集 1:1 不受影响。
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US"],
            countries={"all.txt": ["1.1.1.1:443#US", "1.1.1.1:443#DE→US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual(r["phantom"], 1)
        self.assertEqual(r["missing"], [])
        self.assertEqual(r["excess"], [])

    def test_verify_country_split_matched_duplicates_not_phantom(self):
        # 大师本就含两行同键（两次观测）→ 分目录同样两行属正常，phantom=0。
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "1.1.1.1:443#DE→US"],
            countries={"all.txt": ["1.1.1.1:443#US", "1.1.1.1:443#DE→US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual(r["phantom"], 0)

    def test_verify_country_split_excess_detected(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US"],
            countries={"all.txt": ["1.1.1.1:443#US", "9.9.9.9:443#US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual(r["excess"], ["9.9.9.9:443"])
        self.assertEqual(r["missing"], [])

    def test_verify_country_split_missing_detected(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#US"],
            countries={"all.txt": ["1.1.1.1:443#US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual(r["missing"], ["2.2.2.2:443"])

    def test_verify_country_split_no_all_txt(self):
        d = Path(tempfile.mkdtemp())
        r = verify_country_split(d / "valid")
        self.assertEqual((r["master"], r["countries"]), (0, 0))
        self.assertEqual(r["missing"] + r["excess"], [])
        self.assertEqual(r["dup_endpoints"], 0)

    def test_verify_country_split_dup_endpoint_detected(self):
        # 同一 ip:port 出现在两个国家目录（#SG 与 #CO）→ dup_endpoints 计 1；
        # 键集 1:1 不受影响（missing/excess 为空）
        d = Path(tempfile.mkdtemp())
        valid = d / "valid"
        (valid / "countries" / "SG").mkdir(parents=True)
        (valid / "countries" / "CO").mkdir(parents=True)
        (valid / "countries" / "CN").mkdir(parents=True)
        all_lines = ["1.1.1.1:443#SG→US", "1.1.1.1:443#CO→US", "2.2.2.2:443#CN"]
        (valid / "all.txt").write_text("\n".join(all_lines) + "\n", encoding="utf-8")
        (valid / "countries" / "SG" / "all.txt").write_text(
            "1.1.1.1:443#SG→US\n", encoding="utf-8")
        (valid / "countries" / "CO" / "all.txt").write_text(
            "1.1.1.1:443#CO→US\n", encoding="utf-8")
        (valid / "countries" / "CN" / "all.txt").write_text(
            "2.2.2.2:443#CN\n", encoding="utf-8")
        r = verify_country_split(valid)
        self.assertEqual((r["master"], r["countries"]), (2, 2))
        self.assertEqual(r["missing"], [])
        self.assertEqual(r["excess"], [])
        self.assertEqual(r["dup_endpoints"], 1)

    def test_empty_all_returns_zero(self):
        d, valid = self._tree(all_lines=[], ports={"443.txt": ["9.9.9.9:443#US"]})
        self.assertEqual(reconcile_views(valid), 0)

    def test_newline_only_file_pruned_as_empty(self):
        # 空集合曾以 \"\\n\" 形式（1 字节）落盘；空行不是主集成员，
        # prune 须将其视为空文件整体清除（此前空行被\"保留\"，残留永不愈合）。
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US"],
            ports={"443.txt": [""]},
        )
        (valid / "ports" / "443.txt").write_text("\n", encoding="utf-8")
        removed = reconcile_views(valid)
        self.assertEqual(removed, 1)
        self.assertFalse((valid / "ports" / "443.txt").exists())
        # 混有真实行 + 空行的文件：空行剔除、真实行保留
        d2, valid2 = self._tree(
            all_lines=["1.1.1.1:443#US"],
            ports={"443.txt": ["1.1.1.1:443#US", ""]},
        )
        removed = reconcile_views(valid2)
        self.assertEqual(removed, 1)
        self.assertEqual(
            (valid2 / "ports" / "443.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US\n",
        )

    def test_backfill_missing_country_lines(self):
        """R313：master 缺失行按原字节补入所属国家分裂（延迟升序建目录）；
        键已存在不重复；#ALL 与不可解析行跳过。"""
        d = Path(tempfile.mkdtemp())
        valid = d / "valid"
        (valid / "countries").mkdir(parents=True)
        (valid / "all.txt").write_text(
            "1.1.1.1:443#US-100ms\n"
            "2.2.2.2:443#US-50ms\n"
            "3.3.3.3:443#ALL\n"
            "garbage-line\n",
            encoding="utf-8",
        )
        removed = reconcile_views(valid)
        self.assertEqual(removed, 0)
        self.assertEqual(
            (valid / "countries" / "US" / "all.txt").read_text(
                encoding="utf-8"),
            "2.2.2.2:443#US-50ms\n1.1.1.1:443#US-100ms\n",
        )
        # 幂等：再跑一次无新增无删除
        self.assertEqual(reconcile_views(valid), 0)
        self.assertEqual(
            (valid / "countries" / "US" / "all.txt").read_text(
                encoding="utf-8"),
            "2.2.2.2:443#US-50ms\n1.1.1.1:443#US-100ms\n",
        )


class TestRepMapContract(unittest.TestCase):
    """R276：生产—消费键契约——`reputation.json → {key: score}` 映射
    只收有分条目，无分/垃圾条目静默跳过（quality_check 生产键
    score/risk/source/sources/flags/numeric，下游仅取 score）。"""

    def test_build_rep_map_skips_scoreless(self):
        data = {"proxies": {
            "1.2.3.4:443#US": {"score": 88, "risk": "low",
                               "sources": ["dnsbl"], "flags": ["listed"],
                               "numeric": [70]},
            "5.6.7.8:443#JP": {"risk": "medium"},
            "6.6.6.6:443#DE": "garbage",
        }}
        self.assertEqual(_build_rep_map(data), {"1.2.3.4:443#US": 88})

    def test_build_rep_map_empty(self):
        self.assertEqual(_build_rep_map({}), {})
        self.assertEqual(_build_rep_map({"proxies": {}}), {})

    def test_build_maps_skip_garbage(self):
        """R276：同类加固——family/ip_type 映射遇垃圾条目同样跳过
        （曾与 rep_map 同病：未守卫 isinstance 即 .get 而崩溃）。"""
        fam = {"proxies": {
            "1.2.3.4:443#US": {"family": "datacenter"},
            "5.6.7.8:443#JP": "garbage",
            "6.6.6.6:443#DE": {"family": ""},
        }}
        self.assertEqual(_build_family_map(fam), {"1.2.3.4:443#US": "datacenter"})
        ipt = {"proxies": {
            "1.2.3.4:443#US": {"ip_type": "hosting"},
            "5.6.7.8:443#JP": 42,
            "6.6.6.6:443#DE": {},
        }}
        self.assertEqual(_build_ip_type_map(ipt), {"1.2.3.4:443#US": "hosting"})


if __name__ == "__main__":
    unittest.main()