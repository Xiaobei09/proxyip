"""reorg_country: exit-country re-tagging & directory migration."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import reorg_country as rc
from common import parse_ltd_line, read_exit_region


class TestMarker(unittest.TestCase):
    def test_inserts_marker(self):
        self.assertEqual(
            rc.ensure_exit_marker("1.1.1.1:443#US", "DE"),
            "1.1.1.1:443#US→DE",
        )

    def test_replaces_stale_marker(self):
        self.assertEqual(
            rc.ensure_exit_marker("1.1.1.1:443#US→FR", "DE"),
            "1.1.1.1:443#US→DE",
        )

    def test_keeps_suffixes(self):
        self.assertEqual(
            rc.ensure_exit_marker("1.1.1.1:443#US→FR-OK", "DE"),
            "1.1.1.1:443#US→DE-OK",
        )

    def test_rejects_skip_via_size(self):
        # 空 exit 国度原样返回
        self.assertEqual(
            rc.ensure_exit_marker("1.1.1.1:443#US", ""),
            "1.1.1.1:443#US",
        )


class TestPathHelpers(unittest.TestCase):
    def test_path_country(self):
        self.assertEqual(
            rc._path_country(Path("data/valid/countries/US/all.txt")), "US"
        )
        self.assertIsNone(
            rc._path_country(Path("data/valid/sets/asia/all.txt"))
        )
        self.assertIsNone(rc._path_country(Path("data/valid/ports/443.txt")))
        self.assertIsNone(
            rc._path_country(Path("data/valid/countries/ZZXY/all.txt"))
        )

    def test_target_path(self):
        self.assertEqual(
            rc._target_path(Path("data/valid/countries/US/all.txt"), "DE"),
            Path("data/valid/countries/DE/all.txt"),
        )
        self.assertEqual(
            rc._target_path(Path("data/valid/sets/asia/all.txt"), "DE"),
            Path("data/valid/sets/asia/all.txt"),
        )


def test_moves_preserve_latency_order(self):
        """移入目标文件的行按延迟升序并入，不再破坏保序契约。"""
        us = self.country_dir / "US" / "all.txt"
        de = self.country_dir / "DE" / "all.txt"
        # DE 已有两行：20ms 与 80ms；US 移入 50ms
        self._write("valid/countries/DE/all.txt",
                    ["10.0.0.1:443#DE-20ms", "10.0.0.2:443#DE-80ms"])
        self._write("valid/countries/US/all.txt",
                    ["1.1.1.1:443#US-120ms", "2.2.2.2:443#US"])
        stats = {"moved": 0, "files_written": 0}
        rc.reorganize_file(us, {"2.2.2.2:443#US": "DE"}, stats)
        self.assertEqual(
            self._read("valid/countries/DE/all.txt"),
            ["10.0.0.1:443#DE-20ms", "2.2.2.2:443#US→DE", "10.0.0.2:443#DE-80ms"],
        )
        self.assertEqual(stats["moved"], 1)


class TestReorganizeFile(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="reorg_"))
        self.country_dir = self.tmp / "valid" / "countries"
        self.sets_dir = self.tmp / "valid" / "sets"
        self.ports_dir = self.tmp / "valid" / "ports"
        self.country_dir.mkdir(parents=True)
        self.sets_dir.mkdir(parents=True)
        self.ports_dir.mkdir(parents=True)

    def _write(self, rel, lines):
        p = self.tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("".join(f"{l}\n" for l in lines))

    def _read(self, rel):
        p = self.tmp / rel
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    def test_moves_to_exit_country(self):
        us = self.country_dir / "US" / "all.txt"
        self._write("valid/countries/US/all.txt",
                    ["1.1.1.1:443#US", "2.2.2.2:443#US"])
        stats = {"moved": 0, "files_written": 0}
        rc.reorganize_file(
            us, {"1.1.1.1:443#US": "US", "2.2.2.2:443#US": "DE"}, stats
        )
        self.assertEqual(self._read("valid/countries/US/all.txt"),
                         ["1.1.1.1:443#US→US"])
        self.assertEqual(self._read("valid/countries/DE/all.txt"),
                         ["2.2.2.2:443#US→DE"])
        self.assertEqual(stats["moved"], 1)

    def test_sets_file_marked_not_moved(self):
        asia = self.sets_dir / "asia" / "all.txt"
        self._write("valid/sets/asia/all.txt", ["1.1.1.1:443#US"])
        stats = {"moved": 0, "files_written": 0}
        rc.reorganize_file(
            asia, {"1.1.1.1:443#US": "DE"}, stats
        )
        self.assertEqual(self._read("valid/sets/asia/all.txt"),
                         ["1.1.1.1:443#US→DE"])
        self.assertEqual(stats["moved"], 0)

    def test_idempotent_rerun(self):
        us = self.country_dir / "US" / "all.txt"
        self._write("valid/countries/US/all.txt", ["1.1.1.1:443#US"])
        stats = {"moved": 0, "files_written": 0}
        rc.reorganize_file(us, {"1.1.1.1:443#US": "US"}, stats)
        rc.reorganize_file(us, {"1.1.1.1:443#US": "US"}, stats)
        self.assertEqual(self._read("valid/countries/US/all.txt"),
                         ["1.1.1.1:443#US→US"])
        self.assertEqual(stats["files_written"], 1)

    def test_unknown_key_untouched(self):
        us = self.country_dir / "US" / "all.txt"
        self._write("valid/countries/US/all.txt", ["1.1.1.1:443#US"])
        stats = {"moved": 0, "files_written": 0}
        rc.reorganize_file(us, {"9.9.9.9:443#US": "DE"}, stats)
        self.assertEqual(self._read("valid/countries/US/all.txt"),
                         ["1.1.1.1:443#US"])
        self.assertEqual(stats["files_written"], 0)

    def test_missing_file_noop(self):
        stats = {"moved": 0, "files_written": 0}
        rc.reorganize_file(self.country_dir / "ZZ" / "all.txt", {}, stats)

    def test_all_moved_out_unlinks_source(self):
        # 出口观测覆盖全文件 → 源文件清空不落盘，不留 0 字节残留
        us = self.country_dir / "US" / "all.txt"
        self._write("valid/countries/US/all.txt",
                    ["1.1.1.1:443#US", "2.2.2.2:443#US"])
        stats = {"moved": 0, "files_written": 0}
        rc.reorganize_file(
            us, {"1.1.1.1:443#US": "DE", "2.2.2.2:443#US": "DE"}, stats
        )
        self.assertFalse(us.exists())
        self.assertEqual(self._read("valid/countries/DE/all.txt"),
                         ["1.1.1.1:443#US→DE", "2.2.2.2:443#US→DE"])
        self.assertEqual(stats["moved"], 2)

    def test_prune_orphan_dir_with_stale_subgroups(self):
        # 全迁走后目录残留 cn/rep 等分支文件且无 all.txt → 整个目录清理
        self._write("valid/countries/SC/all.txt",
                    ["5.157.30.18:8443#SC→IE"])
        self._write("valid/countries/SC/rep.txt", ["5.157.30.18:8443#SC-50"])
        self._write("valid/countries/US/all.txt", ["1.1.1.1:443#US"])
        # 场景 A：SC 的 all.txt 已被 reorg 删除（仅剩陈旧分支文件）→ 剪除
        (self.country_dir / "SC" / "all.txt").unlink()
        self.assertEqual(rc._prune_orphan_country_dirs(self.tmp / "valid"), 1)
        self.assertFalse((self.country_dir / "SC").exists())
        # 场景 B：有 all.txt 的合法国家目录保留
        self.assertEqual(rc._prune_orphan_country_dirs(self.tmp / "valid"), 0)
        self.assertTrue((self.country_dir / "US" / "all.txt").exists())


class TestMergeOrdered(unittest.TestCase):
    def test_inserts_by_latency_keeps_relative_order(self):
        existing = "1.1.1.1:443#US-10ms\n2.2.2.2:443#US-50ms\n9.9.9.9:443#US"
        new = ["8.8.8.8:443#US-5ms", "3.3.3.3:443#US-30ms"]
        self.assertEqual(
            rc._merge_ordered(existing, new),
            "8.8.8.8:443#US-5ms\n1.1.1.1:443#US-10ms\n"
            "3.3.3.3:443#US-30ms\n2.2.2.2:443#US-50ms\n9.9.9.9:443#US\n",
        )

    def test_no_latency_lines_sort_last_stable(self):
        existing = "5.5.5.5:443#US-1ms\n6.6.6.6:443#US"
        out = rc._merge_ordered(existing, ["7.7.7.7:443#US"])
        self.assertEqual(
            out,
            "5.5.5.5:443#US-1ms\n6.6.6.6:443#US\n7.7.7.7:443#US\n",
        )

    def test_empty_existing(self):
        self.assertEqual(rc._merge_ordered("", ["1.1.1.1:443#US-5ms"]),
                         "1.1.1.1:443#US-5ms\n")


class TestReorgCountryConsistency(unittest.TestCase):
    """回归守护：``countries/*/all.txt`` 的端点集必须与 ``valid/all.txt`` 的端点集
    一致（剔除 ``#ALL`` 哨兵；键 = ``ip:port``，R177/R231）。

    按**端点键集**而非原始行数断言：同一端点可因不同入口国标注出现在多个国家目录
    （``dup_endpoints``，data-spec 允许的告警、非漂移），若按行数比较，这类合法重复
    以及并发提交（update/quality/exit 三条链交叉 commit）带来的瞬时行数偏移会误报。
    端点集一致才等价于「无代理在分目录中丢失 / 无越界残留」。

    ``#ALL``（入口未知）依 data-spec 只出现在 ``all.txt``/``all_ltd.txt``、不进入
    ``countries/``。本地无数据文件则跳过。"""

    def _valid(self):
        return Path(__file__).resolve().parent.parent / "data" / "valid"

    @staticmethod
    def _keys(lines):
        keys = set()
        for ln in lines:
            if not ln:
                continue
            parsed = parse_ltd_line(ln)
            if parsed and parsed[3] == "ALL":
                continue
            keys.add(ln.split("#", 1)[0])
        return keys

    def test_country_dir_matches_exit_region_r243(self):
        """R243：``countries/<CC>/all.txt`` 里每一行的**出口国**必须就是 ``<CC>``。

        这条不变量被违反时，两个流水线阶段会**互相撤销对方的产出**：

        - ``reorg_country`` 按 docstring 首行的成文契约「按**出口** IP 国家重组」，
          把 ``#<入口>→<出口>`` 里出口≠入口的行迁到出口国目录，并把迁空后的
          目录整棵剪掉（报 ``pruned N orphan country dirs``）；
        - ``annotate_classify.reconcile_views`` 的国家回填原按
          ``parse_ltd_line(...)[3]`` 分组，而它取标注里**第一个** CC —— 即
          **入口**国 —— 于是又把它们填回入口国目录。

        实测症状（``countries/CO``）：3 行 ``#🇨🇴CO→US-…`` 被 reorg 按出口迁到
        ``countries/US/`` 并把空掉的 CO 目录整棵剪掉，下一轮回填又按入口填回
        CO —— **两阶段互相撤销对方的产出**，每次跑批重写数十个文件，
        ``test_no_orphan_dirs`` 常驻红。只在**入口≠出口**（多出口 IP）时暴露，
        故长期被当成「偶发噪声」。

        断言刻意**只针对回填行为**、不扫描已提交数据：同一端点同时出现在多个
        国家目录是 data-spec **允许**的（``dup_endpoints`` 告警、非漂移），
        数据面已有大量此类行，拿它当判据会既误报又判别不了本 bug。
        """
        import tempfile

        import annotate_classify as ac

        # 入口 CO、出口 US 的一行；reorg 已把它放进 countries/US/
        line = ("1.2.3.4:443#\U0001F1E8\U0001F1F4CO\u2192US-100ms-1MB/s-DC-mid"
                "-V4-CN-50-U100")
        key = "1.2.3.4:443"
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            (valid / "countries" / "US").mkdir(parents=True)
            (valid / "all.txt").write_text(line + "\n", encoding="utf-8")
            (valid / "countries" / "US" / "all.txt").write_text(
                line + "\n", encoding="utf-8")
            ac.reconcile_views(valid)
            co = valid / "countries" / "CO" / "all.txt"
            got = co.read_text(encoding="utf-8") if co.exists() else ""
        self.assertNotIn(
            key, got,
            "国家回填按**入口**国分组——与 reorg_country「按出口国重组」的"
            "成文契约冲突，两阶段会互相撤销产出（多出口 IP 上必现）")

    def test_backfill_uses_exit_region_when_present_r243(self):
        """R243：正向锁——出口国与入口国不同时，回填的目标目录是**出口国**。"""
        import tempfile

        import annotate_classify as ac

        line = ("5.6.7.8:443#\U0001F1E7\U0001F1F7BR\u2192NL-200ms-2MB/s-RES-mid"
                "-V4-CN-40-U100")
        with tempfile.TemporaryDirectory() as tmp:
            valid = Path(tmp) / "valid"
            valid.mkdir(parents=True)
            (valid / "all.txt").write_text(line + "\n", encoding="utf-8")
            ac.reconcile_views(valid)
            nl = valid / "countries" / "NL" / "all.txt"
            br = valid / "countries" / "BR" / "all.txt"
            self.assertTrue(
                nl.exists() and "5.6.7.8:443" in nl.read_text(encoding="utf-8"),
                "回填未把行放进出口国目录 NL")
            self.assertFalse(
                br.exists(),
                "回填把行放进了**入口**国目录 BR")

    def test_sum_equals_all_txt(self):
        all_path = self._valid() / "all.txt"
        if not all_path.exists():
            self.skipTest("no data/valid/all.txt")
        master = self._keys(all_path.read_text(encoding="utf-8").splitlines())
        cdir = self._valid() / "countries"
        if not cdir.exists():
            self.skipTest("no data/valid/countries")
        seen = set()
        for d in sorted(cdir.iterdir()):
            f = d / "all.txt"
            if d.is_dir() and f.exists():
                seen |= self._keys(f.read_text(encoding="utf-8").splitlines())
        missing = sorted(master - seen)
        excess = sorted(seen - master)
        self.assertEqual(
            missing, [],
            f"endpoints in all.txt missing from countries: {missing[:5]}",
        )
        self.assertEqual(
            excess, [],
            f"endpoints in countries not in all.txt: {excess[:5]}",
        )

    def test_no_orphan_dirs(self):
        cdir = self._valid() / "countries"
        if not cdir.exists():
            self.skipTest("no data/valid/countries")
        orphan_dirs = sorted(
            d.name for d in cdir.iterdir()
            if d.is_dir() and not (d / "all.txt").exists()
        )
        self.assertEqual(orphan_dirs, [], f"orphan country dirs (no all.txt): {orphan_dirs}")

    def test_no_orphan_set_dirs(self):
        """R301：sets/ 分裂目录同样不得孤儿化（R300 CO 孤儿致两链门禁
        连带失败；sets/ 同理设防；ports/ 为扁平文件无目录形态）。"""
        sdir = self._valid() / "sets"
        if not sdir.exists():
            self.skipTest("no data/valid/sets")
        orphan_dirs = sorted(
            d.name for d in sdir.iterdir()
            if d.is_dir() and not (d / "all.txt").exists()
        )
        self.assertEqual(orphan_dirs, [], f"orphan set dirs (no all.txt): {orphan_dirs}")

    def test_sets_ports_no_excess_vs_master(self):
        """R294：sets/ports 分裂不得有 master 之外的越界残留。

        R289 死锁复盘的姊妹不变量：countries/ 有 missing＋excess 双检，
        sets/ports 只有“子集性”是设计内（精选集合），但 excess（越界）
        永为漂移。本地无数据文件则跳过。"""
        all_path = self._valid() / "all.txt"
        if not all_path.exists():
            self.skipTest("no data/valid/all.txt")
        master = self._keys(all_path.read_text(encoding="utf-8").splitlines())
        for sub, glob in (("sets", "*/all.txt"), ("ports", "*.txt")):
            d = self._valid() / sub
            if not d.exists():
                continue
            seen = set()
            for f in sorted(d.glob(glob)):
                seen |= self._keys(f.read_text(encoding="utf-8").splitlines())
            excess = sorted(seen - master)
            self.assertEqual(
                excess, [],
                f"endpoints in {sub} not in all.txt: {excess[:5]}",
            )


if __name__ == "__main__":
    unittest.main()