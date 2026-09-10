import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from annotate_classify import reconcile_views


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
            "1.1.1.1:443#US\n",
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


if __name__ == "__main__":
    unittest.main()