"""reorg_country: exit-country re-tagging & directory migration."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import reorg_country as rc


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


if __name__ == "__main__":
    unittest.main()