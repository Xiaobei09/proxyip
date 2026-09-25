"""--list-extra-sources 发现功能测试（R156 可发现性，对标 R100/R142）。

内置补充来源 E2 后迁 PCB，公开侧无清单可见性；本 flag 恢复发现口。
动态读 loader 回绑（零硬编码）；无包 fail-open 返回 2。
"""
import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import download_proxies as dp


class TestListExtraSources(unittest.TestCase):
    def test_bundled_lists_origins(self):
        if not dp.EXTRA_SOURCES:
            self.skipTest("needs PCB dl_sources bundle")
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(dp.main(["--list-extra-sources"]), 0)
        lines = buf.getvalue().splitlines()
        self.assertEqual(lines[0], "origin")
        self.assertEqual(lines[1:], dp.extra_source_origins())
        self.assertGreater(len(lines), 1)

    def test_unbundled_returns_two(self):
        with mock.patch.object(dp, "EXTRA_SOURCES", []):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(dp.main(["--list-extra-sources"]), 2)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("PCB bundle missing", err.getvalue())

    def test_warns_when_builtin_empty_r157(self):
        """R157用户侧体验：无包内置为空时 stderr warn（静默降级可见），
        显式 --no-extra-sources 时保持静默（用户意图明确）。"""
        patchers = [
            mock.patch.object(
                dp, "load_source",
                return_value=({"443": {"US": ["1.1.1.1"]}}, None),
            ),
            mock.patch.object(dp, "load_extras", return_value=({}, set(), {})),
            mock.patch.object(dp, "enrich_countries", return_value=0),
            mock.patch.object(dp, "write_outputs", return_value=(
                {"__total__": 1, "__unique__": 1, "__countries__": 1,
                 "__ports__": 1, "__sets__": {}, "443": 1},
                ["1.1.1.1:443#US"],
            )),
            mock.patch.object(dp, "write_source_attribution"),
            mock.patch.object(dp, "_append_source_history"),
            mock.patch.object(dp, "_build_source_stats", return_value={}),
            mock.patch.object(dp, "write_text_if_changed"),
            mock.patch.object(dp, "load_previous_all", return_value=[]),
            mock.patch.object(dp, "write_diff", return_value=(0, 0)),
            mock.patch.object(dp, "append_history"),
            mock.patch.object(dp, "print_stats"),
            mock.patch.object(dp, "write_upstream_meta"),
        ]
        for p in patchers:
            p.start()
        try:
            with mock.patch.object(dp, "EXTRA_SOURCES", []):
                err = io.StringIO()
                with redirect_stderr(err):
                    self.assertEqual(dp.main([]), 0)
                self.assertIn("PCB bundle missing", err.getvalue())
                self.assertIn("--list-extra-sources", err.getvalue())
                err2 = io.StringIO()
                with redirect_stderr(err2):
                    self.assertEqual(dp.main(["--no-extra-sources"]), 0)
                self.assertNotIn("Warning", err2.getvalue())
        finally:
            for p in patchers:
                p.stop()

    def test_help_mentions_flag(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                dp.main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("--list-extra-sources", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
