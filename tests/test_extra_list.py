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

    def test_redact_url_userinfo_r161(self):
        """R161安全合规：userinfo 脱敏（正常 URL 原样，无 userinfo 不误伤）。"""
        self.assertEqual(dp._redact_url_userinfo("https://u:p@example.com/x"),
                         "https://***@example.com/x")
        self.assertEqual(dp._redact_url_userinfo("plain,https://u:p@h/x"),
                         "plain,https://***@h/x")
        self.assertEqual(dp._redact_url_userinfo("https://example.com/a@b"),
                         "https://example.com/a@b")
        self.assertEqual(dp._redact_url_userinfo("notaurl"), "notaurl")

    def test_malformed_spec_echo_redacted_r161(self):
        """R161安全合规：畸形 --extra-source 回显须脱敏（凭证不进 CI 日志）；
        未知 kind 回显同理（经 load_extras 真分支，fetch 已 mock）。"""
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
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(dp.main(
                    ["--extra-source", "https://u:p@example.com/x"]), 0)
            self.assertIn("Ignoring malformed", err.getvalue())
            self.assertIn("***@", err.getvalue())
            self.assertNotIn("u:p@", err.getvalue())
        finally:
            for p in patchers:
                p.stop()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(dp, "_fetch_extra_retry",
                               return_value=b"1.1.1.1\n"):
            with redirect_stderr(err):
                by_port, _, _ = dp.load_extras(
                    [("xmlbogus", "https://u:p@example.com/x")], timeout=1)
        self.assertEqual(by_port, {})
        self.assertIn("***@", err.getvalue())
        self.assertNotIn("u:p@", err.getvalue())

    def test_help_cross_references_list_flag_r159(self):
        """R159功能查找：关联旗标 help 须互指发现口（R143 闭环的下载侧
        对应；固定 COLUMNS 使断言宽度无关，否则窄终端会硬截长 token）。"""
        import os
        buf = io.StringIO()
        with mock.patch.dict(os.environ, {"COLUMNS": "120"}):
            with redirect_stdout(buf):
                with self.assertRaises(SystemExit):
                    dp.main(["--help"])
        self.assertGreaterEqual(buf.getvalue().count("--list-extra-sources"), 4)

    def test_extra_kinds_have_parse_branches_r158(self):
        """R158功能完整性：EXTRA kind 全有 parse_source 分支（防增源漏绑
        静默跳过；R130 绑定锁的下载侧对应）。分支集取自源码 AST（零硬编码
        双份清单），用户文档 kind（json）一并覆盖。"""
        import ast
        src = (Path(dp.__file__).read_text(encoding="utf-8"))
        tree = ast.parse(src)
        branches: set[str] = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Compare)
                    and len(node.ops) == 1
                    and isinstance(node.ops[0], ast.Eq)):
                left, right = node.left, node.comparators[0]
                if (isinstance(left, ast.Name) and left.id == "kind"
                        and isinstance(right, ast.Constant)
                        and isinstance(right.value, str)):
                    branches.add(right.value)
        used = {k for k, _ in dp.EXTRA_SOURCES}
        self.assertEqual(sorted(used - branches), [])
        self.assertIn("json", branches)
        self.assertGreaterEqual(branches, used | {"json"})


if __name__ == "__main__":
    unittest.main()
