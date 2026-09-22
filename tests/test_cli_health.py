"""Every CLI scripts/*.py must exit 0 on ``--help``；库模块（common.py）须带提示以非零码退出。"""
import ast
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import annotate_classify
import build_good
import build_premium
import export_json
import generate_stats

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = sorted(ROOT.glob("scripts/*.py"))
LIBRARY_MODULES = {"common.py"}  # 无 CLI、`__main__` 守卫以退出码 2 提示


class _TopLevelPrint(ast.NodeVisitor):
    """只在模块顶层（不在函数/类体内）找到 print 调用。"""
    def __init__(self) -> None:
        self.found: list[tuple[int, str]] = []

    def visit_Module(self, node: ast.Module) -> None:
        for stmt in node.body:
            expr = stmt.value if isinstance(stmt, ast.Expr) else None
            if isinstance(expr, ast.Call) and isinstance(
                expr.func, ast.Name
            ) and expr.func.id == "print":
                self.found.append((stmt.lineno or 0, "print"))
        self.generic_visit(node)


class TestCliHealth(unittest.TestCase):
    def test_every_script_parses_help(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                want = 2 if script.name in LIBRARY_MODULES else 0
                proc = subprocess.run(
                    [sys.executable, str(script), "--help"],
                    capture_output=True,
                    text=True,
                    timeout=90,
                )
                self.assertEqual(
                    proc.returncode,
                    want,
                    f"{script.name} --help wrong exit (want {want}):\n"
                    f"STDOUT: {proc.stdout[-400:]}\n"
                    f"STDERR: {proc.stderr[-400:]}",
                )

    def test_no_script_prints_at_import_time(self):
        for script in SCRIPTS:
            src = script.read_text(encoding="utf-8")
            visitor = _TopLevelPrint()
            visitor.visit(ast.parse(src))
            self.assertEqual(
                visitor.found, [],
                f"{script.name} prints at import time: {visitor.found}",
            )

    def test_quality_help_has_no_stale_source_enum(self):
        """R278：CLI 帮助不得硬编码信誉源清单（R270 whatismyip 退默认后
        quality_check docstring 枚举过期无人发现；R277 默认集已修，此处
        锁帮助文本）。帮助应指向常量/文档表，而非点名。"""
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "quality_check.py"),
             "--help"],
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertEqual(proc.returncode, 0)
        out = proc.stdout
        self.assertNotIn("whatismyip", out)
        self.assertNotRegex(out, r"— ?\d+ 源")

    def test_china_help_has_no_stale_source_enum(self):
        """CN-09：china_check 帮助不再硬编码过期源枚举（曾缺十余新源），
        与 quality_check 同病（R278）。
        帮助应指向参数表/文档/CI，不再点名。"""
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "china_check.py"),
             "--help"],
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertEqual(proc.returncode, 0)
        out = proc.stdout
        self.assertIn("--cn-limit", out)

    def test_china_help_flags_match_docs(self):
        """R7：china_check --help 与 docs/scripts.md 表格双向对等
        （flag-day 后只剩 generic＋基础旗标；防单边漂移）。"""
        import re
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "china_check.py"),
             "--help"],
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertEqual(proc.returncode, 0)
        help_flags = set(re.findall(r"--[a-z0-9-]+", proc.stdout))
        lines = (ROOT / "docs" / "scripts.md").read_text(
            encoding="utf-8").split("\n")
        start = next(i for i, l in enumerate(lines)
                     if l.startswith("### `scripts/china_check.py`"))
        end = next(i for i, l in enumerate(lines)
                   if l.startswith("### `scripts/exit_family.py`"))
        doc_flags = set(re.findall(r"--[a-z0-9-]+",
                                   "\n".join(lines[start:end])))
        self.assertEqual(help_flags - {"--help"}, doc_flags - {"---"})

    def test_missing_data_dir_degrades_gracefully(self):
        """R286：缺输入目录时各链脚本须优雅降级（空映射/skip 文案、
        返回 0、无 traceback），不得把空数据当硬失败掀翻 CI。"""
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(
                annotate_classify.main(["--data-dir", d]), 0)
            self.assertEqual(
                build_good.main(["--data-dir", d]), 0)
            self.assertEqual(
                build_premium.main(["--data-dir", d]), 0)
            self.assertEqual(
                export_json.main(["--data-dir", d]), 0)
            self.assertEqual(
                generate_stats.main(
                    ["--data-dir", d, "--out", f"{d}/out"]), 0)


if __name__ == "__main__":
    unittest.main()