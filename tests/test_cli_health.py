"""Every scripts/*.py entrypoint must exit 0 on ``--help`` (argparse intact)."""
import ast
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = sorted(ROOT.glob("scripts/*.py"))


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
                proc = subprocess.run(
                    [sys.executable, str(script), "--help"],
                    capture_output=True,
                    text=True,
                    timeout=90,
                )
                self.assertEqual(
                    proc.returncode,
                    0,
                    f"{script.name} --help failed:\n"
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


if __name__ == "__main__":
    unittest.main()