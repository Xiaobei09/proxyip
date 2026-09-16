"""零第三方依赖契约回归：scripts/ 仅允许标准库与项目内模块。"""

import ast
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

STDLIB_TOP = {
    "argparse", "ast", "asyncio", "base64", "bisect", "collections",
    "concurrent", "contextlib", "dataclasses", "datetime", "hashlib",
    "http", "io", "ipaddress", "json", "logging", "math", "os", "pathlib",
    "random", "re", "shutil", "socket", "ssl", "statistics", "struct",
    "subprocess", "sys", "tempfile", "threading", "time", "traceback",
    "unittest", "urllib", "xml", "zipfile", "__future__",
}


class TestZeroDependencyContract(unittest.TestCase):
    def test_all_script_imports_are_stdlib_or_local(self):
        offenders: list[str] = []
        for py in SCRIPTS.glob("*.py"):
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mods = [node.module] if node.module else []
                else:
                    continue
                for m in mods:
                    top = m.split(".", 1)[0]
                    if top not in STDLIB_TOP and top not in {
                        p.stem for p in SCRIPTS.glob("*.py")
                    }:
                        offenders.append(f"{py.name}: import {m}")
        self.assertEqual(offenders, [], "第三方依赖泄漏:\n" + "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()