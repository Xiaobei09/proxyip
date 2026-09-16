"""零第三方依赖契约回归：scripts/ 仅允许标准库与项目内模块。"""

import ast
import pathlib
import re
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


SECRET_RE = re.compile(
    r"""(?i)(api[_-]?key|apikey|access[_-]?token|bearer|auth|secret)
    \s*[:=]\s*["']?[A-Za-z0-9_\-\.]{20,}"""
)


class TestNoPlaintextSecrets(unittest.TestCase):
    """仓库 Hygiene：已跟踪源码不得含明文长密钥（防未来误提交）。"""

    def _tracked(self) -> list[pathlib.Path]:
        import subprocess

        out = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True
        ).stdout
        return [ROOT / f for f in out.splitlines() if f]

    def test_no_secret_pattern_in_source(self):
        placeholder = ("example", "your_", "xxx", "changeme", "placeholder", "tokenizer")
        hits: list[str] = []
        for path in self._tracked():
            if "/tests/" in path.as_posix() or path.suffix not in (
                ".py", ".sh", ".yml", ".yaml", ".json", ".md", ".txt",
            ):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            for m in SECRET_RE.finditer(text):
                if any(s in m.group(0) for s in placeholder):
                    continue
                hits.append(f"{path.relative_to(ROOT)}: {m.group(0)[:60]}")
        self.assertEqual(
            hits, [],
            "明文密钥疑似泄漏:\n" + "\n".join(hits),
        )


if __name__ == "__main__":
    unittest.main()