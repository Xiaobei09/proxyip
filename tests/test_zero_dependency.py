"""零第三方依赖契约回归：scripts/ 仅允许标准库与项目内模块。"""

import ast
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

STDLIB_TOP = {
    "argparse", "ast", "asyncio", "base64", "bisect", "collections",
    "concurrent", "contextlib", "csv", "dataclasses", "datetime", "hashlib",
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


class TestDynamicImportSurface(unittest.TestCase):
    """R8：动态导入与 sys.path 必须收敛到 bundle loader（防第三方
    经字符串导入/外部路径绕过静态 import 审计）。"""

    def test_dynamic_imports_only_in_bundle_loader(self):
        offenders: list[str] = []
        for py in SCRIPTS.glob("*.py"):
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                func = node.func if isinstance(node, ast.Call) else None
                is_dyn = (
                    isinstance(func, ast.Name)
                    and func.id == "__import__"
                ) or (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "importlib"
                )
                if not is_dyn:
                    continue
                if not (py.name == "checks_bundle.py"):
                    offenders.append(f"{py.name}:{node.lineno} 动态导入")
        self.assertEqual(offenders, [],
                         "动态导入只能出现在 checks_bundle.py loader:\n"
                         + "\n".join(offenders))

    def test_syspath_no_absolute_external_literals(self):
        offenders: list[str] = []
        for py in SCRIPTS.glob("*.py"):
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Attribute)
                    and isinstance(node.func.value.value, ast.Name)
                    and node.func.value.value.id == "sys"
                    and node.func.value.attr == "path"
                    and node.func.attr in ("insert", "append")
                ):
                    continue
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(
                        arg.value, str
                    ):
                        v = arg.value
                        if v.startswith(("/", "~")) or (
                            len(v) > 2 and v[1] == ":"
                        ):
                            offenders.append(f"{py.name}:{node.lineno} {v!r}")
        self.assertEqual(offenders, [],
                         "sys.path 禁止硬编码外部绝对路径:\n"
                         + "\n".join(offenders))


CORE_FUNCS = ("write_text_if_changed",)


class TestCallSignatureGuard(unittest.TestCase):
    """R58 回归：write_text_if_changed 仅 (path, content)，杜绝悬空 kwarg。"""

    def test_write_text_if_changed_no_kwargs(self):
        offenders: list[str] = []
        for py in SCRIPTS.glob("*.py"):
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in CORE_FUNCS
                    and node.keywords
                ):
                    offenders.append(
                        f"{py.name}:{node.lineno} "
                        f"kwargs={[k.arg for k in node.keywords]}"
                    )
        self.assertEqual(
            offenders, [],
            "write_text_if_changed 不应接收 kwarg（签名仅 (path, content)）:\n"
            + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()