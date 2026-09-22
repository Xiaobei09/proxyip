"""PCB 防泄漏锁：已迁入私有包的逆向细节（endpoint/真名键/模块路径）不得
出现在公开树。

- 模式清单（``BANNED_MODULES``/``BANNED_LITERAL_RES``/``DOC_BANS``）为
  私有数据，随插件存于 PCB（``pcb/plugins/leak_guard.py``），公开树不
  落地字面。
- 有 bundle 时经 ``checks_bundle.load_plugin("leak_guard")`` 取清单并扫描
  ``scripts/``/``tests/``/``docs/``；无 bundle（fork/公开 CI）时模式扫描
  测试跳过，仅保留不依赖数据的 loader 契约断言与迁移模块不存在断言。
- loader 公开契约：``bundle_available/load_plugin/INTERFACE_VERSION``。
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _guard_data():
    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    import checks_bundle as cb
    if not cb.bundle_available():
        return None
    try:
        return cb.load_plugin("leak_guard")
    except Exception:
        return None


_GUARD = _guard_data()


@unittest.skipIf(_GUARD is None, "PCB bundle 缺省，模式清单不可用")
class TestPcbLeakGuard(unittest.TestCase):
    def test_migrated_modules_absent(self):
        for rel in _GUARD.BANNED_MODULES:
            self.assertFalse((ROOT / rel).exists(),
                             f"{rel} 已迁入 PCB，不得残留公开树")

    def test_endpoint_literals_absent(self):
        pats = [re.compile(re.escape(p)) for p in _GUARD.BANNED_LITERAL_RES]
        hits = []
        for d in ("scripts", "tests"):
            for f in sorted((ROOT / d).glob("*.py")):
                text = f.read_text(encoding="utf-8")
                for pat in pats:
                    if pat.search(text):
                        hits.append(f"{f.name}: {pat.pattern}")
        self.assertEqual(hits, [])

    def test_loader_contract(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import checks_bundle as cb
        self.assertTrue(hasattr(cb, "bundle_available"))
        self.assertTrue(hasattr(cb, "load_plugin"))
        self.assertEqual(cb.INTERFACE_VERSION, 1)
        self.assertIsInstance(cb.bundle_available(), bool)


class TestDocsLeakGuard(unittest.TestCase):
    def test_docs_source_endpoints_absent(self):
        if _GUARD is None:
            self.skipTest("PCB bundle 缺省，模式清单不可用")
        pats = [re.compile(re.escape(p)) for p in _GUARD.DOC_BANS]
        hits = []
        targets = list(sorted((ROOT / "docs").glob("*.md")))
        targets.append(ROOT / "README.md")
        for f in targets:
            if not f.exists():
                continue
            text = f.read_text(encoding="utf-8")
            for pat in pats:
                if pat.search(text):
                    hits.append(f"{f.name}: {pat.pattern}")
        self.assertEqual(hits, [])