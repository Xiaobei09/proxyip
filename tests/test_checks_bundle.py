"""PCB 防泄漏锁：已迁入私有包的逆向细节（endpoint/真名键/模块路径）不得
出现在公开树。

- 模式清单（``BANNED_MODULES``/``BANNED_LITERAL_RES``/``DOC_BANS``）为
  私有数据，随插件存于 PCB（``pcb/plugins/leak_guard.py``），公开树不
  落地字面。
- 有 bundle 时经 ``checks_bundle.load_plugin("leak_guard")`` 取清单并扫描
  ``scripts/``/``tests/``/``docs/``；无 bundle（fork/公开 CI）时模式扫描
  测试跳过，仅保留不依赖数据的 loader 契约断言与迁移模块不存在断言。
- loader 公开契约：根目录定位/显式 require、manifest 校验、单插件与批量
  载入，以及接口版本；这些断言不依赖私有模式清单，缺包环境也必须执行。
"""
import json
import os
import re
import tempfile
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


class TestLoaderLocations(unittest.TestCase):
    """loader 定位/manifest/批量载入契约（无 PCB 也执行）。"""

    def setUp(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import checks_bundle as cb
        self.cb = cb
        self._old_root = os.environ.pop("PROXYIP_PCB_ROOT", None)
        cb._BUNDLE_DIR = None
        cb._MANIFEST = None
        self.addCleanup(self._reset)

    def _reset(self):
        self.cb._BUNDLE_DIR = None
        self.cb._MANIFEST = None
        if self._old_root is None:
            os.environ.pop("PROXYIP_PCB_ROOT", None)
        else:
            os.environ["PROXYIP_PCB_ROOT"] = self._old_root

    def test_default_and_env_override(self):
        self.assertEqual(self.cb.bundle_root(), ROOT / "pcb")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "plugins").mkdir()
            os.environ["PROXYIP_PCB_ROOT"] = str(root)
            self.cb._BUNDLE_DIR = None
            self.assertEqual(self.cb.bundle_root(), root)
            self.assertTrue(self.cb.bundle_available())
            self.assertEqual(self.cb.bundle_dir(), root)
            self.assertEqual(self.cb.require_bundle(), root)

    def test_require_missing_fails_loud(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["PROXYIP_PCB_ROOT"] = d
            self.cb._BUNDLE_DIR = None
            self.assertFalse(self.cb.bundle_available())
            self.assertEqual(self.cb.bundle_dir(), Path(d))
            with self.assertRaisesRegex(RuntimeError, "required but missing"):
                self.cb.require_bundle()

    def test_manifest_validated_and_cached(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "plugins").mkdir()
            (root / "manifest.json").write_text(json.dumps({
                "interface_version": self.cb.INTERFACE_VERSION,
                "plugins": ["sample"],
            }), encoding="utf-8")
            os.environ["PROXYIP_PCB_ROOT"] = str(root)
            self.cb._BUNDLE_DIR = None
            first = self.cb.load_manifest()
            self.assertIs(first, self.cb.load_manifest())
            (root / "manifest.json").write_text(json.dumps({
                "interface_version": self.cb.INTERFACE_VERSION + 1,
            }), encoding="utf-8")
            self.cb._MANIFEST = None
            with self.assertRaisesRegex(RuntimeError, "manifest interface"):
                self.cb.load_manifest()

    def test_batch_load_and_name_validation(self):
        import sys
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            plugins = root / "plugins"
            plugins.mkdir()
            (plugins / "_loader_sample.py").write_text(
                "PCB_INTERFACE_VERSION = 1\n", encoding="utf-8")
            os.environ["PROXYIP_PCB_ROOT"] = str(root)
            self.cb._BUNDLE_DIR = None
            loaded = self.cb.load_plugins("_loader_sample")
            self.assertEqual(loaded["_loader_sample"].PCB_INTERFACE_VERSION, 1)
            sys.modules.pop("_loader_sample", None)
            for bad in ("", "../x", "a.b", None):
                with self.subTest(bad=bad):
                    with self.assertRaises(ValueError):
                        self.cb.load_plugin(bad)


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

    def test_workflow_literals_absent(self):
        pats = [re.compile(re.escape(p)) for p in _GUARD.BANNED_LITERAL_RES]
        hits = []
        targets = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        targets += sorted((ROOT / ".github" / "scripts").glob("*.sh"))
        for f in targets:
            if not f.exists():
                continue
            text = f.read_text(encoding="utf-8")
            for pat in pats:
                if pat.search(text):
                    hits.append(f"{f.name}: {pat.pattern}")
        self.assertEqual(hits, [])

    def test_loader_contract(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import checks_bundle as cb
        for name in ("bundle_available", "bundle_root", "bundle_dir",
                     "require_bundle", "load_manifest", "load_plugin",
                     "load_plugins"):
            self.assertTrue(hasattr(cb, name), name)
        self.assertEqual(cb.INTERFACE_VERSION, 1)
        self.assertIsInstance(cb.bundle_available(), bool)


@unittest.skipIf(_GUARD is None, "PCB bundle 缺省，模式清单不可用")
class TestTrueNameForwardLeak(unittest.TestCase):
    """R91：CN 真名根不得前向泄漏进公开树（Phase A-2 改名前基线）。

    真名表与允许基线均存 PCB（经 loader 获取），本文件零真名字面。
    扫描整词（大小写不敏感）；命中行须匹配同文件的允许模式，
    否则即新增泄漏。允许项仅覆盖已评估类别（CLI 凭证契约/信誉
    规范名/接入实证史/legacy 旗标）；新文件中的真名一律不豁免。
    """

    def _metadata_roots(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import checks_bundle as cb
        try:
            meta = cb.load_plugin("_metadata")
        except Exception:
            self.skipTest("PCB _metadata 不可用")
        return meta.true_roots()

    def test_true_roots_absent_except_allowlisted(self):
        roots = self._metadata_roots()
        word = [re.compile(r"(?<![A-Za-z0-9_])" + re.escape(r) +
                           r"(?![A-Za-z0-9_])", re.IGNORECASE)
                for r in roots]
        allow = [(sfx, re.compile(pat))
                 for sfx, pat in _GUARD.TRUE_ROOT_PUBLIC_ALLOW]
        targets = []
        for d in ("scripts", "tests"):
            targets += sorted((ROOT / d).glob("*.py"))
        targets += sorted((ROOT / "docs").glob("*.md"))
        targets.append(ROOT / "README.md")
        targets += sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        targets += sorted((ROOT / ".github" / "scripts").glob("*.sh"))
        bad = []
        for f in targets:
            if not f.exists():
                continue
            rel = f.relative_to(ROOT).as_posix()
            pats = [p for sfx, p in allow if rel == sfx]
            for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(),
                                     1):
                if any(rx.search(line) for rx in word):
                    if not any(p.search(line) for p in pats):
                        bad.append(f"{rel}:{i}: {line.strip()[:100]}")
        self.assertEqual(bad, [])


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