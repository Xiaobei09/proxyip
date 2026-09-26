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
    命中行须匹配同文件的允许模式，否则即新增泄漏。允许项仅覆盖已
    评估类别（CLI 凭证契约/信誉规范名）；新文件中的真名一律不豁免。

    R217：扫描从「整词边界」升级为「标识符分段」。原正则
    ``(?<![A-Za-z0-9_])root(?![A-Za-z0-9_])`` 对 CamelCase 内嵌
    完全失明——真名夹在 ``Test<真名>PingSource`` 这类标识符里时，
    两侧都是字母，前后顾双双失败，故 20 个真名测试类长期零告警地
    留在公开树。现改为先把标识符按大小写/下划线切成子段再整段比对，
    既能命中内嵌真名，又不会像裸子串匹配那样把 ``ping``/``ip`` 之类
    通用词打成一片误报。本文件自身零真名字面（举例外一律用合成词）。
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

    @staticmethod
    def _segments(text: str) -> set:
        """整词 + CamelCase 子段（小写集合）。"""
        out = set()
        for word in re.findall(r"[A-Za-z0-9]+", text):
            out.add(word.lower())
            for part in re.findall(
                    r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", word):
                out.add(part.lower())
        return out

    def _targets(self):
        targets = []
        for d in ("scripts", "tests"):
            targets += sorted((ROOT / d).glob("*.py"))
        targets += sorted((ROOT / "docs").glob("*.md"))
        targets.append(ROOT / "README.md")
        targets += sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        targets += sorted((ROOT / ".github" / "scripts").glob("*.sh"))
        return [f for f in targets if f.exists()]

    def test_true_roots_absent_except_allowlisted(self):
        roots = {r.lower() for r in self._metadata_roots()}
        allow = [(sfx, re.compile(pat))
                 for sfx, pat in _GUARD.TRUE_ROOT_PUBLIC_ALLOW]
        bad = []
        for f in self._targets():
            rel = f.relative_to(ROOT).as_posix()
            pats = [p for sfx, p in allow if rel == sfx]
            for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(),
                                     1):
                hit = self._segments(line) & roots
                if hit and not any(p.search(line) for p in pats):
                    bad.append(f"{rel}:{i}: {sorted(hit)} {line.strip()[:80]}")
        self.assertEqual(bad, [])

    def test_camelcase_segmentation_is_not_blind(self):
        """R217 自证：分段扫描必须能命中 CamelCase 内嵌真名。

        真名表来自 PCB，本文件零真名字面，故用一条**结构等价**的
        合成根（自造词，非任何真实来源）验证分段逻辑本身有效——
        若哪天分段退化成整词匹配，此用例即红。
        """
        probe = "Synthetic" + "Probe"
        segs = self._segments(f"class Test{probe}Thing(unittest.TestCase):")
        self.assertIn("synthetic", segs)
        self.assertIn("probe", segs)
        # 旧式整词边界对同一输入看不见内嵌子段（记录被替换的盲区）
        legacy = re.compile(r"(?<![A-Za-z0-9_])synthetic(?![A-Za-z0-9_])",
                            re.IGNORECASE)
        self.assertIsNone(legacy.search(f"class Test{probe}Thing:"))


@unittest.skipIf(_GUARD is None, "PCB bundle 缺省，模式清单不可用")
class TestDownloadVendorNamesAbsent(unittest.TestCase):
    """R230：下载来源**厂商名**不得出现在公开树（安全合规 / 私有源隔离）。

    事故链：R227 查出已发布产物以厂商短标签为键 → R229 把键空间换成不透明
    ``dsrc_*`` id；但公开侧的**注释与 docstring** 同样点名厂商（实测 99 处
    跨 9 文件）——键空间改了、散文没改，泄漏照旧。R227 当时**刻意没加**门禁，
    理由是黑名单判据不可靠（PCB 三张表互不覆盖，实测漏 6/13 个键，会给假
    信心）。本轮补上那个**可靠判据**：厂商集合由私有包
    ``leak_guard.download_vendor_tokens()`` 从三张表权威派生，公开树零字面。

    存量（测试数据与功能性契约名）以**计数棘轮**表达：只许下降，不许上升。
    方向感知双向断言：高于基线 = 出现新增泄漏；低于基线 = 该下调基线。
    """

    #: 各文件允许的厂商名命中行数上限（棘轮，只降不升）。
    BASELINES = {
        "tests/test_quality.py": 25,
        "scripts/quality_reputation.py": 18,
        "tests/test_download.py": 3,
        "tests/test_validate.py": 9,
        "docs/data-spec.md": 2,
        "docs/scripts.md": 0,
        "docs/logic.md": 0,
        "scripts/validate_proxies.py": 1,
    }

    ROOT = Path(__file__).resolve().parent.parent

    @staticmethod
    def _tokens():
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                               / "scripts"))
        import checks_bundle as cb
        try:
            return {t.lower() for t in cb.load_plugin("leak_guard")
                    .download_vendor_tokens()}
        except Exception:
            return None

    def _targets(self):
        out = []
        for d in ("scripts", "tests"):
            out += sorted((self.ROOT / d).glob("*.py"))
        out += sorted((self.ROOT / "docs").glob("*.md"))
        out += [self.ROOT / "README.md"]
        return [f for f in out if f.exists()]

    def test_download_vendor_names_absent_or_ratcheted_down(self):
        tokens = self._tokens()
        if tokens is None:
            self.skipTest("私有 leak_guard 不可得：无法派生厂商集，跳过（fail-open）")
        pats = [re.compile(r"(?<![A-Za-z0-9])" + re.escape(t) +
                           r"(?![A-Za-z0-9])", re.IGNORECASE)
                for t in sorted(tokens)]
        counts = {}
        for f in self._targets():
            rel = f.relative_to(self.ROOT).as_posix()
            n = sum(1 for line in f.read_text(encoding="utf-8").splitlines()
                    if any(p.search(line) for p in pats))
            if n:
                counts[rel] = n
        base = self.BASELINES
        for rel, n in sorted(counts.items()):
            with self.subTest(file=rel):
                if n > base.get(rel, 0):
                    self.fail(
                        f"{rel}：厂商名命中 {n} 行 > 棘轮基线 "
                        f"{base.get(rel, 0)}——**出现新增泄漏**。键空间已换"
                        "不透明 id，注释/docstring 里的厂商点名必须一并去身份")
        for rel, b in base.items():
            if counts.get(rel, 0) < b:
                with self.subTest(file=rel):
                    self.fail(
                        f"{rel}：厂商名命中降至 {counts.get(rel, 0)}"
                        f"（基线 {b}）——**该下调 BASELINES**")

    def test_baselines_not_raised(self):
        floor = {
            "tests/test_quality.py": 25,
            "scripts/quality_reputation.py": 18,
            "tests/test_download.py": 3,
            "tests/test_validate.py": 9,
            "docs/data-spec.md": 2,
            "docs/scripts.md": 0,
            "docs/logic.md": 0,
            "scripts/validate_proxies.py": 1,
        }
        for rel, b in self.BASELINES.items():
            with self.subTest(file=rel):
                self.assertLessEqual(b, floor[rel],
                                     f"{rel} 基线只允许下降")


@unittest.skipIf(_GUARD is None, "PCB bundle 缺省，模式清单不可用")
class TestReputationSourceNamesDeidentified(unittest.TestCase):
    """R233：信誉数据源**真名**不得留在已发布 data/ 里（安全合规 / 私有源隔离）。

    实测规模（按权威词表 62 项逐词统计）：**1067304 处**，横跨 7 个文件——
    ``reputation_cache.json`` 407227（每 IP 字典以**源名为键**）、
    ``ipinfo.json`` 323371、``reputation.json`` 310770、
    ``data/valid/reputation_cache.json`` 19871、
    ``data/valid/reputation.json`` 6054（此二项已于 R238 查明为孤儿产物并删除）、
    ``external_check.json`` 8、
    ``upstream_meta.json`` 3。这是本轮实测中**最大的一处泄漏面**。

    公开侧代码早已把三表迁入 PCB（公开树零字面），但真名是**运行时从私有包
    流进公开 data/** 的——与 R227 记录的「已发布产物以真名为键」同族。

    门禁采用**结构化解析**而非文本扫描：2.1MB 级正则全文扫描实测 36s（不可
    接受），而 ``json.load`` 只要 2.2s 且精确（曾试图用引号计数替代，两口径
    实测不一致——``abuse`` 24230、``static`` 2 处对不上，已弃用）。

    存量以**计数棘轮**表达：只许下降，不许上升；方向感知双向断言。

    **R237 收尾**：``quality-check`` 带本轮去身份跑完（2026-09-26T10:12Z）后，
    ``reputation_cache.json``（360826 → **0**）、``ipinfo.json``
    （320824 → **0**）、``reputation.json``（308225 → **0**）全部归零，
    连同 ``external_check`` / ``upstream_meta`` 共 5 个文件清零——即本族在
    ``data/quality/`` 下已彻底迁移完毕。

    **R238** 补清最后两项：``data/valid/reputation{,_cache}.json``（14963+6054）
    经查是 **R452 脱敏压squash（2026-09-21）的孤儿产物**——**无任何脚本产出、
    无任何脚本消费**（``data/valid/`` 下的 glob 只扫 ``*.txt``），且是
    ``data/quality/`` 同名文件的**陈旧副本**（2454 / 905 条 vs 22662 / 17342 条）。
    故直接删除而非迁移：当前数据在 ``data/quality/`` 且已去身份，删除不丢信息。
    另加 ``test_orphan_valid_reputation_artifacts_stay_deleted`` 防复活。
    """

    ROOT = Path(__file__).resolve().parent.parent

    #: 各文件允许残留的「词表内真名」出现数上限（棘轮，只降不升）。
    BASELINES = {
        "data/quality/reputation_cache.json": 0,
        "data/quality/ipinfo.json": 0,
        "data/quality/reputation.json": 0,
        "data/quality/external_check.json": 0,
        "data/quality/upstream_meta.json": 0,
    }

    @staticmethod
    def _vocab():
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                               / "scripts"))
        import checks_bundle as cb
        try:
            names = cb.load_plugin("leak_guard").reputation_source_names()
        except Exception:
            return None
        return {str(n).strip().lower() for n in names}

    def _scan(self, vocab):
        """返回 ``{相对路径: 词表内真名出现数}``（结构化，非文本 grep）。"""
        import json
        found = {}
        for rel in self.BASELINES:
            f = self.ROOT / rel
            if not f.exists():
                continue
            try:
                doc = json.loads(f.read_text(encoding="utf-8"))
            except ValueError:
                continue
            n = 0
            proxies = doc.get("proxies") if isinstance(doc, dict) else None
            if isinstance(proxies, dict):
                for entry in proxies.values():
                    if not isinstance(entry, dict):
                        continue
                    # 缓存形态：每 IP 字典的**键**即源名
                    for k in entry:
                        if str(k).strip().lower() in vocab:
                            n += 1
                    # 记录形态：来源身份字段。``rep_flags`` **不在此列**——
                    # 它是语义标志（hosting/anonymous/listed…）而非来源身份；
                    # 其中 ``abuse`` 与词表撞名属**已知假阳性**（私有包有
                    # rep_abuse.py），哈希它会摧毁 flags 的可判读性。
                    for field in ("sources", "numeric", "rep_sources",
                                  "risk_sources"):
                        seq = entry.get(field)
                        if isinstance(seq, list):
                            n += sum(1 for v in seq
                                     if isinstance(v, str)
                                     and v.strip().lower() in vocab)
                    for field in ("source", "reputation_source"):
                        src = entry.get(field)
                        if (isinstance(src, str)
                                and src.strip().lower() in vocab):
                            n += 1
            if n:
                found[rel] = n
        return found

    def test_reputation_source_names_ratcheted_down(self):
        vocab = self._vocab()
        if vocab is None:
            self.skipTest("私有 leak_guard 不可得：无法派生词表，跳过（fail-open）")
        found = self._scan(vocab)
        for rel, n in sorted(found.items()):
            with self.subTest(file=rel):
                if n > self.BASELINES.get(rel, 0):
                    self.fail(
                        f"{rel}：词表内信誉数据源名 {n} 处 > 棘轮基线 "
                        f"{self.BASELINES.get(rel, 0)}——**出现新增泄漏**。"
                        f"已发布产物只许落 rsrc_* 不透明 id")
        for rel, b in self.BASELINES.items():
            if found.get(rel, 0) < b:
                with self.subTest(file=rel):
                    self.fail(
                        f"{rel}：词表内信誉数据源名降至 {found.get(rel, 0)}"
                        f"（基线 {b}）——**该下调 BASELINES**")

    def test_cache_attribution_keys_are_all_opaque(self):
        """R238：**正向**断言——缓存的归属键必须**全部**是不透明 id。

        比「计数真名」更强：不依赖任何词表，也不受假阳性影响。

        为什么要正向断言：正则全量普查在本族仍会报出 ~5.2 万处命中，但逐条
        归因后**全部**是**载荷内部的归一化信号维度名**（``data.signals`` 的
        ``bogon``/``cloud``/``hosting``/``proxy``/``tor``/``vpnasn``/…），
        其中只有 ``spamhaus`` 与源名撞词，语义是「该 IP 在 Spamhaus 被列出」
        的**信号标签**、不是归属。把它哈希掉会摧毁载荷含义（那是评分器的
        输出字段名）。故「计数真名」在该处不可作为判据，正向断言才是。

        归属面则相反：``reputation_cache.json`` 每 IP 字典的**顶层键**就是
        「该 IP 的信号来自哪个源」，那才是必须去身份的东西——R238 实测
        全部为 ``rsrc_*``，本用例把它锁住。
        """
        import json
        f = self.ROOT / "data" / "quality" / "reputation_cache.json"
        if not f.exists():
            self.skipTest("已发布缓存缺失")
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except ValueError:
            self.skipTest("已发布缓存不可解析")
        proxies = doc.get("proxies") if isinstance(doc, dict) else None
        if not isinstance(proxies, dict) or not proxies:
            self.skipTest("已发布缓存无条目")
        bad = []
        total = 0
        for ip, entry in proxies.items():
            if not isinstance(entry, dict):
                continue
            for k in entry:
                total += 1
                if not (isinstance(k, str) and k.startswith("rsrc_")):
                    bad.append((ip, k))
        self.assertEqual(
            bad[:5], [],
            f"{len(bad)}/{total} 个缓存归属键不是 rsrc_* 不透明 id——"
            f"归属面回退了（载荷内 data.signals 的维度名不在此列）")

    def test_orphan_valid_reputation_artifacts_stay_deleted(self):
        """R238：``data/valid/`` 下那两个孤儿产物**不得复活**。

        它们是 R452 脱敏压squash 的遗留：无生产者、无消费者，且是
        ``data/quality/`` 同名文件的陈旧副本，却仍带 21017 处信誉数据源
        真名。加此断言是为了在**写出的当轮**就抓住回归——若将来有人新增脚本
        往 ``data/valid/`` 写信誉 JSON（那本身就是错位置：信誉产物属
        ``data/quality/``），而不是又攒出一批真名等下一轮清理。
        """
        for rel in ("data/valid/reputation.json",
                    "data/valid/reputation_cache.json"):
            with self.subTest(path=rel):
                self.assertFalse(
                    (self.ROOT / rel).exists(),
                    f"{rel} 复活了——它无生产者无消费者，且是 data/quality/ "
                    f"同名文件的陈旧副本；信誉产物应只写 data/quality/ "
                    f"（并经 rep_public_id 去身份）")

    def test_scan_actually_detects_injected_name(self):
        """自证：判据必须真能命中（注入一个词表内真名 → 计数上升）。"""
        import json
        import tempfile
        vocab = self._vocab()
        if vocab is None or not vocab:
            self.skipTest("词表不可得")
        probe = sorted(vocab)[0]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rel = "data/quality/reputation.json"
            (root / "data/quality").mkdir(parents=True)
            (root / rel).write_text(json.dumps(
                {"proxies": {"1.2.3.4:443#US": {
                    "sources": [probe], "numeric": [],
                    "source": "multi"}}}), encoding="utf-8")
            old_root, self.ROOT = self.ROOT, root
            try:
                got = self._scan(vocab)
            finally:
                self.ROOT = old_root
        self.assertEqual(got.get(rel), 1,
                         f"注入 {probe!r} 后判据未命中——门禁失效")


@unittest.skipIf(_GUARD is None, "PCB bundle 缺省，权威表不可用")
class TestStaticFetchBindingNames(unittest.TestCase):
    """R235：静态表取数函数的**绑定面**不得在公开树按名硬写（安全合规）。

    为什么按「代码形态」而非「词表」判定：词表判定会**误报**——本族源名里
    ``abuse``（158 处）、``static``（50 处）既是源名又是通用英文词，
    ``ip-api``/``dnsbl`` 兼作类别词。R227 的教训是**不可靠判据不能进门禁**
    （漏报或误报都给假信心，比没门禁更糟）。故本门禁以私有包
    ``rep_static._static_fetch_attrs()``（**自派生**，与模块实际导出严格
    一致，有测试自证）为权威，只匹配**完整属性名** ``fetch_<源名>``——
    ``fetch_abuseipdb_public`` 整体匹配，故 ``abuse`` 一词不构成误报。

    实测基线：``quality_reputation.py`` 185 处（37 处 ``_rep_static.fetch_x``
    属性 + 148 处裸名 ``fetch_x``）、``test_quality.py`` 53 处（字符串字面量
    形式），合计 238——这才是该面在代码层的真实规模（R230 棘轮只统计了
    「下载厂商名」，完全没覆盖本族）。

    存量以**计数棘轮**表达，方向感知双向断言。
    """

    ROOT = Path(__file__).resolve().parent.parent

    #: 各文件允许的绑定引用数上限（棘轮，只降不升）。
    BASELINES = {
        "scripts/quality_reputation.py": 185,
        "tests/test_quality.py": 53,
    }

    @staticmethod
    def _attrs():
        """经 ``checks_bundle`` 取权威表（**不做直接 import**）。

        直接 ``import rep_static`` 会被 ``test_zero_dependency`` 判为第三方
        依赖泄漏——其 ``PCB_PLUGINS`` 白名单是**类定义时**从 ``pcb/plugins/``
        扫出来的，无私有包时为空集，故该写法只在带包环境成立。
        ``checks_bundle.load_plugin`` 是本项目唯一认可的私有包访问器。
        """
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                               / "scripts"))
        import checks_bundle as cb
        try:
            return set(cb.load_plugin("rep_static")._static_fetch_attrs())
        except Exception:
            return None

    def _count(self, attrs):
        import ast
        out = {}
        for rel in self.BASELINES:
            f = self.ROOT / rel
            if not f.exists():
                continue
            tree = ast.parse(f.read_text(encoding="utf-8"), filename=rel)
            n = 0
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in attrs:
                    n += 1
                elif isinstance(node, ast.Name) and node.id in attrs:
                    n += 1
                elif (isinstance(node, ast.Constant)
                      and isinstance(node.value, str)
                      and node.value in attrs):
                    n += 1
            if n:
                out[rel] = n
        return out

    def test_static_fetch_bindings_ratcheted_down(self):
        attrs = self._attrs()
        if attrs is None:
            self.skipTest("私有 rep_static 不可得：无法派生权威表，跳过（fail-open）")
        self.assertGreaterEqual(len(attrs), 30, "权威表异常偏小，判据可能失效")
        found = self._count(attrs)
        for rel, n in sorted(found.items()):
            with self.subTest(file=rel):
                if n > self.BASELINES.get(rel, 0):
                    self.fail(
                        f"{rel}：静态表取数函数名绑定 {n} 处 > 棘轮基线 "
                        f"{self.BASELINES.get(rel, 0)}——**出现新增泄漏**。"
                        f"绑定面应改为按私有包权威表遍历，不逐个硬写名字")
        for rel, b in self.BASELINES.items():
            if found.get(rel, 0) < b:
                with self.subTest(file=rel):
                    self.fail(
                        f"{rel}：绑定引用降至 {found.get(rel, 0)}（基线 {b}）"
                        f"——**该下调 BASELINES**")

    def test_gate_detects_a_new_binding(self):
        """自证：注入一个权威表内的绑定名 → 计数必须上升。"""
        import ast
        attrs = self._attrs()
        if not attrs:
            self.skipTest("权威表不可得")
        probe = sorted(attrs)[0]
        src = f"import x\nx = _rep_static.{probe}\ny = {probe}\nz = {probe!r}\n"
        tree = ast.parse(src)
        n = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in attrs:
                n += 1
            elif isinstance(node, ast.Name) and node.id in attrs:
                n += 1
            elif (isinstance(node, ast.Constant)
                  and isinstance(node.value, str)
                  and node.value in attrs):
                n += 1
        self.assertEqual(n, 3, f"三种引用形态各应计 1，判据漏计：{probe}")


@unittest.skipIf(_GUARD is None, "PCB bundle 缺省，模式清单不可用")
class TestDownloadVendorNamesInData(unittest.TestCase):
    """R236：下载来源**厂商名**不得留在已发布 data/ 里（安全合规 / 私有源隔离）。

    R229 起 ``source_origin()`` 就把私有表来源换成不透明 ``dsrc_*``，R230 又
    补了**代码层**门禁——但 **data 层**一直没有门禁，于是接线对不对只能靠人工
    看文件。R236 实测：``data/quality/ip_sources.json`` 等确实在 R229 接线
    **之前**生成，一直带明文标签；``update-proxies`` 首次带 R229 跑完
    （2026-09-26T09:19Z）后该族从 3220 处降到 467 处，``ip_sources.json`` 与
    ``source_stats.json`` **归零**。本门禁把这条曲线锁住。

    判据与代码层门禁同源（``leak_guard.download_vendor_tokens()``，44 词由私有
    包三张表**权威派生**），合并为单条正则避免 44 次全串扫描——实测 7.1s。

    存量以**计数棘轮**表达，方向感知双向断言。
    """

    ROOT = Path(__file__).resolve().parent.parent

    #: 各文件允许的厂商名出现数上限（棘轮，只降不升）。**已归零的文件也列入**
    #: （基线 0）——否则它们会静默回退而无人察觉。
    BASELINES = {
        "data/quality/ipinfo.json": 0,
        "data/quality/reputation.json": 0,
        "data/quality/source_history.json": 117,
        "data/quality/source_quality.json": 0,
        "data/output/source_quality_report.txt": 0,
        "data/quality/ip_sources.json": 0,
        "data/quality/source_stats.json": 0,
    }

    @staticmethod
    def _pattern():
        import re
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                               / "scripts"))
        import checks_bundle as cb
        try:
            toks = sorted(cb.load_plugin("leak_guard").download_vendor_tokens())
        except Exception:
            return None
        if not toks:
            return None
        return re.compile(r"(?<![A-Za-z0-9])(?:"
                          + "|".join(re.escape(t) for t in toks)
                          + r")(?![A-Za-z0-9])", re.IGNORECASE)

    def test_download_vendor_names_in_data_ratcheted_down(self):
        pat = self._pattern()
        if pat is None:
            self.skipTest("私有 leak_guard 不可得：无法派生厂商集，跳过（fail-open）")
        found = {}
        for rel in self.BASELINES:
            f = self.ROOT / rel
            if not f.exists():
                continue
            n = len(pat.findall(
                f.read_text(encoding="utf-8", errors="ignore")))
            if n:
                found[rel] = n
        for rel, n in sorted(found.items()):
            with self.subTest(file=rel):
                if n > self.BASELINES.get(rel, 0):
                    self.fail(
                        f"{rel}：厂商名 {n} 处 > 棘轮基线 "
                        f"{self.BASELINES.get(rel, 0)}——**出现新增泄漏**。"
                        f"私有表来源只许落 dsrc_* 不透明 id")
        for rel, b in self.BASELINES.items():
            if found.get(rel, 0) < b:
                with self.subTest(file=rel):
                    self.fail(
                        f"{rel}：厂商名降至 {found.get(rel, 0)}（基线 {b}）"
                        f"——**该下调 BASELINES**")

    def test_migrated_files_stay_at_zero(self):
        """已归零的两个文件必须保持 0（专项断言，给出更明确的失败信息）。"""
        pat = self._pattern()
        if pat is None:
            self.skipTest("权威词表不可得")
        for rel in ("data/quality/ip_sources.json",
                    "data/quality/source_stats.json"):
            f = self.ROOT / rel
            if not f.exists():
                continue
            n = len(pat.findall(f.read_text(encoding="utf-8", errors="ignore")))
            self.assertEqual(n, 0,
                             f"{rel} 重新出现 {n} 处厂商名——来源键空间回退了")


@unittest.skipIf(_GUARD is None, "PCB bundle 缺省，模式清单不可用")
class TestCnCodenamesRatchetedDown(unittest.TestCase):
    """R236：CN 源**代号**（``cnNN``）须从公开树与 data/ 清除（安全合规）。

    用户在 R236 明确指出：「远程仍然可以找到大量的 cnxx」——据此**推翻**了
    R218–R224 的判断（我当时按「``china.json`` 已发布键、数据契约 E『只增不改
    不删』」把代号层判为有意保留）。口径统一到「全部换成不透明 id」。

    实测基线（清退起点）：
    - **data/ 159 989 处**，全在 ``data/quality/china.json``（单行 JSON）；
    - **代码/文档/CI 582 行 / 17 文件**——``tests/test_china_check.py`` 250、
      ``scripts/china_check.py`` 173、``scripts/china_engine.py`` 64、
      **``.github/workflows/china-check.yml`` 26**（``--cn-limit cnNN=`` 批量
      通道调参表）、``tests/test_common.py`` 25、``tests/test_validate.py`` 14、
      ``scripts/validate_proxies.py`` 6、``README.md`` 5 等。

    不透明 id 的基础设施早已就绪（PCB ``_sources.public_id``，``src_`` 前缀），
    R236 已把它从单向哈希迁到与另两族同构的**可逆**编解码器。公开侧接线
    （含 ``--cn-limit`` 调参表改为不透明 id + ``--list-cn-channels`` 发现
    路径）是机械替换，随本棘轮基线逐轮下调直至归零。

    计数棘轮，方向感知双向断言。**已归零的文件也列入**（基线 0）防回退。
    """

    ROOT = Path(__file__).resolve().parent.parent

    #: 代码/文档/CI 各文件允许的 CNXX 命中**行数**上限（棘轮，只降不升）。
    CODE_BASELINES = {
        "tests/test_china_check.py": 250,
        "scripts/china_check.py": 173,
        "scripts/china_engine.py": 64,
        ".github/workflows/china-check.yml": 26,
        "tests/test_common.py": 25,
        "tests/test_validate.py": 14,
        "scripts/validate_proxies.py": 6,
        "README.md": 5,
        "tests/test_build_good.py": 4,
        "docs/data-spec.md": 4,
        "scripts/common.py": 2,
        "scripts/generate_stats.py": 2,
        "scripts/health_alert.py": 2,
        "scripts/export_json.py": 1,
        "scripts/quality_check.py": 1,
        "tests/test_export_json.py": 1,
        "tests/test_stats.py": 1,
        "docs/scripts.md": 1,
    }

    #: data/ 各文件允许的 CNXX **出现次数**上限（棘轮，只降不升）。
    DATA_BASELINES = {
        # R240：159989 → **0**。R237 的 ``_seal_cn_source_keys``（``sources`` 键
        # ＋ ``basis``）＋ R240 追加的 error 值内代号替换（``pcb bundle missing
        # for cnNN``，实测 10269 处）共同清空。归零后本门禁从「棘轮」升级为
        # **绝对断言**（已发布产物不得再出现任何 CN 代号）。
        "data/quality/china.json": 0,
    }

    _RX = None

    @classmethod
    def _rx(cls):
        if cls._RX is None:
            import re
            cls._RX = re.compile(r"(?<![A-Za-z0-9_])cn\d{1,2}(?![A-Za-z0-9_])",
                                re.IGNORECASE)
        return cls._RX

    def test_cn_codenames_in_code_ratcheted_down(self):
        rx = self._rx()
        found = {}
        for rel, base in self.CODE_BASELINES.items():
            f = self.ROOT / rel
            if not f.exists():
                continue
            n = sum(1 for line in f.read_text(encoding="utf-8").splitlines()
                    if rx.search(line))
            if n:
                found[rel] = n
        for rel, n in sorted(found.items()):
            with self.subTest(file=rel):
                if n > self.CODE_BASELINES.get(rel, 0):
                    self.fail(
                        f"{rel}：CN 代号 {n} 行 > 棘轮基线 "
                        f"{self.CODE_BASELINES.get(rel, 0)}——**出现新增泄漏**。"
                        f"源代号须换成 src_* 不透明 id（发现路径见 --list-cn-channels）")
        for rel, b in self.CODE_BASELINES.items():
            if found.get(rel, 0) < b:
                with self.subTest(file=rel):
                    self.fail(
                        f"{rel}：CN 代号降至 {found.get(rel, 0)} 行（基线 {b}）"
                        f"——**该下调 CODE_BASELINES**")

    def test_cn_codenames_in_data_ratcheted_down(self):
        rx = self._rx()
        found = {}
        for rel in self.DATA_BASELINES:
            f = self.ROOT / rel
            if not f.exists():
                continue
            n = len(rx.findall(f.read_text(encoding="utf-8", errors="ignore")))
            if n:
                found[rel] = n
        for rel, n in sorted(found.items()):
            with self.subTest(file=rel):
                if n > self.DATA_BASELINES.get(rel, 0):
                    self.fail(
                        f"{rel}：CN 代号 {n} 处 > 棘轮基线 "
                        f"{self.DATA_BASELINES.get(rel, 0)}——**出现新增泄漏**")
        for rel, b in self.DATA_BASELINES.items():
            if found.get(rel, 0) < b:
                with self.subTest(file=rel):
                    self.fail(
                        f"{rel}：CN 代号降至 {found.get(rel, 0)} 处（基线 {b}）"
                        f"——**该下调 DATA_BASELINES**")

    def test_gate_detects_an_injected_codename(self):
        """自证：注入一个 CN 代号 → 计数必须上升（两个口径都验）。"""
        rx = self._rx()
        self.assertEqual(len(rx.findall("x cn01 y")), 1)
        self.assertEqual(len(rx.findall("cn01 cn44")), 2)
        # 边界：不得把普通单词里的 cn+数字误判
        self.assertEqual(len(rx.findall("scn0123 acn01_ xcn1")), 0)
        self.assertEqual(len(rx.findall("cn")), 0)


@unittest.skipIf(_GUARD is None, "PCB bundle 缺省，模式清单不可用")
class TestReputationSourceNamesInDocs(unittest.TestCase):
    """R237：信誉数据源名不得留在**公开文档**里（安全合规 / 私有源隔离）。

    用户要求：「另外两种源的**名称和说明**也有大量残留，应该全部迁移」。

    这一面此前**从未被测量**：R230 的厂商名词表只含 44 个下载源短标签，
    不覆盖普通信誉数据源名。R237 实测起点＝**279 处 / 146 个表格行 / 59–60 个
    不同源名**（``docs/logic.md`` §4.3 两张逐源评分表 75 行 +
    ``docs/scripts.md`` 权重表 66 行与节流表 21 行）——是公开树里最大的
    一处「说明」泄漏。

    处置：逐源明细**迁入 PCB**（``REPUTATION_SOURCES.md``，信息不丢），
    公开文档只留方法论 + 指向 ``--list-rep-sources`` 的指针。同时按仓库既有
    先例（R113/M3）把两条文档契约（R256「须逐条命名」、R112「节流表须与实现
    一致」）改写为**更强**的形态：重复表会漂移，指针不会。

    **本门禁的已知假阳性**（刻意保留并记录，不假装词表完美）：剩余命中里
    ``ip-api`` 指公开地理服务 ip-api.com（本仓多处公开使用，非私有源身份）、
    ``abuse`` 指**语义标志**维度、``dnsbl`` 指**机制类别**。故本门禁按
    **计数棘轮**表达存量而非「必须为 0」——它锁的是「不再增长」，不是
    「已清零」。彻底归零需先把这三类通用词从判据里排除（PCB 侧标注哪些
    条目是类别/通用词而非来源身份），单独立项。
    """

    ROOT = Path(__file__).resolve().parent.parent

    #: 各文件允许的信誉数据源名出现数上限（棘轮，只降不升）。
    BASELINES = {
        "docs/scripts.md": 63,
        "docs/logic.md": 13,
    }

    @staticmethod
    def _pattern():
        import re
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                               / "scripts"))
        import checks_bundle as cb
        try:
            names = sorted(cb.load_plugin("leak_guard")
                           .reputation_source_names())
        except Exception:
            return None
        if not names:
            return None
        return re.compile(r"(?<![A-Za-z0-9_])(?:"
                          + "|".join(re.escape(t) for t in names)
                          + r")(?![A-Za-z0-9_])")

    def test_reputation_source_names_in_docs_ratcheted_down(self):
        pat = self._pattern()
        if pat is None:
            self.skipTest("私有 leak_guard 不可得：无法派生词表，跳过（fail-open）")
        found = {}
        for rel in self.BASELINES:
            f = self.ROOT / rel
            if not f.exists():
                continue
            n = len(pat.findall(f.read_text(encoding="utf-8")))
            if n:
                found[rel] = n
        for rel, n in sorted(found.items()):
            with self.subTest(file=rel):
                if n > self.BASELINES.get(rel, 0):
                    self.fail(
                        f"{rel}：信誉数据源名 {n} 处 > 棘轮基线 "
                        f"{self.BASELINES.get(rel, 0)}——**出现新增泄漏**。"
                        f"逐源明细只放私有包，公开文档只留指针")
        for rel, b in self.BASELINES.items():
            if found.get(rel, 0) < b:
                with self.subTest(file=rel):
                    self.fail(
                        f"{rel}：信誉数据源名降至 {found.get(rel, 0)}（基线 {b}）"
                        f"——**该下调 BASELINES**")

    def test_no_source_enumerating_table_left_in_docs(self):
        """结构性判据（**零假阳性**）：文档里不得再有「逐源枚举」的表格行。

        这比词表判定可靠得多——它不关心源叫什么，只要求**文档不再持有一份
        可漂移的副本**。R237 前 ``docs/scripts.md`` 有 83 行、``logic.md``
        有 63 行这样的表。
        """
        import re
        for rel in ("docs/scripts.md", "docs/logic.md"):
            f = self.ROOT / rel
            if not f.exists():
                continue
            rows = [ln for ln in f.read_text(encoding="utf-8").splitlines()
                    if ln.strip().startswith("|")
                    and re.match(r"^\|\s*`?[A-Za-z0-9_.-]+`?\s*\|\s*\d+\s*\|", ln)]
            with self.subTest(doc=rel):
                self.assertEqual(
                    rows, [],
                    f"{rel} 仍留「源 | 权重 | 说明」式枚举表 {len(rows)} 行——"
                    f"副本会与实现漂移，且逐行列出了源名")


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