import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from annotate_classify import reconcile_views, verify_country_split
from annotate_classify import _build_rep_map, _build_family_map
from annotate_classify import _build_ip_type_map
from common import line_to_key


class TestReconcileViews(unittest.TestCase):
    """``reconcile_views`` 须把所有视图约束到 ``all.txt`` 大师清单。

    历史轮次遗留的非 CF 端口/离场节点一旦不在 ``all.txt``，就在每轮
    注解时剔除；同目录 ``ltd`` 还须是本目录 ``all`` 的子集。
    """

    def _tree(self, all_lines, ports=None, countries=None, sets_dir=None):
        d = Path(tempfile.mkdtemp())
        valid = d / "valid"
        (valid / "ports").mkdir(parents=True)
        (valid / "countries" / "US").mkdir(parents=True)
        (valid / "sets" / "asia").mkdir(parents=True)
        (valid / "all.txt").write_text("\n".join(all_lines) + "\n", encoding="utf-8")
        for name, lines in (ports or {}).items():
            (valid / "ports" / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        for name, lines in (countries or {}).items():
            (valid / "countries" / "US" / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        for name, lines in (sets_dir or {}).items():
            (valid / "sets" / "asia" / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return d, valid

    def test_removes_phantom_lines_only(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#US", "3.3.3.3:85#US"],
            ports={"443.txt": ["1.1.1.1:443#US", "8.8.8.8:443#US"], "85.txt": ["9.9.9.9:85#US"]},
        )
        removed = reconcile_views(valid)
        self.assertEqual(removed, 2)
        self.assertEqual(
            (valid / "ports" / "443.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US\n",
        )
        # 越界行全数剔除 → 清空不落盘（不写 0 字节残留）
        self.assertFalse((valid / "ports" / "85.txt").exists())

    def test_key_compare_ignores_note_differences(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US-old"],
            ports={"443.txt": ["1.1.1.1:443#US-new"]},
        )
        self.assertEqual(reconcile_views(valid), 0)
        self.assertEqual(
            (valid / "ports" / "443.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US-new\n",
        )

    def test_country_all_pruned_to_master(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#US"],
            countries={
                "all.txt": ["1.1.1.1:443#US", "9.9.9.9:443#US"],
                "ltd.txt": ["1.1.1.1:443#US"],
            },
        )
        removed = reconcile_views(valid)
        self.assertEqual(removed, 1)
        self.assertEqual(
            (valid / "countries" / "US" / "all.txt").read_text(encoding="utf-8"),
            # R313 起回填缺失方向：越界行剔除后，master 缺失行按原字节补入
            "1.1.1.1:443#US\n2.2.2.2:443#US\n",
        )

    def test_country_ltd_kept_within_country_all(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#US"],
            countries={
                "all.txt": ["1.1.1.1:443#US"],
                "ltd.txt": ["1.1.1.1:443#US", "2.2.2.2:443#US"],
            },
        )
        removed = reconcile_views(valid)
        self.assertEqual(removed, 0)
        self.assertEqual(
            (valid / "countries" / "US" / "ltd.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US\n2.2.2.2:443#US\n",
        )

    def test_set_ltd_missing_from_master_pruned(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#HK"],
            sets_dir={
                "all.txt": ["1.1.1.1:443#US"],
                "ltd.txt": ["1.1.1.1:443#US", "2.2.2.2:443#HK", "9.9.9.9:443#US"],
            },
        )
        removed = reconcile_views(valid)
        self.assertEqual(removed, 1)
        self.assertEqual(
            (valid / "sets" / "asia" / "ltd.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US\n2.2.2.2:443#HK\n",
        )

    def test_verify_country_split_consistent(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#US"],
            countries={"all.txt": ["1.1.1.1:443#US", "2.2.2.2:443#US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual((r["master"], r["countries"]), (2, 2))
        self.assertEqual(r["missing"], [])
        self.assertEqual(r["excess"], [])
        self.assertEqual(r["dup_endpoints"], 0)

    def test_verify_country_split_all_sentinel_excluded(self):
        # ``#ALL``（入口未知）依 data-spec 只在 all.txt/all_ltd.txt、不进
        # countries/：大师键集须剔除 ALL，否则合法哨兵被误报 missing。
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#ALL→US"],
            countries={"all.txt": ["1.1.1.1:443#US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual((r["master"], r["countries"]), (1, 1))
        self.assertEqual(r["missing"], [])
        self.assertEqual(r["excess"], [])

    def test_verify_country_split_phantom_duplicate_detected(self):
        # 同键在分目录行数 > 大师（入口国标注不同的重复行）：reconcile_views
        # 按键裁剪剪不掉 → phantom 计 1，键集 1:1 不受影响。
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US"],
            countries={"all.txt": ["1.1.1.1:443#US", "1.1.1.1:443#DE→US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual(r["phantom"], 1)
        self.assertEqual(r["missing"], [])
        self.assertEqual(r["excess"], [])

    def test_verify_country_split_matched_duplicates_not_phantom(self):
        # 大师本就含两行同键（两次观测）→ 分目录同样两行属正常，phantom=0。
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "1.1.1.1:443#DE→US"],
            countries={"all.txt": ["1.1.1.1:443#US", "1.1.1.1:443#DE→US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual(r["phantom"], 0)

    def test_verify_country_split_excess_detected(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US"],
            countries={"all.txt": ["1.1.1.1:443#US", "9.9.9.9:443#US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual(r["excess"], ["9.9.9.9:443"])
        self.assertEqual(r["missing"], [])

    def test_verify_country_split_missing_detected(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US", "2.2.2.2:443#US"],
            countries={"all.txt": ["1.1.1.1:443#US"]},
        )
        r = verify_country_split(valid)
        self.assertEqual(r["missing"], ["2.2.2.2:443"])

    def test_verify_country_split_no_all_txt(self):
        d = Path(tempfile.mkdtemp())
        r = verify_country_split(d / "valid")
        self.assertEqual((r["master"], r["countries"]), (0, 0))
        self.assertEqual(r["missing"] + r["excess"], [])
        self.assertEqual(r["dup_endpoints"], 0)

    def test_verify_country_split_dup_endpoint_detected(self):
        # 同一 ip:port 出现在两个国家目录（#SG 与 #CO）→ dup_endpoints 计 1；
        # 键集 1:1 不受影响（missing/excess 为空）
        d = Path(tempfile.mkdtemp())
        valid = d / "valid"
        (valid / "countries" / "SG").mkdir(parents=True)
        (valid / "countries" / "CO").mkdir(parents=True)
        (valid / "countries" / "CN").mkdir(parents=True)
        all_lines = ["1.1.1.1:443#SG→US", "1.1.1.1:443#CO→US", "2.2.2.2:443#CN"]
        (valid / "all.txt").write_text("\n".join(all_lines) + "\n", encoding="utf-8")
        (valid / "countries" / "SG" / "all.txt").write_text(
            "1.1.1.1:443#SG→US\n", encoding="utf-8")
        (valid / "countries" / "CO" / "all.txt").write_text(
            "1.1.1.1:443#CO→US\n", encoding="utf-8")
        (valid / "countries" / "CN" / "all.txt").write_text(
            "2.2.2.2:443#CN\n", encoding="utf-8")
        r = verify_country_split(valid)
        self.assertEqual((r["master"], r["countries"]), (2, 2))
        self.assertEqual(r["missing"], [])
        self.assertEqual(r["excess"], [])
        self.assertEqual(r["dup_endpoints"], 1)

    def test_empty_all_returns_zero(self):
        d, valid = self._tree(all_lines=[], ports={"443.txt": ["9.9.9.9:443#US"]})
        self.assertEqual(reconcile_views(valid), 0)

    def test_newline_only_file_pruned_as_empty(self):
        # 空集合曾以 \"\\n\" 形式（1 字节）落盘；空行不是主集成员，
        # prune 须将其视为空文件整体清除（此前空行被\"保留\"，残留永不愈合）。
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US"],
            ports={"443.txt": [""]},
        )
        (valid / "ports" / "443.txt").write_text("\n", encoding="utf-8")
        removed = reconcile_views(valid)
        self.assertEqual(removed, 1)
        self.assertFalse((valid / "ports" / "443.txt").exists())
        # 混有真实行 + 空行的文件：空行剔除、真实行保留
        d2, valid2 = self._tree(
            all_lines=["1.1.1.1:443#US"],
            ports={"443.txt": ["1.1.1.1:443#US", ""]},
        )
        removed = reconcile_views(valid2)
        self.assertEqual(removed, 1)
        self.assertEqual(
            (valid2 / "ports" / "443.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US\n",
        )

    def test_backfill_missing_country_lines(self):
        """R313：master 缺失行按原字节补入所属国家分裂（延迟升序建目录）；
        键已存在不重复；#ALL 与不可解析行跳过。"""
        d = Path(tempfile.mkdtemp())
        valid = d / "valid"
        (valid / "countries").mkdir(parents=True)
        (valid / "all.txt").write_text(
            "1.1.1.1:443#US-100ms\n"
            "2.2.2.2:443#US-50ms\n"
            "3.3.3.3:443#ALL\n"
            "garbage-line\n",
            encoding="utf-8",
        )
        removed = reconcile_views(valid)
        self.assertEqual(removed, 0)
        self.assertEqual(
            (valid / "countries" / "US" / "all.txt").read_text(
                encoding="utf-8"),
            "2.2.2.2:443#US-50ms\n1.1.1.1:443#US-100ms\n",
        )
        # 幂等：再跑一次无新增无删除
        self.assertEqual(reconcile_views(valid), 0)
        self.assertEqual(
            (valid / "countries" / "US" / "all.txt").read_text(
                encoding="utf-8"),
            "2.2.2.2:443#US-50ms\n1.1.1.1:443#US-100ms\n",
        )


class TestRepMapContract(unittest.TestCase):
    """R276：生产—消费键契约——`reputation.json → {key: score}` 映射
    只收有分条目，无分/垃圾条目静默跳过（quality_check 生产键
    score/risk/source/sources/flags/numeric，下游仅取 score）。"""

    def test_build_rep_map_skips_scoreless(self):
        data = {"proxies": {
            "1.2.3.4:443#US": {"score": 88, "risk": "low",
                               "sources": ["dnsbl"], "flags": ["listed"],
                               "numeric": [70]},
            "5.6.7.8:443#JP": {"risk": "medium"},
            "6.6.6.6:443#DE": "garbage",
        }}
        self.assertEqual(_build_rep_map(data), {"1.2.3.4:443#US": 88})

    def test_build_rep_map_empty(self):
        self.assertEqual(_build_rep_map({}), {})
        self.assertEqual(_build_rep_map({"proxies": {}}), {})

    def test_build_maps_skip_garbage(self):
        """R276：同类加固——family/ip_type 映射遇垃圾条目同样跳过
        （曾与 rep_map 同病：未守卫 isinstance 即 .get 而崩溃）。"""
        fam = {"proxies": {
            "1.2.3.4:443#US": {"family": "datacenter"},
            "5.6.7.8:443#JP": "garbage",
            "6.6.6.6:443#DE": {"family": ""},
        }}
        self.assertEqual(_build_family_map(fam), {"1.2.3.4:443#US": "datacenter"})
        ipt = {"proxies": {
            "1.2.3.4:443#US": {"ip_type": "hosting"},
            "5.6.7.8:443#JP": 42,
            "6.6.6.6:443#DE": {},
        }}
        self.assertEqual(_build_ip_type_map(ipt), {"1.2.3.4:443#US": "hosting"})


class TestExitCountryConvergence(unittest.TestCase):
    """R231：出口国汇聚（``build_exit_cc_map``）的优先级与「→出口」标注保真。

    调研背景（用户清单③「出口是否有不符合的情况」）：已发布数据上
    「标签国 ≠ 实测出口国」706 条（4.05%）。逐条归因后结论是——
    **648 条（91.8%）属同一 IP 多出口**（同一 IP 在不同轮次观测落到不同国家，
    用户已明确指出这批存在且属正常），真正标签错仅 58 条（0.33%）。
    而「``→出口`` 标注 vs ``ipinfo.country_code``」的 648 条分歧中，
    **98.15% 落在多出口族群内**，非代码缺陷。

    本类门禁经**反证校准**（每次收紧都因反证未咬住而被迫重做，记录在案）：
      反证 1（首咬未中）：把 ipinfo 循环改内容但仍留在末尾，``setdefault``
        对已置值键空转 → 属空操作，非有效反证；改为**真的前移**后咬住。
      反证 2（首咬未中）：给 family 注入 ``"ipv4"``，被 ``_norm_cc`` 拒掉
        → 注入**合法 CC** 后咬住（``_norm_cc`` 是第二道防线，不该被当作
        门禁有效性的证据）。
      反证 3（连咬两次未中）：自造正则 ``#\\S+?(?:→(\\S+?))?(-|$)`` 的
        ``\\S+?`` 可回溯全量，无备注后缀行整段被吞、捕获组恒 ``None``
        → 比对集被静默清空；改用 :func:`common.read_exit_region` 后咬住。
      反证 3（第二次未中）：判据写成 ``emap[k] not in v``（集合**含**汇聚值
        即通过），而同一 ``ip:port`` 同现于 ``all.txt``/``all_ltd.txt``，
        改一份仍绿 → 收紧为「**每处**标注都必须相等」+ 比对集规模地板后咬住。

    本类把三条不变量固化，防止它们静默退化：
      1. 汇聚优先级 external_check > upstream_meta(裸 IP) > ipinfo 不变；
      2. ``exit_family.json`` 只并入键候选，**不**作为出口国值来源；
      3. 已发布清单里的 ``→出口`` 标注 **100% 忠实**于对同一批数据重算的
         汇聚结果（标注无自身漂移）。
    """

    # ---- 1. 优先级 ----

    def test_priority_external_beats_upstream_and_ipinfo(self):
        from common import build_exit_cc_map
        ec = {"proxies": {"1.2.3.4:443#US": {"exit_geo": {"country": "JP"}}}}
        um = {"proxies": {"1.2.3.4": {"country": "DE"}}}
        ip = {"proxies": {"1.2.3.4:443#US": {"country_code": "FR"}}}
        out = build_exit_cc_map(ip, ec, um)
        self.assertEqual(out.get("1.2.3.4:443#US"), "JP",
                         "external_check 是第一优先级，应压过 upstream/ipinfo")

    def test_upstream_matches_by_bare_ip_and_beats_ipinfo(self):
        """``upstream_meta`` 以**裸 IP** 为键，按行键裸 IP 部分匹配。"""
        from common import build_exit_cc_map
        um = {"proxies": {"1.2.3.4": {"country": "DE"}}}
        ip = {"proxies": {"1.2.3.4:8443#US": {"country_code": "FR"}}}
        out = build_exit_cc_map(ip, None, um)
        self.assertEqual(out.get("1.2.3.4:8443#US"), "DE",
                         "upstream_meta 观测应按裸 IP 命中并压过 ipinfo 兜底")

    def test_ipinfo_is_last_resort_only(self):
        from common import build_exit_cc_map
        ip = {"proxies": {"1.2.3.4:443#US": {"country_code": "FR"}}}
        self.assertEqual(build_exit_cc_map(ip, None, None).get("1.2.3.4:443#US"),
                         "FR", "无更高优先级源时，ipinfo 应兜底")

    def test_blank_and_nonstr_cc_never_enter_map(self):
        from common import build_exit_cc_map
        ip = {"proxies": {
            "1.1.1.1:443#US": {"country_code": ""},
            "2.2.2.2:443#US": {"country_code": None},
            "3.3.3.3:443#US": {"country_code": 42},
            "4.4.4.4:443#US": {"country_code": "us"},
        }}
        out = build_exit_cc_map(ip, None, None)
        self.assertNotIn("1.1.1.1:443#US", out)
        self.assertNotIn("2.2.2.2:443#US", out)
        self.assertNotIn("3.3.3.3:443#US", out)
        self.assertEqual(out.get("4.4.4.4:443#US"), "US",
                         "大小写应归一为大写 CC")

    # ---- 2. exit_family 不作为值来源 ----

    def test_family_data_only_adds_candidate_keys(self):
        """``exit_family`` 是 family 级历史聚合，非本键的出口观测证据。"""
        from common import build_exit_cc_map
        fam = {"proxies": {"1.2.3.4:443#US": {"family": "ipv4"}}}
        out = build_exit_cc_map(None, None, None, fam)
        self.assertEqual(out.get("1.2.3.4:443#US"), None,
                         "仅存在于 exit_family 的键不得被赋出口国值")

    def test_family_data_still_enables_upstream_hit(self):
        """但它并入的键候选须让 upstream_meta 的观测能被命中。"""
        from common import build_exit_cc_map
        fam = {"proxies": {"1.2.3.4:443#US": {"family": "ipv4"}}}
        um = {"proxies": {"1.2.3.4": {"country": "DE"}}}
        out = build_exit_cc_map(None, None, um, fam)
        self.assertEqual(out.get("1.2.3.4:443#US"), "DE")

    # ---- 3. 已发布标注保真（数据面）----

    ROOT = Path(__file__).resolve().parent.parent

    #: 出口实测覆盖率地板（``geo_checked`` 占比）。实测 72.3%；留 12 个百分点
    #: 余量吸收机器人重跑的自然波动，跌破则说明探测覆盖**退化**而非波动。
    GEO_COVERAGE_FLOOR = 0.60

    def _published(self):
        d = self.ROOT / "data" / "quality"
        # 与 audit_entry_cc.audit 的四源加载口径一致（少一个源会让重算结果
        # 与已发布标注不可比——R231 首次实现漏了 upstream_meta，门禁立刻报出
        # 484 条假漂移，正是它把「源集不一致」显性化）。
        need = ("ipinfo.json", "external_check.json", "upstream_meta.json",
                "exit_family.json")
        if not all((d / n).exists() for n in need):
            self.skipTest("已发布 quality 产物缺失（首次提交前）")
        from common import read_json
        return {n: read_json(d / n) for n in need}

    def test_published_exit_annotations_are_faithful(self):
        """清单里的 ``→出口`` 标注须与对同一批已发布数据重算的汇聚结果一致。

        R231 实测：12599/12599 = 100% 一致。标注若漂移，此处立即变红。

        读侧必须用 :func:`common.read_exit_region`（``upsert_exit_region`` 的精确
        逆操作），**不得自造正则**：``#\\S+?(?:→(\\S+?))?(-|$)`` 的 ``\\S+?`` 可回溯
        到全量，对无备注后缀的行会把整段 ``US→DE`` 吞掉、捕获组恒为 ``None``，
        比对集被静默清空——R231 反证 3 实测「篡改 3 行标注后门禁仍 OK」。
        """
        import collections
        from common import build_exit_cc_map, read_exit_region
        pub = self._published()
        emap = build_exit_cc_map(pub["ipinfo.json"], pub["external_check.json"],
                                 pub["upstream_meta.json"],
                                 pub["exit_family.json"])
        ann = collections.defaultdict(set)
        for f in ("all.txt", "all_ltd.txt"):
            fp = self.ROOT / "data" / "valid" / f
            if not fp.exists():
                continue
            for line in fp.read_text(encoding="utf-8").splitlines():
                got = read_exit_region(line)
                if got:
                    key = line_to_key(line)
                    if key:
                        ann[key].add(got)
        self.assertTrue(ann, "清单中未见任何 →出口 标注，无法校验保真度")
        # 判据须是「**每一处**标注都等于汇聚值」，而非「集合里含汇聚值即通过」：
        # 同一 ip:port 常同时出现在 all.txt 与 all_ltd.txt，用 `in` 判据时
        # 篡改其中一份仍会绿——R231 反证 3 实测（连咬两次才定位）。
        bad = [(k, c, emap[k]) for k, v in ann.items() if k in emap
               for c in v if c != emap[k]]
        total = sum(len(v) for v in ann.values())
        self.assertEqual(
            bad[:5], [], f"{len(bad)}/{total} 处已发布 →出口 标注与重算汇聚"
            f"结果不符（标注漂移）")
        self.assertGreater(
            total, 1000,
            f"只读到 {total} 处标注，远低于已发布清单规模——读侧口径退化，"
            f"本门禁会因比对集过小而给出假信心")

    def test_read_exit_region_is_inverse_of_upsert(self):
        """``read_exit_region`` 须与写入侧严格互逆（往返属性）。"""
        from common import read_exit_region, upsert_exit_region
        lines = [
            "1.2.3.4:443#US",
            "1.2.3.4:443#US-DE",
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-12ms",
            "5.6.7.8:8443#\U0001F1E9\U0001F1EA\U0001F1F8DE-3.2MB/s-88ms",
            "9.9.9.9:443#ALL",
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertIsNone(read_exit_region(line),
                                  "无 → 标记的行必须读出 None")
                for cc in ("DE", "US", "ALL"):
                    self.assertEqual(
                        read_exit_region(upsert_exit_region(line, cc)), cc,
                        f"往返失败：{line!r} ↔ {cc}")

    def test_published_exit_geo_coverage_floor(self):
        """出口实测覆盖率不得跌破地板。

        现状：``geo_checked`` 72.3%（12599/17422），27.7% 的条目**无出口实测**，
        其出口符合性**无法判定**——这是出口侧唯一实质短板。
        """
        pub = self._published()
        px = pub["ipinfo.json"].get("proxies") or {}
        if not px:
            self.skipTest("ipinfo.json 无条目")
        checked = sum(1 for v in px.values()
                      if isinstance(v, dict) and v.get("geo_checked"))
        ratio = checked / len(px)
        self.assertGreaterEqual(
            ratio, self.GEO_COVERAGE_FLOOR,
            f"出口实测覆盖率 {ratio:.1%}（{checked}/{len(px)}）跌破地板 "
            f"{self.GEO_COVERAGE_FLOOR:.0%}——探测覆盖退化，出口符合性将大面积"
            f"无法判定")

    def test_multi_exit_ips_stay_a_small_minority(self):
        """多出口 IP（同一 IP 观测到 >1 个出口国）应始终是少数。

        R231 实测：键级 164/14143 = 1.16%，裸 IP 级 599/13927 = 4.30%，
        全部恰好 2 国。若该比例大幅上升，说明出口数据质量在退化
        （IP 池被更激进地轮转），届时「标签≠实测」将失去可解释性。
        """
        pub = self._published()
        px = pub["ipinfo.json"].get("proxies") or {}
        if not px:
            self.skipTest("ipinfo.json 无条目")
        obs = {}
        for key, v in px.items():
            cc = v.get("country_code") if isinstance(v, dict) else None
            if not cc:
                continue
            bare = key.split("#")[0].rsplit(":", 1)[0]
            obs.setdefault(bare, set()).add(cc)
        multi = [b for b, s in obs.items() if len(s) > 1]
        ratio = len(multi) / len(obs)
        self.assertLessEqual(
            ratio, 0.25,
            f"多出口裸 IP 占比 {ratio:.1%}（{len(multi)}/{len(obs)}）超过 25%——"
            f"出口观测大面积自相矛盾，「标签≠实测」将无法归因")


if __name__ == "__main__":
    unittest.main()