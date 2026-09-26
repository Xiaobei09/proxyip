"""normalize_note / merge_note_tokens —— 全仓库统一备注规范器的行为契约。"""

import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from common import (
    _cn_fallback_ms,
    _fmt_cn_speed,
    _note,
    _rewrite_cn_speed,
    cn_display_ms,
    cn_l2_ms,
    cn_mainland_ok,
    cn_best_isp,
    cn_isp_speed,
    clear_note_buckets,
    line_to_key,
    merge_note_tokens,
    normalize_note,
    parse_ltd_line,
    err_name,
    load_china_stable_keys,
    load_speed_keys,
    load_uptime_keys,
    read_json,
    write_text_if_changed,
)


class TestParseLtdLine(unittest.TestCase):
    """parse_ltd_line / line_to_key 的伪国家 ALL + 出口标记 → 边界契约。

    ``#ALL→US`` 是 data-spec.md 定义的合法格式（入口未知但出口已知），
    ALL 必须保持为 ALL，不得坍缩成阿尔巴尼亚 AL。"""

    def test_all_plain_stays_all(self):
        key, ip, port, cc = parse_ltd_line("1.2.3.4:443#ALL-120ms")
        self.assertEqual((key, ip, port, cc), ("1.2.3.4:443#ALL", "1.2.3.4", "443", "ALL"))

    def test_all_with_exit_marker(self):
        key, ip, port, cc = parse_ltd_line("1.2.3.4:443#ALL→US-120ms-0.44MB/s")
        self.assertEqual((key, cc), ("1.2.3.4:443#ALL", "ALL"))

    def test_line_to_key_all_with_exit_marker(self):
        self.assertEqual(line_to_key("1.2.3.4:443#ALL→US-120ms"), "1.2.3.4:443#ALL")

    def test_real_albania_still_al(self):
        key, _, _, cc = parse_ltd_line("1.2.3.4:443#AL-88ms")
        self.assertEqual((key, cc), ("1.2.3.4:443#AL", "AL"))

    def test_exit_marker_cc_parse(self):
        key, _, _, cc = parse_ltd_line("1.2.3.4:443#US→KR-120ms")
        self.assertEqual((key, cc), ("1.2.3.4:443#US", "US"))

    def test_three_letter_non_all_rejected(self):
        self.assertIsNone(parse_ltd_line("1.2.3.4:443#USA-120ms"))
        self.assertIsNone(parse_ltd_line("1.2.3.4:443#ALLY-120ms"))
        self.assertIsNone(parse_ltd_line("1.2.3.4:443#ALZ-1ms"))
        key, _, _, cc = parse_ltd_line("1.2.3.4:443#ALL→US-120ms")
        self.assertEqual((key, cc), ("1.2.3.4:443#ALL", "ALL"))

    def test_speed_first_tag_not_read_as_cc(self):
        """备注以 ``-115MB/s`` 开头、缺国码的畸形行，MB 不得被当作国码。"""
        self.assertIsNone(parse_ltd_line("1.2.3.4:443#-115MB/s-US-120ms"))
        self.assertIsNone(parse_ltd_line("1.2.3.4:443#115MB/s US-120ms"))
        self.assertEqual(_note("1.2.3.4:443#-115MB/s-US-120ms"), "")


class TestCnMainlandOkCap(unittest.TestCase):
    """cn_mainland_ok 的 cap 语义：None 用默认 150，inf 表示关闭（不回落）。"""

    def test_inf_disables_cap(self):
        self.assertTrue(cn_mainland_ok(200, float("inf")))

    def test_default_cap_150(self):
        self.assertFalse(cn_mainland_ok(200))
        self.assertTrue(cn_mainland_ok(149))

    def test_explicit_cap_honored(self):
        self.assertTrue(cn_mainland_ok(80, cap=100))
        self.assertFalse(cn_mainland_ok(120, cap=100))


class TestNormalizeNote(unittest.TestCase):
    def test_canonical_order(self):
        self.assertEqual(
            normalize_note(
                "1.1.1.1:443#🇺🇸US→US-17ms-22.70MB/s-CN-V6-mid-fast-DC-GPT-CF-69"
            ),
            "1.1.1.1:443#🇺🇸US→US-17ms-22.70MB/s-GPT-DC-fast-V6-CN-69",
        )

    def test_collapses_historical_snapshots(self):
        """多轮 CI 堆叠的 (streaming-type-tier-score) 快照收敛为一组。"""
        stacked = (
            "1.2.3.4:443#🇺🇸US→US-21ms-25.23MB/s-CN-V6-GPT-CF-77"
            "-mid-GPT-CF-70-DC-fast-GPT-CF-62-RES-GPT-CF-70"
        )
        self.assertEqual(
            normalize_note(stacked),
            "1.2.3.4:443#🇺🇸US→US-21ms-25.23MB/s-GPT-RES-fast-V6-CN-70",
        )

    def test_rightmost_wins_single_value_buckets(self):
        # 类型 DC→RES、档位 mid→fast、分数 62→70：均取最右
        line = "1.2.3.4:443#🇺🇸US-50ms-1.00MB/s-DC-mid-RES-fast-62-70"
        self.assertEqual(
            normalize_note(line),
            "1.2.3.4:443#🇺🇸US-50ms-1.00MB/s-RES-fast-70",
        )

    def test_three_digit_score_not_treated_as_score(self):
        # 3 位数不匹配 score 桶 → 沉入 other 垫底，70 保持为官方 0-100 分
        line = "1.2.3.4:443#🇺🇸US-50ms-112-70"
        self.assertEqual(
            normalize_note(line),
            "1.2.3.4:443#🇺🇸US-50ms-70-112",
        )

    def test_score_100_parsed_and_clearable(self):
        # 官方信誉分上界含 100（深测带宽加成可达满分）：须落入 score 桶，
        # 否则 clear_note_buckets 的 score 桶清不掉它，会与新版分值叠罗汉
        # （同 test_collapses_historical_snapshots 的旧 token 堆叠风险）。
        line = "1.2.3.4:443#🇺🇸US-50ms-1.00MB/s-CN-100-U16"
        self.assertEqual(
            normalize_note(line),
            "1.2.3.4:443#🇺🇸US-50ms-1.00MB/s-CN-100-U16",
        )
        # 分数回落到 60：100 能被 score 桶清除，不残留 "-100-60" 双分
        cleared = clear_note_buckets(line, "score")
        self.assertNotIn("-100", cleared)
        self.assertEqual(
            merge_note_tokens(cleared, "60"),
            "1.2.3.4:443#🇺🇸US-50ms-1.00MB/s-CN-60-U16",
        )

    def test_family_rightmost(self):
        line = "1.2.3.4:443#🇺🇸US-50ms-V4-V6"
        self.assertEqual(normalize_note(line), "1.2.3.4:443#🇺🇸US-50ms-V6")

    def test_streaming_union_dedup(self):
        line = "1.2.3.4:443#🇺🇸US-50ms-GPT-YT-GPT-NF(US)"
        self.assertEqual(
            normalize_note(line),
            "1.2.3.4:443#🇺🇸US-50ms-GPT-YT-NF(US)",
        )

    def test_cnh_implies_cn(self):
        line = "1.2.3.4:443#🇯🇵JP→SG-50ms-2.00MB/s-CNH"
        self.assertEqual(
            normalize_note(line),
            "1.2.3.4:443#🇯🇵JP→SG-50ms-2.00MB/s-CN-CNH",
        )

    def test_no_emoji_lead_preserved(self):
        self.assertEqual(
            normalize_note("1.2.3.4:80#US-1ms-CN"),
            "1.2.3.4:80#US-1ms-CN",
        )

    def test_bare_cc_untouched(self):
        for note in ("US", "ALL", "🇺🇸US"):
            line = f"1.2.3.4:443#{note}"
            self.assertEqual(normalize_note(line), line)

    def test_unknown_segments_kept_at_end(self):
        line = "1.2.3.4:443#🇺🇸US-50ms-CN-XYZ"
        self.assertEqual(normalize_note(line), f"{line}")

    def test_decimal_latency_never_dropped_r123(self):
        """R123数据格式：小数延迟非常规排序但不得丢失（零真实触发，
        common.py 属他方编辑区，只锁不丢属性；排序归一待对方协调）。"""
        for line in ("1.2.3.4:443#🇺🇸US-8.5ms-5.86MB/s",
                     "1.2.3.4:443#🇺🇸US-8.55ms-5.86MB/s"):
            with self.subTest(line=line):
                out = normalize_note(line)
                ms = line.split("#", 1)[1].split("-")[1]
                self.assertIn(ms, out.split("-"))

    def test_cn_view_speed_token_idempotent(self):
        # CN 视图速度 token（≈ 前缀）须留在速度位，不得被当作未知段垫底
        line = "1.2.3.4:443#🇺🇸US-42ms-≈2.0MB/s-fast-90"
        self.assertEqual(normalize_note(line), "1.2.3.4:443#🇺🇸US-42ms-≈2.0MB/s-fast-90")
        self.assertEqual(normalize_note(normalize_note(line)), normalize_note(line))

    def test_plain_speed_token_untouched(self):
        line = "1.2.3.4:443#🇺🇸US-42ms-25.23MB/s-fast"
        self.assertEqual(normalize_note(line), line)

    def test_uptime_bucket_collapses_stacked(self):
        """多轮累积的 -U<NN> 收敛为最右（最新）一条。"""
        line = (
            "1.2.3.4:443#🇺🇸US-50ms-5.00MB/s-DC-CF-mid-V4-CN-77"
            "-U50-U33-U25-U20-U17-U18-U15-U14-U13-U16-U12-U11"
        )
        self.assertEqual(
            normalize_note(line),
            "1.2.3.4:443#🇺🇸US-50ms-5.00MB/s-DC-mid-V4-CN-77-U11",
        )

    def test_uptime_merge_replaces_value(self):
        line = "1.2.3.4:443#🇺🇸US-50ms-CN-77-U11"
        self.assertEqual(
            merge_note_tokens(line, "U92"),
            "1.2.3.4:443#🇺🇸US-50ms-CN-77-U92",
        )
        # 同值幂等
        self.assertEqual(
            merge_note_tokens(line, "U11"),
            "1.2.3.4:443#🇺🇸US-50ms-CN-77-U11",
        )

    def test_rewrite_cn_speed(self):
        cn_ms = {"1.2.3.4:443#US": 236.4}
        # 有大陆延迟：替换为估算 ≈（min(5.0, 8*60/236.4≈2.03)）
        self.assertEqual(
            _rewrite_cn_speed("1.2.3.4:443#US-42ms-5.00MB/s-fast-90", cn_ms),
            "1.2.3.4:443#US-42ms-≈2.0MB/s-fast-90",
        )
        # 无大陆延迟观测 → 速度语义不明，删除 token
        self.assertEqual(
            _rewrite_cn_speed("2.2.2.2:443#US-42ms-5.00MB/s-fast-90", cn_ms),
            "2.2.2.2:443#US-42ms-fast-90",
        )
        # 无速度 token：原样
        self.assertEqual(
            _rewrite_cn_speed("1.2.3.4:443#US-42ms-fast-90", cn_ms),
            "1.2.3.4:443#US-42ms-fast-90",
        )
        # 大陆延迟低 → 参考上限高，海外实测仍为上限（min 语义）
        cn_fast = {"1.2.3.4:443#US": 30.0}
        self.assertEqual(
            _rewrite_cn_speed("1.2.3.4:443#US-42ms-5.00MB/s-fast-90", cn_fast),
            "1.2.3.4:443#US-42ms-≈5.0MB/s-fast-90",
        )

    def test_rewrite_cn_speed_floor_cap(self):
        # 极端高延迟：8×60/RTT 参考上限跌破 CN_SPEED_FLOOR(0.4) → 被托底，
        # 估算不为 0 也不留海外的夸张实测值（floor 路径此前无测试锁定）。
        cn_slow = {"9.9.9.9:443#US": 5000.0}
        self.assertEqual(
            _rewrite_cn_speed("9.9.9.9:443#US-42ms-5.00MB/s-fast-90", cn_slow),
            "9.9.9.9:443#US-42ms-≈0.4MB/s-fast-90",
        )
        # RTT 缺失/非正数 → 速度 token 删除（宁缺勿假），floor 不适用
        for bad in (0.0, -1.0, 0):
            with self.subTest(bad=bad):
                line = "8.8.8.8:443#US-42ms-5.00MB/s-fast-90"
                self.assertEqual(
                    _rewrite_cn_speed(line, {"8.8.8.8:443#US": bad}),
                    "8.8.8.8:443#US-42ms-fast-90",
                )

    def test_rewrite_cn_speed_never_publishes_zero(self):
        """R221：CN 视图不得发布零速度（契约 A「测速失败省略速度段不写 0」）。

        事故实录：CN 估算值 = ``min(海外实测, RTT 推算上限)``，海外实测
        低至 0.01MB/s（极慢节点的真实读数），而渲染一律 ``round(v, 1)``
        → 0.01 被压成 ``0.0``。实测产物中 ``all_cn.txt`` 78 行、全部 CN
        视图合计 3888 行写着 ``≈0.0MB/s``：把「实测成功但极慢」发布成
        「速度为零」，下游会当成不可用节点——比省略更糟。

        本测试锁三件事：① 一位小数会归零的正数退到两位小数（保住量级）；
        ② 上游实测真为 0 时删 token 而非写 0；③ 已发布视图零命中。
        """
        cn = {"1.2.3.4:443#US": 21.0}
        # ① 低位正数不被压成 0
        for raw, want in (("0.01", "0.01"), ("0.03", "0.03"), ("0.04", "0.04")):
            with self.subTest(raw=raw):
                out = _rewrite_cn_speed(
                    f"1.2.3.4:443#US-42ms-{raw}MB/s-fast-90", cn)
                self.assertIn(f"-≈{want}MB/s", out)
                self.assertNotIn("≈0.0MB/s", out)
        # 正常量级仍保持原有一位小数展示约定（不无谓改动既有格式）
        self.assertIn("-≈0.4MB/s", _rewrite_cn_speed(
            "1.2.3.4:443#US-42ms-0.44MB/s-fast-90", cn))
        # ② 上游实测真为 0 → 删 token，不写 0
        out = _rewrite_cn_speed("1.2.3.4:443#US-42ms-0MB/s-fast-90", cn)
        self.assertEqual(out, "1.2.3.4:443#US-42ms-fast-90")
        self.assertNotIn("MB/s", out)
        # ③ 对已发布 CN 视图逐行做**推导式**校验：把行内既有速度 token 去掉
        #    后交回本函数重渲染，断言永不产生假零。这既立刻可跑（不依赖 CI
        #    重跑数据），又真锁住数据面——若有人改回 round(v,1)，此用例即红。
        #    注：已提交字节里的历史假零由 china_check 重跑自然清除（all_cn.txt
        #    需联网探测，禁手改 data/）；字节级锁在数据重跑后随
        #    TestCommittedCnViewInvariant 一并收口。
        import glob
        import re
        root = Path(__file__).resolve().parent.parent
        line_re = re.compile(r"^([\d.]+:\d+#\S+?)(-\d+(?:\.\d+)?ms)?"
                             r"(-\d+(?:\.\d+)?MB/s)")
        checked = derived_zero = 0
        for f in glob.glob(str(root / "data" / "valid" / "**" / "*.txt"),
                           recursive=True):
            try:
                text = Path(f).read_text(encoding="utf-8")
            except OSError:
                continue
            for raw in text.splitlines():
                m = line_re.match(raw)
                if not m:
                    continue
                key = m.group(1)
                cn = {key: 21.0}
                out = _rewrite_cn_speed(
                    f"{key}-42ms{m.group(3)}", cn)
                checked += 1
                if "-≈0.0MB/s" in out:
                    derived_zero += 1
        if checked:
            self.assertEqual(
                derived_zero, 0,
                f"重渲染 {checked} 行已发布 CN 视图，{derived_zero} 行产出假零")

    def test_fmt_cn_speed_precision_ladder(self):
        """R221：渲染精度阶梯本身（不经整行 rewrite，便于定位）。"""
        self.assertEqual(_fmt_cn_speed(0.01), "0.01")
        self.assertEqual(_fmt_cn_speed(0.04), "0.04")
        self.assertEqual(_fmt_cn_speed(0.05), "0.1")
        self.assertEqual(_fmt_cn_speed(0.44), "0.4")
        self.assertEqual(_fmt_cn_speed(7.24), "7.2")
        self.assertEqual(_fmt_cn_speed(12.53), "12.5")

    def test_rewrite_cn_speed_idempotent_on_estimated(self):
        # 已含 ≈ 估算 token 的行再经 rewrite（重入/CN 视图文件二次处理）——
        # _CN_SPEED_RAW_RE 只匹配裸数值、不匹配 ≈ 前缀，行原样、绝不二次改写
        # 或叠加第二个速度 token（幂等；备注段的历史教训正是 token 无限堆叠，
        # 见 common.py 的 normalize_note 唯一出口注释）。
        line = "7.7.7.7:443#US-42ms-≈2.0MB/s-fast-90"
        cn = {"7.7.7.7:443#US": 236.4}
        self.assertEqual(_rewrite_cn_speed(line, cn), line)
        self.assertEqual(_rewrite_cn_speed(line, cn).count("MB/s"), 1)

    def test_idempotent_on_messy_real_lines(self):
        messy = (
            "137.220.38.195:443#🇺🇸US→US-18ms-39.33MB/s-CN-V6-GPT-CF-74"
            "-mid-GPT-CF-76-DC-fast-GPT-CF-73-RES-GPT-CF-75"
        )
        once = normalize_note(messy)
        self.assertEqual(once, normalize_note(once))


class TestCnDisplayMs(unittest.TestCase):
    """cn_display_ms / cn_l2_ms / _cn_fallback_ms 的大陆延迟"宁缺勿假"契约。

    过滤 1~2ms ICMP/TCP 噪声冒充真实代理延迟；真实大陆 L2 探测本身 >=2 时
    优先采用。"""

    def test_l2_min_over_ok_vantages(self):
        e = {"sources": {
            "cn20": {"status": "ok", "ms": 40},
            "cn24": {"status": "ok", "ms": 55},
            "cn27": {"status": "ok", "ms": 30},
        }}
        self.assertEqual(cn_l2_ms(e), 30.0)

    def test_l2_ignores_non_ok_and_nonpositive(self):
        e = {"sources": {
            "cn20": {"status": "fail", "ms": 10},
            "cn24": {"status": "ok", "ms": 0},
            "cn27": {"status": "ok", "ms": 22},
        }}
        self.assertEqual(cn_l2_ms(e), 22.0)

    def test_l2_candidate_below_two_falls_to_fallback(self):
        e = {"sources": {
            "cn20": {"status": "ok", "ms": 1.5},
            "cn07": {"status": "ok", "ms": 30},  # 非 ICMP 可信 TCP RTT
        }}
        self.assertEqual(cn_display_ms(e), 30.0)

    def test_l2_two_or_above_wins(self):
        e = {"sources": {
            "cn20": {"status": "ok", "ms": 2.0},
            "cn07": {"status": "ok", "ms": 30},
        }}
        self.assertEqual(cn_display_ms(e), 2.0)

    def test_no_l2_uses_min_trusted_tcp_fallback(self):
        e = {"sources": {
            "cn16": {"status": "ok", "ms": 1.0},     # 纯 ICMP 噪声，剔除
            "cn07": {"status": "ok", "ms": 45},
            "cn17": {"status": "ok", "ms": 12},
        }}
        self.assertEqual(cn_display_ms(e), 12.0)

    def test_fallback_accepts_exactly_two(self):
        e = {"sources": {"cn07": {"status": "ok", "ms": 2.0}}}
        self.assertEqual(_cn_fallback_ms(e, e["sources"]), 2.0)

    def test_fallback_rejects_sub_two_noise(self):
        e = {"sources": {"cn07": {"status": "ok", "ms": 1.8}}}
        self.assertIsNone(_cn_fallback_ms(e, e["sources"]))

    def test_legacy_entry_without_sources_uses_ms(self):
        self.assertEqual(cn_l2_ms({"ms": 88.0}), 88.0)
        self.assertIsNone(cn_l2_ms({"ms": -1}))
        self.assertIsNone(cn_display_ms({}))

    def test_nothing_usable_returns_none(self):
        e = {"sources": {"cn16": {"status": "ok", "ms": 1.0}}}
        self.assertIsNone(cn_display_ms(e))

    def test_icmp_level_source_never_used_as_latency(self):
        # cn07/cn08/cn14 的聚合结果带 level="icmp"：即便 ms≈45 也不得
        # 冒充大陆延迟（ICMP 到 IP 边缘 ≠ 隧道/代理延迟），应整源剔除
        e = {"sources": {"cn07": {"status": "ok", "ok": True, "ms": 45.0, "level": "icmp"}}}
        self.assertIsNone(cn_display_ms(e))
        self.assertIsNone(_cn_fallback_ms(e, e["sources"]))

    def test_icmp_level_excluded_even_when_tcp_absent(self):
        # 混合源：纯 ICMP 的 cn07 不参与，TCP 的 cn17 才是候选
        e = {"sources": {
            "cn07": {"status": "ok", "ok": True, "ms": 4.2, "level": "icmp"},
            "cn17": {"status": "ok", "ok": True, "ms": 34.0, "level": "tcp"},
        }}
        self.assertEqual(cn_display_ms(e), 34.0)

    def test_icmp_review_excluded_by_name(self):
        # ICMP 复核源结果不带 level 字段（仅有 ms），须按名称剔除，不得失真
        e = {"sources": {"cn40": {"status": "ok", "ok": True, "ms": 8.0}}}
        self.assertIsNone(cn_display_ms(e))
        # 有真实 TCP 源时 cn40 不再干扰取值
        e2 = {"sources": {
            "cn40": {"status": "ok", "ok": True, "ms": 8.0},
            "cn30": {"status": "ok", "ok": True, "ms": 50.0, "level": "tcp"},
        }}
        self.assertEqual(cn_display_ms(e2), 50.0)


class TestCnBestIsp(unittest.TestCase):
    def test_picks_global_min_carrier_with_short_name(self):
        e = {"isp_ms": {"中国电信": 45.0, "中国移动": 38.0, "中国联通": 60.0}}
        self.assertEqual(cn_best_isp(e), ("移动", 38.0))

    def test_tie_picks_first_best(self):
        e = {"isp_ms": {"中国移动": 30.0, "中国联通": 30.0}}
        self.assertEqual(cn_best_isp(e), ("移动", 30.0))

    def test_no_isp_ms_returns_none(self):
        self.assertIsNone(cn_best_isp({}))
        self.assertIsNone(cn_best_isp({"sources": {}}))
        self.assertIsNone(cn_best_isp({"isp_ms": {}}))

    def test_icmp_noise_rejected(self):
        e = {"isp_ms": {"中国移动": 1.0, "中国电信": 2.5}}
        self.assertEqual(cn_best_isp(e), ("电信", 2.5))

    def test_all_noise_returns_none(self):
        e = {"isp_ms": {"中国移动": 1.0, "中国联通": 2.0}}
        self.assertIsNone(cn_best_isp(e))

    def test_unmapped_isp_name_preserved(self):
        e = {"isp_ms": {"其他运营商": 42.0}}
        self.assertEqual(cn_best_isp(e), ("其他运营商", 42.0))


class TestCnIspSpeed(unittest.TestCase):
    """CN-41：分运营商估算速度，与 _rewrite_cn_speed 同公式。"""

    def test_formula_matches_rewrite_cap(self):
        # 60ms→8.0，120ms→4.0，30ms→16.0（上限语义，无海外实测可比时不截顶）
        self.assertEqual(
            cn_isp_speed({"中国移动": 60.0, "中国电信": 120.0, "中国联通": 30.0}),
            {"中国电信": 4.0, "中国移动": 8.0, "中国联通": 16.0},
        )

    def test_floor_applies(self):
        self.assertEqual(cn_isp_speed({"中国电信": 2000.0}), {"中国电信": 0.4})

    def test_icmp_noise_rejected(self):
        self.assertEqual(
            cn_isp_speed({"中国移动": 1.0, "中国电信": 2.5}),
            {"中国电信": 8.0 * 60.0 / 2.5},
        )

    def test_bad_input_returns_empty(self):
        self.assertEqual(cn_isp_speed(None), {})
        self.assertEqual(cn_isp_speed({}), {})
        self.assertEqual(cn_isp_speed({"中国移动": 1.0}), {})


class TestMergeNoteTokens(unittest.TestCase):
    def test_append_missing_tokens_normalized(self):
        out = merge_note_tokens(
            "5.6.7.8:443#🇺🇸US-27ms-27.78MB/s-DC-mid-V6-fast-GPT-CF-77",
            "CN", "V6", "80",
        )
        self.assertEqual(
            out,
            "5.6.7.8:443#🇺🇸US-27ms-27.78MB/s-GPT-DC-fast-V6-CN-80",
        )

    def test_idempotent(self):
        line = "5.6.7.8:443#🇺🇸US-27ms-27.78MB/s-DC-fast-V6-77"
        once = merge_note_tokens(line, "CN", "CNH")
        self.assertEqual(once, merge_note_tokens(once, "CN", "CNH"))
        self.assertEqual(once.count("V6"), 1)

    def test_best_isp_suffix_roundtrip_preserved(self):
        """-移动=57ms 类最佳运营商后缀是『其他』段垫底 token：normalize_note
        必须保序保留、不拆段、不撞延迟/速度正则，且 key/CN 判定不受影响。"""
        from common import (
            line_to_key, _note, has_token, _NOTE_LAT_RE, _NOTE_SPEED_RE,
        )
        samples = [
            ("1.1.1.1:443#🇺🇸US-57ms-5.00MB/s-fast-V4-CN-移动=57ms",
             "1.1.1.1:443#US"),
            ("2.2.2.2:443#🇨🇳CN-236ms-≈2.0MB/s-fast-V6-CN-90-电信=81ms",
             "2.2.2.2:443#CN"),
            ("3.3.3.3:443#🇯🇵JP-328ms-RES-CN-62-U100-联通=120ms",
             "3.3.3.3:443#JP"),
        ]
        for s, expect_key in samples:
            out = normalize_note(s)
            segs = out.split("#", 1)[-1].split("-") if "#" in out else []
            for seg in segs:
                if "=" in seg:
                    self.assertFalse(_NOTE_LAT_RE.match(seg))
                    self.assertFalse(_NOTE_SPEED_RE.match(seg))
                    self.assertIn("ms", seg)
            self.assertTrue(has_token(_note(out), "CN"))
            self.assertEqual(line_to_key(out), expect_key)


class TestBuildExitCcMap(unittest.TestCase):
    def test_upstream_by_entry_ip(self):
        """upstream_meta 键为代理（接入）裸 IP，按行键入口 IP 部分匹配。"""
        from common import build_exit_cc_map
        upstream = {"proxies": {
            "1.2.3.4": {"country": "sg"},       # 小写规范化
            "9.9.9.9": {"country": "HK"},
        }}
        m = build_exit_cc_map(
            {}, {}, upstream,
            family_data={"proxies": {"9.9.9.9:443#JP": {"exit_v6": "2606::1"}}},
        )
        # 行键入口 IP 命中 upstream；family 键被覆盖为 upstream 出口国
        self.assertEqual(m["9.9.9.9:443#JP"], "HK")
        # 无入口 IP 观测的行不受影响，不产生幽灵键
        self.assertNotIn("10.0.0.1:443#JP", m)

    def test_upstream_fills_ipinfo_backstop(self):
        """upstream（第 2 层）胜过 ipinfo（末位兜底）。"""
        from common import build_exit_cc_map
        ipinfo = {"proxies": {"5.5.5.5:80#SG": {"country_code": "SG"}}}
        upstream = {"proxies": {"5.5.5.5": {"country": "US"}}}
        m = build_exit_cc_map(ipinfo, {}, upstream)
        self.assertEqual(m["5.5.5.5:80#SG"], "US")

    def test_external_beats_upstream(self):
        from common import build_exit_cc_map
        external = {"proxies": {
            "a:443#US": {"exit_geo": {"ip": "1.1.1.1", "country": "DE"}},
        }}
        upstream = {"proxies": {"1.1.1.1": {"country": "SG"}}}
        m = build_exit_cc_map({}, external, upstream)
        self.assertEqual(m["a:443#US"], "DE")

    def test_external_countryCode_field_parsed(self):
        # exit_geo 仅 countryCode（无 country）也应解析
        from common import build_exit_cc_map
        external = {"proxies": {
            "a:443#US": {"exit_geo": {"countryCode": "FR"}},
        }}
        self.assertEqual(build_exit_cc_map({}, external, {})["a:443#US"], "FR")

    def test_empty_external_geo_upstream_backfills(self):
        # external 有行但 exit_geo 无值 → 仅候选，交给 upstream 按入口 IP 兜底
        from common import build_exit_cc_map
        external = {"proxies": {"b:443#US": {"exit_geo": {}}}}
        upstream = {"proxies": {"b": {"country": "JP"}}}
        self.assertEqual(build_exit_cc_map({}, external, upstream)["b:443#US"], "JP")

    def test_bogus_external_geo_ignored(self):
        # 三字母国家码非法 → 不产生幽灵键
        from common import build_exit_cc_map
        external = {"proxies": {"c:443#US": {"exit_geo": {"country": "SGP"}}}}
        self.assertNotIn("c:443#US", build_exit_cc_map({}, external, {}))


class TestRequestFollowBounded(unittest.TestCase):
    """``request_follow`` 的响应体读取须有墙钟截止与字节上限：上游无限滴灌
    或巨型响应不得长时间占用线程 / 撑爆内存（与 WS/SSE 修复同类）。"""

    def _patch_opener(self, resp):
        class _Opener:
            def open(self, req, timeout=None):
                return resp

        return mock.patch(
            "common.urllib.request.build_opener", return_value=_Opener()
        )

    class _OkResp:
        status = 200
        headers = {"X-T": "1"}
        _n = 0

        def read(self, n):
            self._n += 1
            return b"abc" if self._n == 1 else b""

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def test_eof_short_body(self):
        from common import request_follow

        with self._patch_opener(self._OkResp()):
            status, headers, body = request_follow("http://h/x", {}, 10)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"abc")
        self.assertEqual(headers["X-T"], "1")

    class _TrickleResp:
        status = 200
        headers = {}

        def __init__(self, now):
            self._now = now

        def read(self, n):
            self._now[0] += 11  # 每次读都越过墙钟截止；数据永不 EOF
            return b"x" * 512

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def test_trickle_is_capped_by_wallclock(self):
        from common import request_follow

        now = [1000.0]
        resp = self._TrickleResp(now)
        with self._patch_opener(resp), \
             mock.patch("common.time.monotonic", side_effect=lambda: now[0]):
            with self.assertRaises(TimeoutError):
                request_follow("http://h/x", {}, 10)

    class _HugeResp:
        status = 200
        headers = {}

        def read(self, n):
            return b"\x00" * (1024 * 1024)  # 永不 EOF 的巨型响应

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def test_oversized_body_rejected(self):
        from common import request_follow

        with self._patch_opener(self._HugeResp()):
            with self.assertRaisesRegex(RuntimeError, "too large"):
                request_follow("http://h/x", {}, 10)


class TestFetchWithDeadlineBounded(unittest.TestCase):
    """``fetch_with_deadline``/``deadline_open`` 的 worker 内读须受字节上限：
    窗口内高速填充的巨型响应不得撑爆内存。"""

    class _OkResp:
        status = 200
        headers = {}
        _n = 0

        def read(self, n):
            self._n += 1
            return b"tiny-body" if self._n == 1 else b""

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _HugeResp:
        status = 200
        headers = {}

        def read(self, n):
            return b"\x00" * (17 * 1024 * 1024)  # 单次即超出 FETCH_BODY_MAX

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def test_ok_body_returned(self):
        from common import fetch_with_deadline

        with mock.patch(
            "common.urllib.request.urlopen",
            return_value=self._OkResp(),
        ):
            self.assertEqual(fetch_with_deadline("http://h/x", 10), b"tiny-body")

    def test_oversized_body_rejected(self):
        from common import fetch_with_deadline

        with mock.patch(
            "common.urllib.request.urlopen",
            return_value=self._HugeResp(),
        ):
            with self.assertRaisesRegex(RuntimeError, "body too large"):
                fetch_with_deadline("http://h/x", 10)

    def test_deadline_open_oversized_body_rejected(self):
        from common import deadline_open

        with mock.patch(
            "common.urllib.request.urlopen",
            return_value=self._HugeResp(),
        ):
            with self.assertRaisesRegex(RuntimeError, "body too large"):
                deadline_open("http://h/x", 10)


class TestFetchWithMirrorMaxBytes(unittest.TestCase):
    """``fetch_with_mirror`` 的 ``max_bytes`` 透传：静态黑名单调用方须能放大
    上限读取数十 MB 正文，默认 16MiB 仍拒绝巨型响应。"""

    class _OkResp:
        status = 200
        headers = {}

        def read(self, n):
            return b"static-body"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _HugeResp:
        status = 200
        headers = {}

        def read(self, n):
            return b"\x00" * (17 * 1024 * 1024)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def test_default_cap_rejects_oversized(self):
        from common import fetch_with_mirror

        with mock.patch(
            "common.urllib.request.urlopen",
            return_value=self._HugeResp(),
        ):
            with self.assertRaisesRegex(RuntimeError, "body too large"):
                fetch_with_mirror("http://h/x", 10)

    def test_explicit_large_cap_allows_oversized(self):
        from common import fetch_with_mirror

        with mock.patch(
            "common.urllib.request.urlopen",
            return_value=self._HugeResp(),
        ):
            body = fetch_with_mirror("http://h/x", 10, max_bytes=32 * 1024 * 1024)
            self.assertEqual(body, b"\x00" * (17 * 1024 * 1024))

    def test_max_bytes_zero_keeps_default(self):
        from common import fetch_with_mirror

        with mock.patch(
            "common.urllib.request.urlopen",
            return_value=self._OkResp(),
        ):
            self.assertEqual(
                fetch_with_mirror("http://h/x", 10, max_bytes=0),
                b"static-body",
            )


class TestFetchWithMirrorOrdering(unittest.TestCase):
    """``fetch_with_mirror`` 候选次序：主源成功即返回不碰镜像；主源失败按
    镜像兜底；全部候选失败时抛*最后*一个候选的错误（不吞错不假成功）。"""

    def _req_ok(self):
        """单请求成功替身：主源（非 raw）无镜像时也应只请求一次。"""
        calls = {"n": 0}

        def ok(req, timeout=None):
            calls["n"] += 1
            return TestFetchWithMirrorMaxBytes._OkResp()

        return ok, calls

    def test_primary_success_does_not_touch_mirror(self):
        from common import fetch_with_mirror

        ok, calls = self._req_ok()
        with mock.patch("common.urllib.request.urlopen", side_effect=ok):
            with mock.patch(
                "common.mirror_urls",
                return_value=["http://mirror/x"],
            ):
                self.assertEqual(fetch_with_mirror("http://h/x", 10), b"static-body")
        self.assertEqual(calls["n"], 1)

    def test_primary_failure_falls_back_to_mirror(self):
        from common import fetch_with_mirror

        se = [
            urllib.error.HTTPError("http://h/x", 404, "nf", None, None),
            TestFetchWithMirrorMaxBytes._OkResp(),
        ]
        with mock.patch("common.urllib.request.urlopen", side_effect=se):
            with mock.patch(
                "common.mirror_urls",
                return_value=["http://mirror/x"],
            ):
                body = fetch_with_mirror("http://h/x", 10)
        self.assertEqual(body, b"static-body")

    def test_all_candidates_failed_raises_last(self):
        from common import fetch_with_mirror

        se = [
            urllib.error.HTTPError("http://h/x", 404, "nf", None, None),
            urllib.error.HTTPError("http://mirror/x", 502, "bad", None, None),
        ]
        with mock.patch("common.urllib.request.urlopen", side_effect=se):
            with mock.patch(
                "common.mirror_urls",
                return_value=["http://mirror/x"],
            ):
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    fetch_with_mirror("http://h/x", 10)
        self.assertEqual(cm.exception.code, 502)


class TestErrName(unittest.TestCase):
    """err_name 只返回异常类型名，不输出 URL/token（防日志泄漏契约）。"""

    def test_returns_type_name(self):
        self.assertEqual(err_name(TimeoutError(
            "fetch deadline exceeded (15s): https://x/?token=secret"
        )), "TimeoutError")
        self.assertEqual(err_name(ValueError("boom")), "ValueError")

    def test_urlerror_url_not_leaked(self):
        import urllib.error
        err = urllib.error.URLError(
            "connection refused to https://api.example.com/?token=SECRET"
        )
        self.assertEqual(err_name(err), "URLError")
        self.assertNotIn("SECRET", err_name(err))
        self.assertNotIn("example.com", err_name(err))

    def test_hpe_source_name(self):
        import urllib.error
        err = urllib.error.HTTPError("https://x/?token=S", 403, "x", {}, None)
        self.assertEqual(err_name(err), "HTTPError")


class TestLoadKeysGuards(unittest.TestCase):
    def _write(self, td: Path, data) -> Path:
        p = Path(td) / "x.json"
        p.write_text(__import__("json").dumps(data), encoding="utf-8")
        return p

    def test_speed_keys_tolerates_malformed_top_level(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = self._write(Path(td), {"proxies": ["not-a-dict"]})
            self.assertEqual(load_speed_keys(p), set())
            p2 = self._write(Path(td), "not-a-dict")
            self.assertEqual(load_speed_keys(p2), set())

    def test_uptime_keys_filters_below_min_pct_and_non_int(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = self._write(Path(td), {"proxies": {
                "a": {"pct7": 95}, "b": {"pct7": 79}, "c": {"pct7": "90"}}})
            self.assertEqual(load_uptime_keys(path=p), {"a"})

    def test_china_stable_requires_reachable_streak2_flip1(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = self._write(Path(td), {"proxies": {
                "ok": {"verdict": "reachable", "streak": 2, "flip": 1},
                "flip2": {"verdict": "reachable", "streak": 2, "flip": 2},
                "streak1": {"verdict": "reachable", "streak": 1, "flip": 0},
                "unreach": {"verdict": "unreachable", "streak": 5, "flip": 0},
                "no_flip": {"verdict": "reachable", "streak": 3},
                "non_int": {"verdict": "reachable", "streak": "2", "flip": 0},
            }})
            self.assertEqual(load_china_stable_keys(p), {"ok", "no_flip"})


class TestReadJsonNonObject(unittest.TestCase):
    def test_non_object_top_level_returns_empty_dict(self):
        import tempfile
        for payload in ('[]', '"str"', '3', 'true', 'null'):
            with tempfile.TemporaryDirectory() as td:
                p = Path(td) / "x.json"
                p.write_text(payload, encoding="utf-8")
                self.assertEqual(read_json(p), {}, msg=payload)

    def test_broken_and_missing_return_empty_dict(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.json"
            p.write_text("{not json", encoding="utf-8")
            self.assertEqual(read_json(p), {})
            self.assertEqual(read_json(Path(td) / "nope.json"), {})

    def test_object_passthrough(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.json"
            p.write_text('{"a": [1, 2]}', encoding="utf-8")
            self.assertEqual(read_json(p), {"a": [1, 2]})


class TestWriteTextIfChanged(unittest.TestCase):
    def test_skip_when_content_identical(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.txt"
            p.write_text("hello", encoding="utf-8")
            mtime = p.stat().st_mtime_ns
            self.assertFalse(write_text_if_changed(p, "hello"))
            self.assertEqual(p.read_text(), "hello")
            # mtime unchanged → no rewrite
            self.assertEqual(p.stat().st_mtime_ns, mtime)

    def test_writes_new_content(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.txt"
            self.assertTrue(write_text_if_changed(p, "abc"))
            self.assertEqual(p.read_text(), "abc")

    def test_atomic_write_creates_parent(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "sub" / "dir" / "f.txt"
            self.assertTrue(write_text_if_changed(p, "deep"))
            self.assertEqual(p.read_text(), "deep")


if __name__ == "__main__":
    unittest.main()
