"""Tests for china_check.py pure functions."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import china_check as cc
import china_itdog as ci


CN_LINE = "1.2.3.4:2087#\U0001F1FA\U0001F1F8US-10ms-20.07MB/s-GPT-CF"
US_LINE = "5.6.7.8:443#\U0001F1FA\U0001F1F8US-8ms-5.86MB/s"



class TestParseCheckHost(unittest.TestCase):
    def test_ok_report(self):
        payload = {
            "data": {
                cc.CHECKHOST_NODE: {
                    "checks": [{"status": 1, "connectiontime": 185}]
                }
            }
        }
        self.assertEqual(cc.parse_check_host_report(payload)["status"], "ok")
        self.assertTrue(cc.parse_check_host_report(payload)["ok"])
        self.assertEqual(cc.parse_check_host_report(payload)["ms"], 185)

    def test_fail_report(self):
        payload = {
            "data": {
                cc.CHECKHOST_NODE: {
                    "checks": [{"status": 0, "errortext": "Connection timed out"}]
                }
            }
        }
        result = cc.parse_check_host_report(payload)
        self.assertEqual(result["status"], "fail")
        self.assertIn("timed out", result["error"])

    def test_pending_and_bad(self):
        self.assertEqual(cc.parse_check_host_report({"data": {}})["status"], "pending")
        self.assertEqual(cc.parse_check_host_report({})["status"], "error")
        self.assertEqual(cc.parse_check_host_report(None)["status"], "error")


class TestParseXxapi(unittest.TestCase):
    def test_ok(self):
        result = cc.parse_xxapi({"code": 200, "data": {"ping": "207ms"}})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["ms"], 207.0)

    def test_ok_float(self):
        result = cc.parse_xxapi({"code": 200, "data": {"ping": 42.5}})
        self.assertTrue(result["ok"])
        self.assertEqual(result["ms"], 42.5)

    def test_fail(self):
        result = cc.parse_xxapi({"code": 200, "data": {"ping": "failed"}})
        self.assertEqual(result["status"], "fail")

    def test_bad(self):
        self.assertEqual(cc.parse_xxapi({})["status"], "error")
        self.assertEqual(cc.parse_xxapi(None)["status"], "error")
        self.assertEqual(cc.parse_xxapi({"code": 500})["status"], "error")


class TestParseJkapi(unittest.TestCase):
    def test_ok(self):
        report = (
            "=== TCPing测试报告 ===\n"
            "目标地址: 223.5.5.5 (223.5.5.5)\n"
            "目标端口: 443\n"
            "最快延迟: 9.65 ms\n"
            "最慢延迟: 12.13 ms\n"
            "平均延迟: 10.95 ms\n"
            "延迟波动: 2.48 ms\n"
            "测试节点:浙江宁波电信\n"
        )
        result = cc.parse_jkapi(report)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["ok"])
        self.assertAlmostEqual(result["ms"], 10.95)

    def test_fail(self):
        result = cc.parse_jkapi("所有测试均失败，请检查目标可用性")
        self.assertEqual(result["status"], "fail")
        self.assertFalse(result["ok"])

    def test_report_without_avg_inconclusive(self):
        result = cc.parse_jkapi("=== TCPing测试报告 ===\n")
        self.assertEqual(result["status"], "inconclusive")

    def test_unrecognized_inconclusive(self):
        self.assertEqual(cc.parse_jkapi("")["status"], "inconclusive")
        self.assertEqual(cc.parse_jkapi("server error")["status"], "inconclusive")


class TestParsePingpePage(unittest.TestCase):
    def test_extracts_cookie_token_and_cn_ids(self):
        html = (
            "<script>document.cookie=\"antiflood=abc123def;max-age=86400\";"
            "</script>\n"
            "var taskStartToken = \"eyJ0eXAi\";\n"
            "<tr id='ping-CN_5-tr' data-pinger-id='CN_5' data-location='China, Chengdu'>"
            "<tr id='ping-CN_7-tr' data-pinger-id='CN_7' data-location='China, Shanghai'>"
        )
        parsed = cc.parse_pingpe_page(html)
        self.assertEqual(parsed["cookie"], "abc123def")
        self.assertEqual(parsed["token"], "eyJ0eXAi")
        self.assertEqual(parsed["cn_ids"], ["CN_5", "CN_7"])
        self.assertTrue(parsed["has_page"])

    def test_no_cookie_redirect_page(self):
        html = "<html>redirecting<script>document.cookie=\"antiflood=feedbeef;\"</script></html>"
        parsed = cc.parse_pingpe_page(html)
        self.assertEqual(parsed["cookie"], "feedbeef")
        self.assertFalse(parsed["has_page"])

    def test_fallback_row_ids(self):
        html = "<tr id='ping-CN_9-tr' data-location='China, Qingdao'>"
        parsed = cc.parse_pingpe_page(html)
        self.assertEqual(parsed["cn_ids"], ["CN_9"])


class TestParsePingpeResults(unittest.TestCase):
    def test_aggregates_cn_nodes(self):
        payload = {"data": [
            {"node_id": "CN_5", "result": 174600},
            {"node_id": "CN_7", "result": 0},
            {"node_id": "CN_9", "result": 1},
            {"node_id": "US_1", "result": 1},
        ]}
        agg = cc.parse_pingpe_results(payload, ["CN_5", "CN_7", "CN_9"])
        self.assertEqual(agg["reported"], 3)
        self.assertEqual(agg["ok"], 2)
        self.assertEqual(agg["ms"], 174.6)

    def test_filters_by_cn_set(self):
        payload = {"data": [{"node_id": "CN_5", "result": 1}]}
        agg = cc.parse_pingpe_results(payload, ["CN_5", "CN_7"])
        self.assertEqual(agg["reported"], 1)

    def test_bad_payload(self):
        self.assertEqual(cc.parse_pingpe_results({}, [])["reported"], 0)
        self.assertEqual(cc.parse_pingpe_results(None, [])["reported"], 0)


class TestPingpeVerdict(unittest.TestCase):
    def test_majority_ok(self):
        verdict = cc.pingpe_verdict({"reported": 13, "ok": 8})
        self.assertEqual(verdict["status"], "ok")

    def test_majority_fail(self):
        verdict = cc.pingpe_verdict({"reported": 13, "ok": 2})
        self.assertEqual(verdict["status"], "fail")

    def test_inconclusive_few_reported(self):
        verdict = cc.pingpe_verdict({"reported": 3, "ok": 3})
        self.assertEqual(verdict["status"], "inconclusive")


class TestParseTcpping(unittest.TestCase):
    def test_nodes(self):
        payload = {"data": [
            {"name": "bj", "ms": 120, "status": "ok"},
            {"name": "sh", "ms": "80", "status": "ok"},
            {"name": "gz", "ms": None, "status": "timeout"},
        ]}
        result = cc.parse_tcpping(payload)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["ms"], 100.0)

    def test_fail_majority(self):
        payload = {"data": [
            {"ms": None, "status": "fail"},
            {"ms": 10, "status": "ok"},
        ]}
        self.assertEqual(cc.parse_tcpping(payload)["status"], "fail")

    def test_empty(self):
        self.assertEqual(cc.parse_tcpping({})["status"], "error")
        self.assertEqual(cc.parse_tcpping("x")["status"], "error")


class TestMergeVerdict(unittest.TestCase):
    def test_any_ok_reachable(self):
        sources = {
            "check_host": {"status": "ok", "ok": True, "ms": 180},
            "xxapi": {"status": "ok", "ok": True, "ms": 120},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["ms"], 120.0)

    def test_single_ok_uncertain(self):
        sources = {
            "check_host": {"status": "ok", "ok": True, "ms": 180},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "uncertain")

    def test_both_l2_fail_unreachable(self):
        sources = {
            "check_host": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_xxapi_jkapi_double_ok_reachable(self):
        """两只免额单节点源（xxapi+jjkapi）双 ok → reachable，无需 check-host。"""
        sources = {
            "xxapi": {"status": "ok", "ok": True, "ms": 43},
            "jkapi": {"status": "ok", "ok": True, "ms": 11},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["ms"], 11.0)

    def test_xxapi_jkapi_both_fail_unreachable(self):
        sources = {
            "xxapi": {"status": "fail", "ok": False, "ms": None},
            "jkapi": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_xxapi_jkapi_error_skipped(self):
        sources = {
            "xxapi": {"status": "error", "ok": False, "ms": None},
            "jkapi": {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "skipped")

    def test_pingpe_fail_plus_l2_fail(self):
        sources = {
            "check_host": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "ok", "ok": True, "ms": 90},
            "pingpe": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_single_fail_uncertain(self):
        sources = {
            "check_host": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_all_error_skipped(self):
        sources = {
            "check_host": {"status": "error", "ok": False, "ms": None},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "skipped")

    def test_heuristic_only_uncertain(self):
        sources = {
            "check_host": {"status": "error", "ok": False, "ms": None},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "skipped")

    def test_itdog_single_node_weak_ratio_uncertain(self):
        """itdog 仅 1/18 节点可达（ratio≈0.06）→ 不得独立判定 reachable。"""
        sources = {
            "itdog": {"status": "ok", "ok": True, "ms": 200,
                      "level": "tcp", "ok_nodes": 1, "nodes": 18,
                      "ratio": 0.056},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "uncertain")

    def test_itdog_good_ratio_reachable(self):
        sources = {
            "itdog": {"status": "ok", "ok": True, "ms": 90,
                      "level": "http", "ok_nodes": 14, "nodes": 18,
                      "ratio": 0.78},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "reachable")

    def test_itdog_weak_plus_two_single_sources_reachable(self):
        """弱 itdog 不能单独定论，但两路单节点源交叉仍可判 reachable。"""
        sources = {
            "itdog": {"status": "ok", "ok": True, "ms": 200,
                      "ok_nodes": 1, "nodes": 18, "ratio": 0.056},
            "check_host": {"status": "ok", "ok": True, "ms": 150},
            "xxapi": {"status": "ok", "ok": True, "ms": 130},
        }
        # itdog 弱 + check_host/xxapi 双确认 → 仍走单节点交叉线
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "reachable")

    def test_tcptest_good_ratio_reachable(self):
        """tcptest（多节点 TCP）成功率高 → 单源独立判 reachable。"""
        sources = {
            "tcptest": {"status": "ok", "ok": True, "ms": 60,
                        "level": "tcp", "ok_nodes": 8, "nodes": 10,
                        "ratio": 0.8},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "reachable")
        self.assertEqual(
            cc.merge_verdict(sources)["level"], "tcp")

    def test_tcptest_weak_ratio_uncertain(self):
        """tcptest 仅少数节点可达（ratio 低）→ 不得单源定论。"""
        sources = {
            "tcptest": {"status": "ok", "ok": True, "ms": 200,
                        "level": "tcp", "ok_nodes": 1, "nodes": 10,
                        "ratio": 0.1},
            "check_host": {"status": "error", "ok": False, "ms": None},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_tcptest_fail_plus_l2_fail_unreachable(self):
        """tcptest 全节点失败 + check_host/xxapi 失败 → unreachable。"""
        sources = {
            "tcptest": {"status": "fail", "ok": False, "ms": None,
                        "ok_nodes": 0, "nodes": 10, "ratio": 0.0},
            "check_host": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_new_multi_sources_strong_reachable(self):
        """新增四源（pingloc/antping/tcpingcn/chinaz）达标 → 独立判 reachable。"""
        for idx, (name, src) in enumerate([
            ("pingloc", {"status": "ok", "ok": True, "ms": 30, "level": "tcp",
                         "ok_nodes": 12, "nodes": 12, "ratio": 1.0}),
            ("antping", {"status": "ok", "ok": True, "ms": 20, "level": "tcp",
                         "ok_nodes": 150, "nodes": 160, "ratio": 0.94}),
            ("tcpingcn", {"status": "ok", "ok": True, "ms": 15, "level": "tcp",
                          "ok_nodes": 150, "nodes": 160, "ratio": 0.94}),
            ("chinaz", {"status": "ok", "ok": True, "ms": 40, "level": "icmp",
                        "ok_nodes": 45, "nodes": 50, "ratio": 0.90}),
        ]):
            self.assertEqual(
                cc.merge_verdict({name: src})["verdict"],
                "reachable", msg=f"{name} strong → reachable")

    def test_chinaz_degenerate_sample_not_strong(self):
        """多节点源残片样本（<MULTI_MIN_NODES 节点）不得当强确认。"""
        sources = {
            "chinaz": {"status": "ok", "ok": True, "ms": 40, "level": "icmp",
                       "ok_nodes": 1, "nodes": 1, "ratio": 1.0},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_new_multi_fail_combos_unreachable(self):
        """新源多节点失败 + 单节点失败 → unreachable；两大节点失败也 → unreachable。"""
        cases = [
            {"tcpingcn": {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                          "nodes": 160, "ratio": 0.0},
             "check_host": {"status": "fail", "ok": False, "ms": None}},
            {"antping": {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                         "nodes": 160, "ratio": 0.0},
             "chinaz": {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                        "nodes": 50, "ratio": 0.0}},
            {"pingloc": {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                         "nodes": 12, "ratio": 0.0},
             "xxapi": {"status": "fail", "ok": False, "ms": None}},
        ]
        for sources in cases:
            self.assertEqual(
                cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_coffee_strong_reachable(self):
        sources = {
            "coffee": {"status": "ok", "ok": True, "ms": 5, "level": "icmp",
                       "ok_nodes": 15, "nodes": 18, "ratio": 0.83},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "reachable")

    def test_coffee_degenerate_not_strong(self):
        sources = {
            "coffee": {"status": "ok", "ok": True, "ms": 5, "level": "icmp",
                       "ok_nodes": 1, "nodes": 18, "ratio": 0.056},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "uncertain")


class TestAnnotations(unittest.TestCase):
    def test_has_cn_note(self):
        self.assertTrue(cc.has_cn_note("1.2.3.4:80#US-1ms-CN"))
        self.assertTrue(cc.has_cn_note("1.2.3.4:80#US-1ms-GPT-CN-81"))
        self.assertFalse(cc.has_cn_note("1.2.3.4:80#US-1ms"))
        self.assertTrue(cc.has_cn_note("1.2.3.4:80#CN-CN"))  # CC 后确有 -CN 备注
        self.assertFalse(cc.has_cn_note("1.2.3.4:80#CN"))  # 国家码 CN 不算备注
        self.assertFalse(cc.has_cn_note("1.2.3.4:80#\U0001F1E8\U0001F1F3CN-10ms-1MB/s"))

    def test_annotate_cn_idempotent(self):
        self.assertEqual(cc.annotate_cn("1.2.3.4:80#US-1ms-CN"), "1.2.3.4:80#US-1ms-CN")
        self.assertEqual(cc.annotate_cn("1.2.3.4:80#US-1ms"), "1.2.3.4:80#US-1ms-CN")

    def test_generate_all_cn(self):
        text = "1.2.3.4:80#US-1ms\n5.6.7.8:80#US-2ms-CN\n9.9.9.9:80#US-3ms\n"
        reachable = {"1.2.3.4:80#US", "9.9.9.9:80#US"}
        cn_text, count = cc.generate_all_cn(text, reachable)
        self.assertEqual(count, 2)
        self.assertIn("1.2.3.4:80#US-1ms-CN", cn_text)
        self.assertNotIn("5.6.7.8:80#US", cn_text)  # 历史 -CN 已不收
        self.assertIn("9.9.9.9:80#US-3ms-CN", cn_text)

    def test_generate_all_cn_fallback_keys_keeps_history(self):
        """上一轮可达、本轮 uncertain 的键经 fallback 保留，维持 CN 清单 ≥1 万。"""
        text = "1.2.3.4:80#US-42ms-5.00MB/s-fast-90\n"
        reachable = set()
        fallback = {"1.2.3.4:80#US"}
        cn_ms = {"1.2.3.4:80#US": 236.4}
        cn_text, count = cc.generate_all_cn(
            text, reachable, cn_ms=cn_ms, fallback_keys=fallback
        )
        self.assertEqual(count, 1)
        # 兜底行同样走大陆延迟/速度重写，与当期一致
        self.assertIn("1.2.3.4:80#US-236ms-≈2.0MB/s-fast-CN-90", cn_text)

    def test_generate_all_cn_full_pool_subset(self):
        # 全量池文本里非限量（超出每国 20 条）的行同样进入 all_cn.txt
        text = "\n".join(f"10.{i}.0.{i}:80#US-{i}ms" for i in range(1, 30)) + "\n"
        reachable = {f"10.{i}.0.{i}:80#US" for i in range(1, 30)}
        cn_text, count = cc.generate_all_cn(text, reachable)
        self.assertEqual(count, 29)
        self.assertIn("10.25.0.25:80#US-25ms-CN", cn_text)
    def test_generate_all_cn_sorted_by_cn_ms(self):
        text = (
            "1.1.1.1:443#US-9ms-CN\n"
            "2.2.2.2:443#US-5ms-CN\n"
            "3.3.3.3:443#US-1ms-CN\n"
        )
        reachable = {"1.1.1.1:443#US", "2.2.2.2:443#US", "3.3.3.3:443#US"}
        cn_ms = {"1.1.1.1:443#US": 300, "2.2.2.2:443#US": 80, "3.3.3.3:443#US": 500}
        cn_text, count = cc.generate_all_cn(text, reachable, cn_ms)
        self.assertEqual(count, 3)
        lines = cn_text.strip().splitlines()
        # 大陆实测延迟升序：80ms < 300ms < 500ms（海外延迟顺序被覆盖）
        self.assertEqual(
            [l.split("#")[0] for l in lines],
            ["2.2.2.2:443", "1.1.1.1:443", "3.3.3.3:443"],
        )

    def test_generate_all_cn_rewrites_latency_to_cn_rtt(self):
        """CN 清单行内 ms 替换为大陆实测值，速度替换为大陆视角估算 ≈。"""
        text = "1.1.1.1:443#US-42ms-5.00MB/s-fast-90\n"
        reachable = {"1.1.1.1:443#US"}
        cn_ms = {"1.1.1.1:443#US": 236.4}
        cn_text, _n = cc.generate_all_cn(text, reachable, cn_ms)
        self.assertIn("1.1.1.1:443#US-236ms-≈2.0MB/s-fast-CN-90", cn_text)
        # 无大陆观测的行：保留延迟（无替代），但速度无从推算 → 移除海外值
        text2 = "2.2.2.2:443#US-77ms-3.00MB/s\n"
        cn_text2, _n = cc.generate_all_cn(
            text2, {"2.2.2.2:443#US"}, cn_ms, http_keys=set())
        self.assertNotIn("3.00MB/s", cn_text2)
        self.assertIn("2.2.2.2:443#US-77ms-CN", cn_text2)

    def test_rewrite_latency_helper(self):
        import common
        line = "1.2.3.4:80#US-1000ms-x"
        self.assertEqual(common.rewrite_latency(line, 250.6),
                         "1.2.3.4:80#US-251ms-x")
        self.assertEqual(common.rewrite_latency(line, None), line)
        self.assertEqual(common.rewrite_latency(line, 0), line)
        # 无既有 token：原样返回（不注入新语义）
        self.assertEqual(common.rewrite_latency("1.2.3.4:80#US", 99),
                         "1.2.3.4:80#US")

    def test_generate_all_cn_missing_ms_last_stable(self):
        text = "1.1.1.1:443#US-9ms-CN\n2.2.2.2:443#US-5ms-CN\n3.3.3.3:443#US-1ms-CN\n"
        reachable = {"1.1.1.1:443#US", "2.2.2.2:443#US"}
        cn_ms = {"1.1.1.1:443#US": 120}
        cn_text, _ = cc.generate_all_cn(text, reachable, cn_ms)
        lines = cn_text.strip().splitlines()
        # 有大陆延迟的排最前；缺失的按原序稳定垫底
        # （3.3.3.3 不在当期可达集 → 不再入池）
        self.assertEqual(lines[0].split("#")[0], "1.1.1.1:443")
        self.assertEqual(
            [l.split("#")[0] for l in lines[1:]],
            ["2.2.2.2:443"],
        )

    def test_cn_display_ms_prefers_trusted_l2_over_noise(self):
        """CN 展示延迟优先可信大陆探测；L3 复核源 1ms 噪声不得冒充真实值。"""
        import common

        cases = {
            # antping 1ms vs xxapi 234ms → 取 234（大陆视角）
            "1.1.1.1:443#US": {"ms": 1, "sources": {
                "xxapi": {"status": "ok", "ms": 234.0},
                "antping": {"status": "ok", "ms": 1}}},
            # xxapi 35 / jkapi 80 → 取 35（多大陆源取最小）
            "2.2.2.2:443#US": {"sources": {
                "xxapi": {"status": "ok", "ms": 35.0},
                "jkapi": {"status": "ok", "ms": 80.0}}},
            # 无大陆探测，回退合并 ms
            "3.3.3.3:443#US": {"ms": 42, "sources": {
                "tcptest": {"status": "ok", "ms": 42}}},
            # 无 sources 老条目：用 entry ms
            "4.4.4.4:443#US": {"ms": 88},
            # 噪声且无 valid ms → None（不展示伪造值）
            "5.5.5.5:443#US": {"ms": 0, "sources": {"antping": {"status": "ok", "ms": 1}}},
            # merged ms 被 1ms 污染，但 tcptest 有 88ms 可信读数 → 取 88
            "6.6.6.6:443#US": {"ms": 1, "sources": {
                "antping": {"status": "ok", "ms": 1},
                "tcptest": {"status": "ok", "ms": 88.0}}},
            # 唯一 ok 为 chinaz（纯 ICMP）且给 2ms 假象 → 不得冒充大陆延迟；
            # entry 合并 ms 亦被 2ms 污染 → None（宁缺勿假）
            "7.7.7.7:443#US": {"ms": 2, "sources": {
                "chinaz": {"status": "ok", "ms": 2.0}}},
            # chinaz 假象 + tcptest 真实 174ms → 取 174（非 2）
            "8.8.8.8:443#US": {"sources": {
                "chinaz": {"status": "ok", "ms": 2.0},
                "tcptest": {"status": "ok", "ms": 174.8}}},
        }
        got = {k: common.cn_display_ms(v) for k, v in cases.items()}
        self.assertEqual(got, {
            "1.1.1.1:443#US": 234.0,
            "2.2.2.2:443#US": 35.0,
            "3.3.3.3:443#US": 42,
            "4.4.4.4:443#US": 88,
            "5.5.5.5:443#US": None,
            "6.6.6.6:443#US": 88.0,
            "7.7.7.7:443#US": None,
            "8.8.8.8:443#US": 174.8,
        })

    def test_cn_health_report_counts_junk_and_no_ms(self):
        """清单自检：行数 / ≥2ms 之外必属噪声或缺失，须精确计数。"""
        text = (
            "1.2.3.4:443#US→US-35ms-≈3.1MB/s-CN\n"
            "5.6.7.8:443#US→US-1ms-≈1MB/s-CN\n"     # 噪声 1ms
            "0.0.0.1:443#US→US-2ms-≈1MB/s-CN\n"     # ≤2ms 边界算噪声
            "9.9.9.9:443#US→US-78.5ms-≈1MB/s-CN\n"
            "7.7.7.7:443#US→US-≈1MB/s-CN\n"         # 无 ms
        )
        self.assertEqual(cc.cn_health_report(text),
                         {"count": 5, "no_ms": 1, "junk_ms": 2})

    def test_check_cn_health_warns_on_small_pool(self, ):
        """池 <1 万须告警（完整池底线），达标则静默返回报告。"""
        good = "1.2.3.4:443#US→US-35ms-≈3.1MB/s-CN\n" * 10002
        self.assertEqual(cc.check_cn_health(good)["count"], 10002)
        small = "1.2.3.4:443#US→US-35ms-≈1MB/s-CN\n" * 9999
        self.assertEqual(cc.check_cn_health(small)["count"], 9999)

    def test_cn_lists_full_pool_noise_sanitized_end_to_end(self):
        """契约回归：CN 清单保持全可达池，且 1ms 噪声经 cn_display_ms 消毒。

        组合 generate_all_cn + cn_display_ms，覆盖用户可见性质：慢键保留（不因
        延迟被砍）、噪声 ms 不落地、速度估算与诚实读数联动。"""
        import common

        pool = (
            "167.88.160.144:8443#US→US-88ms-≈1MB/s-DC-V4\n"   # 噪声源(antping 1ms) vs L2 234
            "8.8.8.8:443#DE→DE-30ms-≈1MB/s-GPT-V4\n"          # L2 35ms
            "2.2.2.2:443#US→US-10ms-≈1MB/s-RES-V4\n"          # 无 L2，回退 42ms
        )
        entries = {
            "167.88.160.144:8443#US": {"verdict": "reachable", "sources": {
                "xxapi": {"status": "ok", "ms": 234.0},
                "antping": {"status": "ok", "ms": 1}}},
            "8.8.8.8:443#DE": {"verdict": "reachable", "sources": {
                "xxapi": {"status": "ok", "ms": 35.0}}},
            "2.2.2.2:443#US": {"verdict": "reachable", "ms": 42, "sources": {
                "tcptest": {"status": "ok", "ms": 42}}},
        }
        all_keys = set(entries)
        cn_ms = {k: common.cn_display_ms(e) for k, e in entries.items()
                 if common.cn_display_ms(e) is not None}
        text, n = cc.generate_all_cn(pool, all_keys, cn_ms)
        self.assertEqual(n, 3)                     # 全达保留，未被延迟砍掉
        self.assertIn("167.88.160.144:8443#US→US-234ms", text)   # 234 非 1
        self.assertIn("8.8.8.8:443#DE→DE-35ms", text)
        self.assertIn("2.2.2.2:443#US→US-42ms", text)
        self.assertNotIn("-1ms-", text)            # 噪声不得以任何形式落地
        self.assertEqual(cc.cn_health_report(text), {"count": 3, "no_ms": 0, "junk_ms": 0})

    def test_generate_all_cn_fallback_keeps_pool_volume(self):
        """契约回归：当期 reachable 跌到 1 万以下时，fallback_keys 把上轮可达、
        本轮无失败源的键保留进 CN 清单，维持用户硬约束（全量池 ≥ MIN_CN_POOL）。"""
        import common
        pool = "1.2.3.4:80#US-80ms-5MB/s-fast-90\n"
        # 本轮判定失败：reachable 为空集（模拟全源抖动/配额导致整批 uncertain）
        reachable = set()
        fallback = {"1.2.3.4:80#US"}
        # 大陆读数来自上一轮 entry
        cn_ms = {"1.2.3.4:80#US": 200.0}
        text, n = cc.generate_all_cn(pool, reachable, cn_ms, fallback_keys=fallback)
        self.assertEqual(n, 1)
        self.assertIn("1.2.3.4:80#US-200ms-≈2.4MB/s", text)
        self.assertIn("-CN", text)
        self.assertEqual(cc.cn_health_report(text), {"count": 1, "no_ms": 0, "junk_ms": 0})
        # 无 fallback 时（old 行为）→ 空清单
        text0, n0 = cc.generate_all_cn(pool, reachable, cn_ms)
        self.assertEqual(n0, 0)

    def test_generate_all_cn_keeps_full_reachable_pool(self):
        """CN 清单保持完整：全可达键都保留，即使其延迟很慢（噪声也必须上路）。"""
        text = "1.1.1.1:443#US-234ms-CN\n2.2.2.2:443#US-1ms-CN\n3.3.3.3:443#US-8ms\n"
        reachable = {"1.1.1.1:443#US", "2.2.2.2:443#US", "3.3.3.3:443#US"}
        cn_text, count = cc.generate_all_cn(text, reachable, {
            "1.1.1.1:443#US": 234.0, "2.2.2.2:443#US": 35.0, "3.3.3.3:443#US": 8.0,
        })
        self.assertEqual(count, 3)
        for k in reachable:
            self.assertIn(k, cn_text)

    def test_generate_all_cn_no_map_keeps_pool_order(self):
        text = "1.1.1.1:443#US-9ms-CN\n2.2.2.2:443#US-5ms-CN\n"
        reachable = {"1.1.1.1:443#US", "2.2.2.2:443#US"}
        cn_text, count = cc.generate_all_cn(text, reachable)
        self.assertEqual(count, 2)
        self.assertEqual(
            [l.split("#")[0] for l in cn_text.strip().splitlines()],
            ["1.1.1.1:443", "2.2.2.2:443"],
        )


class TestLoadCnPool(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cc_pool_"))
        self._all_file = cc.VALID_ALL_FILE
        self._ltd_file = cc.VALID_ALL_LTD_FILE
        cc.VALID_ALL_FILE = self.tmp / "all.txt"
        cc.VALID_ALL_LTD_FILE = self.tmp / "all_ltd.txt"

    def tearDown(self):
        cc.VALID_ALL_FILE = self._all_file
        cc.VALID_ALL_LTD_FILE = self._ltd_file

    def test_prefers_all_txt(self):
        (self.tmp / "all_ltd.txt").write_text("1.0.0.1:80#US-1ms\n", encoding="utf-8")
        (self.tmp / "all.txt").write_text("2.0.0.1:80#US-2ms\n", encoding="utf-8")
        self.assertEqual(cc.load_cn_pool(), "2.0.0.1:80#US-2ms\n")

    def test_falls_back_to_all_ltd(self):
        (self.tmp / "all_ltd.txt").write_text("1.0.0.1:80#US-1ms\n", encoding="utf-8")
        self.assertEqual(cc.load_cn_pool(), "1.0.0.1:80#US-1ms\n")

    def test_missing_pool(self):
        self.assertEqual(cc.load_cn_pool(), "")


class TestRateLimiter(unittest.TestCase):
    def test_allows_within_window(self):
        limiter = cc.RateLimiter(window=0.2, per_window=2, hour_cap=10)
        limiter.acquire()
        limiter.acquire()

    def test_blocks_beyond_window(self):
        limiter = cc.RateLimiter(window=0.3, per_window=1, hour_cap=10)
        limiter.acquire()
        start = None
        # 第二次 acquire 需等待窗口内放行（约 0.3s）
        import time

        t0 = time.monotonic()
        limiter.acquire()
        self.assertGreaterEqual(time.monotonic() - t0, 0.25)

    def test_hour_cap(self):
        limiter = cc.RateLimiter(window=10.0, per_window=100, hour_cap=2)
        limiter.acquire()
        limiter.acquire()
        with self.assertRaises(cc.RateLimited):
            limiter.acquire()


class TestLoadSample(unittest.TestCase):
    def _path(self, name):
        return Path(tempfile.mkdtemp(prefix="cc_")) / name

    def test_load_sample_respects_limit(self):
        path = self._path("china_check_sample.txt")
        path.write_text(
            "1.1.1.1:80#US-1ms\n2.2.2.2:80#US-2ms\n3.3.3.3:80#US-3ms\n",
            encoding="utf-8",
        )
        sample, used = cc.load_sample(path, limit=2)
        self.assertEqual(len(sample), 2)
        self.assertEqual(sample[0][1], "1.1.1.1:80#US")
        self.assertEqual(used, path)

    def test_load_sample_skips_bad_lines(self):
        path = self._path("china_check_sample_bad.txt")
        path.write_text("garbage\n4.4.4.4:80#US-4ms\n", encoding="utf-8")
        sample, _ = cc.load_sample(path, limit=0)
        self.assertEqual([s[1] for s in sample], ["4.4.4.4:80#US"])


class TestBuildEntry(unittest.TestCase):
    def test_build_entry_shape(self):
        item = ("1.2.3.4:2087#US", "1.2.3.4:2087#US", "1.2.3.4", "2087", "US")
        entry = cc.build_entry(item, {
            "check_host": {"status": "ok", "ok": True, "ms": 100},
            "xxapi": {"status": "ok", "ok": True, "ms": 80},
        })
        self.assertEqual(entry["verdict"], "reachable")
        self.assertEqual(entry["ip"], "1.2.3.4")
        self.assertIn("ts", entry)
        self.assertEqual(entry["sources"]["check_host"]["ms"], 100)


class TestItdogMd5(unittest.TestCase):
    def test_md5_16_length_and_slice(self):
        s = "abc"
        self.assertEqual(
            ci.itdog_md5_16(s), hashlib.md5(s.encode()).hexdigest()[8:24]
        )


class TestItdogParseNodes(unittest.TestCase):
    def test_parses_isp_groups(self):
        html = (
            '<select id="node_select">'
            '<optgroup label="中国电信">'
            '<option value="aaa">湖北十堰 - 电信</option>'
            '<option value="bbb">湖北襄阳 - 电信</option>'
            "</optgroup>"
            '<optgroup label="中国联通">'
            '<option value="ccc">山东济南 - 联通</option>'
            "</optgroup>"
            '<optgroup label="中国移动">'
            '<option value="ddd">山东济南2 - 移动</option>'
            "</optgroup>"
            "</select>"
        )
        self.assertEqual(ci.itdog_parse_nodes(html, 1), ["aaa", "ccc", "ddd"])
        self.assertEqual(ci.itdog_parse_nodes(html, 2), ["aaa", "bbb", "ccc", "ddd"])

    def test_stride_sampling_spreads_across_group(self):
        html = (
            '<optgroup label="中国电信">'
            '<option value="n1">北京 - 电信</option>'
            '<option value="n2">山东 - 电信</option>'
            '<option value="n3">上海 - 电信</option>'
            '<option value="n4">广东 - 电信</option>'
            "</optgroup>"
        )
        # 4 取 3：stride=1 → 前 3；8 取 3：stride=2 → 1/3/5 号位
        html8 = (
            '<optgroup label="中国电信">'
            + "".join(f'<option value="m{i}">x</option>' for i in range(1, 9))
            + "</optgroup>"
        )
        self.assertEqual(ci.itdog_parse_nodes(html, 3), ["n1", "n2", "n3"])
        self.assertEqual(ci.itdog_parse_nodes(html8, 3), ["m1", "m3", "m5"])
        # per_isp 超过组内数量 → 全取
        self.assertEqual(ci.itdog_parse_nodes(html, 9), ["n1", "n2", "n3", "n4"])

    def test_missing_group_skipped(self):
        html = '<optgroup label="中国电信"><option value="aaa">x</option></optgroup>'
        self.assertEqual(ci.itdog_parse_nodes(html, 1), ["aaa"])


class TestItdogParseSubmit(unittest.TestCase):
    def test_task_id(self):
        html = "var task_id='20260816105915300ivbsnctru1ylah0';"
        tid, err = ci.itdog_parse_submit(html)
        self.assertEqual(tid, "20260816105915300ivbsnctru1ylah0")
        self.assertEqual(err, "")

    def test_captcha_page(self):
        tid, err = ci.itdog_parse_submit('<div class="clicaptcha"></div>')
        self.assertIsNone(tid)
        self.assertEqual(err, "captcha")

    def test_no_task(self):
        tid, err = ci.itdog_parse_submit("<html>nothing</html>")
        self.assertIsNone(tid)
        self.assertEqual(err, "no task_id")


class TestItdogRecOk(unittest.TestCase):
    def test_http_ok(self):
        ok, ms, level = ci.itdog_rec_ok({"http_code": 200, "connect_time": 0.02, "all_time": 0.05})
        self.assertIs(ok, True)
        self.assertEqual(ms, 20.0)
        self.assertEqual(level, "http")

    def test_tcp_only_port(self):
        ok, ms, level = ci.itdog_rec_ok({"http_code": 0, "connect_time": 0.013, "all_time": 10.0})
        self.assertIs(ok, True)
        self.assertEqual(ms, 13.0)
        self.assertEqual(level, "tcp")

    def test_connect_refused(self):
        ok, _, _ = ci.itdog_rec_ok({"http_code": 0, "connect_time": 0.001, "all_time": 10.0})
        self.assertIs(ok, False)

    def test_connect_timeout(self):
        ok, _, _ = ci.itdog_rec_ok({"http_code": 0, "connect_time": 10.0, "all_time": 10.0})
        self.assertIs(ok, False)

    def test_node_error_inconclusive(self):
        ok, ms, level = ci.itdog_rec_ok({"type": "node_error", "task_num": 1})
        self.assertIsNone(ok)
        self.assertIsNone(ms)
        self.assertIsNone(level)

    def test_tcping_record_ok(self):
        # batch_tcping：result 为 TCP 耗时毫秒字符串
        ok, ms, level = ci.itdog_rec_ok(
            {"ip": "1.2.3.4", "port": "443", "result": "166",
             "node_id": "abc", "task_num": 1, "address": "Anycast/x"})
        self.assertIs(ok, True)
        self.assertEqual(ms, 166.0)
        self.assertEqual(level, "tcp")

    def test_tcping_record_fail(self):
        ok, ms, level = ci.itdog_rec_ok({"result": "-1", "node_id": "abc"})
        self.assertIs(ok, False)
        self.assertIsNone(ms)
        self.assertIsNone(level)

    def test_tcping_record_bad_result(self):
        ok, _, _ = ci.itdog_rec_ok({"result": None, "node_id": "abc"})
        self.assertIs(ok, False)


class TestItdogAggregate(unittest.TestCase):
    def test_any_node_ok(self):
        records = [
            {"task_num": 1, "node_id": "a", "http_code": 0, "connect_time": 0.001},
            {"task_num": 1, "node_id": "b", "http_code": 0, "connect_time": 0.020},
        ]
        agg = ci.itdog_aggregate(records, 1)
        self.assertEqual(agg[1]["status"], "ok")
        self.assertEqual(agg[1]["ms"], 20.0)
        self.assertEqual(agg[1]["level"], "tcp")

    def test_http_level_wins_over_tcp(self):
        records = [
            {"task_num": 1, "node_id": "a", "http_code": 0, "connect_time": 0.020},
            {"task_num": 1, "node_id": "b", "http_code": 200, "connect_time": 0.030},
        ]
        agg = ci.itdog_aggregate(records, 1)
        self.assertEqual(agg[1]["level"], "http")
        # ms 取所有成功节点最小值（含 tcp 节点）
        self.assertEqual(agg[1]["ms"], 20.0)

    def test_all_fail_level_none(self):
        records = [
            {"task_num": 1, "node_id": "a", "http_code": 0, "connect_time": 0.001},
            {"task_num": 1, "node_id": "b", "http_code": 0, "connect_time": 10.0},
        ]
        agg = ci.itdog_aggregate(records, 1)
        self.assertEqual(agg[1]["status"], "fail")
        self.assertIsNone(agg[1]["level"])

    def test_no_records_error(self):
        self.assertEqual(ci.itdog_aggregate([], 2)[2]["status"], "error")
        self.assertEqual(ci.itdog_aggregate([], 2)[1]["status"], "error")

    def test_node_error_only_error(self):
        records = [{"task_num": 1, "node_id": "a", "type": "node_error"}]
        self.assertEqual(ci.itdog_aggregate(records, 1)[1]["status"], "error")


class TestNewMultiSources(unittest.TestCase):
    """新增四源适配器单测（全部 mock HTTP/WS，不触网）。"""

    class _FakeWS:
        """模拟 _WebSocket：预置若干 (kind, msg) 帧，耗尽后 timeout。"""

        def __init__(self, frames):
            self._frames = list(frames)
            self.sent = []
            self.closed = False

        def send_text(self, payload):
            self.sent.append(payload)

        def settimeout(self, t):
            pass

        def read(self):
            if self._frames:
                kind, msg = self._frames.pop(0)
                return kind, msg
            return "timeout", None

        def close(self):
            self.closed = True

    class _FakeCtx:
        """模拟 urlopen 上下文管理器：read 先返回 body 一次，之后返回 b""。"""

        def __init__(self, body):
            self._body = body
            self._done = False

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            if self._done:
                return b""
            self._done = True
            return self._body

    def _wrap_urlopen(self, body):
        """把 body 包成假 urlopen 上下文管理器（read 有穷尽）。"""
        return self._FakeCtx(body)

    def _wrap_nodes_urlopen(self, body):
        return self._FakeCtx(body)

    def test_pingloc_http_ok(self):
        nodes = mock.MagicMock(
            __enter__=mock.MagicMock(return_value=mock.MagicMock(
                read=mock.MagicMock(return_value=json.dumps({"data": [
                    {"id": "n1"}, {"id": "n2"}]}).encode()))),
            __exit__=mock.MagicMock(return_value=False),
        )
        # exec 的 urlopen 返回完整 SSE 流
        sse = (
            "event: start\ndata: {}\n\n"
            "event: callback\ndata: "
            + json.dumps({"node_id": "n1", "latency": 12.4, "ip": "1.2.3.4",
                          "error_code": 0}) + "\n\n"
            "event: callback\ndata: "
            + json.dumps({"node_id": "n2", "latency": None, "ip": "1.2.3.4",
                          "error_code": 111}) + "\n\n"
            "event: done\ndata: {}\n\n"
        ).encode()
        exec_resp = self._wrap_urlopen(sse)
        calls = {"node": True}

        def fake(url, headers, timeout, method="GET", data=None):
            if url.endswith("/api/v1/node/items"):
                return 200, {}, json.dumps({"data": [{"id": "n1"}, {"id": "n2"}]}).encode()
            return 200, {}, json.dumps({"data": {"token": "task_abc"}}).encode()

        with mock.patch.object(cc, "request_follow", side_effect=fake) as mrf, \
             mock.patch.object(cc.urllib.request, "urlopen", return_value=exec_resp):
            out = cc.pingloc_check("1.2.3.4", 10, method="ping")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 1)
        self.assertEqual(out["ms"], 12.4)
        self.assertEqual(out["level"], "icmp")

    def test_pingloc_all_fail(self):
        sse = (
            "event: callback\ndata: "
            + json.dumps({"node_id": "n1", "latency": None, "ip": "1.2.3.4",
                          "error_code": 2}) + "\n\n"
            "event: callback\ndata: "
            + json.dumps({"node_id": "n2", "latency": None, "ip": "1.2.3.4",
                          "error_code": 2}) + "\n\n"
        ).encode()
        exec_resp = self._wrap_urlopen(sse)

        def fake(url, headers, timeout, method="GET", data=None):
            if url.endswith("/node/items"):
                return 200, {}, json.dumps({"data": [{"id": "n1"}, {"id": "n2"}]}).encode()
            return 200, {}, json.dumps({"data": {"token": "task_abc"}}).encode()

        with mock.patch.object(cc, "request_follow", side_effect=fake) as mrf, \
             mock.patch.object(cc.urllib.request, "urlopen", return_value=exec_resp):
            out = cc.pingloc_check("1.2.3.4", 10, method="ping")
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ok_nodes"], 0)

    def test_pingloc_no_nodes(self):
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, json.dumps({"data": []}).encode())):
            out = cc.pingloc_check("1.2.3.4", 10)
        self.assertEqual(out["status"], "error")

    def test_pingloc_no_token(self):
        def fake(url, headers, timeout, method="GET", data=None):
            if url.endswith("/node/items"):
                return 200, {}, json.dumps({"data": [{"id": "n1"}]}).encode()
            return 200, {}, json.dumps({"data": {}}).encode()

        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.pingloc_check("1.2.3.4", 10)
        self.assertEqual(out["status"], "error")

    def test_pingloc_data_null(self):
        # 上游 data 键存在但为 null：先前 pattern
        # ``.get("data", {}).get("token")`` 会对 None 调 .get 崩溃（CI 失败）。
        def fake(url, headers, timeout, method="GET", data=None):
            if url.endswith("/node/items"):
                return 200, {}, json.dumps({"data": [{"id": "n1"}]}).encode()
            return 200, {}, json.dumps({"data": None}).encode()

        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.pingloc_check("1.2.3.4", 10)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error"], "no token")

    def test_pingloc_nodes_null(self):
        # 节点列表 data 为 null：不得抛异常，走 "no pingloc nodes" 错误分支。
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, json.dumps({"data": None}).encode())):
            out = cc.pingloc_check("1.2.3.4", 10)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error"], "no pingloc nodes")

    def _seed_antping(self, frames):
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {},
                                             json.dumps({"data": "jwt.token.xyz"}).encode())), \
             mock.patch.object(cc, "_WebSocket",
                               return_value=self._FakeWS(frames)):
            return cc.antping_check("1.2.3.4", "443", 10)

    def test_antping_tcp_all_ok(self):
        frames = [
            ("evt", {"data": {"cmd": 4, "status": 200, "speed": 10}}),
            ("evt", {"data": {"cmd": 4, "status": 200, "speed": 20}}),
            ("evt", {"data": {"cmd": 4, "status": 200, "speed": 15}}),
        ]
        out = self._seed_antping(frames)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 3)
        self.assertEqual(out["ms"], 10)
        self.assertEqual(out["level"], "tcp")

    def test_antping_ping_mixed(self):
        frames = [
            ("evt", {"data": {"cmd": 3, "status": 200, "speed": 30}}),
            ("evt", {"data": {"cmd": 3, "status": 500, "speed": 0}}),
        ]
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {},
                                             json.dumps({"data": "jwt.x"}).encode())), \
             mock.patch.object(cc, "_WebSocket",
                               return_value=self._FakeWS(frames)):
            out = cc.antping_check("1.2.3.4", "", 10)  # 无端口 → ICMP
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 1)
        self.assertEqual(out["level"], "icmp")

    def test_antping_no_jwt(self):
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, json.dumps({"data": None}).encode())):
            out = cc.antping_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "error")

    def test_antping_all_fail(self):
        frames = [
            ("evt", {"data": {"cmd": 4, "status": 503, "speed": 0}}),
            ("evt", {"data": {"cmd": 4, "status": 408, "speed": 0}}),
        ]
        out = self._seed_antping(frames)
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ok_nodes"], 0)

    def _seed_tcpingcn(self, rows):
        page = {"r": "r1", "s": "salt1", "ts": "123456", "d": 0}
        task = {"k": "task-k", "r": "r-task", "u": "/api/ws/probe"}

        with mock.patch.object(cc, "_tcpingcn_page_cookie", return_value="c=1"), \
             mock.patch.object(cc, "_tcpingcn_get",
                               return_value=page) as mg, \
             mock.patch.object(cc, "_tcpcn_pow_solve",
                               return_value=("42", 0.1)) as mp, \
             mock.patch.object(cc, "_tcpingcn_post",
                               return_value=task) as mpost, \
             mock.patch.object(cc, "_WebSocket",
                               return_value=self._FakeWS(rows)):
            return cc.tcpingcn_check("1.2.3.4", "80", 10)

    def test_tcpingcn_all_ok(self):
        rows = [
            ("evt", {"event": "hello", "data": {}}),
            ("evt", {"event": "result", "data": {"rtt_avg": 8.4}}),
            ("evt", {"event": "result", "data": {"rtt_avg": 12.0}}),
            ("evt", {"event": "complete", "data": {}}),
        ]
        out = self._seed_tcpingcn(rows)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 2)
        self.assertEqual(out["ms"], 8.4)
        self.assertEqual(out["level"], "tcp")

    def test_tcpingcn_all_fail(self):
        rows = [
            ("evt", {"event": "result", "data": {"rtt_avg": 0}}),
            ("evt", {"event": "result", "data": {"rtt_avg": None}}),
            ("evt", {"event": "complete", "data": {}}),
        ]
        out = self._seed_tcpingcn(rows)
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ok_nodes"], 0)

    def test_tcpingcn_no_challenge(self):
        with mock.patch.object(cc, "_tcpingcn_page_cookie", return_value=""), \
             mock.patch.object(cc, "_tcpingcn_get", return_value={"d": 0}):
            out = cc.tcpingcn_check("1.2.3.4", "80", 10)
        self.assertEqual(out["status"], "error")

    def test_tcpingcn_pow_zero_bits(self):
        # 16 位清 0 → 头 2 字节为 0
        self.assertTrue(cc._tcpcn_check_zero_bits(b"\x00\x00\x01", 16))
        self.assertFalse(cc._tcpcn_check_zero_bits(b"\x00\x01\x00", 16))
        # 12 位清 0 → 头 1 字节为 0 且第 2 字节高 4 位为 0
        self.assertTrue(cc._tcpcn_check_zero_bits(b"\x00\x0f", 12))
        self.assertFalse(cc._tcpcn_check_zero_bits(b"\x00\xf0", 12))

    def _wrap_chinaz(self, frames):
        html = b'<html>let token = "tok_abc";</html>'
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, html)) as mr, \
             mock.patch.object(cc, "_WebSocket",
                               return_value=self._FakeWS(frames)):
            return cc.chinaz_check("1.2.3.4", "", 10)

    def test_chinaz_mixed(self):
        frames = [
            ("evt", {"code": 3, "data": []}),
            ("evt", {"code": 1, "timeMs": "25.5"}),
            ("evt", {"code": 1, "timeMs": "-1"}),
            ("evt", {"code": 10002, "data": {"remain": 100}}),
        ]
        out = self._wrap_chinaz(frames)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 1)
        self.assertEqual(out["nodes"], 2)
        self.assertEqual(out["level"], "icmp")

    def test_chinaz_no_token(self):
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, b"<html>no token</html>")):
            out = cc.chinaz_check("1.2.3.4", "", 10)
        self.assertEqual(out["status"], "error")


class TestTcptestSource(unittest.TestCase):
    def test_pick_nodes_spreads_operator(self):
        nodes = []
        for i in range(12):
            nodes.append({"uuid": f"u{i}", "operator": f"isp{i % 3}",
                          "city": f"c{i}"})
        picked = cc.tcptest_pick_nodes(nodes, 6)
        self.assertEqual(len(picked), 6)
        # 同运营商不重复（运营商均衡）
        self.assertEqual(len(set(picked)), 6)

    def test_pick_nodes_caps_at_count(self):
        nodes = [{"uuid": f"u{i}", "operator": "a"} for i in range(20)]
        self.assertEqual(len(cc.tcptest_pick_nodes(nodes, 10)), 10)

    def test_pick_nodes_empty(self):
        self.assertEqual(cc.tcptest_pick_nodes([], 5), [])

    def test_fetch_nodes_caches(self):
        payload = {
            "has_more": False, "next_cursor": "0",
            "nodes": [
                {"uuid": "a", "enabled": True, "runtime_state": "online"},
                {"uuid": "b", "enabled": True, "runtime_state": "offline"},
                {"uuid": "c", "enabled": False, "runtime_state": "online"},
            ],
        }
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, json.dumps(payload).encode())) as m:
            cc._tcptest_nodes_cache = None
            nodes = cc.tcptest_fetch_nodes(5)
        self.assertEqual([n["uuid"] for n in nodes], ["a"])
        # 缓存命中 → 不再发请求
        with mock.patch.object(cc, "request_follow",
                               side_effect=AssertionError) as m2:
            nodes2 = cc.tcptest_fetch_nodes(5)
        self.assertEqual(len(nodes2), 1)
        cc._tcptest_nodes_cache = None

    def test_fetch_nodes_paginates(self):
        pages = [
            {"has_more": True, "next_cursor": "22",
             "nodes": [{"uuid": "a", "enabled": True, "runtime_state": "online"}]},
            {"has_more": False, "next_cursor": "0",
             "nodes": [{"uuid": "b", "enabled": True, "runtime_state": "online"}]},
        ]
        def fake(url, headers, timeout, method="GET", data=None):
            return 200, {}, json.dumps(pages.pop(0)).encode()
        with mock.patch.object(cc, "request_follow", side_effect=fake):
            cc._tcptest_nodes_cache = None
            nodes = cc.tcptest_fetch_nodes(5)
        self.assertEqual([n["uuid"] for n in nodes], ["a", "b"])
        cc._tcptest_nodes_cache = None

    def test_check_all_ok(self):
        resp = json.dumps({"id": "t1"}).encode()
        state = json.dumps({"state": "succeeded"}).encode()
        results = json.dumps({"results": [
            {"success": True, "data": {"connected": True, "avg_ms": 12.5}},
            {"success": True, "data": {"connected": True, "avg_ms": 20.0}},
        ]}).encode()
        states = [resp, state, results]
        def fake(url, headers, timeout, method="GET", data=None):
            return 200, {}, states.pop(0)
        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.tcptest_check("1.2.3.4", "443", 10, ["u1", "u2"])
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 2)
        self.assertEqual(out["ms"], 12.5)
        self.assertEqual(out["level"], "tcp")

    def test_check_all_fail(self):
        resp = json.dumps({"id": "t1"}).encode()
        state = json.dumps({"state": "failed"}).encode()
        results = json.dumps({"results": [
            {"success": False, "data": {"connected": False}},
            {"success": False, "data": {"connected": False}},
        ]}).encode()
        states = [resp, state, results]
        def fake(url, headers, timeout, method="GET", data=None):
            return 200, {}, states.pop(0)
        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.tcptest_check("1.2.3.4", "443", 10, ["u1", "u2"])
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ratio"], 0.0)

    def test_check_create_rate_limited(self):
        with mock.patch.object(cc, "request_follow",
                               return_value=(429, {}, b"{}")):
            out = cc.tcptest_check("1.2.3.4", "443", 10, ["u1"])
        self.assertEqual(out["status"], "rate_limited")

    def test_check_no_nodes_error(self):
        out = cc.tcptest_check("1.2.3.4", "443", 10, [])
        self.assertEqual(out["status"], "error")


class TestItdogMergeVerdict(unittest.TestCase):
    def _s(self, status):
        return {"status": status, "ok": status == "ok", "ms": 12 if status == "ok" else None}

    def test_itdog_ok_reachable(self):
        sources = {"itdog": self._s("ok"), "check_host": self._s("error")}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "reachable")

    def test_itdog_fail_alone_uncertain(self):
        sources = {"itdog": self._s("fail"), "check_host": self._s("error")}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_itdog_fail_plus_checkhost_fail(self):
        sources = {"itdog": self._s("fail"), "check_host": self._s("fail")}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_pingpe_fail_plus_itdog_fail(self):
        sources = {"pingpe": self._s("fail"), "itdog": self._s("fail")}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_itdog_rate_limited_neutral(self):
        sources = {"itdog": {"status": "rate_limited", "ok": False, "ms": None},
                   "check_host": {"status": "error", "ok": False, "ms": None}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "skipped")


class TestMergeVerdictLevel(unittest.TestCase):
    def _src(self, status, level=None, ms=12.0):
        return {"status": status, "ok": status == "ok", "ms": ms if status == "ok" else None,
                "level": level}

    def test_http_level_propagates(self):
        sources = {
            "itdog": self._src("ok", "http"),
            "check_host": self._src("error"),
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "http")

    def test_tcp_only_level(self):
        sources = {"itdog": self._src("ok", "tcp")}
        self.assertEqual(cc.merge_verdict(sources)["level"], "tcp")

    def test_no_ok_sources_level_none(self):
        sources = {"check_host": self._src("fail"), "xxapi": self._src("fail")}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "unreachable")
        self.assertIsNone(merged["level"])

    def test_sources_without_level_field(self):
        # 旧格式源（无 level 字段）不报错，按 tcp 计
        sources = {"itdog": {"status": "ok", "ok": True, "ms": 10}}
        self.assertEqual(cc.merge_verdict(sources)["level"], "tcp")

    def test_itdog_tcping_is_multi_node_source(self):
        # batch_http 失败 + batch_tcping 单独 ok → reachable（多节点源）
        sources = {
            "itdog": self._src("fail"),
            "itdog_tcping": self._src("ok", "tcp"),
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["basis"], ["itdog_tcping"])

    def test_itdog_tcping_fail_plus_single_fail_unreachable(self):
        sources = {
            "itdog_tcping": self._src("fail"),
            "check_host": self._src("fail"),
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")


class TestWriteContract(unittest.TestCase):
    """china.json 写盘载荷契约：顶层必须有 ``ts``（看门狗/徽章依赖它）。"""

    def test_payload_includes_top_level_ts(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "china.json"
            cc.write_json(
                out,
                {
                    "ts": cc.datetime.now(cc.timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    "proxies": {"x:443#US": {"verdict": "reachable"}},
                },
            )
            data = json.loads(out.read_text())
            self.assertIsInstance(data.get("ts"), str)
            self.assertIn("proxies", data)
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "china.json"
            cc.write_json(out, {"proxies": {"x:443#US": {"verdict": "reachable"}}})
            self.assertIsNone(json.loads(out.read_text()).get("ts"))


class TestApplyStreak(unittest.TestCase):
    def test_consecutive_reachable_accumulates(self):
        entries = {"a": {"verdict": "reachable"}, "b": {"verdict": "unreachable"}}
        prev = {"a": {"verdict": "reachable", "streak": 3},
                "b": {"verdict": "reachable", "streak": 5}}
        cc.apply_streak(entries, prev)
        self.assertEqual(entries["a"]["streak"], 4)
        self.assertEqual(entries["b"]["streak"], 0)

    def test_first_reachable_and_missing_prev_streak(self):
        entries = {"a": {"verdict": "reachable"}, "b": {"verdict": "reachable"},
                   "c": {"verdict": "uncertain"}}
        prev = {"a": {"verdict": "reachable"},  # 无 streak 字段（旧格式）
                "c": {"verdict": "reachable", "streak": 7}}
        cc.apply_streak(entries, prev)
        self.assertEqual(entries["a"]["streak"], 2)   # 上轮可达但无计数 → 按 1 起算
        self.assertEqual(entries["b"]["streak"], 1)   # 首次可达
        self.assertEqual(entries["c"]["streak"], 0)   # 本轮非 reachable 清零

    def test_empty_prev(self):
        entries = {"a": {"verdict": "reachable"}}
        cc.apply_streak(entries, {})
        self.assertEqual(entries["a"]["streak"], 1)

    def test_stale_baseline_resets(self):
        """基线观测早于时间窗 → 连续计数清零重算（防回滚误判）。"""
        now = 1_800_000_000
        entries = {"a": {"verdict": "reachable"}}
        prev = {"a": {"verdict": "reachable", "streak": 9,
                      "last_ok_ts": now - cc.STREAK_GAP_TOLERANCE_S - 60}}
        cc.apply_streak(entries, prev, now=now)
        self.assertEqual(entries["a"]["streak"], 1)
        self.assertEqual(entries["a"]["last_ok_ts"], now)

    def test_fresh_baseline_accumulates_with_ts(self):
        now = 1_800_000_000
        entries = {"a": {"verdict": "reachable"}}
        prev = {"a": {"verdict": "reachable", "streak": 3,
                      "last_ok_ts": now - 3600}}
        cc.apply_streak(entries, prev, now=now)
        self.assertEqual(entries["a"]["streak"], 4)

    def test_gap_within_tolerance_keeps_streak(self):
        """GH 调度实测 2.5~4h 才起一轮：5h 间隔仍在 6h 容差内，streak 须延续。"""
        now = 1_800_000_000
        entries = {"a": {"verdict": "reachable"}}
        prev = {"a": {"verdict": "reachable", "streak": 3,
                      "last_ok_ts": now - 5 * 3600}}
        cc.apply_streak(entries, prev, now=now)
        self.assertEqual(entries["a"]["streak"], 4)

    def test_unreachable_clears_last_ok_ts(self):
        entries = {"a": {"verdict": "unreachable", "last_ok_ts": 1_234}}
        prev = {"a": {"verdict": "reachable", "streak": 2,
                      "last_ok_ts": 1_200}}
        cc.apply_streak(entries, prev, now=1_500)
        self.assertEqual(entries["a"]["streak"], 0)
        self.assertNotIn("last_ok_ts", entries["a"])

    def test_flip_accrues_on_verdict_change(self):
        entries = {"a": {"verdict": "unreachable"}}
        prev = {"a": {"verdict": "reachable", "streak": 2, "flip": 0}}
        cc.apply_streak(entries, prev)
        self.assertEqual(entries["a"]["flip"], 1)

    def test_flip_carries_when_stable(self):
        entries = {"a": {"verdict": "reachable"}}
        prev = {"a": {"verdict": "reachable", "streak": 2, "flip": 2}}
        cc.apply_streak(entries, prev)
        self.assertEqual(entries["a"]["flip"], 2)  # 状态未变不增

    def test_flip_forgiven_after_long_stable_run(self):
        entries = {"a": {"verdict": "reachable"}}
        prev = {"a": {"verdict": "reachable", "streak": cc.FLIP_FORGIVE_STREAK - 1,
                      "flip": 3}}
        cc.apply_streak(entries, prev)
        self.assertEqual(entries["a"]["streak"], cc.FLIP_FORGIVE_STREAK)
        self.assertEqual(entries["a"]["flip"], 0)

    def test_flip_first_seen_is_zero(self):
        entries = {"a": {"verdict": "unreachable"}}
        cc.apply_streak(entries, {})
        self.assertEqual(entries["a"]["flip"], 0)

    def test_flip_both_directions_count(self):
        # 恢复（不可达→可达）同样计一次翻转
        entries = {"a": {"verdict": "reachable"}}
        prev = {"a": {"verdict": "unreachable", "streak": 0, "flip": 1}}
        cc.apply_streak(entries, prev)
        self.assertEqual(entries["a"]["flip"], 2)
        self.assertEqual(entries["a"]["streak"], 1)


class TestStableAdmission(unittest.TestCase):
    def test_flip_excludes_from_stable(self):
        """stable 准入：streak≥2 且 flip≤1；慢性抖动源被排除。"""
        entries = {
            "good": {"verdict": "reachable", "streak": 5, "flip": 1},
            "flapper": {"verdict": "unreachable", "streak": 0, "flip": 3},
            "edge": {"verdict": "reachable", "streak": 2, "flip": 0},
            "lowstreak": {"verdict": "reachable", "streak": 1, "flip": 0},
        }
        stable = {
            k for k, e in entries.items()
            if e.get("streak", 0) >= 2 and e.get("flip", 0) <= cc.STABLE_MAX_FLIP
        }
        self.assertEqual(stable, {"good", "edge"})


class TestAnnotateCnh(unittest.TestCase):
    def test_appends_token(self):
        line = "1.1.1.1:443#US-50ms-CN"
        out = cc.annotate_cnh(line)
        self.assertTrue(out.endswith("-CN-CNH"))

    def test_idempotent(self):
        line = "1.1.1.1:443#US-50ms-CN-CNH"
        self.assertEqual(cc.annotate_cnh(line), line)


class TestGenerateAllCnHttpStrict(unittest.TestCase):
    POOL = (
        "1.1.1.1:443#US-100ms-5MB/s\n"
        "2.2.2.2:443#US-200ms-1MB/s-CN\n"      # 历史 -CN
        "3.3.3.3:443#JP-50ms-2MB/s\n"
    )

    def test_http_keys_annotated_cnh(self):
        text, n = cc.generate_all_cn(
            self.POOL, {"1.1.1.1:443#US"}, http_keys={"1.1.1.1:443#US"})
        self.assertEqual(n, 1)
        self.assertIn("1.1.1.1:443#US-100ms-5MB/s-CN-CNH", text)
        self.assertNotIn("2.2.2.2:443#US", text)  # 历史 -CN 不再兜底

    def test_strict_skips_historical_cn(self):
        text, n = cc.generate_all_cn(self.POOL, set(), strict=True)
        self.assertEqual(n, 0)
        # strict 只影响收录（历史 -CN 不兜底），当前可达行照常标注 -CN
        text, n = cc.generate_all_cn(self.POOL, {"3.3.3.3:443#JP"}, strict=True)
        lines = text.strip().splitlines()
        self.assertEqual(n, 1)
        self.assertEqual(lines[0].split("#")[0], "3.3.3.3:443")
        self.assertTrue(lines[0].endswith("-CN"))

    def test_non_strict_also_skips_historical_cn(self):
        # 历史 -CN 兜底已彻底移除：strict=False 与非 strict 同策略
        _, n = cc.generate_all_cn(self.POOL, set(), strict=False)
        self.assertEqual(n, 0)


class TestGenerateCnSubset(unittest.TestCase):
    POOL = (
        "1.1.1.1:443#US-100ms-5MB/s-CN\n"
        "2.2.2.2:443#US-200ms-1MB/s-CN\n"
        "3.3.3.3:443#JP-50ms-2MB/s\n"
    )

    def test_predicate_filter_keeps_verbatim(self):
        text, n = cc.generate_cn_subset(
            self.POOL, lambda k, l: k == "1.1.1.1:443#US")
        self.assertEqual(n, 1)
        self.assertEqual(text.strip(), "1.1.1.1:443#US-100ms-5MB/s-CN")

    def test_sorted_by_ms(self):
        text, n = cc.generate_cn_subset(
            self.POOL, lambda k, l: k != "3.3.3.3:443#JP",
            cn_ms={"1.1.1.1:443#US": 300, "2.2.2.2:443#US": 80})
        lines = text.strip().splitlines()
        self.assertEqual(n, 2)
        self.assertEqual(lines[0].split("#")[0], "2.2.2.2:443")


class TestScarceQuotaAllocation(unittest.TestCase):
    """check_host 稀缺配额（~250/h）只投递决策键：xxapi 明确 fail 者省略，
    预算全部用于 xxapi ok / 临时性失败者 —— 提高「把 uncertain 翻成
    reachable」的转换率，而不放宽判定杠。"""

    def _args(self):
        from types import SimpleNamespace

        return SimpleNamespace(
            skip_itdog=True,
            skip_itdog_tcping=True,
            pingpe_limit=0,
            workers=4,
            timeout=5,
            api_key="",
        )

    def test_check_host_skipped_when_pair_confirmed(self):
        """xxapi+jkapi 双免额单节点已 double-ok → 稀配额 check-host 直接让位。"""
        import unittest.mock as mock

        items = [
            ("1.1.1.1:80#US", "1.1.1.1:80#US", "1.1.1.1", "80", "US"),
            ("2.2.2.2:80#US", "2.2.2.2:80#US", "2.2.2.2", "80", "US"),
        ]

        def fake_xxapi(ip, port, timeout):
            return {"status": "ok", "ok": True, "ms": float(port)}

        def fake_check_host(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 1.0}

        def fake_jkapi(ip, port, timeout):
            return {"status": "ok", "ok": True, "ms": float(port)}

        with mock.patch.object(cc, "xxapi_check", side_effect=fake_xxapi), mock.patch.object(
            cc, "check_host_check", side_effect=fake_check_host
        ) as mch, mock.patch.object(cc, "jkapi_check", side_effect=fake_jkapi):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual(mch.call_args_list, [])
        self.assertEqual(set(reachable), {"1.1.1.1:80#US", "2.2.2.2:80#US"})

    def test_check_host_skipped_when_pair_failed(self):
        """xxapi+jkapi 双 fail → 已判 unreachable，同样不再浪费稀配额。"""
        import unittest.mock as mock

        items = [("3.3.3.3:80#US", "3.3.3.3:80#US", "3.3.3.3", "80", "US")]

        def fake_xxapi(ip, port, timeout):
            return {"status": "fail", "ok": False, "ms": None, "error": ""}

        def fake_check_host(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 1.0}

        def fake_jkapi(ip, port, timeout):
            return {"status": "fail", "ok": False, "ms": None, "error": ""}

        with mock.patch.object(cc, "xxapi_check", side_effect=fake_xxapi), mock.patch.object(
            cc, "check_host_check", side_effect=fake_check_host
        ) as mch, mock.patch.object(cc, "jkapi_check", side_effect=fake_jkapi):
            entries, _, _ = cc.run_measurements(items, self._args())

        self.assertEqual(mch.call_args_list, [])
        self.assertEqual(entries["3.3.3.3:80#US"]["verdict"], "unreachable")

    def test_check_host_probes_single_ok_for_second_confirm(self):
        """恰好 1 只免额单节点 ok → check-host 补足到双确认即翻正。"""
        import unittest.mock as mock

        items = [("4.4.4.4:80#US", "4.4.4.4:80#US", "4.4.4.4", "80", "US")]

        def fake_xxapi(ip, port, timeout):
            return {"status": "ok", "ok": True, "ms": float(port)}

        def fake_check_host(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 1.0}

        def fake_jkapi(ip, port, timeout):
            return {"status": "error", "ok": False, "ms": None, "error": "http 500"}

        with mock.patch.object(cc, "xxapi_check", side_effect=fake_xxapi), mock.patch.object(
            cc, "check_host_check", side_effect=fake_check_host
        ) as mch, mock.patch.object(cc, "jkapi_check", side_effect=fake_jkapi):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual([c.args[0] for c in mch.call_args_list], ["4.4.4.4"])
        self.assertEqual(set(reachable), {"4.4.4.4:80#US"})

    def test_xxapi_error_still_gets_second_opinion(self):
        import unittest.mock as mock

        items = [("9.9.9.9:443#US", "9.9.9.9:443#US", "9.9.9.9", "443", "US")]

        def fake_xxapi(ip, port, timeout):
            return {"status": "error", "ok": False, "ms": None, "error": "http 500"}

        def fake_check_host(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 5.0}

        with mock.patch.object(cc, "xxapi_check", side_effect=fake_xxapi), mock.patch.object(
            cc, "check_host_check", side_effect=fake_check_host
        ) as mch, mock.patch.object(cc, "jkapi_check",
                                    return_value={"status": "error", "ok": False,
                                                  "ms": None, "error": "http 500"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual(len(mch.call_args_list), 1)
        self.assertEqual(set(reachable), set())
        self.assertEqual(entries["9.9.9.9:443#US"]["verdict"], "uncertain")


class TestSlotRunnerCrashIsolation(unittest.TestCase):
    """任一复核源单键异常不得拖垮整轮（真实事故：tcpingcn cookie 超时
    未被捕获 → 4h50m 探测全部作废）。所有槽位 runner 须把异常写为 error 源。"""

    def _args(self, limits: bool = True):
        from types import SimpleNamespace

        return SimpleNamespace(
            skip_itdog=True,
            skip_itdog_tcping=True,
            pingpe_limit=1,
            workers=4,
            timeout=5,
            api_key="",
            tcpping_token="",
            tcptest_limit=1 if limits else 0,
            tcptest_concurrency=2,
            tcptest_nodes=2,
            coffee_limit=1 if limits else 0,
            coffee_concurrency=2,
            pingloc_limit=1 if limits else 0,
            pingloc_concurrency=2,
            antping_limit=1 if limits else 0,
            antping_concurrency=2,
            tcpingcn_limit=1 if limits else 0,
            tcpingcn_concurrency=2,
            chinaz_limit=1 if limits else 0,
            chinaz_concurrency=2,
        )

    def _item(self, i: int = 0):
        ip = f"10.{i}.0.1"
        return (f"{ip}:80#US", f"{ip}:80#US", ip, "80", "US")

    def _boom(self, *a, **k):
        raise RuntimeError("boom")

    def _ok(self, *a, **k):
        return {"status": "error", "ok": False, "ms": None, "error": "stub"}

    def test_each_slot_runner_isolates_exceptions(self):
        import unittest.mock as mock

        item = self._item(1)
        patches = [
            mock.patch.object(cc, "tcptest_check", side_effect=self._boom),
            mock.patch.object(cc, "coffee_check", side_effect=self._boom),
            mock.patch.object(cc, "pingloc_check", side_effect=self._boom),
            mock.patch.object(cc, "antping_check", side_effect=self._boom),
            mock.patch.object(cc, "tcpingcn_check", side_effect=self._boom),
            mock.patch.object(cc, "chinaz_check", side_effect=self._boom),
            mock.patch.object(cc, "pingpe_check", side_effect=self._boom),
            mock.patch.object(cc, "tcpping_check", side_effect=self._boom),
            mock.patch.object(cc, "xxapi_check",
                              return_value={"status": "ok", "ok": True, "ms": 1.0}),
            mock.patch.object(cc, "jkapi_check", side_effect=self._boom),
            # check_host 也走槽位；抛异常同样须被隔离（l2_check_host 已有守卫）
            mock.patch.object(cc, "check_host_check", side_effect=self._boom),
            mock.patch.object(cc, "itdog_batch_run", return_value={}),
        ]
        for p in patches:
            p.start()
        try:
            entries, _, _ = cc.run_measurements([item], self._args())
        finally:
            for p in patches:
                p.stop()
        srcs = entries[item[1]]["sources"]
        for name in ("tcptest", "coffee", "pingloc", "antping", "tcpingcn",
                     "chinaz", "pingpe", "check_host"):
            self.assertEqual(srcs[name]["status"], "error")
        # 全部错误 → 不误判（skipped/uncertain），且流程未中断
        self.assertIn(entries[item[1]]["verdict"], ("uncertain", "skipped"))


class TestItdogRestrictedToUndecidedKeys(unittest.TestCase):
    """itdog 批量代价高：只投仍未定论的键；双免额已定论（≥2 ok / ≥2 fail）
    的键不得再进 itdog 复核，且 batch_tcping 兜底按节点拉取状态触发。"""

    def _args(self):
        from types import SimpleNamespace

        return SimpleNamespace(
            skip_itdog=False,
            skip_itdog_tcping=False,
            pingpe_limit=0,
            workers=4,
            timeout=5,
            api_key="",
            tcpping_token="",
            itdog_nodes=2,
            itdog_batch_size=5,
            itdog_concurrency=2,
            itdog_pacing=0.0,
            itdog_timeout=10,
            itdog_tcping_nodes=2,
        )

    def test_itdog_sees_only_undecided_keys(self):
        import unittest.mock as mock

        decided = ("10.2.0.1:80#US", "10.2.0.1:80#US", "10.2.0.1", "80", "US")
        pending = ("10.3.0.1:80#US", "10.3.0.1:80#US", "10.3.0.1", "80", "US")
        seen = {}

        def fake_itdog(sample, args, **kwargs):
            seen["keys"] = [key for _, key, _, _, _ in sample]
            return {}

        def fake_jkapi(ip, port, timeout):
            if ip == "10.2.0.1":
                return {"status": "ok", "ok": True, "ms": 1.0}
            return {"status": "error", "ok": False, "ms": None, "error": "x"}

        with mock.patch.object(cc, "xxapi_check",
                               return_value={"status": "ok", "ok": True, "ms": 1.0}), \
             mock.patch.object(cc, "jkapi_check", side_effect=fake_jkapi), \
             mock.patch.object(cc, "check_host_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": "q"}), \
             mock.patch.object(cc, "itdog_batch_run", side_effect=fake_itdog):
            cc.run_measurements([decided, pending], self._args())

        self.assertEqual(seen.get("keys"), ["10.3.0.1:80#US"])

    def test_tcping_fallback_skipped_when_itdog_fully_down(self):
        """itdog 整站失败（全 error 或被投毒全 fail）时不得空转 batch_tcping 兜底；
        已定论键（无 itdog 记录）不得被误算作「节点拉取成功」。"""
        import unittest.mock as mock

        decided = ("10.4.0.1:80#US", "10.4.0.1:80#US", "10.4.0.1", "80", "US")
        for poisoned_status in ("error", "fail"):
            stuck = ("10.8.0.1:80#US", "10.8.0.1:80#US", "10.8.0.1", "80", "US")

            def fake_itdog(sample, args, page_url=None, **kw):
                # 整站被墙/投毒：每个目标都只返回 error/fail，无任何 ok
                return {key: {"status": poisoned_status, "ok": False,
                              "ms": None, "error": "no itdog nodes"}
                        for _, key, _, _, _ in sample}

            with mock.patch.object(cc, "xxapi_check",
                                   return_value={"status": "ok", "ok": True, "ms": 1.0}), \
                 mock.patch.object(cc, "jkapi_check",
                                   return_value={"status": "error", "ok": False,
                                                 "ms": None, "error": "x"}), \
                 mock.patch.object(cc, "check_host_check",
                                   return_value={"status": "error", "ok": False,
                                                 "ms": None, "error": "q"}), \
                 mock.patch.object(cc, "itdog_batch_run", side_effect=fake_itdog) as mib:
                cc.run_measurements([decided, stuck], self._args())

            self.assertEqual(len(mib.call_args_list), 1)  # 只有一次 batch_http，无 tcping 兜底

    def test_tcping_fallback_runs_when_nodes_fetched(self):
        """itdog 节点拉取成功（部分 ok）且部分键 error → 走 batch_tcping 兜底。"""
        import unittest.mock as mock

        a = ("10.6.0.1:80#US", "10.6.0.1:80#US", "10.6.0.1", "80", "US")
        b = ("10.7.0.1:80#US", "10.7.0.1:80#US", "10.7.0.1", "80", "US")

        def fake_itdog(sample, args, page_url=None, **kw):
            out = {}
            for _, key, _, _, _ in sample:
                out[key] = ({"status": "ok", "ok": True, "ms": 5.0, "ratio": 0.9, "nodes": 12}
                            if key == a[1] else
                            {"status": "error", "ok": False, "ms": None, "error": "rl"})
            return out

        with mock.patch.object(cc, "xxapi_check",
                               return_value={"status": "ok", "ok": True, "ms": 1.0}), \
             mock.patch.object(cc, "jkapi_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": "x"}), \
             mock.patch.object(cc, "check_host_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": "q"}), \
             mock.patch.object(cc, "itdog_batch_run", side_effect=fake_itdog) as mib:
            entries, _, _ = cc.run_measurements([a, b], self._args())

        calls = [c for c in mib.call_args_list]
        self.assertEqual(len(calls), 2)
        page_urls = [c.kwargs.get("page_url") for c in calls]
        self.assertIn(cc.ITDOG_TCPING_URL, page_urls)
        fallback = next(c for c in calls if c.kwargs.get("page_url") == cc.ITDOG_TCPING_URL)
        self.assertEqual([key for _, key, _, _, _ in fallback.args[0]],
                         ["10.7.0.1:80#US"])


class TestPingpeTargetsUnresolvedKeys(unittest.TestCase):
    """ping.pe 复核（贵、串行）只投当前尚未判 reachable 的键：
    已由 itdog 多点达标确认的键不再占用复核槽位。"""

    def _args(self):
        from types import SimpleNamespace
        return SimpleNamespace(
            skip_itdog=False,
            skip_itdog_tcping=True,
            pingpe_limit=10,
            workers=4,
            timeout=5,
            api_key="",
            tcpping_token="",
        )

    def test_pingpe_skips_already_reachable(self):
        import unittest.mock as mock

        items = [
            ("1.1.1.1:80#US", "1.1.1.1:80#US", "1.1.1.1", "80", "US"),
            ("2.2.2.2:80#US", "2.2.2.2:80#US", "2.2.2.2", "80", "US"),
        ]

        def fake_xxapi(ip, port, timeout):
            if ip == "2.2.2.2":
                return {"status": "fail", "ok": False, "ms": None, "error": ""}
            return {"status": "ok", "ok": True, "ms": 1.0}

        def fake_check_host(ip, port, limiter, timeout, api_key):
            if ip == "2.2.2.2":
                return {"status": "fail", "ok": False, "ms": None, "error": ""}
            return {"status": "ok", "ok": True, "ms": 1.0}

        def fake_itdog(sample, args, **kwargs):
            # 1.1.1.1 已由 itdog 多点达标 → 应立即判 reachable
            return {
                "1.1.1.1:80#US": {
                    "status": "ok", "ok": True, "ms": 10.0,
                    "ratio": 0.9, "nodes": 12, "level": "tcp",
                },
            }

        with mock.patch.object(cc, "xxapi_check", side_effect=fake_xxapi), \
             mock.patch.object(cc, "check_host_check", side_effect=fake_check_host), \
             mock.patch.object(cc, "jkapi_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": "http 500"}), \
             mock.patch.object(cc, "itdog_batch_run", side_effect=fake_itdog), \
             mock.patch.object(cc, "pingpe_check",
                               return_value={
                                   "status": "ok", "ok": True, "ms": 20.0,
                                   "reported": 13, "ok_nodes": 8}) as mpp, \
             mock.patch.object(cc, "tcpping_check",
                               return_value={"status": "skipped"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual(len(mpp.call_args_list), 1)
        probed = [c.args[0] for c in mpp.call_args_list]
        self.assertEqual(probed, ["2.2.2.2"])
        self.assertEqual(set(reachable), {"1.1.1.1:80#US", "2.2.2.2:80#US"})


class TestItdogBreakerSkipsPacing(unittest.TestCase):
    """断路器跳闸后剩余 batch 应直接短路返回，不再空转 _pace 等待——
    只对真正要发请求的任务付节奏 http:// 间隔。"""

    def _args(self):
        from types import SimpleNamespace
        return SimpleNamespace(
            itdog_nodes=2,
            itdog_batch_size=5,
            itdog_concurrency=4,
            itdog_pacing=0.01,
        )

    def test_tripped_batches_dont_pace(self):
        import unittest.mock as mock

        items = [
            (f"10.{i}.0.1:443#US", f"10.{i}.0.1:443#US",
             f"10.{i}.0.1", "443", "US")
            for i in range(1, 201)
        ]
        with mock.patch.object(ci, "itdog_fetch_nodes", return_value=[1, 2]), \
             mock.patch.object(ci, "itdog_task",
                               side_effect=lambda batch, *a, **k: {
                                   key: {"status": "error", "ok": False,
                                         "ms": None, "error": "boom", "nodes": 0}
                                   for key, _ in batch
                               }), \
             mock.patch.object(ci, "_pace") as mpace:
            ci.itdog_batch_run(items, self._args())

        # 40 个 batch，连续 8 败即跳闸；跳闸后的批不再 _pace
        self.assertLess(mpace.call_count, 40)


class TestPingpeConcurrency(unittest.TestCase):
    """L3 ping.pe 有界并发：同槽位端到端耗时远小于串行（覆盖提升的点）。"""

    def _args(self):
        from types import SimpleNamespace
        return SimpleNamespace(
            skip_itdog=True,
            skip_itdog_tcping=True,
            pingpe_limit=6,
            pingpe_concurrency=4,
            workers=4,
            timeout=5,
            api_key="",
            tcpping_token="",
        )

    def test_concurrent_slots_finish_fast(self):
        import time
        import unittest.mock as mock

        items = [
            (f"10.{i}.0.1:443#US", f"10.{i}.0.1:443#US",
             f"10.{i}.0.1", "443", "US")
            for i in range(1, 7)
        ]

        def slow_pingpe(ip, port, timeout):
            time.sleep(0.2)
            return {"status": "ok", "ok": True, "ms": 1.0,
                    "reported": 13, "ok_nodes": 8}

        with mock.patch.object(cc, "xxapi_check",
                               return_value={"status": "ok", "ok": True,
                                             "ms": 1.0}), \
             mock.patch.object(cc, "check_host_check",
                               return_value={"status": "fail", "ok": False,
                                             "ms": None, "error": ""}), \
             mock.patch.object(cc, "jkapi_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": ""}), \
             mock.patch.object(cc, "PINGPE_SLOT_GAP", 0.01), \
             mock.patch.object(cc, "pingpe_check", side_effect=slow_pingpe), \
             mock.patch.object(cc, "tcpping_check",
                               return_value={"status": "skipped"}):
            t0 = time.monotonic()
            entries, _, _ = cc.run_measurements(items, self._args())
            dt = time.monotonic() - t0

        # 串行 6×0.2s=1.2s；4 并发应明显更快（留 CI 抖动余量）
        self.assertLess(dt, 0.8)
        self.assertEqual(
            [v["sources"]["pingpe"]["ok"] for v in entries.values()].count(True), 6)
        self.assertEqual(
            [v["verdict"] for v in entries.values()].count("reachable"), 6)


class TestItdogTcpingFallbackGuard(unittest.TestCase):
    """主通道节点获取失败（整站被墙/验证码墙）时，同一上游的 tcping
    兜底必然同样拿不到节点，应跳过而非再空转一轮。"""

    def _args(self):
        from types import SimpleNamespace
        return SimpleNamespace(
            skip_itdog=False,
            skip_itdog_tcping=False,
            pingpe_limit=0,
            pingpe_concurrency=4,
            workers=4,
            timeout=5,
            api_key="",
            tcpping_token="",
        )

    def test_fallback_skipped_when_main_nodes_failed(self):
        import unittest.mock as mock

        items = [
            ("1.1.1.1:80#US", "1.1.1.1:80#US", "1.1.1.1", "80", "US"),
            ("2.2.2.2:80#US", "2.2.2.2:80#US", "2.2.2.2", "80", "US"),
        ]

        def failed_nodes(sample, args, **kwargs):
            return {
                item[1]: {"status": "error", "ok": False, "ms": None,
                          "error": "no itdog nodes"}
                for item in sample
            }

        with mock.patch.object(cc, "xxapi_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": ""}), \
             mock.patch.object(cc, "check_host_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": ""}), \
             mock.patch.object(cc, "jkapi_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": ""}), \
             mock.patch.object(cc, "itdog_batch_run", side_effect=failed_nodes) as mib:
            cc.run_measurements(items, self._args())

        # 主通道一次 + 兜底应零次（节点连取都失败的整站性故障不白跑第二轮）
        self.assertEqual(len(mib.call_args_list), 1)
        self.assertNotIn("page_url", mib.call_args_list[0].kwargs)


class TestItdogFullPoolTargets(unittest.TestCase):
    """itdog 目标集 = 去重后全量存活池。同一 (ip,port) 多行只测一次。"""

    def _args(self):
        from types import SimpleNamespace

        return SimpleNamespace(
            itdog_nodes=2,
            itdog_batch_size=50,
            itdog_concurrency=1,
            itdog_pacing=0.0,
            itdog_timeout=3,
            itdog_task_timeout=3,
        )

    def test_cf_lines_are_targeted_and_deduped(self):
        import unittest.mock as mock

        items = [
            (
                "1.1.1.1:2087#\U0001F1FA\U0001F1F8US-10ms-20.07MB/s-GPT-CF",
                "1.1.1.1:2087#US",
                "1.1.1.1",
                "2087",
                "US",
            ),
            ("2.2.2.2:443#US-8ms", "2.2.2.2:443#US", "2.2.2.2", "443", "US"),
            (
                "1.1.1.1:2087#\U0001F1FA\U0001F1F8US-10ms-20.07MB/s-GPT-CF",
                "1.1.1.1:2087#US",
                "1.1.1.1",
                "2087",
                "US",
            ),
        ]
        with mock.patch.object(ci, "itdog_fetch_nodes", return_value=[]):
            res = ci.itdog_batch_run(items, self._args())
        self.assertEqual(sorted(res), ["1.1.1.1:2087#US", "2.2.2.2:443#US"])
        self.assertTrue(all(v["status"] == "error" for v in res.values()))


class TestComputeFallbackMerge(unittest.TestCase):

    def _prev(self, *keys):
        return {k: {"verdict": "reachable", "streak": 2, "sources": {}} for k in keys}

    def test_uncertain_no_fail_merged(self):
        # 上轮可达、本轮 uncertain 且无失败源 → 合并回 reachable + fallback, streak 保留(当轮已标 0)
        prev = self._prev("a:443#US", "b:443#US", "c:443#US")
        entries = {
            "a:443#US": {"verdict": "uncertain", "sources": {"xxapi": {"status": "error"}}},
            "b:443#US": {"verdict": "uncertain", "sources": {"xxapi": {"status": "fail"}}},
            "c:443#US": {"verdict": "reachable", "sources": {}},  # 本轮已确证
        }
        reachable = {"c:443#US"}
        fb = cc.compute_fallback_merge(entries, prev, reachable)
        self.assertEqual(fb, {"a:443#US"})      # b 有失败源不兜底
        self.assertEqual(entries["a:443#US"]["verdict"], "reachable")
        self.assertTrue(entries["a:443#US"]["fallback"])
        self.assertEqual(entries["a:443#US"]["streak"], 0)  # 兜底键不虚报连续可达
        self.assertIn("a:443#US", reachable)
        self.assertNotIn("b:443#US", reachable)  # 被证伪，绝不兜底

    def test_unsampled_copy_streak_zero(self):
        # 本轮完全未采样 → 复制并入，fallback=true 且 streak 清零
        prev = {"a:443#US": {"verdict": "reachable", "streak": 4, "sources": {"xxapi": {"status": "ok"}}}}
        entries = {}
        reachable = set()
        fb = cc.compute_fallback_merge(entries, prev, reachable)
        self.assertEqual(fb, {"a:443#US"})
        self.assertIn("a:443#US", reachable)
        self.assertEqual(entries["a:443#US"]["verdict"], "reachable")
        self.assertTrue(entries["a:443#US"]["fallback"])
        self.assertEqual(entries["a:443#US"]["streak"], 0)  # 未复测不虚报连续
        self.assertEqual(entries["a:443#US"]["sources"], {"xxapi": {"status": "ok"}})

    def test_noreachable_prev_not_merged(self):
        prev = {"a:443#US": {"verdict": "offline", "streak": 5}}
        entries = {"a:443#US": {"verdict": "uncertain", "sources": {}}}
        reachable = set()
        fb = cc.compute_fallback_merge(entries, prev, reachable)
        self.assertEqual(fb, set())
        self.assertNotIn("a:443#US", reachable)

    def test_already_reachable_unchanged(self):
        prev = self._prev("a:443#US")
        entries = {"a:443#US": {"verdict": "reachable", "sources": {}}}
        reachable = {"a:443#US"}
        fb = cc.compute_fallback_merge(entries, prev, reachable)
        self.assertEqual(fb, set())
        self.assertNotIn("fallback", entries["a:443#US"])


class TestCe98Source(unittest.TestCase):
    """98ce.com socket.io-WS 适配器单测（mock _SocketIOClient，不触网）。"""

    class _FakeSIO:
        def __init__(self, frames):
            self._frames = list(frames)
            self.sent = []
            self.closed = False

        def settimeout(self, t):
            pass

        def send(self, text):
            self.sent.append(text)

        def send_event(self, name, arg):
            self.sent.append((name, arg))

        def read(self):
            if self._frames:
                return self._frames.pop(0)
            return "timeout", None

        def close(self):
            self.closed = True

    def _seed(self, frames, html=None):
        if html is None:
            html = ('<html><script id="continuous-tcping-nodes-data">'
                    '[{"name":"上海电信","location":"上海市"},'
                    '{"name":"广州腾讯云","location":"广东省"}]'
                    '</script></html>').encode()
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, html)) as mr, \
             mock.patch.object(cc, "_SocketIOClient",
                               return_value=self._FakeSIO(frames)):
            return cc.ce98_check("1.2.3.4", "443", 10)

    def test_ce98_all_ok(self):
        frames = [
            ("open", {"sid": "x"}),
            ("ack", {"sid": "y"}),
            ("event", ["continuous_tcping_started", {"job_id": "j1"}]),
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "上海电信", "ok": True, "loss": 0,
                        "latest": 5.0, "average": 5.0}]),
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "广州腾讯云", "ok": True, "loss": 0,
                        "latest": 8.0, "average": 8.0}]),
        ]
        out = self._seed(frames)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 2)
        self.assertEqual(out["nodes"], 2)
        self.assertEqual(out["ms"], 5.0)
        self.assertEqual(out["level"], "tcp")

    def test_ce98_mixed_with_lost(self):
        frames = [
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "上海", "ok": True, "loss": 0,
                        "latest": 5.0, "average": 5.0}]),
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "广州", "ok": False, "loss": 1,
                        "latest": 0, "average": 0}]),
        ]
        out = self._seed(frames)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 1)
        self.assertEqual(out["nodes"], 2)
        self.assertEqual(out["ratio"], 0.5)

    def test_ce98_all_fail(self):
        frames = [
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "上海", "ok": False, "latest": 0}]),
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "广州", "ok": False, "latest": 0}]),
        ]
        out = self._seed(frames)
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ok_nodes"], 0)

    def test_ce98_no_nodes_data(self):
        frames = []
        out = self._seed(frames, html=b"<html>no nodes</html>")
        self.assertEqual(out["status"], "error")


class TestBiupingSource(unittest.TestCase):
    """biuping.com SSE 适配器单测（mock request_follow + urlopen，不触网）。"""

    def _sse(self, blocks):
        out = []
        for b in blocks:
            out.append("event: node\ndata: " + json.dumps(b) + "\n\n")
        return "".join(out).encode()

    def _seed(self, sse_body, page_html=None):
        if page_html is None:
            page_html = ('<html><meta name="csrf-token" content="tok123">'
                         "</html>").encode()

        class _Ctx:
            def __init__(self):
                self._done = False

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                if self._done:
                    return b""
                self._done = True
                return sse_body

        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, page_html)) as mr, \
             mock.patch.object(cc.urllib.request, "urlopen",
                               return_value=_Ctx()):
            return cc.biuping_check("1.2.3.4", "443", 10)

    def test_biuping_all_ok(self):
        sse = self._sse([
            {"ok": True, "completed": 1, "total": 2, "results": [
                {"node_id": 1, "isp": "电信", "status": "ok", "latest": 4.8}]},
            {"ok": True, "completed": 2, "total": 2, "results": [
                {"node_id": 45, "isp": "联通", "status": "ok", "latest": 16.9}]},
        ])
        out = self._seed(sse)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 2)
        self.assertEqual(out["nodes"], 2)
        self.assertEqual(out["ms"], 4.8)
        self.assertEqual(out["level"], "tcp")

    def test_biuping_mixed(self):
        sse = self._sse([
            {"ok": True, "results": [
                {"node_id": 1, "isp": "电信", "status": "ok", "latest": 5.0},
                {"node_id": 1, "isp": "联通", "status": "timeout", "latest": None}]},
            {"ok": True, "results": [
                {"node_id": 1, "isp": "移动", "status": "ok", "latest": 9.0}]},
        ])
        out = self._seed(sse)
        # 1:电信、1:联通、1:移动 三个独立节点键
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 2)
        self.assertEqual(out["nodes"], 3)
        self.assertEqual(out["ratio"], round(2 / 3, 3))

    def test_biuping_no_token(self):
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, b"<html>no meta</html>")):
            out = cc.biuping_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "error")


class TestNewMultiSourcesMergeVerdict(unittest.TestCase):
    """ce98 / biuping 并入多节点源合成判定（level/ratio 规则）。"""

    def _ok(self, ok_nodes, nodes, ratio):
        return {"status": "ok", "ok": True, "ms": 30, "level": "tcp",
                "ok_nodes": ok_nodes, "nodes": nodes, "ratio": ratio}

    def test_ce98_strong_reachable(self):
        sources = {"ce98": self._ok(35, 35, 1.0)}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "reachable")

    def test_ce98_degenerate_not_strong(self):
        sources = {"ce98": self._ok(1, 35, 0.029)}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_biuping_strong_reachable(self):
        sources = {"biuping": self._ok(39, 39, 1.0)}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "reachable")

    def test_multi_failed_with_single_unreachable(self):
        """ce98+biuping 都 fail 且 2 单节点源 fail → unreachable。"""
        sources = {
            "ce98": {"status": "fail", "ok": False, "ok_nodes": 0,
                     "nodes": 35, "ratio": 0.0},
            "biuping": {"status": "fail", "ok": False, "ok_nodes": 0,
                        "nodes": 39, "ratio": 0.0},
            "xxapi": {"status": "fail", "ok": False},
            "jkapi": {"status": "fail", "ok": False},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")


if __name__ == "__main__":
    unittest.main()
