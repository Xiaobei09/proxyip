"""Tests for china_check.py pure functions."""

import base64
import hashlib
import io
import json
import socket
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import china_check as cc
import ws_transport as wt


def _registry_sources(testcase):
    """源注册表（代号真相源；无包跳过，终态 CI 直连 PCB 后常跑）。"""
    import china_engine as ce
    try:
        return ce._load_pcb_plugin("_sources")
    except Exception:
        testcase.skipTest("needs PCB _sources bundle")


CN_LINE = "1.2.3.4:2087#\U0001F1FA\U0001F1F8US-10ms-20.07MB/s-GPT-CF"
US_LINE = "5.6.7.8:443#\U0001F1FA\U0001F1F8US-8ms-5.86MB/s"


class TestCheckhostHttpMergeVerdict(unittest.TestCase):
    """CN-32：cn29 并入单节点交叉（应用层第二确认）。"""

    def test_second_confirm_reachable_http(self):
        sources = {
            cc.CN20_CODE: {"status": "ok", "ok": True, "ms": 90},
            cc.CN29_CODE: {"status": "ok", "ok": True, "ms": 39,
                               "level": "http"},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "http")

    def test_http_alone_uncertain(self):
        sources = {cc.CN29_CODE: {
            "status": "ok", "ok": True, "ms": 39, "level": "http"}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_http_fail_harmless(self):
        """http-fail 伴 TCP-ok 仍 uncertain（不定罪，fail 分析在 ok 之后）。"""
        sources = {
            cc.CN27_CODE: {"status": "ok", "ok": True, "ms": 100},
            cc.CN29_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")


class TestCheckhostHttpWiring(unittest.TestCase):
    """CN-32：http 只在 TCP-ok 且其余免额 0 ok 时猎取第二确认。"""

    def _args(self):
        from types import SimpleNamespace
        return SimpleNamespace(cn_limit={"cn30": 0, "cn31": 0, "cn32": 0, "cn33": 0, "cn40": 0}, 
            skip_cn01=True,
            skip_cn02=True,
                
            workers=4,
            timeout=5,
            api_key="",
        )

    def _item(self):
        return ("9.9.9.9:443#US", "9.9.9.9:443#US", "9.9.9.9", "443", "US")

    def _l2(self, tcp):
        return [
            mock.patch.object(cc, "cn20_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn21_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn24_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn25_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn26_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn22_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn23_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn27_check", return_value=tcp),
        ]

    def test_http_hunts_second_confirm(self):
        tcp = {"status": "ok", "ok": True, "ms": 100}
        http = {"status": "ok", "ok": True, "ms": 39, "level": "http"}
        mocks = self._l2(tcp)
        with mock.patch.object(cc, "cn29_check",
                               return_value=http) as mh:
            for p in mocks:
                p.start()
            try:
                entries, reachable, _ = cc.run_measurements([self._item()],
                                                            self._args())
            finally:
                for p in mocks:
                    p.stop()
        self.assertEqual(mh.call_count, 1)
        srcs = entries["9.9.9.9:443#US"]["sources"]
        self.assertEqual(srcs[cc.CN29_CODE]["level"], "http")
        # TCP-ok + http-ok → 双确认 reachable（uncertain 翻正）
        self.assertEqual(entries["9.9.9.9:443#US"]["verdict"], "reachable")
        self.assertIn("9.9.9.9:443#US", reachable)

    def test_http_skipped_when_already_confirmed(self):
        """已有免额 ok 时不浪费配额猎取第三确认。"""
        tcp = {"status": "ok", "ok": True, "ms": 100}
        mocks = self._l2(tcp)
        mocks[0] = mock.patch.object(
            cc, "cn20_check",
            return_value={"status": "ok", "ok": True, "ms": 90})
        with mock.patch.object(cc, "cn29_check",
                               side_effect=AssertionError("must not run")):
            for p in mocks:
                p.start()
            try:
                entries, _, _ = cc.run_measurements([self._item()],
                                                    self._args())
            finally:
                for p in mocks:
                    p.stop()
        self.assertNotIn(cc.CN29_CODE,
                         entries["9.9.9.9:443#US"]["sources"])


class TestCheckhostPingMergeVerdict(unittest.TestCase):
    """CN-31：cn28 并入单节点交叉（主机/端口死因消歧）。"""

    def test_tcp_fail_plus_ping_ok_uncertain(self):
        """TCP 双 fail 原判 unreachable；ping 证主机存活 → 回退 uncertain。"""
        sources = {
            cc.CN27_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN28_CODE: {"status": "ok", "ok": True, "ms": 13,
                               "level": "icmp"},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "uncertain")
        self.assertEqual(merged["level"], "icmp")

    def test_dual_fail_unreachable(self):
        """同节点 TCP+ICMP 双 fail → 置信定罪。"""
        sources = {
            cc.CN27_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN28_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_ping_ok_plus_single_ok_reachable(self):
        sources = {
            cc.CN28_CODE: {"status": "ok", "ok": True, "ms": 13,
                               "level": "icmp"},
            cc.CN24_CODE: {"status": "ok", "ok": True, "ms": 11},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "reachable")

    def test_ping_alone_ok_uncertain(self):
        sources = {cc.CN28_CODE: {
            "status": "ok", "ok": True, "ms": 13, "level": "icmp"}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")


class TestCheckhostPingWiring(unittest.TestCase):
    """CN-31：ping 只在 TCP fail 时追加（配额敏感），落 entries 源键。"""

    def _args(self):
        from types import SimpleNamespace
        return SimpleNamespace(cn_limit={"cn30": 0, "cn31": 0, "cn32": 0, "cn33": 0, "cn40": 0}, 
            skip_cn01=True,
            skip_cn02=True,
                
            workers=4,
            timeout=5,
            api_key="",
        )

    def _item(self):
        return ("9.9.9.9:443#US", "9.9.9.9:443#US", "9.9.9.9", "443", "US")

    def _l2(self, tcp, ping_ret=None):
        mocks = [
            mock.patch.object(cc, "cn20_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn21_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn24_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn25_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn26_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn22_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn23_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "cn27_check", return_value=tcp),
        ]
        if ping_ret is not None:
            mocks.append(mock.patch.object(cc, "cn28_check",
                                           return_value=ping_ret))
        return mocks

    def test_ping_runs_on_tcp_fail(self):
        tcp = {"status": "fail", "ok": False, "ms": None, "error": ""}
        ping = {"status": "ok", "ok": True, "ms": 13, "level": "icmp"}
        mocks = self._l2(tcp)
        with mock.patch.object(cc, "cn28_check",
                               return_value=ping) as mp:
            for p in mocks:
                p.start()
            try:
                entries, _, _ = cc.run_measurements([self._item()],
                                                    self._args())
            finally:
                for p in mocks:
                    p.stop()
        self.assertEqual(mp.call_count, 1)
        srcs = entries["9.9.9.9:443#US"]["sources"]
        self.assertEqual(srcs[cc.CN28_CODE]["ms"], 13)
        # TCP-fail + ping-ok + 全 error → uncertain（不误判死）
        self.assertEqual(entries["9.9.9.9:443#US"]["verdict"], "uncertain")

    def test_ping_skipped_on_tcp_ok(self):
        tcp = {"status": "ok", "ok": True, "ms": 100}
        mocks = self._l2(tcp)
        with mock.patch.object(cc, "cn28_check",
                               side_effect=AssertionError("must not run")):
            for p in mocks:
                p.start()
            try:
                entries, _, _ = cc.run_measurements([self._item()],
                                                    self._args())
            finally:
                for p in mocks:
                    p.stop()
        self.assertNotIn(cc.CN28_CODE,
                         entries["9.9.9.9:443#US"]["sources"])


class TestXxpingMergeVerdict(unittest.TestCase):
    """CN-29：cn21 并入单节点交叉，与其余四源同权。"""

    def test_cn21_cn25_double_ok_reachable(self):
        """跨运营商双 ICMP（枣庄＋宁波）双 ok → reachable。"""
        sources = {
            cc.CN21_CODE: {"status": "ok", "ok": True, "ms": 42.1,
                       "level": "icmp"},
            cc.CN25_CODE: {"status": "ok", "ok": True, "ms": 12.7,
                       "level": "icmp"},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "icmp")

    def test_cn21_alone_ok_uncertain(self):
        sources = {cc.CN21_CODE: {"status": "ok", "ok": True, "ms": 42.1,
                              "level": "icmp"}}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "uncertain")
        self.assertEqual(merged["level"], "icmp")

    def test_cn21_fail_plus_cn20_fail_unreachable(self):
        """同运营商双视角（北京 TCP＋枣庄 ICMP）双 fail → unreachable。"""
        sources = {
            cc.CN21_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_cn21_fail_alone_uncertain(self):
        sources = {
            cc.CN21_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")


class TestJksslMergeVerdict(unittest.TestCase):
    """CN-37：cn26 并入单节点交叉。"""

    def test_double_ok_reachable(self):
        sources = {
            cc.CN26_CODE: {"status": "ok", "ok": True, "ms": None,
                      "level": "tcp"},
            cc.CN20_CODE: {"status": "ok", "ok": True, "ms": 43},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["ms"], 43.0)

    def test_alone_ok_uncertain(self):
        sources = {cc.CN26_CODE: {"status": "ok", "ok": True, "ms": None,
                             "level": "tcp"}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_double_fail_unreachable(self):
        sources = {
            cc.CN26_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN24_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")


class TestXxstatusMergeVerdict(unittest.TestCase):
    """CN-38：cn22 并入单节点交叉。"""

    def test_double_ok_reachable_http(self):
        sources = {
            cc.CN22_CODE: {"status": "ok", "ok": True, "ms": None,
                         "level": "http"},
            cc.CN20_CODE: {"status": "ok", "ok": True, "ms": 43},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "http")
        self.assertEqual(merged["ms"], 43.0)

    def test_alone_ok_uncertain(self):
        sources = {cc.CN22_CODE: {"status": "ok", "ok": True, "ms": None,
                                "level": "http"}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_double_fail_unreachable(self):
        sources = {
            cc.CN22_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN24_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")


class TestXxscanMergeVerdict(unittest.TestCase):
    """CN-39：cn23 并入单节点交叉。"""

    def test_double_ok_reachable(self):
        sources = {
            cc.CN23_CODE: {"status": "ok", "ok": True, "ms": None,
                       "level": "tcp"},
            cc.CN24_CODE: {"status": "ok", "ok": True, "ms": 11},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["ms"], 11.0)

    def test_alone_ok_uncertain(self):
        sources = {cc.CN23_CODE: {"status": "ok", "ok": True, "ms": None,
                              "level": "tcp"}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_skipped_ignored(self):
        """skipped 源不参与判定（全 skipped → skipped，不误判）。"""
        sources = {cc.CN23_CODE: {"status": "skipped", "ok": False, "ms": None,
                              "error": "port not scanned"}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "skipped")

    def test_double_fail_unreachable(self):
        sources = {
            cc.CN23_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")


class TestJkapiIspMerge(unittest.TestCase):
    """L2 免额单节点源电信读数汇聚（merge 入口级，与多节点源同表）。"""
    def test_merge_isp_ms_picks_cn24(self):
        """merge 入口级汇聚收单节点电信读数（与多节点源同表）。"""
        entries = {"k": {"sources": {
            cc.CN24_CODE: {"status": "ok", "ok": True, "ms": 11.0,
                      "isp_ms": {"中国电信": 11.0}},
            cc.CN20_CODE: {"status": "error", "ok": False, "ms": None},
        }}}
        cc.merge_isp_ms(entries)
        self.assertEqual(entries["k"]["isp_ms"], {"中国电信": 11.0})


class TestMergeVerdict(unittest.TestCase):
    def test_any_ok_reachable(self):
        sources = {
            cc.CN27_CODE: {"status": "ok", "ok": True, "ms": 180},
            cc.CN20_CODE: {"status": "ok", "ok": True, "ms": 120},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["ms"], 120.0)

    def test_single_ok_uncertain(self):
        sources = {
            cc.CN27_CODE: {"status": "ok", "ok": True, "ms": 180},
            cc.CN20_CODE: {"status": "error", "ok": False, "ms": None},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "uncertain")

    def test_both_l2_fail_unreachable(self):
        sources = {
            cc.CN27_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_cn20_cn24_double_ok_reachable(self):
        """两只免额单节点源（cn20+cn24）双 ok → reachable，无需 cn27。"""
        sources = {
            cc.CN20_CODE: {"status": "ok", "ok": True, "ms": 43},
            cc.CN24_CODE: {"status": "ok", "ok": True, "ms": 11},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["ms"], 11.0)

    def test_cn20_cn24_both_fail_unreachable(self):
        sources = {
            cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN24_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_cn20_cn24_error_skipped(self):
        sources = {
            cc.CN20_CODE: {"status": "error", "ok": False, "ms": None},
            cc.CN24_CODE: {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "skipped")

    def test_cn40_fail_plus_l2_fail(self):
        sources = {
            cc.CN27_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "ok", "ok": True, "ms": 90},
            cc.CN40_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_single_fail_uncertain(self):
        sources = {
            cc.CN27_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_all_error_skipped(self):
        sources = {
            cc.CN27_CODE: {"status": "error", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "skipped")

    def test_heuristic_only_uncertain(self):
        sources = {
            cc.CN27_CODE: {"status": "error", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "error", "ok": False, "ms": None},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "skipped")

    def test_cn01_single_node_weak_ratio_uncertain(self):
        """cn01 仅 1/18 节点可达（ratio≈0.06）→ 不得独立判定 reachable。"""
        sources = {
            "cn01": {"status": "ok", "ok": True, "ms": 200,
                      "level": "tcp", "ok_nodes": 1, "nodes": 18,
                      "ratio": 0.056},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "uncertain")

    def test_cn01_good_ratio_reachable(self):
        sources = {
            "cn01": {"status": "ok", "ok": True, "ms": 90,
                      "level": "http", "ok_nodes": 14, "nodes": 18,
                      "ratio": 0.78},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "reachable")

    def test_cn01_weak_plus_two_single_sources_reachable(self):
        """弱 cn01 不能单独定论，但两路单节点源交叉仍可判 reachable。"""
        sources = {
            "cn01": {"status": "ok", "ok": True, "ms": 200,
                      "ok_nodes": 1, "nodes": 18, "ratio": 0.056},
            cc.CN27_CODE: {"status": "ok", "ok": True, "ms": 150},
            cc.CN20_CODE: {"status": "ok", "ok": True, "ms": 130},
        }
        # cn01 弱 + cn27/cn20 双确认 → 仍走单节点交叉线
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "reachable")

    def test_cn01_weak_plus_single_ok_uncertain(self):
        """弱 cn01 + 单节点单一确认 → 仍 uncertain（差一路强证据）。"""
        sources = {
            "cn01": {"status": "ok", "ok": True, "ms": 200,
                      "ok_nodes": 1, "nodes": 18, "ratio": 0.056},
            cc.CN27_CODE: {"status": "ok", "ok": True, "ms": 150},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_cn30_good_ratio_reachable(self):
        """cn30（多节点 TCP）成功率高 → 单源独立判 reachable。"""
        sources = {
            cc.CN30_CODE: {"status": "ok", "ok": True, "ms": 60,
                        "level": "tcp", "ok_nodes": 8, "nodes": 10,
                        "ratio": 0.8},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "reachable")
        self.assertEqual(
            cc.merge_verdict(sources)["level"], "tcp")

    def test_cn30_weak_ratio_uncertain(self):
        """cn30 仅少数节点可达（ratio 低）→ 不得单源定论。"""
        sources = {
            cc.CN30_CODE: {"status": "ok", "ok": True, "ms": 200,
                        "level": "tcp", "ok_nodes": 1, "nodes": 10,
                        "ratio": 0.1},
            cc.CN27_CODE: {"status": "error", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_cn30_fail_plus_l2_fail_unreachable(self):
        """cn30 全节点失败 + cn27/cn20 失败 → unreachable。"""
        sources = {
            cc.CN30_CODE: {"status": "fail", "ok": False, "ms": None,
                        "ok_nodes": 0, "nodes": 10, "ratio": 0.0},
            cc.CN27_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_new_multi_sources_strong_reachable(self):
        """新增四源（cn08/cn14/cn17/cn16）达标 → 独立判 reachable。"""
        for idx, (name, src) in enumerate([
            (cc.CN08_CODE, {"status": "ok", "ok": True, "ms": 30, "level": "tcp",
                               "ok_nodes": 12, "nodes": 12, "ratio": 1.0}),
            (cc.CN14_CODE, {"status": "ok", "ok": True, "ms": 20, "level": "tcp",
                         "ok_nodes": 150, "nodes": 160, "ratio": 0.94}),
            (cc.CN17_CODE, {"status": "ok", "ok": True, "ms": 15, "level": "tcp",
                          "ok_nodes": 150, "nodes": 160, "ratio": 0.94}),
            (cc.CN16_CODE, {"status": "ok", "ok": True, "ms": 40, "level": "icmp",
                        "ok_nodes": 45, "nodes": 50, "ratio": 0.90}),
        ]):
            self.assertEqual(
                cc.merge_verdict({name: src})["verdict"],
                "reachable", msg=f"{name} strong → reachable")

    def test_cn16_degenerate_sample_not_strong(self):
        """多节点源残片样本（<MULTI_MIN_NODES 节点）不得当强确认。"""
        sources = {
            cc.CN16_CODE: {"status": "ok", "ok": True, "ms": 40, "level": "icmp",
                       "ok_nodes": 1, "nodes": 1, "ratio": 1.0},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_icmp_only_source_level_honest(self):
        """仅 ICMP 主机存活源（cn07/cn16）确认时，level 如实标 icmp，
        不冒充 tcp（all_cn_http 消费方以此区分传输层证据）。"""
        sources = {
            cc.CN16_CODE: {"status": "ok", "ok": True, "ms": 40,
                       "ok_nodes": 45, "nodes": 50, "ratio": 0.9,
                       "level": "icmp"},
            cc.CN07_CODE: {"status": "ok", "ok": True, "ms": 35,
                       "ok_nodes": 20, "nodes": 30, "ratio": 0.8,
                       "level": "icmp"},
        }
        mv = cc.merge_verdict(sources)
        self.assertEqual(mv["verdict"], "reachable")
        self.assertEqual(mv["level"], "icmp")
        # 混入 TCP 源 → 保守回落 tcp
        sources[cc.CN30_CODE] = {"status": "ok", "ok": True, "ms": 30,
                           "ok_nodes": 12, "nodes": 12, "ratio": 1.0,
                           "level": "tcp"}
        self.assertEqual(cc.merge_verdict(sources)["level"], "tcp")

    def test_new_multi_fail_combos_unreachable(self):
        """新源多节点失败 + 单节点失败 → unreachable；两大节点失败也 → unreachable。"""
        cases = [
            {cc.CN17_CODE: {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                          "nodes": 160, "ratio": 0.0},
             cc.CN27_CODE: {"status": "fail", "ok": False, "ms": None}},
            {cc.CN14_CODE: {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                         "nodes": 160, "ratio": 0.0},
             cc.CN16_CODE: {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                        "nodes": 50, "ratio": 0.0}},
            {cc.CN08_CODE: {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                               "nodes": 12, "ratio": 0.0},
             cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None}},
        ]
        for sources in cases:
            self.assertEqual(
                cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_five_new_multi_sources_strong_reachable(self):
        """新增多个复核源达标 → 独立判 reachable。"""
        for name in (cc.CN42_CODE, cc.CN34_CODE, cc.CN43_CODE, cc.CN44_CODE, cc.CN13_CODE):
            src = {"status": "ok", "ok": True, "ms": 50, "level": "tcp",
                   "ok_nodes": 9, "nodes": 10, "ratio": 0.9}
            self.assertEqual(
                cc.merge_verdict({name: src})["verdict"],
                "reachable", msg=f"{name} strong → reachable")

    def test_five_new_multi_sources_weak_uncertain(self):
        """新源弱确认（ok 但比率<阈值 或 残片）→ uncertain 不误判 reachable。"""
        for name in (cc.CN42_CODE, cc.CN34_CODE, cc.CN43_CODE, cc.CN44_CODE, cc.CN13_CODE):
            weak = {"status": "ok", "ok": True, "ms": 50, "level": "tcp",
                    "ok_nodes": 1, "nodes": 10, "ratio": 0.1}
            self.assertEqual(
                cc.merge_verdict({name: weak})["verdict"],
                "uncertain", msg=f"{name} weak → uncertain")

    def test_per_source_ratio_threshold_wired(self):
        """各多节点源成功率阈值常量必须真正接线（此前多个复核源的 *_MIN_RATIO 定义了却未接入 strong_valid，
        调高任意常量都会被静默回退到 DEFAULT_MIN_RATIO）。"""
        src = {"status": "ok", "ok": True, "ms": 60, "level": "tcp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        for name in (cc.CN11_CODE, cc.CN09_CODE, cc.CN42_CODE, cc.CN34_CODE, cc.CN43_CODE, cc.CN44_CODE, cc.CN13_CODE):
            self.assertEqual(
                cc.merge_verdict({name: dict(src)})["verdict"],
                "reachable", msg=f"{name} ratio 0.7 ≥ 默认阈值 → reachable")
            old = cc._SOURCE_MIN_RATIO[name]
            cc._SOURCE_MIN_RATIO[name] = 0.75
            try:
                self.assertEqual(
                    cc.merge_verdict({name: dict(src)})["verdict"],
                    "uncertain",
                    msg=f"{name} ratio 0.7 < 调高的 0.75 → weak，不得定论")
            finally:
                cc._SOURCE_MIN_RATIO[name] = old

    def test_five_new_multi_fail_combos_unreachable(self):
        """新源多节点失败 + 单节点失败 → unreachable；两大节点失败 → unreachable。"""
        cases = [
            {cc.CN42_CODE: {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                       "nodes": 10, "ratio": 0.0},
             cc.CN27_CODE: {"status": "fail", "ok": False, "ms": None}},
            {cc.CN34_CODE: {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                      "nodes": 10, "ratio": 0.0},
             cc.CN43_CODE: {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                      "nodes": 10, "ratio": 0.0}},
            {cc.CN44_CODE: {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                        "nodes": 10, "ratio": 0.0},
             cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None}},
            {cc.CN13_CODE: {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                        "nodes": 10, "ratio": 0.0},
             cc.CN34_CODE: {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                      "nodes": 10, "ratio": 0.0}},
        ]
        for sources in cases:
            self.assertEqual(
                cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_cn35_merge_and_threshold_wired(self):
        strong = {"status": "ok", "ok": True, "ms": None, "level": "icmp",
                  "ok_nodes": 40, "nodes": 50, "ratio": 0.8}
        self.assertEqual(cc.merge_verdict(
            {cc.CN35_CODE: strong})["verdict"], "reachable")
        weak = dict(strong, ok_nodes=1, nodes=50, ratio=0.02)
        self.assertEqual(cc.merge_verdict(
            {cc.CN35_CODE: weak})["verdict"], "uncertain")
        old = cc._SOURCE_MIN_RATIO[cc.CN35_CODE]
        cc._SOURCE_MIN_RATIO[cc.CN35_CODE] = 0.9
        try:
            self.assertEqual(cc.merge_verdict(
                {cc.CN35_CODE: dict(strong)})["verdict"], "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO[cc.CN35_CODE] = old

    def test_cn35_cli_default_stays_opt_in(self):
        """CN-45：trace 复核源本地默认 opt-in（0/6），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn35")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn35")["concurrency"], 6)

    def test_cn34_not_double_scheduled(self):
        """CN-43 遗留 bug 回归：专用复核相之外，通用循环不得再跑已独立
        调度的源（limit≠0 时双跑双写）。"""
        import re
        src = (Path(__file__).resolve().parent.parent / "scripts"
               / "china_check.py").read_text(encoding="utf-8")
        m = re.search(
            r"for src, check_name in \((.*?)\):", src, re.S)
        self.assertIsNotNone(m, "五源循环丢失")
        self.assertNotIn('"' + "ip" + "ip" + '"', m.group(1))

    def test_cn07_strong_reachable(self):
        sources = {
            cc.CN07_CODE: {"status": "ok", "ok": True, "ms": 5, "level": "icmp",
                             "ok_nodes": 15, "nodes": 18, "ratio": 0.83},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "reachable")

    def test_cn07_degenerate_not_strong(self):
        sources = {
            cc.CN07_CODE: {"status": "ok", "ok": True, "ms": 5, "level": "icmp",
                             "ok_nodes": 1, "nodes": 18, "ratio": 0.056},
        }
        self.assertEqual(
            cc.merge_verdict(sources)["verdict"], "uncertain")


class TestJkpingMergeVerdict(unittest.TestCase):
    """CN-25：cn25 并入单节点交叉（single_ok/single_failed），与
    cn27/cn20/cn24 同权（任 2 ok → reachable，任 2 fail → unreachable）。"""

    def test_cn20_cn25_double_ok_reachable(self):
        sources = {
            cc.CN20_CODE: {"status": "ok", "ok": True, "ms": 43},
            cc.CN25_CODE: {"status": "ok", "ok": True, "ms": 12.7, "level": "icmp"},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["ms"], 12.7)

    def test_cn24_cn25_double_ok_reachable(self):
        """同站双协议（TCP+ICMP）双 ok → reachable（主机+端口双层确认）。"""
        sources = {
            cc.CN24_CODE: {"status": "ok", "ok": True, "ms": 11},
            cc.CN25_CODE: {"status": "ok", "ok": True, "ms": 12.7, "level": "icmp"},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "reachable")

    def test_cn25_alone_ok_uncertain(self):
        sources = {cc.CN25_CODE: {"status": "ok", "ok": True, "ms": 12.7,
                              "level": "icmp"}}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "uncertain")
        self.assertEqual(merged["level"], "icmp")  # 纯 ICMP 证据如实标注，不冒充 tcp

    def test_cn25_fail_plus_cn20_fail_unreachable(self):
        sources = {
            cc.CN25_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_cn25_fail_alone_uncertain(self):
        sources = {
            cc.CN25_CODE: {"status": "fail", "ok": False, "ms": None},
            cc.CN20_CODE: {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_cn25_tcp_mix_level_tcp(self):
        """ICMP + TCP 混证 → level 回落 tcp（与 cn16/cn30 混证同规则）。"""
        sources = {
            cc.CN25_CODE: {"status": "ok", "ok": True, "ms": 12.7, "level": "icmp"},
            cc.CN30_CODE: {"status": "ok", "ok": True, "ms": 60,
                        "ok_nodes": 8, "nodes": 10, "ratio": 0.8,
                        "level": "tcp"},
        }
        self.assertEqual(cc.merge_verdict(sources)["level"], "tcp")


class TestCn01PingSource(unittest.TestCase):
    """CN-26：cn01 batch_ping（同站 ICMP，大节点池）→ 独立多节点源 cn03。"""

    def test_normalize_ok_to_icmp_no_isp(self):
        """tcping 形记录（level=tcp + isp_ms）归一为 icmp 且剥离 isp_ms。"""
        out = cc._batch_ping_normalize({
            "status": "ok", "ok": True, "ms": 22.0, "level": "tcp",
            "ok_nodes": 20, "nodes": 24, "ratio": 0.83,
            "isp_ms": {"中国电信": 5.0},
        })
        self.assertEqual(out["level"], "icmp")
        self.assertNotIn("isp_ms", out)
        self.assertEqual(out["ms"], 22.0)

    def test_normalize_fail_passthrough(self):
        src = {"status": "fail", "ok": False, "ms": None, "error": "x",
               "level": None, "ok_nodes": 0, "nodes": 24, "ratio": 0.0}
        self.assertEqual(cc._batch_ping_normalize(src)["status"], "fail")

    def test_strong_reachable_level_icmp(self):
        sources = {"cn03": {
            "status": "ok", "ok": True, "ms": 22.0, "level": "icmp",
            "ok_nodes": 20, "nodes": 24, "ratio": 0.83}}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "icmp")

    def test_weak_ratio_uncertain(self):
        sources = {"cn03": {
            "status": "ok", "ok": True, "ms": 22.0, "level": "icmp",
            "ok_nodes": 1, "nodes": 24, "ratio": 0.04}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_fail_plus_single_fail_unreachable(self):
        sources = {
            "cn03": {"status": "fail", "ok": False, "ms": None,
                           "ok_nodes": 0, "nodes": 24, "ratio": 0.0},
            cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")


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

    def test_generate_all_cn_best_isp_suffix(self):
        """best_isp 提供时追加最快运营商名字+数据后缀；缺失键不追加。"""
        text = "1.1.1.1:443#US-42ms-5.00MB/s-fast\n2.2.2.2:443#US-77ms\n"
        reachable = {"1.1.1.1:443#US", "2.2.2.2:443#US"}
        best = {"1.1.1.1:443#US": "移动=57ms"}
        cn_text, count = cc.generate_all_cn(text, reachable, best_isp=best)
        self.assertEqual(count, 2)
        # 后缀随行追加（在 CN 之后），键级缺失则不出现
        lines = cn_text.strip().splitlines()
        self.assertIn("-CN-移动=57ms", lines[0])
        self.assertNotIn("=", lines[1])

    def test_generate_cn_subset_best_isp_suffix(self):
        text = "1.1.1.1:443#US-42ms\n2.2.2.2:443#US-77ms-5.00MB/s\n"
        keep = {"1.1.1.1:443#US"}
        best = {"1.1.1.1:443#US": "电信=81ms"}
        cn_text, count = cc.generate_cn_subset(
            text, lambda k, l: k in keep, best_isp=best
        )
        self.assertEqual(count, 1)
        self.assertIn("-电信=81ms", cn_text)

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

    def test_sort_by_ms_explicit_none_last_stable(self):
        """R9：cn_ms 显式 None 值与缺键同等垫底（旧实现 None<float 直接
        TypeError；生产尚无 None 入表，此处锁防御）。"""
        lines = ["1.1.1.1:443#US-9ms", "2.2.2.2:443#US-5ms",
                 "3.3.3.3:443#US-1ms"]
        cn_ms = {"1.1.1.1:443#US": 300, "2.2.2.2:443#US": None}
        out = cc._sort_by_ms(lines, cn_ms)
        self.assertEqual(
            [l.split("#")[0] for l in out],
            ["1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443"],
        )

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
            # cn14 1ms vs cn20 234ms → 取 234（大陆视角）
            "1.1.1.1:443#US": {"ms": 1, "sources": {
                cc.CN20_CODE: {"status": "ok", "ms": 234.0},
                cc.CN14_CODE: {"status": "ok", "ms": 1}}},
            # cn20 35 / cn24 80 → 取 35（多大陆源取最小）
            "2.2.2.2:443#US": {"sources": {
                cc.CN20_CODE: {"status": "ok", "ms": 35.0},
                cc.CN24_CODE: {"status": "ok", "ms": 80.0}}},
            # 无大陆探测，回退合并 ms
            "3.3.3.3:443#US": {"ms": 42, "sources": {
                cc.CN30_CODE: {"status": "ok", "ms": 42}}},
            # 无 sources 老条目：用 entry ms
            "4.4.4.4:443#US": {"ms": 88},
            # 噪声且无 valid ms → None（不展示伪造值）
            "5.5.5.5:443#US": {"ms": 0, "sources": {cc.CN14_CODE: {"status": "ok", "ms": 1}}},
            # merged ms 被 1ms 污染，但 cn30 有 88ms 可信读数 → 取 88
            "6.6.6.6:443#US": {"ms": 1, "sources": {
                cc.CN14_CODE: {"status": "ok", "ms": 1},
                cc.CN30_CODE: {"status": "ok", "ms": 88.0}}},
            # 唯一 ok 为 cn16（纯 ICMP）且给 2ms 假象 → 不得冒充大陆延迟；
            # entry 合并 ms 亦被 2ms 污染 → None（宁缺勿假）
            "7.7.7.7:443#US": {"ms": 2, "sources": {
                cc.CN16_CODE: {"status": "ok", "ms": 2.0}}},
            # cn16 假象 + cn30 真实 174ms → 取 174（非 2）
            "8.8.8.8:443#US": {"sources": {
                cc.CN16_CODE: {"status": "ok", "ms": 2.0},
                cc.CN30_CODE: {"status": "ok", "ms": 174.8}}},
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

    def test_cn_fastest_ms_prefers_isp_min(self):
        """最快运营商视角：isp_ms 全局最小优先，噪声（≤2ms）剔除，无则回退。"""
        import common

        cases = {
            # cn01 三网：电信 45 / 联通 88 / 移动 120 → 取 45（最快运营商）
            "a:443#US": {"sources": {
                cc.CN20_CODE: {"status": "ok", "ms": 60.0},
                "cn01": {"status": "ok", "ms": 45.0}},
                "isp_ms": {"中国电信": 45.0, "中国联通": 88.0, "中国移动": 120.0}},
            # 无 per-ISP 数据 → 回退 cn_display_ms（可信探测）
            "b:443#US": {"sources": {
                cc.CN20_CODE: {"status": "ok", "ms": 70.0},
                cc.CN24_CODE: {"status": "ok", "ms": 90.0}}},
            # isp_ms 全部 ≤2ms（噪声）→ 剔除后回退
            "c:443#US": {"sources": {cc.CN20_CODE: {"status": "ok", "ms": 35.0}},
                         "isp_ms": {"中国电信": 1.0, "中国移动": 2.0}},
            # 仅一个运营商有值 → 取该值
            "d:443#US": {"sources": {cc.CN20_CODE: {"status": "ok", "ms": 40.0}},
                         "isp_ms": {"中国联通": 88.0}},
            # 无任何读数 → None
            "e:443#US": {"sources": {cc.CN14_CODE: {"status": "ok", "ms": 1.0}}},
        }
        got = {k: common.cn_fastest_ms(v) for k, v in cases.items()}
        self.assertEqual(got, {
            "a:443#US": 45.0,
            "b:443#US": 70.0,
            "c:443#US": 35.0,
            "d:443#US": 88.0,
            "e:443#US": None,
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
            "167.88.160.144:8443#US→US-88ms-≈1MB/s-DC-V4\n"   # 噪声源(cn14 1ms) vs L2 234
            "8.8.8.8:443#DE→DE-30ms-≈1MB/s-GPT-V4\n"          # L2 35ms
            "2.2.2.2:443#US→US-10ms-≈1MB/s-RES-V4\n"          # 无 L2，回退 42ms
        )
        entries = {
            "167.88.160.144:8443#US": {"verdict": "reachable", "sources": {
                cc.CN20_CODE: {"status": "ok", "ms": 234.0},
                cc.CN14_CODE: {"status": "ok", "ms": 1}}},
            "8.8.8.8:443#DE": {"verdict": "reachable", "sources": {
                cc.CN20_CODE: {"status": "ok", "ms": 35.0}}},
            "2.2.2.2:443#US": {"verdict": "reachable", "ms": 42, "sources": {
                cc.CN30_CODE: {"status": "ok", "ms": 42}}},
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

    def test_load_sample_falls_back_when_source_missing(self):
        """R96跨工作流：上游未产出 source 时读 FALLBACK_SOURCE。"""
        missing = self._path("china_check_nonexistent.txt")
        fallback = self._path("china_check_fallback.txt")
        fallback.write_text("9.9.9.9:443#DE-9ms\n", encoding="utf-8")
        old = cc.FALLBACK_SOURCE
        cc.FALLBACK_SOURCE = fallback
        try:
            sample, used = cc.load_sample(missing, limit=0)
        finally:
            cc.FALLBACK_SOURCE = old
        self.assertEqual([s[1] for s in sample], ["9.9.9.9:443#DE"])
        self.assertEqual(used, fallback)

    def test_load_sample_both_missing_returns_empty(self):
        """R96跨工作流：双缺失返回空样本（调用方退出 2，不崩溃）。"""
        missing = self._path("china_check_nonexistent_both.txt")
        old = cc.FALLBACK_SOURCE
        cc.FALLBACK_SOURCE = self._path("china_check_fallback_missing.txt")
        try:
            sample, used = cc.load_sample(missing, limit=0)
        finally:
            cc.FALLBACK_SOURCE = old
        self.assertEqual(sample, [])
        self.assertEqual(used, missing)

    def test_main_exits_2_on_empty_sample_r97(self):
        """R97网络健壮性：空样本时 main 返回 2 且不触探测/写盘。

        锁住 R96 的 fail-soft 契约（缺产出/双缺失均经此路）。
        """
        import io
        from contextlib import redirect_stderr
        from pathlib import Path
        from unittest import mock
        with mock.patch.object(cc, "read_json", return_value={}), \
             mock.patch.object(cc, "load_sample",
                               return_value=([], Path("nope.txt"))), \
             mock.patch.object(cc, "run_measurements",
                               side_effect=AssertionError("must not probe")):
            buf = io.StringIO()
            with redirect_stderr(buf):
                rc = cc.main(["--limit", "5"])
            self.assertEqual(rc, 2)
            self.assertIn("no sample", buf.getvalue())

    def test_list_cn_prints_registry_r100(self):
        """R100可发现性：--list-cn 输出 44 代号＋表头（动态读注册表）。"""
        import io
        from contextlib import redirect_stdout
        from unittest import mock
        with mock.patch.object(cc, "run_measurements",
                               side_effect=AssertionError("must not probe")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cc.main(["--list-cn"])
            self.assertEqual(rc, 0)
        lines = buf.getvalue().splitlines()
        self.assertEqual(len(lines), 45)
        self.assertTrue(lines[0].startswith("code plugin"))
        self.assertTrue(all(l.startswith("cn") for l in lines[1:]))

    def test_list_cn_without_bundle_r100(self):
        """R100：无包时 --list-cn 提示并返回 2（fail-open）。"""
        import io
        from contextlib import redirect_stderr
        old = cc._SOURCES_REG
        cc._SOURCES_REG = False
        try:
            buf = io.StringIO()
            with redirect_stderr(buf):
                rc = cc.main(["--list-cn"])
            self.assertEqual(rc, 2)
            self.assertIn("bundle missing", buf.getvalue())
        finally:
            cc._SOURCES_REG = old


    def test_list_cn_matches_registry_r102(self):
        """R102功能完整性：--list-cn 输出与注册表逐行一致。"""
        import io
        from contextlib import redirect_stdout
        reg = cc._sources_registry()
        if reg is None:
            self.skipTest("needs PCB _sources bundle")
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cc.main(["--list-cn"]), 0)
        rows = {}
        for line in buf.getvalue().splitlines()[1:]:
            parts = line.split()
            rows[parts[0]] = parts[1:]
        self.assertEqual(len(rows), 44)
        self.assertEqual(sorted(rows), reg.codes())
        for e in reg.SOURCES:
            cols = rows[e["code"]]
            self.assertEqual(cols[0], e["plugin"])
            self.assertEqual(cols[1], e["family"])

    def test_list_cn_output_has_no_true_names_r105(self):
        """R105安全合规：--list-cn 输出不得含真名根（func 列已摘除）。"""
        import io
        import re
        from contextlib import redirect_stdout
        try:
            meta = cc._load_pcb_plugin("_metadata")
        except Exception:
            self.skipTest("needs PCB _metadata bundle")
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cc.main(["--list-cn"]), 0)
        out = buf.getvalue()
        bad = [r for r in meta.true_roots()
               if re.search(r"(?<![A-Za-z0-9_])" + re.escape(r) +
                           r"(?![A-Za-z0-9_])", out, re.IGNORECASE)]
        self.assertEqual(bad, [])

    def test_help_references_list_cn_r101(self):
        """R101用户侧体验：--help 须指引 --list-cn（发现闭环）。"""
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                cc.main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        out = buf.getvalue()
        self.assertGreaterEqual(out.count("--list-cn"), 4)

class TestHelpDocsFlagsR103(unittest.TestCase):
    """R103功能查找：--help 旗标集与 docs 章节双向一致（增删旗标须同步）。"""

    DOC_HEADER = "### `scripts/china_check.py`"

    def _help_flags(self):
        import re
        import subprocess
        import sys
        from pathlib import Path
        proc = subprocess.run(
            [sys.executable, str(Path(cc.__file__).with_name("china_check.py")),
             "--help"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0)
        return (set(re.findall(r"--([a-z0-9][a-z0-9\-]*)", proc.stdout))
                - {"help"})

    def _docs_flags(self):
        import re
        from pathlib import Path
        lines = (Path(cc.__file__).resolve().parent.parent
                 / "docs" / "scripts.md").read_text(encoding="utf-8").splitlines()
        start = next(i for i, l in enumerate(lines) if l.strip() == self.DOC_HEADER)
        stop = next((i for i in range(start + 1, len(lines))
                     if lines[i].startswith("### ")), len(lines))
        got = set()
        for line in lines[start:stop]:
            got.update(re.findall(r"--([a-z0-9][a-z0-9\-]*)", line))
        return {f for f in got if not f.endswith("-")}  # 排除 --cn- 类占位符

    def test_help_docs_flags_match(self):
        self.assertEqual(self._help_flags(), self._docs_flags())


class TestBuildEntry(unittest.TestCase):
    def test_build_entry_shape(self):
        item = ("1.2.3.4:2087#US", "1.2.3.4:2087#US", "1.2.3.4", "2087", "US")
        entry = cc.build_entry(item, {
            cc.CN27_CODE: {"status": "ok", "ok": True, "ms": 100},
            cc.CN20_CODE: {"status": "ok", "ok": True, "ms": 80},
        })
        self.assertEqual(entry["verdict"], "reachable")
        self.assertEqual(entry["ip"], "1.2.3.4")
        self.assertIn("ts", entry)
        self.assertEqual(entry["sources"][cc.CN27_CODE]["ms"], 100)


class TestWsReadContract(unittest.TestCase):
    """真实 _WebSocket.read 契约：socket.timeout/连接错必须转译为
    ("timeout"/"err")，否则 collect 的墙钟 deadline 会被阻塞 read 架空。"""

    class _FakeSock:
        def __init__(self, exc):
            self._exc = exc

        def recv(self, n):
            raise self._exc

        def settimeout(self, t):
            pass

    def _read(self, exc):
        ws = wt._WebSocket.__new__(wt._WebSocket)
        ws.sock = self._FakeSock(exc)
        ws.buf = b""
        return ws.read()

    def test_socket_timeout_becomes_timeout(self):
        self.assertEqual(self._read(socket.timeout()), ("timeout", None))

    def test_connection_error_becomes_err(self):
        kind, msg = self._read(ConnectionError("boom"))
        self.assertEqual(kind, "err")
        self.assertEqual(msg["error"], "ConnectionError")
        self.assertNotIn("boom", msg["error"])

    def test_socket_timeout_not_swallowed_as_oserror(self):
        """socket.timeout 是 OSError 子类：须先被显式分支捕获为 timeout，
        不得并入 err（否则上游静止时 collect 当作 err 提前放弃收尾）。"""
        self.assertEqual(self._read(socket.timeout()), ("timeout", None))


class TestMergeIspMs(unittest.TestCase):
    def test_merge_across_sources(self):
        entries = {
            "a:443#US": {"sources": {
                "cn01": {"isp_ms": {"中国电信": 45.0, "中国联通": 88.0}},
                cc.CN20_CODE: {"ms": 60.0},
                cc.CN30_CODE: {"isp_ms": {"中国电信": 55.0}},
            }},
        }
        cc.merge_isp_ms(entries)
        e = entries["a:443#US"]
        self.assertIn("isp_ms", e)
        self.assertEqual(e["isp_ms"], {"中国电信": 45.0, "中国联通": 88.0})

    def test_no_sources_no_isp_ms(self):
        entries = {"a:443#US": {"ms": 10}}
        cc.merge_isp_ms(entries)
        self.assertNotIn("isp_ms", entries["a:443#US"])

    def test_merge_four_isp_sources(self):
        """CN-08：cn01/cn30/cn11/cn09 四源 isp_ms 跨源取最小
        （词表由各生产侧保证，合并只过滤非正数值）。"""
        entries = {
            "a:443#US": {"sources": {
                "cn01": {"isp_ms": {"中国电信": 45.0, "中国联通": 88.0}},
                cc.CN30_CODE: {"isp_ms": {"中国电信": 20.0, "中国移动": 50.0}},
                cc.CN11_CODE: {"isp_ms": {"中国联通": 9.0}},
                cc.CN09_CODE: {"isp_ms": {"中国移动": 60.0}},
            }},
        }
        cc.merge_isp_ms(entries)
        self.assertEqual(
            entries["a:443#US"]["isp_ms"],
            {"中国电信": 20.0, "中国联通": 9.0, "中国移动": 50.0})

    def test_negative_ms_ignored(self):
        entries = {"a:443#US": {"sources": {"cn01": {"isp_ms": {"电信": -1.0}}}}}
        cc.merge_isp_ms(entries)
        self.assertNotIn("isp_ms", entries["a:443#US"])


class TestMergeIspSpeed(unittest.TestCase):
    """CN-41：isp_ms 派生 isp_speed（只增字段，同公式估算上限）。"""

    def test_derives_per_isp_speed(self):
        entries = {"a:443#US": {"isp_ms": {"中国电信": 120.0, "中国移动": 60.0}}}
        cc.merge_isp_speed(entries)
        self.assertEqual(
            entries["a:443#US"]["isp_speed"],
            {"中国电信": 4.0, "中国移动": 8.0})

    def test_no_isp_ms_no_field(self):
        entries = {"a:443#US": {"ms": 10}}
        cc.merge_isp_speed(entries)
        self.assertNotIn("isp_speed", entries["a:443#US"])

    def test_all_noise_no_field(self):
        entries = {"a:443#US": {"isp_ms": {"中国移动": 1.5}}}
        cc.merge_isp_speed(entries)
        self.assertNotIn("isp_speed", entries["a:443#US"])


class TestCn01MergeVerdict(unittest.TestCase):
    def _s(self, status):
        return {"status": status, "ok": status == "ok", "ms": 12 if status == "ok" else None}

    def test_cn01_ok_reachable(self):
        sources = {"cn01": self._s("ok"), cc.CN27_CODE: self._s("error")}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "reachable")

    def test_cn01_fail_alone_uncertain(self):
        sources = {"cn01": self._s("fail"), cc.CN27_CODE: self._s("error")}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_cn01_fail_plus_single_fail(self):
        sources = {"cn01": self._s("fail"), cc.CN27_CODE: self._s("fail")}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_cn40_fail_plus_cn01_fail(self):
        sources = {cc.CN40_CODE: self._s("fail"), "cn01": self._s("fail")}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_cn01_rate_limited_neutral(self):
        sources = {"cn01": {"status": "rate_limited", "ok": False, "ms": None},
                   cc.CN27_CODE: {"status": "error", "ok": False, "ms": None}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "skipped")


class TestMergeVerdictLevel(unittest.TestCase):
    def _src(self, status, level=None, ms=12.0):
        return {"status": status, "ok": status == "ok", "ms": ms if status == "ok" else None,
                "level": level}

    def test_http_level_propagates(self):
        sources = {
            "cn01": self._src("ok", "http"),
            cc.CN27_CODE: self._src("error"),
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "http")

    def test_tcp_only_level(self):
        sources = {"cn01": self._src("ok", "tcp")}
        self.assertEqual(cc.merge_verdict(sources)["level"], "tcp")

    def test_no_ok_sources_level_none(self):
        sources = {cc.CN27_CODE: self._src("fail"), cc.CN20_CODE: self._src("fail")}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "unreachable")
        self.assertIsNone(merged["level"])

    def test_sources_without_level_field(self):
        # 旧格式源（无 level 字段）不报错，按 tcp 计
        sources = {"cn01": {"status": "ok", "ok": True, "ms": 10}}
        self.assertEqual(cc.merge_verdict(sources)["level"], "tcp")

    def test_cn01_tcping_is_multi_node_source(self):
        # batch_http 失败 + batch_tcping 单独 ok → reachable（多节点源）
        sources = {
            "cn01": self._src("fail"),
            "cn02": self._src("ok", "tcp"),
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["basis"], ["cn02"])

    def test_cn01_tcping_fail_plus_single_fail_unreachable(self):
        sources = {
            "cn02": self._src("fail"),
            cc.CN27_CODE: self._src("fail"),
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


class TestWriteCnSubset(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())
        self.f = self.tmp / "sub.txt"

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_writes_nonempty(self):
        cc.write_cn_subset(self.f, "a\n")
        self.assertEqual(self.f.read_text(encoding="utf-8"), "a\n")

    def test_empty_unlinks_stale(self):
        self.f.write_text("stale\n", encoding="utf-8")
        cc.write_cn_subset(self.f, "")
        self.assertFalse(self.f.exists())

    def test_empty_without_stale_is_noop(self):
        cc.write_cn_subset(self.f, "")
        self.assertFalse(self.f.exists())


class TestScarceQuotaAllocation(unittest.TestCase):
    """cn27 稀缺配额（~250/h）只投递决策键：cn20 明确 fail 者省略，
    预算全部用于 cn20 ok / 临时性失败者 —— 提高「把 uncertain 翻成
    reachable」的转换率，而不放宽判定杠。"""

    def _args(self):
        from types import SimpleNamespace

        return SimpleNamespace(cn_limit={"cn30": 0, "cn31": 0, "cn32": 0, "cn33": 0, "cn40": 0}, 
            skip_cn01=True,
            skip_cn02=True,
                
            workers=4,
            timeout=5,
            api_key="",
        )

    def test_cn27_skipped_when_pair_confirmed(self):
        """cn20+cn24 双免额单节点已 double-ok → 稀配额 cn27 直接让位。"""
        import unittest.mock as mock

        items = [
            ("1.1.1.1:80#US", "1.1.1.1:80#US", "1.1.1.1", "80", "US"),
            ("2.2.2.2:80#US", "2.2.2.2:80#US", "2.2.2.2", "80", "US"),
        ]

        def fake_cn20(ip, port, timeout):
            return {"status": "ok", "ok": True, "ms": float(port)}

        def fake_cn27(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 1.0}

        def fake_ssl_review(ip, port, timeout):
            return {"status": "ok", "ok": True, "ms": float(port)}

        with mock.patch.object(cc, "cn20_check", side_effect=fake_cn20), mock.patch.object(
            cc, "cn27_check", side_effect=fake_cn27
        ) as mch, mock.patch.object(cc, "cn24_check", side_effect=fake_ssl_review), \
                mock.patch.object(cc, "cn25_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn21_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn26_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn22_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn23_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual(mch.call_args_list, [])
        self.assertEqual(set(reachable), {"1.1.1.1:80#US", "2.2.2.2:80#US"})

    def test_cn27_skipped_when_pair_failed(self):
        """cn20+cn24 双 fail → 已判 unreachable，同样不再浪费稀配额。"""
        import unittest.mock as mock

        items = [("3.3.3.3:80#US", "3.3.3.3:80#US", "3.3.3.3", "80", "US")]

        def fake_cn20(ip, port, timeout):
            return {"status": "fail", "ok": False, "ms": None, "error": ""}

        def fake_cn27(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 1.0}

        def fake_ssl_review(ip, port, timeout):
            return {"status": "fail", "ok": False, "ms": None, "error": ""}

        with mock.patch.object(cc, "cn20_check", side_effect=fake_cn20), mock.patch.object(
            cc, "cn27_check", side_effect=fake_cn27
        ) as mch, mock.patch.object(cc, "cn24_check", side_effect=fake_ssl_review), \
                mock.patch.object(cc, "cn25_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn21_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn26_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn22_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn23_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}):
            entries, _, _ = cc.run_measurements(items, self._args())

        self.assertEqual(mch.call_args_list, [])
        self.assertEqual(entries["3.3.3.3:80#US"]["verdict"], "unreachable")

    def test_cn27_probes_single_ok_for_second_confirm(self):
        """恰好 1 只免额单节点 ok → cn27 补足到双确认即翻正。"""
        import unittest.mock as mock

        items = [("4.4.4.4:80#US", "4.4.4.4:80#US", "4.4.4.4", "80", "US")]

        def fake_cn20(ip, port, timeout):
            return {"status": "ok", "ok": True, "ms": float(port)}

        def fake_cn27(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 1.0}

        def fake_ssl_review(ip, port, timeout):
            return {"status": "error", "ok": False, "ms": None, "error": "http 500"}

        with mock.patch.object(cc, "cn20_check", side_effect=fake_cn20), mock.patch.object(
            cc, "cn27_check", side_effect=fake_cn27
        ) as mch, mock.patch.object(cc, "cn24_check", side_effect=fake_ssl_review), \
                mock.patch.object(cc, "cn25_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn21_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn26_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn22_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn23_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual([c.args[0] for c in mch.call_args_list], ["4.4.4.4"])
        self.assertEqual(set(reachable), {"4.4.4.4:80#US"})

    def test_cn25_second_confirm_skips_cn27(self):
        """CN-25：免额三源中任 2 ok 即双确认——cn20 error + cn24 ok +
        cn25 ok → 稀配额 cn27 直接让位（配额门控按计数泛化）。"""
        import unittest.mock as mock

        items = [("6.6.6.6:80#US", "6.6.6.6:80#US", "6.6.6.6", "80", "US")]

        def fake_cn20(ip, port, timeout):
            return {"status": "error", "ok": False, "ms": None, "error": "http 500"}

        def fake_cn27(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 1.0}

        with mock.patch.object(cc, "cn20_check", side_effect=fake_cn20), mock.patch.object(
            cc, "cn27_check", side_effect=fake_cn27
        ) as mch, mock.patch.object(cc, "cn24_check",
                                    return_value={"status": "ok", "ok": True,
                                                  "ms": 11.0}), \
                mock.patch.object(cc, "cn25_check",
                                  return_value={"status": "ok", "ok": True,
                                                "ms": 12.7, "level": "icmp"}), \
                mock.patch.object(cc, "cn21_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn26_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn22_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn23_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual(mch.call_args_list, [])
        self.assertEqual(set(reachable), {"6.6.6.6:80#US"})

    def test_cn21_second_confirm_skips_cn27(self):
        """CN-29：免额四源中任 2 ok 即双确认——cn24 ok + cn21 ok
        （余者 error）→ 稀配额 cn27 直接让位。"""
        import unittest.mock as mock

        items = [("7.7.7.7:80#US", "7.7.7.7:80#US", "7.7.7.7", "80", "US")]

        def fake_cn20(ip, port, timeout):
            return {"status": "error", "ok": False, "ms": None, "error": "http 500"}

        def fake_cn27(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 1.0}

        with mock.patch.object(cc, "cn20_check", side_effect=fake_cn20), mock.patch.object(
            cc, "cn27_check", side_effect=fake_cn27
        ) as mch, mock.patch.object(cc, "cn24_check",
                                    return_value={"status": "ok", "ok": True,
                                                  "ms": 11.0}), \
                mock.patch.object(cc, "cn25_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn21_check",
                                  return_value={"status": "ok", "ok": True,
                                                "ms": 42.1, "level": "icmp"}), \
                mock.patch.object(cc, "cn26_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn22_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn23_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual(mch.call_args_list, [])
        self.assertEqual(set(reachable), {"7.7.7.7:80#US"})

    def test_scan_second_confirm_skips_cn27(self):
        """CN-39：免额单节点源中任 2 ok 即双确认——cn20 + cn23 ok
        （余者 error）→ 稀配额 cn27 直接让位。"""
        import unittest.mock as mock

        items = [("8.8.4.4:80#US", "8.8.4.4:80#US", "8.8.4.4", "80", "US")]

        def fake_cn20(ip, port, timeout):
            return {"status": "ok", "ok": True, "ms": 43.0}

        def fake_cn27(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 1.0}

        with mock.patch.object(cc, "cn20_check", side_effect=fake_cn20), mock.patch.object(
            cc, "cn27_check", side_effect=fake_cn27
        ) as mch, mock.patch.object(cc, "cn24_check",
                                    return_value={"status": "error", "ok": False,
                                                  "ms": None, "error": "x"}), \
                mock.patch.object(cc, "cn25_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "x"}), \
                mock.patch.object(cc, "cn21_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "x"}), \
                mock.patch.object(cc, "cn26_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "x"}), \
                mock.patch.object(cc, "cn22_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "x"}), \
                mock.patch.object(cc, "cn23_check",
                                  return_value={"status": "ok", "ok": True,
                                                "ms": None, "level": "tcp"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual(mch.call_args_list, [])
        self.assertEqual(set(reachable), {"8.8.4.4:80#US"})

    def test_cn20_error_still_gets_second_opinion(self):
        import unittest.mock as mock

        items = [("9.9.9.9:443#US", "9.9.9.9:443#US", "9.9.9.9", "443", "US")]

        def fake_cn20(ip, port, timeout):
            return {"status": "error", "ok": False, "ms": None, "error": "http 500"}

        def fake_cn27(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 5.0}

        with mock.patch.object(cc, "cn20_check", side_effect=fake_cn20), mock.patch.object(
            cc, "cn27_check", side_effect=fake_cn27
        ) as mch, mock.patch.object(cc, "cn24_check",
                                    return_value={"status": "error", "ok": False,
                                                  "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn25_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn21_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn26_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn22_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn23_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn29_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "cn28_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual(len(mch.call_args_list), 1)
        self.assertEqual(set(reachable), set())
        self.assertEqual(entries["9.9.9.9:443#US"]["verdict"], "uncertain")


class TestSlotRunnerCrashIsolation(unittest.TestCase):
    """任一复核源单键异常不得拖垮整轮（真实事故：cn17 cookie 超时
    未被捕获 → 4h50m 探测全部作废）。所有槽位 runner 须把异常写为 error 源。"""

    def _args(self, limits: bool = True):
        from types import SimpleNamespace

        return SimpleNamespace(cn_limit={"cn07": 1 if limits else 0, "cn08": 1 if limits else 0, "cn14": 1 if limits else 0, "cn16": 1 if limits else 0, "cn17": 1 if limits else 0, "cn30": 1 if limits else 0, "cn40": 1}, cn_concurrency={"cn07": 2, "cn08": 2, "cn14": 2, "cn16": 2, "cn17": 2, "cn30": 2}, cn_nodes={"cn30": 2}, 
            skip_cn01=True,
            skip_cn02=True,
            
            workers=4,
            timeout=5,
            api_key="",
            cn41_token="",
            
            
            
            
            
            
            
            
            
            
            
            
            
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
            mock.patch.object(cc, "cn30_fetch_nodes",
                              return_value=[{"uuid": "u1", "operator": "ct",
                                             "enabled": True,
                                             "runtime_state": "online"}]),
            mock.patch.object(cc, "cn30_pick_nodes",
                              side_effect=lambda nodes, count: ["u1", "u2"]),
            mock.patch.object(cc, "cn30_check", side_effect=self._boom),
            mock.patch.object(cc, "cn07_check", side_effect=self._boom),
            mock.patch.object(cc, "cn08_check", side_effect=self._boom),
            mock.patch.object(cc, "cn14_check", side_effect=self._boom),
            mock.patch.object(cc, "cn17_check", side_effect=self._boom),
            mock.patch.object(cc, "cn16_check", side_effect=self._boom),
            mock.patch.object(cc, "cn40_check", side_effect=self._boom),
            mock.patch.object(cc, "cn41_check", side_effect=self._boom),
            mock.patch.object(cc, "cn20_check",
                              return_value={"status": "ok", "ok": True, "ms": 1.0}),
            mock.patch.object(cc, "cn24_check", side_effect=self._boom),
            mock.patch.object(cc, "cn25_check", side_effect=self._boom),
            mock.patch.object(cc, "cn21_check", side_effect=self._boom),
            mock.patch.object(cc, "cn26_check", side_effect=self._boom),
            mock.patch.object(cc, "cn22_check", side_effect=self._boom),
            mock.patch.object(cc, "cn23_check", side_effect=self._boom),
            # cn27 也走槽位；抛异常同样须被隔离（l2_cn27 已有守卫）
            mock.patch.object(cc, "cn27_check", side_effect=self._boom),
            mock.patch.object(cc, "cn01_batch_run", return_value={}),
        ]
        for p in patches:
            p.start()
        try:
            entries, _, _ = cc.run_measurements([item], self._args())
        finally:
            for p in patches:
                p.stop()
        srcs = entries[item[1]]["sources"]
        for name in (cc.CN30_CODE, cc.CN07_CODE, cc.CN08_CODE, cc.CN14_CODE, cc.CN17_CODE,
                     cc.CN16_CODE, cc.CN40_CODE, cc.CN27_CODE, cc.CN25_CODE, cc.CN21_CODE,
                     cc.CN26_CODE, cc.CN22_CODE, cc.CN23_CODE):
            self.assertEqual(srcs[name]["status"], "error")
        # 全部错误 → 不误判（skipped/uncertain），且流程未中断
        self.assertIn(entries[item[1]]["verdict"], ("uncertain", "skipped"))


@unittest.skipUnless(cc._CN01_BUNDLE, "needs PCB cn01 bundle")
class TestCn01RestrictedToUndecidedKeys(unittest.TestCase):
    """cn01 批量代价高：只投仍未定论的键；双免额已定论（≥2 ok / ≥2 fail）
    的键不得再进 cn01 复核，且 batch_tcping 兜底按节点拉取状态触发。

    需 PCB（cn01 协议已迁入私有包；无包环境跳过）。"""

    def _args(self):
        from types import SimpleNamespace

        return SimpleNamespace(cn_limit={"cn30": 0, "cn31": 0, "cn32": 0, "cn33": 0, "cn40": 0}, 
            skip_cn01=False,
            skip_cn02=False,
                
            workers=4,
            timeout=5,
            api_key="",
            cn41_token="",
            cn01_nodes=2,
            cn01_batch_size=5,
            cn01_concurrency=2,
            cn01_pacing=0.0,
            cn01_timeout=10,
        )

    def test_cn01_sees_only_undecided_keys(self):
        import unittest.mock as mock

        decided = ("10.2.0.1:80#US", "10.2.0.1:80#US", "10.2.0.1", "80", "US")
        pending = ("10.3.0.1:80#US", "10.3.0.1:80#US", "10.3.0.1", "80", "US")
        seen = {}

        def fake_cn01(sample, args, **kwargs):
            seen["keys"] = [key for _, key, _, _, _ in sample]
            return {}

        def fake_ssl_review(ip, port, timeout):
            if ip == "10.2.0.1":
                return {"status": "ok", "ok": True, "ms": 1.0}
            return {"status": "error", "ok": False, "ms": None, "error": "x"}

        with mock.patch.object(cc, "cn20_check",
                               return_value={"status": "ok", "ok": True, "ms": 1.0}), \
              mock.patch.object(cc, "cn24_check", side_effect=fake_ssl_review), \
              mock.patch.object(cc, "cn25_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn21_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn26_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn22_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn23_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn27_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "q"}), \
              mock.patch.object(cc, "cn01_batch_run", side_effect=fake_cn01):
            cc.run_measurements([decided, pending], self._args())

        self.assertEqual(seen.get("keys"), ["10.3.0.1:80#US"])

    def test_cn02_fallback_skipped_when_cn01_fully_down(self):
        """cn01 整站失败（全 error 或被投毒全 fail）时不得空转 batch_tcping 兜底；
        已定论键（无 cn01 记录）不得被误算作「节点拉取成功」。"""
        import unittest.mock as mock

        decided = ("10.4.0.1:80#US", "10.4.0.1:80#US", "10.4.0.1", "80", "US")
        for poisoned_status in ("error", "fail"):
            stuck = ("10.8.0.1:80#US", "10.8.0.1:80#US", "10.8.0.1", "80", "US")

            def fake_cn01(sample, args, page_url=None, **kw):
                # 整站被墙/投毒：每个目标都只返回 error/fail，无任何 ok
                return {key: {"status": poisoned_status, "ok": False,
                              "ms": None, "error": "no nodes"}
                        for _, key, _, _, _ in sample}

            with mock.patch.object(cc, "cn20_check",
                                   return_value={"status": "ok", "ok": True, "ms": 1.0}), \
                  mock.patch.object(cc, "cn24_check",
                                    return_value={"status": "error", "ok": False,
                                                  "ms": None, "error": "x"}), \
                  mock.patch.object(cc, "cn25_check",
                                    return_value={"status": "error", "ok": False,
                                                  "ms": None, "error": "x"}), \
                  mock.patch.object(cc, "cn27_check",
                                    return_value={"status": "error", "ok": False,
                                                  "ms": None, "error": "q"}), \
                  mock.patch.object(cc, "cn01_batch_run", side_effect=fake_cn01) as mib:
                cc.run_measurements([decided, stuck], self._args())

            self.assertEqual(len(mib.call_args_list), 1)  # 只有一次 batch_http，无 tcping 兜底

    def test_cn02_fallback_runs_when_nodes_fetched(self):
        """cn01 节点拉取成功（部分 ok）且部分键 error → 走 batch_tcping 兜底。"""
        import unittest.mock as mock

        a = ("10.6.0.1:80#US", "10.6.0.1:80#US", "10.6.0.1", "80", "US")
        b = ("10.7.0.1:80#US", "10.7.0.1:80#US", "10.7.0.1", "80", "US")

        def fake_cn01(sample, args, page_url=None, **kw):
            out = {}
            for _, key, _, _, _ in sample:
                out[key] = ({"status": "ok", "ok": True, "ms": 5.0, "ratio": 0.9, "nodes": 12}
                            if key == a[1] else
                            {"status": "error", "ok": False, "ms": None, "error": "rl"})
            return out

        with mock.patch.object(cc, "cn20_check",
                               return_value={"status": "ok", "ok": True, "ms": 1.0}), \
              mock.patch.object(cc, "cn24_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn25_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn21_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn26_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn22_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn23_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn27_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "q"}), \
              mock.patch.object(cc, "cn01_batch_run", side_effect=fake_cn01) as mib:
            entries, _, _ = cc.run_measurements([a, b], self._args())

        calls = [c for c in mib.call_args_list]
        # batch_http + batch_tcping 兜底 + batch_ping 兜底（CN-26 新增）
        self.assertEqual(len(calls), 3)
        page_urls = [c.kwargs.get("page_url") for c in calls]
        self.assertIn(cc.CN02_PAGE_URL, page_urls)
        self.assertIn(cc.CN03_PAGE_URL, page_urls)
        fallback = next(c for c in calls if c.kwargs.get("page_url") == cc.CN02_PAGE_URL)
        self.assertEqual([key for _, key, _, _, _ in fallback.args[0]],
                         ["10.7.0.1:80#US"])
        ping_call = next(c for c in calls if c.kwargs.get("page_url") == cc.CN03_PAGE_URL)
        self.assertEqual([key for _, key, _, _, _ in ping_call.args[0]],
                         ["10.7.0.1:80#US"])
        # ping 结果归一落地：level=icmp、无 isp_ms
        ping_res = entries["10.7.0.1:80#US"]["sources"]["cn03"]
        self.assertEqual(ping_res["status"], "error")  # 替身回 error，原样落地


class TestBiupingPingSource(unittest.TestCase):
    """CN-34：cn10（同站 ICMP，复用 port="" 分支）。"""

    def test_strong_reachable(self):
        sources = {cc.CN10_CODE: {
            "status": "ok", "ok": True, "ms": 7.5, "level": "icmp",
            "ok_nodes": 39, "nodes": 39, "ratio": 1.0}}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "icmp")

    def test_weak_ratio_uncertain(self):
        sources = {cc.CN10_CODE: {
            "status": "ok", "ok": True, "ms": 7.5, "level": "icmp",
            "ok_nodes": 1, "nodes": 39, "ratio": 0.026}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_fail_plus_single_fail_unreachable(self):
        sources = {
            cc.CN10_CODE: {"status": "fail", "ok": False, "ms": None,
                             "ok_nodes": 0, "nodes": 39, "ratio": 0.0},
            cc.CN24_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 7.5, "level": "icmp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(
            cc.merge_verdict({cc.CN10_CODE: dict(src)})["verdict"],
            "reachable")
        old = cc._SOURCE_MIN_RATIO[cc.CN10_CODE]
        cc._SOURCE_MIN_RATIO[cc.CN10_CODE] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({cc.CN10_CODE: dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO[cc.CN10_CODE] = old

    def test_raw_slot_dispatch(self):
        cands = [("1.2.3.4:443#US line", "1.2.3.4:443#US",
                  "1.2.3.4", "443", "US")]
        entries: dict = {"1.2.3.4:443#US": {}}
        with mock.patch.object(
                cc, "cn10_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_raw_slots(cands, entries, 5, cc.CN10_CODE, 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(
            entries["1.2.3.4:443#US"][cc.CN10_CODE]["status"], "ok")


class TestAntpingPingSource(unittest.TestCase):
    """CN-28：同站 ICMP，复用 code=3 分支。"""

    def test_strong_reachable(self):
        sources = {cc.CN15_CODE: {
            "status": "ok", "ok": True, "ms": 1, "level": "icmp",
            "ok_nodes": 178, "nodes": 179, "ratio": 0.994}}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "icmp")

    def test_weak_ratio_uncertain(self):
        sources = {cc.CN15_CODE: {
            "status": "ok", "ok": True, "ms": 1, "level": "icmp",
            "ok_nodes": 1, "nodes": 179, "ratio": 0.006}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_fail_plus_single_fail_unreachable(self):
        sources = {
            cc.CN15_CODE: {"status": "fail", "ok": False, "ms": None,
                             "ok_nodes": 0, "nodes": 186, "ratio": 0.0},
            cc.CN24_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 1, "level": "icmp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(cc.merge_verdict({cc.CN15_CODE: dict(src)})["verdict"],
                         "reachable")
        old = cc._SOURCE_MIN_RATIO[cc.CN15_CODE]
        cc._SOURCE_MIN_RATIO[cc.CN15_CODE] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({cc.CN15_CODE: dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO[cc.CN15_CODE] = old

    def test_ws_slot_dispatch(self):
        """通用 WS slot 须能派发同站 ping 槽且只写本源键。"""
        cands = [("1.2.3.4:443#US line", "1.2.3.4:443#US",
                  "1.2.3.4", "443", "US")]
        entries: dict = {"1.2.3.4:443#US": {}}
        with mock.patch.object(
                cc, "cn15_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_ws_source_slots(cands, entries, 5, cc.CN15_CODE, 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(
            entries["1.2.3.4:443#US"][cc.CN15_CODE]["status"], "ok")


class TestGlobalpingSource(unittest.TestCase):
    """CN-46：Globalping 北京探针 ICMP（公开侧只留合并判定与默认 opt-in；
    协议细节见 pcb/tests/test_cn36.py）。"""

    def test_single_vote_wiring(self):
        """单节点票：与同站 status 槽交叉即 reachable；孤证 uncertain；双 fail 定罪。"""
        ok = {"status": "ok", "ok": True, "ms": 5.7, "level": "icmp"}
        xx = {"status": "ok", "ok": True, "ms": 60.0}
        self.assertEqual(
            cc.merge_verdict({cc.CN36_CODE: ok, cc.CN20_CODE: xx})["verdict"],
            "reachable")
        self.assertEqual(
            cc.merge_verdict({cc.CN36_CODE: dict(ok)})["verdict"],
            "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None}
        self.assertEqual(
            cc.merge_verdict({cc.CN36_CODE: dict(fail),
                              cc.CN20_CODE: dict(fail)})["verdict"],
            "unreachable")

    def test_cli_default_stays_opt_in(self):
        """CN-46：复核 ping 本地默认 opt-in（0/4），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn36")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn36")["concurrency"], 4)


class TestGlobalpingTraceSource(unittest.TestCase):
    """CN-47：Globalping 路由追踪（公开侧只留合并判定与默认 opt-in）。"""

    def test_single_vote_wiring(self):
        ok = {"status": "ok", "ok": True, "ms": None, "level": "icmp"}
        xx = {"status": "ok", "ok": True, "ms": 60.0}
        self.assertEqual(
            cc.merge_verdict(
                {cc.CN37_CODE: ok, cc.CN20_CODE: xx})["verdict"],
            "reachable")
        self.assertEqual(
            cc.merge_verdict(
                {cc.CN37_CODE: dict(ok)})["verdict"],
            "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None}
        self.assertEqual(
            cc.merge_verdict({cc.CN37_CODE: dict(fail),
                              cc.CN20_CODE: dict(fail)})["verdict"],
            "unreachable")

    def test_cli_default_stays_opt_in(self):
        """CN-47：复核 trace 本地默认 opt-in（0/4），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn37")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn37")["concurrency"], 4)


class TestGlobalpingHttpSource(unittest.TestCase):
    """CN-48：Globalping 应用层确认（公开侧只留合并判定与默认 opt-in）。"""

    def test_single_vote_wiring(self):
        ok = {"status": "ok", "ok": True, "ms": 5.0, "level": "http"}
        xx = {"status": "ok", "ok": True, "ms": 60.0}
        self.assertEqual(
            cc.merge_verdict(
                {cc.CN38_CODE: ok, cc.CN20_CODE: xx})["verdict"],
            "reachable")
        self.assertEqual(
            cc.merge_verdict(
                {cc.CN38_CODE: dict(ok)})["verdict"],
            "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None}
        self.assertEqual(
            cc.merge_verdict({cc.CN38_CODE: dict(fail),
                              cc.CN20_CODE: dict(fail)})["verdict"],
            "unreachable")

    def test_cli_default_stays_opt_in(self):
        """CN-48：复核 http 本地默认 opt-in（0/4），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn38")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn38")["concurrency"], 4)


class TestGlobalpingMtrSource(unittest.TestCase):
    """CN-49：Globalping MTR（公开侧只留合并判定与默认 opt-in）。"""

    def test_single_vote_wiring(self):
        ok = {"status": "ok", "ok": True, "ms": None, "level": "icmp"}
        xx = {"status": "ok", "ok": True, "ms": 60.0}
        self.assertEqual(
            cc.merge_verdict(
                {cc.CN39_CODE: ok, cc.CN20_CODE: xx})["verdict"],
            "reachable")
        self.assertEqual(
            cc.merge_verdict(
                {cc.CN39_CODE: dict(ok)})["verdict"],
            "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None}
        self.assertEqual(
            cc.merge_verdict({cc.CN39_CODE: dict(fail),
                              cc.CN20_CODE: dict(fail)})["verdict"],
            "unreachable")

    def test_cli_default_stays_opt_in(self):
        """CN-49：复核 mtr 本地默认 opt-in（0/4），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn39")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn39")["concurrency"], 4)


class TestTcptestHttpMergeVerdict(unittest.TestCase):
    """CN-35：应用层复核并入多节点合成判定。"""

    def test_merge_strong_weak_fail(self):
        strong = {"status": "ok", "ok": True, "ms": 15.8, "level": "http",
                  "ok_nodes": 8, "nodes": 10, "ratio": 0.8}
        merged = cc.merge_verdict({cc.CN32_CODE: strong})
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "http")
        weak = dict(strong, ok_nodes=1, nodes=10, ratio=0.1)
        self.assertEqual(cc.merge_verdict(
            {cc.CN32_CODE: weak})["verdict"], "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None,
                "ok_nodes": 0, "nodes": 10, "ratio": 0.0}
        self.assertEqual(cc.merge_verdict(
            {cc.CN32_CODE: fail,
             cc.CN20_CODE: {"status": "fail", "ok": False,
                       "ms": None}})["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 15.8, "level": "http",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(
            cc.merge_verdict({cc.CN32_CODE: dict(src)})["verdict"],
            "reachable")
        old = cc._SOURCE_MIN_RATIO[cc.CN32_CODE]
        cc._SOURCE_MIN_RATIO[cc.CN32_CODE] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({cc.CN32_CODE: dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO[cc.CN32_CODE] = old

    def test_phase_runs_http_only(self):
        """TCP/ping 0 ＋ http 1 → 只跑 http 通道。"""
        from types import SimpleNamespace

        args = SimpleNamespace(cn_limit={"cn04": 0, "cn07": 0, "cn08": 0, "cn09": 0, "cn10": 0, "cn11": 0, "cn13": 0, "cn14": 0, "cn15": 0, "cn16": 0, "cn17": 0, "cn18": 0, "cn30": 0, "cn31": 0, "cn32": 1, "cn34": 0, "cn40": 0, "cn42": 0, "cn43": 0, "cn44": 0}, cn_concurrency={"cn04": 2, "cn10": 2, "cn30": 2, "cn31": 2, "cn32": 2}, cn_nodes={"cn30": 2}, 
            skip_cn01=True, skip_cn02=True, 
            workers=4, timeout=5, api_key="", cn41_token="",
              
             
             
              
              
              
             
             
             
            )
        item = ("10.9.9.9:443#US", "10.9.9.9:443#US", "10.9.9.9", "443", "US")
        seen_types = []

        def fake_check(ip, port, timeout, uuids, operators=None,
                       probe_type="tcping"):
            seen_types.append(probe_type)
            return {"status": "ok", "ok": True, "ms": 15.8,
                    "level": "http", "ok_nodes": 10, "nodes": 10,
                    "ratio": 1.0}

        def fake_l2(ip, port, timeout):
            return {"status": "error", "ok": False, "ms": None, "error": "x"}

        with mock.patch.object(cc, "cn30_fetch_nodes",
                               return_value=[{"uuid": "u1", "operator": "ct",
                                              "enabled": True,
                                              "runtime_state": "online"}]), \
              mock.patch.object(cc, "cn30_pick_nodes",
                                side_effect=lambda nodes, count: ["u1", "u2"]), \
              mock.patch.object(cc, "cn30_check", side_effect=fake_check), \
              mock.patch.object(cc, "cn20_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn21_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn24_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn25_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn26_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn22_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn23_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn27_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn28_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn29_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}):
            entries, reachable, _ = cc.run_measurements([item], args)
        self.assertEqual(seen_types, ["http"])
        self.assertIn(cc.CN32_CODE, entries["10.9.9.9:443#US"]["sources"])
        self.assertNotIn(cc.CN30_CODE, entries["10.9.9.9:443#US"]["sources"])
        self.assertNotIn(cc.CN31_CODE, entries["10.9.9.9:443#US"]["sources"])
        self.assertIn("10.9.9.9:443#US", reachable)


class TestTcptestPingMergeVerdict(unittest.TestCase):
    """CN-33：ICMP 复核并入多节点合成判定。"""

    def test_merge_strong_weak_fail(self):
        strong = {"status": "ok", "ok": True, "ms": 15.0, "level": "icmp",
                  "ok_nodes": 8, "nodes": 10, "ratio": 0.8}
        self.assertEqual(cc.merge_verdict(
            {cc.CN31_CODE: strong})["verdict"], "reachable")
        self.assertEqual(cc.merge_verdict(
            {cc.CN31_CODE: strong})["level"], "icmp")
        weak = dict(strong, ok_nodes=1, nodes=10, ratio=0.1)
        self.assertEqual(cc.merge_verdict(
            {cc.CN31_CODE: weak})["verdict"], "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None,
                "ok_nodes": 0, "nodes": 10, "ratio": 0.0}
        self.assertEqual(cc.merge_verdict(
            {cc.CN31_CODE: fail,
             cc.CN20_CODE: {"status": "fail", "ok": False,
                       "ms": None}})["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 15.0, "level": "icmp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(
            cc.merge_verdict({cc.CN31_CODE: dict(src)})["verdict"],
            "reachable")
        old = cc._SOURCE_MIN_RATIO[cc.CN31_CODE]
        cc._SOURCE_MIN_RATIO[cc.CN31_CODE] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({cc.CN31_CODE: dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO[cc.CN31_CODE] = old

    def test_phase_runs_on_ping_limit_only(self):
        """TCP 0 ＋ ping 1 → 只跑 ping（节点复用同一采样）。"""
        from types import SimpleNamespace

        args = SimpleNamespace(cn_limit={"cn04": 0, "cn07": 0, "cn08": 0, "cn09": 0, "cn11": 0, "cn13": 0, "cn14": 0, "cn15": 0, "cn16": 0, "cn17": 0, "cn18": 0, "cn30": 0, "cn31": 1, "cn34": 0, "cn40": 0, "cn42": 0, "cn43": 0, "cn44": 0}, cn_concurrency={"cn04": 2, "cn30": 2, "cn31": 2}, cn_nodes={"cn30": 2}, 
            skip_cn01=True, skip_cn02=True, 
            workers=4, timeout=5, api_key="", cn41_token="",
              
             
              
              
              
             
             
            )
        item = ("10.9.9.9:443#US", "10.9.9.9:443#US", "10.9.9.9", "443", "US")
        seen_types = []

        def fake_check(ip, port, timeout, uuids, operators=None,
                       probe_type="tcping"):
            seen_types.append(probe_type)
            return {"status": "ok", "ok": True, "ms": 15.0,
                    "level": "icmp" if probe_type == "ping" else "tcp",
                    "ok_nodes": 10, "nodes": 10, "ratio": 1.0}

        def fake_l2(ip, port, timeout):
            return {"status": "error", "ok": False, "ms": None, "error": "x"}

        with mock.patch.object(cc, "cn30_fetch_nodes",
                               return_value=[{"uuid": "u1", "operator": "ct",
                                              "enabled": True,
                                              "runtime_state": "online"}]), \
              mock.patch.object(cc, "cn30_pick_nodes",
                                side_effect=lambda nodes, count: ["u1", "u2"]), \
              mock.patch.object(cc, "cn30_check", side_effect=fake_check), \
              mock.patch.object(cc, "cn20_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn21_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn24_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn25_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn26_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn22_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn23_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn27_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn28_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn29_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}):
            entries, reachable, _ = cc.run_measurements([item], args)
        self.assertEqual(seen_types, ["ping"])
        self.assertIn(cc.CN31_CODE, entries["10.9.9.9:443#US"]["sources"])
        self.assertNotIn(cc.CN30_CODE, entries["10.9.9.9:443#US"]["sources"])
        self.assertIn("10.9.9.9:443#US", reachable)


class TestTcptestTraceMergeVerdict(unittest.TestCase):
    """CN-40：路由复核并入多节点合成判定。"""

    def test_merge_strong_weak_fail(self):
        strong = {"status": "ok", "ok": True, "ms": None, "level": "icmp",
                  "ok_nodes": 100, "nodes": 158, "ratio": 0.63}
        self.assertEqual(cc.merge_verdict(
            {cc.CN33_CODE: strong})["verdict"], "reachable")
        self.assertEqual(cc.merge_verdict(
            {cc.CN33_CODE: strong})["level"], "icmp")
        weak = dict(strong, ok_nodes=1, nodes=158, ratio=0.006)
        self.assertEqual(cc.merge_verdict(
            {cc.CN33_CODE: weak})["verdict"], "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None,
                "ok_nodes": 0, "nodes": 158, "ratio": 0.0}
        self.assertEqual(cc.merge_verdict(
            {cc.CN33_CODE: fail,
             cc.CN20_CODE: {"status": "fail", "ok": False,
                       "ms": None}})["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": None, "level": "icmp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(
            cc.merge_verdict({cc.CN33_CODE: dict(src)})["verdict"],
            "reachable")
        old = cc._SOURCE_MIN_RATIO[cc.CN33_CODE]
        cc._SOURCE_MIN_RATIO[cc.CN33_CODE] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({cc.CN33_CODE: dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO[cc.CN33_CODE] = old

        """TCP/ping/http 0 ＋ trace 1 → 只跑 trace 通道。"""
        from types import SimpleNamespace

        args = SimpleNamespace(cn_limit={"cn04": 0, "cn07": 0, "cn08": 0, "cn09": 0, "cn10": 0, "cn11": 0, "cn12": 0, "cn13": 0, "cn14": 0, "cn15": 0, "cn16": 0, "cn17": 0, "cn18": 0, "cn30": 0, "cn31": 0, "cn32": 0, "cn33": 1, "cn34": 0, "cn40": 0, "cn42": 0, "cn43": 0, "cn44": 0}, cn_concurrency={"cn04": 2, "cn10": 2, "cn12": 2, "cn30": 2, "cn31": 2, "cn32": 2, "cn33": 2}, cn_nodes={"cn30": 2}, 
            skip_cn01=True, skip_cn02=True, 
            workers=4, timeout=5, api_key="", cn41_token="",
              
             
             
             
              
              
              
             
             
             
             
            )
        item = ("10.9.9.9:443#US", "10.9.9.9:443#US", "10.9.9.9", "443", "US")
        seen_types = []

        def fake_check(ip, port, timeout, uuids, operators=None,
                       probe_type="tcping"):
            seen_types.append(probe_type)
            return {"status": "ok", "ok": True, "ms": None,
                    "level": "icmp", "ok_nodes": 100, "nodes": 158,
                    "ratio": 0.63}

        def fake_l2(ip, port, timeout):
            return {"status": "error", "ok": False, "ms": None, "error": "x"}

        with mock.patch.object(cc, "cn30_fetch_nodes",
                               return_value=[{"uuid": "u1", "operator": "ct",
                                              "enabled": True,
                                              "runtime_state": "online"}]), \
              mock.patch.object(cc, "cn30_pick_nodes",
                                side_effect=lambda nodes, count: ["u1", "u2"]), \
              mock.patch.object(cc, "cn30_check", side_effect=fake_check), \
              mock.patch.object(cc, "cn20_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn21_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn22_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn23_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn24_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn25_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn26_check", side_effect=fake_l2), \
              mock.patch.object(cc, "cn27_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn28_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "cn29_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}):
            entries, reachable, _ = cc.run_measurements([item], args)
        self.assertEqual(seen_types, ["traceroute"])
        self.assertIn(cc.CN33_CODE, entries["10.9.9.9:443#US"]["sources"])
        for other in (cc.CN30_CODE, cc.CN31_CODE, cc.CN32_CODE):
            self.assertNotIn(other, entries["10.9.9.9:443#US"]["sources"])
        self.assertIn("10.9.9.9:443#US", reachable)


class TestCn06MergeVerdict(unittest.TestCase):
    """CN-42：cn06 并入多节点合成判定。"""

    def test_merge_and_threshold_wired(self):
        strong = {"status": "ok", "ok": True, "ms": 15.0, "level": "tcp",
                  "ok_nodes": 12, "nodes": 16, "ratio": 0.75,
                  "isp_ms": {"中国电信": 15.0}}
        merged = cc.merge_verdict({"cn06": strong})
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "tcp")
        weak = dict(strong, ok_nodes=1, nodes=16, ratio=0.0625)
        self.assertEqual(cc.merge_verdict(
            {"cn06": weak})["verdict"], "uncertain")
        old = cc._SOURCE_MIN_RATIO["cn06"]
        self.assertEqual(old, cc.DEFAULT_MIN_RATIO)
        cc._SOURCE_MIN_RATIO["cn06"] = 0.9
        try:
            self.assertEqual(cc.merge_verdict(
                {"cn06": dict(strong)})["verdict"], "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO["cn06"] = old

class TestCn04MergeVerdict(unittest.TestCase):
    """CN-27：cn04 并入多节点合成判定。"""

    def _ok(self, delay=30.0, nodes=28, ratio=1.0, isp=None):
        src = {"status": "ok", "ok": True, "ms": delay, "level": "tcp",
               "ok_nodes": nodes, "nodes": nodes, "ratio": ratio}
        if isp is not None:
            src["isp_ms"] = isp
        return src

    def test_strong_reachable(self):
        self.assertEqual(
            cc.merge_verdict({"cn04": self._ok()})["verdict"], "reachable")

    def test_weak_ratio_uncertain(self):
        src = self._ok(nodes=28, ratio=0.04)
        src["ok_nodes"] = 1
        self.assertEqual(
            cc.merge_verdict({"cn04": src})["verdict"], "uncertain")

    def test_degenerate_sample_not_strong(self):
        src = self._ok(nodes=1, ratio=1.0)
        src["ok_nodes"] = 1
        self.assertEqual(
            cc.merge_verdict({"cn04": src})["verdict"], "uncertain")

    def test_fail_plus_single_fail_unreachable(self):
        sources = {
            "cn04": {"status": "fail", "ok": False, "ms": None,
                        "ok_nodes": 0, "nodes": 28, "ratio": 0.0},
            cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_per_source_ratio_threshold_wired(self):
        """cn04 阈值须真正接线（_SOURCE_MIN_RATIO 缺项会静默回退默认）。"""
        src = self._ok(nodes=10, ratio=0.7)
        src["ok_nodes"] = 7
        self.assertEqual(cc.merge_verdict({"cn04": dict(src)})["verdict"],
                         "reachable")
        old = cc._SOURCE_MIN_RATIO["cn04"]
        cc._SOURCE_MIN_RATIO["cn04"] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({"cn04": dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO["cn04"] = old


@unittest.skipUnless(cc._CN01_BUNDLE, "needs PCB cn01 bundle")
class TestCn01PingFallbackGuard(unittest.TestCase):
    """CN-26：batch_ping 只补 error/rate_limited 键；TCP 实测 fail 的键
    不用 ICMP 主机存活翻案（保守）；整站失败时不空转。"""

    def _args(self):
        from types import SimpleNamespace
        return SimpleNamespace(cn_limit={"cn30": 0, "cn31": 0, "cn32": 0, "cn33": 0, "cn40": 0}, cn_concurrency={"cn40": 4}, 
            skip_cn01=False,
            skip_cn02=False,
                
            
            workers=4,
            timeout=5,
            api_key="",
            cn41_token="",
        )

    def _item(self, ip):
        return (f"{ip}:80#US", f"{ip}:80#US", ip, "80", "US")

    def test_tcp_fail_keys_excluded_from_ping(self):
        """cn01 实测 fail（端口层结论）→ ping_pending 为空，不发 ping 任务。"""
        import unittest.mock as mock

        items = [self._item("10.9.0.1")]

        def fake_cn01(sample, args, page_url=None, **kw):
            if page_url == cc.CN03_PAGE_URL:
                raise AssertionError("ping must not run for fail keys")
            return {key: {"status": "fail", "ok": False, "ms": None,
                          "error": "unreachable"}
                    for _, key, _, _, _ in sample}

        with mock.patch.object(cc, "cn20_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn27_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn24_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn25_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn21_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn26_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn22_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn23_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn01_batch_run", side_effect=fake_cn01):
            entries, _, _ = cc.run_measurements(items, self._args())

        self.assertNotIn("cn03", entries["10.9.0.1:80#US"]["sources"])

    def test_ping_ok_lands_normalized(self):
        """ping 兜底 ok → sources.cn03 归一为 icmp 且无 isp_ms。"""
        import unittest.mock as mock

        items = [self._item("10.10.0.1"), self._item("10.10.0.2")]

        def fake_cn01(sample, args, page_url=None, **kw):
            if page_url == cc.CN03_PAGE_URL:
                return {key: {"status": "ok", "ok": True, "ms": 22.0,
                              "level": "tcp", "ok_nodes": 20, "nodes": 24,
                              "ratio": 0.83, "isp_ms": {"中国电信": 5.0}}
                        for _, key, _, _, _ in sample}
            out = {}
            for _, key, _, _, _ in sample:
                # .1 http 即 ok（证站点存活，node_fetch_ok=True）；
                # .2 http error（进 tcping/ping 兜底链）。
                if key == "10.10.0.1:80#US":
                    out[key] = {"status": "ok", "ok": True, "ms": 30.0,
                                "level": "tcp", "ok_nodes": 20, "nodes": 24,
                                "ratio": 0.83}
                else:
                    out[key] = {"status": "error", "ok": False, "ms": None,
                                "error": "rl"}
            return out

        with mock.patch.object(cc, "cn20_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn27_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn24_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn25_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn21_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn26_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn22_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn23_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn01_batch_run", side_effect=fake_cn01):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        ping_res = entries["10.10.0.2:80#US"]["sources"]["cn03"]
        self.assertEqual(ping_res["level"], "icmp")
        self.assertNotIn("isp_ms", ping_res)
        self.assertIn("10.10.0.2:80#US", reachable)


class TestPingpeTargetsUnresolvedKeys(unittest.TestCase):
    """ping.pe 复核（贵、串行）只投当前尚未判 reachable 的键：
    已由 cn01 多点达标确认的键不再占用复核槽位。"""

    def _args(self):
        from types import SimpleNamespace
        return SimpleNamespace(cn_limit={"cn30": 0, "cn31": 0, "cn32": 0, "cn33": 0, "cn40": 10}, 
            skip_cn01=False,
            skip_cn02=True,
                
            workers=4,
            timeout=5,
            api_key="",
            cn41_token="",
        )

    def test_cn40_skips_already_reachable(self):
        import unittest.mock as mock

        items = [
            ("1.1.1.1:80#US", "1.1.1.1:80#US", "1.1.1.1", "80", "US"),
            ("2.2.2.2:80#US", "2.2.2.2:80#US", "2.2.2.2", "80", "US"),
        ]

        def fake_cn20(ip, port, timeout):
            if ip == "2.2.2.2":
                return {"status": "fail", "ok": False, "ms": None, "error": ""}
            return {"status": "ok", "ok": True, "ms": 1.0}

        def fake_cn27(ip, port, limiter, timeout, api_key):
            if ip == "2.2.2.2":
                return {"status": "fail", "ok": False, "ms": None, "error": ""}
            return {"status": "ok", "ok": True, "ms": 1.0}

        def fake_cn01(sample, args, **kwargs):
            # 1.1.1.1 已由 cn01 多点达标 → 应立即判 reachable
            return {
                "1.1.1.1:80#US": {
                    "status": "ok", "ok": True, "ms": 10.0,
                    "ratio": 0.9, "nodes": 12, "level": "tcp",
                },
            }

        with mock.patch.object(cc, "cn20_check", side_effect=fake_cn20), \
              mock.patch.object(cc, "cn27_check", side_effect=fake_cn27), \
              mock.patch.object(cc, "cn24_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "http 500"}), \
              mock.patch.object(cc, "cn25_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "http 500"}), \
              mock.patch.object(cc, "cn21_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "http 500"}), \
              mock.patch.object(cc, "cn28_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "http 500"}), \
              mock.patch.object(cc, "cn01_batch_run", side_effect=fake_cn01), \
             mock.patch.object(cc, "cn40_check",
                               return_value={
                                   "status": "ok", "ok": True, "ms": 20.0,
                                   "reported": 13, "ok_nodes": 8}) as mpp, \
             mock.patch.object(cc, "cn41_check",
                               return_value={"status": "skipped"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual(len(mpp.call_args_list), 1)
        probed = [c.args[0] for c in mpp.call_args_list]
        self.assertEqual(probed, ["2.2.2.2"])
        self.assertEqual(set(reachable), {"1.1.1.1:80#US", "2.2.2.2:80#US"})


class TestPingpeConcurrency(unittest.TestCase):
    """L3 ping.pe 有界并发：同槽位端到端耗时远小于串行（覆盖提升的点）。"""

    def _args(self):
        from types import SimpleNamespace
        return SimpleNamespace(cn_limit={"cn30": 0, "cn31": 0, "cn32": 0, "cn33": 0, "cn40": 6}, cn_concurrency={"cn40": 4}, 
            skip_cn01=True,
            skip_cn02=True,
                
            
            workers=4,
            timeout=5,
            api_key="",
            cn41_token="",
        )

    def test_concurrent_slots_finish_fast(self):
        import time
        import unittest.mock as mock

        items = [
            (f"10.{i}.0.1:443#US", f"10.{i}.0.1:443#US",
             f"10.{i}.0.1", "443", "US")
            for i in range(1, 7)
        ]

        def slow_cn40(ip, port, timeout):
            time.sleep(0.2)
            return {"status": "ok", "ok": True, "ms": 1.0,
                    "reported": 13, "ok_nodes": 8}

        with mock.patch.object(cc, "cn20_check",
                               return_value={"status": "ok", "ok": True,
                                             "ms": 1.0}), \
              mock.patch.object(cc, "cn27_check",
                                return_value={"status": "fail", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn24_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn25_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn21_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn26_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn22_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn23_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn28_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "CN40_SLOT_GAP", 0.01), \
             mock.patch.object(cc, "cn40_check", side_effect=slow_cn40), \
             mock.patch.object(cc, "cn41_check",
                               return_value={"status": "skipped"}):
            t0 = time.monotonic()
            entries, _, _ = cc.run_measurements(items, self._args())
            dt = time.monotonic() - t0

        # 串行 6×0.2s=1.2s；4 并发理想 ~0.6s。阈值 1.0s：仍能证明并行（远小于
        # 串行 1.2s），又给重载 CI 调度抖动留足缓冲，避免时序断言偶发 flaky。
        self.assertLess(dt, 1.0)
        self.assertEqual(
            [v["sources"][cc.CN40_CODE]["ok"] for v in entries.values()].count(True), 6)
        self.assertEqual(
            [v["verdict"] for v in entries.values()].count("reachable"), 6)


@unittest.skipUnless(cc._CN01_BUNDLE, "needs PCB cn01 bundle")
class TestCn01TcpingFallbackGuard(unittest.TestCase):
    """主通道节点获取失败（整站被墙/验证码墙）时，同一上游的 tcping
    兜底必然同样拿不到节点，应跳过而非再空转一轮。"""

    def _args(self):
        from types import SimpleNamespace
        return SimpleNamespace(cn_limit={"cn30": 0, "cn31": 0, "cn32": 0, "cn33": 0, "cn40": 0}, cn_concurrency={"cn40": 4}, 
            skip_cn01=False,
            skip_cn02=False,
                
            
            workers=4,
            timeout=5,
            api_key="",
            cn41_token="",
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
                          "error": "no nodes"}
                for item in sample
            }

        with mock.patch.object(cc, "cn20_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn27_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn24_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn25_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn21_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn26_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn22_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn23_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "cn01_batch_run", side_effect=failed_nodes) as mib:
            cc.run_measurements(items, self._args())

        # 主通道一次 + 兜底应零次（节点连取都失败的整站性故障不白跑第二轮）
        self.assertEqual(len(mib.call_args_list), 1)
        self.assertNotIn("page_url", mib.call_args_list[0].kwargs)


class TestComputeFallbackMerge(unittest.TestCase):

    def _prev(self, *keys):
        return {k: {"verdict": "reachable", "streak": 2, "sources": {}} for k in keys}

    def test_source_fault_states_do_not_block_fallback(self):
        # 与 merge_verdict 的 fail_sources 口径一致：仅 status=="fail"（明确不可
        # 达证据）算"证伪"；error/poll timeout/rate_limited 均为源侧故障，
        # 不得阻断上一轮可达键的兜底复活——三态逐一显式锁定防改口径。
        for fault in ("error", "timeout", "rate_limited"):
            with self.subTest(fault=fault):
                prev = self._prev("a:443#US")
                entries = {"a:443#US": {
                    "verdict": "uncertain",
                    "sources": {cc.CN27_CODE: {"status": fault}},
                }}
                reachable = set()
                fb = cc.compute_fallback_merge(entries, prev, reachable)
                self.assertEqual(fb, {"a:443#US"})
                self.assertEqual(entries["a:443#US"]["verdict"], "reachable")
                self.assertIn("a:443#US", reachable)

    def test_uncertain_no_fail_merged(self):
        # 上轮可达、本轮 uncertain 且无失败源 → 合并回 reachable + fallback, streak 保留(当轮已标 0)
        prev = self._prev("a:443#US", "b:443#US", "c:443#US")
        entries = {
            "a:443#US": {"verdict": "uncertain", "sources": {cc.CN20_CODE: {"status": "error"}}},
            "b:443#US": {"verdict": "uncertain", "sources": {cc.CN20_CODE: {"status": "fail"}}},
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
        prev = {"a:443#US": {"verdict": "reachable", "streak": 4, "sources": {cc.CN20_CODE: {"status": "ok"}}}}
        entries = {}
        reachable = set()
        fb = cc.compute_fallback_merge(entries, prev, reachable)
        self.assertEqual(fb, {"a:443#US"})
        self.assertIn("a:443#US", reachable)
        self.assertEqual(entries["a:443#US"]["verdict"], "reachable")
        self.assertTrue(entries["a:443#US"]["fallback"])
        self.assertEqual(entries["a:443#US"]["streak"], 0)  # 未复测不虚报连续
        self.assertEqual(entries["a:443#US"]["sources"], {cc.CN20_CODE: {"status": "ok"}})

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

    def test_skipped_no_fail_merged(self):
        # 上轮可达、本轮全源 error(未获确认、无 fail) → 兜底（原实现仅放行
        # reachable/uncertain，会把全源异常轮的键挡在 -CN 之外，跌穿告警）。
        prev = self._prev("a:443#US")
        entries = {"a:443#US": {
            "verdict": "skipped",
            "sources": {cc.CN20_CODE: {"status": "error"},
                        "cn02": {"status": "error"}},
            "streak": 1,
        }}
        reachable = set()
        fb = cc.compute_fallback_merge(entries, prev, reachable)
        self.assertEqual(fb, {"a:443#US"})
        self.assertEqual(entries["a:443#US"]["verdict"], "reachable")
        self.assertTrue(entries["a:443#US"]["fallback"])
        self.assertEqual(entries["a:443#US"]["streak"], 0)
        self.assertIn("a:443#US", reachable)

    def test_merged_keeps_prev_readings(self):
        # 本轮全源 error 被兜底回 reachable 的键，若当轮无大陆读数（ms/isp_ms
        # 为空），须沿用上一轮读数——否则 china.json 里 cn_fastest_ms 读成
        # None，all_cn.txt（run 尾从 prev 回填）与 build_good/annotate（只读
        # china.json）对同一键渲染出不同大陆读数，破坏同口径。
        from common import cn_fastest_ms
        prev = {
            "a:443#US": {
                "verdict": "reachable", "streak": 2, "sources": {},
                "ms": 289.0, "isp_ms": {"CT": 289.0, "CM": 301.0},
            },
        }
        entries = {"a:443#US": {
            "verdict": "uncertain",
            "sources": {cc.CN20_CODE: {"status": "error"}, "cn01": {"status": "error"}},
        }}
        reachable = set()
        fb = cc.compute_fallback_merge(entries, prev, reachable)
        self.assertEqual(fb, {"a:443#US"})
        e = entries["a:443#US"]
        self.assertEqual(e["ms"], 289.0)
        self.assertEqual(e["isp_ms"], {"CT": 289.0, "CM": 301.0})
        self.assertEqual(cn_fastest_ms(e), 289.0)
        self.assertIn("a:443#US", reachable)

    def test_merged_keeps_cur_reading_if_present(self):
        # 当轮已有读数时不覆盖：仅回填缺失字段，不以历史值顶掉新读数。
        prev = {"a:443#US": {"verdict": "reachable", "streak": 2, "sources": {},
                             "ms": 500.0}}
        entries = {"a:443#US": {"verdict": "uncertain", "sources": {},
                                "ms": 110.0}}
        reachable = set()
        fb = cc.compute_fallback_merge(entries, prev, reachable)
        self.assertEqual(fb, {"a:443#US"})
        self.assertEqual(entries["a:443#US"]["ms"], 110.0)


class TestCe98PingSource(unittest.TestCase):
    """CN-12：同站 continuous-ping 通道（协议测试已迁 PCB），mock，不触网。"""


    def test_merge_strong_weak_fail(self):
        strong = {"status": "ok", "ok": True, "ms": 3.4, "level": "icmp",
                  "ok_nodes": 35, "nodes": 35, "ratio": 1.0}
        self.assertEqual(cc.merge_verdict(
            {cc.CN12_CODE: strong})["verdict"], "reachable")
        weak = dict(strong, ok_nodes=1, nodes=35, ratio=0.029)
        self.assertEqual(cc.merge_verdict(
            {cc.CN12_CODE: weak})["verdict"], "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None,
                "ok_nodes": 0, "nodes": 35, "ratio": 0.0}
        self.assertEqual(cc.merge_verdict(
            {cc.CN12_CODE: fail,
             cc.CN20_CODE: {"status": "fail", "ok": False,
                       "ms": None}})["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 5.0, "level": "icmp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(
            cc.merge_verdict({cc.CN12_CODE: dict(src)})["verdict"],
            "reachable")
        old = cc._SOURCE_MIN_RATIO[cc.CN12_CODE]
        cc._SOURCE_MIN_RATIO[cc.CN12_CODE] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({cc.CN12_CODE: dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO[cc.CN12_CODE] = old

    def test_raw_slot_dispatch(self):
        cands = [("1.2.3.4:443#US line", "1.2.3.4:443#US",
                  "1.2.3.4", "443", "US")]
        entries: dict = {"1.2.3.4:443#US": {}}
        with mock.patch.object(
                cc, "cn12_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_raw_slots(cands, entries, 5, cc.CN12_CODE, 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(
            entries["1.2.3.4:443#US"][cc.CN12_CODE]["status"], "ok")


class TestNewMultiSourcesMergeVerdict(unittest.TestCase):
    """cn11 / cn09 并入多节点源合成判定（level/ratio 规则）。"""

    def _ok(self, ok_nodes, nodes, ratio):
        return {"status": "ok", "ok": True, "ms": 30, "level": "tcp",
                "ok_nodes": ok_nodes, "nodes": nodes, "ratio": ratio}

    def test_cn11_strong_reachable(self):
        sources = {cc.CN11_CODE: self._ok(35, 35, 1.0)}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "reachable")

    def test_cn11_degenerate_not_strong(self):
        sources = {cc.CN11_CODE: self._ok(1, 35, 0.029)}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_cn09_strong_reachable(self):
        sources = {cc.CN09_CODE: self._ok(39, 39, 1.0)}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "reachable")

    def test_multi_failed_with_single_unreachable(self):
        """cn11+cn09 都 fail 且 2 单节点源 fail → unreachable。"""
        sources = {
            cc.CN11_CODE: {"status": "fail", "ok": False, "ok_nodes": 0,
                     "nodes": 35, "ratio": 0.0},
            cc.CN09_CODE: {"status": "fail", "ok": False, "ok_nodes": 0,
                        "nodes": 39, "ratio": 0.0},
            cc.CN20_CODE: {"status": "fail", "ok": False},
            cc.CN24_CODE: {"status": "fail", "ok": False},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")


class TestWsBufferCaps(unittest.TestCase):
    """WS 重组缓冲上限：声明超大帧（2^40）且永不补全的上游，读循环必须在
    ``WS_MAX_BUF`` 内返回 err，而不是随滴灌无限累积内存。"""

    class _DripSock:
        def __init__(self, chunk):
            self.chunk = chunk

        def recv(self, n):
            return self.chunk

        def settimeout(self, t):
            pass

        def close(self):
            pass

    def _wedged_chunk(self):
        import struct
        # 文本帧(FIN|opcode=1) + ln==127(64 位长度=2^40)：永远装不满 → 只累积
        return b"\x81\x7f" + struct.pack(">Q", 1 << 40) + b"\x00" * 65526

    def test_cn01_websocket_read_caps_accumulation(self):
        ws = wt._WebSocket.__new__(wt._WebSocket)
        ws.sock = self._DripSock(self._wedged_chunk())
        ws.buf = b""
        out = ws.read()
        self.assertEqual(out[0], "err")
        self.assertIn("buffer overflow", out[1]["error"])
        self.assertLessEqual(len(ws.buf), wt.WS_MAX_BUF + 65536)


class TestTcpingcnPingSource(unittest.TestCase):
    """CN-18：cn18 merge/dispatch（mock，不触网）。"""

    def test_merge_strong_weak_fail(self):
        strong = {"status": "ok", "ok": True, "ms": 22.0, "level": "icmp",
                  "ok_nodes": 100, "nodes": 160, "ratio": 0.625}
        self.assertEqual(cc.merge_verdict(
            {cc.CN18_CODE: strong})["verdict"], "reachable")
        weak = dict(strong, ok_nodes=1, nodes=160, ratio=0.006)
        self.assertEqual(cc.merge_verdict(
            {cc.CN18_CODE: weak})["verdict"], "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None,
                "ok_nodes": 0, "nodes": 160, "ratio": 0.0}
        self.assertEqual(cc.merge_verdict(
            {cc.CN18_CODE: fail,
             cc.CN20_CODE: {"status": "fail", "ok": False,
                       "ms": None}})["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 20.0, "level": "icmp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(
            cc.merge_verdict({cc.CN18_CODE: dict(src)})["verdict"],
            "reachable")
        old = cc._SOURCE_MIN_RATIO[cc.CN18_CODE]
        cc._SOURCE_MIN_RATIO[cc.CN18_CODE] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({cc.CN18_CODE: dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO[cc.CN18_CODE] = old

    def test_ws_slot_dispatch(self):
        cands = [("1.2.3.4:443#US line", "1.2.3.4:443#US",
                  "1.2.3.4", "443", "US")]
        entries: dict = {"1.2.3.4:443#US": {}}
        with mock.patch.object(
                cc, "cn18_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_ws_source_slots(cands, entries, 5, cc.CN18_CODE, 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(
            entries["1.2.3.4:443#US"][cc.CN18_CODE]["status"], "ok")


class TestTcpingcnMtrSource(unittest.TestCase):
    """CN-19：cn19 merge/dispatch/CLI（mock，不触网）。"""

    def test_merge_and_threshold_wired(self):
        strong = {"status": "ok", "ok": True, "ms": None, "level": "icmp",
                  "ok_nodes": 100, "nodes": 139, "ratio": 0.72}
        self.assertEqual(cc.merge_verdict(
            {cc.CN19_CODE: strong})["verdict"], "reachable")
        weak = dict(strong, ok_nodes=1, nodes=139, ratio=0.007)
        self.assertEqual(cc.merge_verdict(
            {cc.CN19_CODE: weak})["verdict"], "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None,
                "ok_nodes": 0, "nodes": 139, "ratio": 0.0}
        self.assertEqual(cc.merge_verdict(
            {cc.CN19_CODE: fail,
             cc.CN20_CODE: {"status": "fail", "ok": False,
                       "ms": None}})["verdict"], "unreachable")
        old = cc._SOURCE_MIN_RATIO[cc.CN19_CODE]
        cc._SOURCE_MIN_RATIO[cc.CN19_CODE] = 0.8
        try:
            self.assertEqual(cc.merge_verdict(
                {cc.CN19_CODE: dict(strong)})["verdict"], "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO[cc.CN19_CODE] = old

    def test_ws_slot_dispatch(self):
        cands = [("1.2.3.4:443#US line", "1.2.3.4:443#US",
                  "1.2.3.4", "443", "US")]
        entries: dict = {"1.2.3.4:443#US": {}}
        with mock.patch.object(
                cc, "cn19_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_ws_source_slots(cands, entries, 5, cc.CN19_CODE, 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(
            entries["1.2.3.4:443#US"][cc.CN19_CODE]["status"], "ok")

    def test_cli_default_stays_opt_in(self):
        """CN-44：mtr 复核本地默认 opt-in（0/6），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn19")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn19")["concurrency"], 6)


class TestNeedsProbe(unittest.TestCase):
    def test_no_entry_needs_probe(self):
        self.assertTrue(cc.needs_probe({}, "1.1.1.1:80#US"))

    def test_two_single_node_ok_stops(self):
        entries = {
            "1.1.1.1:80#US": {
                cc.CN27_CODE: {"status": "ok", "ok": True, "ms": 100, "level": "http"},
                cc.CN20_CODE: {"status": "ok", "ok": True, "ms": 120, "level": "http"},
            }
        }
        self.assertFalse(cc.needs_probe(entries, "1.1.1.1:80#US"))

    def test_two_single_node_fail_stops(self):
        entries = {
            "1.1.1.1:80#US": {
                cc.CN27_CODE: {"status": "fail", "ok": False, "ms": None},
                cc.CN20_CODE: {"status": "fail", "ok": False, "ms": None},
            }
        }
        self.assertFalse(cc.needs_probe(entries, "1.1.1.1:80#US"))

    def test_single_node_ok_uncertain_keeps(self):
        entries = {
            "1.1.1.1:80#US": {
                cc.CN27_CODE: {"status": "ok", "ok": True, "ms": 100, "level": "http"}
            }
        }
        self.assertTrue(cc.needs_probe(entries, "1.1.1.1:80#US"))

    def test_error_only_keeps(self):
        entries = {
            "1.1.1.1:80#US": {
                cc.CN24_CODE: {"status": "error", "ok": False, "ms": None, "error": "x"}
            }
        }
        self.assertTrue(cc.needs_probe(entries, "1.1.1.1:80#US"))

    def test_multi_node_strong_stops(self):
        entries = {
            "1.1.1.1:80#US": {
                "cn01": {
                    "status": "ok", "ok": True, "ms": 50, "level": "http",
                    "ratio": 0.9, "nodes": 18,
                }
            }
        }
        self.assertFalse(cc.needs_probe(entries, "1.1.1.1:80#US"))

    def test_multi_node_weak_keeps(self):
        entries = {
            "1.1.1.1:80#US": {
                "cn01": {
                    "status": "ok", "ok": True, "ms": 50, "level": "http",
                    "ratio": 0.1, "nodes": 18,
                }
            }
        }
        self.assertTrue(cc.needs_probe(entries, "1.1.1.1:80#US"))


class TestBuildCnBest(unittest.TestCase):
    def test_skips_none_and_non_dict_entries(self):
        # 回归 R236：cn_best_isp 返回 None（无 per-ISP 读数）不得导致
        # `for isp, ms in [None]` 解包 TypeError 崩溃整轮 china_check。
        entries = {
            "1.1.1.1:443#US": {"isp_ms": {"移动": 57.0}},   # 有效
            "2.2.2.2:443#US": {"isp_ms": {"电信": 2.0}},    # 全 ≤2ms → None
            "3.3.3.3:443#US": {"isp_ms": {}},               # 空 → None
            "4.4.4.4:443#US": {},                            # 无 isp_ms → None
            "5.5.5.5:443#US": "not-a-dict",                  # 非 dict → None
        }
        out = cc.build_cn_best(entries)
        self.assertEqual(out, {"1.1.1.1:443#US": "移动=57ms"})

    def test_empty_entries(self):
        self.assertEqual(cc.build_cn_best({}), {})

    def test_rounds_best_ms(self):
        out = cc.build_cn_best({"k": {"isp_ms": {"电信": 42.6}}})
        self.assertEqual(out["k"], "电信=43ms")


class TestMainExitCodes(unittest.TestCase):
    """R281：退出码契约——空输入样本 → 2（用法/数据问题），无网络动作；
    与 quality_check 缺源返回 1、health_alert 非 strict 下恒 0 的分工一致。"""

    def test_empty_source_exits_2_without_network(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "empty.txt"
            src.write_text("", encoding="utf-8")
            with mock.patch.object(
                    cc, "request_follow",
                    side_effect=AssertionError("no network in test")):
                rc = cc.main(["--source", str(src)])
        self.assertEqual(rc, 2)


class TestCiEnabledSources(unittest.TestCase):
    """CN-01：CI 启用的复核源与文档一致（防 CI 行与 README 链漂移）。

    cn11（34 大陆省运营商节点 TCPing）毕业为默认启用：CI 传
    `--cn-limit cn11=200 --cn-concurrency cn11=6`（同级预算）；
    注册表默认仍 0（本地按需显式启用）。"""

    def test_ci_enables_cn11(self):
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        self.assertIn("--cn-limit cn11=200", wf)
        self.assertIn("--cn-concurrency cn11=6", wf)

    def test_ci_enables_cn09(self):
        """CN-02：cn09 毕业（约 39 ISP×节点，活体 21 单元出数）
        与 cn11 同级预算；CLI 默认仍 0。"""
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        self.assertIn("--cn-limit cn09=200", wf)
        self.assertIn("--cn-concurrency cn09=8", wf)

    def test_cn44_stays_disabled_for_captcha(self):
        """CN-03：cn44 源有 captcha 墙（活体实证），启用即须绕过
        反爬——合规禁区。CI 不得启用；若对方撤销验证墙，本锁须由人
        复核后同步解除（改测试即改决策）。"""
        import re
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        self.assertIsNone(
            re.search(r"--cn-limit cn44=([1-9]\d*)", wf),
            "cn44 在 captcha 墙移除前不得进 CI")

    def test_cn11_cli_default_stays_opt_in(self):
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn09")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn09")["concurrency"], 8)
        self.assertEqual(reg.by_code("cn11")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn11")["concurrency"], 6)

    def test_graduated_limits_match_readme(self):
        """CN-10：已毕业源的 CI 配额须与 README 链一致（防 CI 行与文档
        双边漂移；生产出数待下次 china 验证）。"""
        import re
        root = Path(__file__).resolve().parent.parent
        wf = (root / ".github" / "workflows" / "china-check.yml").read_text(
            encoding="utf-8")
        readme = (root / "README.md").read_text(encoding="utf-8")
        for name in ("cn11", "cn09", "cn10", "cn04", "cn15", "cn18",
                       "cn31", "cn32", "cn33", "cn06", "cn19", "cn34",
                       "cn35", "cn36", "cn37", "cn38", "cn39", "cn05",
                       "cn40", "cn12"):
            m = re.search(rf"--cn-limit {name}=(\d+).*?"
                          rf"--cn-concurrency {name}=(\d+)", wf, re.S)
            self.assertIsNotNone(m, f"CI 未启用 {name}")
            limit, conc = m.group(1), m.group(2)
            self.assertRegex(
                readme,
                re.compile(re.escape(f"{name}（{limit} 键/{conc} 并发")),
                f"README 链与 CI 配额不一致：{name}")

    def test_cn04_cli_default_stays_opt_in(self):
        """CN-27：四源复核本地默认 opt-in（0/6），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn04")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn04")["concurrency"], 6)

    def test_cn05_cli_default_stays_opt_in(self):
        """CN-50：同族复核本地默认 opt-in（0/6），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn05")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn05")["concurrency"], 6)

    def test_cn15_cli_default_stays_opt_in(self):
        """CN-28：同站 ping 本地默认 opt-in（0/8），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn15")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn15")["concurrency"], 8)

    def test_cn31_cli_default_stays_opt_in(self):
        """CN-33：复核 ping 本地默认 opt-in（0/8，与 TCP 同并发），
        只在 CI 显式启用（400/20）。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn31")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn31")["concurrency"], 8)

    def test_cn32_cli_default_stays_opt_in(self):
        """CN-35：复核 http 本地默认 opt-in（0/8），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn32")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn32")["concurrency"], 8)

    def test_cn33_cli_default_stays_opt_in(self):
        """CN-40：trace 复核本地默认 opt-in（0/8），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn33")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn33")["concurrency"], 8)

    def test_cn10_cli_default_stays_opt_in(self):
        """CN-34：cn10 本地默认 opt-in（0/8），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn10")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn10")["concurrency"], 8)

    def test_cn12_cli_default_stays_opt_in(self):
        """CN-36：同站 ping 复核本地默认 opt-in（0/6），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn12")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn12")["concurrency"], 6)

    def test_cli_default_stays_opt_in(self):
        """CN-42：tcpping-ws 本地默认 opt-in（0/6），只在 CI 显式启用。"""
        reg = _registry_sources(self)
        self.assertEqual(reg.by_code("cn06")["limit_default"], 0)
        self.assertEqual(reg.by_code("cn06")["concurrency"], 6)

    def test_all_enabled_l3_limits_present(self):
        """CN-12：CI 启用的全部 L3 复核源配额原地锁定（cn30/cn07/
        cn08/cn14/cn17/cn16/cn40/cn11/cn12/cn04），防 CI 行
        误删某源致覆盖无声缩水。"""
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        for code, lim in (("cn30", 800), ("cn07", 1200), ("cn08", 600),
                            ("cn14", 500), ("cn17", 400), ("cn16", 200),
                            ("cn40", 300), ("cn11", 200), ("cn09", 200),
                            ("cn04", 200), ("cn15", 200), ("cn18", 200),
                            ("cn31", 400), ("cn10", 200), ("cn32", 200),
                            ("cn12", 200), ("cn33", 200), ("cn06", 200),
                            ("cn34", 100), ("cn35", 100), ("cn36", 60),
                            ("cn37", 40), ("cn38", 40), ("cn39", 40),
                            ("cn05", 200), ("cn19", 200)):
            flag = f"--cn-limit {code}={lim}"
            self.assertIn(flag, wf, f"CI 缺复核配额：{flag}")

    def test_ci_command_dry_runs(self):
        """R15：workflow china 步骤原样 dry-run（parser/workflow 漂移即红；
        无网络无写盘；此前每轮手工验证，现锁进套件）。"""
        import re
        import shlex
        import unittest.mock as mock
        root = Path(__file__).resolve().parent.parent
        wf = (root / ".github" / "workflows" / "china-check.yml").read_text(
            encoding="utf-8")
        m = re.search(r"run: >-\n((?:[ ]{9,}.*\n?)+)", wf)
        self.assertIsNotNone(m, "china 步骤 run 块丢失")
        cmd = " ".join(l.strip() for l in m.group(1).splitlines()
                       if l.strip())
        argv = shlex.split(cmd)
        self.assertEqual(argv[:2], ["python", "scripts/china_check.py"])
        with mock.patch.object(
                cc, "request_follow",
                side_effect=AssertionError("dry-run must not touch net")):
            self.assertEqual(cc.main(argv[2:] + ["--dry-run"]), 0)

    def test_ci_run_block_folds_to_single_command(self):
        """URGENT-CI：china-check.yml 的 `run: >-` 折叠块必须折成单条 shell
        命令——任一续行缩进多一格即成超缩进行，YAML 保留其换行，bash 把
        `--xxx-limit` 当独立命令执行（exit 127），且整轮跑残缺命令
        （2026-09-19 run 35467680392：2.5h 后死于 line 2，L3 全 skip）。
        另禁重复行（argparse last-wins 掩盖配额漂移）。"""
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        lines = wf.splitlines()
        start = next(i for i, l in enumerate(lines) if l.strip() == "run: >-")
        block = []
        for l in lines[start + 1:]:
            if not l.strip():
                continue
            indent = len(l) - len(l.lstrip())
            if indent <= 8:
                break
            block.append(l)
        self.assertTrue(block, "CI run 块为空")
        indents = {len(l) - len(l.lstrip()) for l in block}
        self.assertEqual(len(indents), 1,
                         f"CI run 块缩进不统一（>- 折叠断裂）：{sorted(indents)}")
        stripped = [l.strip() for l in block]
        self.assertEqual(len(stripped), len(set(stripped)), "CI run 块有重复行")
        self.assertTrue(stripped[0].startswith("python scripts/china_check.py"))

    def test_cn17_limit_restored_after_altcha(self):
        """CN-30：cn17 ALTCHA 打通后复活——CI 配额恢复 400，
        同通道 ping 200 并行（停烧锁已解除，复活验证见本轮活体）。"""
        import re
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        m = re.search(r"--cn-limit cn17=(\d+)", wf)
        self.assertIsNotNone(m, "cn17 配额丢失")
        self.assertEqual(int(m.group(1)), 400)
        m = re.search(r"--cn-limit cn18=(\d+)", wf)
        self.assertIsNotNone(m, "cn18 配额丢失")
        self.assertEqual(int(m.group(1)), 200)

    def test_ci_flags_all_defined(self):
        """CN-13：CI 传给 china_check.py 的每个 flag 必须在 argparse 中
        有定义（防死 flag：CI 改名/脚本改名不同步则作业 argparse 直接
        报错整轮失败）。"""
        import re
        root = Path(__file__).resolve().parent.parent
        wf = (root / ".github" / "workflows" / "china-check.yml").read_text(
            encoding="utf-8")
        src = (root / "scripts" / "china_check.py").read_text(
            encoding="utf-8")
        defined = set(re.findall(r'"(--[a-z0-9-]+)"', src))
        used = set(re.findall(r"--[a-z0-9-]+", wf))
        script_flags = {f for f in used if not f.startswith("--jq")
                        and f != "--json" and f != "--workflow"}
        unknown = sorted(script_flags - defined)
        self.assertEqual(unknown, [], f"CI 用了未定义的 flag：{unknown}")

    def test_raw_slots_dispatch_mapping(self):
        """CN-11：通用 slot 按源名派发到对应 check 函数；异常收敛为
        error 记录（不抛、不串源）。"""
        cands = [("1.2.3.4:443#US line", "1.2.3.4:443#US",
                  "1.2.3.4", "443", "US")]
        entries: dict = {"1.2.3.4:443#US": {}}
        with mock.patch.object(
                cc, "cn11_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_raw_slots(cands, entries, 5, cc.CN11_CODE, 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(entries["1.2.3.4:443#US"][cc.CN11_CODE]["status"], "ok")
        with mock.patch.object(
                cc, "cn09_check",
                side_effect=RuntimeError("boom")):
            cc._run_raw_slots(cands, entries, 5, cc.CN09_CODE, 2)
        err = entries["1.2.3.4:443#US"][cc.CN09_CODE]
        self.assertEqual(err["status"], "error")
        self.assertEqual(err["error"], "RuntimeError")
        with mock.patch.object(
                cc, "cn04_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_raw_slots(cands, entries, 5, "cn04", 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(entries["1.2.3.4:443#US"]["cn04"]["status"], "ok")


class TestCnCacheSplitMerge(unittest.TestCase):
    """--cn-cache-ttl：china.json 新鲜键复用，过期/缺失/非可达复测。"""

    NOW = 1_700_000_000.0

    def _item(self, key="1.2.3.4:80#US"):
        return (key, key, "1.2.3.4", "80", "US")

    def _prev(self, verdict="reachable", age=100, **kw):
        e = {"verdict": verdict, "checked_at": self.NOW - age,
             "streak": 3, "sources": {}}
        e.update(kw)
        return e

    def test_ttl_off_probes_all(self):
        sample = [self._item()]
        prev = {"1.2.3.4:80#US": self._prev()}
        cached, probe = cc.split_cn_cache(sample, prev, 0, self.NOW)
        self.assertEqual(cached, {})
        self.assertEqual(probe, sample)

    def test_fresh_reachable_reused(self):
        key = "1.2.3.4:80#US"
        prev = {key: self._prev("reachable", age=100)}
        cached, probe = cc.split_cn_cache([self._item(key)], prev, 3600,
                                           self.NOW)
        self.assertEqual(probe, [])
        self.assertIn(key, cached)
        self.assertEqual(cached[key]["streak"], 3)

    def test_fresh_uncertain_reused(self):
        key = "1.2.3.4:80#US"
        prev = {key: self._prev("uncertain", age=100)}
        cached, probe = cc.split_cn_cache([self._item(key)], prev, 3600,
                                           self.NOW)
        self.assertEqual(probe, [])
        self.assertIn(key, cached)

    def test_expired_reprobed(self):
        key = "1.2.3.4:80#US"
        prev = {key: self._prev("reachable", age=7200)}
        cached, probe = cc.split_cn_cache([self._item(key)], prev, 3600,
                                           self.NOW)
        self.assertEqual(cached, {})
        self.assertEqual(len(probe), 1)

    def test_missing_checked_at_reprobed(self):
        key = "1.2.3.4:80#US"
        prev = {key: {"verdict": "reachable", "streak": 1}}
        cached, probe = cc.split_cn_cache([self._item(key)], prev, 3600,
                                           self.NOW)
        self.assertEqual(cached, {})
        self.assertEqual(len(probe), 1)

    def test_fresh_fail_reprobed(self):
        key = "1.2.3.4:80#US"
        prev = {key: self._prev("fail", age=10)}
        cached, probe = cc.split_cn_cache([self._item(key)], prev, 3600,
                                           self.NOW)
        self.assertEqual(cached, {})
        self.assertEqual(len(probe), 1)

    def test_merge_syncs_sets_and_isolates_prev(self):
        key = "1.2.3.4:80#US"
        prev = {key: self._prev("reachable", age=100)}
        cached, _ = cc.split_cn_cache([self._item(key)], prev, 3600,
                                       self.NOW)
        entries, reachable, uncertain = {}, set(), set()
        cc.merge_cn_cache(entries, reachable, uncertain, cached)
        self.assertIn(key, entries)
        self.assertIn(key, reachable)
        self.assertNotIn(key, uncertain)
        entries[key]["streak"] = 99
        self.assertEqual(prev[key]["streak"], 3)


class TestCnOptResolver(unittest.TestCase):
    """代号运行时件：generic > legacy 属性 > 注册表默认 > default。"""

    def _args(self, **kw):
        from types import SimpleNamespace
        return SimpleNamespace(**kw)

    def test_parse_cn_kv(self):
        self.assertEqual(cc.parse_cn_kv(["cn30=800", "CN31=200"]),
                         {"cn30": 800, "cn31": 200})
        self.assertEqual(cc.parse_cn_kv(["bogus", "=5", "cn32=abc", ""]),
                         {})
        self.assertEqual(cc.parse_cn_kv(None), {})

    def test_parse_cn_kv_warns_malformed_r87(self):
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            out = cc.parse_cn_kv(["bogus", "cn30=800", "cn32=abc"])
        self.assertEqual(out, {"cn30": 800})
        err = buf.getvalue()
        self.assertIn("bogus", err)
        self.assertIn("cn32=abc", err)

    def test_warn_unknown_cn_codes_r87(self):
        import io
        from contextlib import redirect_stderr
        args = self._args(cn_limit={"cn30": 800, "cn99": 1},
                          cn_concurrency={}, cn_nodes={})
        buf = io.StringIO()
        with redirect_stderr(buf):
            cc.warn_unknown_cn_codes(args)
        self.assertIn("cn99", buf.getvalue())

    def test_dry_run_prints_plan_r87(self):
        import io
        from contextlib import redirect_stderr
        from unittest import mock
        with mock.patch.object(cc, "read_json", return_value={}), \
             mock.patch.object(cc, "load_sample",
                               return_value=([("1.1.1.1", "1.1.1.1:443#US",
                                              "1.1.1.1", "443", None)],
                                             "all_rep.txt")):
            buf = io.StringIO()
            with redirect_stderr(buf):
                rc = cc.main(["--dry-run", "--cn-limit", "cn30=800",
                              "--cn-limit", "bogus"])
            self.assertEqual(rc, 0)
            err = buf.getvalue()
            self.assertIn("dry-run plan", err)
            self.assertIn("cn30", err)

    def test_generic_beats_legacy(self):
        args = self._args(cn_limit={"cn30": 800}, tcptest_limit=150)
        self.assertEqual(
            cc.cn_opt(args, "cn30", "limit", legacy="tcptest_limit",
                      default=0), 800)

    def test_legacy_attr_used(self):
        args = self._args(tcptest_limit=150)
        self.assertEqual(
            cc.cn_opt(args, "cn30", "limit", legacy="tcptest_limit",
                      default=0), 150)

    def test_registry_default_with_fake_registry(self):
        class FakeReg:
            @staticmethod
            def by_code(code):
                return {"limit_default": 150, "concurrency": 8} \
                    if code == "cn30" else None
        old = cc._SOURCES_REG
        cc._SOURCES_REG = FakeReg()
        try:
            args = self._args()
            self.assertEqual(cc.cn_opt(args, "cn30", "limit", default=0),
                             150)
            self.assertEqual(
                cc.cn_opt(args, "cn30", "concurrency", default=0), 8)
        finally:
            cc._SOURCES_REG = old

    def test_missing_everything_returns_default(self):
        args = self._args()
        old = cc._SOURCES_REG
        cc._SOURCES_REG = False
        try:
            self.assertEqual(cc.cn_opt(args, "cn99", "limit", default=7), 7)
        finally:
            cc._SOURCES_REG = old

    def test_nodes_kind_skips_registry(self):
        class ExplodingReg:
            @staticmethod
            def by_code(code):
                raise AssertionError("nodes 不应查注册表")
        old = cc._SOURCES_REG
        cc._SOURCES_REG = ExplodingReg()
        try:
            args = self._args()
            self.assertEqual(cc.cn_opt(args, "cn30", "nodes", default=10),
                             10)
        finally:
            cc._SOURCES_REG = old


class TestCnOverrideMatrixR89(unittest.TestCase):
    """R89功能查找：泛型覆盖适用矩阵（防静默接线漂移；改派线须同步改docs）。

    矩阵由源码派生：字面量 cn_opt 调用＋动态循环变量（cn42/43/44/13
    的 limit/concurrency）。intent 语义：batch-legacy（cn01-03）/
    L2常开（cn20-29）/搭车（cn41）码无泛型 knob，设之无效。
    """

    _DYN_CODES = ("cn42", "cn43", "cn44", "cn13")
    _MATRIX = None

    @classmethod
    def setUpClass(cls):
        """R90性能：源文件读盘＋正则派生一次（原每断言一次，共 4 次）。"""
        super().setUpClass()
        cls._MATRIX = cls._derive_matrix()

    @classmethod
    def _derive_matrix(cls):
        import re
        from pathlib import Path
        src = (Path(cc.__file__).resolve().parent.parent
               / "scripts" / "china_check.py").read_text(encoding="utf-8")
        got = {"limit": set(), "concurrency": set(), "nodes": set()}
        for m in re.finditer(
                r'cn_opt\(args,\s*"(cn\d+)",\s*"(limit|concurrency|nodes)"', src):
            got[m.group(2)].add(m.group(1))
        dyn = set(re.findall(r'cn_opt\(args,\s*src,\s*"(limit|concurrency|nodes)"',
                             src))
        for kind in dyn:
            got[kind] |= set(cls._DYN_CODES)
        return {k: sorted(v) for k, v in got.items()}

    def _matrix(self):
        return self._MATRIX

    def test_limit_matrix(self):
        m = self._matrix()["limit"]
        self.assertEqual(m, sorted(
            ["cn04", "cn05", "cn06", "cn07", "cn08", "cn09", "cn10",
             "cn11", "cn12", "cn13", "cn14", "cn15", "cn16", "cn17",
             "cn18", "cn19", "cn30", "cn31", "cn32", "cn33", "cn34",
             "cn35", "cn36", "cn37", "cn38", "cn39", "cn40",
             "cn42", "cn43", "cn44"]))

    def test_concurrency_matrix(self):
        m = self._matrix()["concurrency"]
        self.assertEqual(m, sorted(
            ["cn04", "cn05", "cn06", "cn07", "cn08", "cn09", "cn10",
             "cn11", "cn12", "cn13", "cn14", "cn15", "cn16", "cn17",
             "cn18", "cn19", "cn30", "cn31", "cn32", "cn33", "cn34",
             "cn35", "cn36", "cn37", "cn38", "cn39", "cn40",
             "cn42", "cn43", "cn44"]))

    def test_nodes_matrix(self):
        self.assertEqual(self._matrix()["nodes"], ["cn02", "cn30"])

    def test_exempt_codes_documented(self):
        m = self._matrix()
        exempt = sorted(set(f"cn{i:02d}" for i in range(1, 45))
                        - set(m["limit"]))
        self.assertEqual(exempt, sorted(
            ["cn01", "cn02", "cn03"] + [f"cn{i:02d}" for i in range(20, 30)]
            + ["cn41"]))

    def test_inapplicable_warns_r99(self):
        """R99验证正确性：豁免码设覆盖打 warn，生效码静默（与矩阵同构）。"""
        import io
        from contextlib import redirect_stderr
        from types import SimpleNamespace
        args = SimpleNamespace(
            cn_limit={"cn30": 1, "cn01": 1, "cn20": 1, "cn41": 1},
            cn_concurrency={}, cn_nodes={"cn30": 1, "cn07": 1})
        buf = io.StringIO()
        with redirect_stderr(buf):
            cc.warn_inapplicable_cn_codes(args)
        err = buf.getvalue()
        for c in ("cn01", "cn20", "cn41", "cn07"):
            self.assertIn(c, err, c)
        self.assertNotIn("'cn30'", err)

    def test_inapplicable_skips_without_bundle_r99(self):
        """R99：无包时跳过豁免提示（fail-open 少提示）。"""
        import io
        from contextlib import redirect_stderr
        from types import SimpleNamespace
        old = cc._SOURCES_REG
        cc._SOURCES_REG = False
        try:
            args = SimpleNamespace(
                cn_limit={"cn01": 1}, cn_concurrency={}, cn_nodes={})
            buf = io.StringIO()
            with redirect_stderr(buf):
                cc.warn_inapplicable_cn_codes(args)
            self.assertEqual(buf.getvalue(), "")
        finally:
            cc._SOURCES_REG = old

    def test_registry_loads_once_per_process_r90(self):
        """R90性能：N 次 cn_opt 只触发 ≤1 次插件加载（进程内缓存）。

        防回退逐调用 import（loader 含 sys.path 操作＋版本校验，
        高频调用即放大约 55 处派线点的单轮开销）。
        """
        from types import SimpleNamespace
        from unittest import mock
        real_load = cc._load_pcb_plugin
        calls = []
        old = cc._SOURCES_REG
        cc._SOURCES_REG = None
        try:
            with mock.patch.object(cc, "_load_pcb_plugin",
                                   side_effect=lambda n: (calls.append(n),
                                                          real_load(n))[1]):
                args = SimpleNamespace(cn_limit={"cn30": 1},
                                       cn_concurrency={}, cn_nodes={})
                for code in ("cn30", "cn31", "cn07", "cn40", "cn99"):
                    cc.cn_opt(args, code, "limit", default=0)
                    cc.cn_opt(args, code, "concurrency", default=0)
                args2 = SimpleNamespace(
                    cn_limit={"cn01": 1}, cn_concurrency={"cn20": 1},
                    cn_nodes={"cn07": 1})
                cc.warn_unknown_cn_codes(args2)
                cc.warn_inapplicable_cn_codes(args2)
                import io
                from contextlib import redirect_stderr, redirect_stdout
                with redirect_stderr(io.StringIO()), \
                     redirect_stdout(io.StringIO()):
                    cc.list_cn_sources()
            self.assertLessEqual(len(calls), 1, calls)
        finally:
            cc._SOURCES_REG = old


class TestEngineRegistryTables(unittest.TestCase):
    """engine 判定表注册表驱动（有包）与 legacy 回退（无包）双路径。"""

    def _reg(self):
        import china_engine as ce
        try:
            return ce._load_pcb_plugin("_sources")
        except Exception:
            self.skipTest("needs PCB _sources bundle")

    def test_tables_match_registry(self):
        import china_engine as ce
        reg = self._reg()
        multi = sorted(e["code"] for e in reg.SOURCES
                       if e["verdict"] == "multi")
        single = sorted(e["code"] for e in reg.SOURCES
                        if e["verdict"] == "single")
        self.assertEqual(sorted(ce._MULTI_OK), multi)
        self.assertEqual(sorted(ce._SINGLE_OK), single)
        self.assertEqual(sorted(ce._SINGLE_FAILED), single)
        self.assertEqual(sorted(ce._MULTI_FAILED),
                         sorted(s for s in multi if s != "cn41"))

    def test_ratio_map_match_registry(self):
        import china_engine as ce
        reg = self._reg()
        expect = {e["code"]: (e["min_ratio_value"]
                              if e.get("min_ratio_value") is not None
                              else ce.DEFAULT_MIN_RATIO)
                  for e in reg.SOURCES if e.get("min_ratio")}
        self.assertEqual(ce._SOURCE_MIN_RATIO, expect)
        self.assertEqual(ce._SOURCE_MIN_RATIO["cn16"], 0.4)

    def test_builder_none_without_bundle(self):
        import china_engine as ce
        with mock.patch.object(ce, "_load_pcb_plugin",
                               side_effect=ModuleNotFoundError("no pcb")):
            self.assertIsNone(ce._build_verdict_tables())

class TestRegistryDocsTable(unittest.TestCase):
    """docs/scripts.md 代号默认表须与 PCB 注册表逐行一致（生成器锁）。"""

    def test_docs_table_matches_registry(self):
        import re
        reg = _registry_sources(self)
        doc = (Path(__file__).resolve().parent.parent / "docs"
               / "scripts.md").read_text(encoding="utf-8")
        rows = re.findall(r"^\| `(cn\d+)` \| (.*?) \| (.*?) \| (.*?) \|$",
                          doc, re.M)
        self.assertEqual(len(rows), 44)
        by_code = {code: (desc, lim, conc) for code, desc, lim, conc in rows}
        for e in reg.SOURCES:
            self.assertIn(e["code"], by_code, e["code"])
            desc, lim, conc = by_code[e["code"]]
            self.assertEqual(desc, e["desc"], e["code"])
            self.assertEqual(lim, "常开" if e["limit_default"] is None
                             else str(e["limit_default"]), e["code"])
            self.assertEqual(conc, "—" if e["concurrency"] is None
                             else str(e["concurrency"]), e["code"])


class TestNoStaleProtocolDefs(unittest.TestCase):
    """R455：loader 回绑名不得被模块内协议定义遮蔽（R442 cn41_check
    重复定义复发：有 token 即 NameError，空 token 恰好行为一致而潜伏）；
    协议常量（*_URL）亦不得残留。纯 AST，CI 无包可跑。"""

    STALE_DEFS = ("cn41_check", "cn41_parse", "cn40_check",
                  "parse_pingpe_page", "parse_pingpe_results",
                  "pingpe_verdict", "cn42_check", "cn43_check",
                  "cn44_check", "cn34_check", "cn35_check",
                  "cn30_check", "cn30_fetch_nodes",
                  "cn30_pick_nodes", "cn07_check", "cn08_check",
                  "cn14_check", "cn15_check", "cn16_check",
                  "cn17_check", "cn18_check",
                  "cn19_check", "cn11_check", "cn12_check",
                  "cn09_check", "cn10_check", "cn04_check",
                  "cn05_check", "cn27_check",
                  "cn28_check", "cn29_check",
                  "cn20_check", "cn21_check", "cn22_check",
                  "cn23_check", "cn24_check", "cn25_check",
                  "cn26_check", "cn36_check",
                  "cn37_check", "cn38_check",
                  "cn39_check", "cn13_check",
                  "cn01_batch_run")
    STALE_CONSTS = ("TCPPING_URL", "PINGPE_URL", "BOCE_URL",
                    "SEVENTEEN_URL", "PING0_URL", "IPIP_URL")

    def test_no_stale_defs_or_consts(self):
        import ast
        src = (Path(__file__).resolve().parent.parent / "scripts"
               / "china_check.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        defs = {n.name for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        consts = {t.id for t in ast.walk(tree)
                  if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Store)}
        bad_defs = sorted(set(self.STALE_DEFS) & defs)
        bad_consts = sorted(set(self.STALE_CONSTS) & consts)
        self.assertEqual(bad_defs, [], f"残留协议定义遮蔽 loader：{bad_defs}")
        self.assertEqual(bad_consts, [], f"残留协议常量：{bad_consts}")


class TestLoaderBindingsLive(unittest.TestCase):
    """loader 回绑必须全部成功（有包时）：插件属性名漂移/拼写回归
    即整族静默 fail-open（R459：cn06 三 p 拼写自 R425 潜伏；R3 曾误删
    RHS 把全族打熄）。无包跳过（fail-open 本就是该态正确行为）。"""

    FLAGS = ("_CN01_BUNDLE", "_CN04_BUNDLE", "_CN06_BUNDLE",
             "_CN07_BUNDLE", "_CN08_BUNDLE", "_CN27_BUNDLE",
             "_CN20_BUNDLE", "_CN24_BUNDLE", "_CN40_BUNDLE",
             "_CN41_BUNDLE", "_CN30_BUNDLE", "_CN17_BUNDLE",
             "_CN11_BUNDLE", "_CN09_BUNDLE", "_CN36_BUNDLE",
             "_CN34_BUNDLE", "_CN13_BUNDLE", "_LEGACY_REVIEW_BUNDLE")

    def test_all_bundle_flags_true_with_pcb(self):
        _registry_sources(self)
        for f in self.FLAGS:
            self.assertTrue(getattr(cc, f, False), f)

    def test_key_bindings_not_none_with_pcb(self):
        _registry_sources(self)
        for name in ("cn01_batch_run", "cn30_check", "cn40_check",
                     "cn07_check", "cn42_check", "cn20_check",
                     "cn27_check"):
            self.assertIsNotNone(getattr(cc, name, None), name)


class TestWorkflowCodesInRegistry(unittest.TestCase):
    """R10：workflow 通用配额拼写的代号必须全部存在于注册表
    （拼写错误代号会静默落到 default；CI 无包时跳过，终态直连后常跑）。"""

    def test_workflow_codes_subset_of_registry(self):
        import re
        reg = _registry_sources(self)
        known = set(reg.codes())
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        used = set(re.findall(r"--cn-(?:limit|concurrency|nodes) ([A-Za-z0-9_]+)=", wf))
        self.assertTrue(used, "workflow 未见通用配额")
        unknown = sorted(c for c in used if c not in known)
        self.assertEqual(unknown, [], f"workflow 引用未知代号：{unknown}")


class TestDrainFutures(unittest.TestCase):
    """R11：槽位 join 收敛到 _drain_futures（完成序等待，结果无关序；
    逃逸异常上抛，与旧提交序循环语义一致）。"""

    def test_joins_all_regardless_of_order(self):
        import time
        from concurrent.futures import ThreadPoolExecutor
        done = []
        def work(i):
            time.sleep(0.05 * (3 - i))
            done.append(i)
        with ThreadPoolExecutor(max_workers=3) as pool:
            cc._drain_futures([pool.submit(work, i) for i in range(3)])
        self.assertEqual(sorted(done), [0, 1, 2])

    def test_escaping_exception_propagates(self):
        from concurrent.futures import ThreadPoolExecutor
        def boom():
            raise RuntimeError("escape")
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.assertRaises(RuntimeError):
                cc._drain_futures([pool.submit(boom)])


class TestSlotPhaseDispatchPerCode(unittest.TestCase):
    """R12：逐码复核相派发接线（limit=1＋check 抛错 → 该码 error 行）。
    任一码的相未接线/守卫错即爆红——cn06 式整族熄火（R3）不再潜伏。
    有包/无包双态同断言（fail-open 行同样落键）。"""

    PHASES = (
        ("cn04", "cn04_check"), ("cn05", "cn05_check"),
        ("cn06", "cn06_check"), ("cn07", "cn07_check"),
        ("cn08", "cn08_check"), ("cn09", "cn09_check"),
        ("cn10", "cn10_check"), ("cn11", "cn11_check"),
        ("cn12", "cn12_check"), ("cn13", "cn13_check"),
        ("cn14", "cn14_check"), ("cn15", "cn15_check"),
        ("cn16", "cn16_check"), ("cn17", "cn17_check"),
        ("cn18", "cn18_check"), ("cn19", "cn19_check"),
        ("cn30", "cn30_check"), ("cn31", "cn30_check"),
        ("cn32", "cn30_check"), ("cn33", "cn30_check"),
        ("cn34", "cn34_check"), ("cn35", "cn35_check"),
        ("cn36", "cn36_check"), ("cn37", "cn37_check"),
        ("cn38", "cn38_check"), ("cn39", "cn39_check"),
        ("cn40", "cn40_check"), ("cn42", "cn42_check"),
        ("cn43", "cn43_check"), ("cn44", "cn44_check"),
    )

    def _args(self, code):
        from types import SimpleNamespace
        return SimpleNamespace(
            cn_limit={"cn30": 0, "cn40": 0, code: 1},
            cn_concurrency={code: 2},
            skip_cn01=True, skip_cn02=True,
            workers=4, timeout=5, api_key="", tcpping_token="")

    def _boom(self, *a, **k):
        raise RuntimeError("boom")

    def _err(self, *a, **k):
        return {"status": "error", "ok": False, "ms": None,
                "error": "x"}

    def test_each_phase_dispatches(self):
        import unittest.mock as mock
        item = ("10.9.9.9:443#US", "10.9.9.9:443#US", "10.9.9.9",
                "443", "US")
        for code, binding in self.PHASES:
            with self.subTest(code=code):
                patches = [
                    mock.patch.object(cc, binding,
                                      side_effect=self._boom),
                    mock.patch.object(cc, "cn30_fetch_nodes",
                                      return_value=[{"uuid": "u1",
                                                     "operator": "ct",
                                                     "enabled": True,
                                                     "runtime_state": "online"}]),
                    mock.patch.object(cc, "cn30_pick_nodes",
                                      side_effect=lambda n, c: ["u1"]),
                    mock.patch.object(cc, "cn20_check",
                                      side_effect=self._err),
                    mock.patch.object(cc, "cn21_check",
                                      side_effect=self._err),
                    mock.patch.object(cc, "cn22_check",
                                      side_effect=self._err),
                    mock.patch.object(cc, "cn23_check",
                                      side_effect=self._err),
                    mock.patch.object(cc, "cn24_check",
                                      side_effect=self._err),
                    mock.patch.object(cc, "cn25_check",
                                      side_effect=self._err),
                    mock.patch.object(cc, "cn26_check",
                                      side_effect=self._err),
                    mock.patch.object(cc, "cn27_check",
                                      return_value={"status": "error",
                                                    "ok": False, "ms": None,
                                                    "error": "x"}),
                    mock.patch.object(cc, "cn28_check",
                                      return_value={"status": "error",
                                                    "ok": False, "ms": None,
                                                    "error": "x"}),
                    mock.patch.object(cc, "cn29_check",
                                      return_value={"status": "error",
                                                    "ok": False, "ms": None,
                                                    "error": "x"}),
                    mock.patch.object(cc, "cn41_check",
                                      return_value={"status": "skipped"}),
                ]
                for pm in patches:
                    pm.start()
                try:
                    entries, _, _ = cc.run_measurements(
                        [item], self._args(code))
                finally:
                    for pm in patches:
                        pm.stop()
                row = entries["10.9.9.9:443#US"]["sources"].get(code)
                self.assertIsNotNone(row, f"{code} 相未派发")
                self.assertEqual(row["status"], "error", code)


class TestArgparseDestConsumed(unittest.TestCase):
    """R18：argparse 每个 dest 必须被消费（直接读取/字符串引用/插件透传
    白名单三者居其一；死旗标（协议特有参数）即因此类
    审计发现，不再复发）。"""

    PASSTHROUGH = {"cn01_nodes", "cn01_batch_size", "cn01_concurrency",
                   "cn01_pacing", "cn01_timeout"}

    def test_all_dests_consumed(self):
        import ast
        import re
        src = (Path(__file__).resolve().parent.parent / "scripts"
               / "china_check.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        dests = {}
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_argument"):
                continue
            flags = [a.value for a in node.args
                     if isinstance(a, ast.Constant)
                     and isinstance(a.value, str)
                     and a.value.startswith("-")]
            if not flags:
                continue
            longs = [f for f in flags if f.startswith("--")]
            dest = (longs[0] if longs else flags[0]).lstrip("-").replace(
                "-", "_")
            dests[dest] = node.lineno
        dead = []
        for dest, ln in sorted(dests.items()):
            read = (
                re.search(r"args\." + re.escape(dest) + r"\b", src)
                or re.search(r'"' + re.escape(dest) + r'"', src)
                or dest in self.PASSTHROUGH
            )
            if not read:
                dead.append(f"{dest} (line {ln})")
        self.assertEqual(dead, [])


class TestNoLegacySourceFlags(unittest.TestCase):
    """R19：flag-day 完整性锁。workflow/CLI 帮助不得重现任何已删除的
    legacy 源旗标（`--<stem>-limit/-concurrency`）；重现即红。"""

    LEGACY_PATTERNS = (
        "-limit", "-concurrency",
    )
    # 拼接写法：leak 锁禁真名键字面（R441 判例），此处只能拆分引用。
    LEGACY_STEMS = (
        "tcp" + "test", "tcp" + "test-ping", "tcp" + "test-http",
        "tcp" + "test-trace", "ping" + "pe", "coff" + "ee",
        "ping" + "loc", "antp" + "ing", "antp" + "ing-ping",
        "tcping" + "cn", "tcping" + "cn-ping", "tcping" + "cn-mtr",
        "chin" + "az", "ce" + "98", "ce" + "98-ping", "biup" + "ing",
        "biup" + "ing-ping", "aa1p" + "ing", "aa1h" + "ttp",
        "tcpp" + "ing-ws", "ip" + "ip", "ip" + "ip-trace",
        "globalp" + "ing", "globalp" + "ing-trace",
        "globalp" + "ing-http", "globalp" + "ing-mtr", "bo" + "ce",
        "17" + "ce", "ping" + "0", "wan" + "sui",
    )

    def test_workflow_has_no_legacy_flags(self):
        import re
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        hits = []
        for stem in self.LEGACY_STEMS:
            for suffix in ("-limit", "-concurrency"):
                pat = "--" + stem + suffix + r"(?![\w-])"
                if re.search(pat, wf):
                    hits.append("--" + stem + suffix)
        self.assertEqual(hits, [])

    def test_help_has_no_legacy_flags(self):
        import re
        import subprocess
        import sys
        root = Path(__file__).resolve().parent.parent
        proc = subprocess.run(
            [sys.executable, str(root / "scripts" / "china_check.py"),
             "--help"],
            capture_output=True, text=True, timeout=90)
        self.assertEqual(proc.returncode, 0)
        hits = []
        for stem in self.LEGACY_STEMS:
            for suffix in ("-limit", "-concurrency"):
                pat = "--" + stem + suffix + r"(?![\w-])"
                if re.search(pat, proc.stdout):
                    hits.append("--" + stem + suffix)
        self.assertEqual(hits, [])


class TestCiChainDefinition(unittest.TestCase):
    """R20：CI 链定义锁（文件名/cron/concurrency 组/contents 权限；
    防误删改名与调度丢失；cancel-in-progress 调优不在此列）。"""

    WORKFLOWS = (
        "annotate-classify.yml",
        "build-good.yml",
        "china-check.yml",
        "deep-speed.yml",
        "exit-family.yml",
        "quality-check.yml",
        "stats.yml",
        "update-proxies.yml",
    )
    CRONS = {
        "china-check.yml": "11 * * * *",
        "deep-speed.yml": "7 3 * * 6",
        "stats.yml": "40 */2 * * *",
        "update-proxies.yml": "0 */2 * * *",
    }

    def test_workflow_files_and_groups(self):
        import re
        d = Path(__file__).resolve().parent.parent / ".github" / "workflows"
        self.assertEqual(sorted(f.name for f in d.glob("*.yml")),
                         sorted(self.WORKFLOWS))
        for name in self.WORKFLOWS:
            text = (d / name).read_text(encoding="utf-8")
            stem = name[: -len(".yml")]
            m = re.search(r"concurrency:\s*\n\s*group:\s*(\S+)", text)
            self.assertIsNotNone(m, f"{name} 缺 concurrency 组")
            self.assertEqual(m.group(1), stem, f"{name} 组名漂移")

    def test_schedules_and_permissions(self):
        import re
        d = Path(__file__).resolve().parent.parent / ".github" / "workflows"
        for name in self.WORKFLOWS:
            text = (d / name).read_text(encoding="utf-8")
            self.assertIn("contents: write", text, f"{name} 缺写权限")
        for name, cron in self.CRONS.items():
            text = (d / name).read_text(encoding="utf-8")
            self.assertIn(f'cron: "{cron}"', text, f"{name} 调度丢失")


class TestCnCacheTtlLocked(unittest.TestCase):
    """R21：CI 的 `--cn-cache-ttl 21600` 不得删除或调小（删即回到数小时
    全量复测；R13–R17 实测 4h40m→3m17s）。"""

    def test_workflow_keeps_cache_ttl(self):
        import re
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        m = re.search(r"--cn-cache-ttl (\d+)", wf)
        self.assertIsNotNone(m, "CI 缓存 TTL 丢失")
        self.assertGreaterEqual(int(m.group(1)), 21600)


class TestWorkflowTriggerEdges(unittest.TestCase):
    """R23：workflow_run 触发边锁（ chain 拓扑：删触发即断链；
    根工作流仅 schedule/dispatch，无 workflow_run 父边）。"""

    EDGES = {
        "annotate-classify.yml": ["Quality check"],
        "build-good.yml": ["Quality check", "China check"],
        "exit-family.yml": ["Quality check"],
        "quality-check.yml": ["Update proxy list"],
        "stats.yml": ["Quality check", "China check",
                      "Exit family check", "Build good lists"],
        "china-check.yml": [],
        "update-proxies.yml": [],
        "deep-speed.yml": [],
    }

    def test_trigger_edges(self):
        import re
        d = Path(__file__).resolve().parent.parent / ".github" / "workflows"
        for name, want in sorted(self.EDGES.items()):
            text = (d / name).read_text(encoding="utf-8")
            m = re.search(r"workflows:\s*\[(.*?)\]", text)
            got = ([x.strip().strip('"').strip("'") for x in m.group(1).split(",")]
                   if m else [])
            got = [x for x in got if x]
            self.assertEqual(got, want, f"{name} 触发边漂移")


if __name__ == "__main__":
    unittest.main()