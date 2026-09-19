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
import china_itdog as ci


CN_LINE = "1.2.3.4:2087#\U0001F1FA\U0001F1F8US-10ms-20.07MB/s-GPT-CF"
US_LINE = "5.6.7.8:443#\U0001F1FA\U0001F1F8US-8ms-5.86MB/s"



class TestParseCheckHostHttp(unittest.TestCase):
    """CN-32：check-host /http 报告解析（呼和浩特应用层）。"""

    def _payload(self, check):
        return {"data": {cc.CHECKHOST_NODE: {"checks": [check]}}}

    def test_ok_http(self):
        """http_status 404 亦为完整往返 → ok，level=http。"""
        payload = self._payload(
            {"status": 1, "connectiontime": 39, "http_status": 404,
             "target_ip": "223.5.5.5"})
        result = cc.parse_check_host_http_report(payload)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["ok"])
        self.assertEqual(result["ms"], 39.0)
        self.assertEqual(result["level"], "http")

    def test_ok_tcp_fallback(self):
        """status=1 但无 HTTP 应答 → 传输层 ok（itdog connect_time 同理）。"""
        payload = self._payload(
            {"status": 1, "connectiontime": 39, "http_status": 0})
        result = cc.parse_check_host_http_report(payload)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["level"], "tcp")

    def test_fail_report(self):
        payload = self._payload(
            {"status": 0, "errortext": "Connection timed out"})
        result = cc.parse_check_host_http_report(payload)
        self.assertEqual(result["status"], "fail")
        self.assertIn("timed out", result["error"])

    def test_pending_and_bad(self):
        self.assertEqual(
            cc.parse_check_host_http_report({"data": {}})["status"],
            "pending")
        self.assertEqual(cc.parse_check_host_http_report({})["status"],
                         "error")
        self.assertEqual(cc.parse_check_host_http_report(None)["status"],
                         "error")


class TestCheckhostHttpCheck(unittest.TestCase):
    """CN-32：checkhost_http_check 提交＋轮询（mock，不触网）。"""

    def _ok_report(self):
        return json.dumps({
            "data": {cc.CHECKHOST_NODE: {"checks": [
                {"status": 1, "connectiontime": 39, "http_status": 200,
                 "target_ip": "1.2.3.4"}]}}}).encode()

    def _limiter(self):
        return cc.RateLimiter(window=10.0, per_window=100, hour_cap=100)

    def test_ok_flow_posts_http_endpoint(self):
        submit = json.dumps({"uuid": "u9"}).encode()
        calls = []

        def fake(url, headers, timeout, method="GET", data=None):
            calls.append((url, method))
            if method == "POST":
                return 200, {}, submit
            return 200, {}, self._ok_report()

        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.checkhost_http_check("1.2.3.4", "443",
                                          self._limiter(), 10, "")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["level"], "http")
        self.assertTrue(calls[0][0].endswith("/http"))
        self.assertNotIn("isp_ms", out)

    def test_submit_body_carries_port(self):
        """端口必须进提交体（逐端口 HTTPS 实测）。"""
        seen = {}

        def fake(url, headers, timeout, method="GET", data=None):
            if method == "POST":
                seen["body"] = json.loads(data.decode())
                return 200, {}, json.dumps({"uuid": "u9"}).encode()
            return 200, {}, self._ok_report()

        with mock.patch.object(cc, "request_follow", side_effect=fake):
            cc.checkhost_http_check("1.2.3.4", "8443", self._limiter(), 10, "")
        self.assertEqual(seen["body"]["port"], 8443)
        self.assertEqual(seen["body"]["target"], "1.2.3.4")

    def test_submit_429_rate_limited(self):
        with mock.patch.object(cc, "request_follow",
                               side_effect=urllib.error.HTTPError(
                                   "http://x", 429, "Too Many Requests",
                                   {}, io.BytesIO(b""))):
            out = cc.checkhost_http_check("1.2.3.4", "443",
                                          self._limiter(), 10, "")
        self.assertEqual(out["status"], "rate_limited")

    def test_no_uuid(self):
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, b"{}")):
            out = cc.checkhost_http_check("1.2.3.4", "443",
                                          self._limiter(), 10, "")
        self.assertEqual(out["status"], "error")


class TestCheckhostHttpMergeVerdict(unittest.TestCase):
    """CN-32：checkhost_http 并入单节点交叉（应用层第二确认）。"""

    def test_second_confirm_reachable_http(self):
        sources = {
            "xxapi": {"status": "ok", "ok": True, "ms": 90},
            "checkhost_http": {"status": "ok", "ok": True, "ms": 39,
                               "level": "http"},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "http")

    def test_http_alone_uncertain(self):
        sources = {"checkhost_http": {
            "status": "ok", "ok": True, "ms": 39, "level": "http"}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_http_fail_harmless(self):
        """http-fail 伴 TCP-ok 仍 uncertain（不定罪，fail 分析在 ok 之后）。"""
        sources = {
            "check_host": {"status": "ok", "ok": True, "ms": 100},
            "checkhost_http": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")


class TestCheckhostHttpWiring(unittest.TestCase):
    """CN-32：http 只在 TCP-ok 且其余免额 0 ok 时猎取第二确认。"""

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

    def _item(self):
        return ("9.9.9.9:443#US", "9.9.9.9:443#US", "9.9.9.9", "443", "US")

    def _l2(self, tcp):
        return [
            mock.patch.object(cc, "xxapi_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "xxping_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "jkapi_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "jkping_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "check_host_check", return_value=tcp),
        ]

    def test_http_hunts_second_confirm(self):
        tcp = {"status": "ok", "ok": True, "ms": 100}
        http = {"status": "ok", "ok": True, "ms": 39, "level": "http"}
        mocks = self._l2(tcp)
        with mock.patch.object(cc, "checkhost_http_check",
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
        self.assertEqual(srcs["checkhost_http"]["level"], "http")
        # TCP-ok + http-ok → 双确认 reachable（uncertain 翻正）
        self.assertEqual(entries["9.9.9.9:443#US"]["verdict"], "reachable")
        self.assertIn("9.9.9.9:443#US", reachable)

    def test_http_skipped_when_already_confirmed(self):
        """已有免额 ok 时不浪费配额猎取第三确认。"""
        tcp = {"status": "ok", "ok": True, "ms": 100}
        mocks = self._l2(tcp)
        mocks[0] = mock.patch.object(
            cc, "xxapi_check",
            return_value={"status": "ok", "ok": True, "ms": 90})
        with mock.patch.object(cc, "checkhost_http_check",
                               side_effect=AssertionError("must not run")):
            for p in mocks:
                p.start()
            try:
                entries, _, _ = cc.run_measurements([self._item()],
                                                    self._args())
            finally:
                for p in mocks:
                    p.stop()
        self.assertNotIn("checkhost_http",
                         entries["9.9.9.9:443#US"]["sources"])


class TestParseCheckHostPing(unittest.TestCase):
    """CN-31：check-host /ping 报告解析（呼和浩特 ICMP）。"""

    def _payload(self, checks):
        return {"data": {cc.CHECKHOST_NODE: {"checks": checks}}}

    def test_ok_report(self):
        payload = self._payload(
            [{"status": 1, "connectiontime": 13,
              "target_ip": "223.5.5.5", "errortext": ""}])
        result = cc.parse_check_host_ping_report(payload)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["ok"])
        self.assertEqual(result["ms"], 13)

    def test_fail_report(self):
        payload = self._payload(
            [{"status": 0, "errortext": "Connection timed out"}])
        result = cc.parse_check_host_ping_report(payload)
        self.assertEqual(result["status"], "fail")
        self.assertIn("timed out", result["error"])

    def test_pending_and_bad(self):
        self.assertEqual(
            cc.parse_check_host_ping_report({"data": {}})["status"],
            "pending")
        self.assertEqual(cc.parse_check_host_ping_report({})["status"],
                         "error")
        self.assertEqual(cc.parse_check_host_ping_report(None)["status"],
                         "error")


class TestCheckhostPingCheck(unittest.TestCase):
    """CN-31：checkhost_ping_check 提交＋轮询（mock request_follow）。"""

    def _ok_report(self):
        return json.dumps({
            "data": {cc.CHECKHOST_NODE: {"checks": [
                {"status": 1, "connectiontime": 13,
                 "target_ip": "1.2.3.4", "errortext": ""}]}}}).encode()

    def test_ok_flow(self):
        submit = json.dumps({"uuid": "u1"}).encode()
        calls = []

        def fake(url, headers, timeout, method="GET", data=None):
            calls.append((url, method))
            if method == "POST":
                return 200, {}, submit
            return 200, {}, self._ok_report()

        limiter = cc.RateLimiter(window=10.0, per_window=100, hour_cap=100)
        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.checkhost_ping_check("1.2.3.4", limiter, 10, "")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ms"], 13)
        self.assertEqual(out["level"], "icmp")
        self.assertTrue(calls[0][0].endswith("/ping"))
        self.assertNotIn("isp_ms", out)

    def test_submit_429_rate_limited(self):
        limiter = cc.RateLimiter(window=10.0, per_window=100, hour_cap=100)
        with mock.patch.object(cc, "request_follow",
                               side_effect=urllib.error.HTTPError(
                                   "http://x", 429, "Too Many Requests",
                                   {}, io.BytesIO(b""))):
            out = cc.checkhost_ping_check("1.2.3.4", limiter, 10, "")
        self.assertEqual(out["status"], "rate_limited")

    def test_hour_cap_no_network(self):
        limiter = cc.RateLimiter(window=10.0, per_window=100, hour_cap=1)
        limiter.acquire()  # 占满配额
        with mock.patch.object(
                cc, "request_follow",
                side_effect=AssertionError("no network")):
            out = cc.checkhost_ping_check("1.2.3.4", limiter, 10, "")
        self.assertEqual(out["status"], "rate_limited")

    def test_no_uuid(self):
        limiter = cc.RateLimiter(window=10.0, per_window=100, hour_cap=100)
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, b"{}")):
            out = cc.checkhost_ping_check("1.2.3.4", limiter, 10, "")
        self.assertEqual(out["status"], "error")


class TestCheckhostPingMergeVerdict(unittest.TestCase):
    """CN-31：checkhost_ping 并入单节点交叉（主机/端口死因消歧）。"""

    def test_tcp_fail_plus_ping_ok_uncertain(self):
        """TCP 双 fail 原判 unreachable；ping 证主机存活 → 回退 uncertain。"""
        sources = {
            "check_host": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "fail", "ok": False, "ms": None},
            "checkhost_ping": {"status": "ok", "ok": True, "ms": 13,
                               "level": "icmp"},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "uncertain")
        self.assertEqual(merged["level"], "icmp")

    def test_dual_fail_unreachable(self):
        """同节点 TCP+ICMP 双 fail → 置信定罪。"""
        sources = {
            "check_host": {"status": "fail", "ok": False, "ms": None},
            "checkhost_ping": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_ping_ok_plus_single_ok_reachable(self):
        sources = {
            "checkhost_ping": {"status": "ok", "ok": True, "ms": 13,
                               "level": "icmp"},
            "jkapi": {"status": "ok", "ok": True, "ms": 11},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "reachable")

    def test_ping_alone_ok_uncertain(self):
        sources = {"checkhost_ping": {
            "status": "ok", "ok": True, "ms": 13, "level": "icmp"}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")


class TestCheckhostPingWiring(unittest.TestCase):
    """CN-31：ping 只在 TCP fail 时追加（配额敏感），落 entries 源键。"""

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

    def _item(self):
        return ("9.9.9.9:443#US", "9.9.9.9:443#US", "9.9.9.9", "443", "US")

    def _l2(self, tcp, ping_ret=None):
        mocks = [
            mock.patch.object(cc, "xxapi_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "xxping_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "jkapi_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "jkping_check",
                              return_value={"status": "error", "ok": False,
                                            "ms": None, "error": "x"}),
            mock.patch.object(cc, "check_host_check", return_value=tcp),
        ]
        if ping_ret is not None:
            mocks.append(mock.patch.object(cc, "checkhost_ping_check",
                                           return_value=ping_ret))
        return mocks

    def test_ping_runs_on_tcp_fail(self):
        tcp = {"status": "fail", "ok": False, "ms": None, "error": ""}
        ping = {"status": "ok", "ok": True, "ms": 13, "level": "icmp"}
        mocks = self._l2(tcp)
        with mock.patch.object(cc, "checkhost_ping_check",
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
        self.assertEqual(srcs["checkhost_ping"]["ms"], 13)
        # TCP-fail + ping-ok + 全 error → uncertain（不误判死）
        self.assertEqual(entries["9.9.9.9:443#US"]["verdict"], "uncertain")

    def test_ping_skipped_on_tcp_ok(self):
        tcp = {"status": "ok", "ok": True, "ms": 100}
        mocks = self._l2(tcp)
        with mock.patch.object(cc, "checkhost_ping_check",
                               side_effect=AssertionError("must not run")):
            for p in mocks:
                p.start()
            try:
                entries, _, _ = cc.run_measurements([self._item()],
                                                    self._args())
            finally:
                for p in mocks:
                    p.stop()
        self.assertNotIn("checkhost_ping",
                         entries["9.9.9.9:443#US"]["sources"])


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


class TestParseXxping(unittest.TestCase):
    """CN-29：xxapi api/ping（枣庄 BGP ICMP）JSON 解析＋echo 校验。"""

    def _payload(self, time="8.239ms", ip="223.5.5.5"):
        return {"code": 200, "msg": "数据请求成功",
                "data": {"ip": ip, "server": "中国山东枣庄BGP",
                         "time": time, "url": "223.5.5.5"}}

    def test_ok(self):
        result = cc.parse_xxping(self._payload(), "223.5.5.5")
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["ok"])
        self.assertAlmostEqual(result["ms"], 8.239)

    def test_echo_mismatch_fail(self):
        """TEST-NET 垃圾回显（data.ip 与请求不一致）→ fail，不误判可达。"""
        payload = self._payload(time="577.266ms", ip="183.2.160.48")
        result = cc.parse_xxping(payload, "203.0.113.1")
        self.assertEqual(result["status"], "fail")
        self.assertFalse(result["ok"])

    def test_refusal_error(self):
        """-4 禁止访问（私网目标）：后端拒绝测试，无信号，按 error。"""
        result = cc.parse_xxping(
            {"code": -4, "msg": "禁止访问该URL", "data": ""}, "10.255.255.1")
        self.assertEqual(result["status"], "error")

    def test_200_without_time_inconclusive(self):
        payload = {"code": 200, "data": {"ip": "1.2.3.4"}}
        self.assertEqual(
            cc.parse_xxping(payload, "1.2.3.4")["status"], "inconclusive")

    def test_bad_payload(self):
        self.assertEqual(cc.parse_xxping(None, "1.2.3.4")["status"], "error")
        self.assertEqual(cc.parse_xxping({}, "1.2.3.4")["status"], "error")
        self.assertEqual(
            cc.parse_xxping({"code": 200}, "1.2.3.4")["status"], "error")


class TestXxpingCheck(unittest.TestCase):
    """CN-29：xxping_check 传输层＋level 语义（mock，不触网）。"""

    _BODY = (b'{"code":200,"msg":"ok","data":{"ip":"223.5.5.5",'
             b'"server":"cn","time":"8.239ms","url":"223.5.5.5"}}')

    def test_ok_level_icmp(self):
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, self._BODY)):
            out = cc.xxping_check("223.5.5.5", "443", 10)
        self.assertEqual(out["status"], "ok")
        self.assertAlmostEqual(out["ms"], 8.239)
        self.assertEqual(out["level"], "icmp")
        self.assertNotIn("isp_ms", out)  # BGP 机房运营商不明，不产出

    def test_refusal_no_level(self):
        body = '{"code":-4,"msg":"禁止访问该URL","data":""}'.encode()
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, body)):
            out = cc.xxping_check("10.0.0.1", "443", 10)
        self.assertEqual(out["status"], "error")
        self.assertIsNone(out["level"])

    def test_rate_limited(self):
        with mock.patch.object(cc, "request_follow",
                               side_effect=urllib.error.HTTPError(
                                   "http://x", 429, "Too Many Requests",
                                   {}, io.BytesIO(b""))):
            out = cc.xxping_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "rate_limited")

    def test_transport_error(self):
        with mock.patch.object(cc, "request_follow",
                               side_effect=urllib.error.URLError("boom")):
            out = cc.xxping_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error"], "URLError")

    def test_bad_json(self):
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, b"not json")):
            out = cc.xxping_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "error")


class TestXxpingMergeVerdict(unittest.TestCase):
    """CN-29：xxping 并入单节点交叉，与其余四源同权。"""

    def test_xxping_jkping_double_ok_reachable(self):
        """跨运营商双 ICMP（枣庄＋宁波）双 ok → reachable。"""
        sources = {
            "xxping": {"status": "ok", "ok": True, "ms": 42.1,
                       "level": "icmp"},
            "jkping": {"status": "ok", "ok": True, "ms": 12.7,
                       "level": "icmp"},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "icmp")

    def test_xxping_alone_ok_uncertain(self):
        sources = {"xxping": {"status": "ok", "ok": True, "ms": 42.1,
                              "level": "icmp"}}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "uncertain")
        self.assertEqual(merged["level"], "icmp")

    def test_xxping_fail_plus_xxapi_fail_unreachable(self):
        """同运营商双视角（北京 TCP＋枣庄 ICMP）双 fail → unreachable。"""
        sources = {
            "xxping": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_xxping_fail_alone_uncertain(self):
        sources = {
            "xxping": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")


class TestParseJkping(unittest.TestCase):
    """CN-25：jkapi zz_ping（宁波电信 ICMP）纯文本报告解析。"""

    def test_ok(self):
        report = (
            "=== Ping测试报告 ===\n"
            "目标地址:223.5.5.5\n"
            "最快延迟:12.5ms\n"
            "最慢延迟:12.9ms\n"
            "平均延迟:12.73ms\n"
            "丢 包 率:0% (发:4/收:4)\n"
            "测试节点:浙江宁波电信\n"
        )
        result = cc.parse_jkping(report)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["ok"])
        self.assertAlmostEqual(result["ms"], 12.73)

    def test_ok_int_ms_with_loss(self):
        # 8.8.8.8 活体实证：50% 丢包但有回显 → 主机存活 ok（端口层另由 TCP 源判定）
        report = ("=== Ping测试报告 ===\n目标地址:8.8.8.8\n平均延迟:176ms\n"
                  "丢 包 率:50% (发:4/收:2)\n测试节点:浙江宁波电信\n")
        result = cc.parse_jkping(report)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["ms"], 176.0)

    def test_fail(self):
        result = cc.parse_jkping("无法获取ping结果，目标可能禁Ping或无法访问")
        self.assertEqual(result["status"], "fail")
        self.assertFalse(result["ok"])

    def test_tcping_report_rejected(self):
        # TCPing 报告含 "Ping测试报告" 子串：须判 inconclusive，不得误解析为 ICMP ok
        report = ("=== TCPing测试报告 ===\n目标地址: 223.5.5.5 (223.5.5.5)\n"
                  "目标端口: 443\n平均延迟: 10.95 ms\n测试节点:浙江宁波电信\n")
        result = cc.parse_jkping(report)
        self.assertEqual(result["status"], "inconclusive")
        self.assertFalse(result["ok"])

    def test_report_without_avg_inconclusive(self):
        result = cc.parse_jkping("=== Ping测试报告 ===\n")
        self.assertEqual(result["status"], "inconclusive")

    def test_unrecognized_inconclusive(self):
        self.assertEqual(cc.parse_jkping("")["status"], "inconclusive")
        self.assertEqual(cc.parse_jkping("server error")["status"], "inconclusive")


class TestJkpingCheck(unittest.TestCase):
    """CN-25：jkping_check 传输层 + level/证据语义（mock request_follow，不触网）。"""

    def test_ok_level_icmp(self):
        body = ("=== Ping测试报告 ===\n平均延迟:12.73ms\n"
                "测试节点:浙江宁波电信\n").encode()
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, body)):
            out = cc.jkping_check("223.5.5.5", "443", 10)
        self.assertEqual(out["status"], "ok")
        self.assertTrue(out["ok"])
        self.assertAlmostEqual(out["ms"], 12.73)
        self.assertEqual(out["level"], "icmp")
        # ICMP 不产出 isp_ms（防 ICMP RTT 污染 cn_fastest_ms，chinaz/coffee 同口径）
        self.assertNotIn("isp_ms", out)

    def test_fail_no_level(self):
        body = "无法获取ping结果，目标可能禁Ping或无法访问".encode()
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, body)):
            out = cc.jkping_check("192.0.2.1", "443", 10)
        self.assertEqual(out["status"], "fail")
        self.assertFalse(out["ok"])
        self.assertIsNone(out["level"])

    def test_rate_limited(self):
        with mock.patch.object(cc, "request_follow",
                               side_effect=urllib.error.HTTPError(
                                   "http://x", 429, "Too Many Requests",
                                   {}, io.BytesIO(b""))):
            out = cc.jkping_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "rate_limited")
        self.assertFalse(out["ok"])

    def test_transport_error(self):
        with mock.patch.object(cc, "request_follow",
                               side_effect=urllib.error.URLError("boom")):
            out = cc.jkping_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error"], "URLError")

    def test_non_200_error(self):
        with mock.patch.object(cc, "request_follow",
                               return_value=(500, {}, b"err")):
            out = cc.jkping_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "error")


class TestJkMirrorFailover(unittest.TestCase):
    """CN-26：jk 系双镜像（jkapi.com → api.jkapi.com，同站同节点活体实证）。"""

    _TCP_OK = ("=== TCPing测试报告 ===\n平均延迟: 10.91 ms\n"
               "测试节点:浙江宁波电信\n").encode()
    _PING_OK = ("=== Ping测试报告 ===\n平均延迟:12.65ms\n"
                "测试节点:浙江宁波电信\n").encode()

    def _route(self, primary_exc=None, primary_status=200, primary_body=b"",
               mirror_body=None):
        """按 URL 分流的 request_follow 替身：主站按设定失败，镜像回业务体。"""
        def fake(url, headers, timeout, method="GET", data=None):
            if "api.jkapi.com" in url:
                if mirror_body is None:
                    raise urllib.error.URLError("mirror down")
                return 200, {}, mirror_body
            if primary_exc is not None:
                raise primary_exc
            return primary_status, {}, primary_body
        return fake

    def test_jkapi_primary_down_mirror_ok(self):
        with mock.patch.object(cc, "request_follow",
                               side_effect=self._route(
                                   primary_exc=urllib.error.URLError("reset"),
                                   mirror_body=self._TCP_OK)):
            out = cc.jkapi_check("223.5.5.5", "443", 10)
        self.assertEqual(out["status"], "ok")
        self.assertAlmostEqual(out["ms"], 10.91)

    def test_jkapi_both_down_error(self):
        with mock.patch.object(cc, "request_follow",
                               side_effect=self._route(
                                   primary_exc=urllib.error.URLError("reset"))):
            out = cc.jkapi_check("223.5.5.5", "443", 10)
        self.assertEqual(out["status"], "error")

    def test_jkapi_429_no_failover(self):
        """429 系共享配额限流：直接返回，不耗镜像配额。"""
        seen = []

        def fake(url, headers, timeout, method="GET", data=None):
            seen.append(url)
            raise urllib.error.HTTPError(url, 429, "Too Many Requests", {}, io.BytesIO(b""))

        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.jkapi_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "rate_limited")
        self.assertEqual(len(seen), 1)
        self.assertNotIn("api.jkapi.com", seen[0])

    def test_jkping_primary_500_mirror_ok(self):
        with mock.patch.object(cc, "request_follow",
                               side_effect=self._route(
                                   primary_status=500, primary_body=b"err",
                                   mirror_body=self._PING_OK)):
            out = cc.jkping_check("223.5.5.5", "443", 10)
        self.assertEqual(out["status"], "ok")
        self.assertAlmostEqual(out["ms"], 12.65)
        self.assertEqual(out["level"], "icmp")


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

    def test_transport_failure_redacts_token_url(self):
        """R275：tcpping token 进 URL query，传输异常不得把 token/URL
        带入持久化 error 字段（_err 仅取类型名；防 china.json/CI 日志泄漏）。"""
        token = "SECRET-TOKEN-XYZ"
        boom = urllib.error.URLError(
            f"https://tcpping.cn/ping_api?url=1.2.3.4&port=443&token={token}")
        with mock.patch.object(cc, "request_follow", side_effect=boom):
            out = cc.tcpping_check("1.2.3.4", "443", token, 5)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error"], "URLError")
        self.assertNotIn(token, out["error"])
        self.assertNotIn("tcpping.cn", out["error"])


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

    def test_icmp_only_source_level_honest(self):
        """仅 ICMP 主机存活源（coffee/chinaz）确认时，level 如实标 icmp，
        不冒充 tcp（all_cn_http 消费方以此区分传输层证据）。"""
        sources = {
            "chinaz": {"status": "ok", "ok": True, "ms": 40,
                       "ok_nodes": 45, "nodes": 50, "ratio": 0.9,
                       "level": "icmp"},
            "coffee": {"status": "ok", "ok": True, "ms": 35,
                       "ok_nodes": 20, "nodes": 30, "ratio": 0.8,
                       "level": "icmp"},
        }
        mv = cc.merge_verdict(sources)
        self.assertEqual(mv["verdict"], "reachable")
        self.assertEqual(mv["level"], "icmp")
        # 混入 TCP 源 → 保守回落 tcp
        sources["tcptest"] = {"status": "ok", "ok": True, "ms": 30,
                           "ok_nodes": 12, "nodes": 12, "ratio": 1.0,
                           "level": "tcp"}
        self.assertEqual(cc.merge_verdict(sources)["level"], "tcp")

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

    def test_five_new_multi_sources_strong_reachable(self):
        """新增五源（boce/ipip/17ce/ping0/wansui）达标 → 独立判 reachable。"""
        for name in ("boce", "ipip", "17ce", "ping0", "wansui"):
            src = {"status": "ok", "ok": True, "ms": 50, "level": "tcp",
                   "ok_nodes": 9, "nodes": 10, "ratio": 0.9}
            self.assertEqual(
                cc.merge_verdict({name: src})["verdict"],
                "reachable", msg=f"{name} strong → reachable")

    def test_five_new_multi_sources_weak_uncertain(self):
        """新源弱确认（ok 但比率<阈值 或 残片）→ uncertain 不误判 reachable。"""
        for name in ("boce", "ipip", "17ce", "ping0", "wansui"):
            weak = {"status": "ok", "ok": True, "ms": 50, "level": "tcp",
                    "ok_nodes": 1, "nodes": 10, "ratio": 0.1}
            self.assertEqual(
                cc.merge_verdict({name: weak})["verdict"],
                "uncertain", msg=f"{name} weak → uncertain")

    def test_per_source_ratio_threshold_wired(self):
        """各多节点源成功率阈值常量必须真正接线（此前 ce98/biuping/boce/
        ipip/17ce/ping0/wansui 的 *_MIN_RATIO 定义了却未接入 strong_valid，
        调高任意常量都会被静默回退到 ITDOG_MIN_RATIO）。"""
        src = {"status": "ok", "ok": True, "ms": 60, "level": "tcp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        for name in ("ce98", "biuping", "boce", "ipip", "17ce", "ping0", "wansui"):
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
            {"boce": {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                      "nodes": 10, "ratio": 0.0},
             "check_host": {"status": "fail", "ok": False, "ms": None}},
            {"ipip": {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                      "nodes": 10, "ratio": 0.0},
             "17ce": {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                      "nodes": 10, "ratio": 0.0}},
            {"ping0": {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                       "nodes": 10, "ratio": 0.0},
             "xxapi": {"status": "fail", "ok": False, "ms": None}},
            {"wansui": {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                        "nodes": 10, "ratio": 0.0},
             "ipip": {"status": "fail", "ok": False, "ms": None, "ok_nodes": 0,
                      "nodes": 10, "ratio": 0.0}},
        ]
        for sources in cases:
            self.assertEqual(
                cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_ipip_check_parse_ok(self):
        """tools.ipip.net POST-JSON 多节点响应 → ok（可达）。"""
        payload = json.dumps({"nodes": [
            {"name": "北京电信", "delay": 12, "status": "ok"},
            {"name": "上海联通", "delay": 15, "status": "ok"},
            {"name": "广州移动", "delay": 20, "status": "ok"},
        ]}).encode()
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, payload)):
            out = cc.ipip_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 3)
        self.assertEqual(out["ms"], 12)
        self.assertEqual(out["level"], "tcp")

    def test_ipip_check_all_fail(self):
        payload = json.dumps({"nodes": [
            {"name": "北京电信", "delay": None, "status": "timeout"},
            {"name": "上海联通", "delay": None, "status": "timeout"},
        ]}).encode()
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, payload)):
            out = cc.ipip_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ok_nodes"], 0)

    def test_boce_check_parse_ok(self):
        """boce 壳页+建任务+轮询结果 → ok。"""
        shell = b'<html><meta name="csrf-token" content="tk123"></html>'
        probe = json.dumps({"task_id": "t1"}).encode()
        result = json.dumps({"nodes": [
            {"name": "北京电信", "delay": 12, "status": "ok"},
            {"name": "上海联通", "delay": 15, "status": "ok"},
            {"name": "广州移动", "delay": 0, "status": "fail"},
        ]}).encode()

        def fake(url, headers, timeout, method="GET", data=None):
            if url.endswith("/api/v1/probe") and method == "POST":
                self.assertEqual(headers.get("X-CSRF-Token"), "tk123")
                return 200, {}, probe
            if "/result" in url:
                return 200, {}, result
            return 200, {"Set-Cookie": "JSESSIONID=abc; Path=/"}, shell

        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.boce_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 2)
        self.assertEqual(out["ratio"], round(2 / 3, 3))

    def test_seventeen_check_parse_ok(self):
        """17ce 壳页+api.php tasks → ok。"""
        shell = b'<html><script>var token="tok_9"</script></html>'
        api = json.dumps({"tasks": [
            {"result": {"delay": 12}},
            {"result": {"delay": 15}},
            {"result": {"delay": 0}},
        ]}).encode()

        def fake(url, headers, timeout, method="GET", data=None):
            if "api.php" in url:
                return 200, {}, api
            return 200, {"Set-Cookie": "PHPSESSID=x; Path=/"}, shell

        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.seventeen_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 2)

    def test_ping0_check_captcha_fail_open(self):
        """ping0 遇验证码墙 → error（fail-open）。"""
        shell = b'<html><script src="https://challenges.cloudflare.com/turnstile"></script></html>'
        with mock.patch.object(cc, "request_follow", return_value=(200, {}, shell)):
            out = cc.ping0_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["ok"], False)

    def test_ping0_check_parse_ok(self):
        """ping0 免挑战路径 POST /api/probe → ok。"""
        shell = b"<html>ping0 tool</html>"
        probe = json.dumps({"nodes": [
            {"city": "北京", "delay": 12},
            {"city": "上海", "delay": 15},
        ]}).encode()

        def fake(url, headers, timeout, method="GET", data=None):
            if url.endswith("/api/probe"):
                return 200, {}, probe
            return 200, {}, shell

        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.ping0_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 2)

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


class TestJkpingMergeVerdict(unittest.TestCase):
    """CN-25：jkping 并入单节点交叉（single_ok/single_failed），与
    check_host/xxapi/jkapi 同权（任 2 ok → reachable，任 2 fail → unreachable）。"""

    def test_xxapi_jkping_double_ok_reachable(self):
        sources = {
            "xxapi": {"status": "ok", "ok": True, "ms": 43},
            "jkping": {"status": "ok", "ok": True, "ms": 12.7, "level": "icmp"},
        }
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["ms"], 12.7)

    def test_jkapi_jkping_double_ok_reachable(self):
        """同站双协议（TCP+ICMP）双 ok → reachable（主机+端口双层确认）。"""
        sources = {
            "jkapi": {"status": "ok", "ok": True, "ms": 11},
            "jkping": {"status": "ok", "ok": True, "ms": 12.7, "level": "icmp"},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "reachable")

    def test_jkping_alone_ok_uncertain(self):
        sources = {"jkping": {"status": "ok", "ok": True, "ms": 12.7,
                              "level": "icmp"}}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "uncertain")
        self.assertEqual(merged["level"], "icmp")  # 纯 ICMP 证据如实标注，不冒充 tcp

    def test_jkping_fail_plus_xxapi_fail_unreachable(self):
        sources = {
            "jkping": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_jkping_fail_alone_uncertain(self):
        sources = {
            "jkping": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_jkping_tcp_mix_level_tcp(self):
        """ICMP + TCP 混证 → level 回落 tcp（与 chinaz/tcptest 混证同规则）。"""
        sources = {
            "jkping": {"status": "ok", "ok": True, "ms": 12.7, "level": "icmp"},
            "tcptest": {"status": "ok", "ok": True, "ms": 60,
                        "ok_nodes": 8, "nodes": 10, "ratio": 0.8,
                        "level": "tcp"},
        }
        self.assertEqual(cc.merge_verdict(sources)["level"], "tcp")


class TestItdogPingSource(unittest.TestCase):
    """CN-26：itdog batch_ping（同站 ICMP，大节点池）→ 独立多节点源 itdog_ping。"""

    def test_normalize_ok_to_icmp_no_isp(self):
        """tcping 形记录（level=tcp + isp_ms）归一为 icmp 且剥离 isp_ms。"""
        out = cc._itdog_ping_normalize({
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
        self.assertEqual(cc._itdog_ping_normalize(src)["status"], "fail")

    def test_strong_reachable_level_icmp(self):
        sources = {"itdog_ping": {
            "status": "ok", "ok": True, "ms": 22.0, "level": "icmp",
            "ok_nodes": 20, "nodes": 24, "ratio": 0.83}}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "icmp")

    def test_weak_ratio_uncertain(self):
        sources = {"itdog_ping": {
            "status": "ok", "ok": True, "ms": 22.0, "level": "icmp",
            "ok_nodes": 1, "nodes": 24, "ratio": 0.04}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_fail_plus_single_fail_unreachable(self):
        sources = {
            "itdog_ping": {"status": "fail", "ok": False, "ms": None,
                           "ok_nodes": 0, "nodes": 24, "ratio": 0.0},
            "xxapi": {"status": "fail", "ok": False, "ms": None},
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

    def test_cn_fastest_ms_prefers_isp_min(self):
        """最快运营商视角：isp_ms 全局最小优先，噪声（≤2ms）剔除，无则回退。"""
        import common

        cases = {
            # itdog 三网：电信 45 / 联通 88 / 移动 120 → 取 45（最快运营商）
            "a:443#US": {"sources": {
                "xxapi": {"status": "ok", "ms": 60.0},
                "itdog": {"status": "ok", "ms": 45.0}},
                "isp_ms": {"中国电信": 45.0, "中国联通": 88.0, "中国移动": 120.0}},
            # 无 per-ISP 数据 → 回退 cn_display_ms（可信探测）
            "b:443#US": {"sources": {
                "xxapi": {"status": "ok", "ms": 70.0},
                "jkapi": {"status": "ok", "ms": 90.0}}},
            # isp_ms 全部 ≤2ms（噪声）→ 剔除后回退
            "c:443#US": {"sources": {"xxapi": {"status": "ok", "ms": 35.0}},
                         "isp_ms": {"中国电信": 1.0, "中国移动": 2.0}},
            # 仅一个运营商有值 → 取该值
            "d:443#US": {"sources": {"xxapi": {"status": "ok", "ms": 40.0}},
                         "isp_ms": {"中国联通": 88.0}},
            # 无任何读数 → None
            "e:443#US": {"sources": {"antping": {"status": "ok", "ms": 1.0}}},
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

    def test_fetch_captcha_page_fails_open(self):
        """CN-18：取节点页遇验证码墙 → ([], {}) 静默失败开放，不抛异常；
        上游 itdog_batch_run 按无节点处理（实证：受限出口被风控拦截）。"""
        html = ('<html><div class="clicaptcha">请完成验证</div></html>').encode()
        with mock.patch.object(ci, "request_follow",
                               return_value=(200, {}, html)):
            self.assertEqual(ci.itdog_fetch_nodes(2, "https://x/"), ([], {}))


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


class TestItdogCollect(unittest.TestCase):
    class _FakeWS:
        def __init__(self, frames):
            self._frames = list(frames)
            self.closed = False

        def send_text(self, payload):
            pass

        def read(self):
            if self._frames:
                return self._frames.pop(0)
            return "timeout", None

        def close(self):
            self.closed = True

    def _collect(self, frames, expected, timeout=1.0):
        with mock.patch.object(ci, "_WebSocket",
                               return_value=self._FakeWS(frames)):
            return ci.itdog_collect("task", expected, timeout)

    def test_evt_does_not_skip_tail_records(self):
        """进度事件绝不计入收齐判定：3 rec + 1 evt 交错，3 条节点记录必须收齐。"""
        frames = [
            ("rec", {"task_num": 1}),
            ("evt", {"progress": True}),
            ("rec", {"task_num": 2}),
            ("rec", {"task_num": 3}),
        ]
        out = self._collect(frames, expected=3)
        self.assertEqual([r.get("task_num") for r in out], [1, 2, 3])
        self.assertNotIn("progress", {m for r in out for m in r})

    def test_only_records_counted_toward_expected(self):
        frames = [("rec", {"task_num": 1}), ("evt", {"x": 1}),
                  ("rec", {"task_num": 2}), ("rec", {"task_num": 3}),
                  ("done", None)]
        out = self._collect(frames, expected=2)
        self.assertEqual([r.get("task_num") for r in out], [1, 2])

    def test_done_breaks_early(self):
        out = self._collect([("rec", {"task_num": 1}), ("done", None)], expected=9)
        self.assertEqual(len(out), 1)

    def test_timeout_returns_partial(self):
        out = self._collect([("rec", {"task_num": 1})], expected=5, timeout=0.05)
        self.assertEqual(len(out), 1)


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
        ws = ci._WebSocket.__new__(ci._WebSocket)
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

    def test_isp_ms_per_isP(self):
        node_isp = {"dx": "中国电信", "lt": "中国联通", "yd": "中国移动"}
        records = [
            {"task_num": 1, "node_id": "dx", "http_code": 0, "connect_time": 0.030},
            {"task_num": 1, "node_id": "dx2", "http_code": 0, "connect_time": 0.040},
            {"task_num": 1, "node_id": "lt", "http_code": 200, "connect_time": 0.120},
            {"task_num": 1, "node_id": "yd", "http_code": 0, "connect_time": 0.080},
        ]
        agg = ci.itdog_aggregate(records, 1, node_isp)
        self.assertEqual(agg[1]["isp_ms"], {"中国电信": 30.0, "中国联通": 120.0,
                                            "中国移动": 80.0})
        # 全局 ms 仍为全部节点最小值
        self.assertEqual(agg[1]["ms"], 30.0)

    def test_isp_ms_unknown_nodeid_falls_back_to_name(self):
        node_isp = {"dx": "中国电信"}
        records = [
            # node_id 回声不一致（不在采样映射内），但 node_name 带运营商关键词
            {"task_num": 1, "node_id": "zz",
             "node_name": "湖北十堰-中国电信", "http_code": 0, "connect_time": 0.025},
            {"task_num": 1, "node_id": "lt", "node_name": "山东济南-联通",
             "http_code": 0, "connect_time": 0.130},
        ]
        agg = ci.itdog_aggregate(records, 1, node_isp)
        self.assertEqual(
            agg[1]["isp_ms"], {"中国电信": 25.0, "中国联通": 130.0}
        )
        self.assertEqual(agg[1]["ms"], 25.0)

    def test_isp_ms_empty_without_strip(self):
        records = [
            {"task_num": 1, "node_id": "x", "http_code": 200, "connect_time": 0.020},
        ]
        agg = ci.itdog_aggregate(records, 1)
        self.assertEqual(agg[1]["status"], "ok")
        self.assertEqual(agg[1]["isp_ms"], {})

    def test_isp_ms_tcping_shape(self):
        """CN-07：batch_tcping 降级通道（result 毫秒字符串、无 http_code）
        同样经 node_isp 映射产出 isp_ms——双通道运营商视角不断档。"""
        node_isp = {"dx": "中国电信", "yd": "中国移动"}
        records = [
            {"task_num": 1, "node_id": "dx", "result": "33",
             "address": "Anycast/x"},
            {"task_num": 1, "node_id": "yd", "result": "77",
             "address": "Anycast/x"},
            {"task_num": 1, "node_id": "zz", "result": "-1",
             "address": "Anycast/x"},
        ]
        agg = ci.itdog_aggregate(records, 1, node_isp)
        self.assertEqual(agg[1]["status"], "ok")
        self.assertEqual(agg[1]["level"], "tcp")
        self.assertEqual(
            agg[1]["isp_ms"], {"中国电信": 33.0, "中国移动": 77.0})


class TestMergeIspMs(unittest.TestCase):
    def test_merge_across_sources(self):
        entries = {
            "a:443#US": {"sources": {
                "itdog": {"isp_ms": {"中国电信": 45.0, "中国联通": 88.0}},
                "xxapi": {"ms": 60.0},
                "tcptest": {"isp_ms": {"中国电信": 55.0}},
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
        """CN-08：itdog/tcptest/ce98/biuping 四源 isp_ms 跨源取最小
        （词表由各生产侧保证，合并只过滤非正数值）。"""
        entries = {
            "a:443#US": {"sources": {
                "itdog": {"isp_ms": {"中国电信": 45.0, "中国联通": 88.0}},
                "tcptest": {"isp_ms": {"中国电信": 20.0, "中国移动": 50.0}},
                "ce98": {"isp_ms": {"中国联通": 9.0}},
                "biuping": {"isp_ms": {"中国移动": 60.0}},
            }},
        }
        cc.merge_isp_ms(entries)
        self.assertEqual(
            entries["a:443#US"]["isp_ms"],
            {"中国电信": 20.0, "中国联通": 9.0, "中国移动": 50.0})

    def test_negative_ms_ignored(self):
        entries = {"a:443#US": {"sources": {"itdog": {"isp_ms": {"电信": -1.0}}}}}
        cc.merge_isp_ms(entries)
        self.assertNotIn("isp_ms", entries["a:443#US"])


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

    def test_pingloc_sse_never_ending_is_capped_by_wallclock(self):
        # 上游只回 200 头、随后持续发心跳而不 EOF —— 若 read 循环无整体
        # 墙钟上限，worker 会永久挂住令 fut.result() 无限阻塞整条管道。
        heartbeat = b"event: comment\ndata: heartbeat\n\n"
        reads = {"n": 0}

        class _HungCtx:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                reads["n"] += 1
                return heartbeat  # 永不返回 b"" → 旧 while True 无限循环

        cc_time = cc.time  # 真实模块对象（含 monotonic）

        def _clock():
            # 首调返回 0（deadline=0+timeout+20），再调 +10 → 第二次 while 条件越界
            _clock.t += 10.0
            return _clock.t

        _clock.t = -10.0

        def fake(url, headers, timeout, method="GET", data=None):
            if url.endswith("/node/items"):
                return 200, {}, json.dumps({"data": [{"id": "n1"}]}).encode()
            return 200, {}, json.dumps({"data": {"token": "task_abc"}}).encode()

        with mock.patch.object(cc, "request_follow", side_effect=fake), \
             mock.patch.object(cc.urllib.request, "urlopen", return_value=_HungCtx()), \
             mock.patch.object(cc_time, "monotonic", side_effect=_clock):
            out = cc.pingloc_check("1.2.3.4", 10, method="ping")

        self.assertEqual(reads["n"], 2)  # 第二轮 while 墙钟越界即制动
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ok_nodes"], 0)

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

        with mock.patch.object(cc, "_tcpingcn_session_cookie", return_value="c=1"), \
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
        with mock.patch.object(cc, "_tcpingcn_session_cookie", return_value=""), \
              mock.patch.object(cc, "_tcpingcn_get", return_value={"d": 0}):
            out = cc.tcpingcn_check("1.2.3.4", "80", 10)
        self.assertEqual(out["status"], "error")

    def test_tcpingcn_pow_valueerror_kept_inline(self):
        """远端 d 非数字（int() 抛 ValueError）→ 按探测失败处理，不逃逸整轮。"""
        with mock.patch.object(cc, "_tcpingcn_session_cookie", return_value=""), \
              mock.patch.object(cc, "_tcpingcn_get", return_value={"r": "r", "s": "s", "ts": 1, "d": "abc"}), \
             mock.patch.object(cc, "_tcpcn_yc", return_value="p"), \
             mock.patch.object(cc, "_tcpcn_bc", return_value="salt"), \
             mock.patch.object(cc, "_tcpcn_pow_solve",
                               side_effect=ValueError("invalid literal for int()")):
            out = cc.tcpingcn_check("1.2.3.4", "80", 10)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error"], "ValueError")

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

    def test_check_isp_ms_per_carrier(self):
        """CN-04：tcptest 以 uuid 关联节点运营商，按 itdog 口径归一
        出 isp_ms（海外/未知丢弃）；无映射时缺省该键。"""
        results = json.dumps({"results": [
            {"success": True, "node_uuid": "u-telecom",
             "data": {"connected": True, "avg_ms": 30.0}},
            {"success": True, "node_uuid": "u-telecom2",
             "data": {"connected": True, "avg_ms": 20.0}},
            {"success": True, "node_uuid": "u-mobile",
             "data": {"connected": True, "avg_ms": 50.0}},
            {"success": True, "node_uuid": "u-oversea",
             "data": {"connected": True, "avg_ms": 5.0}},
            {"success": True, "node_uuid": "u-unknown",
             "data": {"connected": True, "avg_ms": 7.0}},
            {"success": False, "node_uuid": "u-unicom",
             "data": {"connected": False}},
        ]}).encode()
        states = [json.dumps({"id": "t1"}).encode(),
                  json.dumps({"state": "succeeded"}).encode(), results]

        def fake(url, headers, timeout, method="GET", data=None):
            return 200, {}, states.pop(0)
        operators = {"u-telecom": "电信", "u-telecom2": "电信",
                     "u-mobile": "移动", "u-oversea": "海外"}
        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.tcptest_check(
                "1.2.3.4", "443", 10, ["u-telecom"], operators)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(
            out["isp_ms"], {"中国电信": 20.0, "中国移动": 50.0})

    def test_check_no_isp_ms_without_operators(self):
        results = json.dumps({"results": [
            {"success": True, "node_uuid": "u1",
             "data": {"connected": True, "avg_ms": 12.5}},
        ]}).encode()
        states = [json.dumps({"id": "t1"}).encode(),
                  json.dumps({"state": "succeeded"}).encode(), results]

        def fake(url, headers, timeout, method="GET", data=None):
            return 200, {}, states.pop(0)
        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.tcptest_check("1.2.3.4", "443", 10, ["u1"])
        self.assertEqual(out["status"], "ok")
        self.assertNotIn("isp_ms", out)


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
        ) as mch, mock.patch.object(cc, "jkapi_check", side_effect=fake_jkapi), \
                mock.patch.object(cc, "jkping_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "xxping_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}):
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
        ) as mch, mock.patch.object(cc, "jkapi_check", side_effect=fake_jkapi), \
                mock.patch.object(cc, "jkping_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "xxping_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}):
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
        ) as mch, mock.patch.object(cc, "jkapi_check", side_effect=fake_jkapi), \
                mock.patch.object(cc, "jkping_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "xxping_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual([c.args[0] for c in mch.call_args_list], ["4.4.4.4"])
        self.assertEqual(set(reachable), {"4.4.4.4:80#US"})

    def test_jkping_second_confirm_skips_check_host(self):
        """CN-25：免额三源中任 2 ok 即双确认——xxapi error + jkapi ok +
        jkping ok → 稀配额 check-host 直接让位（配额门控按计数泛化）。"""
        import unittest.mock as mock

        items = [("6.6.6.6:80#US", "6.6.6.6:80#US", "6.6.6.6", "80", "US")]

        def fake_xxapi(ip, port, timeout):
            return {"status": "error", "ok": False, "ms": None, "error": "http 500"}

        def fake_check_host(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 1.0}

        with mock.patch.object(cc, "xxapi_check", side_effect=fake_xxapi), mock.patch.object(
            cc, "check_host_check", side_effect=fake_check_host
        ) as mch, mock.patch.object(cc, "jkapi_check",
                                    return_value={"status": "ok", "ok": True,
                                                  "ms": 11.0}), \
                mock.patch.object(cc, "jkping_check",
                                  return_value={"status": "ok", "ok": True,
                                                "ms": 12.7, "level": "icmp"}), \
                mock.patch.object(cc, "xxping_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual(mch.call_args_list, [])
        self.assertEqual(set(reachable), {"6.6.6.6:80#US"})

    def test_xxping_second_confirm_skips_check_host(self):
        """CN-29：免额四源中任 2 ok 即双确认——jkapi ok + xxping ok
        （余者 error）→ 稀配额 check-host 直接让位。"""
        import unittest.mock as mock

        items = [("7.7.7.7:80#US", "7.7.7.7:80#US", "7.7.7.7", "80", "US")]

        def fake_xxapi(ip, port, timeout):
            return {"status": "error", "ok": False, "ms": None, "error": "http 500"}

        def fake_check_host(ip, port, limiter, timeout, api_key):
            return {"status": "ok", "ok": True, "ms": 1.0}

        with mock.patch.object(cc, "xxapi_check", side_effect=fake_xxapi), mock.patch.object(
            cc, "check_host_check", side_effect=fake_check_host
        ) as mch, mock.patch.object(cc, "jkapi_check",
                                    return_value={"status": "ok", "ok": True,
                                                  "ms": 11.0}), \
                mock.patch.object(cc, "jkping_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "xxping_check",
                                  return_value={"status": "ok", "ok": True,
                                                "ms": 42.1, "level": "icmp"}):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        self.assertEqual(mch.call_args_list, [])
        self.assertEqual(set(reachable), {"7.7.7.7:80#US"})

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
                                                  "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "jkping_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "xxping_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "checkhost_http_check",
                                  return_value={"status": "error", "ok": False,
                                                "ms": None, "error": "http 500"}), \
                mock.patch.object(cc, "checkhost_ping_check",
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
            mock.patch.object(cc, "tcptest_fetch_nodes",
                              return_value=[{"uuid": "u1", "operator": "ct",
                                             "enabled": True,
                                             "runtime_state": "online"}]),
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
            mock.patch.object(cc, "jkping_check", side_effect=self._boom),
            mock.patch.object(cc, "xxping_check", side_effect=self._boom),
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
                     "chinaz", "pingpe", "check_host", "jkping", "xxping"):
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
              mock.patch.object(cc, "jkping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "xxping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
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
                  mock.patch.object(cc, "jkping_check",
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
              mock.patch.object(cc, "jkping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "xxping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "check_host_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "q"}), \
              mock.patch.object(cc, "itdog_batch_run", side_effect=fake_itdog) as mib:
            entries, _, _ = cc.run_measurements([a, b], self._args())

        calls = [c for c in mib.call_args_list]
        # batch_http + batch_tcping 兜底 + batch_ping 兜底（CN-26 新增）
        self.assertEqual(len(calls), 3)
        page_urls = [c.kwargs.get("page_url") for c in calls]
        self.assertIn(cc.ITDOG_TCPING_URL, page_urls)
        self.assertIn(cc.ITDOG_PING_URL, page_urls)
        fallback = next(c for c in calls if c.kwargs.get("page_url") == cc.ITDOG_TCPING_URL)
        self.assertEqual([key for _, key, _, _, _ in fallback.args[0]],
                         ["10.7.0.1:80#US"])
        ping_call = next(c for c in calls if c.kwargs.get("page_url") == cc.ITDOG_PING_URL)
        self.assertEqual([key for _, key, _, _, _ in ping_call.args[0]],
                         ["10.7.0.1:80#US"])
        # ping 结果归一落地：level=icmp、无 isp_ms
        ping_res = entries["10.7.0.1:80#US"]["sources"]["itdog_ping"]
        self.assertEqual(ping_res["status"], "error")  # 替身回 error，原样落地


class TestAa1pingSource(unittest.TestCase):
    """CN-27：ping.aa1.cn WS TCPing 适配器单测（mock _WebSocket，不触网）。"""

    class _FakeWS:
        def __init__(self, frames):
            self._frames = list(frames)
            self.sent = []
            self.closed = False

        def settimeout(self, t):
            pass

        def send_text(self, payload):
            self.sent.append(payload)

        def read(self):
            if self._frames:
                return self._frames.pop(0)
            return "timeout", None

        def close(self):
            self.closed = True

    def _cities(self, n=3):
        return [{"city": f"城{i}", "operator": "电信"} for i in range(n)]

    def _res(self, city, op, delay):
        return {"province": "省", "city": city, "operator": op,
                "tcping_delay": delay, "packet_test": 0,
                "ip_address": "1.2.3.4:443", "geo_location": "中国"}

    def _run(self, frames):
        with mock.patch.object(cc, "_WebSocket",
                               return_value=self._FakeWS(frames)):
            return cc.aa1ping_check("1.2.3.4", "443", 10)

    def test_all_ok_with_isp_ms(self):
        frames = [
            ("evt", {"status": "success",
                     "city_list": self._cities(3), "jc_Count": 3}),
            ("evt", {"status": "success", "results": [
                self._res("城0", "电信", 5.0),
                self._res("城1", "联通", 9.0),
                self._res("城2", "移动", 12.0)]}),
        ]
        out = self._run(frames)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 3)
        self.assertEqual(out["nodes"], 3)
        self.assertEqual(out["ms"], 5.0)
        self.assertEqual(out["level"], "tcp")
        self.assertEqual(out["ratio"], 1.0)
        self.assertEqual(out["isp_ms"],
                         {"中国电信": 5.0, "中国联通": 9.0, "中国移动": 12.0})

    def test_unknown_operator_dropped_from_isp(self):
        frames = [
            ("evt", {"status": "success",
                     "city_list": self._cities(2), "jc_Count": 2}),
            ("evt", {"status": "success", "results": [
                self._res("城0", "电信", 5.0),
                self._res("城1", "多线", 4.0)]}),
        ]
        out = self._run(frames)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["isp_ms"], {"中国电信": 5.0})

    def test_all_fail(self):
        frames = [
            ("evt", {"status": "success",
                     "city_list": self._cities(2), "jc_Count": 2}),
            ("evt", {"status": "success", "results": [
                dict(self._res("城0", "电信", 0.0), packet_test=1),
                dict(self._res("城1", "联通", 0.0), packet_test=1)]}),
        ]
        out = self._run(frames)
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ok_nodes"], 0)
        self.assertEqual(out["ratio"], 0.0)

    def test_duplicate_city_deduped(self):
        frames = [
            ("evt", {"status": "success",
                     "city_list": self._cities(1), "jc_Count": 1}),
            ("evt", {"status": "success", "results": [
                self._res("城0", "电信", 5.0)]}),
            ("evt", {"status": "success", "results": [
                self._res("城0", "电信", 6.0)]}),
        ]
        out = self._run(frames)
        self.assertEqual(out["ok_nodes"], 1)
        self.assertEqual(out["nodes"], 1)

    def test_ws_connect_fail(self):
        with mock.patch.object(cc, "_WebSocket",
                               side_effect=RuntimeError("boom")):
            out = cc.aa1ping_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "error")
        self.assertFalse(out["ok"])

    def test_sends_port_honoring_target(self):
        """domain 必须携带真实端口（逐端口实测，活体已证回显 ip:port）。"""
        fake = self._FakeWS([
            ("evt", {"status": "success",
                     "city_list": self._cities(1), "jc_Count": 1}),
            ("evt", {"status": "success", "results": [
                self._res("城0", "电信", 5.0)]}),
        ])
        with mock.patch.object(cc, "_WebSocket", return_value=fake):
            cc.aa1ping_check("1.2.3.4", "8443", 10)
        sent = json.loads(fake.sent[0])
        self.assertEqual(sent["domain"], "1.2.3.4:8443")
        self.assertEqual(sent["lines"], cc.AA1PING_LINES)


class TestBiupingPingSource(unittest.TestCase):
    """CN-34：biuping_ping（同站 ICMP，复用 port="" 分支）。"""

    def test_wrapper_ignores_port_strips_isp(self):
        ret = {"status": "ok", "ok": True, "ms": 7.5, "level": "icmp",
               "ok_nodes": 39, "nodes": 39, "ratio": 1.0,
               "isp_ms": {"中国电信": 7.5}}
        with mock.patch.object(cc, "biuping_check",
                               return_value=dict(ret)) as m:
            out = cc.biuping_ping_check("1.2.3.4", "443", 10)
        m.assert_called_once_with("1.2.3.4", "", 10)
        self.assertEqual(out["level"], "icmp")
        self.assertNotIn("isp_ms", out)
        self.assertEqual(out["ms"], 7.5)

    def test_strong_reachable(self):
        sources = {"biuping_ping": {
            "status": "ok", "ok": True, "ms": 7.5, "level": "icmp",
            "ok_nodes": 39, "nodes": 39, "ratio": 1.0}}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "icmp")

    def test_weak_ratio_uncertain(self):
        sources = {"biuping_ping": {
            "status": "ok", "ok": True, "ms": 7.5, "level": "icmp",
            "ok_nodes": 1, "nodes": 39, "ratio": 0.026}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_fail_plus_single_fail_unreachable(self):
        sources = {
            "biuping_ping": {"status": "fail", "ok": False, "ms": None,
                             "ok_nodes": 0, "nodes": 39, "ratio": 0.0},
            "jkapi": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 7.5, "level": "icmp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(
            cc.merge_verdict({"biuping_ping": dict(src)})["verdict"],
            "reachable")
        old = cc._SOURCE_MIN_RATIO["biuping_ping"]
        cc._SOURCE_MIN_RATIO["biuping_ping"] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({"biuping_ping": dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO["biuping_ping"] = old

    def test_raw_slot_dispatch(self):
        cands = [("1.2.3.4:443#US line", "1.2.3.4:443#US",
                  "1.2.3.4", "443", "US")]
        entries: dict = {"1.2.3.4:443#US": {}}
        with mock.patch.object(
                cc, "biuping_ping_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_raw_slots(cands, entries, 5, "biuping_ping", 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(
            entries["1.2.3.4:443#US"]["biuping_ping"]["status"], "ok")


class TestAntpingPingSource(unittest.TestCase):
    """CN-28：antping_ping（同站 ICMP，复用 code=3 分支）。"""

    def test_wrapper_forces_icmp_path(self):
        """包装只转调 code=3：port 被忽略（仅槽位接口保留），target 走 ip。"""
        ret = {"status": "ok", "ok": True, "ms": 1, "level": "icmp",
               "ok_nodes": 178, "nodes": 179, "ratio": 0.994}
        with mock.patch.object(cc, "antping_check",
                               return_value=dict(ret)) as m:
            out = cc.antping_ping_check("1.2.3.4", "443", 10)
        m.assert_called_once_with("1.2.3.4", "", 10)
        self.assertEqual(out, ret)
        self.assertEqual(out["level"], "icmp")

    def test_no_isp_ms_from_wrapper(self):
        """节点帧无运营商归一，包装不得伪造 isp_ms。"""
        ret = {"status": "ok", "ok": True, "ms": 1, "level": "icmp",
               "ok_nodes": 150, "nodes": 160, "ratio": 0.94}
        with mock.patch.object(cc, "antping_check", return_value=dict(ret)):
            out = cc.antping_ping_check("1.2.3.4", "443", 10)
        self.assertNotIn("isp_ms", out)

    def test_strong_reachable(self):
        sources = {"antping_ping": {
            "status": "ok", "ok": True, "ms": 1, "level": "icmp",
            "ok_nodes": 178, "nodes": 179, "ratio": 0.994}}
        merged = cc.merge_verdict(sources)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "icmp")

    def test_weak_ratio_uncertain(self):
        sources = {"antping_ping": {
            "status": "ok", "ok": True, "ms": 1, "level": "icmp",
            "ok_nodes": 1, "nodes": 179, "ratio": 0.006}}
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "uncertain")

    def test_fail_plus_single_fail_unreachable(self):
        sources = {
            "antping_ping": {"status": "fail", "ok": False, "ms": None,
                             "ok_nodes": 0, "nodes": 186, "ratio": 0.0},
            "jkapi": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 1, "level": "icmp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(cc.merge_verdict({"antping_ping": dict(src)})["verdict"],
                         "reachable")
        old = cc._SOURCE_MIN_RATIO["antping_ping"]
        cc._SOURCE_MIN_RATIO["antping_ping"] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({"antping_ping": dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO["antping_ping"] = old

    def test_ws_slot_dispatch(self):
        """通用 WS slot 须能派发 antping_ping 且只写本源键。"""
        cands = [("1.2.3.4:443#US line", "1.2.3.4:443#US",
                  "1.2.3.4", "443", "US")]
        entries: dict = {"1.2.3.4:443#US": {}}
        with mock.patch.object(
                cc, "antping_ping_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_ws_source_slots(cands, entries, 5, "antping_ping", 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(
            entries["1.2.3.4:443#US"]["antping_ping"]["status"], "ok")


class TestTcptestHttpSource(unittest.TestCase):
    """CN-35：tcptest type=http 同站应用层（mock，不触网）。"""

    def _run(self, results):
        bodies = []

        def fake(url, headers, timeout, method="GET", data=None):
            if method == "POST" and url.endswith("/tasks"):
                bodies.append(json.loads(data.decode()))
                return 201, {}, json.dumps({"id": "t1"}).encode()
            if "/results" in url:
                return 200, {}, json.dumps({"results": results}).encode()
            return 200, {}, json.dumps({"state": "succeeded"}).encode()

        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.tcptest_check("1.2.3.4", "443", 10, ["u1", "u2"],
                                   {"u1": "电信", "u2": "联通"},
                                   probe_type="http")
        return out, bodies

    def _ok_row(self, uuid="u1", status=400, ms=15.76):
        return {"node_uuid": uuid, "success": True,
                "data": {"status": status, "connect_ms": ms,
                         "first_byte_ms": ms, "resolved_ip": "1.2.3.4"}}

    def test_http_ok_level_http_with_isp(self):
        out, bodies = self._run(
            [self._ok_row("u1", 400, 15.76),
             self._ok_row("u2", 404, 28.5)])
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ms"], 15.8)
        self.assertEqual(out["level"], "http")
        self.assertEqual(out["ok_nodes"], 2)
        # HTTP 与 TCP 同口径产出 isp_ms（itdog 一致；ICMP 才豁免）
        self.assertEqual(out["isp_ms"],
                         {"中国电信": 15.8, "中国联通": 28.5})
        create = next(b for b in bodies if b.get("type") == "http")
        self.assertEqual(create["target"], "http://1.2.3.4:443/")

    def test_http_all_fail(self):
        bad = {"node_uuid": "u1", "success": False, "data": {},
               "error": "timeout"}
        out, _ = self._run([bad])
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ratio"], 0.0)

    def test_http_code_zero_not_ok(self):
        """无 HTTP 应答（status=0）不得冒充应用层确认。"""
        row = self._ok_row("u1", 0, 15.76)
        out, _ = self._run([row])
        self.assertEqual(out["status"], "fail")

    def test_merge_strong_weak_fail(self):
        strong = {"status": "ok", "ok": True, "ms": 15.8, "level": "http",
                  "ok_nodes": 8, "nodes": 10, "ratio": 0.8}
        merged = cc.merge_verdict({"tcptest_http": strong})
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "http")
        weak = dict(strong, ok_nodes=1, nodes=10, ratio=0.1)
        self.assertEqual(cc.merge_verdict(
            {"tcptest_http": weak})["verdict"], "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None,
                "ok_nodes": 0, "nodes": 10, "ratio": 0.0}
        self.assertEqual(cc.merge_verdict(
            {"tcptest_http": fail,
             "xxapi": {"status": "fail", "ok": False,
                       "ms": None}})["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 15.8, "level": "http",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(
            cc.merge_verdict({"tcptest_http": dict(src)})["verdict"],
            "reachable")
        old = cc._SOURCE_MIN_RATIO["tcptest_http"]
        cc._SOURCE_MIN_RATIO["tcptest_http"] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({"tcptest_http": dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO["tcptest_http"] = old

    def test_phase_runs_http_only(self):
        """TCP/ping 0 ＋ http 1 → 只跑 http 通道。"""
        from types import SimpleNamespace

        args = SimpleNamespace(
            skip_itdog=True, skip_itdog_tcping=True, pingpe_limit=0,
            workers=4, timeout=5, api_key="", tcpping_token="",
            tcptest_limit=0, tcptest_concurrency=2, tcptest_nodes=2,
            tcptest_ping_limit=0, tcptest_ping_concurrency=2,
            tcptest_http_limit=1, tcptest_http_concurrency=2,
            coffee_limit=0, pingloc_limit=0, antping_limit=0,
            tcpingcn_limit=0, chinaz_limit=0, ce98_limit=0,
            biuping_limit=0, boce_limit=0, ipip_limit=0,
            antping_ping_limit=0, tcpingcn_ping_limit=0,
            aa1ping_limit=0, aa1ping_concurrency=2,
            biuping_ping_limit=0, biuping_ping_concurrency=2,
            **{"17ce_limit": 0, "ping0_limit": 0, "wansui_limit": 0})
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

        with mock.patch.object(cc, "tcptest_fetch_nodes",
                               return_value=[{"uuid": "u1", "operator": "ct",
                                              "enabled": True,
                                              "runtime_state": "online"}]), \
              mock.patch.object(cc, "tcptest_check", side_effect=fake_check), \
              mock.patch.object(cc, "xxapi_check", side_effect=fake_l2), \
              mock.patch.object(cc, "xxping_check", side_effect=fake_l2), \
              mock.patch.object(cc, "jkapi_check", side_effect=fake_l2), \
              mock.patch.object(cc, "jkping_check", side_effect=fake_l2), \
              mock.patch.object(cc, "check_host_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "checkhost_ping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "checkhost_http_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}):
            entries, reachable, _ = cc.run_measurements([item], args)
        self.assertEqual(seen_types, ["http"])
        self.assertIn("tcptest_http", entries["10.9.9.9:443#US"]["sources"])
        self.assertNotIn("tcptest", entries["10.9.9.9:443#US"]["sources"])
        self.assertNotIn("tcptest_ping", entries["10.9.9.9:443#US"]["sources"])
        self.assertIn("10.9.9.9:443#US", reachable)


class TestTcptestPingSource(unittest.TestCase):
    """CN-33：tcptest type=ping 同站 ICMP（mock request_follow，不触网）。"""

    def _ping_result(self, ok=True, ms=14.8, uuid="u1"):
        data = {"avg_ms": ms, "latest_ms": ms, "packets_received": 1,
                "packet_loss_percent": 0.0} if ok else {"avg_ms": 0}
        return {"node_uuid": uuid, "success": ok, "data": data}

    def _run(self, results):
        bodies = []

        def fake(url, headers, timeout, method="GET", data=None):
            if method == "POST" and url.endswith("/tasks"):
                bodies.append(json.loads(data.decode()))
                return 201, {}, json.dumps({"id": "t1"}).encode()
            if "/results" in url:
                return 200, {}, json.dumps({"results": results}).encode()
            return 200, {}, json.dumps({"state": "succeeded"}).encode()

        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.tcptest_check("1.2.3.4", "443", 10, ["u1", "u2"],
                                   {"u1": "电信", "u2": "联通"},
                                   probe_type="ping")
        return out, bodies

    def test_ping_ok_level_icmp_no_isp(self):
        out, bodies = self._run(
            [self._ping_result(True, 14.8, "u1"),
             self._ping_result(True, 27.3, "u2")])
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ms"], 14.8)
        self.assertEqual(out["level"], "icmp")
        self.assertEqual(out["ok_nodes"], 2)
        # ICMP 不产 isp_ms（与 chinaz 等同口径），即便有 operators 映射
        self.assertNotIn("isp_ms", out)
        # ping 目标为裸 IP（无端口概念）
        create = next(b for b in bodies if b.get("type") == "ping")
        self.assertEqual(create["target"], "1.2.3.4")

    def test_ping_all_fail(self):
        out, _ = self._run(
            [self._ping_result(False, 0, "u1"),
             self._ping_result(False, 0, "u2")])
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ratio"], 0.0)

    def test_tcp_default_unchanged(self):
        """默认仍走 TCP（connected 语义＋isp_ms），防重构回归。"""
        res = {"node_uuid": "u1", "success": True,
               "data": {"connected": True, "avg_ms": 60.0}}

        def fake(url, headers, timeout, method="GET", data=None):
            if method == "POST" and url.endswith("/tasks"):
                return 201, {}, json.dumps({"id": "t1"}).encode()
            if "/results" in url:
                return 200, {}, json.dumps({"results": [res]}).encode()
            return 200, {}, json.dumps({"state": "succeeded"}).encode()

        with mock.patch.object(cc, "request_follow", side_effect=fake):
            out = cc.tcptest_check("1.2.3.4", "443", 10, ["u1"],
                                   {"u1": "电信"})
        self.assertEqual(out["level"], "tcp")
        self.assertEqual(out["isp_ms"], {"中国电信": 60.0})

    def test_merge_strong_weak_fail(self):
        strong = {"status": "ok", "ok": True, "ms": 15.0, "level": "icmp",
                  "ok_nodes": 8, "nodes": 10, "ratio": 0.8}
        self.assertEqual(cc.merge_verdict(
            {"tcptest_ping": strong})["verdict"], "reachable")
        self.assertEqual(cc.merge_verdict(
            {"tcptest_ping": strong})["level"], "icmp")
        weak = dict(strong, ok_nodes=1, nodes=10, ratio=0.1)
        self.assertEqual(cc.merge_verdict(
            {"tcptest_ping": weak})["verdict"], "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None,
                "ok_nodes": 0, "nodes": 10, "ratio": 0.0}
        self.assertEqual(cc.merge_verdict(
            {"tcptest_ping": fail,
             "xxapi": {"status": "fail", "ok": False,
                       "ms": None}})["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 15.0, "level": "icmp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(
            cc.merge_verdict({"tcptest_ping": dict(src)})["verdict"],
            "reachable")
        old = cc._SOURCE_MIN_RATIO["tcptest_ping"]
        cc._SOURCE_MIN_RATIO["tcptest_ping"] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({"tcptest_ping": dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO["tcptest_ping"] = old

    def test_phase_runs_on_ping_limit_only(self):
        """TCP 0 ＋ ping 1 → 只跑 ping（节点复用同一采样）。"""
        from types import SimpleNamespace

        args = SimpleNamespace(
            skip_itdog=True, skip_itdog_tcping=True, pingpe_limit=0,
            workers=4, timeout=5, api_key="", tcpping_token="",
            tcptest_limit=0, tcptest_concurrency=2, tcptest_nodes=2,
            tcptest_ping_limit=1, tcptest_ping_concurrency=2,
            coffee_limit=0, pingloc_limit=0, antping_limit=0,
            tcpingcn_limit=0, chinaz_limit=0, ce98_limit=0,
            biuping_limit=0, boce_limit=0, ipip_limit=0,
            antping_ping_limit=0, tcpingcn_ping_limit=0,
            aa1ping_limit=0, aa1ping_concurrency=2,
            **{"17ce_limit": 0, "ping0_limit": 0, "wansui_limit": 0})
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

        with mock.patch.object(cc, "tcptest_fetch_nodes",
                               return_value=[{"uuid": "u1", "operator": "ct",
                                              "enabled": True,
                                              "runtime_state": "online"}]), \
              mock.patch.object(cc, "tcptest_check", side_effect=fake_check), \
              mock.patch.object(cc, "xxapi_check", side_effect=fake_l2), \
              mock.patch.object(cc, "xxping_check", side_effect=fake_l2), \
              mock.patch.object(cc, "jkapi_check", side_effect=fake_l2), \
              mock.patch.object(cc, "jkping_check", side_effect=fake_l2), \
              mock.patch.object(cc, "check_host_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "checkhost_ping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}), \
              mock.patch.object(cc, "checkhost_http_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "x"}):
            entries, reachable, _ = cc.run_measurements([item], args)
        self.assertEqual(seen_types, ["ping"])
        self.assertIn("tcptest_ping", entries["10.9.9.9:443#US"]["sources"])
        self.assertNotIn("tcptest", entries["10.9.9.9:443#US"]["sources"])
        self.assertIn("10.9.9.9:443#US", reachable)


class TestAa1pingMergeVerdict(unittest.TestCase):
    """CN-27：aa1ping 并入多节点合成判定。"""

    def _ok(self, delay=30.0, nodes=28, ratio=1.0, isp=None):
        src = {"status": "ok", "ok": True, "ms": delay, "level": "tcp",
               "ok_nodes": nodes, "nodes": nodes, "ratio": ratio}
        if isp is not None:
            src["isp_ms"] = isp
        return src

    def test_strong_reachable(self):
        self.assertEqual(
            cc.merge_verdict({"aa1ping": self._ok()})["verdict"], "reachable")

    def test_weak_ratio_uncertain(self):
        src = self._ok(nodes=28, ratio=0.04)
        src["ok_nodes"] = 1
        self.assertEqual(
            cc.merge_verdict({"aa1ping": src})["verdict"], "uncertain")

    def test_degenerate_sample_not_strong(self):
        src = self._ok(nodes=1, ratio=1.0)
        src["ok_nodes"] = 1
        self.assertEqual(
            cc.merge_verdict({"aa1ping": src})["verdict"], "uncertain")

    def test_fail_plus_single_fail_unreachable(self):
        sources = {
            "aa1ping": {"status": "fail", "ok": False, "ms": None,
                        "ok_nodes": 0, "nodes": 28, "ratio": 0.0},
            "xxapi": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources)["verdict"], "unreachable")

    def test_per_source_ratio_threshold_wired(self):
        """aa1ping 阈值须真正接线（_SOURCE_MIN_RATIO 缺项会静默回退默认）。"""
        src = self._ok(nodes=10, ratio=0.7)
        src["ok_nodes"] = 7
        self.assertEqual(cc.merge_verdict({"aa1ping": dict(src)})["verdict"],
                         "reachable")
        old = cc._SOURCE_MIN_RATIO["aa1ping"]
        cc._SOURCE_MIN_RATIO["aa1ping"] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({"aa1ping": dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO["aa1ping"] = old


class TestItdogPingFallbackGuard(unittest.TestCase):
    """CN-26：batch_ping 只补 error/rate_limited 键；TCP 实测 fail 的键
    不用 ICMP 主机存活翻案（保守）；整站失败时不空转。"""

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

    def _item(self, ip):
        return (f"{ip}:80#US", f"{ip}:80#US", ip, "80", "US")

    def test_tcp_fail_keys_excluded_from_ping(self):
        """itdog 实测 fail（端口层结论）→ ping_pending 为空，不发 ping 任务。"""
        import unittest.mock as mock

        items = [self._item("10.9.0.1")]

        def fake_itdog(sample, args, page_url=None, **kw):
            if page_url == cc.ITDOG_PING_URL:
                raise AssertionError("ping must not run for fail keys")
            return {key: {"status": "fail", "ok": False, "ms": None,
                          "error": "unreachable"}
                    for _, key, _, _, _ in sample}

        with mock.patch.object(cc, "xxapi_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": ""}), \
              mock.patch.object(cc, "check_host_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "jkapi_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "jkping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "xxping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "itdog_batch_run", side_effect=fake_itdog):
            entries, _, _ = cc.run_measurements(items, self._args())

        self.assertNotIn("itdog_ping", entries["10.9.0.1:80#US"]["sources"])

    def test_ping_ok_lands_normalized(self):
        """ping 兜底 ok → sources.itdog_ping 归一为 icmp 且无 isp_ms。"""
        import unittest.mock as mock

        items = [self._item("10.10.0.1"), self._item("10.10.0.2")]

        def fake_itdog(sample, args, page_url=None, **kw):
            if page_url == cc.ITDOG_PING_URL:
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

        with mock.patch.object(cc, "xxapi_check",
                               return_value={"status": "error", "ok": False,
                                             "ms": None, "error": ""}), \
              mock.patch.object(cc, "check_host_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "jkapi_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "jkping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "xxping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "itdog_batch_run", side_effect=fake_itdog):
            entries, reachable, _ = cc.run_measurements(items, self._args())

        ping_res = entries["10.10.0.2:80#US"]["sources"]["itdog_ping"]
        self.assertEqual(ping_res["level"], "icmp")
        self.assertNotIn("isp_ms", ping_res)
        self.assertIn("10.10.0.2:80#US", reachable)


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
              mock.patch.object(cc, "jkping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "http 500"}), \
              mock.patch.object(cc, "xxping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": "http 500"}), \
              mock.patch.object(cc, "checkhost_ping_check",
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
        with mock.patch.object(ci, "itdog_fetch_nodes", return_value=([1, 2], {})), \
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
              mock.patch.object(cc, "jkping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "xxping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "checkhost_ping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "PINGPE_SLOT_GAP", 0.01), \
             mock.patch.object(cc, "pingpe_check", side_effect=slow_pingpe), \
             mock.patch.object(cc, "tcpping_check",
                               return_value={"status": "skipped"}):
            t0 = time.monotonic()
            entries, _, _ = cc.run_measurements(items, self._args())
            dt = time.monotonic() - t0

        # 串行 6×0.2s=1.2s；4 并发理想 ~0.6s。阈值 1.0s：仍能证明并行（远小于
        # 串行 1.2s），又给重载 CI 调度抖动留足缓冲，避免时序断言偶发 flaky。
        self.assertLess(dt, 1.0)
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
              mock.patch.object(cc, "jkping_check",
                                return_value={"status": "error", "ok": False,
                                              "ms": None, "error": ""}), \
              mock.patch.object(cc, "xxping_check",
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
        with mock.patch.object(ci, "itdog_fetch_nodes", return_value=([], {})):
            res = ci.itdog_batch_run(items, self._args())
        self.assertEqual(sorted(res), ["1.1.1.1:2087#US", "2.2.2.2:443#US"])
        self.assertTrue(all(v["status"] == "error" for v in res.values()))


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
                    "sources": {"check_host": {"status": fault}},
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

    def test_skipped_no_fail_merged(self):
        # 上轮可达、本轮全源 error(未获确认、无 fail) → 兜底（原实现仅放行
        # reachable/uncertain，会把全源异常轮的键挡在 -CN 之外，跌穿告警）。
        prev = self._prev("a:443#US")
        entries = {"a:443#US": {
            "verdict": "skipped",
            "sources": {"xxapi": {"status": "error"},
                        "itdog_tcping": {"status": "error"}},
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
            "sources": {"xxapi": {"status": "error"}, "itdog": {"status": "error"}},
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
    """CN-36：ce98_ping（同站 continuous-ping 通道，mock，不触网）。"""

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

    _HTML = ('<html><script id="continuous-ping-nodes-data">'
             '[{"name":"上海电信","location":"上海市"},'
             '{"name":"北京联通","location":"北京市"}]'
             '</script></html>').encode()

    def _run(self, frames, html=None):
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, html or self._HTML)), \
              mock.patch.object(cc, "_SocketIOClient",
                                return_value=self._FakeSIO(frames)):
            return cc.ce98_ping_check("1.2.3.4", "443", 10)

    def test_ping_all_ok_no_isp(self):
        frames = [
            ("event", ["continuous_ping_started", {"job_id": "j1"}]),
            ("event", ["continuous_ping_node_update",
                       {"node_name": "上海电信", "ok": True, "loss": 0,
                        "latest": 3.4, "average": 3.4}]),
            ("event", ["continuous_ping_node_update",
                       {"node_name": "北京联通", "ok": True, "loss": 0,
                        "latest": 9.0, "average": 9.0}]),
        ]
        out = self._run(frames)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 2)
        self.assertEqual(out["nodes"], 2)
        self.assertEqual(out["ms"], 3.4)
        self.assertEqual(out["level"], "icmp")
        # ICMP 不产 isp_ms（TCP 版同节点名会产出，此处须剥离）
        self.assertNotIn("isp_ms", out)

    def test_ping_all_fail(self):
        frames = [
            ("event", ["continuous_ping_node_update",
                       {"node_name": "上海", "ok": False, "latest": 0}]),
            ("event", ["continuous_ping_node_update",
                       {"node_name": "广州", "ok": False, "latest": 0}]),
        ]
        out = self._run(frames)
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ratio"], 0.0)

    def test_ping_no_nodes_data(self):
        out = self._run([], html=b"<html>no nodes</html>")
        self.assertEqual(out["status"], "error")

    def test_ping_sends_no_port(self):
        """ping 通道提交体无 port（与 TCP 相区分）。"""
        fake = self._FakeSIO([
            ("event", ["continuous_ping_started", {"job_id": "j1"}]),
            ("event", ["continuous_ping_node_update",
                       {"node_name": "上海电信", "ok": True, "loss": 0,
                        "latest": 3.4, "average": 3.4}]),
            ("event", ["continuous_ping_node_update",
                       {"node_name": "北京联通", "ok": True, "loss": 0,
                        "latest": 9.0, "average": 9.0}]),
        ])
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, self._HTML)), \
              mock.patch.object(cc, "_SocketIOClient", return_value=fake):
            cc.ce98_ping_check("1.2.3.4", "8443", 10)
        starts = [s for s in fake.sent
                  if isinstance(s, tuple) and s[0] == "start_continuous_ping"]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0][1]["target"], "1.2.3.4")
        self.assertNotIn("port", starts[0][1])

    def test_merge_strong_weak_fail(self):
        strong = {"status": "ok", "ok": True, "ms": 3.4, "level": "icmp",
                  "ok_nodes": 35, "nodes": 35, "ratio": 1.0}
        self.assertEqual(cc.merge_verdict(
            {"ce98_ping": strong})["verdict"], "reachable")
        weak = dict(strong, ok_nodes=1, nodes=35, ratio=0.029)
        self.assertEqual(cc.merge_verdict(
            {"ce98_ping": weak})["verdict"], "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None,
                "ok_nodes": 0, "nodes": 35, "ratio": 0.0}
        self.assertEqual(cc.merge_verdict(
            {"ce98_ping": fail,
             "xxapi": {"status": "fail", "ok": False,
                       "ms": None}})["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 5.0, "level": "icmp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(
            cc.merge_verdict({"ce98_ping": dict(src)})["verdict"],
            "reachable")
        old = cc._SOURCE_MIN_RATIO["ce98_ping"]
        cc._SOURCE_MIN_RATIO["ce98_ping"] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({"ce98_ping": dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO["ce98_ping"] = old

    def test_raw_slot_dispatch(self):
        cands = [("1.2.3.4:443#US line", "1.2.3.4:443#US",
                  "1.2.3.4", "443", "US")]
        entries: dict = {"1.2.3.4:443#US": {}}
        with mock.patch.object(
                cc, "ce98_ping_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_raw_slots(cands, entries, 5, "ce98_ping", 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(
            entries["1.2.3.4:443#US"]["ce98_ping"]["status"], "ok")


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

    def test_ce98_isp_ms_per_carrier(self):
        """CN-05：ce98 以节点名关键词归一运营商出 isp_ms（云厂商/
        裸地名丢弃）；与 itdog 口径一致供跨源合并。"""
        frames = [
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "上海电信", "ok": True, "loss": 0,
                        "latest": 6.0, "average": 6.0}]),
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "北京联通", "ok": True, "loss": 0,
                        "latest": 9.0, "average": 9.0}]),
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "广州腾讯云", "ok": True, "loss": 0,
                        "latest": 8.0, "average": 8.0}]),
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "深圳", "ok": True, "loss": 0,
                        "latest": 7.0, "average": 7.0}]),
        ]
        out = self._seed(frames)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(
            out["isp_ms"], {"中国电信": 6.0, "中国联通": 9.0})

    def test_ce98_early_exit_when_all_nodes_reported(self):
        """CN-15：页节点全部回执即提前结束，不空等 30s idle 窗口
        （读次数 == started＋更新数，不再多一次 timeout 轮询）。"""
        reads = []

        class _CountingSIO(self._FakeSIO):
            def read(self):
                reads.append(1)
                return super().read()

        frames = [
            ("event", ["continuous_tcping_started", {"job_id": "j1"}]),
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "上海电信", "ok": True, "loss": 0,
                        "latest": 5.0, "average": 5.0}]),
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "广州腾讯云", "ok": True, "loss": 0,
                        "latest": 8.0, "average": 8.0}]),
        ]
        html = ('<html><script id="continuous-tcping-nodes-data">'
                '[{"name":"上海电信","location":"上海市"},'
                '{"name":"广州腾讯云","location":"广东省"}]'
                '</script></html>').encode()
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, html)), \
             mock.patch.object(cc, "_SocketIOClient",
                               return_value=_CountingSIO(frames)):
            out = cc.ce98_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 2)
        self.assertEqual(len(reads), 3)

    def test_ce98_no_early_exit_on_partial(self):
        """页节点未收齐时仍等到超时/结束（残缺样本不提前收兵）。"""
        frames = [
            ("event", ["continuous_tcping_started", {"job_id": "j1"}]),
            ("event", ["continuous_tcping_node_update",
                       {"node_name": "上海电信", "ok": True, "loss": 0,
                        "latest": 5.0, "average": 5.0}]),
        ]
        html = ('<html><script id="continuous-tcping-nodes-data">'
                '[{"name":"上海电信"},{"name":"广州腾讯云"},{"name":"北京联通"}]'
                '</script></html>').encode()
        with mock.patch.object(cc, "request_follow",
                               return_value=(200, {}, html)), \
             mock.patch.object(cc, "_SocketIOClient",
                               return_value=self._FakeSIO(frames)):
            out = cc.ce98_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 1)

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

    def test_biuping_isp_ms_per_carrier(self):
        """CN-06：biuping 以结果自带 isp 字段归一出 isp_ms（未知丢弃）；
        与 itdog/ce98/tcptest 同口径供跨源合并。"""
        sse = self._sse([
            {"ok": True, "results": [
                {"node_id": 1, "isp": "电信", "status": "ok", "latest": 6.0},
                {"node_id": 2, "isp": "电信", "status": "ok", "latest": 4.0},
                {"node_id": 3, "isp": "移动", "status": "ok", "latest": 9.0},
                {"node_id": 4, "isp": "阿里云", "status": "ok", "latest": 2.0},
                {"node_id": 5, "status": "ok", "latest": 3.0}]},
        ])
        out = self._seed(sse)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(
            out["isp_ms"], {"中国电信": 4.0, "中国移动": 9.0})

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

    def test_itdog_websocket_read_caps_accumulation(self):
        ws = ci._WebSocket.__new__(ci._WebSocket)
        ws.sock = self._DripSock(self._wedged_chunk())
        ws.buf = b""
        out = ws.read()
        self.assertEqual(out[0], "err")
        self.assertIn("buffer overflow", out[1]["error"])
        self.assertLessEqual(len(ws.buf), ci.WS_MAX_BUF + 65536)

    def test_china_socketio_read_caps_accumulation(self):
        client = cc._SocketIOClient.__new__(cc._SocketIOClient)
        client.sock = self._DripSock(self._wedged_chunk())
        client.buf = b""
        out = client.read()
        self.assertEqual(out[0], "err")
        self.assertIn("buffer overflow", out[1]["error"])
        self.assertLessEqual(len(client.buf), cc.WS_MAX_BUF + 65536)


class TestTcpingcnAltchaSession(unittest.TestCase):
    """CN-30：ALTCHA 握手＋进程级会话缓存＋403 自愈（全部 mock，不触网）。"""

    def setUp(self):
        self._saved = dict(cc._TCPINGCN_SESSION)

    def tearDown(self):
        cc._TCPINGCN_SESSION.clear()
        cc._TCPINGCN_SESSION.update(self._saved)

    class _FakeResp:
        def __init__(self, body: bytes):
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self._body

    class _FakeOp:
        """按 URL 供 canned JSON；solve 时向 jar 植入 pass cookie。"""

        def __init__(self, jar, challenge, solve_ok=True):
            self.jar = jar
            self.challenge = challenge
            self.solve_ok = solve_ok
            self.posts = []

        def open(self, req, timeout=None):
            url = req.full_url
            if url.endswith("/api/probe/page"):
                return TestTcpingcnAltchaSession._FakeResp(
                    json.dumps({"r": "r", "s": "s", "ts": 1,
                                "d": 0}).encode())
            if url.endswith("/api/probe/captcha-challenge"):
                return TestTcpingcnAltchaSession._FakeResp(
                    json.dumps(self.challenge).encode())
            if url.endswith("/api/probe/captcha-solve"):
                raw = req.data.decode()
                self.posts.append(json.loads(raw))
                if self.solve_ok:
                    from http.cookiejar import Cookie
                    self.jar.set_cookie(Cookie(
                        0, "probe_captcha_pass", "PASS1", None, False,
                        "www.tcping.cn", False, False, "/", True,
                        False, None, False, None, None, {}))
                    return TestTcpingcnAltchaSession._FakeResp(b'{"ok":true}')
                return TestTcpingcnAltchaSession._FakeResp(b'{"ok":false}')
            raise AssertionError(f"unexpected url {url}")

    def _challenge(self):
        salt = "s?x=1"
        target = hashlib.sha256(f"{salt}7".encode()).hexdigest()
        return {"algorithm": "SHA-256", "challenge": target,
                "maxNumber": 64, "salt": salt, "signature": "sig"}

    def _factory(self, challenge=None, solve_ok=True):
        ch = challenge or self._challenge()
        ops = []

        def build(jar):
            op = self._FakeOp(jar, ch, solve_ok)
            ops.append(op)
            return op

        return build, ops

    def test_handshake_ok_returns_cookie(self):
        build, ops = self._factory()
        cookie = cc._tcpingcn_altcha_handshake(5, _build_opener=build)
        self.assertEqual(cookie, "probe_captcha_pass=PASS1")
        # solve 载荷须为 base64（裸对象回 400 参数错误，活体结论锁定）
        sent = ops[0].posts[0]["payload"]
        payload = json.loads(base64.b64decode(sent).decode())
        self.assertEqual(payload["number"], 7)
        self.assertIn("signature", payload)

    def test_handshake_solve_rejected(self):
        build, _ = self._factory(solve_ok=False)
        with self.assertRaises(RuntimeError):
            cc._tcpingcn_altcha_handshake(5, _build_opener=build)

    def test_handshake_no_challenge(self):
        build, _ = self._factory(challenge={"maxNumber": 0})
        with self.assertRaises(RuntimeError):
            cc._tcpingcn_altcha_handshake(5, _build_opener=build)

    def test_session_cached_within_ttl(self):
        calls = []

        def fake_handshake(timeout):
            calls.append(timeout)
            return "probe_captcha_pass=X"

        with mock.patch.object(cc, "_tcpingcn_altcha_handshake",
                               side_effect=fake_handshake):
            cc._TCPINGCN_SESSION.clear()
            self.assertEqual(cc._tcpingcn_session_cookie(5),
                             "probe_captcha_pass=X")
            self.assertEqual(cc._tcpingcn_session_cookie(5),
                             "probe_captcha_pass=X")
        self.assertEqual(len(calls), 1)  # 频率敏感：窗内只握手一次

    def test_invalidate_clears_session(self):
        cc._TCPINGCN_SESSION.update({"cookie": "c", "at": 1.0})
        cc._tcpingcn_invalidate_session()
        self.assertEqual(cc._TCPINGCN_SESSION["cookie"], "")

    def test_tcpingcn_403_reauth_retry_ok(self):
        """任务 403-altcha → 清会话重握手 → 第二次提交成功（仅重试一次）。"""
        task = {"k": "k", "r": "r", "u": "/u"}

        class _WS:
            def __init__(self, *a, **k):
                pass

            def settimeout(self, t):
                pass

            def send_text(self, p):
                pass

            def read(self):
                return ("evt", {"event": "complete", "data": {}})

            def close(self):
                pass

        posted = []

        def fake_post(url, body, cookie=""):
            posted.append(cookie)
            if len(posted) == 1:
                raise RuntimeError(
                    'HTTP 403: {"captcha":"altcha","error":"x"}')
            return task

        with mock.patch.object(cc, "_tcpingcn_session_cookie",
                               side_effect=["c-old", "c-new"]), \
              mock.patch.object(cc, "_tcpingcn_invalidate_session") as mi, \
              mock.patch.object(cc, "_tcpingcn_get",
                                return_value={"r": "r", "s": "s",
                                              "ts": 1, "d": 0}), \
              mock.patch.object(cc, "_tcpcn_pow_solve",
                                return_value=("42", 0.1)), \
              mock.patch.object(cc, "_tcpingcn_post",
                                side_effect=fake_post), \
              mock.patch.object(cc, "_WebSocket", _WS):
            out = cc.tcpingcn_check("1.2.3.4", "443", 10)
        self.assertEqual(mi.call_count, 1)
        self.assertEqual(posted, ["c-old", "c-new"])
        # complete 即收尾、0 行 → fail（不可达），但关键是走完重试不断言崩
        self.assertEqual(out["status"], "fail")

    def test_tcpingcn_403_twice_gives_error(self):
        """两次 403 即认失败（不死循环）。"""
        def always_403(url, body, cookie=""):
            raise RuntimeError('HTTP 403: {"captcha":"altcha"}')

        with mock.patch.object(cc, "_tcpingcn_session_cookie",
                               return_value="c"), \
              mock.patch.object(cc, "_tcpingcn_invalidate_session"), \
              mock.patch.object(cc, "_tcpingcn_get",
                                return_value={"r": "r", "s": "s",
                                              "ts": 1, "d": 0}), \
              mock.patch.object(cc, "_tcpcn_pow_solve",
                                return_value=("42", 0.1)), \
              mock.patch.object(cc, "_tcpingcn_post",
                                side_effect=always_403):
            out = cc.tcpingcn_check("1.2.3.4", "443", 10)
        self.assertEqual(out["status"], "error")


class TestTcpingcnPingSource(unittest.TestCase):
    """CN-30：tcpingcn_ping（同站 ICMP，紧凑键解析）。"""

    class _FakeWS:
        def __init__(self, frames):
            self._frames = list(frames)

        def settimeout(self, t):
            pass

        def send_text(self, p):
            pass

        def read(self):
            if self._frames:
                return self._frames.pop(0)
            return "timeout", None

        def close(self):
            pass

    def _row(self, area, isp, rtt, loss=0):
        return {"a": area, "i": isp, "r": rtt, "m": rtt, "q": loss}

    def _run(self, frames):
        page = {"r": "r", "s": "s", "ts": 1, "d": 0}
        task = {"k": "k", "r": "r", "u": "/u"}
        with mock.patch.object(cc, "_tcpingcn_session_cookie",
                               return_value="c"), \
              mock.patch.object(cc, "_tcpingcn_get",
                                return_value=page), \
              mock.patch.object(cc, "_tcpcn_pow_solve",
                                return_value=("42", 0.1)), \
              mock.patch.object(cc, "_tcpingcn_post",
                                return_value=task), \
              mock.patch.object(cc, "_WebSocket",
                                return_value=self._FakeWS(frames)):
            return cc.tcpingcn_ping_check("1.2.3.4", "443", 10)

    def test_ok_with_dedup_and_complete(self):
        frames = [
            ("evt", {"event": "hello", "data": {}}),
            ("evt", {"event": "result",
                     "data": self._row("上海", "联通", 5.0)}),
            ("evt", {"event": "result",
                     "data": self._row("上海", "电信", 9.0)}),
            ("evt", {"event": "result",
                     "data": self._row("上海", "联通", 6.0)}),  # 同键去重
            ("evt", {"event": "complete", "data": {}}),
            ("evt", {"event": "result",
                     "data": self._row("北京", "移动", 1.0)}),  # complete 后忽略
        ]
        out = self._run(frames)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["ok_nodes"], 2)
        self.assertEqual(out["nodes"], 2)
        self.assertEqual(out["ms"], 5.0)
        self.assertEqual(out["level"], "icmp")
        self.assertNotIn("isp_ms", out)  # 显示语义未定，宁缺勿假

    def test_all_fail(self):
        frames = [
            ("evt", {"event": "result",
                     "data": self._row("上海", "联通", 0)}),
            ("evt", {"event": "complete", "data": {}}),
        ]
        out = self._run(frames)
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["ratio"], 0.0)

    def test_loss_timeout_fails(self):
        """loss≥100（前端 yl 口径超时）即便 rtt>0 也不算可达。"""
        frames = [
            ("evt", {"event": "result",
                     "data": self._row("上海", "电信", 30.0, loss=100)}),
            ("evt", {"event": "complete", "data": {}}),
        ]
        out = self._run(frames)
        self.assertEqual(out["status"], "fail")

    def test_rtt_helpers(self):
        self.assertEqual(cc._tcpingcn_ping_rtt({"r": 12.5}), 12.5)
        self.assertEqual(cc._tcpingcn_ping_rtt({"rtt_avg": 7.0}), 7.0)
        self.assertEqual(cc._tcpingcn_ping_rtt({"m": 0}), 0.0)
        self.assertEqual(cc._tcpingcn_ping_rtt({}), 0.0)
        self.assertEqual(cc._tcpingcn_ping_loss({"q": 0}), 0.0)
        self.assertEqual(cc._tcpingcn_ping_loss({}), 0.0)

    def test_merge_strong_weak_fail(self):
        strong = {"status": "ok", "ok": True, "ms": 22.0, "level": "icmp",
                  "ok_nodes": 100, "nodes": 160, "ratio": 0.625}
        self.assertEqual(cc.merge_verdict(
            {"tcpingcn_ping": strong})["verdict"], "reachable")
        weak = dict(strong, ok_nodes=1, nodes=160, ratio=0.006)
        self.assertEqual(cc.merge_verdict(
            {"tcpingcn_ping": weak})["verdict"], "uncertain")
        fail = {"status": "fail", "ok": False, "ms": None,
                "ok_nodes": 0, "nodes": 160, "ratio": 0.0}
        self.assertEqual(cc.merge_verdict(
            {"tcpingcn_ping": fail,
             "xxapi": {"status": "fail", "ok": False,
                       "ms": None}})["verdict"], "unreachable")

    def test_ratio_threshold_wired(self):
        src = {"status": "ok", "ok": True, "ms": 20.0, "level": "icmp",
               "ok_nodes": 7, "nodes": 10, "ratio": 0.7}
        self.assertEqual(
            cc.merge_verdict({"tcpingcn_ping": dict(src)})["verdict"],
            "reachable")
        old = cc._SOURCE_MIN_RATIO["tcpingcn_ping"]
        cc._SOURCE_MIN_RATIO["tcpingcn_ping"] = 0.75
        try:
            self.assertEqual(
                cc.merge_verdict({"tcpingcn_ping": dict(src)})["verdict"],
                "uncertain")
        finally:
            cc._SOURCE_MIN_RATIO["tcpingcn_ping"] = old

    def test_ws_slot_dispatch(self):
        cands = [("1.2.3.4:443#US line", "1.2.3.4:443#US",
                  "1.2.3.4", "443", "US")]
        entries: dict = {"1.2.3.4:443#US": {}}
        with mock.patch.object(
                cc, "tcpingcn_ping_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_ws_source_slots(cands, entries, 5, "tcpingcn_ping", 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(
            entries["1.2.3.4:443#US"]["tcpingcn_ping"]["status"], "ok")


class TestTcpingcnHttpParity(unittest.TestCase):
    """``_tcpingcn_get/_post`` 对 HTTPError 的转换须对称（RuntimeError 带状态码），
    且畸形 JSON 不伪装成空成功。"""

    def _patch_deadline_open(self, side_effect):
        return mock.patch.object(cc, "deadline_open", side_effect=side_effect)

    def test_get_http_error_becomes_runtime_error(self):
        err = urllib.error.HTTPError(
            "http://tcping.cn/ping", 429, "Too Many Requests",
            {"Content-Type": "application/json"}, io.BytesIO(b'{"m":"n"}'),
        )
        with self._patch_deadline_open(side_effect=err):
            with self.assertRaisesRegex(RuntimeError, "HTTP 429"):
                cc._tcpingcn_get("http://tcping.cn/ping", cookie="")

    def test_get_ok_parses_json(self):
        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"uuid": "u1"}'

        with mock.patch.object(
            cc, "deadline_open",
            new=lambda req, timeout: _Resp(),
        ):
            self.assertEqual(cc._tcpingcn_get("http://tcping.cn/x", cookie=""), {"uuid": "u1"})

    def test_post_http_error_becomes_runtime_error(self):
        err = urllib.error.HTTPError(
            "http://tcping.cn/ping", 400, "Bad Request",
            {"Content-Type": "application/json"}, io.BytesIO(b'{}'),
        )
        with self._patch_deadline_open(side_effect=err):
            with self.assertRaisesRegex(RuntimeError, "HTTP 400"):
                cc._tcpingcn_post("http://tcping.cn/x", {"probe": "t"}, cookie="")


class TestNeedsProbe(unittest.TestCase):
    def test_no_entry_needs_probe(self):
        self.assertTrue(cc.needs_probe({}, "1.1.1.1:80#US"))

    def test_two_single_node_ok_stops(self):
        entries = {
            "1.1.1.1:80#US": {
                "check_host": {"status": "ok", "ok": True, "ms": 100, "level": "http"},
                "xxapi": {"status": "ok", "ok": True, "ms": 120, "level": "http"},
            }
        }
        self.assertFalse(cc.needs_probe(entries, "1.1.1.1:80#US"))

    def test_two_single_node_fail_stops(self):
        entries = {
            "1.1.1.1:80#US": {
                "check_host": {"status": "fail", "ok": False, "ms": None},
                "xxapi": {"status": "fail", "ok": False, "ms": None},
            }
        }
        self.assertFalse(cc.needs_probe(entries, "1.1.1.1:80#US"))

    def test_single_node_ok_uncertain_keeps(self):
        entries = {
            "1.1.1.1:80#US": {
                "check_host": {"status": "ok", "ok": True, "ms": 100, "level": "http"}
            }
        }
        self.assertTrue(cc.needs_probe(entries, "1.1.1.1:80#US"))

    def test_error_only_keeps(self):
        entries = {
            "1.1.1.1:80#US": {
                "jkapi": {"status": "error", "ok": False, "ms": None, "error": "x"}
            }
        }
        self.assertTrue(cc.needs_probe(entries, "1.1.1.1:80#US"))

    def test_multi_node_strong_stops(self):
        entries = {
            "1.1.1.1:80#US": {
                "itdog": {
                    "status": "ok", "ok": True, "ms": 50, "level": "http",
                    "ratio": 0.9, "nodes": 18,
                }
            }
        }
        self.assertFalse(cc.needs_probe(entries, "1.1.1.1:80#US"))

    def test_multi_node_weak_keeps(self):
        entries = {
            "1.1.1.1:80#US": {
                "itdog": {
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

    ce98（34 大陆省运营商节点 TCPing）毕业为默认启用：CI 传
    `--ce98-limit 200 --ce98-concurrency 6`（chinaz 同级预算）；
    CLI 默认仍 0（本地按需显式启用）。"""

    def test_ci_enables_ce98(self):
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        self.assertIn("--ce98-limit 200", wf)
        self.assertIn("--ce98-concurrency 6", wf)

    def test_ci_enables_biuping(self):
        """CN-02：biuping 毕业（约 39 ISP×节点，活体 21 单元出数）
        与 ce98 同级预算；CLI 默认仍 0。"""
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        self.assertIn("--biuping-limit 200", wf)
        self.assertIn("--biuping-concurrency 8", wf)

    def test_ping0_stays_disabled_for_captcha(self):
        """CN-03：ping0.cc 有 captcha 墙（活体实证），启用即须绕过
        反爬——合规禁区。CI 不得启用；若对方撤销验证墙，本锁须由人
        复核后同步解除（改测试即改决策）。"""
        import re
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        self.assertIsNone(
            re.search(r"--ping0-limit\s+[1-9]", wf),
            "ping0 在 captcha 墙移除前不得进 CI")

    def test_ce98_cli_default_stays_opt_in(self):
        import re
        src = (Path(__file__).resolve().parent.parent / "scripts"
               / "china_check.py").read_text(encoding="utf-8")
        m = re.search(r'"--ce98-limit", type=int, default=(\d+)', src)
        self.assertIsNotNone(m, "ce98-limit 参数定义丢失")
        self.assertEqual(int(m.group(1)), 0)
        m = re.search(r'"--ce98-concurrency", type=int, default=(\d+)', src)
        self.assertIsNotNone(m, "ce98-concurrency 参数定义丢失")
        self.assertEqual(int(m.group(1)), 6)
        m = re.search(r'"--biuping-limit", type=int, default=(\d+)', src)
        self.assertIsNotNone(m, "biuping-limit 参数定义丢失")
        self.assertEqual(int(m.group(1)), 0)
        m = re.search(r'"--biuping-concurrency", type=int, default=(\d+)', src)
        self.assertIsNotNone(m, "biuping-concurrency 参数定义丢失")
        self.assertEqual(int(m.group(1)), 8)

    def test_graduated_limits_match_readme(self):
        """CN-10：已毕业源的 CI 配额须与 README 链一致（防 CI 行与文档
        双边漂移；生产出数待下次 china 验证）。"""
        import re
        root = Path(__file__).resolve().parent.parent
        wf = (root / ".github" / "workflows" / "china-check.yml").read_text(
            encoding="utf-8")
        readme = (root / "README.md").read_text(encoding="utf-8")
        for name, flag in (("98ce.com", "ce98"), ("biuping.com", "biuping"),
                           ("biuping-ping", "biuping-ping"),
                           ("aa1ping", "aa1ping"),
                           ("antping-ping", "antping-ping"),
                           ("tcpingcn-ping", "tcpingcn-ping"),
                           ("tcptest-ping", "tcptest-ping"),
                           ("tcptest-http", "tcptest-http"),
                           ("ce98-ping", "ce98-ping")):
            m = re.search(rf"--{flag}-limit (\d+).*?--{flag}-concurrency (\d+)",
                          wf, re.S)
            self.assertIsNotNone(m, f"CI 未启用 {name}")
            limit, conc = m.group(1), m.group(2)
            self.assertRegex(
                readme,
                re.compile(re.escape(f"{name}（{limit} 键/{conc} 并发")),
                f"README 链与 CI 配额不一致：{name}")

    def test_aa1ping_cli_default_stays_opt_in(self):
        """CN-27：aa1ping 本地默认 opt-in（0/6），只在 CI 显式启用；
        与 ce98/biuding 毕业路径一致。"""
        import re
        src = (Path(__file__).resolve().parent.parent / "scripts"
               / "china_check.py").read_text(encoding="utf-8")
        m = re.search(r'"--aa1ping-limit", type=int, default=(\d+)', src)
        self.assertIsNotNone(m, "aa1ping-limit 参数定义丢失")
        self.assertEqual(int(m.group(1)), 0)
        m = re.search(r'"--aa1ping-concurrency", type=int, default=(\d+)', src)
        self.assertIsNotNone(m, "aa1ping-concurrency 参数定义丢失")
        self.assertEqual(int(m.group(1)), 6)

    def test_antping_ping_cli_default_stays_opt_in(self):
        """CN-28：antping-ping 本地默认 opt-in（0/8），只在 CI 显式启用。"""
        import re
        src = (Path(__file__).resolve().parent.parent / "scripts"
               / "china_check.py").read_text(encoding="utf-8")
        m = re.search(r'"--antping-ping-limit", type=int, default=(\d+)', src)
        self.assertIsNotNone(m, "antping-ping-limit 参数定义丢失")
        self.assertEqual(int(m.group(1)), 0)
        m = re.search(r'"--antping-ping-concurrency", type=int, default=(\d+)',
                      src)
        self.assertIsNotNone(m, "antping-ping-concurrency 参数定义丢失")
        self.assertEqual(int(m.group(1)), 8)

    def test_tcptest_ping_cli_default_stays_opt_in(self):
        """CN-33：tcptest-ping 本地默认 opt-in（0/8，与 TCP 同并发），
        只在 CI 显式启用（400/20）。"""
        import re
        src = (Path(__file__).resolve().parent.parent / "scripts"
               / "china_check.py").read_text(encoding="utf-8")
        m = re.search(r'"--tcptest-ping-limit", type=int, default=(\d+)', src)
        self.assertIsNotNone(m, "tcptest-ping-limit 参数定义丢失")
        self.assertEqual(int(m.group(1)), 0)
        m = re.search(r'"--tcptest-ping-concurrency", type=int, default=([A-Za-z_0-9]+)',
                      src)
        self.assertIsNotNone(m, "tcptest-ping-concurrency 参数定义丢失")
        self.assertEqual(m.group(1), "TCPTEST_CONCURRENCY")
        self.assertEqual(cc.TCPTEST_CONCURRENCY, 8)

    def test_tcptest_http_cli_default_stays_opt_in(self):
        """CN-35：tcptest-http 本地默认 opt-in（0/8），只在 CI 显式启用。"""
        import re
        src = (Path(__file__).resolve().parent.parent / "scripts"
               / "china_check.py").read_text(encoding="utf-8")
        m = re.search(r'"--tcptest-http-limit", type=int, default=(\d+)', src)
        self.assertIsNotNone(m, "tcptest-http-limit 参数定义丢失")
        self.assertEqual(int(m.group(1)), 0)
        m = re.search(r'"--tcptest-http-concurrency", type=int, default=([A-Za-z_0-9]+)',
                      src)
        self.assertIsNotNone(m, "tcptest-http-concurrency 参数定义丢失")
        self.assertEqual(m.group(1), "TCPTEST_CONCURRENCY")
        self.assertEqual(cc.TCPTEST_CONCURRENCY, 8)

    def test_biuping_ping_cli_default_stays_opt_in(self):
        """CN-34：biuping-ping 本地默认 opt-in（0/8），只在 CI 显式启用。"""
        import re
        src = (Path(__file__).resolve().parent.parent / "scripts"
               / "china_check.py").read_text(encoding="utf-8")
        m = re.search(r'"--biuping-ping-limit", type=int, default=(\d+)', src)
        self.assertIsNotNone(m, "biuping-ping-limit 参数定义丢失")
        self.assertEqual(int(m.group(1)), 0)
        m = re.search(r'"--biuping-ping-concurrency", type=int, default=(\d+)',
                      src)
        self.assertIsNotNone(m, "biuping-ping-concurrency 参数定义丢失")
        self.assertEqual(int(m.group(1)), 8)

    def test_ce98_ping_cli_default_stays_opt_in(self):
        """CN-36：ce98-ping 本地默认 opt-in（0/6），只在 CI 显式启用。"""
        import re
        src = (Path(__file__).resolve().parent.parent / "scripts"
               / "china_check.py").read_text(encoding="utf-8")
        m = re.search(r'"--ce98-ping-limit", type=int, default=(\d+)', src)
        self.assertIsNotNone(m, "ce98-ping-limit 参数定义丢失")
        self.assertEqual(int(m.group(1)), 0)
        m = re.search(r'"--ce98-ping-concurrency", type=int, default=(\d+)',
                      src)
        self.assertIsNotNone(m, "ce98-ping-concurrency 参数定义丢失")
        self.assertEqual(int(m.group(1)), 6)

    def test_all_enabled_l3_limits_present(self):
        """CN-12：CI 启用的全部 L3 复核源配额原地锁定（tcptest/coffee/
        pingloc/antping/tcpingcn/chinaz/pingpe/ce98/biuding/aa1ping），防 CI 行
        误删某源致覆盖无声缩水。"""
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        for flag in ("--tcptest-limit 800", "--coffee-limit 1200",
                     "--pingloc-limit 600", "--antping-limit 500",
                     "--tcpingcn-limit 400", "--chinaz-limit 200",
                     "--pingpe-limit 300",
                     "--ce98-limit 200", "--biuping-limit 200",
                     "--aa1ping-limit 200", "--antping-ping-limit 200",
                     "--tcpingcn-ping-limit 200",
                     "--tcptest-ping-limit 400",
                     "--biuping-ping-limit 200",
                     "--tcptest-http-limit 200",
                     "--ce98-ping-limit 200"):
            self.assertIn(flag, wf, f"CI 缺复核配额：{flag}")

    def test_tcpingcn_limit_restored_after_altcha(self):
        """CN-30：tcping.cn ALTCHA 打通后复活——CI 配额恢复 400，
        同通道 ping 200 并行（停烧锁已解除，复活验证见本轮活体）。"""
        import re
        wf = (Path(__file__).resolve().parent.parent / ".github"
              / "workflows" / "china-check.yml").read_text(encoding="utf-8")
        m = re.search(r"--tcpingcn-limit (\d+)", wf)
        self.assertIsNotNone(m, "tcpingcn-limit flag 丢失")
        self.assertEqual(int(m.group(1)), 400)
        m = re.search(r"--tcpingcn-ping-limit (\d+)", wf)
        self.assertIsNotNone(m, "tcpingcn-ping-limit flag 丢失")
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
                cc, "ce98_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_raw_slots(cands, entries, 5, "ce98", 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(entries["1.2.3.4:443#US"]["ce98"]["status"], "ok")
        with mock.patch.object(
                cc, "biuping_check",
                side_effect=RuntimeError("boom")):
            cc._run_raw_slots(cands, entries, 5, "biuping", 2)
        err = entries["1.2.3.4:443#US"]["biuping"]
        self.assertEqual(err["status"], "error")
        self.assertEqual(err["error"], "RuntimeError")
        with mock.patch.object(
                cc, "aa1ping_check",
                return_value={"status": "ok", "ok": True}) as m:
            cc._run_raw_slots(cands, entries, 5, "aa1ping", 2)
            m.assert_called_once_with("1.2.3.4", "443", 5)
        self.assertEqual(entries["1.2.3.4:443#US"]["aa1ping"]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
