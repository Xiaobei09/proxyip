"""Tests for quality_check.py pure functions."""

import argparse
import asyncio
import contextlib
import io
import json
import re
import sys
import time
import tempfile
import traceback
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import quality_check as qc
import common
import quality_reputation as qr


class TestParseEntry(unittest.TestCase):
    def test_parses_ltd_line(self):
        self.assertEqual(
            qc.parse_ltd_line("1.2.3.4:443#\U0001F1FA\U0001F1F8US-8ms-5.86MB/s"),
            ("1.2.3.4:443#US", "1.2.3.4", "443", "US"),
        )

    def test_parses_line_without_flag(self):
        self.assertEqual(
            qc.parse_ltd_line("1.2.3.4:443#US-8ms"),
            ("1.2.3.4:443#US", "1.2.3.4", "443", "US"),
        )

    def test_parses_line_with_exit_arrow(self):
        self.assertEqual(
            qc.parse_ltd_line("1.2.3.4:443#\U0001F1FA\U0001F1F8US\u2192NRT-8ms-5.86MB/s"),
            ("1.2.3.4:443#US", "1.2.3.4", "443", "US"),
        )

    def test_parses_all_cc_as_pseudo_country(self):
        self.assertEqual(
            qc.parse_ltd_line("1.2.3.4:443#ALL-120ms-0.44MB/s"),
            ("1.2.3.4:443#ALL", "1.2.3.4", "443", "ALL"),
        )

    def test_all_not_collapsed_to_albania(self):
        parsed = qc.parse_ltd_line("1.2.3.4:443#ALL-120ms")
        self.assertEqual(parsed[0], "1.2.3.4:443#ALL")
        parsed_al = qc.parse_ltd_line("1.2.3.4:443#AL-120ms")
        self.assertEqual(parsed_al[0], "1.2.3.4:443#AL")

    def test_rejects_bad_lines(self):
        self.assertIsNone(qc.parse_ltd_line(""))
        self.assertIsNone(qc.parse_ltd_line("garbage"))
        self.assertIsNone(qc.parse_ltd_line("1.2.3.4:443"))
        self.assertIsNone(qc.parse_ltd_line("1.2.3.4:abc#US-1ms"))

    def test_line_to_key(self):
        self.assertEqual(
            qc.line_to_key("5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-80ms-1.25MB/s"),
            "5.6.7.8:8443#JP",
        )
        self.assertIsNone(qc.line_to_key(""))

    def test_ipv6_with_port_parses(self):
        # 池内 IPv6 条目为无括号 ``ip:port#cc`` 拼接，rsplit 正确取端口
        self.assertEqual(
            qc.parse_ltd_line("2606:4700::1:443#US-8ms"),
            ("2606:4700::1:443#US", "2606:4700::1", "443", "US"),
        )
        self.assertEqual(
            qc.parse_ltd_line("2400:cb00::1:8443#JP-8ms"),
            ("2400:cb00::1:8443#JP", "2400:cb00::1", "8443", "JP"),
        )

    def test_bracketed_ipv6_kept_in_addr(self):
        # 方括号 IPv6 目前不产生于下载/验证管线（is_valid_ip 拒绝括号），
        # 解析器保持字面地址与端口分离契约
        self.assertEqual(
            qc.parse_ltd_line("[2606:4700::1]:443#US-8ms"),
            ("[2606:4700::1]:443#US", "[2606:4700::1]", "443", "US"),
        )


class TestParseHeaders(unittest.TestCase):
    def test_parses_status_and_headers(self):
        raw = b"HTTP/1.1 301 Moved\r\nLocation: https://x/?country=DE\r\ncontent-length: 0\r\n\r\n"
        status, headers = qc.parse_headers(raw)
        self.assertEqual(status, 301)
        self.assertEqual(headers["location"], "https://x/?country=DE")
        self.assertEqual(headers["content-length"], "0")

    def test_bad_status(self):
        status, headers = qc.parse_headers(b"garbage\r\n")
        self.assertIsNone(status)
        self.assertEqual(headers, {})


class TestGroupChunks(unittest.TestCase):
    def test_chunking(self):
        self.assertEqual(qc.group_chunks(list(range(250)), 100), [
            list(range(100)), list(range(100, 200)), list(range(200, 250)),
        ])

    def test_empty(self):
        self.assertEqual(qc.group_chunks([], 100), [])


class TestIpTypeAndRisk(unittest.TestCase):
    def test_classify_ip(self):
        self.assertEqual(qc.classify_ip({"hosting": True}), "DC")
        self.assertEqual(qc.classify_ip({"mobile": True}), "MOB")
        self.assertEqual(qc.classify_ip({"proxy": True}), "PROXY")
        self.assertEqual(qc.classify_ip({}), "RES")

    def test_derive_risk_keyless(self):
        w = qc.REPUTATION_WEIGHTS
        self.assertEqual(
            qc.derive_risk({"ip-api": {"proxy": True, "hosting": True}},
                           None, w), "medium"
        )
        self.assertEqual(
            qc.derive_risk({"ip-api": {"proxy": True, "hosting": False}},
                           None, w), "medium"
        )
        self.assertEqual(
            qc.derive_risk({"ip-api": {"proxy": False, "hosting": False}},
                           None, w), "low"
        )
        self.assertEqual(
            qc.derive_risk({"netcoffee": {"trust_score": 20}}, None, w), "high"
        )
        self.assertEqual(
            qc.derive_risk({"netcoffee": {"trust_score": 50}}, None, w),
            "medium"
        )
        self.assertEqual(
            qc.derive_risk({"netcoffee": {"trust_score": 90}}, None, w), "low"
        )

    def test_derive_risk_from_score(self):
        w = qc.REPUTATION_WEIGHTS
        self.assertEqual(qc.derive_risk({}, {"score": 90}, w), "high")
        self.assertEqual(qc.derive_risk({}, {"score": 50}, w), "medium")
        self.assertEqual(qc.derive_risk({}, {"score": 10}, w), "low")


class TestTimeBudgetGate(unittest.TestCase):
    """D-42：``--time-budget`` 墙钟相位感知止损门槛（到点停开新相位、已得结果仍落盘）。"""

    def test_unlimited_always_in_budget(self):
        self.assertTrue(qc._within_budget(time.monotonic(), 0))
        self.assertTrue(qc._within_budget(time.monotonic() - 1e6, 0))

    def test_budget_boundary(self):
        start = time.monotonic()
        self.assertTrue(qc._within_budget(start, 5))
        time.sleep(0.01)
        # 未到期（起点后不足 5s）
        self.assertTrue(qc._within_budget(start, 5))
        # 模拟超期：起点大幅早于现在
        self.assertFalse(qc._within_budget(time.monotonic() - 10, 5))
        # 恰好边界：已用 == 预算视为超期（< 而非 <=）
        self.assertFalse(qc._within_budget(start - 5, 5))


class TestBatchSyncDeadline(unittest.TestCase):
    """D-42 补漏：reputation 相位 batch_sync 透传 wall-clock deadline 止损。

    deadline 前不再新开探测任务、已提交任务收尾、超龄不重试——防止
    大面积缓存失效时把后处理拖过 120min job 硬杀。
    """

    def test_expired_deadline_truncates_all(self):
        called = []
        async def run():
            res = await qr.batch_sync(
                ["1.1.1.1", "2.2.2.2"],
                lambda ip: called.append(ip) or {"ok": True},
                deadline=time.monotonic() - 1,
            )
            return res
        res = asyncio.run(run())
        self.assertEqual(res, {})
        self.assertEqual(called, [])

    def test_fresh_deadline_runs_all(self):
        called = []
        async def run():
            return await qr.batch_sync(
                ["1.1.1.1", "2.2.2.2"],
                lambda ip: called.append(ip) or {"ok": True},
                deadline=time.monotonic() + 30,
                delay=0,
            )
        res = asyncio.run(run())
        self.assertEqual(len(res), 2)
        self.assertEqual(len(called), 2)

    def test_expired_deadline_skips_retry(self):
        calls = []
        async def run():
            return await qr.batch_sync(
                ["1.1.1.1"],
                lambda ip: calls.append(ip) or None,
                deadline=time.monotonic() + 30,
                delay=0,
                retries=1,
            )
        res = asyncio.run(run())
        # None=成功响应但无信号：记录但**不重试**（R238 语义）
        self.assertEqual(res, {"1.1.1.1": None})
        self.assertEqual(calls, ["1.1.1.1"])


class TestBuildIpinfo(unittest.TestCase):
    def test_tls_proxy_geo_match(self):
        results = {
            "1.2.3.4:443#US": {
                "key": "1.2.3.4:443#US", "cc": "US",
                "ip": "9.9.9.9",
            }
        }
        geo = {
            "9.9.9.9": {
                "status": "success", "country": "United States",
                "countryCode": "US", "regionName": "California",
                "as": "AS1 X", "asn": "AS1", "org": "Org",
                "isp": "Isp", "proxy": False, "hosting": True,
                "mobile": False,
            }
        }
        info = qc.build_ipinfo_map(results, geo, {})["1.2.3.4:443#US"]
        self.assertEqual(info["exit_ip"], "9.9.9.9")
        self.assertTrue(info["country_match"])
        self.assertEqual(info["ip_type"], "DC")
        self.assertEqual(info["risk"], "low")
        self.assertEqual(info["reputation"], 90)
        self.assertEqual(info["reputation_source"], "ip-api")
        self.assertTrue(info["geo_checked"])

    def test_reputation_netcoffee_wins(self):
        results = {
            "1.2.3.4:443#US": {
                "key": "1.2.3.4:443#US", "cc": "US",
                "ip": "9.9.9.9",
            }
        }
        geo = {"9.9.9.9": {"status": "success", "countryCode": "US"}}
        nc = {"9.9.9.9": {"netcoffee": {"trust_score": 42,
                                          "is_datacenter": True}}}
        info = qc.build_ipinfo_map(results, geo, {}, nc)["1.2.3.4:443#US"]
        # 连续风险 58 + 共识 hosting 标记 10 → 32
        self.assertEqual(info["reputation"], 32)
        self.assertEqual(info["reputation_source"], "multi")
        self.assertEqual(info["rep_flags"], ["hosting"])
        self.assertEqual(info["risk"], "medium")

    def test_no_geo_no_reputation(self):
        results = {
            "1.2.3.4:443#US": {
                "key": "1.2.3.4:443#US", "cc": "US",
                "ip": "9.9.9.9",
            }
        }
        info = qc.build_ipinfo_map(results, {}, {})["1.2.3.4:443#US"]
        self.assertNotIn("reputation", info)
        self.assertFalse(info["geo_checked"])
        self.assertEqual(info["risk"], "low")

    def test_mismatch_country(self):
        results = {
            "1.2.3.4:443#JP": {
                "key": "1.2.3.4:443#JP", "cc": "JP",
                "ip": "8.8.8.8",
            }
        }
        geo = {"8.8.8.8": {"status": "success", "countryCode": "US"}}
        info = qc.build_ipinfo_map(results, geo, {})["1.2.3.4:443#JP"]
        self.assertFalse(info["country_match"])


class TestResolveExitIps(unittest.TestCase):
    def test_priority_trace_over_exit_family_over_proxy(self):
        results = {
            "a": {"ip": "1.1.1.1", "external_check": {
                "exit_geo": {"ip": "9.9.9.9"}}},
            "b": {"ip": "2.2.2.2", "external_check": None},
            "c": {"ip": "3.3.3.3"},
        }
        fam_map = {
            "a": {"exit_v4": "8.8.8.8"},   # 被 trace 覆盖
            "b": {"exit_v4": "7.7.7.7", "exit_v6": None},
            "d": {"exit_v4": "6.6.6.6"},   # 不在 results 中 → 忽略
        }
        out = qc.resolve_exit_ips(results, fam_map)
        self.assertEqual(out["a"]["exit_ip"], "9.9.9.9")
        self.assertEqual(out["a"]["exit_ip_source"], "trace")
        self.assertEqual(out["b"]["exit_ip"], "7.7.7.7")
        self.assertEqual(out["b"]["exit_ip_source"], "exit_family")
        # 无任何出口信息 → 回退代理自身 IP（保持旧行为）
        self.assertEqual(out["c"]["exit_ip"], "3.3.3.3")
        self.assertEqual(out["c"]["exit_ip_source"], "proxy")

    def test_dual_prefers_v4_only_v6_falls_back(self):
        results = {
            "dual": {"ip": "1.1.1.1"},
            "v6": {"ip": "2.2.2.2"},
        }
        fam_map = {
            "dual": {"exit_v4": "4.4.4.4", "exit_v6": "2001:db8::1"},
            "v6": {"exit_v4": None, "exit_v6": "2001:db8::2"},
        }
        out = qc.resolve_exit_ips(results, fam_map)
        self.assertEqual(out["dual"]["exit_ip"], "4.4.4.4")
        self.assertEqual(out["dual"]["exit_ip_source"], "exit_family")
        self.assertEqual(out["v6"]["exit_ip"], "2001:db8::2")
        self.assertEqual(out["v6"]["exit_ip_source"], "exit_family")

    def test_malformed_family_entries_ignored(self):
        results = {"a": {"ip": "1.1.1.1"}}
        out = qc.resolve_exit_ips(results, {"a": "junk", "b": None})
        self.assertEqual(out["a"]["exit_ip"], "1.1.1.1")

    def test_none_and_missing_exit_geo_no_crash(self):
        """CI 回归：external_check 存在但 exit_geo 为 null/缺失时不得崩溃。"""
        results = {
            "a": {"ip": "1.1.1.1", "external_check": {
                "success": True, "response_ms": 3, "colo": "IAD",
                "ipv4_ok": True, "ipv6_ok": False, "exit_geo": None,
            }},
            "b": {"ip": "2.2.2.2", "external_check": {"success": False}},
            "c": {"ip": "3.3.3.3", "external_check": {
                "success": True, "exit_geo": {"ip": None}}},
        }
        out = qc.resolve_exit_ips(results, {})
        for key, ip in (("a", "1.1.1.1"), ("b", "2.2.2.2"), ("c", "3.3.3.3")):
            self.assertEqual(out[key]["exit_ip"], ip)
            self.assertEqual(out[key]["exit_ip_source"], "proxy")

    def test_build_reputation_uses_exit_ip(self):
        risk_data = {"9.9.9.9": {"netcoffee": {"trust_score": 80}}}
        rep_map = qc.build_reputation_map(
            {"a": {"key": "k", "ip": "1.1.1.1", "exit_ip": "9.9.9.9"}},
            risk_data, qc.REPUTATION_WEIGHTS,
        )
        self.assertIn("k", rep_map)
        # 入口 IP 上即使有数据也不应被采用
        empty = qc.build_reputation_map(
            {"a": {"key": "k", "ip": "1.1.1.1", "exit_ip": "9.9.9.9"}},
            {"1.1.1.1": {"netcoffee": {"trust_score": 80}}},
            qc.REPUTATION_WEIGHTS,
        )
        self.assertEqual(empty, {})


class TestAnnotation(unittest.TestCase):
    def test_build_annotation(self):
        self.assertEqual(
            qc.build_annotation("NF(US) D+ YT GPT", "DC"), "NF(US) D+ YT GPT-DC"
        )
        self.assertEqual(qc.build_annotation("", "CF"), "CF")
        self.assertEqual(qc.build_annotation("", ""), "")

    def test_annotate_text(self):
        annotations = {
            "1.2.3.4:443#US": "NF(US)-DC",
            "5.6.7.8:8443#JP": "GPT-CF",
        }
        text = (
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-120ms-0.44MB/s\n"
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-80ms\n"
            "9.9.9.9:443#\U0001F1FA\U0001F1F8US-50ms\n"
        )
        out, changed = qc.annotate_text(text, annotations)
        self.assertTrue(changed)
        lines = out.splitlines()
        self.assertTrue(lines[0].endswith("-NF(US)-DC"))
        self.assertTrue(lines[1].endswith("-GPT"))
        self.assertFalse(lines[2].endswith("-"))

    def test_annotate_text_with_exits(self):
        """Exit markers are now handled by annotate_classify; annotate_text
        only appends annotation tokens."""
        annotations = {"1.2.3.4:443#US": "GPT-CF"}
        text = "1.2.3.4:443#\U0001F1FA\U0001F1F8US-120ms-0.44MB/s\n"
        out, changed = qc.annotate_text(text, annotations)
        self.assertTrue(changed)
        self.assertEqual(
            out.strip(),
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-120ms-0.44MB/s-GPT",
        )
        out2, changed2 = qc.annotate_text(out, annotations)
        self.assertFalse(changed2)
        self.assertEqual(out2.strip(), out.strip())

    def test_insert_exit_region(self):
        self.assertEqual(
            qc.insert_exit_region("1.2.3.4:443#\U0001F1FA\U0001F1F8US-8ms", "LAX"),
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US\u2192LAX-8ms",
        )
        self.assertEqual(
            qc.insert_exit_region("1.2.3.4:443#US-8ms", "LAX"),
            "1.2.3.4:443#US\u2192LAX-8ms",
        )
        self.assertEqual(
            qc.insert_exit_region("1.2.3.4:443#\U0001F1FA\U0001F1F8US\u2192NRT-8ms", "LAX"),
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US\u2192NRT-8ms",
        )
        self.assertEqual(qc.insert_exit_region("1.2.3.4:443", "LAX"), "1.2.3.4:443")
        self.assertEqual(
            qc.insert_exit_region("1.2.3.4:443#US-8ms", ""), "1.2.3.4:443#US-8ms"
        )

    def test_insert_exit_region_after_all(self):
        self.assertEqual(
            qc.insert_exit_region("1.2.3.4:443#ALL-120ms-0.44MB/s", "US"),
            "1.2.3.4:443#ALL\u2192US-120ms-0.44MB/s",
        )

    def test_annotate_all_line_with_exit(self):
        """annotate_text no longer handles exit markers (→CC is annotate_classify's job)."""
        text = "1.2.3.4:443#ALL-120ms-0.44MB/s\n"
        out, changed = qc.annotate_text(text, {})
        self.assertFalse(changed)
        self.assertEqual(out.strip(), "1.2.3.4:443#ALL-120ms-0.44MB/s")

    def test_build_exits_removed(self):
        """build_exits 已删——出口国统一走 common.build_exit_cc_map。"""
        self.assertFalse(hasattr(qc, "build_exits"))


class TestReputation(unittest.TestCase):
    W = qc.REPUTATION_WEIGHTS

    def test_abuse_takes_precedence(self):
        signals = {
            "netcoffee": {"trust_score": 5, "is_abuser": True},
            "ip-api": {"proxy": True, "hosting": True},
        }
        self.assertEqual(qc.compute_reputation(signals, {"score": 90}, self.W), 10)

    def test_otx_cached_string_signal_tolerated(self):
        """缓存投毒韧性：otx 信号数值字段为非 int 字符串 → 不崩、按 0 计分。"""
        sigs = {"otx": {"reputation": "abc", "pulse_count": "xyz"}}
        # 主路径 vote_reputation 内部连续罚分与 flag 判定均不抛 ValueError
        self.assertEqual(qc.compute_reputation(sigs, None, self.W), 100)
        self.assertEqual(qc.vote_reputation(sigs, self.W)[0], 100)

    def test_as_int_coercion(self):
        self.assertEqual(qr._as_int(90), 90)
        self.assertEqual(qr._as_int("90"), 90)
        self.assertEqual(qr._as_int("abc"), 0)
        self.assertEqual(qr._as_int(None), 0)
        self.assertEqual(qr._as_int(3.0), 3)
        self.assertEqual(qr._as_int(3.7), 0)
        self.assertEqual(qr._as_int(True), 0)

    def test_trust_score_direct(self):
        self.assertEqual(
            qc.compute_reputation({"netcoffee": {"trust_score": 63}},
                                  None, self.W), 63
        )

    def test_trust_score_clamped(self):
        self.assertEqual(
            qc.compute_reputation({"netcoffee": {"trust_score": 150}},
                                  None, self.W), 100
        )
        self.assertEqual(
            qc.compute_reputation({"netcoffee": {"trust_score": -5}},
                                  None, self.W), 0
        )

    def test_netcoffee_flag_penalty(self):
        nc = {"netcoffee": {"is_abuser": True, "is_tor": True, "is_vpn": True}}
        # 共识标记：abuse 35 + tor 40 + vpn 22 = 97 → 3
        self.assertEqual(qc.compute_reputation(nc, None, self.W), 3)
        nc = {"netcoffee": {"is_datacenter": True}}
        # 共识 hosting 标记 10 → 90
        self.assertEqual(qc.compute_reputation(nc, None, self.W), 90)

    def test_source_score_per_source(self):
        self.assertEqual(
            qc.source_score("netcoffee", {"trust_score": 63}), 63)
        self.assertEqual(
            qc.source_score("netcoffee", {"is_datacenter": True}), 85)
        self.assertEqual(
            qc.source_score("ncgy", {"is_tor": True, "is_anonymous": True}), 45)
        self.assertEqual(qc.source_score("ncgy", {"is_vpn": True}), 75)
        self.assertEqual(
            qc.source_score("ip-api", {"proxy": True, "hosting": True}), 65)
        self.assertEqual(
            qc.source_score("ip-api", {"proxy": False, "hosting": False}), 100)
        self.assertEqual(
            qc.source_score("ip-api", {"proxy": True, "mobile": True}), 80)
        self.assertEqual(
            qc.source_score(
                "ipdata", {"security": {"tor": True}, "threat_score": 30}), 25)
        self.assertEqual(
            qc.source_score("getipintel", {"probability": 0.3}), 70)
        self.assertIsNone(qc.source_score("getipintel", {"probability": -3}))
        self.assertEqual(
            qc.source_score("ipapi_is", {"is_tor": True, "is_vpn": True}), 25)
        self.assertIsNone(qc.source_score("bogus", {}))

    def test_source_score_proxycheck(self):
        self.assertEqual(
            qc.source_score("proxycheck", {"is_proxy": True, "risk": 50}), 50)
        self.assertEqual(
            qc.source_score("proxycheck", {"is_proxy": False, "is_vpn": True}), 55)
        self.assertEqual(
            qc.source_score("proxycheck", {"is_proxy": False, "risk": 20}), 80)
        self.assertEqual(
            qc.source_score("proxycheck", {"is_proxy": False, "is_hosting": True}), 70)
        self.assertEqual(
            qc.source_score("proxycheck", {}), 100)

    def test_source_score_ip2location(self):
        self.assertEqual(
            qc.source_score("ip2location", {"is_proxy": True}), 70)
        self.assertIsNone(
            qc.source_score("ip2location", {"is_proxy": False}))

    def test_weighted_merge(self):
        signals = {"netcoffee": {"trust_score": 80},
                   "ncgy": {"is_vpn": True}}
        score, sources = qc.weighted_reputation(signals, self.W)
        self.assertEqual(score, 78)
        self.assertEqual(set(sources), {"netcoffee", "ncgy"})

    def test_weighted_merge_renormalizes(self):
        signals = {"netcoffee": {"trust_score": 50}}
        score, sources = qc.weighted_reputation(signals, self.W)
        self.assertEqual(score, 50)
        self.assertEqual(sources, ["netcoffee"])

    def test_no_signals(self):
        self.assertIsNone(qc.compute_reputation({}, None, self.W))
        self.assertEqual(qc.weighted_reputation({}, self.W), (None, []))

    def test_ipapi_only(self):
        # 共识一致：proxy 28 + hosting 10 → 62
        self.assertEqual(
            qc.compute_reputation(
                {"ip-api": {"proxy": True, "hosting": True}}, None, self.W), 62
        )
        self.assertIsNone(qc.compute_reputation({}, None, self.W))

    def test_consensus_negation_vetoes_proxy(self):
        """单源报 proxy 但他人明确说非代理 → 共识否定，不扣分。"""
        sigs = {
            "netcoffee": {"is_proxy": True},
            "ip-api": {"proxy": False},
            "ncgy": {"clean": True},
        }
        self.assertEqual(qc.compute_reputation(sigs, None, self.W), 100)
        _, responding, flagged, _ = qc.vote_reputation(sigs, self.W)
        self.assertEqual(flagged, [])
        self.assertEqual(set(responding), {"ncgy", "netcoffee", "ip-api"})

    def test_consensus_two_sources_agree_on_proxy(self):
        """多源一致报 proxy → 统一扣分。"""
        sigs = {
            "netcoffee": {"is_proxy": True},
            "proxycheck": {"is_proxy": True},
        }
        score, _r, flagged, _n = qc.vote_reputation(sigs, self.W)
        self.assertEqual(score, 72)
        self.assertEqual(flagged, ["proxy"])

    def test_greynoise_abuse_not_double_penalized_with_noise(self):
        """同一 IP 恶意+噪音：abuse 特判即最高口径，不叠加 noise 二次罚分。"""
        sigs = {
            "greynoise": {
                "is_abuse": True, "is_noise": True,
                "classification": "malicious",
            },
        }
        # greynoise 恶意目录按特判 60 罚（非不加 noise 的 consensus 35 口径）
        score, _r, flagged, _n = qc.vote_reputation(sigs, self.W)
        self.assertEqual(score, 40)
        self.assertEqual(flagged, ["abuse"])
        self.assertNotIn("noise", flagged)

    def test_greynoise_riot_penalty(self):
        sigs = {"greynoise": {"is_riot": True}}
        score, _r, flagged, _n = qc.vote_reputation(sigs, self.W)
        self.assertEqual(flagged, ["bot"])
        self.assertEqual(score, 65)

    def test_ipdata_threat_score_numeric(self):
        """ipdata threat_score 进入连续型罚分链。"""
        sigs = {"ipdata": {"is_proxy": False, "threat_score": 40}}
        score, _r, _f, numeric = qc.vote_reputation(sigs, self.W)
        self.assertEqual(score, 60)
        self.assertEqual(numeric, ["ipdata"])

    def test_otx_numeric_penalty_sign_matches_flag_semantics(self):
        """OTX reputation 负=恶意（官方 -3..+3，负号幅值越大越脏）。数值罚分
        按负侧幅值计，正/零声誉不罚——与 _flag_opinions 的 listed 语义一致，
        纠正此前把正声誉当脏、负声誉当净的符号反转。"""
        self.assertEqual(qr._numeric_risk_penalty(
            "otx", {"reputation": -100, "pulse_count": 0}), 80)
        self.assertEqual(qr._numeric_risk_penalty(
            "otx", {"reputation": -100, "pulse_count": 99}), 100)
        self.assertEqual(qr._numeric_risk_penalty(
            "otx", {"reputation": 100, "pulse_count": 0}), 0)
        self.assertEqual(qr._numeric_risk_penalty(
            "otx", {"reputation": 0, "pulse_count": 0}), 0)
        self.assertEqual(qr._numeric_risk_penalty(
            "otx", {"reputation": -3, "pulse_count": 0}), 15)
        self.assertEqual(qr.source_score(
            "otx", {"reputation": -100, "pulse_count": 0}), 20)
        self.assertEqual(qr.source_score(
            "otx", {"reputation": 100, "pulse_count": 0}), 100)
        dirty, _r, flagged, _n = qr.vote_reputation(
            {"otx": {"reputation": -100, "pulse_count": 0}},
            qr.REPUTATION_WEIGHTS)
        self.assertEqual(dirty, 0)
        self.assertEqual(flagged, ["listed"])
        fresh, _r2, flagged2, _n2 = qr.vote_reputation(
            {"otx": {"reputation": 100, "pulse_count": 0}},
            qr.REPUTATION_WEIGHTS)
        self.assertEqual(fresh, 100)
        self.assertEqual(flagged2, [])

    def test_mobile_bonus_noise_crawler_excluded(self):
        """mobile 奖励需所有风险维度均不成立，noise/crawler 视为风险。"""
        self.assertEqual(qr._mobile_clean_bonus({"mobile": True}), 5)
        self.assertEqual(qr._mobile_clean_bonus({"mobile": True, "crawler": True}), 0)
        self.assertEqual(qr._mobile_clean_bonus({"mobile": True, "noise": True}), 0)

    def test_consensus_clean_source_abstains_on_unknown(self):
        """ncgy clean 只否定它检查过的家族；对无关家族不投票。"""
        sigs = {
            "netcoffee": {"is_vpn": True, "is_tor": True},
            "ncgy": {"clean": True},
        }
        score, _r, flagged, _n = qc.vote_reputation(sigs, self.W)
        self.assertIn("vpn", flagged)
        self.assertIn("tor", flagged)

    def test_consensus_disagreement_tie_benefit_of_doubt(self):
        # 权重相等的正负票打平 → 无结论，不扣分
        sigs = {
            "proxycheck": {"is_vpn": True, "is_proxy": True},
            "ffraud": {"is_vpn": False, "is_proxy": False},
        }
        score, _r, flagged, _n = qc.vote_reputation(sigs, self.W)
        self.assertEqual(flagged, [])
        self.assertEqual(score, 100)

    def test_ipwhois_source_score_and_vote(self):
        self.assertEqual(qc.source_score(
            "ipwhois", {"security": {"tor": True}}), 55)
        self.assertIsNone(qc.source_score(
            "ipwhois", {"security": {"proxy": False, "vpn": False,
                                     "hosting": False, "tor": False,
                                     "anonymous": False}}))
        score, _r, flagged, _n = qc.vote_reputation(
            {"ipwhois": {"security": {"proxy": True}}}, self.W)
        self.assertEqual(score, 72)
        self.assertEqual(flagged, ["proxy"])

    def test_stopforumspam_source_score_and_vote(self):
        self.assertEqual(
            qc.source_score("stopforumspam", {"is_abuse": True}), 50)
        self.assertIsNone(qc.source_score("stopforumspam", {}))
        # abuse 35 + tor 40 → 100-75 = 25
        score, _r, flagged, _n = qc.vote_reputation(
            {"stopforumspam": {"is_abuse": True, "torexit": True}}, self.W)
        self.assertEqual(score, 25)
        self.assertEqual(sorted(flagged), ["abuse", "tor"])

    def test_static_list_sources_vote_and_score(self):
        score, _r, flagged, _n = qc.vote_reputation(
            {"tor_exit": {"is_tor": True}}, self.W)
        self.assertEqual(score, 60)
        self.assertEqual(flagged, ["tor"])
        score, _r, flagged, _n = qc.vote_reputation(
            {"spamhaus": {"is_listed": True}}, self.W)
        self.assertEqual(score, 70)
        self.assertEqual(flagged, ["listed"])
        self.assertEqual(qc.source_score("tor_exit", {"is_tor": True}), 45)
        self.assertEqual(qc.source_score("spamhaus", {"is_listed": True}), 55)
        self.assertIn("tor_exit", qc.REPUTATION_WEIGHTS)
        self.assertIn("spamhaus", qc.REPUTATION_WEIGHTS)
        # ipwhois 免费层不再返回 connection/security，已退出默认源（保留权重供 opt-in）
        self.assertNotIn("ipwhois", qc.DEFAULT_REP_SOURCES)
        self.assertIn("ipwhois", qc.REPUTATION_WEIGHTS)
        self.assertIn("stopforumspam", qc.DEFAULT_REP_SOURCES)
        # R268：maltiverse 退出默认源（实域参与共识近零），权重保留供 opt-in
        self.assertNotIn("maltiverse", qc.DEFAULT_REP_SOURCES)
        self.assertIn("maltiverse", qc.REPUTATION_WEIGHTS)
        self.assertIn("spamcop", qc.DEFAULT_REP_SOURCES)
        # ipapi_is 与 ipwhois 同样：解析器保留但退出默认源（opt-in）
        self.assertNotIn("ipapi_is", qc.DEFAULT_REP_SOURCES)
        self.assertIn("ipapi_is", qc.REPUTATION_WEIGHTS)
        self.assertIn("tor_exit", qc.DEFAULT_REP_SOURCES)

    def test_hackmyip_source_vote(self):
        """hackmyip hosting/proxy/mobile flags vote into the semantic dims."""
        self.assertIn("hackmyip", qc.DEFAULT_REP_SOURCES)
        self.assertIn("hackmyip", qc.REPUTATION_WEIGHTS)
        self.assertEqual(qr._flag_opinions(
            "hackmyip", {"is_proxy": True, "is_hosting": False,
                         "is_mobile": False}),
            {"hosting": False, "mobile": False, "proxy": True})
        self.assertEqual(qr._flag_opinions(
            "hackmyip", {"is_hosting": True}), {"hosting": True})
        self.assertEqual(qr._flag_opinions(
            "hackmyip", {"is_mobile": True}), {"mobile": True})
        score, _r, flagged, _n = qc.vote_reputation(
            {"hackmyip": {"is_proxy": True, "is_hosting": False,
                          "is_mobile": False}}, self.W)
        self.assertEqual(flagged, ["proxy"])

    def test_feodo_source_vote(self):
        """feodo 僵尸网络 C2 静态 IP 命中 → abuse 维度。"""
        self.assertIn("feodo", qc.DEFAULT_REP_SOURCES)
        self.assertIn("feodo", qc.REPUTATION_WEIGHTS)
        self.assertEqual(qr._flag_opinions(
            "feodo", {"is_abuse": True}), {"abuse": True})
        score, _r, flagged, _n = qc.vote_reputation(
            {"feodo": {"is_abuse": True}}, self.W)
        self.assertEqual(flagged, ["abuse"])

    def test_new_static_rep_sources_registered(self):
        """新增静态信誉源（blocklist.de 三类别 + dan.me.uk + Tor 出口冗余）
        全部默认启用、各有权重、能被 source_score 打分。"""
        for name in (
            "blocklist_de",
            "blocklist_de_ssh",
            "blocklist_de_apache",
            "danmeuk_tor",
            "tor_bulk",
        ):
            self.assertIn(name, qc.DEFAULT_REP_SOURCES)
            self.assertIn(name, qc.REPUTATION_WEIGHTS)
            self.assertIn(name, qc.STATIC_LIST_SCORES)
            self.assertGreater(qc.REPUTATION_WEIGHTS[name], 0)

    def test_blocklist_de_sources_vote_abuse(self):
        """blocklist.de 各类别命中 → abuse 维度。"""
        for name in ("blocklist_de", "blocklist_de_ssh", "blocklist_de_apache"):
            self.assertEqual(
                qr._flag_opinions(name, {"is_abuse": True}), {"abuse": True})
            self.assertEqual(
                qc.source_score(name, {"is_abuse": True}),
                qc.STATIC_LIST_SCORES[name])
            self.assertIsNone(qc.source_score(name, {}))
        for name in ("danmeuk_tor", "tor_bulk"):
            self.assertEqual(
                qr._flag_opinions(name, {"is_tor": True}), {"tor": True})
            self.assertEqual(
                qc.source_score(name, {"is_tor": True}),
                qc.STATIC_LIST_SCORES[name])
            self.assertIsNone(qc.source_score(name, {}))

    def test_new_rep_static_sources_registered(self):
        """c2_tracker/botscout/greensnow/sslproxies/socks_proxy 默认启用。"""
        for name in ("c2_tracker", "botscout", "greensnow", "sslproxies",
                     "socks_proxy"):
            self.assertIn(name, qc.DEFAULT_REP_SOURCES)
            self.assertIn(name, qc.REPUTATION_WEIGHTS)
            self.assertIn(name, qc.STATIC_LIST_SCORES)
            self.assertGreater(qc.REPUTATION_WEIGHTS[name], 0)

    def test_r214_rep_static_sources_registered(self):
        """R214：vpn_ips（X4BNet VPN 出口 CIDR）+ dshield（DShield /24
        攻击子网）        断言 vpn_ips 退默认（保留 opt-in 权重/派发），dshield 仍默认启用。"""
        for name in ("dshield",):
            self.assertIn(name, qc.DEFAULT_REP_SOURCES)
        for name in ("vpn_ips", "dshield"):
            self.assertIn(name, qc.REPUTATION_WEIGHTS)
            self.assertIn(name, qc.STATIC_LIST_SCORES)
            self.assertGreater(qc.REPUTATION_WEIGHTS[name], 0)
        self.assertNotIn("vpn_ips", qc.DEFAULT_REP_SOURCES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["vpn_ips"], 0)
        self.assertEqual(
            qr._flag_opinions("vpn_ips", {"is_vpn": True}), {"vpn": True})
        self.assertEqual(
            qc.source_score("vpn_ips", {"is_vpn": True}),
            qc.STATIC_LIST_SCORES["vpn_ips"])
        self.assertEqual(
            qr._flag_opinions("dshield", {"is_abuse": True}), {"abuse": True})
        self.assertEqual(
            qc.source_score("dshield", {"is_abuse": True}),
            qc.STATIC_LIST_SCORES["dshield"])
        self.assertIsNone(qc.source_score("vpn_ips", {}))

    def test_dnsbl_source_registered(self):
        """R251：dnsbl（Spamhaus ZEN via DoH）默认启用、权重 8、有 pacing、
        命中 → listed 维度，score 70。"""
        self.assertIn("dnsbl", qc.DEFAULT_REP_SOURCES)
        self.assertIn("dnsbl", qc.REPUTATION_WEIGHTS)
        self.assertEqual(qc.REPUTATION_WEIGHTS["dnsbl"], 8)
        self.assertIn("dnsbl", qr.SOURCE_PACING)
        self.assertEqual(
            qr._flag_opinions("dnsbl", {"is_listed": True}), {"listed": True})
        self.assertEqual(qr._flag_opinions("dnsbl", {}), {})
        self.assertEqual(qr.source_score("dnsbl", {"is_listed": True}), 70)
        self.assertIsNone(qr.source_score("dnsbl", {}))

    def test_dnsbl_lookup_parse(self):
        """SBL(2/3)/XBL(4/5)→listed；PBL(6/7)/CSS(8/9)/无应答→None。"""
        cases = [
            (["127.0.0.2"], {"is_listed": True, "dnsbl_code": 2}),
            (["127.0.0.3"], {"is_listed": True, "dnsbl_code": 3}),
            (["127.0.0.4"], {"is_listed": True, "dnsbl_code": 4}),
            (["127.0.0.5"], {"is_listed": True, "dnsbl_code": 5}),
            (["127.0.0.2", "127.0.0.4"], {"is_listed": True, "dnsbl_code": 2}),
            (["127.0.0.6"], None),  # PBL 忽略（邮件策略网段）
            (["127.0.0.7"], None),
            (["127.0.0.8"], None),  # CSS snowshoe 弱信号忽略
            (["127.0.0.9"], None),
            ([], None),             # NXDOMAIN/无应答 = 未列出
        ]
        for answers, expect in cases:
            with unittest.mock.patch.object(
                    qr, "_doh_query", return_value=answers):
                self.assertEqual(qr.dnsbl_lookup_sync("8.8.8.8"), expect)
        # 非 IPv4 直接短路：不触发 DoH 查询
        with unittest.mock.patch.object(qr, "_doh_query") as m:
            self.assertIsNone(qr.dnsbl_lookup_sync("2001:db8::1"))
            self.assertIsNone(qr.dnsbl_lookup_sync("not-an-ip"))
            m.assert_not_called()
        with unittest.mock.patch.object(qr, "_doh_query",
                                        return_value=["127.0.0.2"]) as m:
            qr.dnsbl_lookup_sync("1.2.3.4")
            self.assertEqual(
                m.call_args[0][0], "4.3.2.1.[REDACTED_PRIVATE_RESOURCE]")

    def test_spamcop_lookup_sync_codes(self):
        """R268：SpamCop 命中码 127.0.0.2 → listed；其余/空 → None。"""
        for answers, expect in [
            (["127.0.0.2"], {"is_listed": True, "dnsbl_code": 2}),
            (["127.0.0.1"], None),   # 反解失败码忽略
            (["127.0.0.4"], None),   # 非 SpamCop 码
            ([], None),              # 未列出
        ]:
            with unittest.mock.patch.object(
                    qr, "_doh_query", return_value=answers):
                self.assertEqual(qr.spamcop_lookup_sync("8.8.8.8"), expect)
        with unittest.mock.patch.object(qr, "_doh_query") as m:
            self.assertIsNone(qr.spamcop_lookup_sync("2001:db8::1"))
            m.assert_not_called()
        with unittest.mock.patch.object(qr, "_doh_query",
                                        return_value=["127.0.0.2"]) as m:
            qr.spamcop_lookup_sync("1.2.3.4")
            self.assertEqual(
                m.call_args[0][0], "4.3.2.1.[REDACTED_PRIVATE_RESOURCE]")
        # 与 dnsbl 同维：listed 信号与罚分口径一致。
        self.assertEqual(
            qr._flag_opinions("spamcop", {"is_listed": True}),
            {"listed": True})
        self.assertEqual(qr.source_score("spamcop", {"is_listed": True}), 70)
        self.assertIsNone(qr.source_score("spamcop", {}))

    def test_dronebl_lookup_sync_codes(self):
        """R269：DroneBL 命中码 2~13 → listed；其余/空 → None。"""
        for code in (2, 3, 5, 7, 13):
            with unittest.mock.patch.object(
                    qr, "_doh_query",
                    return_value=[f"127.0.0.{code}"]):
                self.assertEqual(
                    qr.dronebl_lookup_sync("8.8.8.8"),
                    {"is_listed": True, "dnsbl_code": code})
        for answers, expect in [
            (["127.0.0.1"], None),  # 非入榜码
            ([], None),              # 未列出
        ]:
            with unittest.mock.patch.object(
                    qr, "_doh_query", return_value=answers):
                self.assertEqual(qr.dronebl_lookup_sync("8.8.8.8"), expect)
        with unittest.mock.patch.object(qr, "_doh_query") as m:
            self.assertIsNone(qr.dronebl_lookup_sync("2001:db8::1"))
            m.assert_not_called()
        with unittest.mock.patch.object(qr, "_doh_query",
                                        return_value=["127.0.0.3"]) as m:
            qr.dronebl_lookup_sync("1.2.3.4")
            self.assertEqual(
                m.call_args[0][0], "4.3.2.1.[REDACTED_PRIVATE_RESOURCE]")
        self.assertEqual(
            qr._flag_opinions("dronebl", {"is_listed": True}),
            {"listed": True})
        self.assertEqual(qr.source_score("dronebl", {"is_listed": True}), 70)
        self.assertIsNone(qr.source_score("dronebl", {}))

    def test_default_sources_add_dronebl_drop_iplocation(self):
        """R269：每轮一增一减——默认源含 dronebl、不含 iplocation。"""
        self.assertIn("dronebl", qr.DEFAULT_REP_SOURCES)
        self.assertNotIn("iplocation", qr.DEFAULT_REP_SOURCES)
        self.assertIn("dronebl", qr.REPUTATION_WEIGHTS)
        self.assertIn("iplocation", qr.REPUTATION_WEIGHTS)

    def test_spamrats_lookup_sync_codes(self):
        """R270/R271：SpamRats 命中码 2/3 → listed；DYN 4/其余/空 → None；
        且 listed 信号必须进入共识投票与计分（R271 补接分支的回归锁）。"""
        for code in (2, 3):
            with unittest.mock.patch.object(
                    qr, "_doh_query",
                    return_value=[f"127.0.0.{code}"]):
                self.assertEqual(
                    qr.spamrats_lookup_sync("8.8.8.8"),
                    {"is_listed": True, "dnsbl_code": code})
        for answers in (["127.0.0.1"], ["127.0.0.4"], []):
            with unittest.mock.patch.object(
                    qr, "_doh_query", return_value=answers):
                self.assertIsNone(qr.spamrats_lookup_sync("8.8.8.8"))
        with unittest.mock.patch.object(qr, "_doh_query") as m:
            self.assertIsNone(qr.spamrats_lookup_sync("2001:db8::1"))
            m.assert_not_called()
        with unittest.mock.patch.object(qr, "_doh_query",
                                        return_value=["127.0.0.2"]) as m:
            qr.spamrats_lookup_sync("1.2.3.4")
            self.assertEqual(
                m.call_args[0][0], "4.3.2.1.[REDACTED_PRIVATE_RESOURCE]")
        # opt-in：有权重/pacing/派发但不进默认。
        self.assertNotIn("spamrats", qr.DEFAULT_REP_SOURCES)
        self.assertIn("spamrats", qr.REPUTATION_WEIGHTS)
        self.assertIn("spamrats", qr.SOURCE_PACING)
        # 计分接线：与 spamcop/dronebl 同维同分。
        self.assertEqual(
            qr._flag_opinions("spamrats", {"is_listed": True}),
            {"listed": True})
        self.assertEqual(qr._flag_opinions("spamrats", {}), {})
        self.assertEqual(qr.source_score("spamrats", {"is_listed": True}), 70)
        self.assertIsNone(qr.source_score("spamrats", {}))

    def test_sorbs_lookup_sync_codes(self):
        """R271：SORBS 新增 opt-in 源——命中码 2/7 → listed；动态住宅段
        4/8/9/其余/空 → None；listed 信号进入共识投票与计分。"""
        for code in (2, 7):
            with unittest.mock.patch.object(
                    qr, "_doh_query",
                    return_value=[f"127.0.0.{code}"]):
                self.assertEqual(
                    qr.sorbs_lookup_sync("8.8.8.8"),
                    {"is_listed": True, "dnsbl_code": code})
        for answers in (["127.0.0.1"], ["127.0.0.4"], ["127.0.0.8"],
                        ["127.0.0.9"], []):
            with unittest.mock.patch.object(
                    qr, "_doh_query", return_value=answers):
                self.assertIsNone(qr.sorbs_lookup_sync("8.8.8.8"))
        with unittest.mock.patch.object(qr, "_doh_query") as m:
            self.assertIsNone(qr.sorbs_lookup_sync("2001:db8::1"))
            self.assertIsNone(qr.sorbs_lookup_sync("not-an-ip"))
            m.assert_not_called()
        with unittest.mock.patch.object(qr, "_doh_query",
                                        return_value=["127.0.0.2"]) as m:
            qr.sorbs_lookup_sync("1.2.3.4")
            self.assertEqual(
                m.call_args[0][0], "4.3.2.1.[REDACTED_PRIVATE_RESOURCE]")
        self.assertNotIn("sorbs", qr.DEFAULT_REP_SOURCES)
        self.assertIn("sorbs", qr.REPUTATION_WEIGHTS)
        self.assertEqual(qr.REPUTATION_WEIGHTS["sorbs"], 5)
        self.assertIn("sorbs", qr.SOURCE_PACING)
        self.assertEqual(
            qr._flag_opinions("sorbs", {"is_listed": True}),
            {"listed": True})
        self.assertEqual(qr._flag_opinions("sorbs", {}), {})
        self.assertEqual(qr.source_score("sorbs", {"is_listed": True}), 70)
        self.assertIsNone(qr.source_score("sorbs", {}))

    def test_dnsbl_family_consensus_listed(self):
        """R271：dnsbl/spamcop/dronebl/spamrats/sorbs 五家命中 listed 时
        共识均投 listed 票（任一漏接即回归失败）。R272 起含 uceprotect
        共六家，R273 起含 psbl 共七家。"""
        for name in ("dnsbl", "spamcop", "dronebl", "spamrats", "sorbs",
                     "uceprotect", "psbl"):
            self.assertEqual(
                qr._flag_opinions(name, {"is_listed": True}),
                {"listed": True}, name)
            self.assertEqual(
                qr.source_score(name, {"is_listed": True}), 70, name)

    def test_uceprotect_lookup_sync_codes(self):
        """R272：UCEPROTECT L1 新增 opt-in 源——命中码仅 2 → listed；
        其余/空 → None；listed 信号进入共识投票与计分。test-point
        2.0.0.127 经 DoH 实测回包 127.0.0.2（分区存活实证）。"""
        with unittest.mock.patch.object(
                qr, "_doh_query", return_value=["127.0.0.2"]):
            self.assertEqual(
                qr.uceprotect_lookup_sync("8.8.8.8"),
                {"is_listed": True, "dnsbl_code": 2})
        for answers in (["127.0.0.1"], ["127.0.0.3"], ["127.0.0.4"], []):
            with unittest.mock.patch.object(
                    qr, "_doh_query", return_value=answers):
                self.assertIsNone(qr.uceprotect_lookup_sync("8.8.8.8"))
        with unittest.mock.patch.object(qr, "_doh_query") as m:
            self.assertIsNone(qr.uceprotect_lookup_sync("2001:db8::1"))
            self.assertIsNone(qr.uceprotect_lookup_sync("not-an-ip"))
            m.assert_not_called()
        with unittest.mock.patch.object(qr, "_doh_query",
                                        return_value=["127.0.0.2"]) as m:
            qr.uceprotect_lookup_sync("1.2.3.4")
            self.assertEqual(
                m.call_args[0][0], "4.3.2.1.[REDACTED_PRIVATE_RESOURCE]")
        self.assertNotIn("uceprotect", qr.DEFAULT_REP_SOURCES)
        self.assertIn("uceprotect", qr.REPUTATION_WEIGHTS)
        self.assertEqual(qr.REPUTATION_WEIGHTS["uceprotect"], 5)
        self.assertIn("uceprotect", qr.SOURCE_PACING)
        self.assertEqual(
            qr._flag_opinions("uceprotect", {"is_listed": True}),
            {"listed": True})
        self.assertEqual(qr._flag_opinions("uceprotect", {}), {})
        self.assertEqual(
            qr.source_score("uceprotect", {"is_listed": True}), 70)
        self.assertIsNone(qr.source_score("uceprotect", {}))

    def test_psbl_lookup_sync_codes(self):
        """R273：PSBL 新增 opt-in 源——命中码仅 2 → listed；其余/空 →
        None；listed 信号进入共识投票与计分。test-point 2.0.0.127 经
        DoH 实测回包 127.0.0.2（分区存活实证）。"""
        with unittest.mock.patch.object(
                qr, "_doh_query", return_value=["127.0.0.2"]):
            self.assertEqual(
                qr.psbl_lookup_sync("8.8.8.8"),
                {"is_listed": True, "dnsbl_code": 2})
        for answers in (["127.0.0.1"], ["127.0.0.3"], []):
            with unittest.mock.patch.object(
                    qr, "_doh_query", return_value=answers):
                self.assertIsNone(qr.psbl_lookup_sync("8.8.8.8"))
        with unittest.mock.patch.object(qr, "_doh_query") as m:
            self.assertIsNone(qr.psbl_lookup_sync("2001:db8::1"))
            self.assertIsNone(qr.psbl_lookup_sync("not-an-ip"))
            m.assert_not_called()
        with unittest.mock.patch.object(qr, "_doh_query",
                                        return_value=["127.0.0.2"]) as m:
            qr.psbl_lookup_sync("1.2.3.4")
            self.assertEqual(
                m.call_args[0][0], "4.3.2.1.[REDACTED_PRIVATE_RESOURCE]")
        self.assertNotIn("psbl", qr.DEFAULT_REP_SOURCES)
        self.assertIn("psbl", qr.REPUTATION_WEIGHTS)
        self.assertEqual(qr.REPUTATION_WEIGHTS["psbl"], 5)
        self.assertIn("psbl", qr.SOURCE_PACING)
        self.assertEqual(
            qr._flag_opinions("psbl", {"is_listed": True}),
            {"listed": True})
        self.assertEqual(qr._flag_opinions("psbl", {}), {})
        self.assertEqual(qr.source_score("psbl", {"is_listed": True}), 70)
        self.assertIsNone(qr.source_score("psbl", {}))

    def test_dnsbl_lookup_shared_skeleton(self):
        """R273：七源 lookup 共用骨架——多应答取首个命中码、非 127 网段
        跳过、非法码容错；spamcop 旧精确匹配语义等价（单码 2）。"""
        with unittest.mock.patch.object(
                qr, "_doh_query",
                return_value=["8.8.8.8", "127.0.0.9", "not-an-ip",
                              "127.0.0.2"]):
            self.assertEqual(
                qr.spamcop_lookup_sync("1.2.3.4"),
                {"is_listed": True, "dnsbl_code": 2})
        with unittest.mock.patch.object(
                qr, "_doh_query",
                return_value=["127.0.0.3", "127.0.0.2"]):
            self.assertEqual(
                qr.dnsbl_lookup_sync("1.2.3.4"),
                {"is_listed": True, "dnsbl_code": 3})

    def test_dnsbl_skeleton_constants_cleanup(self):
        """R274：骨架常量锁——dnsbl 码表常量化；sorbs pacing 与其余
        DNSBL 归一 (6, 0.15)；旧 SPAMCOP_LISTED_CODE 单码常量已移除
        （语义由薄包装 frozenset((2,)) 承载）。"""
        self.assertEqual(qr.DNSBL_LISTED_CODES, frozenset((2, 3, 4, 5)))
        for name in ("spamcop", "dronebl", "spamrats", "sorbs",
                     "uceprotect", "psbl"):
            self.assertEqual(qr.SOURCE_PACING[name], (6, 0.15), name)
        # dnsbl 例外：主源上限 12000/轮，pacing (6, 0.2) 保持不变。
        self.assertEqual(qr.SOURCE_PACING["dnsbl"], (6, 0.2))
        self.assertFalse(hasattr(qr, "SPAMCOP_LISTED_CODE"))

    def test_default_sources_drop_maltiverse_add_spamcop(self):
        """R268：每轮一增一减——默认源含 spamcop、不含 maltiverse。"""
        self.assertIn("spamcop", qr.DEFAULT_REP_SOURCES)
        self.assertNotIn("maltiverse", qr.DEFAULT_REP_SOURCES)
        self.assertIn("spamcop", qr.REPUTATION_WEIGHTS)
        self.assertIn("maltiverse", qr.REPUTATION_WEIGHTS)

    def test_doh_query_endpoint_fallback(self):
        """端点失败转镜像；全部失败抛错（不把故障当「干净」）。"""
        responses = [
            "not json",
            None,  # json null -> missing Status
            {"Status": 0, "Answer": [{"data": "1.2.3.4"}]},
        ]
        index = [0]

        def fake_deadline_open(req, timeout, max_bytes=None):
            cur = responses[min(index[0], len(responses) - 1)]
            index[0] += 1

            class FakeResp:
                def read(self, *a):
                    if cur is None:
                        return b"null"
                    if isinstance(cur, str):
                        raise OSError("bad payload")
                    return json.dumps(cur).encode()
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    pass
            return FakeResp()

        qr._DOH_STICKY.clear()
        with unittest.mock.patch.object(qr, "deadline_open",
                                        side_effect=fake_deadline_open):
            self.assertEqual(
                qr._doh_query("1.2.3.4.[REDACTED_PRIVATE_RESOURCE]"),
                ["1.2.3.4"])

        # 全部端点失败 → 抛异常（而非返回 []）
        qr._DOH_STICKY.clear()
        with unittest.mock.patch.object(
                qr, "deadline_open",
                side_effect=OSError("all endpoints dead")):
            with self.assertRaises(OSError):
                qr._doh_query("1.2.3.4.[REDACTED_PRIVATE_RESOURCE]")

    def test_doh_query_sticky_leader(self):
        """成功端点被 sticky 复用：同一进程后续查询不再先空等慢/死端点。"""
        qr._DOH_STICKY.clear()

        def fake_deadline_open(req, timeout, max_bytes=None):
            if "dns.google" not in req.full_url:
                raise OSError("only dns.google reachable")

            class FakeResp:
                def read(self, *a):
                    return json.dumps(
                        {"Status": 0, "Answer": [{"data": "1.2.3.4"}]}
                    ).encode()
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    pass
            return FakeResp()

        calls = []

        def traced(req, timeout=30, max_bytes=None):
            calls.append(req.full_url)
            return fake_deadline_open(req, timeout, max_bytes)

        with unittest.mock.patch.object(qr, "deadline_open",
                                        side_effect=traced):
            self.assertEqual(qr._doh_query("4.3.2.1.[REDACTED_PRIVATE_RESOURCE]"),
                             ["1.2.3.4"])
        # 第一次：alidns/cloudflare 失败 → 失败回落至 dns.google 成功。
        self.assertEqual(len(calls), len(qr.DNSBL_DOH_ENDPOINTS))
        self.assertEqual(qr._DOH_STICKY[-1][0], qr.DNSBL_DOH_ENDPOINTS[-1])

        calls.clear()
        with unittest.mock.patch.object(qr, "deadline_open",
                                        side_effect=traced):
            # sticky 命中 dns.google → 仅一次调用即返回，不再空等 alidns。
            self.assertEqual(qr._doh_query("5.5.5.5.[REDACTED_PRIVATE_RESOURCE]"),
                             ["1.2.3.4"])
        self.assertEqual(len(calls), 1)
        self.assertIn("dns.google", calls[0])

    def test_doh_sticky_thread_safe(self):
        """R262：并发读 stale/写 sticky 不得 IndexError，长度恒 ≤1。

        list 无锁时「读到 stale 后 pop()」与他线程 pop 交错会抛
        IndexError，使一次 DoH 查询白白失败并触发重试。多线程压测
        helper 验证加锁后无异常且始终收敛为单条。
        """
        import threading as _th
        qr._DOH_STICKY.clear()
        qr._DOH_STICKY.append((qr.DNSBL_DOH_ENDPOINTS[0], 0.0))
        errs = []

        def worker():
            try:
                for _ in range(300):
                    qr._doh_sticky_order()
                    qr._doh_sticky_record(qr.DNSBL_DOH_ENDPOINTS[-1])
            except Exception as exc:  # noqa: BLE001
                errs.append(exc)

        ts = [_th.Thread(target=worker) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errs, [])
        self.assertLessEqual(len(qr._DOH_STICKY), 1)
        qr._DOH_STICKY.clear()

    def test_abuseipdb_public_source_registered(self):
        """R251：abuseipdb_public 公共黑名单默认启用、有权重/静态分。"""
        self.assertIn("abuseipdb_public", qc.DEFAULT_REP_SOURCES)
        self.assertIn("abuseipdb_public", qc.REPUTATION_WEIGHTS)
        self.assertIn("abuseipdb_public", qc.STATIC_LIST_SCORES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["abuseipdb_public"], 0)
        self.assertEqual(
            qr._flag_opinions("abuseipdb_public", {"is_abuse": True}),
            {"abuse": True})
        self.assertEqual(
            qc.source_score("abuseipdb_public", {"is_abuse": True}),
            qc.STATIC_LIST_SCORES["abuseipdb_public"])
        self.assertIsNone(qc.source_score("abuseipdb_public", {}))

    def test_wwuyi_unreachable_source_registered(self):
        """REP-1：wwuyi_unreachable 第三方失联表默认启用、有权重/静态分。

        温和口径：命中投 listed 票（非 abuse），静态 70，权重 2。
        """
        self.assertIn("wwuyi_unreachable", qc.DEFAULT_REP_SOURCES)
        self.assertIn("wwuyi_unreachable", qc.REPUTATION_WEIGHTS)
        self.assertIn("wwuyi_unreachable", qc.STATIC_LIST_SCORES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["wwuyi_unreachable"], 0)
        self.assertEqual(
            qr._flag_opinions("wwuyi_unreachable", {"is_listed": True}),
            {"listed": True})
        self.assertEqual(qc.source_score("wwuyi_unreachable", {}), None)
        self.assertEqual(
            qc.source_score("wwuyi_unreachable", {"is_listed": True}),
            qc.STATIC_LIST_SCORES["wwuyi_unreachable"])
        self.assertEqual(qc.STATIC_LIST_SCORES["wwuyi_unreachable"], 70)

    def test_wwuyi_blocked_source_registered(self):
        """REP-2：wwuyi_blocked 维护者拉黑表默认启用、有权重/静态分。

        口径略强于失联（静态 65），仍投 listed 票（非滥用定性）。
        """
        self.assertIn("wwuyi_blocked", qc.DEFAULT_REP_SOURCES)
        self.assertIn("wwuyi_blocked", qc.REPUTATION_WEIGHTS)
        self.assertIn("wwuyi_blocked", qc.STATIC_LIST_SCORES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["wwuyi_blocked"], 0)
        self.assertEqual(
            qr._flag_opinions("wwuyi_blocked", {"is_listed": True}),
            {"listed": True})
        self.assertEqual(qc.source_score("wwuyi_blocked", {}), None)
        self.assertEqual(
            qc.source_score("wwuyi_blocked", {"is_listed": True}),
            qc.STATIC_LIST_SCORES["wwuyi_blocked"])
        self.assertEqual(qc.STATIC_LIST_SCORES["wwuyi_blocked"], 65)

    def test_wwuyi_unreachable_fetch_uses_default_timeout(self):
        """REP-1：小表用默认静态超时；URL 为上游 unreachable_ips.txt。"""
        calls = []

        def fake(url, timeout, headers=None, max_bytes=None):
            calls.append((url, timeout))
            return b"1.2.3.4\n"

        with unittest.mock.patch.object(qr, "fetch_with_mirror",
                                        side_effect=fake):
            got = asyncio.run(qr.fetch_wwuyi_unreachable())
        self.assertEqual(len(calls), 1)
        self.assertIn("unreachable_ips.txt", calls[0][0])
        self.assertEqual(calls[0][1], qr.STATIC_LIST_TIMEOUT)
        self.assertEqual(len(got), 1)

    def test_wwuyi_blocked_fetch_uses_default_timeout(self):
        """REP-2：小表用默认静态超时；URL 为上游 blocked_ips.txt。"""
        calls = []

        def fake(url, timeout, headers=None, max_bytes=None):
            calls.append((url, timeout))
            return b"1.2.3.4\n"

        with unittest.mock.patch.object(qr, "fetch_with_mirror",
                                        side_effect=fake):
            got = asyncio.run(qr.fetch_wwuyi_blocked())
        self.assertEqual(len(calls), 1)
        self.assertIn("blocked_ips.txt", calls[0][0])
        self.assertEqual(calls[0][1], qr.STATIC_LIST_TIMEOUT)
        self.assertEqual(len(got), 1)

    def test_firehol_level2_source_registered(self):
        """REP-3：firehol_level2 默认启用、有权重/静态分。

        L1 超集（更广更噪）：listed 票，静态 50，权重 4。
        """
        self.assertIn("firehol_level2", qc.DEFAULT_REP_SOURCES)
        self.assertIn("firehol_level2", qc.REPUTATION_WEIGHTS)
        self.assertIn("firehol_level2", qc.STATIC_LIST_SCORES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["firehol_level2"], 0)
        self.assertEqual(
            qr._flag_opinions("firehol_level2", {"is_listed": True}),
            {"listed": True})
        self.assertEqual(qc.source_score("firehol_level2", {}), None)
        self.assertEqual(
            qc.source_score("firehol_level2", {"is_listed": True}),
            qc.STATIC_LIST_SCORES["firehol_level2"])
        self.assertEqual(qc.STATIC_LIST_SCORES["firehol_level2"], 50)

    def test_bruteforceblocker_source_registered(self):
        """REP-4：bruteforceblocker 默认启用、有权重/静态分。

        SSH 爆破榜（同 blocklist_de_ssh 信号族）：abuse 票，静态 45，权重 3。
        """
        self.assertIn("bruteforceblocker", qc.DEFAULT_REP_SOURCES)
        self.assertIn("bruteforceblocker", qc.REPUTATION_WEIGHTS)
        self.assertIn("bruteforceblocker", qc.STATIC_LIST_SCORES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["bruteforceblocker"], 0)
        self.assertEqual(
            qr._flag_opinions("bruteforceblocker", {"is_abuse": True}),
            {"abuse": True})
        self.assertEqual(qc.source_score("bruteforceblocker", {}), None)
        self.assertEqual(
            qc.source_score("bruteforceblocker", {"is_abuse": True}),
            qc.STATIC_LIST_SCORES["bruteforceblocker"])
        self.assertEqual(qc.STATIC_LIST_SCORES["bruteforceblocker"], 45)

    def test_firehol_level2_fetch_uses_default_timeout(self):
        """REP-3：365KB 小表用默认静态超时；URL 为 level2 netset。"""
        calls = []

        def fake(url, timeout, headers=None, max_bytes=None):
            calls.append((url, timeout))
            return b"1.2.3.4\n"

        with unittest.mock.patch.object(qr, "fetch_with_mirror",
                                        side_effect=fake):
            got = asyncio.run(qr.fetch_firehol_level2())
        self.assertEqual(len(calls), 1)
        self.assertIn("firehol_level2", calls[0][0])
        self.assertEqual(calls[0][1], qr.STATIC_LIST_TIMEOUT)
        self.assertEqual(len(got), 1)

    def test_bruteforceblocker_fetch_strips_inline_comments(self):
        """REP-4：`IP # 时间 次数 ID` 行内注释取首列；URL 为 blist.php。"""
        calls = []

        def fake(url, timeout, headers=None, max_bytes=None):
            calls.append((url, timeout))
            return ("171.231.185.91\t\t# 2026-09-17 10:44:35\t\t25\t2853450\n"
                    "# comment line\n").encode()

        with unittest.mock.patch.object(qr, "fetch_with_mirror",
                                        side_effect=fake):
            got = asyncio.run(qr.fetch_bruteforceblocker())
        self.assertEqual(len(calls), 1)
        self.assertIn("blist.php", calls[0][0])
        self.assertEqual(calls[0][1], qr.STATIC_LIST_TIMEOUT)
        self.assertIn("171.231.185.91", got)
        self.assertEqual(len(got), 1)

    def test_dataplane_vncrfb_source_registered(self):
        """REP-5：dataplane_vncrfb 默认启用、有权重/静态分。

        VNC 爆破榜（新信号族）：abuse 票，静态 45，权重 3。
        """
        self.assertIn("dataplane_vncrfb", qc.DEFAULT_REP_SOURCES)
        self.assertIn("dataplane_vncrfb", qc.REPUTATION_WEIGHTS)
        self.assertIn("dataplane_vncrfb", qc.STATIC_LIST_SCORES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["dataplane_vncrfb"], 0)
        self.assertEqual(
            qr._flag_opinions("dataplane_vncrfb", {"is_abuse": True}),
            {"abuse": True})
        self.assertEqual(qc.source_score("dataplane_vncrfb", {}), None)
        self.assertEqual(
            qc.source_score("dataplane_vncrfb", {"is_abuse": True}),
            qc.STATIC_LIST_SCORES["dataplane_vncrfb"])
        self.assertEqual(qc.STATIC_LIST_SCORES["dataplane_vncrfb"], 45)

    def test_dataplane_vncrfb_fetch_takes_third_pipe_field(self):
        """REP-5：`count | org | IP | …` 取第 3 字段；URL 为 vncrfb.txt。"""
        calls = []

        def fake(url, timeout, headers=None, max_bytes=None):
            calls.append((url, timeout))
            return ("14 | ORG | 1.2.3.4 | 2026-09-18 | vncrfb\n"
                    "# comment\nshort|only\n").encode()

        with unittest.mock.patch.object(qr, "fetch_with_mirror",
                                        side_effect=fake):
            got = asyncio.run(qr.fetch_dataplane_vncrfb())
        self.assertEqual(len(calls), 1)
        self.assertIn("vncrfb.txt", calls[0][0])
        self.assertEqual(calls[0][1], qr.STATIC_LIST_TIMEOUT)
        self.assertIn("1.2.3.4", got)
        self.assertEqual(len(got), 1)

    def test_drb_c2_source_registered(self):
        """REP-6：drb_c2 默认启用、有权重/静态分。

        30 天审核 C2：abuse 票，静态 50，权重 4。
        """
        self.assertIn("drb_c2", qc.DEFAULT_REP_SOURCES)
        self.assertIn("drb_c2", qc.REPUTATION_WEIGHTS)
        self.assertIn("drb_c2", qc.STATIC_LIST_SCORES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["drb_c2"], 0)
        self.assertEqual(
            qr._flag_opinions("drb_c2", {"is_abuse": True}),
            {"abuse": True})
        self.assertEqual(qc.source_score("drb_c2", {}), None)
        self.assertEqual(
            qc.source_score("drb_c2", {"is_abuse": True}),
            qc.STATIC_LIST_SCORES["drb_c2"])
        self.assertEqual(qc.STATIC_LIST_SCORES["drb_c2"], 50)

    def test_drb_c2_fetch_takes_first_csv_column(self):
        """REP-6：`IP,描述` 取首列；URL 为 IPC2s-30day.csv。"""
        calls = []

        def fake(url, timeout, headers=None, max_bytes=None):
            calls.append((url, timeout))
            return ("#ip,ioc\n1.15.76.39,Possible Cobaltstrike C2 IP\n"
                    ).encode()

        with unittest.mock.patch.object(qr, "fetch_with_mirror",
                                        side_effect=fake):
            got = asyncio.run(qr.fetch_drb_c2())
        self.assertEqual(len(calls), 1)
        self.assertIn("IPC2s-30day.csv", calls[0][0])
        self.assertEqual(calls[0][1], qr.STATIC_LIST_TIMEOUT)
        self.assertIn("1.15.76.39", got)
        self.assertEqual(len(got), 1)

    def test_nordvpn_exits_source_registered(self):
        """REP-7：nordvpn_exits 默认启用、有权重/静态分。

        NordVPN 出口表（日更）：vpn 票，静态 55，权重 3。
        """
        self.assertIn("nordvpn_exits", qc.DEFAULT_REP_SOURCES)
        self.assertIn("nordvpn_exits", qc.REPUTATION_WEIGHTS)
        self.assertIn("nordvpn_exits", qc.STATIC_LIST_SCORES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["nordvpn_exits"], 0)
        self.assertEqual(
            qr._flag_opinions("nordvpn_exits", {"is_vpn": True}),
            {"vpn": True})
        self.assertEqual(qc.source_score("nordvpn_exits", {}), None)
        self.assertEqual(
            qc.source_score("nordvpn_exits", {"is_vpn": True}),
            qc.STATIC_LIST_SCORES["nordvpn_exits"])
        self.assertEqual(qc.STATIC_LIST_SCORES["nordvpn_exits"], 55)

    def test_nordvpn_exits_fetch_takes_first_csv_column(self):
        """REP-7：`IP,描述` 取首列；URL 为 NordVPNIPs.csv。"""
        calls = []

        def fake(url, timeout, headers=None, max_bytes=None):
            calls.append((url, timeout))
            return ("#ip,status\n89.35.28.131,NordVPN IP\n").encode()

        with unittest.mock.patch.object(qr, "fetch_with_mirror",
                                        side_effect=fake):
            got = asyncio.run(qr.fetch_nordvpn_exits())
        self.assertEqual(len(calls), 1)
        self.assertIn("NordVPNIPs.csv", calls[0][0])
        self.assertEqual(calls[0][1], qr.STATIC_LIST_TIMEOUT)
        self.assertIn("89.35.28.131", got)
        self.assertEqual(len(got), 1)

    def test_blackhole_monster_source_registered(self):
        """REP-8：blackhole_monster 默认启用、有权重/静态分。

        每日攻击者裸 IP（Maltrail 定性）：abuse 票，静态 50，权重 4。
        """
        self.assertIn("blackhole_monster", qc.DEFAULT_REP_SOURCES)
        self.assertIn("blackhole_monster", qc.REPUTATION_WEIGHTS)
        self.assertIn("blackhole_monster", qc.STATIC_LIST_SCORES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["blackhole_monster"], 0)
        self.assertEqual(
            qr._flag_opinions("blackhole_monster", {"is_abuse": True}),
            {"abuse": True})
        self.assertEqual(qc.source_score("blackhole_monster", {}), None)
        self.assertEqual(
            qc.source_score("blackhole_monster", {"is_abuse": True}),
            qc.STATIC_LIST_SCORES["blackhole_monster"])
        self.assertEqual(qc.STATIC_LIST_SCORES["blackhole_monster"], 50)

    def test_blackhole_monster_fetch_bare_ips(self):
        """REP-8：裸 IP 直取；URL 为 blackhole-today。"""
        calls = []

        def fake(url, timeout, headers=None, max_bytes=None):
            calls.append((url, timeout))
            return b"1.14.69.226\n"

        with unittest.mock.patch.object(qr, "fetch_with_mirror",
                                        side_effect=fake):
            got = asyncio.run(qr.fetch_blackhole_monster())
        self.assertEqual(len(calls), 1)
        self.assertIn("blackhole-today", calls[0][0])
        self.assertEqual(calls[0][1], qr.STATIC_LIST_TIMEOUT)
        self.assertIn("1.14.69.226", got)
        self.assertEqual(len(got), 1)

    def test_myipms_blacklist_source_registered(self):
        """REP-9：myipms_blacklist 默认启用、有权重/静态分。

        10 天攻击源 htaccess：abuse 票，静态 50，权重 4。
        """
        self.assertIn("myipms_blacklist", qc.DEFAULT_REP_SOURCES)
        self.assertIn("myipms_blacklist", qc.REPUTATION_WEIGHTS)
        self.assertIn("myipms_blacklist", qc.STATIC_LIST_SCORES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["myipms_blacklist"], 0)
        self.assertEqual(
            qr._flag_opinions("myipms_blacklist", {"is_abuse": True}),
            {"abuse": True})
        self.assertEqual(qc.source_score("myipms_blacklist", {}), None)
        self.assertEqual(
            qc.source_score("myipms_blacklist", {"is_abuse": True}),
            qc.STATIC_LIST_SCORES["myipms_blacklist"])
        self.assertEqual(qc.STATIC_LIST_SCORES["myipms_blacklist"], 50)

    def test_myipms_blacklist_fetch_takes_deny_from_column(self):
        """REP-9：`deny from IP` 取第 3 列；URL 为 latest_blacklist.txt。"""
        calls = []

        def fake(url, timeout, headers=None, max_bytes=None):
            calls.append((url, timeout))
            return b"# comment\ndeny from 156.59.198.135\nallow from 9.9.9.9\n"

        with unittest.mock.patch.object(qr, "fetch_with_mirror",
                                        side_effect=fake):
            got = asyncio.run(qr.fetch_myipms_blacklist())
        self.assertEqual(len(calls), 1)
        self.assertIn("latest_blacklist.txt", calls[0][0])
        self.assertEqual(calls[0][1], qr.STATIC_LIST_TIMEOUT)
        self.assertIn("156.59.198.135", got)
        self.assertEqual(len(got), 1)

    def test_ipnoise_source_registered(self):
        """REP-10：ipnoise 默认启用、有权重/静态分。

        7 天蜜罐攻击者：abuse 票，静态 50，权重 4。
        """
        self.assertIn("ipnoise", qc.DEFAULT_REP_SOURCES)
        self.assertIn("ipnoise", qc.REPUTATION_WEIGHTS)
        self.assertIn("ipnoise", qc.STATIC_LIST_SCORES)
        self.assertGreater(qc.REPUTATION_WEIGHTS["ipnoise"], 0)
        self.assertEqual(
            qr._flag_opinions("ipnoise", {"is_abuse": True}),
            {"abuse": True})
        self.assertEqual(qc.source_score("ipnoise", {}), None)
        self.assertEqual(
            qc.source_score("ipnoise", {"is_abuse": True}),
            qc.STATIC_LIST_SCORES["ipnoise"])
        self.assertEqual(qc.STATIC_LIST_SCORES["ipnoise"], 50)

    def test_ipnoise_fetch_bare_ips(self):
        """REP-10：裸 IP 直取（`#` 注释行跳过）；URL 为 7d.txt。"""
        calls = []

        def fake(url, timeout, headers=None, max_bytes=None):
            calls.append((url, timeout))
            return b"# Title: IPnoise\n1.2.3.4\n"

        with unittest.mock.patch.object(qr, "fetch_with_mirror",
                                        side_effect=fake):
            got = asyncio.run(qr.fetch_ipnoise())
        self.assertEqual(len(calls), 1)
        self.assertIn("7d.txt", calls[0][0])
        self.assertEqual(calls[0][1], qr.STATIC_LIST_TIMEOUT)
        self.assertIn("1.2.3.4", got)
        self.assertEqual(len(got), 1)

    def test_abuseipdb_public_fetch_uses_large_timeout(self):
        """R259：8.2MB 列表用独立放宽超时，慢网不致统一 15s fail-open。"""
        calls = []

        def fake(url, timeout, headers=None, max_bytes=None):
            calls.append((url, timeout))
            return b"1.2.3.4\n5.6.7.8\n"

        with unittest.mock.patch.object(qr, "fetch_with_mirror",
                                        side_effect=fake):
            got = asyncio.run(qr.fetch_abuseipdb_public())
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], qr.ABUSEIPDB_PUBLIC_TIMEOUT)
        self.assertGreater(qr.ABUSEIPDB_PUBLIC_TIMEOUT,
                           qr.STATIC_LIST_TIMEOUT)
        self.assertEqual(len(got), 2)

    def test_docs_enumerate_all_sources(self):
        """R256：docs/logic.md 与 docs/scripts.md 必须命名每个信誉源。

        防新增源（权重/静态）时漏同步文档；loop-state 认为「可发现性」是
        文档契约的一部分。源名以字面出现即通过（含 per-IP 表与静态表）。"""
        root = Path(__file__).resolve().parents[1]
        logic = (root / "docs" / "logic.md").read_text(encoding="utf-8")
        scripts = (root / "docs" / "scripts.md").read_text(encoding="utf-8")
        for name in qr.REPUTATION_WEIGHTS:
            self.assertIn(
                name, logic,
                f"docs/logic.md 缺少信誉源 {name}")
            self.assertIn(
                name, scripts,
                f"docs/scripts.md 缺少信誉源 {name}")

    def test_default_sources_match_docs(self):
        """R277：`--reputation-sources` 文档默认值必须与代码
        `DEFAULT_REP_SOURCES` 集合全等。

        防退默认（R270 whatismyip / R271 vpn_ips）只改代码漏改文档——
        R256 枚举测试只查源名出现，拦不住默认集漂移。用集合比对，
        opt-in 源（spamrats/sorbs/uceprotect/psbl 等）两边都不含。"""
        root = Path(__file__).resolve().parents[1]
        scripts = (root / "docs" / "scripts.md").read_text(encoding="utf-8")
        m = re.search(
            r"\| `--reputation-sources` \|[^\n]*\| ([^|]+) \|", scripts)
        self.assertIsNotNone(m, "docs 默认源清单行解析失败")
        doc_default = set(m.group(1).strip().split(","))
        self.assertEqual(doc_default, set(qr.DEFAULT_REP_SOURCES))
        for name in ("whatismyip", "vpn_ips", "spamrats", "sorbs",
                     "uceprotect", "psbl"):
            self.assertNotIn(name, qr.DEFAULT_REP_SOURCES, name)
            self.assertIn(name, qr.REPUTATION_WEIGHTS, name)

    def test_doc_section_refs_resolve(self):
        """R295：文档章节引用（如 `logic.md §4.0`）必须指向真实标题。

        防标题重编号后引用悬空。扫描 README＋docs 全文（现仅两处：
        §4.0 出口 IP 解析、§7.2 三数据源），逐条解析。"""
        root = Path(__file__).resolve().parents[1]
        files = [root / "README.md"] + sorted((root / "docs").glob("*.md"))
        refs = set()
        for f in files:
            refs |= set(re.findall(
                r"([a-z][a-z0-9-]*\.md) §(\d+(?:\.\d+)*)",
                f.read_text(encoding="utf-8")))
        self.assertTrue(refs, "未扫到任何章节引用，扫描器可能失效")
        header_re = re.compile(r"^#{1,4}\s+(\d+(?:\.\d+)*)\b", re.M)
        for doc, sec in sorted(refs):
            text = (root / "docs" / doc
                    if (root / "docs" / doc).exists()
                    else root / doc).read_text(encoding="utf-8")
            headers = set(header_re.findall(text))
            self.assertIn(
                sec, headers, f"{doc} §{sec} 无对应标题")

    def test_all_weight_sources_have_dispatch(self):
        """R263：每个 REPUTATION_WEIGHTS 源必须有 ``if "<name>" in sources``
        派发分支，且每个静态分源都在权重表内。

        防「新增源只登记权重、忘接派发」→ 该源静默空转（永不查询/投票），
        分数被悄悄拉低却无任何报错。以源码文本做静态不变量校验。"""
        root = Path(__file__).resolve().parents[1]
        src = (root / "scripts" / "quality_reputation.py").read_text(
            encoding="utf-8")
        weights_match = re.search(
            r"REPUTATION_WEIGHTS\s*=\s*\{(.*?)\n\}", src, re.S)
        self.assertIsNotNone(weights_match)
        weight_keys = re.findall(
            r'"([a-z0-9_]+)"\s*:', weights_match.group(1))
        dispatched = set(re.findall(r'if "([a-z0-9_]+)" in sources', src))
        self.assertEqual(
            set(weight_keys) - dispatched, set(),
            "REPUTATION_WEIGHTS 中的源缺派发分支")
        static_match = re.search(
            r"STATIC_LIST_SCORES\s*=\s*\{(.*?)\n\}", src, re.S)
        self.assertIsNotNone(static_match)
        static_keys = set(re.findall(
            r'"([a-z0-9_]+)"\s*:', static_match.group(1)))
        self.assertEqual(
            static_keys - set(weight_keys), set(),
            "STATIC_LIST_SCORES 含不在权重表内的源")

    def test_parse_reputation_sources_unknown_warned(self):
        """R260：未知源名返回 unknown 供告警，合法源过滤保留；
        全错（无合法源）回退默认全集——typo 不再静默无提示。"""
        srcs, unknown = qc.parse_reputation_sources("dnsbl,dnslb, cins")
        self.assertEqual(srcs, ["dnsbl", "cins"])
        self.assertEqual(unknown, ["dnslb"])
        srcs, unknown = qc.parse_reputation_sources("dnslb,typo")
        self.assertEqual(srcs, list(qc.DEFAULT_REP_SOURCES))
        self.assertEqual(unknown, ["dnslb", "typo"])
        self.assertEqual(qc.parse_reputation_sources("")[0],
                         list(qc.DEFAULT_REP_SOURCES))
        self.assertEqual(qc.parse_reputation_sources("", "none")[0], [])
        self.assertEqual(qc.parse_reputation_sources("", "netcoffee")[0],
                         ["netcoffee", "ip-api"])
        self.assertEqual(qc.parse_reputation_sources("", "ip-api")[0],
                         ["ip-api"])

    def test_parse_reputation_weights_unknown_warned(self):
        """R261：权重覆盖对未知源名/无冒号片段告警并丢弃，
        不再静默新增 dict 键让 typo 权重悄悄不生效。"""
        base = dict(qr.REPUTATION_WEIGHTS)
        w, unknown = qc.parse_reputation_weights(
            "dnsbl:12, netoffee:40, ,foo:9, bare", base=dict(base))
        self.assertEqual(w["dnsbl"], 12)
        self.assertNotIn("netoffee", w)
        self.assertNotIn("foo", w)
        self.assertEqual(unknown, ["netoffee:40", "foo:9", "bare"])
        w2, unk2 = qc.parse_reputation_weights("netcoffee:abc")
        self.assertEqual(unk2, [])
        self.assertEqual(w2["netcoffee"], base["netcoffee"])
        w3, unk3 = qc.parse_reputation_weights("")
        self.assertEqual(w3, base)
        self.assertEqual(unk3, [])

    def test_static_list_size_report(self):
        """R253：静态源尺寸上报——非空打印逐源大小，全空打印 all empty，
        便于 R245 式死源审计（空列表静默 = 不可发现）。

        R255 补充：**已启用但为空/拉取失败（fail-open）的静态源以
        ``<name>=0`` 显式列出**，可与「未启用」区分；未启用的源即使被
        fetch 返回也绝不入报。"""
        seed_keys = (
            "abuse_list", "dc_asn", "vpn_asn", "resproxy_asn", "tor_exit",
            "spamhaus", "cins", "et_compromised", "feodo", "blocklist_de",
            "blocklist_de_ssh", "blocklist_de_apache", "danmeuk_tor",
            "tor_bulk", "urlhaus", "threatfox", "firehol_level1",
            "binarydefense", "c2_tracker", "botscout", "greensnow",
            "sslproxies", "socks_proxy", "vpn_ips", "dshield",
            "abuseipdb_public", "wwuyi_unreachable", "wwuyi_blocked",
            "firehol_level2", "bruteforceblocker", "dataplane_vncrfb",
            "drb_c2", "nordvpn_exits", "blackhole_monster",
            "myipms_blacklist", "ipnoise",
        )

        def fake_static(sources):
            d = {}
            for k in seed_keys:
                d[k] = qr.IpSet() if k != "dc_asn" else set()
                if k in ("vpn_asn", "resproxy_asn"):
                    d[k] = set()
            d["cins"] = qr.IpSet(["1.1.1.1", "2.2.2.2"])
            d["dshield"] = qr.IpSet(["3.3.3.3"])  # 未启用源也要被忽略
            return d

        args = argparse.Namespace(
            reputation_sources=["cins", "abuse_list"],
            no_rep_cache=True, rep_cache_ttl=0, getipintel_email="",
        )
        with unittest.mock.patch.object(qr, "fetch_static_lists",
                                        side_effect=fake_static), \
             unittest.mock.patch.object(qr, "fetch_ipsum_list",
                                        return_value=set()), \
             contextlib.redirect_stdout(io.StringIO()) as buf:
            asyncio.run(qr.lookup_all_risk(["1.1.1.1"], args))
        out = buf.getvalue()
        # 非空 + 空全列出（abuse_list=0 表明已启用但本次零命中/拉取失败），
        # 未启用的 dshield 即使非空也不入报。
        self.assertIn("Reputation static lists: abuse_list=0, cins=2", out)
        self.assertNotIn("dshield", out)
        self.assertNotIn("all empty", out)

        def fake_empty(sources):
            d = fake_static(sources)
            d["cins"] = qr.IpSet()
            d["dshield"] = qr.IpSet()
            return d

        with unittest.mock.patch.object(qr, "fetch_static_lists",
                                        side_effect=fake_empty), \
             unittest.mock.patch.object(qr, "fetch_ipsum_list",
                                        return_value=set()), \
             contextlib.redirect_stdout(io.StringIO()) as buf2:
            asyncio.run(qr.lookup_all_risk(["1.1.1.1"], args))
        self.assertIn("all empty", buf2.getvalue())

    def test_batch_cap_truncation_reported(self):
        """R257：cap 截断可见性——need>cap 时日志带 cap-truncated N。

        缓存大面积失效/退出池增长时，dnsbl(12000) 等带 cap 源会静默只查
        前 cap 个 IP；此前日志报的是传入 need 数，截断不可见，审计会误判
        覆盖率。现在多余量显式标出，且返回集确实只含前 cap 个。"""
        args = argparse.Namespace(
            reputation_sources=["dnsbl"],
            no_rep_cache=True, rep_cache_ttl=0, getipintel_email="",
        )
        ips = [f"10.0.{i}.{j}" for i in range(2) for j in (1, 2, 3)]
        with unittest.mock.patch.object(qr, "DNSBL_ZEN_CAP", 2), \
             unittest.mock.patch.object(
                 qr, "dnsbl_lookup_sync",
                 side_effect=lambda ip: {"is_listed": True, "dnsbl_code": 2}
             ), \
             contextlib.redirect_stdout(io.StringIO()) as buf:
            risk = asyncio.run(qr.lookup_all_risk(ips, args))
        out = buf.getvalue()
        self.assertIn("Reputation source dnsbl:", out)
        self.assertIn("6 need, 2 queried", out)
        self.assertIn("cap-truncated 4", out)
        self.assertEqual(len(risk), 2)

    def test_batch_cap_priority_unseen_first(self):
        """R258：cap 压力下优先查询从未有过信号的 IP。

        有旧缓存（过期、fallback 可用）的 IP 被截断时仍有兜底注入；绝无
        信号的新 IP 被截断则本轮完全无该源覆盖。排序让「无兜底新 IP」排
        前，cap=1 时应只查新 IP、旧 IP 走 stale fallback。"""
        args = argparse.Namespace(
            reputation_sources=["dnsbl"],
            no_rep_cache=False, rep_cache_ttl=604800,
            getipintel_email="",
        )
        stale_ts = time.time() - 1_000_000  # 远超 7 天 TTL → 过期
        seed = {
            "10.0.0.1": {  # 有旧缓存（过期但有信号 → fallback）
                "dnsbl": {"ts": stale_ts,
                          "data": {"is_listed": True, "dnsbl_code": 2}},
            },
        }
        calls = []

        def stub(ip):
            calls.append(ip)
            return {"is_listed": True, "dnsbl_code": 2}

        with unittest.mock.patch.object(qr, "load_rep_cache",
                                        return_value=seed), \
             unittest.mock.patch.object(qr, "save_rep_cache",
                                        lambda _c: None), \
             unittest.mock.patch.object(qr, "DNSBL_ZEN_CAP", 1), \
             unittest.mock.patch.object(qr, "dnsbl_lookup_sync",
                                        side_effect=stub), \
             contextlib.redirect_stdout(io.StringIO()) as buf:
            risk = asyncio.run(
                qr.lookup_all_risk(["10.0.0.1", "10.0.0.2"], args))
        # 只查了从未有信号的 10.0.0.2；10.0.0.1 未在线补查。
        self.assertEqual(calls, ["10.0.0.2"])
        self.assertIn("2 need, 1 queried, 1 resolved",
                      buf.getvalue())
        self.assertIn("cap-truncated 1", buf.getvalue())
        # 旧信号以 fallback 注入，10.0.0.1 仍出信号而不丢覆盖。
        self.assertIn("dnsbl", risk.get("10.0.0.1", {}))
        self.assertIn("dnsbl", risk.get("10.0.0.2", {}))

    def test_new_rep_abuse_sources_vote_abuse(self):
        """c2_tracker/botscout/greensnow 命中 → abuse 维度。"""
        for name in ("c2_tracker", "botscout", "greensnow"):
            self.assertEqual(
                qr._flag_opinions(name, {"is_abuse": True}), {"abuse": True})
            self.assertEqual(
                qc.source_score(name, {"is_abuse": True}),
                qc.STATIC_LIST_SCORES[name])
            self.assertIsNone(qc.source_score(name, {}))

    def test_new_rep_proxy_sources_vote_proxy(self):
        """sslproxies/socks_proxy 命中 → proxy 维度（独立代理族证据）。"""
        for name in ("sslproxies", "socks_proxy"):
            self.assertEqual(
                qr._flag_opinions(name, {"is_proxy": True}), {"proxy": True})
            self.assertEqual(
                qc.source_score(name, {"is_proxy": True}),
                qc.STATIC_LIST_SCORES[name])
            self.assertIsNone(qc.source_score(name, {}))

    def test_fetch_static_lists_new_sources_wired2(self):
        """fetch_static_lists 能取到 5 个新静态源。"""
        def _set(items):
            return qr.IpSet(items)
        with unittest.mock.patch.object(
                qr, "fetch_c2_tracker",
                new=unittest.mock.AsyncMock(side_effect=lambda: _set(["10.0.0.1"]))), \
             unittest.mock.patch.object(
                qr, "fetch_botscout",
                new=unittest.mock.AsyncMock(side_effect=lambda: _set(["10.0.0.2"]))), \
             unittest.mock.patch.object(
                qr, "fetch_greensnow",
                new=unittest.mock.AsyncMock(side_effect=lambda: _set(["10.0.0.3"]))), \
             unittest.mock.patch.object(
                qr, "fetch_sslproxies",
                new=unittest.mock.AsyncMock(side_effect=lambda: _set(["10.0.0.4"]))), \
             unittest.mock.patch.object(
                qr, "fetch_socks_proxy",
                new=unittest.mock.AsyncMock(side_effect=lambda: _set(["10.0.0.5"]))):
            out = asyncio.run(
                qr.fetch_static_lists(["c2_tracker", "botscout", "greensnow",
                                       "sslproxies", "socks_proxy"]))
        self.assertIn("10.0.0.1", out["c2_tracker"])
        self.assertIn("10.0.0.2", out["botscout"])
        self.assertIn("10.0.0.3", out["greensnow"])
        self.assertIn("10.0.0.4", out["sslproxies"])
        self.assertIn("10.0.0.5", out["socks_proxy"])

    def test_cache_cap_tiles(self):
        """REP_CACHE_MAX 裁剪逻辑：超阈值仅保留最新 REP_CACHE_MAX 项。"""
        import time
        cache = {}
        now = time.time()
        for i in range(qc.REP_CACHE_MAX + 25):
            cache[f"10.0.{i >> 8}.{i & 255}"] = {
                "netcoffee": {"ts": now - i, "data": {"trust_score": 60}}
            }
        # 复现 lookup_all_risk 的 TTL 裁剪 + 封顶分支
        ttl = 7 * 86400
        pruned = {}
        for ip, entry in cache.items():
            fresh = {src: e for src, e in entry.items()
                     if (e.get("ts") or 0) + ttl >= now}
            if fresh:
                pruned[ip] = fresh
        self.assertGreater(len(pruned), qc.REP_CACHE_MAX)
        if len(pruned) > qc.REP_CACHE_MAX:
            def last_ts(item) -> float:
                _ip, entry = item
                return max((e.get("ts") or 0 for e in entry.values()
                            if isinstance(e, dict)), default=0.0)
            for ip, _ in sorted(pruned.items(), key=last_ts,
                                reverse=True)[qc.REP_CACHE_MAX:]:
                del pruned[ip]
        self.assertEqual(len(pruned), qc.REP_CACHE_MAX)

    def test_mobile_bonus_only_when_otherwise_clean(self):
        sigs = {"ip-api": {"proxy": False, "hosting": False, "mobile": True}}
        self.assertEqual(qc.compute_reputation(sigs, None, self.W), 100)
        sigs = {"ip-api": {"proxy": False, "hosting": True, "mobile": True}}
        # 有 hosting 标记则不加成
        self.assertEqual(qc.compute_reputation(sigs, None, self.W), 90)

    def test_reputation_risk_boundaries(self):
        self.assertEqual(qc.reputation_risk(0), "high")
        self.assertEqual(qc.reputation_risk(29), "high")
        self.assertEqual(qc.reputation_risk(30), "medium")
        self.assertEqual(qc.reputation_risk(74), "medium")
        self.assertEqual(qc.reputation_risk(75), "low")
        self.assertEqual(qc.reputation_risk(100), "low")
        self.assertIsNone(qc.reputation_risk(None))

    def test_build_reputation_map(self):
        results = {
            "1.2.3.4:443#US": {
                "key": "1.2.3.4:443#US", "ip": "1.2.3.4",
            },
            "5.6.7.8:8443#JP": {
                "key": "5.6.7.8:8443#JP", "ip": "5.6.7.8",
            },
        }
        risk_data = {"5.6.7.8": {"netcoffee": {"trust_score": 70}}}
        rep = qc.build_reputation_map(results, risk_data, self.W)
        self.assertNotIn("1.2.3.4:443#US", rep)
        self.assertEqual(rep["5.6.7.8:8443#JP"]["score"], 70)
        self.assertEqual(rep["5.6.7.8:8443#JP"]["source"], "netcoffee")
        self.assertEqual(rep["5.6.7.8:8443#JP"]["sources"], ["netcoffee"])

    def test_deep_speed_bonus(self):
        results = {"a": {"key": "a", "ip": "1.1.1.1"}}
        risk_data = {"1.1.1.1": {"netcoffee": {"trust_score": 70}}}
        deep = {"proxies": {
            "a": {"cdnjs": {"agg_mbps": 25.0}, "ovh": {"agg_mbps": 50.0}},
        }}
        rep = qc.build_reputation_map(results, risk_data, self.W, deep)
        # 最优目标 50MB/s → +10 满额加成
        self.assertEqual(rep["a"]["score"], 80)
        self.assertEqual(rep["a"]["deep_bonus"], 10)

    def test_deep_speed_bonus_scales_and_caps(self):
        results = {"a": {"key": "a", "ip": "1.1.1.1"},
                   "b": {"key": "b", "ip": "2.2.2.2"},
                   "c": {"key": "c", "ip": "3.3.3.3"}}
        risk_data = {ip: {"netcoffee": {"trust_score": 70}}
                     for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3")}
        deep = {"proxies": {
            "a": {"cdnjs": {"agg_mbps": 12.5}},   # 半额
            "b": {"cdnjs": {"agg_mbps": 500.0}},  # 封顶
            "c": {"ovh": {"streams_ok": 0}},      # 无带宽观测
        }}
        rep = qc.build_reputation_map(results, risk_data, self.W, deep)
        self.assertEqual(rep["a"]["deep_bonus"], 2)   # round(12.5/50*10) 银行家舍入
        self.assertEqual(rep["b"]["score"], 80)
        self.assertNotIn("deep_bonus", rep["c"])

    def test_deep_speed_no_ghost_scores(self):
        """深测是抽样：无信誉分来源的节点不得凭带宽产生分数。"""
        results = {"a": {"key": "a", "ip": "9.9.9.9"}}
        deep = {"proxies": {"a": {"cdnjs": {"agg_mbps": 99.0}}}}
        rep = qc.build_reputation_map(results, {}, self.W, deep)
        self.assertNotIn("a", rep)

    def test_deep_speed_stale_produces_no_bonus(self):
        """read_fresh 判过期返回 None → 消费端整链无带宽加分（组合契约）。"""
        results = {"a": {"key": "a", "ip": "1.1.1.1"}}
        risk_data = {"1.1.1.1": {"netcoffee": {"trust_score": 70}}}
        rep = qc.build_reputation_map(results, risk_data, self.W, None)
        self.assertEqual(rep["a"]["score"], 70)
        self.assertNotIn("deep_bonus", rep["a"])

    def test_netcoffee_lookup_parsing(self):
        payload = (
            b'{"trust_score":61,"is_datacenter":true,"is_vpn":false,'
            b'"is_proxy":false,"is_tor":false,"is_abuser":false,'
            b'"is_mobile":false,"is_crawler":false,"isResidential":false}'
        )

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return payload

        def fake_urlopen(req, timeout=0):
            self.assertIn("iprisk/1.2.3.4", req.full_url)
            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.netcoffee_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out["trust_score"], 61)
        self.assertTrue(out["is_datacenter"])
        self.assertFalse(out["is_vpn"])

    def test_netcoffee_lookup_empty(self):
        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return b"{}"

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            self.assertIsNone(qc.netcoffee_lookup_sync("1.2.3.4"))
        finally:
            qc.urllib.request.urlopen = orig

    def test_ncgy_lookup_parsing(self):
        payload = (
            b'{"ip":"1.2.3.4","proxy":{"is_proxy":true,"is_vpn":false,'
            b'"is_tor":false,"is_hosting":true,"is_cdn":false,'
            b'"is_school":false,"is_anonymous":true}}'
        )

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return payload

        def fake_urlopen(req, timeout=0):
            self.assertIn("nc.gy", req.full_url)
            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.ncgy_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertTrue(out["is_proxy"])
        self.assertTrue(out["is_hosting"])
        self.assertTrue(out["is_anonymous"])
        self.assertFalse(out["is_vpn"])

    def test_ncgy_lookup_clean(self):
        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return (
                        b'{"ip":"1.2.3.4","proxy":{"is_proxy":false,'
                        b'"is_vpn":false,"is_tor":false,"is_hosting":false,'
                        b'"is_cdn":false,"is_school":false,'
                        b'"is_anonymous":false}}'
                    )

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.ncgy_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out, {"clean": True})

    def test_getipintel_lookup(self):
        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return b"0.25"

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.getipintel_lookup_sync("1.2.3.4", "a@b.com")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out, {"probability": 0.25})

    def test_getipintel_error_none(self):
        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return b"-5"

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            self.assertIsNone(qc.getipintel_lookup_sync("1.2.3.4", "a@b.com"))
        finally:
            qc.urllib.request.urlopen = orig

    def test_netcoffee_enriched_fields(self):
        payload = (
            b'{"trust_score":61,"is_datacenter":true,"company_type":"hosting",'
            b'"asn_kind":"hosting","abuser_score":"0.35 (High)"}'
        )

        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.netcoffee_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out["company_type"], "hosting")
        self.assertEqual(out["asn_kind"], "hosting")
        self.assertEqual(out["abuser_score"], 0.35)

    def test_ipapi_is_enriched_fields(self):
        payload = (
            b'{"is_datacenter":false,"is_vpn":true,"is_abuser":false,'
            b'"company":{"type":"hosting","abuser_score":"0.50 (Medium)"},'
            b'"asn":{"type":"hosting","abuser_score":"0.20 (Medium)"}}'
        )

        def fake_urlopen(req, timeout=0):
            self.assertIn("api.ipapi.is", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.ipapi_is_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertTrue(out["is_vpn"])
        self.assertEqual(out["company_type"], "hosting")
        self.assertEqual(out["asn_type"], "hosting")
        self.assertEqual(out["company_abuser_score"], 0.50)
        self.assertEqual(out["asn_abuser_score"], 0.20)

    def test_ipquery_lookup_parsing(self):
        payload = (
            b'{"risk":{"is_mobile":false,"is_vpn":true,"is_tor":false,'
            b'"is_proxy":false,"is_datacenter":true,"risk_score":35},'
            b'"isp":{"asn":"AS15169","org":"Google LLC","isp":"Google"}}'
        )

        def fake_urlopen(req, timeout=0):
            self.assertIn("api.ipquery.io/1.2.3.4", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.ipquery_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertTrue(out["is_vpn"])
        self.assertTrue(out["is_datacenter"])
        self.assertEqual(out["risk_score"], 35)
        self.assertEqual(out["asn"], "AS15169")

    def test_ipwhois_lookup_parsing(self):
        # R242 回归：IPWHOIS_URL 用命名占位符 {ip}，URL 构造须 .format(ip=ip)，
        # 否则每次调用 KeyError，源 100% 失效（实测 rep_sources 中从不出现）。
        payload = (
            b'{"success":true,"connection":{"asn":36352,"type":"Hosting"},'
            b'"security":{"anonymous":false,"proxy":false,"vpn":false,'
            b'"tor":false,"hosting":true}}'
        )

        def fake_urlopen(req, timeout=0):
            self.assertIn("ipwhois.app/json/1.2.3.4", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.ipwhois_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out["connection_type"], "Hosting")
        self.assertTrue(out["security"]["hosting"])
        self.assertEqual(out["asn"], "AS36352")
        flags = qr._flag_opinions("ipwhois", out)
        self.assertTrue(flags["hosting"])
        self.assertFalse(flags["proxy"])

    def test_stopforumspam_lookup_parsing(self):
        payload = (
            b'{"success":1,"ip":{"value":"1.2.3.4","appears":1,'
            b'"frequency":92,"confidence":95.34,"torexit":1,"asn":60729,'
            b'"country":"de"}}'
        )

        def fake_urlopen(req, timeout=0):
            self.assertIn("stopforumspam.org/api?ip=1.2.3.4", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.stopforumspam_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertTrue(out["is_abuse"])
        self.assertTrue(out["torexit"])
        self.assertEqual(out["confidence"], 95.34)
        self.assertEqual(out["frequency"], 92)
        self.assertEqual(out["asn"], "AS60729")
        self.assertEqual(
            qr._flag_opinions("stopforumspam", out),
            {"abuse": True, "tor": True})

    def test_stopforumspam_clean_returns_none(self):
        payload = (
            b'{"success":1,"ip":{"value":"1.2.3.4","appears":0,'
            b'"frequency":0,"torexit":0,"asn":15169,"country":"us"}}'
        )

        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            self.assertIsNone(qc.stopforumspam_lookup_sync("1.2.3.4"))
        finally:
            qc.urllib.request.urlopen = orig

    def _maltiverse_with(self, payload):
        def fake_urlopen(req, timeout=0):
            self.assertIn("api.maltiverse.com/ip/1.2.3.4", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            return qc.maltiverse_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig

    def test_maltiverse_lookup_parsing(self):
        # 取 current 字段；忽略历史脏数据 is_known_attacker
        out = self._maltiverse_with(
            b'{"classification":"malicious","is_open_proxy":true,'
            b'"is_known_attacker":true,"is_tor_node":false,'
            b'"blacklist":[{"last_seen":"2026-09-01 00:00:00",'
            b'"labels":["malicious-activity"],"source":"X"}]}'
        )
        self.assertEqual(out["classification"], "malicious")
        self.assertTrue(out["is_open_proxy"])
        self.assertTrue(out["recent_blacklist"])
        self.assertNotIn("is_known_attacker", out)
        self.assertNotIn("is_tor_node", out)
        self.assertEqual(
            qr._flag_opinions("maltiverse", out),
            {"proxy": True, "abuse": True})

    def test_maltiverse_clean_and_stale_blacklist(self):
        # neutral 无结构布尔 + 陈旧黑名单 → None（负缓存）
        self.assertIsNone(self._maltiverse_with(
            b'{"classification":"neutral","is_open_proxy":false,'
            b'"is_known_attacker":true,'
            b'"blacklist":[{"last_seen":"2012-01-01 00:00:00",'
            b'"labels":["malicious-activity"]}]}'
        ))
        # suspicious（无布尔）仍返回分类
        out = self._maltiverse_with(b'{"classification":"suspicious"}')
        self.assertEqual(out, {"classification": "suspicious"})
        self.assertEqual(qr._flag_opinions("maltiverse", out), {"abuse": True})

    def test_maltiverse_source_score_and_vote(self):
        self.assertEqual(
            qc.source_score("maltiverse", {"classification": "malicious"}), 40)
        self.assertEqual(
            qc.source_score("maltiverse", {"classification": "suspicious"}), 65)
        self.assertIsNone(qc.source_score("maltiverse", {}))
        score, _r, flagged, _n = qc.vote_reputation(
            {"maltiverse": {"classification": "malicious", "is_open_proxy": True}},
            self.W)
        self.assertEqual(score, 37)
        self.assertEqual(sorted(flagged), ["abuse", "proxy"])

    def test_ensure_worker_executor_sizes_default_pool(self):
        async def scenario():
            first = qc.ensure_worker_executor(60)
            second = qc.ensure_worker_executor(4)
            return first, second

        first, second = asyncio.run(scenario())
        self.assertGreaterEqual(first, 64)
        self.assertEqual(first, second)

    def test_ffraud_lookup_parsing(self):
        payload = (
            b'{"fraud_score":0,"risk":"none","proxy":false,"vpn":false,'
            b'"tor":false,"hosting":true,"is_abuser":false,'
            b'"recent_abuse":false,"connection_type":"Residential"}'
        )

        def fake_urlopen(req, timeout=0):
            self.assertIn("api.ffraud.com", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.ffraud_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out["fraud_score"], 0)
        self.assertTrue(out["is_hosting"])
        self.assertEqual(out["connection_type"], "Residential")

    def test_whatismyip_lookup_parsing(self):
        payload = (
            b'{"data":{"security":{"isVpn":false,"isProxy":true,"isTor":false,'
            b'"isHosting":false,"isBlacklisted":true,"score":40},'
            b'"network":{"connectionType":"Residential"}}}'
        )

        def fake_urlopen(req, timeout=0):
            self.assertIn("whatismyip.ai", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.whatismyip_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertTrue(out["is_proxy"])
        self.assertTrue(out["is_blacklisted"])
        self.assertEqual(out["score"], 40)
        self.assertEqual(out["connection_type"], "Residential")

    def test_hackmyip_lookup_parsing(self):
        payload = (
            b'{"success":true,"data":{"privacy":{"hosting":true,"proxy":false,'
            b'"mobile":false},"network":{"asn":212194,"isp":"Yuusei LTD",'
            b'"org":"Ipxo"}}}'
        )

        def fake_urlopen(req, timeout=0):
            self.assertIn("hackmyip.com/api/lookup", req.full_url)
            self.assertIn("1.2.3.4", req.full_url)
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.hackmyip_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertTrue(out["is_hosting"])
        self.assertFalse(out["is_proxy"])
        self.assertFalse(out["is_mobile"])
        self.assertEqual(out["asn"], "AS212194")

    def test_hackmyip_lookup_bad_payload(self):
        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return b'{"success":false,"error":"boom"}'

            return FakeResp()

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = fake_urlopen
        try:
            out = qc.hackmyip_lookup_sync("1.2.3.4")
        finally:
            qc.urllib.request.urlopen = orig
        self.assertIsNone(out)

    def test_parse_abuser_score(self):
        self.assertEqual(qc.parse_abuser_score("0.0039 (Low)"), 0.0039)
        self.assertEqual(qc.parse_abuser_score("42"), 42.0)
        self.assertEqual(qc.parse_abuser_score(0.5), 0.5)
        self.assertIsNone(qc.parse_abuser_score("n/a"))

    def test_norm_asn(self):
        self.assertEqual(qc.norm_asn("AS15169"), "AS15169")
        self.assertEqual(qc.norm_asn("15169"), "AS15169")
        self.assertEqual(qc.norm_asn("AS15169,Google LLC,US"), "AS15169")
        self.assertIsNone(qc.norm_asn("Google LLC"))

    def test_source_score_new_sources(self):
        self.assertEqual(qc.source_score("ipquery", {"risk_score": 20}), 80)
        self.assertEqual(qc.source_score("ipquery", {"is_vpn": True}), 70)
        self.assertEqual(
            qc.source_score("ipquery", {"is_datacenter": True, "asn": "AS1"}),
            85,
        )
        self.assertIsNone(qc.source_score("ipquery", {"asn": ""}))
        self.assertEqual(
            qc.source_score("ffraud", {"fraud_score": 0, "is_hosting": True}),
            85,
        )
        self.assertEqual(qc.source_score("ffraud", {"is_abuser": True}), 80)
        self.assertIsNone(qc.source_score("ffraud", {}))
        self.assertEqual(qc.source_score("whatismyip", {"score": 40}), 60)
        self.assertEqual(qc.source_score("whatismyip", {"is_tor": True}), 55)
        self.assertIsNone(qc.source_score("whatismyip", {}))
        self.assertEqual(qc.source_score("abuse_list", {"is_abuse": True}), 60)
        self.assertIsNone(qc.source_score("abuse_list", {"is_abuse": False}))
        self.assertEqual(qc.source_score("dc_asn", {"is_hosting": True}), 85)
        self.assertIsNone(qc.source_score("dc_asn", {}))
        self.assertEqual(qc.source_score("vpn_asn", {"is_vpn": True}), 70)
        self.assertEqual(
            qc.source_score("resproxy_asn", {"is_proxy": True}), 75)

    def test_source_score_enriched_penalties(self):
        self.assertEqual(
            qc.source_score("netcoffee", {"company_type": "hosting"}), 85)
        self.assertEqual(
            qc.source_score("netcoffee", {"abuser_score": 0.5}), 80)
        self.assertEqual(
            qc.source_score("netcoffee", {"abuser_score": 0.0039}), 100)
        self.assertEqual(
            qc.source_score("ipapi_is", {"company_type": "hosting"}), 85)
        self.assertEqual(
            qc.source_score("ipapi_is", {"company_abuser_score": 0.5}), 80)

    def test_source_score_abuser_score_string_forms(self):
        # R237：缓存/上游可能给 "0.5 (High)" 这类字符串，此前 `or 0` 与阈值
        # 做 str>=float 比较会抛 TypeError；改用 parse_abuser_score 归一。
        self.assertEqual(
            qc.source_score("netcoffee", {"abuser_score": "0.5 (High)"}), 80)
        self.assertEqual(
            qc.source_score("netcoffee", {"abuser_score": "0.0039 (Low)"}), 100)
        self.assertEqual(
            qc.source_score(
                "ipapi_is", {"company_abuser_score": "0.5 (High)"}), 80)
        self.assertEqual(
            qc.source_score("netcoffee", {"abuser_score": "n/a"}), 100)

    def test_numeric_risk_penalty_ignores_bool(self):
        # bool 是 int 子类：投毒 true 不应被当成 1 分风险罚分
        self.assertIsNone(qr._numeric_risk_penalty("scamalytics", {"score": True}))
        self.assertEqual(
            qr._numeric_risk_penalty("scamalytics", {"score": 7}), 7)

    def test_collect_signals_clean_geo_includes_ipapi(self):
        signals = qc.collect_signals(
            "9.9.9.9",
            {"status": "success", "countryCode": "US"},
            {},
            qc.REPUTATION_WEIGHTS,
        )
        self.assertIn("ip-api", signals)

    def test_collect_signals_no_geo_excludes_ipapi(self):
        signals = qc.collect_signals(
            "9.9.9.9", {}, {}, qc.REPUTATION_WEIGHTS
        )
        self.assertNotIn("ip-api", signals)

    def test_collect_signals_skips_empty_sentinel(self):
        # R238 负缓存哨兵 {} 不得进入 signals（防御未来路径泄漏）
        signals = qc.collect_signals(
            "1.1.1.1", {},
            {"1.1.1.1": {"netcoffee": {}, "ncgy": {"is_proxy": True}}},
            qc.REPUTATION_WEIGHTS,
        )
        self.assertNotIn("netcoffee", signals)
        self.assertIn("ncgy", signals)

    def test_vote_reputation_ignores_empty_sentinel(self):
        # 空哨兵不得虚增 responding（否则 source 计数/标签失真）
        signals = {"netcoffee": {}, "ncgy": {"is_proxy": True}}
        score, responding, _flagged, _numeric = qr.vote_reputation(
            signals, qc.REPUTATION_WEIGHTS
        )
        self.assertEqual(responding, ["ncgy"])
        self.assertIsNotNone(score)

    def test_all_rep_sources_have_weights(self):
        """All default reputation sources must have positive weights."""
        for name in qc.DEFAULT_REP_SOURCES:
            self.assertIn(name, qc.REPUTATION_WEIGHTS)
            self.assertGreater(qc.REPUTATION_WEIGHTS[name], 0)


class TestIpSet(unittest.TestCase):
    def test_exact_ip(self):
        s = qc.IpSet(["1.2.3.4", "5.6.7.8/32"])
        self.assertIn("1.2.3.4", s)
        self.assertIn("5.6.7.8", s)

    def test_cidr_containment(self):
        s = qc.IpSet(["10.0.0.0/24", "2001:db8::/32"])
        self.assertIn("10.0.0.1", s)
        self.assertIn("10.0.0.255", s)
        self.assertNotIn("10.0.1.1", s)
        self.assertIn("2001:db8::1", s)
        self.assertNotIn("2001:db9::1", s)

    def test_skips_comments_and_garbage(self):
        s = qc.IpSet(["# comment", "; skip", "not-an-ip", "1.2.3.4"])
        self.assertIn("1.2.3.4", s)
        self.assertEqual(len(s), 1)

    def test_bad_ip_returns_false(self):
        s = qc.IpSet(["1.2.3.4"])
        self.assertNotIn("not-an-ip", s)


class TestStaticLists(unittest.TestCase):
    def _patch_urlopen(self, text):
        def fake_urlopen(req, timeout=0):
            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return text.encode()

            return FakeResp()

        return fake_urlopen

    def test_fetch_asn_list_finds_asn_column(self):
        text = (
            "slug,name,jurisdiction,asn,protocols\n"
            "airvpn,AirVPN,Italy,,WireGuard\n"
            "nord,NordVPN,Panama,AS212238,WireGuard\n"
        )
        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = self._patch_urlopen(text)
        try:
            out = asyncio.run(qc.fetch_asn_list("http://x/asn.csv"))
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out, {"AS212238"})

    def test_fetch_asn_list_first_col_fallback(self):
        text = "asn,name\nAS15169,Google\nAS8075,Microsoft\n"
        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = self._patch_urlopen(text)
        try:
            out = asyncio.run(qc.fetch_asn_list("http://x/asn.csv"))
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(out, {"AS15169", "AS8075"})

    def test_fetch_static_lists_fail_open(self):
        def boom(req, timeout=0):
            raise OSError("network down")

        orig = qc.urllib.request.urlopen
        qc.urllib.request.urlopen = boom
        try:
            out = asyncio.run(qc.fetch_static_lists(["abuse_list", "dc_asn"]))
        finally:
            qc.urllib.request.urlopen = orig
        self.assertEqual(len(out["abuse_list"]), 0)
        self.assertEqual(out["dc_asn"], set())

    def test_fetch_text_list_gate_non_list_content(self):
        """R266：网关把错误页以 200 原样吐出（HTML）时不得静默解析成空表
        假「干净」，应显式告警（fail-open 语义保留，但可观测）。"""
        import logging as _l
        stream = io.StringIO()
        handler = _l.StreamHandler(stream)
        logger = _l.getLogger()
        old_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(_l.WARNING)
        try:
            with unittest.mock.patch.object(
                    qr, "fetch_with_mirror",
                    return_value=b"<html><body>blocked</body></html>"):
                got = asyncio.run(qr.fetch_text_list("https://x/list"))
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        self.assertEqual(got, set())
        self.assertIn("non-list content", stream.getvalue())

    def test_fetch_text_list_clean_lines(self):
        """R266 回归：正常 IP 列表不受内容门槛影响，注释行照旧跳过。"""
        with unittest.mock.patch.object(
                qr, "fetch_with_mirror",
                return_value=b"# header\n1.2.3.4\n5.6.7.8\n"):
            got = asyncio.run(qr.fetch_text_list("https://x/list"))
        self.assertEqual(got, {"1.2.3.4", "5.6.7.8"})

    def test_static_list_error_logged_desensitized(self):
        """R264：静态源任务抛异常时按 err_name 记类别，不得透传含
        URL/token 的原始异常串（common.err_name 脱敏约定）。"""
        import logging

        async def boom():
            raise OSError(
                "https://example.com/list?token=SECRETTOKEN failed")

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger()
        old_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.WARNING)
        try:
            with unittest.mock.patch.object(
                    qr, "fetch_cins_badguys", boom):
                out = asyncio.run(qr.fetch_static_lists(["cins"]))
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        self.assertEqual(len(out["cins"]), 0)
        logged = stream.getvalue()
        self.assertIn("cins", logged)
        self.assertIn("OSError", logged)
        self.assertNotIn("SECRETTOKEN", logged)


class TestReputationFiles(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())
        self._rep_file, self._rank_file = (
            qc.REPUTATION_FILE,
            qc.REP_RANK_FILE,
        )
        qc.REPUTATION_FILE = self.tmp / "reputation.json"
        qc.REP_RANK_FILE = self.tmp / "all_rep.txt"
        self._speed, self._china = common.SPEED_FILE, common.CHINA_FILE
        common.SPEED_FILE = self.tmp / "speed.json"
        common.CHINA_FILE = self.tmp / "china.json"

    def tearDown(self):
        qc.REPUTATION_FILE = self._rep_file
        qc.REP_RANK_FILE = self._rank_file
        common.SPEED_FILE, common.CHINA_FILE = self._speed, self._china

    def test_write_reputation_files_sorted(self):
        text = (
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms-1.00MB/s\n"
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-50ms-2.00MB/s\n"
            "9.9.9.9:443#\U0001F1FA\U0001F1F8US-30ms-3.00MB/s\n"
        )
        annotations = {"1.2.3.4:443#US": "DC-90", "5.6.7.8:8443#JP": "DC-40",
                       "9.9.9.9:443#US": "DC-90"}
        rep_map = {
            "9.9.9.9:443#US": {"score": 90, "risk": "low", "source": "netcoffee"},
            "1.2.3.4:443#US": {"score": 90, "risk": "low", "source": "netcoffee"},
            "5.6.7.8:8443#JP": {"score": 40, "risk": "medium",
                                "source": "ip-api"},
        }
        qc.write_reputation_files(text, annotations, rep_map)
        ranked = qc.REP_RANK_FILE.read_text(encoding="utf-8").splitlines()
        self.assertTrue(ranked[0].startswith("9.9.9.9:443"))
        self.assertTrue(ranked[1].startswith("1.2.3.4:443"))
        self.assertTrue(ranked[2].startswith("5.6.7.8:8443"))
        self.assertTrue(ranked[0].endswith("-DC-90"))
        data = json.loads(qc.REPUTATION_FILE.read_text(encoding="utf-8"))
        self.assertEqual(len(data["proxies"]), 3)
        keys = list(data["proxies"])
        self.assertEqual(keys[0], "1.2.3.4:443#US")
        self.assertEqual(keys[1], "9.9.9.9:443#US")
        self.assertEqual(data["proxies"]["5.6.7.8:8443#JP"]["score"], 40)

    def test_write_reputation_files_variants(self):
        text = (
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms-1.00MB/s\n"
            "5.6.7.8:8443#\U0001F1F5JP-50ms-2.00MB/s\n"
        )
        cdir = self.tmp / "countries" / "US"
        cdir.mkdir(parents=True)
        (cdir / "all.txt").write_text(text, encoding="utf-8")
        common.SPEED_FILE.write_text(
            json.dumps({"proxies": {"1.2.3.4:443#US": {}}}), encoding="utf-8"
        )
        common.CHINA_FILE.write_text(
            json.dumps(
                {
                    "proxies": {
                        "5.6.7.8:8443#JP": {"verdict": "reachable", "streak": 3}
                    }
                }
            ),
            encoding="utf-8",
        )
        annotations = {"1.2.3.4:443#US": "DC-90", "5.6.7.8:8443#JP": "DC-40"}
        rep_map = {
            "1.2.3.4:443#US": {"score": 90, "risk": "low", "source": "netcoffee"},
            "5.6.7.8:8443#JP": {"score": 40, "risk": "medium",
                                "source": "ip-api"},
        }
        qc.write_reputation_files(text, annotations, rep_map)
        ver = (self.tmp / "all_rep_verified.txt").read_text(encoding="utf-8")
        self.assertEqual([l.split("#")[0] for l in ver.splitlines()],
                         ["1.2.3.4:443"])
        sta = (self.tmp / "all_rep_stable.txt").read_text(encoding="utf-8")
        self.assertEqual([l.split("#")[0] for l in sta.splitlines()],
                         ["5.6.7.8:8443"])
        cver = (cdir / "rep_verified.txt").read_text(encoding="utf-8")
        self.assertEqual([l.split("#")[0] for l in cver.splitlines()],
                         ["1.2.3.4:443"])

    def test_write_reputation_files_root_ltd(self):
        (self.tmp / "all_ltd.txt").write_text(
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms-1.00MB/s\n"
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-50ms-2.00MB/s\n",
            encoding="utf-8",
        )
        common.SPEED_FILE.write_text(
            json.dumps({"proxies": {"1.2.3.4:443#US": {}}}), encoding="utf-8"
        )
        common.CHINA_FILE.write_text(
            json.dumps(
                {
                    "proxies": {
                        "5.6.7.8:8443#JP": {"verdict": "reachable", "streak": 3}
                    }
                }
            ),
            encoding="utf-8",
        )
        rep_map = {
            "1.2.3.4:443#US": {"score": 90, "risk": "low", "source": "netcoffee"},
            "5.6.7.8:8443#JP": {"score": 40, "risk": "medium",
                                "source": "ip-api"},
        }
        qc.write_reputation_files("", {}, rep_map)
        base = (self.tmp / "all_rep_ltd.txt").read_text(encoding="utf-8")
        self.assertEqual([l.split("#")[0] for l in base.splitlines()],
                         ["1.2.3.4:443", "5.6.7.8:8443"])
        ver = (self.tmp / "all_rep_ltd_verified.txt").read_text(encoding="utf-8")
        self.assertEqual([l.split("#")[0] for l in ver.splitlines()],
                         ["1.2.3.4:443"])
        sta = (self.tmp / "all_rep_ltd_stable.txt").read_text(encoding="utf-8")
        self.assertEqual([l.split("#")[0] for l in sta.splitlines()],
                         ["5.6.7.8:8443"])

    def test_write_reputation_files_root_ltd_stale_cleaned(self):
        stale = [
            self.tmp / "all_rep_ltd.txt",
            self.tmp / "all_rep_ltd_verified.txt",
            self.tmp / "all_rep_ltd_stable.txt",
        ]
        for p in stale:
            p.write_text("1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms\n",
                         encoding="utf-8")
        qc.write_reputation_files("", {}, {"1.2.3.4:443#US":
                                           {"score": 90, "risk": "low",
                                            "source": "netcoffee"}})
        for p in stale:
            self.assertFalse(p.exists())

    def test_write_reputation_files_dir_group_rep_stale_cleaned(self):
        cdir = self.tmp / "countries" / "US"
        sdir = self.tmp / "sets" / "asia"
        cdir.mkdir(parents=True)
        sdir.mkdir(parents=True)
        (cdir / "cn.txt").write_text(
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms\n", encoding="utf-8"
        )
        (cdir / "cn_rep.txt").write_text(
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms\n", encoding="utf-8"
        )
        (sdir / "cn4_ltd.txt").write_text(
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-50ms\n", encoding="utf-8"
        )
        (sdir / "cn4_rep_ltd.txt").write_text(
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-50ms\n", encoding="utf-8"
        )
        qc.write_reputation_files("", {}, {})
        self.assertTrue((cdir / "cn_rep.txt").exists())
        self.assertTrue((sdir / "cn4_rep_ltd.txt").exists())
        (cdir / "cn.txt").unlink()
        (sdir / "cn4_ltd.txt").unlink()
        qc.write_reputation_files("", {}, {})
        self.assertFalse((cdir / "cn_rep.txt").exists())
        self.assertFalse((sdir / "cn4_rep_ltd.txt").exists())

    def test_write_reputation_files_empty_source_unlinks(self):
        # 空源（残留空目录）→ 空清单不落盘，不留 1 字节 "\n" 残留
        cdir = self.tmp / "countries" / "US"
        cdir.mkdir(parents=True)
        (cdir / "all.txt").write_text("", encoding="utf-8")
        (cdir / "rep.txt").write_text("stale\n", encoding="utf-8")
        (cdir / "cn_ltd.txt").write_text("", encoding="utf-8")
        (cdir / "cn_rep_ltd.txt").write_text("stale\n", encoding="utf-8")
        qc.write_reputation_files("", {}, {})
        self.assertFalse((cdir / "rep.txt").exists())
        self.assertFalse((cdir / "cn_rep_ltd.txt").exists())

    def test_write_reputation_files_dir_rep_stale_cleaned(self):
        cdir = self.tmp / "countries" / "US"
        sdir = self.tmp / "sets" / "asia"
        cdir.mkdir(parents=True)
        sdir.mkdir(parents=True)
        (cdir / "all.txt").write_text(
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms\n", encoding="utf-8"
        )
        (cdir / "rep.txt").write_text(
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms\n", encoding="utf-8"
        )
        (sdir / "ltd.txt").write_text(
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-50ms\n", encoding="utf-8"
        )
        (sdir / "rep_ltd.txt").write_text(
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-50ms\n", encoding="utf-8"
        )
        qc.write_reputation_files("", {}, {})
        self.assertTrue((cdir / "rep.txt").exists())
        self.assertTrue((sdir / "rep_ltd.txt").exists())
        (cdir / "all.txt").unlink()
        (sdir / "ltd.txt").unlink()
        qc.write_reputation_files("", {}, {})
        self.assertFalse((cdir / "rep.txt").exists())
        self.assertFalse((sdir / "rep_ltd.txt").exists())

    def test_write_reputation_files_unscored_last(self):
        text = (
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms\n"
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-50ms\n"
        )
        rep_map = {"5.6.7.8:8443#JP": {"score": 80, "risk": "low",
                                        "source": "netcoffee"}}
        qc.write_reputation_files(text, {}, rep_map)
        lines = qc.REP_RANK_FILE.read_text(encoding="utf-8").splitlines()
        self.assertTrue(lines[0].startswith("5.6.7.8:8443"))
        self.assertTrue(lines[1].startswith("1.2.3.4:443"))

    def test_write_reputation_files_nested_dirs(self):
        cdir = self.tmp / "countries" / "US"
        sdir = self.tmp / "sets" / "hot"
        cdir.mkdir(parents=True)
        sdir.mkdir(parents=True)
        (cdir / "all.txt").write_text(
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms-1.00MB/s\n"
            "9.9.9.9:443#\U0001F1FA\U0001F1F8US-30ms-3.00MB/s\n",
            encoding="utf-8",
        )
        (sdir / "all.txt").write_text(
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-100ms-1.00MB/s\n"
            "5.6.7.8:8443#\U0001F1EF\U0001F1F5JP-50ms-2.00MB/s\n",
            encoding="utf-8",
        )
        annotations = {"9.9.9.9:443#US": "DC-90", "5.6.7.8:8443#JP": "GPT-CF"}
        rep_map = {
            "9.9.9.9:443#US": {"score": 90, "risk": "low", "source": "netcoffee"},
            "1.2.3.4:443#US": {"score": 70, "risk": "low", "source": "ip-api"},
            "5.6.7.8:8443#JP": {"score": 40, "risk": "medium",
                                "source": "ip-api"},
        }
        qc.write_reputation_files("", annotations, rep_map)
        c_rep = (cdir / "rep.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(c_rep), 2)
        self.assertTrue(c_rep[0].startswith("9.9.9.9:443"))
        self.assertTrue(c_rep[0].endswith("-DC-90"))
        self.assertTrue(c_rep[1].startswith("1.2.3.4:443"))
        s_rep = (sdir / "rep.txt").read_text(encoding="utf-8").splitlines()
        self.assertTrue(s_rep[0].startswith("1.2.3.4:443"))
        self.assertTrue(s_rep[1].startswith("5.6.7.8:8443"))
        self.assertTrue(s_rep[1].endswith("-GPT"))
        self.assertFalse((sdir / "ltd.txt").exists())


class TestAnnotateNestedValidFiles(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())
        self._valid = qc.VALID_DIR
        qc.VALID_DIR = self.tmp

    def tearDown(self):
        qc.VALID_DIR = self._valid

    def test_annotates_nested_all_and_ltd(self):
        cdir = self.tmp / "countries" / "US"
        sdir = self.tmp / "sets" / "hot"
        cdir.mkdir(parents=True)
        sdir.mkdir(parents=True)
        line = "1.2.3.4:443#\U0001F1FA\U0001F1F8US-120ms-0.44MB/s\n"
        (cdir / "all.txt").write_text(line, encoding="utf-8")
        (cdir / "ltd.txt").write_text(line, encoding="utf-8")
        (sdir / "all.txt").write_text(line, encoding="utf-8")
        (sdir / "rep.txt").write_text(line, encoding="utf-8")
        annotations = {"1.2.3.4:443#US": "GPT-CF"}
        qc.annotate_valid_files(annotations)
        self.assertTrue(
            (cdir / "all.txt").read_text(encoding="utf-8").endswith("-GPT\n")
        )
        self.assertTrue(
            (cdir / "ltd.txt").read_text(encoding="utf-8").endswith("-GPT\n")
        )
        self.assertTrue(
            (sdir / "all.txt").read_text(encoding="utf-8").endswith("-GPT\n")
        )
        self.assertFalse(
            (sdir / "rep.txt").read_text(encoding="utf-8").endswith("-GPT\n")
        )

    def test_annotate_reconciles_phantom_rows(self):
        (self.tmp / "all.txt").write_text(
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-120ms-0.44MB/s\n",
            encoding="utf-8",
        )
        cdir = self.tmp / "countries" / "US"
        cdir.mkdir(parents=True)
        good = "1.2.3.4:443#\U0001F1FA\U0001F1F8US-120ms-0.44MB/s\n"
        phantom = ("9.9.9.9:443#\U0001F1FA\U0001F1F8US-150ms-0.50MB/s\n")
        write = lambda p, s: (p.parent.mkdir(parents=True, exist_ok=True), p.write_text(s, encoding="utf-8"))
        write(cdir / "all.txt", good + phantom)
        write(cdir / "ltd.txt", good + phantom)
        pruned = qc.annotate_valid_files({"1.2.3.4:443#US": "GPT-CF"})
        self.assertEqual(
            (cdir / "all.txt").read_text(encoding="utf-8"),
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-120ms-0.44MB/s-GPT\n",
        )
        self.assertEqual(
            (cdir / "ltd.txt").read_text(encoding="utf-8"),
            "1.2.3.4:443#\U0001F1FA\U0001F1F8US-120ms-0.44MB/s-GPT\n",
        )
        self.assertEqual(pruned, 2)


class TestReputationCache(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())
        self._cache_file = qr.REP_CACHE_FILE
        qr.REP_CACHE_FILE = self.tmp / "reputation_cache.json"

    def tearDown(self):
        qr.REP_CACHE_FILE = self._cache_file

    def _args(self, ttl=604800, no_cache=False):
        return argparse.Namespace(
            reputation_sources=["netcoffee"],
            no_rep_cache=no_cache,
            rep_cache_ttl=ttl,
            getipintel_email="",
        )

    def test_cache_reused_within_ttl(self):
        calls = []
        orig = qr.netcoffee_lookup_sync
        qr.netcoffee_lookup_sync = lambda ip: (calls.append(ip), {"risk": "low"})[1]
        try:
            first = asyncio.run(qc.lookup_all_risk(
                ["1.1.1.1", "2.2.2.2"], self._args()
            ))
            n1 = len(calls)
            second = asyncio.run(qc.lookup_all_risk(
                ["1.1.1.1", "2.2.2.2"], self._args()
            ))
        finally:
            qr.netcoffee_lookup_sync = orig
        self.assertEqual(n1, 2)
        self.assertEqual(len(calls), 2)
        self.assertEqual(first["1.1.1.1"]["netcoffee"], {"risk": "low"})
        self.assertEqual(second["1.1.1.1"]["netcoffee"], {"risk": "low"})
        self.assertTrue(qr.REP_CACHE_FILE.exists())

    def test_cache_expired_requeries(self):
        # 用与运行时一致的 per-source schema，真正验证「过期 → 重查」语义：
        # 1.1.1.1 过期须重查；8.8.8.8 仍新鲜则不重查。
        # R258：cap 压力下无兜底/从未见过的 2.2.2.2 优先于有旧兜底的
        # 1.1.1.1 查询（本用例无 cap，顺序仍体现该优先级排序）。
        now = time.time()
        qc.save_rep_cache({
            "1.1.1.1": {"netcoffee": {"ts": now - 2 * 604800, "data": {"risk": "low"}}},
            "8.8.8.8": {"netcoffee": {"ts": now, "data": {"risk": "medium"}}},
        })
        calls = []
        orig = qr.netcoffee_lookup_sync
        qr.netcoffee_lookup_sync = lambda ip: (calls.append(ip), {"risk": "low"})[1]
        try:
            asyncio.run(qc.lookup_all_risk(
                ["1.1.1.1", "2.2.2.2", "8.8.8.8"], self._args()
            ))
        finally:
            qr.netcoffee_lookup_sync = orig
        self.assertEqual(calls, ["2.2.2.2", "1.1.1.1"])
        self.assertEqual(len(calls), 2)

    def test_negative_signal_cached_and_not_requeried(self):
        # R238：源返回 None（成功但无信号，如 greynoise 干净 IP）须写入负缓存
        # 哨兵 data:{}，TTL 内下轮不再重查，且不进入 risk_data（不改共识面）。
        calls = []
        orig = qr.netcoffee_lookup_sync
        qr.netcoffee_lookup_sync = lambda ip: (calls.append(ip), None)[1]
        try:
            first = asyncio.run(qc.lookup_all_risk(["1.1.1.1"], self._args()))
            n1 = len(calls)
            second = asyncio.run(qc.lookup_all_risk(["1.1.1.1"], self._args()))
        finally:
            qr.netcoffee_lookup_sync = orig
        self.assertEqual(n1, 1)
        self.assertEqual(len(calls), 1)  # 第二轮命中负缓存，未重查
        self.assertNotIn("netcoffee", first.get("1.1.1.1", {}))
        self.assertNotIn("netcoffee", second.get("1.1.1.1", {}))
        cache = json.loads(qr.REP_CACHE_FILE.read_text(encoding="utf-8"))["proxies"]
        self.assertEqual(cache["1.1.1.1"]["netcoffee"]["data"], {})

    def test_negative_cache_shorter_ttl_than_positive(self):
        # 负缓存 TTL 上限 NEG_CACHE_TTL(<正 TTL)：2 天前的负条目应重查，
        # 同龄正条目仍在 TTL 内复用——限制「干净→恶意」检测时延。
        now = time.time()
        qc.save_rep_cache({
            "1.1.1.1": {"netcoffee": {"ts": now - 2 * 86400, "data": {}}},
            "8.8.8.8": {"netcoffee": {"ts": now - 2 * 86400, "data": {"risk": "low"}}},
        })
        calls = []
        orig = qr.netcoffee_lookup_sync
        qr.netcoffee_lookup_sync = lambda ip: (calls.append(ip), {"risk": "high"})[1]
        try:
            asyncio.run(qc.lookup_all_risk(
                ["1.1.1.1", "8.8.8.8"], self._args()
            ))
        finally:
            qr.netcoffee_lookup_sync = orig
        self.assertEqual(calls, ["1.1.1.1"])  # 仅负条目重查

    def test_negative_signal_not_retried(self):
        # 无信号不是失败：不应触发 batch_sync 重试（旧行为会重查 2 次）。
        calls = []
        orig = qr.netcoffee_lookup_sync
        qr.netcoffee_lookup_sync = lambda ip: (calls.append(ip), None)[1]
        try:
            asyncio.run(qc.lookup_all_risk(["1.1.1.1"], self._args()))
        finally:
            qr.netcoffee_lookup_sync = orig
        self.assertEqual(calls, ["1.1.1.1"])

    def test_negative_cache_refresh_failure_no_false_signal(self):
        # 负缓存过期后刷新失败：兜底不得把空哨兵 {} 当作真实信号注入。
        now = time.time()
        qc.save_rep_cache({
            "1.1.1.1": {"netcoffee": {"ts": now - 2 * 604800, "data": {}}},
        })
        orig = qr.netcoffee_lookup_sync

        def boom(ip):
            raise RuntimeError("api down")

        qr.netcoffee_lookup_sync = boom
        try:
            out = asyncio.run(qc.lookup_all_risk(["1.1.1.1"], self._args()))
        finally:
            qr.netcoffee_lookup_sync = orig
        self.assertNotIn("netcoffee", out.get("1.1.1.1", {}))

    def test_stale_fallback_on_refresh_failure(self):
        # 过期 + 刷新失败 → 回退使用最近缓存信号（不因过期而丢弃），
        # 且过期条目不随写回被删除。
        now = time.time()
        qc.save_rep_cache({
            "1.1.1.1": {"netcoffee": {"ts": now - 2 * 604800, "data": {"risk": "low"}}},
        })
        calls = []
        orig = qr.netcoffee_lookup_sync

        def boom(ip):
            calls.append(ip)
            raise RuntimeError("api down")

        qr.netcoffee_lookup_sync = boom
        try:
            out = asyncio.run(qc.lookup_all_risk(
                ["1.1.1.1"], self._args()
            ))
        finally:
            qr.netcoffee_lookup_sync = orig
        # 过期后确实尝试刷新（回调被调用；batch_sync 默认重试 1 次 → 2 calls）
        self.assertEqual(calls, ["1.1.1.1", "1.1.1.1"])
        # 刷新失败 → 旧缓存信号仍在结果中，未被当作「无信号」丢弃
        self.assertEqual(out["1.1.1.1"]["netcoffee"], {"risk": "low"})
        # 写回时过期条目保留（不删除）
        data = json.loads(qr.REP_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertIn("1.1.1.1", data["proxies"])

    def test_stale_fallback_token_priority_partial_failure(self):
        """混合场景：fresh(不重查) vs 到期成功(刷新覆盖) vs 到期失败
        (兜底旧信号)，一次 run 内三路优先级必须正确，写回 ts 只更新成功者。"""
        now = time.time()
        ttl = 7 * 86400
        qc.save_rep_cache({
            "1.1.1.1": {"netcoffee": {"ts": now, "data": {"risk": "low"}}},
            "2.2.2.2": {"netcoffee": {"ts": now - 2 * ttl, "data": {"risk": "medium"}}},
            "3.3.3.3": {"netcoffee": {"ts": now - 2 * ttl, "data": {"risk": "medium"}}},
        })
        calls: list[str] = []
        orig = qr.netcoffee_lookup_sync

        def mock(ip):
            calls.append(ip)
            if ip == "2.2.2.2":
                raise RuntimeError("api down")
            return {"risk": "high"}

        qr.netcoffee_lookup_sync = mock
        try:
            out = asyncio.run(qc.lookup_all_risk(
                ["1.1.1.1", "2.2.2.2", "3.3.3.3"], self._args()
            ))
        finally:
            qr.netcoffee_lookup_sync = orig
        # fresh 不清命：1.1.1.1 不被查询，直接复用
        self.assertEqual(out["1.1.1.1"]["netcoffee"], {"risk": "low"})
        self.assertNotIn("1.1.1.1", calls)
        # 到期失败 → 兜底旧信号（medium 未被"无信号"丢弃）
        self.assertEqual(out["2.2.2.2"]["netcoffee"], {"risk": "medium"})
        # 到期成功 → 刷新信号覆盖
        self.assertEqual(out["3.3.3.3"]["netcoffee"], {"risk": "high"})
        # 每 IP 只被查一次（排除 batch_sync 重试对成功者的再查；2.2.2.2 失败重试 1 次）
        self.assertEqual(
            {ip: calls.count(ip) for ip in set(calls)},
            {"2.2.2.2": 2, "3.3.3.3": 1},
        )
        # 写回 ts：只有成功刷新的 3.3.3.3 被更新；失败者保留旧 ts（下轮再试）
        cache = json.loads(qr.REP_CACHE_FILE.read_text(encoding="utf-8"))["proxies"]
        self.assertGreaterEqual(cache["3.3.3.3"]["netcoffee"]["ts"], now)
        self.assertEqual(cache["2.2.2.2"]["netcoffee"]["ts"], now - 2 * ttl)

    def test_no_rep_cache_flag(self):
        calls = []
        orig = qr.netcoffee_lookup_sync
        qr.netcoffee_lookup_sync = lambda ip: (calls.append(ip), {"risk": "low"})[1]
        try:
            asyncio.run(qc.lookup_all_risk(
                ["1.1.1.1", "2.2.2.2"], self._args(no_cache=True)
            ))
        finally:
            qr.netcoffee_lookup_sync = orig
        self.assertEqual(len(calls), 2)
        self.assertFalse(qr.REP_CACHE_FILE.exists())

    def test_rep_cache_pruned_to_max_keeps_recent(self):
        """REP_CACHE_MAX 上限：超过时按每个 IP 最近信号 ts 裁最旧（防无限膨胀）。"""
        now = time.time()
        qc.save_rep_cache({
            ip: {"netcoffee": {"ts": now - i, "data": {"risk": "low"}}}
            for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3",
                                    "4.4.4.4", "5.5.5.5"])
        })
        orig = qr.netcoffee_lookup_sync
        qr.netcoffee_lookup_sync = lambda ip: {"risk": "low"}
        try:
            with unittest.mock.patch.object(qr, "REP_CACHE_MAX", 3):
                asyncio.run(qc.lookup_all_risk(["1.1.1.1"], self._args()))
        finally:
            qr.netcoffee_lookup_sync = orig
        data = json.loads(qr.REP_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertEqual(len(data["proxies"]), 3)
        self.assertEqual(set(data["proxies"]), {"1.1.1.1", "2.2.2.2", "3.3.3.3"})

    def test_abuse_deadline_truncates_loop(self):
        """abuse 顺序查询超 deadline → 立即截断，不发任何请求（D-42 相位内止损）。"""
        args = argparse.Namespace(
            abuse_service="abuseipdb", abuse_key="k",
            reputation_weights={"abuseipdb": 35},
        )
        results = {"1.2.3.4:443#US": {}}
        ipinfo = {"1.2.3.4:443#US": {"exit_ip": "5.6.7.8"}}
        calls: list[str] = []
        orig = qr.abuse_lookup_sync

        def fake(ip, service, key):
            calls.append(ip)
            return {"score": 10}

        qr.abuse_lookup_sync = fake
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                out = asyncio.run(qr.run_abuse(
                    results, ipinfo, args, deadline=-1.0
                ))
        finally:
            qr.abuse_lookup_sync = orig
        self.assertEqual(out, {})
        self.assertEqual(calls, [])
        self.assertIn("(0/1)", buf.getvalue())

    def test_ipqs_timeout_redacts_key(self):
        """IPQS 超时异常净化：DEBUG 日志面不泄露 key（R212 安全维度闭环）。"""
        secret = "s3cr3t-ipqs-key-0001"
        leaked_url = f"https://ipqualityscore.com/api/json/ip/{secret}/5.6.7.8"

        def fake_deadline_open(req, timeout, max_bytes=None):
            raise TimeoutError(f"fetch deadline exceeded (10s): {req.full_url}")

        class _FakeReq:
            full_url = leaked_url

        captured_tb = None
        orig = qr.deadline_open
        qr.deadline_open = fake_deadline_open
        try:
            with self.assertRaises(TimeoutError) as ctx:
                qr.abuse_lookup_sync("5.6.7.8", "ipqualityscore", secret)
            captured_tb = traceback.format_exc()
        finally:
            qr.deadline_open = orig
        msg = str(ctx.exception)
        self.assertNotIn(secret, msg)
        self.assertIn("5.6.7.8", msg)
        self.assertIn("redacted", msg)
        # traceback 面（logging exc_info / format_exc）也不得残留 key（R213 修正）
        self.assertIsNotNone(captured_tb)
        self.assertNotIn(secret, captured_tb)

    def test_malformed_cache_tolerated(self):
        qr.REP_CACHE_FILE.write_text("{not json\n", encoding="utf-8")
        calls = []
        orig = qr.netcoffee_lookup_sync
        qr.netcoffee_lookup_sync = lambda ip: (calls.append(ip), {"risk": "low"})[1]
        try:
            out = asyncio.run(qc.lookup_all_risk(
                ["1.1.1.1", "2.2.2.2"], self._args()
            ))
        finally:
            qr.netcoffee_lookup_sync = orig
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(out), 2)
        data = json.loads(qr.REP_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertIn("1.1.1.1", data["proxies"])

    def test_cached_signal_ttl_boundary(self):
        now = 1_000_000.0
        cache = {
            "1.1.1.1": {"netcoffee": {"ts": now - 5, "data": {"risk": "low"}}},
        }
        # 恰好 TTL(ts+ttl==now)：视为新鲜（含边界）
        self.assertEqual(
            qr.cached_signal(cache, "1.1.1.1", "netcoffee", now, ttl=5),
            {"risk": "low"},
        )
        # 超过 TTL 一瞬(ts+ttl<now)：视为过期
        self.assertIsNone(
            qr.cached_signal(cache, "1.1.1.1", "netcoffee", now + 0.001, ttl=5)
        )
        # ttl<=0（--no-rep-cache）一律返回 None
        self.assertIsNone(
            qr.cached_signal(cache, "1.1.1.1", "netcoffee", now, ttl=0)
        )
        # 未知 IP / 未知来源 / 非 dict data 均返回 None
        self.assertIsNone(qr.cached_signal(cache, "9.9.9.9", "netcoffee", now, 5))
        self.assertIsNone(qr.cached_signal(cache, "1.1.1.1", "other", now, 5))
        self.assertIsNone(
            qr.cached_signal({"2.2.2.2": {"netcoffee": {"ts": now, "data": []}}},
                            "2.2.2.2", "netcoffee", now, 5)
        )


class TestAbuseFallback(unittest.TestCase):
    """预算跳过/截断滥用相位时，用最近 abuse.json 兜底（滥用分具最高优先级）。"""

    def setUp(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())
        self._orig = qr.ABUSE_FILE
        qr.ABUSE_FILE = self.tmp / "abuse.json"

    def tearDown(self):
        qr.ABUSE_FILE = self._orig

    def _write(self, entries, age=0.0):
        qr.write_json(qr.ABUSE_FILE, qr.keyed_json(entries))
        if age:
            import os
            t = time.time() - age
            os.utime(qr.ABUSE_FILE, (t, t))

    def test_missing_and_corrupt_return_empty(self):
        self.assertEqual(qr.load_abuse_file(), {})
        qr.ABUSE_FILE.write_text("{not json", encoding="utf-8")
        self.assertEqual(qr.load_abuse_file(), {})

    def test_roundtrip_and_stale_ttl(self):
        self._write({"1.1.1.1:443#US": {"service": "abuseipdb", "score": 40}})
        loaded = qr.load_abuse_file()
        self.assertEqual(loaded["1.1.1.1:443#US"]["score"], 40)
        # 超龄 → 不兜底
        self._write({"1.1.1.1:443#US": {"score": 40}}, age=2 * 86400)
        self.assertEqual(qr.load_abuse_file(), {})

    def test_merge_only_fills_valid_missing_keys(self):
        fresh = {"a": {"score": 1}}
        cached = {"a": {"score": 9}, "b": {"score": 2}, "c": {"score": 3}}
        merged = qr.merge_abuse_fallback(fresh, cached, {"a", "b"})
        self.assertEqual(merged["a"]["score"], 1)   # 不覆盖新结果
        self.assertEqual(merged["b"]["score"], 2)   # 补齐缺失
        self.assertNotIn("c", merged)               # 非本轮键不注入
        self.assertNotIn("c", fresh)


class TestAnnotateClassify(unittest.TestCase):
    """Tests for annotate_classify.py suffix filling and classification."""

    def test_speed_tier(self):
        from annotate_classify import speed_tier
        self.assertEqual(speed_tier("-10ms-10.5MB/s"), "fast")
        self.assertEqual(speed_tier("-10ms-3.2MB/s"), "mid")
        self.assertEqual(speed_tier("-10ms-0.5MB/s"), "slow")
        self.assertEqual(speed_tier("-10ms"), "unknown")
        # ≈ 大陆估算 token 不是实测——不给档位（R77 防御收紧）
        self.assertEqual(speed_tier("-10ms-≈2.0MB/s"), "unknown")
        self.assertEqual(speed_tier("≈99MB/s"), "unknown")

    def test_fill_cn_token(self):
        from annotate_classify import fill_and_classify
        line = "1.2.3.4:443#🇺🇸US-100ms"
        result = fill_and_classify(
            line,
            china_sets=({"1.2.3.4:443#US"}, set()),
            family_map={},
            rep_map={},
            ip_type_map={},
        )
        self.assertIn("-CN", result)
        self.assertTrue(result.endswith("-CN"))

    def test_removes_stale_cn_token(self):
        """行带历史 -CN，但当期 china.json 不再判定可达 → 撤销 -CN。"""
        from annotate_classify import fill_and_classify
        stale = "1.2.3.4:443#🇺🇸US-100ms-5.00MB/s-CN-V6-DC-77"
        result = fill_and_classify(
            stale,
            china_sets=(set(), set()),
            family_map={},
            rep_map={},
            ip_type_map={},
        )
        self.assertNotIn("-CN", result)
        self.assertTrue(result.endswith("-77"))

    def test_keeps_cnh_by_http_level(self):
        """应用层 HTTP 确认（cnh_set）即使 verdict 非 reachable 也保留。"""
        from annotate_classify import fill_and_classify
        line = "1.2.3.4:443#🇺🇸US-100ms-5.00MB/s-CNH"
        result = fill_and_classify(
            line,
            china_sets=(set(), {"1.2.3.4:443#US"}),
            family_map={},
            rep_map={},
            ip_type_map={},
        )
        self.assertTrue(result.endswith("-CN-CNH"))

    def test_fill_family_token(self):
        from annotate_classify import fill_and_classify
        line = "1.2.3.4:443#🇺🇸US-100ms"
        result = fill_and_classify(
            line,
            china_sets=(set(), set()),
            family_map={"1.2.3.4:443#US": "ipv6"},
            rep_map={},
            ip_type_map={},
        )
        self.assertIn("-V6", result)

    def test_clears_family_token_when_family_unknown(self):
        """exit_family 对该 key 显式记为 unknown（探测全失败）→ 清掉旧
        V4/V6/DS token：宁可未知也不冒称，防止误导下游 v4/v6 划分。"""
        from annotate_classify import fill_and_classify
        stale = "1.2.3.4:443#🇺🇸US-100ms-5.00MB/s-V6-DC-77-CN"
        result = fill_and_classify(
            stale,
            china_sets=(set(), set()),
            family_map={"1.2.3.4:443#US": "unknown"},
            rep_map={},
            ip_type_map={},
        )
        self.assertNotIn("-V6", result)
        for t in ("-V4", "-DS"):
            self.assertNotIn(t, result)
        self.assertIn("-77", result)

    def test_family_absent_preserves_token(self):
        """整体无 family 数据（family_map 缺该 key）→ 不动既有家族 token
        （数据集缺失≠该行未知，保持无侵入语义）。"""
        from annotate_classify import fill_and_classify
        stale = "1.2.3.4:443#🇺🇸US-100ms-5.00MB/s-DS-DC-50"
        result = fill_and_classify(
            stale,
            china_sets=(set(), set()),
            family_map={},
            rep_map={},
            ip_type_map={},
        )
        self.assertIn("-DS", result)
        self.assertIn("-50", result)


    def test_fill_rep_score(self):
        from annotate_classify import fill_and_classify
        line = "1.2.3.4:443#🇺🇸US-100ms"
        result = fill_and_classify(
            line,
            china_sets=(set(), set()),
            family_map={},
            rep_map={"1.2.3.4:443#US": 85},
            ip_type_map={},
        )
        self.assertTrue(result.endswith("-85"))

    def test_fill_uptime_token(self):
        from annotate_classify import fill_and_classify
        line = "1.2.3.4:443#🇺🇸US-100ms"
        result = fill_and_classify(
            line,
            china_sets=(set(), set()),
            family_map={},
            rep_map={},
            ip_type_map={},
            uptime_map={"1.2.3.4:443#US": 92},
        )
        self.assertTrue(result.endswith("-U92"))
        # 幂等
        again = fill_and_classify(
            result, (set(), set()), {}, {}, {},
            uptime_map={"1.2.3.4:443#US": 92},
        )
        self.assertEqual(again, result)

    def test_no_uptime_token_without_data(self):

        from annotate_classify import fill_and_classify
        result = fill_and_classify(
            "1.2.3.4:443#🇺🇸US-100ms",
            (set(), set()), {}, {}, {}, None,
        )
        self.assertIsNone(re.search(r"-U\d+", result))

    def test_add_ip_type_and_tier(self):
        from annotate_classify import fill_and_classify
        line = "1.2.3.4:443#🇺🇸US-100ms-5.5MB/s"
        result = fill_and_classify(
            line,
            china_sets=(set(), set()),
            family_map={},
            rep_map={},
            ip_type_map={"1.2.3.4:443#US": "DC"},
        )
        self.assertIn("-DC", result)
        self.assertIn("-fast", result)
        self.assertTrue(result.endswith("-DC-fast"))

    def test_idempotent(self):
        from annotate_classify import fill_and_classify
        line = "1.2.3.4:443#🇺🇸US-100ms-5.5MB/s-CN-V6-GPT-85-DC-fast"
        result = fill_and_classify(
            line,
            china_sets=({"1.2.3.4:443#US"}, set()),
            family_map={"1.2.3.4:443#US": "ipv6"},
            rep_map={"1.2.3.4:443#US": 85},
            ip_type_map={"1.2.3.4:443#US": "DC"},
        )
        # 历史乱序段被规范器重排为规范顺序，且不重复追加
        self.assertEqual(
            result,
            "1.2.3.4:443#🇺🇸US-100ms-5.5MB/s-GPT-DC-fast-V6-CN-85",
        )
        # 幂等：再次处理不变
        self.assertEqual(fill_and_classify(
            result,
            china_sets=({"1.2.3.4:443#US"}, set()),
            family_map={"1.2.3.4:443#US": "ipv6"},
            rep_map={"1.2.3.4:443#US": 85},
            ip_type_map={"1.2.3.4:443#US": "DC"},
        ), result)

    def test_normalizes_stacked_suffixes(self):
        """多轮历史堆叠的快照段被收敛为单组规范段。"""
        from annotate_classify import fill_and_classify
        stacked = ("1.2.3.4:443#🇺🇸US→US-21ms-25.23MB/s-CN-V6-GPT-CF-77"
                   "-mid-GPT-CF-70-DC-fast-GPT-CF-62-RES-GPT-CF-70")
        result = fill_and_classify(
            stacked,
            china_sets=(set(), set()),
            family_map={},
            rep_map={},
            ip_type_map={},
        )
        self.assertEqual(
            result,
            "1.2.3.4:443#🇺🇸US→US-21ms-25.23MB/s-GPT-RES-fast-V6-70",
        )

    def test_skip_no_cc_line(self):
        from annotate_classify import fill_and_classify
        line = "not-a-proxy-line"
        result = fill_and_classify(
            line, (set(), set()), {}, {}, {}, {},
        )
        self.assertEqual(result, line)

    def test_fill_exit_marker(self):
        from annotate_classify import fill_and_classify
        line = "1.2.3.4:443#🇺🇸US-100ms"
        result = fill_and_classify(
            line,
            china_sets=(set(), set()),
            family_map={},
            rep_map={},
            ip_type_map={},
            exit_map={"1.2.3.4:443#US": "JP"},
        )
        self.assertIn("→JP", result)
        self.assertTrue(result.startswith("1.2.3.4:443#"))
        # CC should still be US, exit marker inserted after it
        self.assertIn("#🇺🇸US→JP-", result)

    def test_fill_exit_marker_existing(self):
        from annotate_classify import fill_and_classify
        line = "1.2.3.4:443#🇺🇸US→LAX-100ms"
        result = fill_and_classify(
            line,
            china_sets=(set(), set()),
            family_map={},
            rep_map={},
            ip_type_map={},
            exit_map={"1.2.3.4:443#US": "JP"},
        )
        # 已有 → 但与新观测不同 → 陈旧出口，应替换
        self.assertIn("→JP", result)
        self.assertNotIn("→LAX", result)

    def test_fill_exit_marker_no_match(self):
        from annotate_classify import fill_and_classify
        line = "1.2.3.4:443#🇺🇸US-100ms"
        result = fill_and_classify(
            line,
            china_sets=(set(), set()),
            family_map={},
            rep_map={},
            ip_type_map={},
            exit_map={"9.9.9.9:443#DE": "FR"},
        )
        # Key not in exit_map → no change
        self.assertEqual(result, line)


class TestBuildExitMap(unittest.TestCase):
    def test_build_exit_map(self):
        from annotate_classify import _build_exit_map
        ipinfo = {
            "proxies": {
                "1.2.3.4:443#US": {"country_code": "JP"},
                "5.6.7.8:443#US": {"country_code": "US"},
                "9.9.9.9:443#DE": {"country_code": "FR"},
            }
        }
        exit_map = _build_exit_map(ipinfo)
        self.assertEqual(exit_map, {
            "1.2.3.4:443#US": "JP",
            "5.6.7.8:443#US": "US",
            "9.9.9.9:443#DE": "FR",
        })

    def test_build_exit_map_multi_source_priority(self):
        """external_check > upstream_meta(按入口 IP) > ipinfo 三源回退。"""
        from annotate_classify import _build_exit_map
        ipinfo = {
            "proxies": {
                "a:443#US": {"country_code": "JP"},   # 陈旧入口地理，被 external 覆盖
                "b:443#US": {"country_code": "JP"},   # 仅 ipinfo 兜底
                "c:443#US": {},                        # 由 upstream 补齐
                "e:443#US": {"country_code": "KR"},   # 仅 ipinfo 兜底
            }
        }
        external = {
            "proxies": {
                "a:443#US": {"exit_geo": {"country": "SG"}},
                "d:443#US": {"exit_geo": {"country": None}},  # 无国家 → 由 upstream 补
                "f:443#US": {"exit_geo": {"country": 123}},  # 非法 → 忽略
            }
        }
        upstream = {
            "proxies": {
                "c": {"country": "HK"},
                "d": {"clientIp": "::1", "country": "TW"},
            }
        }
        exit_map = _build_exit_map(ipinfo, external, upstream)
        self.assertEqual(exit_map, {
            "a:443#US": "SG",
            "b:443#US": "JP",
            "c:443#US": "HK",
            "d:443#US": "TW",
            "e:443#US": "KR",
        })

    def test_build_exit_map_missing_fields(self):
        from annotate_classify import _build_exit_map
        ipinfo = {
            "proxies": {
                "a:443#US": {"country_match": None},  # unknown → skip
                "b:443#US": {"country_code": "XX", "country_match": False},  # mismatch → included
                "c:443#US": {},  # no country_match → skip
                "d:443#US": {"country_code": "", "country_match": False},  # empty cc → skip
            }
        }
        exit_map = _build_exit_map(ipinfo)
        self.assertEqual(exit_map, {"b:443#US": "XX"})


class TestBuildMetaCountryMismatch(unittest.TestCase):
    def test_country_mismatch_in_meta(self):
        results = {"a": {}}
        ipinfo = {
            "a": {"ip_type": "DC", "risk": "low", "country_match": True},
            "b": {"ip_type": "DC", "risk": "low", "country_match": False},
        }
        meta = qc.build_meta(results, ipinfo, {}, None)
        self.assertEqual(meta["country_mismatch"], 1)

    def test_country_mismatch_all_match(self):
        results = {"a": {}}
        ipinfo = {"a": {"ip_type": "DC", "risk": "low", "country_match": True}}
        meta = qc.build_meta(results, ipinfo, {}, None)
        self.assertEqual(meta["country_mismatch"], 0)


class TestReorgCountry(unittest.TestCase):
    def test_ensure_exit_marker(self):
        from reorg_country import ensure_exit_marker
        line = "1.2.3.4:443#\U0001F1E6\U0001F1E8CA-10ms"
        result = ensure_exit_marker(line, "EG")
        self.assertIn("#\U0001F1E6\U0001F1E8CA→EG-", result)
        self.assertIn("1.2.3.4:443", result)

    def test_ensure_exit_marker_existing(self):
        from reorg_country import ensure_exit_marker
        line = "1.2.3.4:443#\U0001F1F3\U0001F1F5NP→JP-10ms"
        result = ensure_exit_marker(line, "US")
        # 已有 → 但国家不同 → 陈旧观测，直接替换
        self.assertIn("NP→US", result)
        self.assertNotIn("→JP", result)

    def test_ensure_exit_marker_same(self):
        from reorg_country import ensure_exit_marker
        line = "1.2.3.4:443#\U0001F1F3\U0001F1F5NP→JP-10ms"
        result = ensure_exit_marker(line, "JP")
        self.assertEqual(result, line)

    def test_reorganize_mismatched_line(self):
        import json
        import tempfile
        from reorg_country import reorganize
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            valid = tmp_path / "data" / "valid"
            countries = valid / "countries"
            (countries / "CA").mkdir(parents=True)
            (countries / "EG").mkdir(parents=True)
            (countries / "CA" / "all.txt").write_text(
                "166.1.228.218:443#\U0001F1E6\U0001F1E8CA-10ms\n"
                "1.2.3.4:443#\U0001F1E6\U0001F1E8CA-20ms\n"
            )
            (countries / "EG" / "all.txt").write_text("")
            ipinfo = {
                "proxies": {
                    "166.1.228.218:443#CA": {
                        "country_code": "EG",
                        "country_match": False,
                    },
                    "1.2.3.4:443#CA": {
                        "country_code": "CA",
                        "country_match": True,
                    },
                }
            }
            ipinfo_path = valid / "ipinfo.json"
            ipinfo_path.write_text(json.dumps(ipinfo))
            moved = reorganize(ipinfo_path, tmp_path / "data")
            self.assertEqual(moved, 1)
            ca_lines = (countries / "CA" / "all.txt").read_text().strip().splitlines()
            self.assertEqual(len(ca_lines), 1)
            self.assertIn("1.2.3.4:443", ca_lines[0])
            eg_lines = (countries / "EG" / "all.txt").read_text().strip().splitlines()
            self.assertEqual(len(eg_lines), 1)
            self.assertIn("166.1.228.218:443", eg_lines[0])
            # Should have →EG marker, NOT rewritten CC
            self.assertIn("→EG", eg_lines[0])
            self.assertIn("#\U0001F1E6\U0001F1E8CA→EG", eg_lines[0])

    def test_merge_ordered_preserves_sort_and_stable_order(self):
        from reorg_country import _merge_ordered
        existing = "a:443#US-10ms\nb:443#US-50ms\nc:443#US-999ms\n"
        merged = _merge_ordered(existing, ["d:443#US-30ms", "e:443#US-no-ms"])
        lines = merged.splitlines()
        self.assertEqual(lines[0], "a:443#US-10ms")
        self.assertEqual(lines[1], "d:443#US-30ms")
        self.assertEqual(lines[2], "b:443#US-50ms")
        self.assertEqual(lines[3], "c:443#US-999ms")
        self.assertEqual(lines[4], "e:443#US-no-ms")

    def test_merge_ordered_empty_target_starts_with_new(self):
        from reorg_country import _merge_ordered
        self.assertEqual(
            _merge_ordered("", ["x:443#US-5ms"]),
            "x:443#US-5ms\n",
        )

    def test_reorganize_all_moved_source_recreated(self):
        """整文件全部线被移出（countries 源为目标不同 CC）时，源清空后 unlink，目标正常接管。"""
        import json
        import tempfile
        from reorg_country import reorganize
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            valid = tmp_path / "data" / "valid"
            countries = valid / "countries"
            (countries / "CA").mkdir(parents=True)
            (countries / "US").mkdir(parents=True)
            (countries / "CA" / "all.txt").write_text("166.1.228.218:443#\U0001F1E6\U0001F1E8CA-10ms\n")
            ipinfo = {"proxies": {
                "166.1.228.218:443#CA": {"country_code": "US", "country_match": False},
            }}
            ipinfo_path = valid / "ipinfo.json"
            ipinfo_path.write_text(json.dumps(ipinfo))
            moved = reorganize(ipinfo_path, tmp_path / "data")
            self.assertEqual(moved, 1)
            self.assertFalse((countries / "CA" / "all.txt").exists())
            self.assertIn(
                "166.1.228.218", (countries / "US" / "all.txt").read_text()
            )


class TestFreshDeepSpeed(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="qcfresh_"))
        patcher = unittest.mock.patch.object(qc, "QUALITY_DIR", self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write(self, payload):
        (self.dir / "deep_speed.json").write_text(
            json.dumps(payload, ensure_ascii=False)
        )

    def test_fresh_epoch_ts_returns(self):
        self._write({"ts": time.time(), "proxies": {"k": {"a": 1}}})
        self.assertIsNotNone(qc.read_fresh_deep_speed())

    def test_fresh_iso_ts_returns(self):
        self._write({"generated_at": datetime.now(timezone.utc).isoformat()})
        self.assertIsNotNone(qc.read_fresh_deep_speed())

    def test_real_deep_speed_uses_generated_field(self):
        self._write({"generated": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"), "proxies": {}})
        self.assertIsNotNone(qc.read_fresh_deep_speed())

    def test_stale_iso_ts_returns_none(self):
        old = (datetime.now(timezone.utc) - timedelta(days=12)).isoformat()
        self._write({"generated_at": old, "proxies": {"k": {"a": 1}}})
        self.assertIsNone(qc.read_fresh_deep_speed())

    def test_stale_generated_field_returns_none(self):
        old = (datetime.now(timezone.utc) - timedelta(days=12)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        self._write({"generated": old, "proxies": {"k": {"a": 1}}})
        self.assertIsNone(qc.read_fresh_deep_speed())

    def test_missing_ts_returns_none(self):
        self._write({"proxies": {"k": {"a": 1}}})
        self.assertIsNone(qc.read_fresh_deep_speed())

    def test_invalid_ts_returns_none(self):
        self._write({"generated_at": "not-a-date"})
        self.assertIsNone(qc.read_fresh_deep_speed())

    def test_missing_file_returns_none(self):
        self.assertIsNone(qc.read_fresh_deep_speed())


class TestExternalCheck(unittest.TestCase):
    def test_check_external_api_success(self):
        import quality_probe as qs
        fake_data = {
            "success": True,
            "responseTime": 123,
            "colo": "HKG",
            "probe_results": {
                "ipv4": {
                    "ok": True,
                    "exit": {"countryCode": "HK", "country": "Hong Kong", "asn": 12345},
                },
                "ipv6": {"ok": False},
            },
        }
        fake_resp = json.dumps(fake_data).encode()

        class FakeResp:
            def read(self):
                return fake_resp
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        def fake_urlopen(req, timeout=30):
            return FakeResp()

        with unittest.mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = asyncio.run(
                qs.check_external_api("1.2.3.4", "443", timeout=5)
            )
        self.assertTrue(result["success"])
        self.assertEqual(result["response_ms"], 123)
        self.assertEqual(result["colo"], "HKG")
        self.assertTrue(result["ipv4_ok"])
        self.assertFalse(result["ipv6_ok"])
        self.assertEqual(result["exit_geo"]["countryCode"], "HK")

    def test_check_external_api_failure(self):
        import quality_probe as qs

        def fake_urlopen(req, timeout=30):
            raise ConnectionError("nope")

        with unittest.mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = asyncio.run(
                qs.check_external_api("1.2.3.4", "443", timeout=5)
            )
        self.assertFalse(result["success"])

    def test_build_meta_includes_ext_check(self):
        results = {
            "k1": {"ip": "1.1.1.1", "external_check": {"success": True}},
            "k2": {"ip": "2.2.2.2", "external_check": {"success": False}},
            "k3": {"ip": "3.3.3.3"},
        }
        meta = qc.build_meta(results, {}, {})
        self.assertEqual(meta["ext_check_total"], 2)
        self.assertEqual(meta["ext_check_ok"], 1)

    def test_build_meta_contract_field_set(self):
        # 契约锁：build_meta 输出与 data-spec.md:277 quality_meta 文档一致
        meta = qc.build_meta({"k1": {"ip": "1.1.1.1"}}, {}, {}, {})
        self.assertEqual(
            set(meta),
            {"ts", "total", "tls", "by_type", "risk", "abuse_checked",
             "reputation_checked", "rep_dist", "rep_avg", "rep_median",
             "country_mismatch", "ext_check_total", "ext_check_ok",
             "skipped"},
        )

    def test_build_meta_skipped_persisted(self):
        # R201：预算耗尽而跳过的相位须落盘，使降级批次机器可检测
        meta = qc.build_meta(
            {"k1": {"ip": "1.1.1.1"}}, {}, {}, {},
            skipped=["ip-api geo", "reputation lookup"],
        )
        self.assertEqual(meta["skipped"], ["ip-api geo", "reputation lookup"])
        self.assertEqual(qc.build_meta({"k1": {"ip": "1.1.1.1"}}, {}, {}, {})["skipped"], [])

    def test_build_meta_rep_aggregates(self):
        results = {"k%d" % i: {"ip": "1.1.1.%d" % i} for i in range(1, 6)}
        ipinfo = {"k1": {"ip_type": "datacenter", "risk": "low",
                         "country_match": False}}
        rep_map = {
            "k1": {"score": 10}, "k2": {"score": 40},
            "k3": {"score": 70}, "k4": {"score": 90},
        }
        meta = qc.build_meta(results, ipinfo, {}, rep_map)
        # reps=[10,40,70,90] → 均值 52.5、中位 55、四桶各 1、country_mismatch 1
        self.assertEqual(meta["rep_avg"], 52.5)
        self.assertEqual(meta["rep_median"], 55.0)
        self.assertEqual(meta["rep_dist"],
                         {"0-25": 1, "25-50": 1, "50-75": 1, "75-100": 1})
        self.assertEqual(meta["reputation_checked"], 4)
        self.assertEqual(meta["by_type"], {"datacenter": 1})
        self.assertEqual(meta["country_mismatch"], 1)

    def test_build_meta_rep_odd_median_and_empty(self):
        results = {"k%d" % i: {"ip": "1.1.1.%d" % i} for i in range(1, 6)}
        rep_map = {"k1": {"score": 60}}
        # 单值中位=自身
        self.assertEqual(qc.build_meta(results, {}, {}, rep_map)["rep_median"], 60.0)
        # 无评分 → None，不除零
        meta = qc.build_meta(results, {}, {})
        self.assertIsNone(meta["rep_avg"])
        self.assertIsNone(meta["rep_median"])
        self.assertEqual(meta["rep_dist"], {k: 0 for k in (
            "0-25", "25-50", "50-75", "75-100")})


class TestNewReputationSources(unittest.TestCase):
    """+5 free reputation sources: freeipapi / scamalytics / iplocation /
    CINS ci-badguys / EmergingThreats compromised."""

    def test_source_score_freeipapi(self):
        self.assertEqual(qr.source_score("freeipapi", {"is_proxy": True}), 70)
        self.assertEqual(qr.source_score("freeipapi", {"is_proxy": False}), 100)

    def test_source_score_scamalytics(self):
        self.assertEqual(qr.source_score("scamalytics", {"score": 5}), 95)
        self.assertEqual(qr.source_score("scamalytics", {"score": 80}), 20)
        self.assertIsNone(qr.source_score("scamalytics", {}))

    def test_source_score_iplocation(self):
        self.assertEqual(qr.source_score("iplocation", {"is_proxy": True}), 70)
        self.assertEqual(qr.source_score("iplocation", {"isp": "X"}), 100)

    def test_source_score_new_static_lists(self):
        self.assertEqual(qr.source_score("cins", {"is_listed": True}), 50)
        self.assertIsNone(qr.source_score("cins", {}))
        self.assertEqual(qr.source_score("et_compromised", {"is_abuse": True}), 45)
        self.assertIsNone(qr.source_score("et_compromised", {}))

    def test_flag_opinions(self):
        self.assertEqual(
            qr._flag_opinions("freeipapi", {"is_proxy": True}), {"proxy": True})
        self.assertEqual(
            qr._flag_opinions("freeipapi", {"is_proxy": False}), {"proxy": False})
        self.assertEqual(qr._flag_opinions("freeipapi", {}), {})
        self.assertEqual(
            qr._flag_opinions("scamalytics", {"is_blacklisted": True}),
            {"listed": True})
        self.assertEqual(qr._flag_opinions("scamalytics", {}), {})
        self.assertEqual(
            qr._flag_opinions("iplocation", {"is_proxy": True}), {"proxy": True})
        self.assertEqual(
            qr._flag_opinions("cins", {"is_listed": True}), {"listed": True})
        self.assertEqual(
            qr._flag_opinions("et_compromised", {"is_abuse": True}),
            {"abuse": True})

    def test_vote_reputation_consensus_proxy(self):
        score, _r, flagged, _n = qr.vote_reputation({
            "freeipapi": {"is_proxy": True},
            "iplocation": {"is_proxy": True},
        }, qr.REPUTATION_WEIGHTS)
        self.assertEqual(score, 72)
        self.assertIn("proxy", flagged)

    def test_vote_reputation_numeric_scamalytics(self):
        score, _r, flagged, _n = qr.vote_reputation(
            {"scamalytics": {"score": 30}}, qr.REPUTATION_WEIGHTS)
        self.assertEqual(score, 70)
        self.assertNotIn("listed", flagged)

    def test_vote_reputation_consensus_dnsbl_listed(self):
        """R265：dnsbl(ZEN SBL/XBL) 命中 listed → 共识扣 30（100→70，
        即 R252 所述 89→59 的同一口径），且与 cins/firehol_level1 等
        同维度源并存时仅计一次、不重复扣分。"""
        score, _r, flagged, _n = qr.vote_reputation(
            {"dnsbl": {"is_listed": True, "dnsbl_code": 2}},
            qr.REPUTATION_WEIGHTS)
        self.assertEqual(score, 70)
        self.assertIn("listed", flagged)
        score2, _r2, flagged2, _n2 = qr.vote_reputation(
            {"dnsbl": {"is_listed": True},
             "cins": {"is_listed": True},
             "firehol_level1": {"is_listed": True}},
            qr.REPUTATION_WEIGHTS)
        self.assertEqual(score2, 70)
        self.assertEqual(flagged2.count("listed"), 1)

    def test_defaults_include_new_sources(self):
        for name in ("freeipapi", "scamalytics", "dronebl", "cins",
                     "et_compromised"):
            self.assertIn(name, qr.DEFAULT_REP_SOURCES)
            self.assertIn(name, qr.REPUTATION_WEIGHTS)
        # R269：iplocation 退出默认源（最低权重、proxy 维度被超集覆盖）
        self.assertNotIn("iplocation", qr.DEFAULT_REP_SOURCES)
        self.assertIn("iplocation", qr.REPUTATION_WEIGHTS)

    def test_bounded_coverage_caps(self):
        self.assertTrue(0 < qr.SCAMALYTICS_CAP <= 5000)
        self.assertTrue(0 < qr.FREEIPAPI_CAP <= 10000)
        self.assertTrue(0 < qr.IPLOCATION_CAP <= 10000)

    def test_freeipapi_lookup_parsing(self):
        body = json.dumps({
            "ipAddress": "1.2.3.4", "isProxy": False, "asn": 15169,
            "asnOrganization": "Google LLC",
        }).encode()
        with unittest.mock.patch("urllib.request.urlopen") as m:
            fake = unittest.mock.MagicMock()
            fake.read.return_value = body
            m.return_value.__enter__.return_value = fake
            out = qr.freeipapi_lookup_sync("1.2.3.4")
        self.assertEqual(out, {
            "is_proxy": False, "asn": "AS15169", "org": "Google LLC"})

    def test_freeipapi_lookup_no_signal(self):
        body = json.dumps({"ipAddress": "1.2.3.4", "isProxy": False}).encode()
        with unittest.mock.patch("urllib.request.urlopen") as m:
            fake = unittest.mock.MagicMock()
            fake.read.return_value = body
            m.return_value.__enter__.return_value = fake
            self.assertIsNone(qr.freeipapi_lookup_sync("1.2.3.4"))

    def test_scamalytics_lookup_parsing(self):
        html = (
            '<div class="score_container" style="width: 10px;">'
            "Fraud Score: 12</div>"
            '<pre>\n"ip":"1.1.1.1",\n"score":"12",\n"risk":"medium",\n'
            '"is_blacklisted_external": false,\n...\n</pre>'
        )
        with unittest.mock.patch("urllib.request.urlopen") as m:
            fake = unittest.mock.MagicMock()
            fake.read.return_value = html.encode()
            m.return_value.__enter__.return_value = fake
            out = qr.scamalytics_lookup_sync("1.1.1.1")
        self.assertEqual(out, {"score": 12, "is_blacklisted": False})

    def test_scamalytics_lookup_missing_score(self):
        with unittest.mock.patch("urllib.request.urlopen") as m:
            fake = unittest.mock.MagicMock()
            fake.read.return_value = b"<html>no score</html>"
            m.return_value.__enter__.return_value = fake
            self.assertIsNone(qr.scamalytics_lookup_sync("1.1.1.1"))

    def test_iplocation_lookup_parsing(self):
        body = json.dumps({
            "ip": "1.2.3.4", "isp": "X Corp", "is_proxy": "Yes",
        }).encode()
        with unittest.mock.patch("urllib.request.urlopen") as m:
            fake = unittest.mock.MagicMock()
            fake.read.return_value = body
            m.return_value.__enter__.return_value = fake
            out = qr.iplocation_lookup_sync("1.2.3.4")
        self.assertEqual(out, {"is_proxy": True, "isp": "X Corp"})

    def test_iplocation_lookup_clean(self):
        body = json.dumps({"ip": "1.2.3.4", "isp": "HomeNet",
                           "is_proxy": "No"}).encode()
        with unittest.mock.patch("urllib.request.urlopen") as m:
            fake = unittest.mock.MagicMock()
            fake.read.return_value = body
            m.return_value.__enter__.return_value = fake
            out = qr.iplocation_lookup_sync("1.2.3.4")
        self.assertEqual(out, {"isp": "HomeNet"})

    def test_fetch_cins_splits_whitespace(self):
        lines = ["1.2.3.4 5.6.7.8", "  9.9.9.9  "]

        async def _fake(url):
            return lines

        with unittest.mock.patch.object(qr, "fetch_text_list",
                                        side_effect=_fake):
            ipset = asyncio.run(
                qr.fetch_cins_badguys())
        for ip in ("1.2.3.4", "5.6.7.8", "9.9.9.9"):
            self.assertIn(ip, ipset)

    def test_fetch_static_lists_includes_new(self):
        async def _c():
            return qr.IpSet(["1.1.1.1"])

        async def _e():
            return qr.IpSet(["2.2.2.2"])

        with unittest.mock.patch.object(qr, "fetch_cins_badguys",
                                        side_effect=_c), \
             unittest.mock.patch.object(qr, "fetch_et_compromised",
                                        side_effect=_e):
            out = asyncio.run(
                qr.fetch_static_lists(["cins", "et_compromised"]))
        self.assertIn("1.1.1.1", out["cins"])
        self.assertIn("2.2.2.2", out["et_compromised"])

    def test_fetch_static_lists_new_sources_wired(self):
        async def _a():
            return qr.IpSet(["10.0.0.1"])

        async def _b():
            return qr.IpSet(["10.0.0.2"])

        async def _c():
            return qr.IpSet(["10.0.0.3"])

        async def _d():
            return qr.IpSet(["10.0.0.4"])

        async def _e():
            return qr.IpSet(["10.0.0.5"])

        with unittest.mock.patch.object(
                qr, "fetch_blocklist_de", side_effect=_a), \
             unittest.mock.patch.object(
                qr, "fetch_blocklist_de_ssh", side_effect=_b), \
             unittest.mock.patch.object(
                qr, "fetch_blocklist_de_apache", side_effect=_c), \
             unittest.mock.patch.object(
                qr, "fetch_dan_tor", side_effect=_d), \
             unittest.mock.patch.object(
                qr, "fetch_tor_bulk", side_effect=_e):
            out = asyncio.run(
                qr.fetch_static_lists([
                    "blocklist_de", "blocklist_de_ssh", "blocklist_de_apache",
                    "danmeuk_tor", "tor_bulk",
                ]))
        self.assertIn("10.0.0.1", out["blocklist_de"])
        self.assertIn("10.0.0.2", out["blocklist_de_ssh"])
        self.assertIn("10.0.0.3", out["blocklist_de_apache"])
        self.assertIn("10.0.0.4", out["danmeuk_tor"])
        self.assertIn("10.0.0.5", out["tor_bulk"])


    def test_greynoise_malicious_strong_penalty(self):
        """GreyNoise 恶意扫描 → abuse 家族按 60 从严（非通用 35）。"""
        sig = {"is_abuse": True, "is_noise": False, "is_riot": False}
        self.assertEqual(qr._flag_opinions("greynoise", sig), {"abuse": True})
        self.assertEqual(qr.source_score("greynoise", sig), 40)
        score, _r, flagged, _n = qr.vote_reputation(
            {"greynoise": sig}, {"greynoise": 8})
        self.assertEqual(score, 40)
        self.assertEqual(flagged, ["abuse"])

    def test_greynoise_riot_and_noise_differentiated(self):
        """GreyNoise botnet(is_riot)/噪音(is_noise) 按 35/15 差异化扣分。"""
        self.assertEqual(
            qr._flag_opinions("greynoise", {"is_riot": True}), {"bot": True})
        self.assertEqual(qr.source_score("greynoise", {"is_riot": True}), 65)
        score, _r, flagged, _n = qr.vote_reputation(
            {"greynoise": {"is_riot": True}}, {"greynoise": 8})
        self.assertEqual(score, 65)
        self.assertEqual(flagged, ["bot"])
        self.assertEqual(
            qr._flag_opinions("greynoise", {"is_noise": True}), {"noise": True})
        score, _r, flagged, _n = qr.vote_reputation(
            {"greynoise": {"is_noise": True}}, {"greynoise": 8})
        self.assertEqual(score, 85)
        self.assertEqual(flagged, ["noise"])

    def test_greynoise_clean_no_signal(self):
        """干净 IP（无 noise/riot/malicious）→ 无 signal，score 100。"""
        self.assertIsNone(qr.source_score(
            "greynoise", {"is_noise": False, "is_riot": False}))
        score, _r, _f, _n = qr.vote_reputation(
            {"greynoise": {"is_noise": False, "is_riot": False}},
            {"greynoise": 8})
        self.assertEqual(score, 100)

    def test_family_penalty_max_of_confirmers(self):
        """同家族多源确认 → 每源取各自强度，vote 再取 max 且每家族仅计一次。"""
        sigs = {
            "greynoise": {"is_abuse": True},
            "feodo": {"is_abuse": True},
        }
        weights = {"greynoise": 8, "feodo": 4}
        score, _r, flagged, _n = qr.vote_reputation(sigs, weights)
        self.assertEqual(flagged, ["abuse"])
        self.assertEqual(score, 100 - 60)  # greynoise is_abuse 60 从严，feodo 通用 35 被 max 覆盖
        self.assertEqual(qr._family_penalty("greynoise", "abuse", sigs["greynoise"]), 60)
        self.assertEqual(qr._family_penalty("feodo", "abuse", sigs["feodo"]),
                         qr.FLAG_PENALTIES["abuse"])

    def test_mobile_clean_bonus_helper(self):
        self.assertEqual(qr._mobile_clean_bonus({"mobile": True}), 5)
        self.assertEqual(qr._mobile_clean_bonus({"mobile": True, "proxy": True}), 0)
        self.assertEqual(qr._mobile_clean_bonus({"mobile": False}), 0)
        self.assertEqual(qr._mobile_clean_bonus({}), 0)

    def test_consensus_min_confirm_weight(self):
        """min_confirm_weight 门槛抑制单低权重源定罪。"""
        sig = {"greynoise": {"is_abuse": True}}
        W = {"greynoise": 8}
        self.assertEqual(
            qr.consensus_flags(sig, W), {"abuse": True})
        self.assertEqual(
            qr.consensus_flags(sig, W, min_confirm_weight=100),
            {"abuse": None})

    def test_vote_responding_excludes_zero_weight(self):
        """权重 0 的源不应计入 responding。"""
        sigs = {"netcoffee": {"is_proxy": True}, "zero_w": {"is_proxy": True}}
        W = {"netcoffee": 20, "zero_w": 0}
        _s, responding, _f, _n = qr.vote_reputation(sigs, W)
        self.assertNotIn("zero_w", responding)
        self.assertIn("netcoffee", responding)


class TestBuildMetaRepMedian(unittest.TestCase):
    """build_meta 的 rep_median 对奇数长度取中间值，偶数取两中间均值。"""

    def _meta(self, scores):
        rep_map = {f"k{i}": {"score": s} for i, s in enumerate(scores)}
        return qc.build_meta({}, {}, {}, rep_map)

    def test_odd_len_takes_middle(self):
        self.assertEqual(self._meta([60, 70, 75, 80, 90])["rep_median"], 75.0)

    def test_even_len_averages_mid_two(self):
        self.assertEqual(self._meta([60, 70, 80, 90])["rep_median"], 75.0)

    def test_empty_reps_none(self):
        self.assertIsNone(self._meta([])["rep_median"])


class TestContinuousPenalty(unittest.TestCase):
    def test_single_source(self):
        merged, used = qr.continuous_penalty(
            {"netcoffee": {"trust_score": 80}},
            {"netcoffee": 10},
        )
        self.assertEqual(merged, 20)
        self.assertEqual(used, ["netcoffee"])

    def test_weighted_blend(self):
        merged, used = qr.continuous_penalty(
            {
                "netcoffee": {"trust_score": 80},
                "getipintel": {"probability": 0.5},
            },
            {"netcoffee": 10, "getipintel": 20},
        )
        self.assertEqual(merged, 40)
        self.assertEqual(sorted(used), ["getipintel", "netcoffee"])

    def test_no_responding_sources(self):
        merged, used = qr.continuous_penalty({"netcoffee": {}}, {"netcoffee": 10})
        self.assertIsNone(merged)
        self.assertEqual(used, [])

    def test_zero_weight_ignored(self):
        merged, used = qr.continuous_penalty(
            {"getipintel": {"probability": 0.9}},
            {"getipintel": 0},
        )
        self.assertIsNone(merged)
        self.assertEqual(used, [])

    def test_invalid_getipintel_probability_ignored(self):
        merged, used = qr.continuous_penalty(
            {"getipintel": {"probability": 1.5}},
            {"getipintel": 20},
        )
        self.assertIsNone(merged)
        self.assertEqual(used, [])


class TestBuildRanked(unittest.TestCase):
    def test_sorts_score_desc_latency_asc_key(self):
        text = "\n".join([
            "1.0.0.1:443#US-10ms",
            "1.0.0.2:443#US-5ms",
            "1.0.0.3:443#US-5ms",
            "1.0.0.4:443#US-3ms",
        ])
        annotations = {
            "1.0.0.1:443#US": "80",
            "1.0.0.2:443#US": "50",
            "1.0.0.3:443#US": "80",
        }
        rep_map = {
            "1.0.0.1:443#US": {"score": 80},
            "1.0.0.2:443#US": {"score": 50},
            "1.0.0.3:443#US": {"score": 80},
        }
        self.assertEqual(
            qc.build_ranked(text, annotations, rep_map),
            [
                "1.0.0.3:443#US-5ms-80",
                "1.0.0.1:443#US-10ms-80",
                "1.0.0.2:443#US-5ms-50",
                "1.0.0.4:443#US-3ms",
            ],
        )

    def test_unscored_lines_keep_relative_order_at_end(self):
        text = "\n".join([
            "1.0.0.5:443#US-10ms",
            "1.0.0.6:443#US-20ms",
            "1.0.0.7:443#US-30ms",
        ])
        self.assertEqual(
            qc.build_ranked(text, {}, {}),
            [
                "1.0.0.5:443#US-10ms",
                "1.0.0.6:443#US-20ms",
                "1.0.0.7:443#US-30ms",
            ],
        )

    def test_missing_latency_sorts_last_within_score(self):
        text = "1.0.0.1:443#US-10ms\n1.0.0.2:443#US-1ms\n1.0.0.3:443#US\n"
        rep = {f"1.0.0.{i}:443#US": {"score": 90} for i in (1, 2, 3)}
        out = qc.build_ranked(text, {}, rep)
        self.assertEqual(out[:2], ["1.0.0.2:443#US-1ms", "1.0.0.1:443#US-10ms"])
        self.assertEqual(out[2], "1.0.0.3:443#US")

    def test_existing_score_not_duplicated(self):
        text = "1.0.0.1:443#US-10ms-50\n"
        annotations = {"1.0.0.1:443#US": "50"}
        rep_map = {"1.0.0.1:443#US": {"score": 50}}
        out = qc.build_ranked(text, annotations, rep_map)
        self.assertTrue(out[0].endswith("-50"))
        self.assertEqual(out[0].count("-50"), 1)


class TestBuildAnnotations(unittest.TestCase):
    def test_score_from_rep_map(self):
        results = {"1.0.0.1:443#US": {"key": "1.0.0.1:443#US"}}
        rep_map = {"1.0.0.1:443#US": {"score": 73}}
        self.assertEqual(qc.build_annotations(results, rep_map), {
            "1.0.0.1:443#US": "73",
        })

    def test_missing_rep_yields_empty_string(self):
        results = {"1.0.0.1:443#US": {"key": "1.0.0.1:443#US"}}
        self.assertEqual(qc.build_annotations(results, {}), {
            "1.0.0.1:443#US": "",
        })


class TestRepParsers(unittest.TestCase):
    """quality_reputation 的纯解析函数（abuse 分数与 ASN 归一）契约锁。"""

    def test_abuser_score_numeric(self):
        self.assertEqual(qr.parse_abuser_score(0.0039), 0.0039)
        self.assertEqual(qr.parse_abuser_score(7), 7.0)

    def test_abuser_score_string_label(self):
        self.assertEqual(qr.parse_abuser_score("0.0039 (Low)"), 0.0039)
        self.assertEqual(qr.parse_abuser_score("2.5 (High)"), 2.5)

    def test_abuser_score_invalid_none(self):
        self.assertIsNone(qr.parse_abuser_score("(Low)"))
        self.assertIsNone(qr.parse_abuser_score("not-a-number"))
        self.assertIsNone(qr.parse_abuser_score(None))

    def test_norm_asn_variants(self):
        self.assertEqual(qr.norm_asn("AS15169"), "AS15169")
        self.assertEqual(qr.norm_asn("15169"), "AS15169")
        self.assertEqual(qr.norm_asn("as3310"), "AS3310")
        self.assertEqual(qr.norm_asn("ASN15169"), "AS15169")

    def test_norm_asn_invalid_none(self):
        self.assertIsNone(qr.norm_asn("garbage"))
        self.assertIsNone(qr.norm_asn(None))
        self.assertIsNone(qr.norm_asn(""))


class TestRunExitCodes(unittest.TestCase):
    """R303：缺源返回 1（与 china 空样本返 2、health 非 strict 恒 0 的
    分工一致，见 docs/scripts.md 退出码约定）。无网络动作。"""

    def test_missing_source_returns_1(self):
        import argparse
        import asyncio
        args = argparse.Namespace(
            source=Path("/nonexistent-all.txt"), workers=2)
        self.assertEqual(asyncio.run(qc.run(args)), 1)


if __name__ == "__main__":
    unittest.main()
