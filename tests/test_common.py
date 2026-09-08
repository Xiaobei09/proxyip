"""normalize_note / merge_note_tokens —— 全仓库统一备注规范器的行为契约。"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from common import (
    _cn_fallback_ms,
    _rewrite_cn_speed,
    cn_display_ms,
    cn_l2_ms,
    merge_note_tokens,
    normalize_note,
)


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
            "xxapi": {"status": "ok", "ms": 40},
            "jkapi": {"status": "ok", "ms": 55},
            "check_host": {"status": "ok", "ms": 30},
        }}
        self.assertEqual(cn_l2_ms(e), 30.0)

    def test_l2_ignores_non_ok_and_nonpositive(self):
        e = {"sources": {
            "xxapi": {"status": "fail", "ms": 10},
            "jkapi": {"status": "ok", "ms": 0},
            "check_host": {"status": "ok", "ms": 22},
        }}
        self.assertEqual(cn_l2_ms(e), 22.0)

    def test_l2_candidate_below_two_falls_to_fallback(self):
        e = {"sources": {
            "xxapi": {"status": "ok", "ms": 1.5},
            "coffee": {"status": "ok", "ms": 30},  # 非 ICMP 可信 TCP RTT
        }}
        self.assertEqual(cn_display_ms(e), 30.0)

    def test_l2_two_or_above_wins(self):
        e = {"sources": {
            "xxapi": {"status": "ok", "ms": 2.0},
            "coffee": {"status": "ok", "ms": 30},
        }}
        self.assertEqual(cn_display_ms(e), 2.0)

    def test_no_l2_uses_min_trusted_tcp_fallback(self):
        e = {"sources": {
            "chinaz": {"status": "ok", "ms": 1.0},    # 纯 ICMP 噪声，剔除
            "coffee": {"status": "ok", "ms": 45},
            "tcpingcn": {"status": "ok", "ms": 12},
        }}
        self.assertEqual(cn_display_ms(e), 12.0)

    def test_fallback_accepts_exactly_two(self):
        e = {"sources": {"coffee": {"status": "ok", "ms": 2.0}}}
        self.assertEqual(_cn_fallback_ms(e, e["sources"]), 2.0)

    def test_fallback_rejects_sub_two_noise(self):
        e = {"sources": {"coffee": {"status": "ok", "ms": 1.8}}}
        self.assertIsNone(_cn_fallback_ms(e, e["sources"]))

    def test_legacy_entry_without_sources_uses_ms(self):
        self.assertEqual(cn_l2_ms({"ms": 88.0}), 88.0)
        self.assertIsNone(cn_l2_ms({"ms": -1}))
        self.assertIsNone(cn_display_ms({}))

    def test_nothing_usable_returns_none(self):
        e = {"sources": {"chinaz": {"status": "ok", "ms": 1.0}}}
        self.assertIsNone(cn_display_ms(e))


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


class TestBuildExitCcMap(unittest.TestCase):
    def test_upstream_by_exit_ip_resolved(self):
        """upstream_meta 裸出口 IP 键经 build_exit_ip_map 解析到行键。"""
        from common import build_exit_cc_map, build_exit_ip_map
        external = {"proxies": {
            "a:443#US": {"exit_geo": {"ip": "1.1.1.1", "country": None}},
        }}
        family = {"proxies": {
            "b:443#US": {"exit_v4": "2.2.2.2"},
            "c:443#US": {"exit_v6": "2606:4700::1"},
        }}
        ips = build_exit_ip_map(external, family)
        self.assertEqual(ips, {
            "a:443#US": "1.1.1.1",
            "b:443#US": "2.2.2.2",
            "c:443#US": "2606:4700::1",
        })
        upstream = {"proxies": {
            "1.1.1.1": {"country": "sg"},       # 小写规范化
            "2.2.2.2": {"country": "HK"},
        }}
        m = build_exit_cc_map({}, external, upstream, family_data=family)
        # upstream（第 2 层）胜过 ipinfo（末位兜底）
        self.assertEqual(m["a:443#US"], "SG")
        self.assertEqual(m["b:443#US"], "HK")
        # c 无 upstream 观测 → 不受影响，且不产生幽灵键
        self.assertNotIn("c:443#US", m)

    def test_upstream_line_key_compat(self):
        """upstream_meta 若直接为行键则原样命中。"""
        from common import build_exit_cc_map
        m = build_exit_cc_map(
            {}, {}, {"proxies": {"x:443#US": {"country": "FR"}}}, {}
        )
        self.assertEqual(m, {"x:443#US": "FR"})

    def test_external_beats_upstream(self):
        from common import build_exit_cc_map
        external = {"proxies": {
            "a:443#US": {"exit_geo": {"ip": "1.1.1.1", "country": "DE"}},
        }}
        upstream = {"proxies": {"1.1.1.1": {"country": "SG"}}}
        m = build_exit_cc_map({}, external, upstream)
        self.assertEqual(m["a:443#US"], "DE")


class TestRequestFollowBounded(unittest.TestCase):
    """``request_follow`` 的响应体读取须有墙钟截止与字节上限：上游无限滴灌
    或巨型响应不得长时间占用线程 / 撑爆内存（与 WS/SSE 修复同类）。"""

    def _patch_opener(self, resp):
        import common

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


if __name__ == "__main__":
    unittest.main()
