"""Tests for quality_probe.py pure parsers and ip-api batch cascades."""

import asyncio
import contextlib
import io
import json
import sys
import time
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import quality_probe as qp
from common import parse_headers


class _Reader:
    """Feed pre-built bytes through an asyncio.StreamReader."""

    def __init__(self, data: bytes):
        self._r = asyncio.StreamReader()
        self._r.feed_data(data)
        self._r.feed_eof()

    @property
    def reader(self) -> asyncio.StreamReader:
        return self._r


class TestReadUntil(unittest.IsolatedAsyncioTestCase):
    async def test_delim_found(self):
        r = _Reader(b"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\nbody").reader
        self.assertEqual(
            await qp.read_until(r, b"\r\n\r\n", 1024),
            b"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\n",
        )

    async def test_push_back_leaves_remainder_in_buffer(self):
        # TCP 一次交付超过 delim 时，多余字节必须留在缓冲区不被丢弃
        r = _Reader(b"abcdDELIMefgh")
        self.assertEqual(await qp.read_until(r.reader, b"DELIM", 64), b"abcdDELIM")
        self.assertEqual(await r.reader.read(), b"efgh")

    async def test_eof_returns_what_came(self):
        r = _Reader(b"partial-no-delim")
        self.assertEqual(
            await qp.read_until(r.reader, b"DELIM", 1024), b"partial-no-delim")


class TestReadChunked(unittest.IsolatedAsyncioTestCase):
    async def test_single_chunk(self):
        r = _Reader(b"3\r\nabc\r\n0\r\n\r\n")
        self.assertEqual(await qp.read_chunked(r.reader, 64, b""), b"abc")

    async def test_multi_chunk_and_trailer(self):
        # 5 字节 + 3 字节两个 chunk，最后 0 chunk 带尾部空行
        r = _Reader(b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n")
        self.assertEqual(await qp.read_chunked(r.reader, 64, b""), b"helloabc")

    async def test_cap_excess_keeps_prefix(self):
        # body 已达 cap 上限时立即返回，不再读流
        r = _Reader(b"5\r\nhello\r\n0\r\n\r\n")
        self.assertEqual(await qp.read_chunked(r.reader, 2, b"xx"), b"xx")

    async def test_bad_size_breaks(self):
        # chunk 头首行不是合法 16 进制长度 → 停止聚合，保留已收 body
        r = _Reader(b"zzz\r\nrest")
        self.assertEqual(await qp.read_chunked(r.reader, 64, b"pre"), b"pre")


class TestReadHttpResponse(unittest.IsolatedAsyncioTestCase):
    async def test_content_length(self):
        r = _Reader(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        status, headers, body = await qp.read_http_response(r.reader, 1024)
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-length"], "5")
        self.assertEqual(body, b"hello")

    async def test_chunked(self):
        raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        raw += b"3\r\nabc\r\n0\r\n\r\n"
        status, headers, body = await qp.read_http_response(_Reader(raw).reader, 1024)
        self.assertEqual(status, 200)
        self.assertTrue("chunked" in headers.get("transfer-encoding", "").lower())
        self.assertEqual(body, b"abc")

    async def test_no_body_no_length(self):
        raw = b"HTTP/1.1 204 No Content\r\n\r\n"
        status, _, body = await qp.read_http_response(_Reader(raw).reader, 1024)
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")

    async def test_malformed_status_none(self):
        raw = b"NOT-HTTP\r\n\r\n"
        status, headers, body = await qp.read_http_response(_Reader(raw).reader, 1024)
        self.assertIsNone(status)
        self.assertEqual(body, b"")


class TestGroupChunks(unittest.TestCase):
    def test_chunk_by_size(self):
        items = list(range(7))
        self.assertEqual(
            qp.group_chunks(items, 3), [[0, 1, 2], [3, 4, 5], [6]]
        )

    def test_empty(self):
        self.assertEqual(qp.group_chunks([], 3), [])


class TestParseHeaders(unittest.TestCase):
    def test_status_and_headers(self):
        status, headers = parse_headers(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/plain")

    def test_bad_status(self):
        status, _ = parse_headers(b"BOGUS\r\n\r\n")
        self.assertIsNone(status)


class TestRunChecks(unittest.IsolatedAsyncioTestCase):
    async def test_time_budget_cancels_pending(self):
        # 超出时间预算的探测任务必须被取消并入 GC 集合，不残留、可复跑
        async def slow_check(*args, **kwargs):
            await asyncio.sleep(5)
            return {"done": True}

        entries = [("1.1.1.1:443#US", "1.1.1.1", "443", "US"),
                   ("2.2.2.2:443#JP", "2.2.2.2", "443", "JP")]
        ns = unittest.mock.Mock(workers=1, time_budget=0.15)
        finished = []

        async def timed_check(entry, method, args):
            t0 = asyncio.get_running_loop().time()
            res = await slow_check(entry, method, args)
            finished.append(asyncio.get_running_loop().time() - t0)
            return res

        with unittest.mock.patch.object(qp, "check_one", timed_check):
            out = await qp.run_checks(entries, {}, ns)
        self.assertEqual(out, {})
        self.assertEqual(finished, [])  # pending 全部被取消，无任务跑满

    async def test_results_collected_on_success(self):
        async def ok_check(entry, method, args):
            return {"key": entry[0], "ok": True}

        entries = [("1.1.1.1:443#US", "1.1.1.1", "443", "US"),
                   ("2.2.2.2:443#JP", "2.2.2.2", "443", "JP")]
        ns = unittest.mock.Mock(workers=2, time_budget=5)
        with unittest.mock.patch.object(qp, "check_one", ok_check):
            out = await qp.run_checks(entries, {}, ns)
        self.assertEqual(sorted(out), ["1.1.1.1:443#US", "2.2.2.2:443#JP"])


class TestBatchIpapi(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # R163：传输层已 mock 时须绕过 E3/R153 无包短路（dummy 端点永不真调）。
        for name in ("IPAPI_BATCH_URL", "IPAPI_GET_URL"):
            p = unittest.mock.patch.object(
                qp, name, f"http://dummy.invalid/{name.lower()}")
            p.start()
            self.addCleanup(p.stop)

    async def test_partial_success_keeps_only_success(self):
        with unittest.mock.patch.object(
            qp, "ipapi_batch_sync",
            return_value=[
                {"status": "success", "countryCode": "US"},
                {"status": "reserved"},  # fail 项丢弃
                {"status": "success", "countryCode": "JP"},
            ],
        ), unittest.mock.patch.object(qp, "ipapi_get_sync") as get:
            out = await qp.batch_ipapi(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        self.assertEqual(list(out), ["1.1.1.1", "3.3.3.3"])
        get.assert_not_called()

    async def test_query_preferred_over_position(self):
        """带 query 自回填且乱序/缺项 → 按 query 键控，不错位到相邻 IP。"""
        with unittest.mock.patch.object(
            qp, "ipapi_batch_sync",
            return_value=[
                {"status": "success", "query": "2.2.2.2", "countryCode": "FR"},
                {"status": "success", "query": "1.1.1.1", "countryCode": "US"},
            ],
        ), unittest.mock.patch.object(qp, "ipapi_get_sync") as get:
            out = await qp.batch_ipapi(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        self.assertEqual(out["1.1.1.1"]["countryCode"], "US")
        self.assertEqual(out["2.2.2.2"]["countryCode"], "FR")
        self.assertNotIn("3.3.3.3", out)  # 缺失项不得错位占用相邻键
        get.assert_not_called()

    async def test_partial_batch_exception_keeps_success_skips_fallback(self):
        """某 chunk 抛异常、其余成功（any_batch_ok）→ 只保成功 chunk，
        失败 chunk 不触发 per-IP 兜底（deadline 止损优先，地理下轮补齐）。"""
        ips = [f"1.0.0.{i}" for i in range(150)]
        calls = {"n": 0}

        def _batch(chunk):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("network down")
            return [{"status": "success", "query": ip, "countryCode": "US"}
                    for ip in chunk]

        with unittest.mock.patch.object(
            qp, "ipapi_batch_sync", side_effect=_batch,
        ), unittest.mock.patch.object(qp, "ipapi_get_sync") as get:
            out = await qp.batch_ipapi(ips)
        self.assertEqual(calls["n"], 2)
        self.assertIn("1.0.0.0", out)
        self.assertIn("1.0.0.99", out)
        self.assertEqual(len(out), 100)
        get.assert_not_called()

    async def test_fallback_to_per_ip_when_batch_all_fail(self):
        with unittest.mock.patch.object(
            qp, "ipapi_batch_sync", side_effect=RuntimeError("network down"),
        ), unittest.mock.patch.object(
            qp, "ipapi_get_sync",
            side_effect=[
                {"status": "success", "countryCode": "DE"},
                {"status": "fail", "message": "reserved"},
            ],
        ):
            out = await qp.batch_ipapi(["1.1.1.1", "2.2.2.2"])
        self.assertEqual(list(out), ["1.1.1.1"])
        self.assertEqual(out["1.1.1.1"]["countryCode"], "DE")

    async def test_deadline_stops_batch_chunks(self):
        """deadline 超龄：批量分块阶段直接退出，不再发起任何请求。"""
        with unittest.mock.patch.object(
            qp, "ipapi_batch_sync",
            side_effect=RuntimeError("network down"),
        ) as batch, unittest.mock.patch.object(
            qp, "ipapi_get_sync",
            side_effect=RuntimeError("network down"),
        ) as get:
            out = await qp.batch_ipapi(["1.1.1.1", "2.2.2.2"], deadline=-1)
        self.assertEqual(out, {})
        batch.assert_not_called()
        get.assert_not_called()

    async def test_deadline_stops_per_ip_fallback(self):
        """批量全挂 + deadline 即将超龄：per-IP 兜底首个请求后即止损。"""
        with unittest.mock.patch.object(
            qp, "ipapi_batch_sync", side_effect=RuntimeError("network down"),
        ) as batch, unittest.mock.patch.object(
            qp, "ipapi_get_sync", side_effect=RuntimeError("network down"),
        ) as get:
            out = await qp.batch_ipapi(
                ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
                deadline=time.monotonic() + 0.05,
            )
        self.assertEqual(out, {})
        # 批量：3 IP 在 <0.05s 内全部失败后进入兜底；兜底至多 2 次即超龄退出
        self.assertLessEqual(batch.call_count, 3)
        self.assertLessEqual(get.call_count, 2)

    async def test_deadline_truncation_warns_stderr(self):
        """deadline 截断：partial geo 返回 + stderr 含截断警告文案。"""
        with unittest.mock.patch.object(
            qp, "ipapi_batch_sync", side_effect=RuntimeError("network down"),
        ), unittest.mock.patch.object(
            qp, "ipapi_get_sync", side_effect=RuntimeError("network down"),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                out = await qp.batch_ipapi(["1.1.1.1"], deadline=-1)
        self.assertEqual(out, {})
        self.assertIn("truncated by time deadline", buf.getvalue())

    async def test_no_bundle_returns_empty_without_sleep(self):
        """R153网络健壮性：E3无包双端点None→直接空表，不空转重试/sleep
        （否则万级IP×1.5s兜底拖死质量相位）。"""
        with unittest.mock.patch.object(qp, "IPAPI_BATCH_URL", None), \
             unittest.mock.patch.object(qp, "IPAPI_GET_URL", None), \
             unittest.mock.patch.object(qp, "ipapi_batch_sync") as batch, \
             unittest.mock.patch.object(qp, "ipapi_get_sync") as get, \
             unittest.mock.patch.object(qp.asyncio, "sleep") as sl:
            out = await qp.batch_ipapi(["1.1.1.1", "2.2.2.2"])
        self.assertEqual(out, {})
        batch.assert_not_called()
        get.assert_not_called()
        sl.assert_not_called()

    async def test_batch_partial_ok_short_circuits_fallback(self):
        """批量部分成功（any_batch_ok=True）→ per-IP 兜底永不触发。"""
        with unittest.mock.patch.object(
            qp, "ipapi_batch_sync",
            return_value=[
                {"status": "success", "countryCode": "US"},
                {"status": "success", "countryCode": "JP"},
            ],
        ) as batch, unittest.mock.patch.object(
            qp, "ipapi_get_sync",
        ) as get:
            out = await qp.batch_ipapi(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        self.assertEqual(sorted(out), ["1.1.1.1", "2.2.2.2"])
        get.assert_not_called()

    async def test_deadline_truncation_warns_scale(self):
        """per-IP 兜底被截断 → partial 结果 + stderr 含 (N/M) 规模文案。"""
        with unittest.mock.patch.object(
            qp, "ipapi_batch_sync",
            side_effect=RuntimeError("network down"),
        ), unittest.mock.patch.object(
            qp, "ipapi_get_sync",
            side_effect=RuntimeError("network down"),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                out = await qp.batch_ipapi(
                    ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
                    deadline=-1,
                )
        self.assertEqual(out, {})
        # 已完成请求数/总量为 (0/3)，截断文案同时含子串与规模
        self.assertIn("truncated by time deadline", buf.getvalue())
        self.assertIn("(0/3)", buf.getvalue())


class TestCheckExternalApiBoolGuard(unittest.IsolatedAsyncioTestCase):
    """success 判定契约：仅 JSON 布尔 true 视为成功。

    字符串 ``"false"``/``"true"``（部分 API 的字符串布尔）不得漂移成
    成功判定；None/0/字符串均非显式 ``True``。
    """

    def setUp(self):
        # R163：传输层已 mock 时须绕过 E3 无包短路（dummy 端点永不真调）。
        p = unittest.mock.patch.object(
            qp, "EXTERNAL_CHECK_URL", "https://dummy.invalid/check")
        p.start()
        self.addCleanup(p.stop)

    async def _run(self, payload: bytes) -> dict:
        with unittest.mock.patch("quality_probe.fetch_with_deadline",
                                 return_value=payload):
            return await qp.check_external_api("1.2.3.4", "443", timeout=5)

    def test_success_string_false_is_not_success(self):
        res = asyncio.run(self._run(b'{"success": "false"}'))
        self.assertIs(res["success"], False)

    def test_success_real_true_is_success(self):
        res = asyncio.run(self._run(b'{"success": true}'))
        self.assertIs(res["success"], True)

    def test_success_missing_is_false(self):
        res = asyncio.run(self._run(b'{}'))
        self.assertIs(res["success"], False)

    def test_exit_geo_and_booleans_mapped(self):
        payload = json.dumps({
            "success": True,
            "responseTime": 123,
            "probe_results": {
                "ipv4": {"ok": True, "exit": {"ip": "9.9.9.9", "country": "US"}},
                "ipv6": {"ok": False, "exit": None},
            },
        }).encode()
        res = asyncio.run(self._run(payload))
        self.assertIs(res["ipv4_ok"], True)
        self.assertIs(res["ipv6_ok"], False)
        self.assertEqual(res["exit_geo"]["ip"], "9.9.9.9")

    def test_error_shapes_minimal_dict(self):
        """探测失败的返回形状：仅 success=False，不假定其它字段存在。"""
        with unittest.mock.patch(
                "quality_probe.fetch_with_deadline",
                side_effect=OSError("api down")):
            res = asyncio.run(qp.check_external_api("1.2.3.4", "443", timeout=5))
        self.assertEqual(res, {"success": False})