"""Tests for quality_probe.py pure parsers and ip-api batch cascades."""

import asyncio
import sys
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


class TestBatchIpapi(unittest.IsolatedAsyncioTestCase):
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