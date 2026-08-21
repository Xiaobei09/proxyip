"""Tests for china_check.py pure functions."""

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import china_check as cc


CN_LINE = "1.2.3.4:2087#\U0001F1FA\U0001F1F8US-10ms-20.07MB/s-GPT-CF"
US_LINE = "5.6.7.8:443#\U0001F1FA\U0001F1F8US-8ms-5.86MB/s"


class TestHeuristic(unittest.TestCase):
    def test_cf_detected(self):
        self.assertTrue(cc.is_cf_heuristic(CN_LINE))

    def test_non_cf_rejected(self):
        self.assertFalse(cc.is_cf_heuristic(US_LINE))

    def test_cf_only_line(self):
        self.assertTrue(cc.is_cf_heuristic("9.9.9.9:80#US-1ms-CF"))

    def test_cf_line_with_exit_arrow(self):
        self.assertTrue(cc.is_cf_heuristic("9.9.9.9:80#US\u2192NRT-1ms-CF"))

    def test_all_line_note(self):
        line = "9.9.9.9:80#ALL-120ms-0.44MB/s-CF"
        self.assertEqual(cc._note(line), "-120ms-0.44MB/s-CF")
        self.assertTrue(cc.is_cf_heuristic(line))

    def test_no_annotation(self):
        self.assertFalse(cc.is_cf_heuristic("1.2.3.4:80#US"))


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
        merged = cc.merge_verdict(sources, cf=False)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["ms"], 120.0)

    def test_single_ok_uncertain(self):
        sources = {
            "check_host": {"status": "ok", "ok": True, "ms": 180},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        merged = cc.merge_verdict(sources, cf=False)
        self.assertEqual(merged["verdict"], "uncertain")

    def test_both_l2_fail_unreachable(self):
        sources = {
            "check_host": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources, cf=False)["verdict"], "unreachable")

    def test_pingpe_fail_plus_l2_fail(self):
        sources = {
            "check_host": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "ok", "ok": True, "ms": 90},
            "pingpe": {"status": "fail", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources, cf=False)["verdict"], "uncertain")

    def test_single_fail_uncertain(self):
        sources = {
            "check_host": {"status": "fail", "ok": False, "ms": None},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources, cf=False)["verdict"], "uncertain")

    def test_all_error_skipped(self):
        sources = {
            "check_host": {"status": "error", "ok": False, "ms": None},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        self.assertEqual(cc.merge_verdict(sources, cf=False)["verdict"], "skipped")

    def test_heuristic_only_uncertain(self):
        sources = {
            "check_host": {"status": "error", "ok": False, "ms": None},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        merged = cc.merge_verdict(sources, cf=True)
        self.assertEqual(merged["verdict"], "skipped")
        self.assertIn("heuristic", merged["basis"])


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
        self.assertEqual(count, 3)
        self.assertIn("1.2.3.4:80#US-1ms-CN", cn_text)
        self.assertIn("5.6.7.8:80#US-2ms-CN", cn_text)
        self.assertIn("9.9.9.9:80#US-3ms-CN", cn_text)

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

    def test_generate_all_cn_missing_ms_last_stable(self):
        text = "1.1.1.1:443#US-9ms-CN\n2.2.2.2:443#US-5ms-CN\n3.3.3.3:443#US-1ms-CN\n"
        reachable = {"1.1.1.1:443#US", "2.2.2.2:443#US"}
        cn_ms = {"1.1.1.1:443#US": 120}
        cn_text, _ = cc.generate_all_cn(text, reachable, cn_ms)
        lines = cn_text.strip().splitlines()
        # 有大陆延迟的排最前；缺失的按原序稳定垫底
        # （3.3.3.3 带历史 -CN 也入池，与 2.2.2.2 同缺 ms，按原序在其后）
        self.assertEqual(lines[0].split("#")[0], "1.1.1.1:443")
        self.assertEqual(
            [l.split("#")[0] for l in lines[1:]],
            ["2.2.2.2:443", "3.3.3.3:443"],
        )

    def test_generate_all_cn_no_map_keeps_pool_order(self):
        text = "1.1.1.1:443#US-9ms-CN\n2.2.2.2:443#US-5ms-CN\n"
        reachable = set()
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
            cc.itdog_md5_16(s), hashlib.md5(s.encode()).hexdigest()[8:24]
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
        self.assertEqual(cc.itdog_parse_nodes(html, 1), ["aaa", "ccc", "ddd"])
        self.assertEqual(cc.itdog_parse_nodes(html, 2), ["aaa", "bbb", "ccc", "ddd"])

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
        self.assertEqual(cc.itdog_parse_nodes(html, 3), ["n1", "n2", "n3"])
        self.assertEqual(cc.itdog_parse_nodes(html8, 3), ["m1", "m3", "m5"])
        # per_isp 超过组内数量 → 全取
        self.assertEqual(cc.itdog_parse_nodes(html, 9), ["n1", "n2", "n3", "n4"])

    def test_missing_group_skipped(self):
        html = '<optgroup label="中国电信"><option value="aaa">x</option></optgroup>'
        self.assertEqual(cc.itdog_parse_nodes(html, 1), ["aaa"])


class TestItdogParseSubmit(unittest.TestCase):
    def test_task_id(self):
        html = "var task_id='20260816105915300ivbsnctru1ylah0';"
        tid, err = cc.itdog_parse_submit(html)
        self.assertEqual(tid, "20260816105915300ivbsnctru1ylah0")
        self.assertEqual(err, "")

    def test_captcha_page(self):
        tid, err = cc.itdog_parse_submit('<div class="clicaptcha"></div>')
        self.assertIsNone(tid)
        self.assertEqual(err, "captcha")

    def test_no_task(self):
        tid, err = cc.itdog_parse_submit("<html>nothing</html>")
        self.assertIsNone(tid)
        self.assertEqual(err, "no task_id")


class TestItdogRecOk(unittest.TestCase):
    def test_http_ok(self):
        ok, ms, level = cc.itdog_rec_ok({"http_code": 200, "connect_time": 0.02, "all_time": 0.05})
        self.assertIs(ok, True)
        self.assertEqual(ms, 20.0)
        self.assertEqual(level, "http")

    def test_tcp_only_port(self):
        ok, ms, level = cc.itdog_rec_ok({"http_code": 0, "connect_time": 0.013, "all_time": 10.0})
        self.assertIs(ok, True)
        self.assertEqual(ms, 13.0)
        self.assertEqual(level, "tcp")

    def test_connect_refused(self):
        ok, _, _ = cc.itdog_rec_ok({"http_code": 0, "connect_time": 0.001, "all_time": 10.0})
        self.assertIs(ok, False)

    def test_connect_timeout(self):
        ok, _, _ = cc.itdog_rec_ok({"http_code": 0, "connect_time": 10.0, "all_time": 10.0})
        self.assertIs(ok, False)

    def test_node_error_inconclusive(self):
        ok, ms, level = cc.itdog_rec_ok({"type": "node_error", "task_num": 1})
        self.assertIsNone(ok)
        self.assertIsNone(ms)
        self.assertIsNone(level)

    def test_tcping_record_ok(self):
        # batch_tcping：result 为 TCP 耗时毫秒字符串
        ok, ms, level = cc.itdog_rec_ok(
            {"ip": "1.2.3.4", "port": "443", "result": "166",
             "node_id": "abc", "task_num": 1, "address": "Anycast/x"})
        self.assertIs(ok, True)
        self.assertEqual(ms, 166.0)
        self.assertEqual(level, "tcp")

    def test_tcping_record_fail(self):
        ok, ms, level = cc.itdog_rec_ok({"result": "-1", "node_id": "abc"})
        self.assertIs(ok, False)
        self.assertIsNone(ms)
        self.assertIsNone(level)

    def test_tcping_record_bad_result(self):
        ok, _, _ = cc.itdog_rec_ok({"result": None, "node_id": "abc"})
        self.assertIs(ok, False)


class TestItdogAggregate(unittest.TestCase):
    def test_any_node_ok(self):
        records = [
            {"task_num": 1, "node_id": "a", "http_code": 0, "connect_time": 0.001},
            {"task_num": 1, "node_id": "b", "http_code": 0, "connect_time": 0.020},
        ]
        agg = cc.itdog_aggregate(records, 1)
        self.assertEqual(agg[1]["status"], "ok")
        self.assertEqual(agg[1]["ms"], 20.0)
        self.assertEqual(agg[1]["level"], "tcp")

    def test_http_level_wins_over_tcp(self):
        records = [
            {"task_num": 1, "node_id": "a", "http_code": 0, "connect_time": 0.020},
            {"task_num": 1, "node_id": "b", "http_code": 200, "connect_time": 0.030},
        ]
        agg = cc.itdog_aggregate(records, 1)
        self.assertEqual(agg[1]["level"], "http")
        # ms 取所有成功节点最小值（含 tcp 节点）
        self.assertEqual(agg[1]["ms"], 20.0)

    def test_all_fail_level_none(self):
        records = [
            {"task_num": 1, "node_id": "a", "http_code": 0, "connect_time": 0.001},
            {"task_num": 1, "node_id": "b", "http_code": 0, "connect_time": 10.0},
        ]
        agg = cc.itdog_aggregate(records, 1)
        self.assertEqual(agg[1]["status"], "fail")
        self.assertIsNone(agg[1]["level"])

    def test_no_records_error(self):
        self.assertEqual(cc.itdog_aggregate([], 2)[2]["status"], "error")
        self.assertEqual(cc.itdog_aggregate([], 2)[1]["status"], "error")

    def test_node_error_only_error(self):
        records = [{"task_num": 1, "node_id": "a", "type": "node_error"}]
        self.assertEqual(cc.itdog_aggregate(records, 1)[1]["status"], "error")


class TestItdogMergeVerdict(unittest.TestCase):
    def _s(self, status):
        return {"status": status, "ok": status == "ok", "ms": 12 if status == "ok" else None}

    def test_itdog_ok_reachable(self):
        sources = {"itdog": self._s("ok"), "check_host": self._s("error")}
        self.assertEqual(cc.merge_verdict(sources, cf=False)["verdict"], "reachable")

    def test_itdog_fail_alone_uncertain(self):
        sources = {"itdog": self._s("fail"), "check_host": self._s("error")}
        self.assertEqual(cc.merge_verdict(sources, cf=False)["verdict"], "uncertain")

    def test_itdog_fail_plus_checkhost_fail(self):
        sources = {"itdog": self._s("fail"), "check_host": self._s("fail")}
        self.assertEqual(cc.merge_verdict(sources, cf=False)["verdict"], "unreachable")

    def test_pingpe_fail_plus_itdog_fail(self):
        sources = {"pingpe": self._s("fail"), "itdog": self._s("fail")}
        self.assertEqual(cc.merge_verdict(sources, cf=False)["verdict"], "unreachable")

    def test_itdog_rate_limited_neutral(self):
        sources = {"itdog": {"status": "rate_limited", "ok": False, "ms": None},
                   "check_host": {"status": "error", "ok": False, "ms": None}}
        self.assertEqual(cc.merge_verdict(sources, cf=False)["verdict"], "skipped")


class TestMergeVerdictLevel(unittest.TestCase):
    def _src(self, status, level=None, ms=12.0):
        return {"status": status, "ok": status == "ok", "ms": ms if status == "ok" else None,
                "level": level}

    def test_http_level_propagates(self):
        sources = {
            "itdog": self._src("ok", "http"),
            "check_host": self._src("error"),
        }
        merged = cc.merge_verdict(sources, cf=False)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["level"], "http")

    def test_tcp_only_level(self):
        sources = {"itdog": self._src("ok", "tcp")}
        self.assertEqual(cc.merge_verdict(sources, cf=False)["level"], "tcp")

    def test_no_ok_sources_level_none(self):
        sources = {"check_host": self._src("fail"), "xxapi": self._src("fail")}
        merged = cc.merge_verdict(sources, cf=False)
        self.assertEqual(merged["verdict"], "unreachable")
        self.assertIsNone(merged["level"])

    def test_sources_without_level_field(self):
        # 旧格式源（无 level 字段）不报错，按 tcp 计
        sources = {"itdog": {"status": "ok", "ok": True, "ms": 10}}
        self.assertEqual(cc.merge_verdict(sources, cf=False)["level"], "tcp")

    def test_itdog_tcping_is_multi_node_source(self):
        # batch_http 失败 + batch_tcping 单独 ok → reachable（多节点源）
        sources = {
            "itdog": self._src("fail"),
            "itdog_tcping": self._src("ok", "tcp"),
        }
        merged = cc.merge_verdict(sources, cf=False)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["basis"], ["itdog_tcping"])

    def test_itdog_tcping_fail_plus_single_fail_unreachable(self):
        sources = {
            "itdog_tcping": self._src("fail"),
            "check_host": self._src("fail"),
        }
        self.assertEqual(cc.merge_verdict(sources, cf=False)["verdict"], "unreachable")


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
        self.assertEqual(n, 2)
        self.assertIn("1.1.1.1:443#US-100ms-5MB/s-CN-CNH", text)
        self.assertIn("2.2.2.2:443#US-200ms-1MB/s-CN", text)

    def test_strict_skips_historical_cn(self):
        text, n = cc.generate_all_cn(self.POOL, set(), strict=True)
        self.assertEqual(n, 0)
        # strict 只影响收录（历史 -CN 不兜底），当前可达行照常标注 -CN
        text, n = cc.generate_all_cn(self.POOL, {"3.3.3.3:443#JP"}, strict=True)
        lines = text.strip().splitlines()
        self.assertEqual(n, 1)
        self.assertEqual(lines[0].split("#")[0], "3.3.3.3:443")
        self.assertTrue(lines[0].endswith("-CN"))

    def test_non_strict_keeps_historical_cn(self):
        _, n = cc.generate_all_cn(self.POOL, set(), strict=False)
        self.assertEqual(n, 1)


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


if __name__ == "__main__":
    unittest.main()
