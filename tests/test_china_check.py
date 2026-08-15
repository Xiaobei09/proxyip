"""Tests for china_check.py pure functions."""

import sys
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
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        merged = cc.merge_verdict(sources, cf=False)
        self.assertEqual(merged["verdict"], "reachable")
        self.assertEqual(merged["ms"], 180.0)

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
        self.assertEqual(cc.merge_verdict(sources, cf=False)["verdict"], "reachable")

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

    def test_heuristic_only_reachable(self):
        sources = {
            "check_host": {"status": "error", "ok": False, "ms": None},
            "xxapi": {"status": "error", "ok": False, "ms": None},
        }
        merged = cc.merge_verdict(sources, cf=True)
        self.assertEqual(merged["verdict"], "reachable")
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
    def test_load_sample_respects_limit(self):
        path = Path("/tmp/opencode/china_check_sample.txt")
        path.write_text(
            "1.1.1.1:80#US-1ms\n2.2.2.2:80#US-2ms\n3.3.3.3:80#US-3ms\n",
            encoding="utf-8",
        )
        sample, used = cc.load_sample(path, limit=2)
        self.assertEqual(len(sample), 2)
        self.assertEqual(sample[0][1], "1.1.1.1:80#US")
        self.assertEqual(used, path)

    def test_load_sample_skips_bad_lines(self):
        path = Path("/tmp/opencode/china_check_sample_bad.txt")
        path.write_text("garbage\n4.4.4.4:80#US-4ms\n", encoding="utf-8")
        sample, _ = cc.load_sample(path, limit=0)
        self.assertEqual([s[1] for s in sample], ["4.4.4.4:80#US"])


class TestBuildEntry(unittest.TestCase):
    def test_build_entry_shape(self):
        item = ("1.2.3.4:2087#US", "1.2.3.4:2087#US", "1.2.3.4", "2087", "US")
        entry = cc.build_entry(item, {"check_host": {"status": "ok", "ok": True, "ms": 100}})
        self.assertEqual(entry["verdict"], "reachable")
        self.assertEqual(entry["ip"], "1.2.3.4")
        self.assertIn("ts", entry)
        self.assertEqual(entry["sources"]["check_host"]["ms"], 100)


if __name__ == "__main__":
    unittest.main()
