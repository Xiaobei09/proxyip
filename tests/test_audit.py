import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from audit_entry_cc import (
    CF_ASN,
    classify,
    is_literal_ip,
    load_entry_geo_cache,
    save_entry_geo_cache,
)


class TestIsLiteralIp(unittest.TestCase):
    def test_v4_v6_domain(self):
        self.assertTrue(is_literal_ip("1.2.3.4"))
        self.assertTrue(is_literal_ip("2606:4700::1"))
        self.assertTrue(is_literal_ip("[2606:4700::1]"))
        self.assertFalse(is_literal_ip("example.com"))
        self.assertFalse(is_literal_ip(""))


class TestClassify(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(classify("US", {"cc": "US", "asn": 1234}, None), "ok")

    def test_ok_with_drift(self):
        self.assertEqual(
            classify("US", {"cc": "US", "asn": 1234}, "EG"), "ok_with_drift"
        )

    def test_tag_mismatch(self):
        self.assertEqual(
            classify("US", {"cc": "JP", "asn": 1234}, "JP"), "tag_mismatch"
        )

    def test_cf_fronted_wins_over_mismatch(self):
        self.assertEqual(
            classify("US", {"cc": "JP", "asn": CF_ASN}, "JP"), "cf_fronted"
        )

    def test_entry_unknown(self):
        for geo in (None, {}, {"cc": None, "asn": 1}):
            self.assertEqual(classify("US", geo, None), "entry_unknown")


class TestEntryGeoCache(unittest.TestCase):
    def _qdir(self, td):
        qdir = Path(td) / "quality"
        qdir.mkdir(parents=True)
        return qdir

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            qdir = self._qdir(td)
            src = {"1.1.1.1": {"cc": "US", "asn": 13335},
                   "2606:4700::1": {"cc": "DE", "asn": 13335}}
            save_entry_geo_cache(qdir / "entry_geo.json", src)
            got = load_entry_geo_cache(qdir / "entry_geo.json")
        self.assertEqual(got, src)

    def test_missing_and_corrupt(self):
        with tempfile.TemporaryDirectory() as td:
            qdir = self._qdir(td)
            (qdir / "entry_geo.json").write_text("{bad", encoding="utf-8")
            self.assertEqual(load_entry_geo_cache(qdir / "entry_geo.json"), {})
            self.assertEqual(load_entry_geo_cache(qdir / "no_such.json"), {})

    def test_cached_ip_not_re_queried(self):
        """缓存命中即不重查 ip-api；仅缺失 IP 进入 lookup_geo。"""
        from audit_entry_cc import audit as run_audit

        with tempfile.TemporaryDirectory() as td:
            qdir = self._qdir(td)
            (qdir / "entry_geo.json").write_text(json.dumps({
                "updated_at": "2026-09-16T00:00:00Z",
                "ips": {"1.1.1.1": {"cc": "US", "asn": 1234}},
            }), encoding="utf-8")
            src = Path(td) / "valid" / "all.txt"
            src.parent.mkdir(parents=True)
            src.write_text(
                "1.1.1.1:443#US-10ms\n2.2.2.2:443#US-10ms\n",
                encoding="utf-8",
            )
            with mock.patch(
                "audit_entry_cc.lookup_geo",
                return_value={"2.2.2.2": {"cc": "US", "asn": 9}},
            ) as lg:
                report = run_audit(src, qdir, timeout=10, delay=0)
            lg.assert_called_once_with(["2.2.2.2"], timeout=10, delay=0)
            self.assertEqual(
                report["proxies"]["1.1.1.1:443#US"]["entry_geo"], "US"
            )
            self.assertEqual(
                report["proxies"]["2.2.2.2:443#US"]["entry_geo"], "US"
            )
            cached = json.loads(
                (qdir / "entry_geo.json").read_text(encoding="utf-8")
            )["ips"]
            self.assertIn("1.1.1.1", cached)
            self.assertIn("2.2.2.2", cached)


class TestAuditEndToEndCacheWritten(unittest.TestCase):
    def test_audit_creates_entry_geo_cache(self):
        from audit_entry_cc import audit as run_audit

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            qdir = base / "quality"
            qdir.mkdir(parents=True)
            (base / "valid").mkdir(parents=True)
            src = base / "valid" / "all.txt"
            src.write_text("1.1.1.1:443#US-10ms\n", encoding="utf-8")
            with mock.patch(
                "audit_entry_cc.lookup_geo",
                return_value={"1.1.1.1": {"cc": "US", "asn": 1234}},
            ):
                report = run_audit(src, qdir, timeout=10, delay=0)
            self.assertEqual(report["proxies"]["1.1.1.1:443#US"]["asn"], 1234)
            cache_file = qdir / "entry_geo.json"
            self.assertTrue(cache_file.exists())
            self.assertIn(
                "1.1.1.1",
                json.loads(cache_file.read_text(encoding="utf-8"))["ips"],
            )

    def test_stale_cache_entries_retained_r95(self):
        """R95数据格式：entry_geo 跨批累计保留（无主动裁剪）。

        实现只增不减（audit 186-192 行：load 全量＋补缺失＋整体回写，
        无删除路径）；docs/data-spec 与 scripts.md 均作此述。本测试
        锁住该语义：过期 IP 不复查且不丢失。
        """
        from audit_entry_cc import audit as run_audit

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            qdir = base / "quality"
            qdir.mkdir(parents=True)
            (base / "valid").mkdir(parents=True)
            src = base / "valid" / "all.txt"
            src.write_text("1.1.1.1:443#US-10ms\n", encoding="utf-8")
            (qdir / "entry_geo.json").write_text(
                json.dumps({
                    "updated_at": "2026-01-01T00:00:00Z",
                    "ips": {"9.9.9.9": {"cc": "DE", "asn": 1}}}),
                encoding="utf-8")
            with mock.patch(
                "audit_entry_cc.lookup_geo",
                return_value={"1.1.1.1": {"cc": "US", "asn": 1234}},
            ) as lg:
                run_audit(src, qdir, timeout=10, delay=0)
            if lg.called:
                self.assertNotIn("9.9.9.9", lg.call_args[0][0])
            saved = json.loads(
                (qdir / "entry_geo.json").read_text(encoding="utf-8"))
            self.assertIn("updated_at", saved)
            self.assertIn("9.9.9.9", saved["ips"])
            self.assertIn("1.1.1.1", saved["ips"])


class TestLookupGeoRetryR111(unittest.TestCase):
    """R111网络健壮性：lookup_geo 有界重试＋耗尽跳过（不抛异常）。"""

    def setUp(self):
        # R163：传输层已 mock 时须绕过 E3 无包短路（dummy 端点永不真调）。
        import audit_entry_cc as ae
        self._url_patch = mock.patch.object(
            ae, "IPAPI_BATCH_URL", "http://dummy.invalid/batch")
        self._url_patch.start()
        self.addCleanup(self._url_patch.stop)

    def _resp(self, payload):
        m = mock.MagicMock()
        m.read.return_value = json.dumps(payload).encode()
        cm = mock.MagicMock()
        cm.__enter__.return_value = m
        return cm

    def test_retry_then_success(self):
        import audit_entry_cc as ae
        payload = [{"status": "success", "query": "1.1.1.1",
                    "countryCode": "US", "as": "AS1234 X"}]
        calls = []

        def fake_open(req, timeout):
            calls.append(1)
            if len(calls) == 1:
                raise TimeoutError("boom")
            return self._resp(payload)

        with mock.patch.object(ae, "deadline_open", side_effect=fake_open), \
             mock.patch.object(ae.time, "sleep"):
            out = ae.lookup_geo(["1.1.1.1"], timeout=1, delay=0.01, retries=2)
        self.assertEqual(out, {"1.1.1.1": {"cc": "US", "asn": 1234}})
        self.assertEqual(len(calls), 2)

    def test_exhaustion_skips_without_raise(self):
        import io
        from contextlib import redirect_stderr
        import audit_entry_cc as ae

        with mock.patch.object(ae, "deadline_open",
                               side_effect=TimeoutError("down")), \
             mock.patch.object(ae.time, "sleep"):
            buf = io.StringIO()
            with redirect_stderr(buf):
                out = ae.lookup_geo(["1.1.1.1", "2.2.2.2"], timeout=1,
                                    delay=0.01, retries=1)
        self.assertEqual(out, {})
        self.assertIn("failed", buf.getvalue())


class TestAudit(unittest.TestCase):
    def _qfile(self, qdir: Path, name: str, data: dict) -> None:
        (qdir / name).write_text(json.dumps(data), encoding="utf-8")

    def test_audit_end_to_end(self):
        """真实流：解析 all.txt → domain_entry 不入查列表；入境 IP 按 geo 表归类；
        ?? 未知→ entry_unknown + 写入 quality/entry_audit.json。"""
        from audit_entry_cc import audit as run_audit

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            qdir = base / "quality"
            qdir.mkdir(parents=True)
            (base / "valid").mkdir(parents=True)
            src = base / "valid" / "all.txt"
            src.write_text(
                "5.5.5.5:443#US-10ms\n"
                "1.1.1.1:443#US-10ms\n"
                "2.2.2.2:443#US-10ms\n"
                "cf.example.com:443#US-10ms\n",
                encoding="utf-8",
            )
            geo = {"1.1.1.1": {"cc": "US", "asn": 1234},
                   "2.2.2.2": {"cc": "US", "asn": CF_ASN}}
            with mock.patch("audit_entry_cc.lookup_geo", return_value=geo) as lg:
                report = run_audit(src, qdir, timeout=10, delay=0)
            lg.assert_called_once()
            self.assertEqual(report["total"], 4)
            self.assertIn("ok", report["proxies"]["1.1.1.1:443#US"]["verdict"])
            self.assertEqual(report["proxies"]["2.2.2.2:443#US"]["asn"], CF_ASN)
            self.assertEqual(
                report["proxies"]["cf.example.com:443#US"]["verdict"],
                "domain_entry",
            )
            self.assertEqual(report["summary"].get("domain_entry"), 1)
            self.assertEqual(report["summary"].get("cf_fronted"), 1)
            self.assertEqual(report["summary"].get("entry_unknown"), 1)
            self.assertEqual(report["proxies"]
                             ["5.5.5.5:443#US"]["entry_geo"], None)
            self.assertEqual(report["proxies"]
                             ["5.5.5.5:443#US"]["entry_ip"], "5.5.5.5")

    def test_main_writes_entry_audit(self):
        from audit_entry_cc import main as run_main

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            (base / "valid").mkdir(parents=True)
            (base / "quality").mkdir(parents=True)
            (base / "valid" / "all.txt").write_text(
                "1.1.1.1:443#US-10ms\n2.2.2.2:443#US-10ms\n",
                encoding="utf-8",
            )
            with mock.patch("audit_entry_cc.lookup_geo", return_value={}):
                rc = run_main(["--data-dir", str(base)])
            self.assertEqual(rc, 0)
            out = json.loads(
                (base / "quality" / "entry_audit.json").read_text(encoding="utf-8")
            )
            self.assertEqual(out["total"], 2)
            self.assertIn("entry_unknown", out["summary"])
            self.assertEqual(
                set(out),
                {"generated_at", "total", "summary", "proxies"},
                msg="entry_audit.json 顶层字段契约漂移（data-spec:285）",
            )

    def test_no_bundle_missing_warns_r172(self):
        """R172功能完整性：无包＋缓存缺失时 warn（R157 家族审计链对应；
        真 lookup 短路零网络；有包/有缓存皆静默）。"""
        import io
        from contextlib import redirect_stderr
        from audit_entry_cc import audit as run_audit
        import audit_entry_cc as ae

        def _tree(entries):
            td = tempfile.TemporaryDirectory()
            base = Path(td.name)
            (base / "valid").mkdir(parents=True)
            qdir = base / "quality"
            qdir.mkdir(parents=True)
            (base / "valid" / "all.txt").write_text(
                "".join(entries), encoding="utf-8")
            return td, base, qdir

        td, base, qdir = _tree(["1.1.1.1:443#US-10ms\n"])
        try:
            with mock.patch.object(ae, "IPAPI_BATCH_URL", None):
                err = io.StringIO()
                with redirect_stderr(err):
                    report = run_audit(base / "valid" / "all.txt", qdir,
                                       timeout=1, delay=0)
                self.assertIn("PCB bundle missing", err.getvalue())
                self.assertIn("entry_unknown", report["summary"])
        finally:
            td.cleanup()
        td, base, qdir = _tree(["1.1.1.1:443#US-10ms\n"])
        try:
            geo = {"1.1.1.1": {"cc": "US", "asn": 1234}}
            with mock.patch("audit_entry_cc.lookup_geo", return_value=geo):
                err = io.StringIO()
                with redirect_stderr(err):
                    run_audit(base / "valid" / "all.txt", qdir,
                              timeout=1, delay=0)
                self.assertNotIn("Warning", err.getvalue())
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
