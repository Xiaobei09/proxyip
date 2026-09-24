"""外部端点 loader 契约测试（R152 E3）。

``EXTERNAL_CHECK_URL / EXT_API_SOURCES / IPAPI_BATCH_URL / IPAPI_GET_URL``
经 ``_EXT_API_BUNDLE`` 回绑 PCB ``ext_api``；无包时为 None/[]，
调用方 fail-open 跳过。形状断言不依赖 bundle；一致性断言有包执行。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import common as cm


class TestExtBundleContract(unittest.TestCase):
    def test_names_exist_with_shape(self):
        self.assertIsInstance(cm.EXT_API_SOURCES, list)
        self.assertTrue(cm.EXTERNAL_CHECK_URL is None
                        or cm.EXTERNAL_CHECK_URL.startswith("https://"))
        self.assertTrue(cm.IPAPI_BATCH_URL is None
                        or cm.IPAPI_BATCH_URL.startswith("http"))
        self.assertTrue(cm.IPAPI_GET_URL is None
                        or "{ip}" in cm.IPAPI_GET_URL)

    def test_bundle_flag_bool(self):
        self.assertIsInstance(cm._EXT_API_BUNDLE, bool)

    def test_matches_plugin_when_bundled(self):
        if not cm._EXT_API_BUNDLE:
            self.skipTest("needs PCB ext_api bundle")
        from checks_bundle import load_plugin
        plug = load_plugin("ext_api")
        self.assertEqual(cm.EXTERNAL_CHECK_URL, plug.EXTERNAL_CHECK_URL)
        self.assertEqual(cm.EXT_API_SOURCES, plug.EXT_API_SOURCES)
        self.assertEqual(cm.IPAPI_BATCH_URL, plug.IPAPI_BATCH_URL)
        self.assertEqual(cm.IPAPI_GET_URL, plug.IPAPI_GET_URL)

    def test_fail_open_without_bundle(self):
        from unittest import mock
        import audit_entry_cc as ae
        import download_proxies as dp
        import asyncio
        import quality_probe as qp
        with mock.patch.object(cm, "IPAPI_BATCH_URL", None), \
             mock.patch.object(cm, "IPAPI_GET_URL", None), \
             mock.patch.object(cm, "EXTERNAL_CHECK_URL", None), \
             mock.patch.object(cm, "EXT_API_SOURCES", []), \
             mock.patch.object(ae, "IPAPI_BATCH_URL", None), \
             mock.patch.object(dp, "IPAPI_BATCH_URL", None), \
             mock.patch.object(qp, "EXTERNAL_CHECK_URL", None):
            self.assertEqual(ae.lookup_geo(["1.1.1.1"], timeout=1, delay=0), {})
            self.assertEqual(dp.lookup_countries(["1.1.1.1"], 1, 0), {})
            self.assertEqual(asyncio.run(qp.check_external_api("1.1.1.1", "443")),
                             {"success": False})


if __name__ == "__main__":
    unittest.main()
