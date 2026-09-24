"""下载源 loader 契约测试（R150 E2）。

``EXTRA_SOURCES / SOURCE_LABELS / SOURCE_ORIGIN_MAP`` 经
``_DL_SOURCES_BUNDLE`` 回绑 PCB ``dl_sources``；无包时依次为空
（下载仅 all.json 主源，标签/归属走通用规则）。形状断言不依赖
bundle（空亦合法）；一致性断言有包执行、无包跳过。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import download_proxies as dp


class TestDlBundleContract(unittest.TestCase):
    def test_names_exist_with_shape(self):
        self.assertIsInstance(dp.EXTRA_SOURCES, list)
        self.assertIsInstance(dp.SOURCE_LABELS, dict)
        self.assertIsInstance(dp.SOURCE_ORIGIN_MAP, dict)
        for kind, url in dp.EXTRA_SOURCES:
            self.assertIsInstance(kind, str)
            self.assertTrue(url.startswith("https://"), url)

    def test_bundle_flag_bool(self):
        self.assertIsInstance(dp._DL_SOURCES_BUNDLE, bool)

    def test_matches_plugin_when_bundled(self):
        if not dp._DL_SOURCES_BUNDLE:
            self.skipTest("needs PCB dl_sources bundle")
        from checks_bundle import load_plugin
        plug = load_plugin("dl_sources")
        self.assertEqual(dp.EXTRA_SOURCES, plug.EXTRA_SOURCES)
        self.assertEqual(dp.SOURCE_LABELS, plug.SOURCE_LABELS)
        for url, origin in plug.SOURCE_ORIGIN_MAP.items():
            self.assertEqual(dp.SOURCE_ORIGIN_MAP.get(url), origin)


if __name__ == "__main__":
    unittest.main()
