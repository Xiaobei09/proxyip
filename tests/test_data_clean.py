"""数据卫生守卫：``data/valid`` 不允许空清单残留文件。

契约（docs/data-spec.md / scripts.md）：空清单不落盘并清理上一轮残留。
历史 bug 曾以两种形式产生空壳并入库：
- 0 字节文件（``write_text`` 写空字符串）
- 1 字节换行文件（``"\\n".join([]) + "\\n"``）

CI 全量测试（quality-check / update-proxies / exit-family / china-check /
deep-speed 的 ``discover -s tests`` 步）在每次轮巡航时扫描已提交树，
一旦某释放版本重新引入空壳，即在入库前红警定位。
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from common import DATA_DIR

VALID_DIR = DATA_DIR / "valid"


class TestNoEmptyResidueFiles(unittest.TestCase):
    def test_no_zero_or_newline_only_files_in_data_valid(self):
        offenders = []
        for path in sorted(VALID_DIR.rglob("*.txt")):
            size = os.path.getsize(path)
            if size == 0:
                offenders.append(f"{path.relative_to(DATA_DIR)} (0 bytes)")
            elif size == 1 and path.read_text(encoding="utf-8") == "\n":
                offenders.append(f"{path.relative_to(DATA_DIR)} (newline-only)")
        self.assertEqual(
            offenders, [], "空清单残留文件不应入库：\n" + "\n".join(offenders)
        )