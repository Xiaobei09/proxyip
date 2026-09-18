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
from common import normalize_note, parse_ltd_line

VALID_DIR = DATA_DIR / "valid"


class TestNoEmptyResidueFiles(unittest.TestCase):
    def test_no_zero_or_newline_only_files_in_data_valid(self):
        offenders = []
        for path in sorted(VALID_DIR.rglob("*.txt")):
            size = os.path.getsize(path)
            if size == 0:
                offenders.append(f"{self._rel(path)} (0 bytes)")
            elif size == 1 and path.read_text(encoding="utf-8") == "\n":
                offenders.append(f"{self._rel(path)} (newline-only)")
        self.assertEqual(
            offenders, [], "空清单残留文件不应入库：\n" + "\n".join(offenders)
        )

    @staticmethod
    def _rel(path: Path) -> str:
        try:
            return str(path.relative_to(VALID_DIR))
        except ValueError:
            return str(path)


class TestFormatContract(unittest.TestCase):
    """R280：数据格式契约合成锁（契约 A/B）。

    实证：`data/valid/all.txt` 17974 行经 `parse_ltd_line` 全过、
    备注词表全落在归一桶内（DC/RES/MOB/PROXY、fast/mid/slow、V4/V6/DS、
    CN/CNH、U<NN>、→出口，历史 GPT/D+/YT 容忍）、延迟升序零违反。
    此处用合成行锁定解析与归一语义（不依赖 18k 活数据，避免 CI 脆弱）。
    """

    def test_contract_line_forms_parse(self):
        cases = [
            "1.2.3.4:443#US",
            "1.2.3.4:443#🇺🇸US-8ms-5.86MB/s",
            "1.2.3.4:443#🇺🇸US-8.5ms",
            "1.2.3.4:443#🇺🇸US→LAX-8ms-5.86MB/s-GPT-PROXY-fast-V4-CN-97-U100",
            "1.2.3.4:443#🇺🇸US-8ms-CN-U100",
            "1.2.3.4:443#🇺🇸US-8ms-RES-mid-DS-CNH-U60",
        ]
        for line in cases:
            with self.subTest(line=line):
                parsed = parse_ltd_line(line)
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed[3], "US")

    def test_normalize_keeps_contract_buckets(self):
        line = "1.2.3.4:443#US-8ms-5.86MB/s-GPT-PROXY-fast-V4-CN-97-U100"
        out = normalize_note(line)
        for tok in ("GPT", "PROXY-fast", "V4", "CN", "U100"):
            self.assertIn(tok, out)