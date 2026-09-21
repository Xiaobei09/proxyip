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


class TestNoSecretsInTree(unittest.TestCase):
    """R288：入库文件不得含真密钥（私钥/webhook token/GitHub PAT/Slack token）。

    实证：全树仅 tests/test_health.py 命中，均为 `SECRET_TOKEN_ABC` 类
    脱敏固件。扫描对象为 git 跟踪的文本文件；tests/ 固件目录整体豁免。
    """

    PATTERNS = (
        "BEGIN (?:RSA )?PRIVATE KEY",
        "discord\\.com/api/webhooks/\\d+/[A-Za-z0-9_-]{10,}",
        "ghp_[A-Za-z0-9]{20,}",
        "xoxb-[A-Za-z0-9-]{10,}",
    )
    EXEMPT_PREFIXES = ("tests/",)

    def test_no_live_secrets(self):
        import re
        import subprocess
        proc = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=Path(__file__).resolve().parent.parent,
        )
        if proc.returncode != 0:
            self.skipTest("无 git 环境")
        root = Path(__file__).resolve().parent.parent
        offenders = []
        for rel in proc.stdout.splitlines():
            if not rel or rel.startswith(self.EXEMPT_PREFIXES):
                continue
            p = root / rel
            try:
                text = p.read_text(encoding="utf-8")
            except (OSError, ValueError, UnicodeDecodeError):
                continue
            for pat in self.PATTERNS:
                if re.search(pat, text):
                    offenders.append(f"{rel} ~ /{pat}/")
                    break
        self.assertEqual(offenders, [], "疑似真密钥入库：\n" + "\n".join(offenders))