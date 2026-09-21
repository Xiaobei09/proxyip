"""PCB 防泄漏锁：已迁入私有包的逆向细节不得出现在公开树。

- 已迁移模块路径必须不存在（如 ``scripts/china_itdog.py``）。
- 已迁移的 endpoint 字面必须不出现在公开 ``scripts/`` 与 ``tests/``
  （文档只保留行为描述，endpoint 随插件走）。
- loader 公开契约：``bundle_available/load_plugin/INTERFACE_VERSION``。
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 已迁入 PCB 的公开侧禁区：模块路径 + endpoint 字面（随插件迁移同步追加）。
# 注意：模式用拼接构造，避免本文件字面自匹配。
BANNED_MODULES = ("scripts/china_itdog.py",)
_HOST = "https://www" + ".itdog.cn/"
_AA1 = "aa1" + ".cn"
BANNED_LITERAL_RES = (
    _HOST + "batch_http/",
    _HOST + "batch_tcping/",
    _HOST + "batch_ping/",
    "wss://www" + ".itdog.cn/websockets",
    "wss://ping-qyc" + "." + _AA1 + "/tcping",
    "wss://ping-qyc" + "." + _AA1 + "/http",
    "https://ping" + "." + _AA1,
    "wss://wss" + ".phpencode.cn/www.tcpping.cn",
    # 已代号化的源身份：公开树只许代号，禁真名键。
    '"' + "itdog" + '"',
    '"' + "itdog_tcping" + '"',
    '"' + "itdog_ping" + '"',
    "'" + "itdog" + "'",
    "'" + "itdog_tcping" + "'",
    "'" + "itdog_ping" + "'",
    '"' + "aa1ping" + '"',
    '"' + "aa1http" + '"',
    "'" + "aa1ping" + "'",
    "'" + "aa1http" + "'",
    '"' + "tcpping_ws" + '"',
    "'" + "tcpping_ws" + "'",
    # cn07 探测端点（含 /start 与 /result；netcoffee 信誉库同域不同路径不受限）。
    "https://ip.net" + ".coffee/api/ping",
    '"' + "coffee" + '"',
    "'" + "coffee" + "'",
    # cn08（pingloc）探测端点（node/items 建树起点；task/create|exec 同基）。
    "https://www.pingloc" + ".com/api/v1",
    '"' + "pingloc" + '"',
    "'" + "pingloc" + "'",
    # cn09/cn10（biuping）探测端点（壳页 CSRF 起点；probe_sse.php 同基）。
    "https://www.biuping" + ".com/ping/",
    '"' + "biuping" + '"',
    "'" + "biuping" + "'",
    '"' + "biuping_ping" + '"',
    "'" + "biuping_ping" + "'",
    # cn11/cn12（98ce socket.io）探测端点（壳页节点表建树起点；同站
    # /continuous-ping 与 socket.io 事件通道同基）。
    "https://www.98ce" + ".com",
    '"' + "ce98" + '"',
    "'" + "ce98" + "'",
    '"' + "ce98_ping" + '"',
    "'" + "ce98_ping" + "'",
    # cn13（wansui）探测端点（壳页 token 起点；/ws 任务帧同基）。
    "https://www.wansui" + ".cn",
    '"' + "wansui" + '"',
    "'" + "wansui" + "'",
    # cn14/cn15（antping）探测端点（publicKey 建 JWT 起点；/ws 任务帧同基）。
    "https://antping" + ".com",
    '"' + "antping" + '"',
    "'" + "antping" + "'",
    '"' + "antping_ping" + '"',
    "'" + "antping_ping" + "'",
    # cn16（chinaz）探测端点（壳页 token 起点；pingwebsocket 同基）。
    "https://ping.chinaz" + ".com",
    "wss://tooldata" + ".chinaz.com/pingwebsocket",
    '"' + "chinaz" + '"',
    "'" + "chinaz" + "'",
    # cn17/cn18/cn19（tcpingcn）探测端点（壳页手牌起点；wss 任务帧同基）。
    "https://www" + ".tcping.cn",
    "wss://www" + ".tcping.cn",
    '"' + "tcpingcn" + '"',
    "'" + "tcpingcn" + "'",
    '"' + "tcpingcn_ping" + '"',
    "'" + "tcpingcn_ping" + "'",
    '"' + "tcpingcn_mtr" + '"',
    "'" + "tcpingcn_mtr" + "'",
    # cn20/cn21/cn22/cn23（xxapi 小小 API）四端点（免 key JSON，单节点）。
    "https://v2.xxapi" + ".cn",
    '"' + "xxapi" + '"',
    "'" + "xxapi" + "'",
    '"' + "xxping" + '"',
    "'" + "xxping" + "'",
    '"' + "xxstatus" + '"',
    "'" + "xxstatus" + "'",
    '"' + "xxscan" + '"',
    "'" + "xxscan" + "'",
    # cn24/cn25/cn26（无铭 API 三端点）免 key 单节点源（宁波电信）。
    "https://jkapi" + ".com",
    "https://api.jkapi" + ".com",
    '"' + "jkapi" + '"',
    "'" + "jkapi" + "'",
    '"' + "jkping" + '"',
    "'" + "jkping" + "'",
    '"' + "jkssl" + '"',
    "'" + "jkssl" + "'",
    # cn27/cn28/cn29（呼和浩特单节点三端点）免 key 源（5/10s + 250/h 配额）。
    "https://api.check-host" + ".cc/tcp",
    "https://api.check-host" + ".cc/ping",
    "https://api.check-host" + ".cc/http",
    "https://api.check-host" + ".cc/report/{uuid}",
    '"' + "check_host" + '"',
    "'" + "check_host" + "'",
    '"' + "checkhost_ping" + '"',
    "'" + "checkhost_ping" + "'",
    '"' + "checkhost_http" + '"',
    "'" + "checkhost_http" + "'",
    # cn30/cn31/cn32/cn33（多节点 REST 四通道）免 key 源；端点含翻页/任务/结果。
    "https://www.tcptest" + ".cn/api/v1",
    '"' + "tcptest" + '"',
    "'" + "tcptest" + "'",
    '"' + "tcptest_ping" + '"',
    "'" + "tcptest_ping" + "'",
    '"' + "tcptest_http" + '"',
    "'" + "tcptest_http" + "'",
    '"' + "tcptest_trace" + '"',
    "'" + "tcptest_trace" + "'",
    # cn34/cn35（tools.ipip.net 多节点 TCPing/路由追踪，SSE）免 key 源。
    "https://tools.ipip" + ".net/api/v1",
    '"' + "ipip" + '"',
    "'" + "ipip" + "'",
    # cn36-cn39（globalping 社区探针四通道）匿名免 key 源。
    "https://api.globalping" + ".io/v1",
    '"' + "globalping" + '"',
    "'" + "globalping" + "'",
    # cn40（ping.pe 多节点复核，antiflood + start_token）免 key 源。
    "https://tcp.ping" + ".pe",
    '"' + "ping" + "pe" + '"',
    "'" + "ping" + "pe" + "'",
    # cn41（tcpping.cn 多运营商 TCPing，token 由 CLI 注入）复核源。
    "https://tcpping" + ".cn",
    '"' + "tcpping" + '"',
    "'" + "tcpping" + "'",
    # cn42-cn44（boce.com/17ce.com/ping0.cc 多节点复核，休眠）免 key 源。
    "https://www.boce" + ".com",
    '"' + "boce" + '"',
    "'" + "boce" + "'",
    "https://www.17ce" + ".com",
    '"' + "17ce" + '"',
    "'" + "17ce" + "'",
    "https://ping0" + ".cc",
    '"' + "ping0" + '"',
    "'" + "ping0" + "'",
)
SCAN_DIRS = ("scripts", "tests")
# 扫描排除：本锁文件自身（含模式构造行）。
SCAN_EXCLUDE = {"test_checks_bundle.py"}


class TestPcbLeakGuard(unittest.TestCase):
    def test_migrated_modules_absent(self):
        for rel in BANNED_MODULES:
            self.assertFalse((ROOT / rel).exists(),
                             f"{rel} 已迁入 PCB，不得残留公开树")

    def test_endpoint_literals_absent(self):
        pats = [re.compile(p) for p in BANNED_LITERAL_RES]
        hits = []
        for d in SCAN_DIRS:
            for f in sorted((ROOT / d).glob("*.py")):
                if f.name in SCAN_EXCLUDE:
                    continue
                text = f.read_text(encoding="utf-8")
                for pat in pats:
                    if pat.search(text):
                        hits.append(f"{f.name}: {pat.pattern}")
        self.assertEqual(hits, [])

    def test_loader_contract(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import checks_bundle as cb
        self.assertTrue(hasattr(cb, "bundle_available"))
        self.assertTrue(hasattr(cb, "load_plugin"))
        self.assertEqual(cb.INTERFACE_VERSION, 1)
        self.assertIsInstance(cb.bundle_available(), bool)


# 文档侧禁区（R13）：研究日志/散文中的我方源域名与真名键（已逐项收敛，
# 决策记录类的第三方排除项与信誉族不在此列，见轮次日志）。
_DOC_BANS = (
    "boce" + ".com",
    "17ce" + ".com",
    "ping0" + ".cc",
    "tools.ipip" + ".net",
    "ipip" + ".net",
    "check-host" + ".cc",
    "xxapi" + ".cn",
    "jkapi" + ".com",
    "antping" + ".com",
    "chinaz" + ".com",
    "98ce" + ".com",
    "wansui" + ".cn",
    "pingloc" + ".com",
    "tcping" + ".cn",
    "tcp.ping" + ".pe",
    "api.hostmonit" + ".com",
    '"' + "boce" + '"',
    "'" + "boce" + "'",
    '"' + "17ce" + '"',
    "'" + "17ce" + "'",
    '"' + "ping0" + '"',
    "'" + "ping0" + "'",
    '"' + "tcpping" + '"',
    "'" + "tcpping" + "'",
    '"' + "pingpe" + '"',
    "'" + "pingpe" + "'",
    '"' + "coffee" + '"',
    "'" + "coffee" + "'",
    '"' + "chinaz" + '"',
    "'" + "chinaz" + "'",
    '"' + "antping" + '"',
    "'" + "antping" + "'",
    '"' + "xxapi" + '"',
    "'" + "xxapi" + "'",
    '"' + "jkapi" + '"',
    "'" + "jkapi" + "'",
    '"' + "check_host" + '"',
    "'" + "check_host" + "'",
    '"' + "tcptest" + '"',
    "'" + "tcptest" + "'",
    '"' + "ipip" + '"',
    "'" + "ipip" + "'",
    '"' + "globalping" + '"',
    "'" + "globalping" + "'",
    '"' + "wansui" + '"',
    "'" + "wansui" + "'",
    '"' + "ce98" + '"',
    "'" + "ce98" + "'",
)


class TestDocsLeakGuard(unittest.TestCase):
    def test_docs_source_endpoints_absent(self):
        pats = [re.compile(p) for p in _DOC_BANS]
        hits = []
        targets = list(sorted((ROOT / "docs").glob("*.md")))
        targets.append(ROOT / "README.md")
        for f in targets:
            text = f.read_text(encoding="utf-8")
            for pat in pats:
                if pat.search(text):
                    hits.append(f"{f.name}: {pat.pattern}")
        self.assertEqual(hits, [])
