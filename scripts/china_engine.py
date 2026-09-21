#!/usr/bin/env python3
"""大陆可达判定引擎（merge_verdict 及阈值表）。

从 ``china_check`` 拆出的纯判定层：输入各源 status/ratio/nodes，输出
verdict/basis/ms/level；不含任何站点私有协议细节（源身份以代号出现）。
``china_check`` 以兼容导入回填（``cc.merge_verdict`` 等名字保持可用，
测试零改）。
"""

from checks_bundle import load_plugin as _load_pcb_plugin

# 公开代号（与插件声明一致；无包环境数据口径不变；稳定公开标识）。
try:
    _itdog = _load_pcb_plugin("china_itdog")
    CN01_CODE = _itdog.CODE_HTTP
    CN02_CODE = _itdog.CODE_TCPING
    CN03_CODE = _itdog.CODE_PING
except Exception:
    CN01_CODE = "cn01"
    CN02_CODE = "cn02"
    CN03_CODE = "cn03"
try:
    _aa1 = _load_pcb_plugin("cn_aa1")
    CN04_CODE = _aa1.CODE_PING
    CN05_CODE = _aa1.CODE_HTTP
except Exception:
    CN04_CODE = "cn04"
    CN05_CODE = "cn05"
try:
    _tcpping_ws = _load_pcb_plugin("cn06")
    CN06_CODE = _tcpping_ws.CODE
except Exception:
    CN06_CODE = "cn06"
try:
    _coffee = _load_pcb_plugin("cn_coffee")
    CN07_CODE = _coffee.CODE
except Exception:
    CN07_CODE = "cn07"
try:
    _pingloc = _load_pcb_plugin("cn_pingloc")
    CN08_CODE = _pingloc.CODE
except Exception:
    CN08_CODE = "cn08"

try:
    _biuping = _load_pcb_plugin("cn_biuping")
    CN09_CODE = _biuping.CODE_TCPING
    CN10_CODE = _biuping.CODE_PING
except Exception:
    CN09_CODE = "cn09"
    CN10_CODE = "cn10"

try:
    _ce98 = _load_pcb_plugin("cn_ce98")
    CN11_CODE = _ce98.CODE
    CN12_CODE = _ce98.CODE_PING
except Exception:
    CN11_CODE = "cn11"
    CN12_CODE = "cn12"

try:
    _wansui = _load_pcb_plugin("cn_wansui")
    CN13_CODE = _wansui.CODE
except Exception:
    CN13_CODE = "cn13"

try:
    _antping = _load_pcb_plugin("cn_antping")
    CN14_CODE = _antping.CODE
    CN15_CODE = _antping.CODE_PING
except Exception:
    CN14_CODE = "cn14"
    CN15_CODE = "cn15"

try:
    _chinaz = _load_pcb_plugin("cn_chinaz")
    CN16_CODE = _chinaz.CODE
except Exception:
    CN16_CODE = "cn16"

try:
    _tcpingcn = _load_pcb_plugin("cn_tcpingcn")
    CN17_CODE = _tcpingcn.CODE
    CN18_CODE = _tcpingcn.CODE_PING
    CN19_CODE = _tcpingcn.CODE_MTR
except Exception:
    CN17_CODE = "cn17"
    CN18_CODE = "cn18"
    CN19_CODE = "cn19"
try:
    _tcptest = _load_pcb_plugin("cn_tcptest")
    CN30_CODE = _tcptest.CODE
    CN31_CODE = _tcptest.CODE_PING
    CN32_CODE = _tcptest.CODE_HTTP
    CN33_CODE = _tcptest.CODE_TRACE
except Exception:
    CN30_CODE = "cn30"
    CN31_CODE = "cn31"
    CN32_CODE = "cn32"
    CN33_CODE = "cn33"

try:
    _ipip = _load_pcb_plugin("cn_ipip")
    CN34_CODE = _ipip.CODE
    CN35_CODE = _ipip.CODE_TRACE
except Exception:
    CN34_CODE = "cn34"
    CN35_CODE = "cn35"

try:
    _globalping = _load_pcb_plugin("cn_globalping")
    CN36_CODE = _globalping.CODE
    CN37_CODE = _globalping.CODE_TRACE
    CN38_CODE = _globalping.CODE_HTTP
    CN39_CODE = _globalping.CODE_MTR
except Exception:
    CN36_CODE = "cn36"
    CN37_CODE = "cn37"
    CN38_CODE = "cn38"
    CN39_CODE = "cn39"

try:
    _pingpe = _load_pcb_plugin("cn_pingpe")
    CN40_CODE = _pingpe.CODE
except Exception:
    CN40_CODE = "cn40"

try:
    _tcpping = _load_pcb_plugin("cn_tcpping")
    CN41_CODE = _tcpping.CODE
except Exception:
    CN41_CODE = "cn41"

try:
    _legacy = _load_pcb_plugin("cn_legacy_review")
    CN42_CODE = _legacy.CODE_BOCE
    CN43_CODE = _legacy.CODE_17CE
    CN44_CODE = _legacy.CODE_PING0
except Exception:
    CN42_CODE = "cn42"
    CN43_CODE = "cn43"
    CN44_CODE = "cn44"

DEFAULT_MIN_RATIO = 0.5   # itdog 系列单源确认所需的最小节点成功率（防单节点假阳性）
MULTI_MIN_NODES = 5  # 多节点源至少报告 5 个节点才可作强确认（防限流残缺样本退化）
CN07_MIN_RATIO = 0.5  # 节点成功率达 50% 即可单独判可达（多节点 ICMP 优势）
CN16_MIN_RATIO = 0.4  # 51~53 节点可能个别缺席，放宽阈值
CN11_MIN_RATIO = DEFAULT_MIN_RATIO  # 三网多节点，≥50% 大陆节点 TCP 可达即判可达
CN09_MIN_RATIO = DEFAULT_MIN_RATIO
CN42_MIN_RATIO = DEFAULT_MIN_RATIO
CN34_MIN_RATIO = DEFAULT_MIN_RATIO
CN43_MIN_RATIO = DEFAULT_MIN_RATIO
CN44_MIN_RATIO = DEFAULT_MIN_RATIO
CN13_MIN_RATIO = DEFAULT_MIN_RATIO
CN04_MIN_RATIO = DEFAULT_MIN_RATIO
CN05_MIN_RATIO = DEFAULT_MIN_RATIO
CN15_MIN_RATIO = DEFAULT_MIN_RATIO
CN18_MIN_RATIO = DEFAULT_MIN_RATIO
CN10_MIN_RATIO = DEFAULT_MIN_RATIO
CN12_MIN_RATIO = DEFAULT_MIN_RATIO
CN06_MIN_RATIO = DEFAULT_MIN_RATIO
CN19_MIN_RATIO = DEFAULT_MIN_RATIO
CN35_MIN_RATIO = DEFAULT_MIN_RATIO
# 各多节点源可独立判 reachable 的最小节点成功率（strong_valid 的单一入口）。
# 原实现只特判多节点 ICMP 源/cn16，cn11/cn09/cn42/cn34/cn43/cn44/cn13 的
# 阈值常量定义了却从未被读取——调高任意一个都会被静默回退到 DEFAULT_MIN_RATIO。
# 这里统一接线，让每源的阈值真正生效；改动某个常量即按比例收紧/放宽该源。
def _build_verdict_tables():
    """判定表（代号运行时件）：PCB 注册表驱动；无包回 None 用 legacy 静态表。

    返回 (multi_codes, single_codes, min_ratio_map)。min_ratio_map 只含
    注册表标 min_ratio 的代号（值为专属数值或 DEFAULT_MIN_RATIO），余者
    strong_valid 回退 DEFAULT_MIN_RATIO（与旧行为一致）。
    """
    try:
        reg = _load_pcb_plugin("_sources")
    except Exception:
        return None
    multi = tuple(e["code"] for e in reg.SOURCES
                  if e.get("verdict") == "multi")
    single = tuple(e["code"] for e in reg.SOURCES
                   if e.get("verdict") == "single")
    ratios = {e["code"]: (e["min_ratio_value"]
                          if e.get("min_ratio_value") is not None
                          else DEFAULT_MIN_RATIO)
              for e in reg.SOURCES if e.get("min_ratio")}
    return multi, single, ratios


_REG_TABLES = _build_verdict_tables()
if _REG_TABLES is not None:
    _MULTI_OK = _REG_TABLES[0]
    _SINGLE_OK = _REG_TABLES[1]
    _SOURCE_MIN_RATIO = _REG_TABLES[2]
else:
    _MULTI_OK = (
        CN40_CODE, CN01_CODE, CN41_CODE, CN02_CODE, CN03_CODE, CN30_CODE, CN31_CODE, CN32_CODE, CN33_CODE, CN06_CODE, CN07_CODE, CN08_CODE, CN14_CODE, CN15_CODE, CN17_CODE, CN18_CODE, CN19_CODE, CN16_CODE, CN11_CODE, CN12_CODE, CN09_CODE, CN10_CODE, CN04_CODE, CN05_CODE,
        CN42_CODE, CN34_CODE, CN35_CODE, CN43_CODE, CN44_CODE, CN13_CODE)
    _SINGLE_OK = ("cn27", "cn28", "cn29", "cn20", "cn21", "cn22", "cn23", "cn24", "cn25", "cn26", CN36_CODE, CN37_CODE, CN38_CODE, CN39_CODE)
    _SOURCE_MIN_RATIO = {
        CN07_CODE: CN07_MIN_RATIO,
        CN16_CODE: CN16_MIN_RATIO,
        CN11_CODE: CN11_MIN_RATIO,
        CN09_CODE: CN09_MIN_RATIO,
        CN42_CODE: CN42_MIN_RATIO,
        CN34_CODE: CN34_MIN_RATIO,
        CN43_CODE: CN43_MIN_RATIO,
        CN44_CODE: CN44_MIN_RATIO,
        CN13_CODE: CN13_MIN_RATIO,
        CN04_CODE: CN04_MIN_RATIO,
        CN05_CODE: CN05_MIN_RATIO,
        CN15_CODE: CN15_MIN_RATIO,
        CN18_CODE: CN18_MIN_RATIO,
        CN30_CODE: DEFAULT_MIN_RATIO,
        CN31_CODE: DEFAULT_MIN_RATIO,
        CN32_CODE: DEFAULT_MIN_RATIO,
        CN33_CODE: DEFAULT_MIN_RATIO,
        CN10_CODE: CN10_MIN_RATIO,
        CN12_CODE: CN12_MIN_RATIO,
        CN06_CODE: CN06_MIN_RATIO,
        CN19_CODE: CN19_MIN_RATIO,
        CN35_CODE: CN35_MIN_RATIO,
    }
# cn41（token 搭车相）失败不计入 multi_failed（旧行为原样保留：其 skipped/
# fail 语义由 pingpe 相内部消化，不参与多节点失败联动）。
_MULTI_FAILED = tuple(s for s in _MULTI_OK if s != CN41_CODE)
_SINGLE_FAILED = _SINGLE_OK
def merge_verdict(sources: dict) -> dict:
    """跨源合成大陆可达性判定。

    - 确认证据至少一路强：≥1 个达标多节点源（threshold+≥5 节点）或
      ≥2 个单节点源（交叉）→ reachable；仅 1 个单节点源或弱多节点
      （无强多节点）→ uncertain（单点/弱证据不可靠）
    - 多节点源（ping.pe / cn01 / cn02 / tcpping）单独确认 → reachable，
      但**要求该源节点成功率达阈值**（cn01 系列按 ``ratio``≥0.5；
      ping.pe/tcpping 内部已是多数/60% 规则，视作满足）；比率过低的单源
      判定 → uncertain（单节点假阳性抑制）
    - 单节点源 ≥2 个失败 → unreachable（源集合见 single_failed 表）
    - 多节点源失败且所有单节点源也失败 → unreachable
    - 有确认源但也有失败源（冲突）→ 强证据多数裁定：强多节点确认或
      ≥2 单节点确认仍判 reachable（多数证据盖过单点证伪）；仅弱确认/
      孤证与失败并存时归 uncertain（保守）
    - 全部为错误/跳过 → skipped（不误判）
    - ``level``：证据分级——任一成功源给出应用层（HTTP）确认 → "http"，
      仅传输层（TCP）确认 → "tcp"，无成功源 → None

    比率字段约定：``ratio`` 存在且 < ``DEFAULT_MIN_RATIO`` 视为"弱确认"，
    不独立支撑 reachable；缺失（如单节点源）按 1.0 处理。
    """
    ok_sources = [name for name, r in sources.items() if r.get("ok")]
    fail_sources = [name for name, r in sources.items() if r["status"] == "fail"]
    ms_values = [
        r["ms"] for r in sources.values()
        if r.get("ok") and isinstance(r.get("ms"), (int, float)) and r["ms"] > 0
    ]
    ms = round(min(ms_values), 1) if ms_values else None
    # 证据分级：任一成功源给出应用层确认 → "http"；仅传输层 → "tcp"；
    # 仅 ICMP 主机存活源（多节点 ICMP/cn16）→ "icmp"（如实标注，不冒充 TCP）
    if any(sources[s].get("level") == "http" for s in ok_sources):
        level = "http"
    elif ok_sources and all(
        sources[s].get("level") == "icmp" for s in ok_sources
    ):
        level = "icmp"
    elif ok_sources:
        level = "tcp"
    else:
        level = None

    multi_ok = [s for s in ok_sources if s in _MULTI_OK]
    single_ok = [s for s in ok_sources if s in _SINGLE_OK]

    def strong_valid(source: str) -> bool:
        """该多节点源是否能独立支撑 reachable（成功率+最低报告节点数达标）。"""
        ratio = sources[source].get("ratio")
        if ratio is None:
            return True  # pingpe/tcpping 内部已实施多数/60% 规则
        if (sources[source].get("nodes") or 0) < MULTI_MIN_NODES:
            return False  # 残缺样本（限流/连接中断）不作强确认，防退化为单点假阳性
        return ratio >= _SOURCE_MIN_RATIO.get(source, DEFAULT_MIN_RATIO)

    strong_multi = [s for s in multi_ok if strong_valid(s)]

    if len(strong_multi) >= 1:
        basis = ok_sources[:]
        return {"verdict": "reachable", "basis": basis, "ms": ms, "level": level}
    if len(single_ok) >= 2:
        basis = ok_sources[:]
        return {"verdict": "reachable", "basis": basis, "ms": ms, "level": level}
    # 多节点源只有弱确认（如 cn01 仅 1/24 节点可达）→ 不能单独定论
    if multi_ok:
        basis = ok_sources[:]
        return {"verdict": "uncertain", "basis": basis, "ms": ms, "level": level}
    if ok_sources:
        basis = ok_sources[:]
        return {"verdict": "uncertain", "basis": basis, "ms": ms, "level": level}
    # 单节点源（大陆境内自备服务器实测）≥2 个不约而同 fail → 足够置信判 unreachable
    single_failed = [s for s in fail_sources if s in _SINGLE_FAILED]
    if len(single_failed) >= 2:
        return {"verdict": "unreachable", "basis": fail_sources, "ms": None, "level": None}
    multi_failed = [s for s in fail_sources if s in _MULTI_FAILED]
    if len(multi_failed) >= 2 or (len(multi_failed) >= 1 and len(single_failed) >= 1):
        return {"verdict": "unreachable", "basis": fail_sources, "ms": None, "level": None}
    if fail_sources:
        return {"verdict": "uncertain", "basis": fail_sources, "ms": None, "level": None}
    return {"verdict": "skipped", "basis": [], "ms": None, "level": None}


_CN_ISP_KEYWORDS = (("电信", "中国电信"), ("联通", "中国联通"), ("移动", "中国移动"))
def _cn_isp_label(node_name: str) -> str | None:
    """节点名含运营商关键词即归一返回，否则 None。"""
    if not isinstance(node_name, str) or not node_name:
        return None
    for kw, label in _CN_ISP_KEYWORDS:
        if kw in node_name:
            return label
    return None
