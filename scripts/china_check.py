#!/usr/bin/env python3
"""Mainland-China reachability checks for the alive proxy pool.

独立 CI（``china-check.yml``）运行：对 ``data/valid/all.txt`` 全量（约 1.9 万行，
``--source data/valid/all.txt --limit 0``）做大陆连通性检测，产出一致结论后写回：
（本地缺省仍走 ``all_rep.txt`` 按信誉降序取前 250 的小样本）

- ``data/quality/china.json``  — 逐条检测明细（keyed，``{"proxies": {...}}``；
  含合成 verdict、证据分级 ``level`` 与连续可达轮数 ``streak``）
- ``data/valid/all_cn.txt``  — 全量大陆可达清单（源为 ``data/valid/all.txt`` 全量存活池，
  仅含本轮判定 reachable 的行（严格活清单，历史累积 ``-CN`` 不再自动纳入）；回退 all_ltd.txt；
  按大陆实测延迟升序；应用层确认行追加 ``-CNH``）
- ``data/valid/all_cn_http.txt`` — 应用层（HTTP）确认子集：本轮 level=http 或历史
  已带 ``-CNH`` 的行
- ``data/valid/all_cn_stable.txt`` — 跨轮稳定子集：连续 ≥2 轮 reachable 且
  历史翻转 ≤1（flip 判定排除慢性抖动源）
  （strict，不含历史兜底）
- ``data/valid/all.txt`` / ``all_ltd.txt`` — 可达者追加 ``-CN`` 备注

检测分层（均为无账号/免登录）：

- L2 批量通道 cn01 实测（主源，全量，PCB 插件）：每任务 5 目标 × 24 节点
  （电信/联通/移动各 8，池子 ~80/ISP，跨省等距采样），经 WebSocket 收结果，
  TCP 连通即判可达；节点返回 http_code>0 时计应用层确认（level=http）——
  TLS 端口上明文探测会收到 CF 的 400 响应，同样证明完整数据往返无 TCP 层干扰。
- L2 cn02 补测（降级通道）：cn01 对某目标失败/被限时，改用纯 TCPING 复测——
  节点池大得多（每 ISP ~75-88 个，默认取 8×3=24 节点），结果记为独立多节点源
  ``cn02``。
- L2 cn03 补测（CN-26，ICMP 主机存活通道）：同上触发条件，改用 ICMP 复测——
  节点池电信 87 / 联通 83 / 移动 89（默认取 8×3=24 节点），结果记
  为独立多节点源 ``cn03``（``level`` 归一为 ``icmp`` 且不产
  ``isp_ms``，ICMP 不得进展示延迟，多节点 ICMP 源同口径）。
- L2 单节点实测（并发）：`cn27`（呼和浩特阿里云 1 节点，需控速）+
  `cn20`（北京节点 TCP，免 key）+ `cn21`（CN-29：山东枣庄
  BGP 节点 ICMP，免 key，`level=icmp`，echo 校验防垃圾回显）+
  `cn24`（宁波电信 TCP，免 key）+
  `cn25`（同站同节点 ICMP 主机存活，免 key，`level=icmp`，
  不进延迟显示/不产 isp_ms）+   `cn26`（CN-37：同站同节点 TLS
  握手，免 key，双镜像，`level="tcp"` 保守，无 ms，只作布尔见证）+
  `cn22`（CN-38：同站 HTTP 状态码，免 key，
  `level="http"`，无 ms）+ `cn23`（CN-39：同站 8 端口
  扫描，仅 443 键产出证据，`level="tcp"`，无 ms）+
  `cn28`（CN-31：同节点 ICMP，
  仅 TCP 判 fail 时追加消歧，`level=icmp`，共用 250/h 配额）+
  `cn29`（CN-32：同节点 HTTPS 应用层确认，首个 http 级
  单节点源，仅 TCP-ok 且其余免额 0 ok 时追加猎取第二确认，共用配额）——
  十只免额单节点源中任 2 ok 即双确认（single_ok≥2→reachable），cn27
  的 250/h 配额不再是可达判定的瓶颈。
- L3 多节点复核（有界并发小样本）：`cn40`（约 13 个大陆节点，≥7/13 可达即判可达）；
  `cn30`（免费 REST，~146 大陆节点取子集做 TCP 探测，结果按节点成功率
  判定）；`cn11`（socket.io-WS，34 个大陆各省运营商节点持续 TCPing，零 key）；
  `cn09`（同站多节点 TCPing，HTTP SSE 约 39 个 ISP×节点测量单元，零 key）；
  `cn10`（CN-34，同站 ICMP，`level=icmp`，不产 `isp_ms`）；可选
  `cn41`（多运营商，需站长签发 token，缺则自动跳过）。
  `cn04`（CN-27：独立运营商 28 城三网 TCPing，WS 纯 JSON 无鉴权，
  节点原生 per-ISP，端口直连）。
  `cn12`（CN-36：同站 ICMP，35 节点 socket.io，
  结果帧与 TCP 同形，`level=icmp`，不产 `isp_ms`）。
  `cn32`（CN-35：同站应用层，`status>0` 即确认，
  `level=http`，ms 取 connect_ms；与 TCP 同节点采样）。
  `cn17`（~163 TCP 节点 + CN-30 同通道 `cn18` ICMP、
  `cn19` MTR，SHA-256 PoW + ALTCHA 会话复用纯 Python，真实端口直连）。
- 已评估并放弃：`api.hostmonit.com/check_port`（已 404）。
- 2026-09 穷尽复核（CN-19/21/22）：cn42（API 404＋AliyunCaptcha）、ipip
  （POST 405）、cn43（路由迁移）、cn44（Turnstile＋端点 404）、cn13
  （TLS 无 SAN）、aizhan（AliyunCaptcha）、站长测速（captcha＋JS 内聚）、
  cn27.net（零 CN）、dnschecker（403）、pingtool（404 无 CN）、
  oioweb/uomg（TLS 坏）。CN-25/26/27 复核见 docs/logic.md（jk 同站第二协议/
   cn03 已接入；cn42/cn43/aizhan 经逆向确认仍阻塞；ping.sx 零 CN）。

保守判定逻辑（merge_verdict）：
     多节点源（cn40/cn01/cn02/cn03/cn41/cn30/cn31/cn32/cn33/cn06/cn07/cn08/cn14/cn15/
   cn17/cn18/cn19/cn16/cn11/cn12/cn09/cn10/aa1ping/aa1http/cn42/cn34/cn35/cn43/cn44/cn13）任一 ok 且成功率达标 → reachable；
   单节点源（cn27/cn28/cn29/cn20/cn21/cn22/cn23/cn24/cn25/cn26/cn36/cn37/cn38/cn39）≥2 个 ok → reachable；仅 1 个 ok → uncertain；
  单节点源 ≥2 个 fail → unreachable；
  多节点源 fail + 任一单节点源 fail → unreachable。
  证据分级（level）：任一成功源给出应用层确认 → "http"，仅传输层 → "tcp"，
  仅 ICMP 主机存活 → "icmp"。

跨轮稳定性：写 china.json 前读取上一轮结果，per-key 维护连续可达轮数
``streak``；采样置顶上轮 reachable（续保复检，防覆盖波动把稳定 CN 键
翻出池），其次上轮 uncertain（升格候选）优先复检。

纯标准库（urllib / json / threading / concurrent.futures）。运行时告警不计入
判定，仅记录 ``skipped``；单源失败不误判。
"""

import argparse
import base64
import hashlib
import http.cookiejar
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from common import (
    CHINA_FILE,
    DEFAULT_SOURCE,
    REP_RANK_FILE,
    UA,
    VALID_ALL_CN_FILE,
    VALID_ALL_CN_HTTP_FILE,
    VALID_ALL_CN_STABLE_FILE,
    VALID_ALL_FILE,
    VALID_ALL_LTD_FILE,
    VALID_DIR,
    deadline_open,
    err_name,
    has_token,
    line_to_key,
    merge_note_tokens,
    parse_ltd_line,
    read_json,
    request_follow,
    rewrite_latency,
    clear_note_buckets,
    cn_fastest_ms,
    cn_best_isp,
    cn_isp_speed,
    cn_l2_ms,
    cn_mainland_ok,
    CN_LATENCY_CAP_MS,
    _rewrite_cn_speed,
    write_json,
    write_text_if_changed,
    _note,
)
from ws_transport import _WebSocket
from ws_transport import WS_MAX_BUF as _WS_MAX_BUF
from checks_bundle import load_plugin as _load_pcb_plugin

# 批量通道（cn01 系）协议细节已迁入私有包（PCB）：有 bundle 时从插件取，无 bundle 时
# cn01 系源整段跳过（fail-open；调参回退为历史公开值，仅用于 CLI 默认展示）。
_ITDOG_BUNDLE = False
try:
    _itdog = _load_pcb_plugin("china_itdog")
    ITDOG_BATCH_SIZE = _itdog.ITDOG_BATCH_SIZE
    ITDOG_CONCURRENCY = _itdog.ITDOG_CONCURRENCY
    ITDOG_NODES_PER_ISP = _itdog.ITDOG_NODES_PER_ISP
    ITDOG_PACING = _itdog.ITDOG_PACING
    ITDOG_PING_NODES_PER_ISP = _itdog.ITDOG_PING_NODES_PER_ISP
    ITDOG_PING_URL = _itdog.ITDOG_PING_URL
    ITDOG_TASK_TIMEOUT = _itdog.ITDOG_TASK_TIMEOUT
    ITDOG_TCPING_NODES_PER_ISP = _itdog.ITDOG_TCPING_NODES_PER_ISP
    ITDOG_TCPING_URL = _itdog.ITDOG_TCPING_URL
    itdog_batch_run = _itdog.itdog_batch_run
    _ITDOG_BUNDLE = True
except Exception:
    ITDOG_BATCH_SIZE = 5
    ITDOG_CONCURRENCY = 8
    ITDOG_NODES_PER_ISP = 8
    ITDOG_PACING = 0.5
    ITDOG_PING_NODES_PER_ISP = 8
    ITDOG_PING_URL = None
    ITDOG_TASK_TIMEOUT = 45.0
    ITDOG_TCPING_NODES_PER_ISP = 8
    ITDOG_TCPING_URL = None
    itdog_batch_run = None
WS_MAX_BUF = _WS_MAX_BUF
del _WS_MAX_BUF

# aa1 双通道（cn04/cn05）已迁入 PCB 插件 cn_aa1：有 bundle 时取实现，
# 无 bundle 时对应源 fail-open（_run_raw_slots 写 error 行，不崩）。
_AA1_BUNDLE = False
try:
    _aa1 = _load_pcb_plugin("cn_aa1")
    aa1ping_check = _aa1.aa1ping_check
    aa1http_check = _aa1.aa1http_check
    _AA1_BUNDLE = True
except Exception:
    aa1ping_check = None
    aa1http_check = None
# cn06 已迁入 PCB 插件：有 bundle 时取实现，
_TCPPING_WS_BUNDLE = False
try:
    _tcpping_ws = _load_pcb_plugin("cn06")
    tcpping_ws_check = _tcpping_ws.tcppping_ws_check
    TCPPING_WS_CODE = _tcpping_ws.CODE
    _TCPPING_WS_BUNDLE = True
except Exception:
    tcpping_ws_check = None
    TCPPING_WS_CODE = "cn06"

# cn07 已迁入 PCB 插件 cn_coffee：有 bundle 时取实现（内部含快速重试），
# 无 bundle 时 fail-open（_run_raw_slots 写 error 行）。
_COFFEE_BUNDLE = False
try:
    _coffee = _load_pcb_plugin("cn_coffee")
    coffee_check = _coffee.coffee_check
    COFFEE_CODE = _coffee.CODE
    COFFEE_CONCURRENCY = _coffee.COFFEE_CONCURRENCY
    _COFFEE_BUNDLE = True
except Exception:
    coffee_check = None
    COFFEE_CODE = "cn07"
    COFFEE_CONCURRENCY = 24

def _err(e: Exception) -> str:
    """异常类型名（不带 ``str(e)``：URLError 的 str 含完整 URL 与 token）。"""
    return err_name(e)


FALLBACK_SOURCE = DEFAULT_SOURCE

LIMIT_DEFAULT = 250
PINGPE_LIMIT_DEFAULT = 300
PINGPE_CONCURRENCY = 6  # cn40 L3 有界并发（每键端到端 ~20-40s，串行太慢）
PINGPE_SLOT_GAP = 2.0  # 单 worker 键间最小间隔（对上游礼貌）
WORKERS_DEFAULT = 56  # L2 免额单节点源并发（基准 1000 键：48w≈108s / 64w≈86s / 无 429；取中保守）
TIMEOUT_DEFAULT = 10
POLL_DEADLINE = 75.0
POLL_INTERVAL = 3.0

# cn27-cn29（呼和浩特阿里云单节点三端点：应用层 TCP/ICMP/HTTPS，免 key，
# 匿名限速 5/10s + 250/h）已迁入 PCB 插件 cn_checkhost（协议细节见
# pcb/docs/cn28.md）。名额由 run_measurements 用公共数值常量构造共享
# 限速器；无 bundle 时三 check 为 None → 调用 TypeError → except → error
# 行 fail-open。
CH_WINDOW_SEC = 10.0
CH_PER_WINDOW = 5  # 匿名限速 5/10s
CH_HOUR_CAP = 250
_CHECKHOST_BUNDLE = False
try:
    _checkhost = _load_pcb_plugin("cn_checkhost")
    check_host_check = _checkhost.check_host_check
    checkhost_ping_check = _checkhost.checkhost_ping_check
    checkhost_http_check = _checkhost.checkhost_http_check
    RateLimiter = _checkhost.RateLimiter
    RateLimited = _checkhost.RateLimited
    CHECK_HOST_CODE = _checkhost.CODE
    CHECKHOST_PING_CODE = _checkhost.CODE_PING
    CHECKHOST_HTTP_CODE = _checkhost.CODE_HTTP
    _CHECKHOST_BUNDLE = True
except Exception:
    check_host_check = None
    checkhost_ping_check = None
    checkhost_http_check = None
    RateLimiter = None
    RateLimited = None
    CHECK_HOST_CODE = "cn27"
    CHECKHOST_PING_CODE = "cn28"
    CHECKHOST_HTTP_CODE = "cn29"

# cn20-cn23（xxapi 北京 TCP / 枣庄 ICMP / 状态码 / 443 扫描，免 key JSON，
# 单节点源族）已迁入 PCB 插件 cn_xxapi（协议细节见 pcb/docs/xxapi.md）。
# 无 bundle 时 l2 循环写 fail-open（attr 为 None，except 兜底）。
_XXAPI_BUNDLE = False
try:
    _xxapi = _load_pcb_plugin("cn_xxapi")
    xxapi_check = _xxapi.xxapi_check
    xxping_check = _xxapi.xxping_check
    xxstatus_check = _xxapi.xxstatus_check
    xxscan_check = _xxapi.xxscan_check
    XXAPI_CODE = _xxapi.CODE
    XXPING_CODE = _xxapi.CODE_PING
    XXSTATUS_CODE = _xxapi.CODE_STATUS
    XXSCAN_CODE = _xxapi.CODE_SCAN
    _XXAPI_BUNDLE = True
except Exception:
    xxapi_check = None
    xxping_check = None
    xxstatus_check = None
    xxscan_check = None
    XXAPI_CODE = "cn20"
    XXPING_CODE = "cn21"
    XXSTATUS_CODE = "cn22"
    XXSCAN_CODE = "cn23"


# cn24-cn26（jkapi 无铭 API：TC ping / ICMP ping / TLS 握手，免 key 双镜像，
# 宁波电信单节点源族）已迁入 PCB 插件 cn_jkapi（协议细节见 pcb/docs/jkapi.md）。
# 无 bundle 时卡死源（None），L2 循环跳过。
_JKAPI_BUNDLE = False
try:
    _jkapi = _load_pcb_plugin("cn_jkapi")
    jkapi_check = _jkapi.jkapi_check
    jkping_check = _jkapi.jkping_check
    jkssl_check = _jkapi.jkssl_check
    JKAPI_CODE = _jkapi.CODE
    JKPING_CODE = _jkapi.CODE_PING
    JKSSL_CODE = _jkapi.CODE_SSL
    _JKAPI_BUNDLE = True
except Exception:
    jkapi_check = None
    jkping_check = None
    jkssl_check = None
    JKAPI_CODE = "cn24"
    JKPING_CODE = "cn25"
    JKSSL_CODE = "cn26"


# cn40 ping.pe —— 约 13 个大陆节点（antiflood + start_token 流程）已迁入
# PCB 插件 cn_pingpe（协议细节见 pcb/docs/pingpe.md）。无 bundle 时
# _run_pingpe_slots 写 fail-open。
_PINGPE_BUNDLE = False
try:
    _pingpe = _load_pcb_plugin("cn_pingpe")
    pingpe_check = _pingpe.pingpe_check
    parse_pingpe_page = _pingpe.parse_pingpe_page
    parse_pingpe_results = _pingpe.parse_pingpe_results
    pingpe_verdict = _pingpe.pingpe_verdict
    PINGPE_CODE = _pingpe.CODE
    _PINGPE_BUNDLE = True
except Exception:
    pingpe_check = None
    parse_pingpe_page = None
    parse_pingpe_results = None
    pingpe_verdict = None
    PINGPE_CODE = "cn40"
from china_engine import (
    ITDOG_MIN_RATIO, MULTI_MIN_NODES, _SOURCE_MIN_RATIO,
    merge_verdict, ITDOG_CODE_HTTP, ITDOG_CODE_TCPING, ITDOG_CODE_PING,
    AA1_CODE_PING, AA1_CODE_HTTP, _cn_isp_label,
)  # 判定引擎（拆分单向依赖；cc.* 名字保持可用）
# cn41 tcpping.cn —— 多运营商 TCPing，需站长签发的 token（缺则跳过）已迁入
# PCB 插件 cn_tcpping（协议细节见 pcb/docs/tcpping.md）。token 为运行期凭证，
# 仍由公开 CLI 注入（--tcpping-token / TCPPING_CN_TOKEN env），本站不藏 key。
_TCPPING_BUNDLE = False
try:
    _tcpping_p = _load_pcb_plugin("cn_tcpping")
    parse_tcpping = _tcpping_p.parse_tcpping
    tcpping_check = _tcpping_p.tcpping_check
    TCPPING_CODE = _tcpping_p.CODE
    _TCPPING_BUNDLE = True
except Exception:
    parse_tcpping = None
    tcpping_check = None
    TCPPING_CODE = "cn41"

# cn30-cn33（tcptest.cn 多节点 REST：TCP/ICMP/HTTP/路由，免 key，~146
# 大陆节点取子集均衡采样）已迁入 PCB 插件 cn_tcptest（协议细节见
# pcb/docs/tcptest.md）。节点列表进程内缓存（插件内）；无 bundle 时
# 三函数为 None → run_measurements 跳过节点拉取，_run_tcptest_slots
# 写 fail-open error 行。配置常量（NODES/CONCURRENCY/LIMIT_DEFAULT）
# 由插件回绑，供 CLI 默认值与并发上界使用。
_TCPTEST_BUNDLE = False
try:
    _tcptest = _load_pcb_plugin("cn_tcptest")
    tcptest_fetch_nodes = _tcptest.tcptest_fetch_nodes
    tcptest_pick_nodes = _tcptest.tcptest_pick_nodes
    tcptest_check = _tcptest.tcptest_check
    TCPTEST_CODE = _tcptest.CODE
    TCPTEST_PING_CODE = _tcptest.CODE_PING
    TCPTEST_HTTP_CODE = _tcptest.CODE_HTTP
    TCPTEST_TRACE_CODE = _tcptest.CODE_TRACE
    TCPTEST_NODES = _tcptest.NODES
    TCPTEST_CONCURRENCY = _tcptest.CONCURRENCY
    TCPTEST_LIMIT_DEFAULT = _tcptest.LIMIT_DEFAULT
    _TCPTEST_BUNDLE = True
except Exception:
    tcptest_fetch_nodes = None
    tcptest_pick_nodes = None
    tcptest_check = None
    TCPTEST_CODE = "cn30"
    TCPTEST_PING_CODE = "cn31"
    TCPTEST_HTTP_CODE = "cn32"
    TCPTEST_TRACE_CODE = "cn33"
    TCPTEST_NODES = 10
    TCPTEST_CONCURRENCY = 8
    TCPTEST_LIMIT_DEFAULT = 150

# cn07（大陆多节点 ICMP，REST+轮询）协议细节已迁入 PCB 插件；
# 无 bundle 时该源 fail-open（_run_raw_slots 记 error 行）。

# cn08 已迁入 PCB 插件 cn_pingloc：有 bundle 时取实现（纯 HTTP+SSE 零鉴权，
# 协议细节见 pcb/docs/pingloc.md），无 bundle 时 _run_pingloc_slots 写 fail-open。
_PINGLOC_BUNDLE = False
try:
    _pingloc = _load_pcb_plugin("cn_pingloc")
    pingloc_check = _pingloc.pingloc_check
    PINGLOC_CODE = _pingloc.CODE
    _PINGLOC_BUNDLE = True
except Exception:
    pingloc_check = None
    PINGLOC_CODE = "cn08"

try:
    _antping = _load_pcb_plugin("cn_antping")
    antping_check = _antping.antping_check
    antping_ping_check = _antping.antping_ping_check
    ANTPING_CODE = _antping.CODE
    ANTPING_PING_CODE = _antping.CODE_PING
except Exception:
    antping_check = None
    antping_ping_check = None
    ANTPING_CODE = "cn14"
    ANTPING_PING_CODE = "cn15"

try:
    _chinaz = _load_pcb_plugin("cn_chinaz")
    chinaz_check = _chinaz.chinaz_check
    CHINAZ_CODE = _chinaz.CODE
except Exception:
    chinaz_check = None
    CHINAZ_CODE = "cn16"

# cn17/cn18/cn19（单键多节点 TCP 探测/同站 ICMP/同站 MTR）已迁入
# PCB 插件 cn_tcpingcn（ALTCHA 会话 + SHA-256 PoW + WS 共享；协议细节见
# pcb/docs/tcpingcn.md）。无 bundle 时 _run_ws_source_slots 写 fail-open。
_TCPINGCN_BUNDLE = False
try:
    _tcpingcn = _load_pcb_plugin("cn_tcpingcn")
    tcpingcn_check = _tcpingcn.tcpingcn_check
    tcpingcn_ping_check = _tcpingcn.tcpingcn_ping_check
    tcpingcn_mtr_check = _tcpingcn.tcpingcn_mtr_check
    TCPINGCN_CODE = _tcpingcn.CODE
    TCPINGCN_PING_CODE = _tcpingcn.CODE_PING
    TCPINGCN_MTR_CODE = _tcpingcn.CODE_MTR
    _TCPINGCN_BUNDLE = True
except Exception:
    tcpingcn_check = None
    tcpingcn_ping_check = None
    tcpingcn_mtr_check = None
    TCPINGCN_CODE = "cn17"
    TCPINGCN_PING_CODE = "cn18"
    TCPINGCN_MTR_CODE = "cn19"
# cn11 —— 免费大陆多节点持续 TCPing（socket.io v4 over WebSocket，零 key）：
# cn11/cn12 已迁入 PCB 插件 cn_ce98（socket.io-WS 多节点 TCPing/ICMP，零 key；
# 协议细节见 pcb/docs/ce98.md）。无 bundle 时 _run_raw_slots 记 fail-open。
_CE98_BUNDLE = False
try:
    _ce98 = _load_pcb_plugin("cn_ce98")
    ce98_check = _ce98.ce98_check
    ce98_ping_check = _ce98.ce98_ping_check
    CE98_CODE = _ce98.CODE
    CE98_PING_CODE = _ce98.CODE_PING
    _CE98_BUNDLE = True
except Exception:
    ce98_check = None
    ce98_ping_check = None
    CE98_CODE = "cn11"
    CE98_PING_CODE = "cn12"

# cn09/cn10 —— 免费大陆多节点 TCPing/Ping（纯 HTTP + SSE，零 key）：
# 协议细节已迁 PCB（cn_biuping 插件 + pcb/docs/biuping.md）。
# cn09/cn10 已迁入 PCB 插件 cn_biuping：有 bundle 时取实现（纯 HTTP+SSE 零鉴权，
# 壳页 CSRF → /probe_sse.php 事件流，协议细节见 pcb/docs/biuping.md），无 bundle
# 时 _run_raw_slots 记 fail-open。
_BIUPING_BUNDLE = False
try:
    _biuping = _load_pcb_plugin("cn_biuping")
    biuping_check = _biuping.biuping_check
    biuping_ping_check = _biuping.biuping_ping_check
    BIUPING_CODE_TCPING = _biuping.CODE_TCPING
    BIUPING_CODE_PING = _biuping.CODE_PING
    _BIUPING_BUNDLE = True
except Exception:
    biuping_check = None
    biuping_ping_check = None
    BIUPING_CODE_TCPING = "cn09"
    BIUPING_CODE_PING = "cn10"

# cn36-cn39（globalping 社区探针：ICMP/路由追踪/应用层/MTR，匿名免 key
# 单节点冗余票）已迁入 PCB 插件 cn_globalping（协议细节见
# pcb/docs/globalping.md）。无 bundle 时四函数为 None → _run_raw_slots
# 写 fail-open error 行。四路匿名 250/h 配额；CI 配额 60/40/40/40 键@4
# 并发由 CI 行经 --<name>-limit 显式启用。
_GLOBALPING_BUNDLE = False
try:
    _globalping = _load_pcb_plugin("cn_globalping")
    globalping_check = _globalping.globalping_check
    globalping_trace_check = _globalping.globalping_trace_check
    globalping_http_check = _globalping.globalping_http_check
    globalping_mtr_check = _globalping.globalping_mtr_check
    GLOBALPING_CODE = _globalping.CODE
    GLOBALPING_TRACE_CODE = _globalping.CODE_TRACE
    GLOBALPING_HTTP_CODE = _globalping.CODE_HTTP
    GLOBALPING_MTR_CODE = _globalping.CODE_MTR
    _GLOBALPING_BUNDLE = True
except Exception:
    globalping_check = None
    globalping_trace_check = None
    globalping_http_check = None
    globalping_mtr_check = None
    GLOBALPING_CODE = "cn36"
    GLOBALPING_TRACE_CODE = "cn37"
    GLOBALPING_HTTP_CODE = "cn38"
    GLOBALPING_MTR_CODE = "cn39"

# cn10 同站 ICMP 复用（CN-34）：biuping_ping_check（pcb cn_biuping 插件）
# 即 ping 模式（type=ping，level=icmp）。单列 cn10 源走
# ICMP，与 TCP 同站同节点池（约 39 测量单元）、不同协议层（低增益-同站）。
# ping 原生 ms 已实证（广东电信 7.578ms），但为与全部 ICMP 源一致仍剥离
# isp_ms（防 1~8ms 进展示；多节点 ICMP 源同口径）。

# cn12 同站 ICMP 复用（CN-36，见 pcb cn_ce98.ce98_ping_check）：35 节点（电信 11/
# 移动 10/联通 8/多线 4/港澳台 1/海外 1，原生 isp 字段），结果帧与 TCP
# 同形（ok/loss/latest/average）；level=icmp，不产 isp_ms。


# —— 博采网拨测族（HTTP 多节点 TCPing，cookie-session + CSRF token 反爬）：
# cn42/cn43/cn44 —— boce.com/17ce.com/ping0.cc 三源（多节点 TCPing，免 key，
# cookie-session+CSRF / HMAC token / header-token 反爬）已迁入 PCB 插件
# cn_legacy_review（协议细节与休眠状态见 pcb/docs/legacy_review.md）。
# 2026-09 复核：cn42 API 404＋AliyunCaptcha、cn43 /api.php 404 路由迁移、
# cn44 Turnstile＋端点 404 —— 三源休眠，公开树禁绕过验证墙（须人复核解除）。

# cn34/cn35（tools.ipip.net GET+SSE 多节点 TCPing/路由追踪，免 key，
# 原生三网 isp_ms）已迁入 PCB 插件 cn_ipip（协议细节见 pcb/docs/ipip.md）。
# 无 bundle 时两函数为 None → _run_raw_slots 写 fail-open error 行。
# 常数（探测端点/采集窗/探针数）由插件持有；CI 配额 100/100 键@8 并发
# 经 --<name>-limit 显式启用。
_IPIP_BUNDLE = False
try:
    _ipip = _load_pcb_plugin("cn_ipip")
    ipip_check = _ipip.ipip_check
    ipip_trace_check = _ipip.ipip_trace_check
    IPIP_CODE = _ipip.CODE
    IPIP_TRACE_CODE = _ipip.CODE_TRACE
    _IPIP_BUNDLE = True
except Exception:
    ipip_check = None
    ipip_trace_check = None
    IPIP_CODE = "cn34"
    IPIP_TRACE_CODE = "cn35"

_LEGACY_REVIEW_BUNDLE = False
try:
    _legacy = _load_pcb_plugin("cn_legacy_review")
    boce_check = _legacy.boce_check
    seventeen_check = _legacy.seventeen_check
    ping0_check = _legacy.ping0_check
    BOCE_CODE = _legacy.CODE_BOCE
    SEVENTEEN_CODE = _legacy.CODE_17CE
    PING0_CODE = _legacy.CODE_PING0
    _LEGACY_REVIEW_BUNDLE = True
except Exception:
    boce_check = None
    seventeen_check = None
    ping0_check = None
    BOCE_CODE = "cn42"
    SEVENTEEN_CODE = "cn43"
    PING0_CODE = "cn44"

# cn13 已迁入 PCB 插件 cn_wansui（cookie token + WS 推送 TCPing，休眠态；
# 协议细节见 pcb/docs/wansui.md）。无 bundle 时 _run_raw_slots 记 fail-open。
_WANSUI_BUNDLE = False
try:
    _wansui = _load_pcb_plugin("cn_wansui")
    wansui_check = _wansui.wansui_check
    WANSUI_CODE = _wansui.CODE
    _WANSUI_BUNDLE = True
except Exception:
    wansui_check = None
    WANSUI_CODE = "cn13"

# itdog.cn —— 无账号批量探活（每任务约 5 目标 × 3 运营商 × ITDOG_NODES_PER_ISP
# 节点（默认 8 → 24），需走 WebSocket 收结果，任务级另出 per-ISP 最小 RTT）

CN_TOKEN = "CN"


# ------------------------------------------------------------ 解析函数（纯）


# ------------------------------------------------------------ 探测 I/O（网络）

def tcpping_check(ip: str, port: str, token: str, timeout: float) -> dict:
    if not token:
        return {"status": "skipped", "ok": False, "ms": None, "error": "no token"}
    url = f"{TCPPING_URL}?url={ip}&port={port}&token={urllib.parse.quote(token)}"
    try:
        status, _, resp = request_follow(url, {"User-Agent": UA, "Accept": "application/json"}, timeout)
    except urllib.error.HTTPError as e:
        return {"status": "error", "ok": False, "ms": None, "error": f"http {e.code}"}
    except Exception as e:
        return {"status": "error", "ok": False, "ms": None, "error": _err(e)}
    if status != 200:
        return {"status": "error", "ok": False, "ms": None, "error": f"http {status}"}
    try:
        payload = json.loads(resp.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {"status": "error", "ok": False, "ms": None, "error": "bad json"}
    return parse_tcpping(payload)

# ------------------------------------------------------------ cn11-cn12（socket.io）/ cn09-cn10（SSE）


# 大陆节点名运营商关键词 → cn01 口径归一（电信/联通/移动），供各源
# isp_ms 跨源合并；云厂商/裸地名/未知返回 None（不贡献运营商视角）。


# ------------------------------------------------------------ 判定合成

def merge_isp_ms(entries: dict) -> None:
    """就地合并各源 ``isp_ms`` 到 per-key ``entry["isp_ms"]``（各运营商最小 RTT）。

    源结果只需带 ``isp_ms``（``{运营商: ms}``，cn01/cn30/cn11/cn09/
    aa1ping/cn32 多节点源与 cn24 单节点（宁波电信，CN-39）提供，
    其他源缺省 {}-即贡献空），跨源按运营商取最小——显示口径=最快运营商视角。无任何
    per-ISP 读数的条目不写该字段，下游回退 ``cn_display_ms`` 单值口径。
    """
    for e in entries.values():
        if not isinstance(e, dict):
            continue
        sources = e.get("sources")
        if not isinstance(sources, dict):
            continue
        merged: dict[str, float] = {}
        for _name, r in sources.items():
            if not isinstance(r, dict):
                continue
            im = r.get("isp_ms")
            if not isinstance(im, dict):
                continue
            for isp, v in im.items():
                if isinstance(v, (int, float)) and v > 0:
                    merged[isp] = min(merged.get(isp, v), v)
        if merged:
            e["isp_ms"] = {
                isp: round(v, 1) for isp, v in sorted(merged.items())
            }


def merge_isp_speed(entries: dict) -> None:
    """就地由已合并的 ``entry["isp_ms"]`` 派生 ``entry["isp_speed"]``
    （``{运营商: 估算MB/s}``，公式见 ``common.cn_isp_speed``，与 CN 清单
    ``≈XMB/s`` 同口径）。

    只增字段：无 ``isp_ms`` 的条目不写该字段；展示层消费（后缀/排序）留待
    CN/信誉逻辑优化轮，前端契约零改动。
    """
    for e in entries.values():
        if not isinstance(e, dict):
            continue
        sp = cn_isp_speed(e.get("isp_ms"))
        if sp:
            e["isp_speed"] = sp


def needs_probe(entries: dict, key: str) -> bool:
    """仅对仍未定论的键继续投递多节点源：uncertain/无判定才扫；
    reachable/unreachable 已定论，避免浪费免费源配额反复探测死键。"""
    return merge_verdict(entries.get(key, {}))["verdict"] in ("uncertain", "skipped")


def has_cn_note(line: str) -> bool:
    return has_token(_note(line), "CN")


def annotate_cn(line: str) -> str:
    return merge_note_tokens(line, "CN")


# ------------------------------------------------------------ 数据装载与写出

def load_sample(source: Path, limit: int) -> tuple[list, Path]:
    """返回 ``([(line, key, ip, port, cc), ...], used_path)``，按信誉降序截取。"""
    path = source if source.exists() else FALLBACK_SOURCE
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    out = []
    for line in lines:
        parsed = parse_ltd_line(line)
        if not parsed:
            continue
        key, ip, port, cc = parsed
        out.append((line, key, ip, port, cc))
    if limit and limit > 0:
        out = out[:limit]
    return out, path


def build_entry(item, sources: dict) -> dict:
    _, key, ip, port, cc = item
    merged = merge_verdict(sources)
    return {
        "ip": ip,
        "port": port,
        "cc": cc,
        "verdict": merged["verdict"],
        "basis": merged["basis"],
        "ms": merged["ms"],
        "level": merged.get("level"),
        "sources": sources,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def load_cn_pool() -> str:
    """全量存活池文本（``all_cn.txt`` 生成源）：优先 ``data/valid/all.txt``，缺则回退 all_ltd.txt。"""
    path = VALID_ALL_FILE
    if not path.exists():
        path = VALID_ALL_LTD_FILE
    return path.read_text(encoding="utf-8") if path.exists() else ""


def annotate_cnh(line: str) -> str:
    """给行追加 ``-CNH``（应用层 HTTP 确认），幂等。"""
    return merge_note_tokens(line, "CNH")


STREAK_GAP_TOLERANCE_S = 6 * 3600  # 连续轮时间窗：基线观测早于此视为中断。
# GitHub schedule 实测每 ~2.5-4h 才实际起一轮（cron 队列抖动 + 同 workflow
# 去重），3h 容差会被反复击穿、每一轮都把 streak 清零 → stable 永远攒不起来
# （实测 02:56→06:37 相隔 3h40m 即全体重置）。6h 容差吸收调度抖动：轮间
# 间隔可容忍跳过一到两班，同时仍能在长时间停更时如实降温。
FLIP_FORGIVE_STREAK = 4  # 连续可达达此轮数后清零 flip（稳定恢复赦免历史抖动）
STABLE_MAX_FLIP = 1  # stable 准入：历史翻转次数上限（排除慢性抖动源）
# CN 清单延迟语义（common.cn_fastest_ms / cn_l2_ms）：每行展示大陆视角读数，
# 最快运营商视角（entry isp_ms 全局最小）优先，无 per-ISP 读数回退可信大陆
# 探测 cn_l2_ms；
# 绝不让 L3 复核源的 1ms 噪声冒充真实延迟。CN 清单保持完整（全可达集），
# --cn-latency-cap 只用于信息性 cn_mainland 打标，不砍清单。


def apply_streak(
    entries: dict, prev_entries: dict, now: float | None = None
) -> None:
    """就地写入连续可达轮数 ``streak``、最近可达时间 ``last_ok_ts`` 与翻转
    计数 ``flip``。

    reachable 且上一轮也 reachable、且上一轮观测距今 ≤
    STREAK_GAP_TOLERANCE_S → 上一轮 streak+1；否则从 1 起算。其余 verdict
    清零并清除 last_ok_ts。

    ``flip``：上一轮与本轮 reachable 状态相反则 +1，否则沿用上一轮计数；
    连续可达达 FLIP_FORGIVE_STREAK 轮后清零（稳定恢复即赦免历史抖动）。
    stable 准入要求 flip ≤ STABLE_MAX_FLIP，排除"可达↔不可达"慢性振荡源。

    时间窗判定用于对抗 china.json 被并发工作流短暂回滚（lost-update）：
    基线落后数小时时不再误把连续可达清零。无 last_ok_ts 的旧格式按紧邻
    一轮处理，保持向后兼容。
    """
    if now is None:
        now = time.time()
    now = int(now)
    for key, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        prev = prev_entries.get(key) if isinstance(prev_entries, dict) else None
        prev_reachable = (
            isinstance(prev, dict) and prev.get("verdict") == "reachable"
        )
        cur_reachable = entry.get("verdict") == "reachable"
        prev_flip = prev.get("flip") if isinstance(prev, dict) else None
        flip = prev_flip if isinstance(prev_flip, int) and prev_flip > 0 else 0
        if isinstance(prev, dict) and prev_reachable != cur_reachable:
            flip += 1
        if cur_reachable:
            base = 0
            if prev_reachable:
                ts = prev.get("last_ok_ts")
                fresh = (
                    not isinstance(ts, (int, float))
                    or ts <= 0
                    or (now - ts) <= STREAK_GAP_TOLERANCE_S
                )
                if fresh:
                    ps = prev.get("streak")
                    base = ps if isinstance(ps, int) and ps > 0 else 1
            entry["streak"] = base + 1
            entry["last_ok_ts"] = now
            if entry["streak"] >= FLIP_FORGIVE_STREAK:
                flip = 0
        else:
            entry["streak"] = 0
            entry.pop("last_ok_ts", None)
        entry["flip"] = flip


def _sort_by_ms(lines: list[str], cn_ms: dict | None) -> list[str]:
    """``cn_ms`` 提供时按大陆延迟升序稳定排序；缺失排最后。"""
    if not cn_ms:
        return lines
    indexed = list(enumerate(lines))
    indexed.sort(
        key=lambda item: (
            cn_ms.get(line_to_key(item[1]), float("inf")),
            item[0],
        )
    )
    return [line for _i, line in indexed]


def generate_all_cn(
    pool_text: str,
    reachable_keys: set,
    cn_ms: dict | None = None,
    http_keys: set | None = None,
    strict: bool = False,
    fallback_keys: set | None = None,
    best_isp: dict | None = None,
) -> tuple[str, int]:
    """大陆可达清单：本次判可达的行（源为全量池文本）。

    - ``best_isp``（``key -> '移动=57ms'`` 之类）：追加"表现最好的运营商
      名字与其数据"后缀（仅当 cn01 等 per-ISP 读数存在时构造，缺省不追加）。

    - ``http_keys``：应用层（HTTP）确认的 key 集合，对应行追加 ``-CNH``
    - ``strict=True``：保留参数以兼容调用方（行为与假等同，均已不收历史兜底）
    - ``fallback_keys``：**历史兜底集合**——上一轮可达、本轮仅因源配额/抖动
      落入 uncertain（而非被 ≥2 失败源证伪）的键。CN 全量清单维持
      ≥ MIN_CN_POOL（用户硬约束，避免单次调度/源异常把可达池削到 1 万以下）；
      这些键本就是近期稳定可达，清单语义为"可达集合快照"，非本轮活体确认，
      故保留既诚实又守规模。兜底行仍经大陆延迟/速度重写，与当期一致。
- ``cn_ms``（``key -> 大陆实测毫秒``）提供时：
       * 行内延迟 token **替换为大陆实测 RTT**——CN 清单里 ``ms`` 的语义
         即"大陆使用者连接该节点的延迟"，而非海外 runner 的 TLS 延迟；
       * 行内速度 token **替换为大陆视角估算** ``≈XMB/s``（大陆 RTT 推算
         的单流参考上限与海外实测取小）。测不到大陆延迟的节点速度不得而知，
         删除速度 token，避免海外测速冒充大陆体验——同一行内 ``MB/s``
         的语义随清单而定（CN 清单=大陆视角）；
       * **键级缺失回退**：可达但无大陆读数的键（``cn_ms`` 中无此键）
         速度 token 删除、延迟 token 保留海外值（与 ``build_good`` /
         ``validate_proxies.write_variant`` 同一规则：无读数不冒充大陆值，
         海外值作展示回退）；
       * 按大陆延迟升序输出（对大陆使用者比海外延迟更有参考意义）；
         未测到延迟的行排在最后，同延迟保持原池顺序。
       缺省 ``None`` 时保持原池顺序、不改写延迟。
    """
    keep = set(reachable_keys)
    if fallback_keys:
        keep |= set(fallback_keys)
    lines = []
    for line in pool_text.splitlines():
        if not line.strip():
            continue
        key = line_to_key(line)
        if not key:
            continue
        if key in keep:
            out = annotate_cn(line)
            if http_keys and key in http_keys:
                out = annotate_cnh(out)
            if cn_ms:
                out = rewrite_latency(out, cn_ms.get(key))
                out = _rewrite_cn_speed(out, cn_ms)
            if best_isp and key in best_isp:
                out = merge_note_tokens(out, best_isp[key])
            lines.append(out)
    lines = _sort_by_ms(lines, cn_ms)
    return "\n".join(lines) + ("\n" if lines else ""), len(lines)


def generate_cn_subset(
    pool_text: str,
    keep,
    cn_ms: dict | None = None,
    best_isp: dict | None = None,
) -> tuple[str, int]:
    """按谓词过滤全量池文本，保持行原文；``keep(key, line)`` 为真则保留。

    排序规则同 :func:`generate_all_cn`（``cn_ms`` 升序，缺失垫底）；
    ``cn_ms`` 提供时同样将行内延迟替换为大陆实测 RTT（CN 视图语义），
    并将速度替换为大陆视角估算（``≈XMB/s``，见 :func:`generate_all_cn`）；
    ``best_isp`` 同 :func:`generate_all_cn`，追加最快运营商品牌后缀。
    """
    lines = []
    for line in pool_text.splitlines():
        if not line.strip():
            continue
        key = line_to_key(line)
        if not key:
            continue
        if keep(key, line):
            out = line
            if cn_ms:
                out = rewrite_latency(out, cn_ms.get(key))
                out = _rewrite_cn_speed(out, cn_ms)
            if best_isp and key in best_isp:
                out = merge_note_tokens(out, best_isp[key])
            lines.append(out)
    lines = _sort_by_ms(lines, cn_ms)
    return "\n".join(lines) + ("\n" if lines else ""), len(lines)


def write_cn_subset(path: Path, text: str) -> None:
    """原子写 CN 子集；空文本清理残留旧文件（防跨轮误导计数）。"""
    if text:
        write_text_if_changed(path, text)
    elif path.exists():
        path.unlink()


# 大陆清单健康下限：清单须保持完整（正常水平 ≥1 万可达键）。
MIN_CN_POOL = 10000
# 大陆延迟的最小可信读数：互联网真实 RTT 一向 ≥ ~2ms（同机房直连也难低于
# 个位数），≤2ms 即是 L3 复核源 1ms 噪声（cn14 等）漏网的信号。
CN_MIN_CREDIBLE_MS = 2.0


def cn_health_report(cn_text: str) -> dict[str, int]:
    """清单自检：``{count, no_ms, junk_ms}``。

    - ``count``：总行数（完整池规模）；
    - ``no_ms``：无 ms token 的行数（漏重写信令）；
    - ``junk_ms``：ms ≤ CN_MIN_CREDIBLE_MS 的行数（噪声侵入信令）。

    供主流程在落地后即时自检并告警，防止"清单被裁 / 1ms 假延迟回归"。
    """
    count = no_ms = junk_ms = 0
    for line in cn_text.splitlines():
        if not line.strip():
            continue
        count += 1
        m = next(
            (t[:-2] for t in line.split("-") if t.endswith("ms")),
            None,
        )
        if not m or not m.replace(".", "").isdigit():
            no_ms += 1
        elif float(m) <= CN_MIN_CREDIBLE_MS:
            junk_ms += 1
    return {"count": count, "no_ms": no_ms, "junk_ms": junk_ms}


def check_cn_health(cn_text: str, min_count: int = MIN_CN_POOL) -> dict[str, int]:
    """落地即自检：不达标打告警（失败即暴露，不静默）。返回报告。"""
    report = cn_health_report(cn_text)
    if report["count"] < min_count:
        print(
            f"WARNING: all_cn.txt too small ({report['count']} < {min_count}) — "
            f"pool shrank or reachability collapsed; check pool/verdicts",
            file=sys.stderr,
        )
    if report["junk_ms"]:
        print(
            f"WARNING: {report['junk_ms']} lines with ms <= "
            f"{CN_MIN_CREDIBLE_MS:g}ms (L3 noise leaked into CN lists)",
            file=sys.stderr,
        )
    if report["no_ms"]:
        print(
            f"WARNING: {report['no_ms']} lines missing ms token "
            f"(reachable keys without any credible mainland reading)",
            file=sys.stderr,
        )
    return report


def annotate_cn_files(reachable_keys: set) -> None:
    """给 all.txt / all_ltd.txt 同步当期 -CN：可达 → 追加；不可达 → 撤销。

    历史实现只增不减导致过期 -CN 累积（曾达 13817 条而真可达仅 112）。
    改为以当期可达集为准的严格交战：key 在可达集内且未带 -CN 则补，
    否则若带 -CN/-CNH 则清除（与 annotate_classify 同策略，幂等）。
    """
    for name in ("all.txt", "all_ltd.txt"):
        path = VALID_DIR / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        changed = False
        out = []
        for line in text.splitlines():
            if not line:
                continue
            key = line_to_key(line)
            if key and key in reachable_keys:
                if not has_cn_note(line) and merge_note_tokens(line, "CN") != line:
                    out.append(merge_note_tokens(line, "CN"))
                    changed = True
                    continue
            elif has_cn_note(line) and clear_note_buckets(line, "cn") != line:
                out.append(clear_note_buckets(line, "cn"))
                changed = True
                continue
            out.append(line)
        if changed:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
            tmp.replace(path)


# ------------------------------------------------------------ 主流程

def _run_pingpe_slots(
    candidates: list, entries: dict, timeout: float,
    tcpping_token: str, concurrency: int,
) -> None:
    """L3 cn40 多节点复核：串行→有界并发。每键端到端 ~20-40s（AJAX 启动
    + 轮询），串行 40 键 ≈ 26min；并发受控后同槽位耗时 ~7min，覆盖翻倍而
    不增加对上游的访问总量。并发数默认 `PINGPE_CONCURRENCY`。"""

    def work(item) -> None:
        _, key, ip, port, _ = item
        try:
            # 只看函数占位（loader 全有全无，与 _PINGPE_BUNDLE 同步；
            # 不读 flag，使单测 mock pingpe_check 时与有无 bundle 无关）。
            if pingpe_check is None:
                entries.setdefault(key, {})[PINGPE_CODE] = _bundle_missing(PINGPE_CODE)
            else:
                entries[key][PINGPE_CODE] = pingpe_check(ip, port, timeout)
            if tcpping_check is None:
                if tcpping_token:
                    entries.setdefault(key, {})[TCPPING_CODE] = _bundle_missing(TCPPING_CODE)
            else:
                tcpping = tcpping_check(ip, port, tcpping_token, timeout)
                if tcpping["status"] != "skipped":
                    entries[key][TCPPING_CODE] = tcpping
        except Exception as exc:
            logging.debug("cn40 failed for %s: %s", key, _err(exc))
            entries.setdefault(key, {})[PINGPE_CODE] = {
                "status": "error", "ok": False, "ms": None, "error": _err(exc)}
        time.sleep(PINGPE_SLOT_GAP)

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(work, item) for item in candidates]
        for fut in futures:
            fut.result()


def _run_tcptest_slots(
    candidates: list, entries: dict, timeout: float,
    node_uuids: list[str], concurrency: int,
    operators: dict | None = None,
    probe_type: str = "tcping", source: str = TCPTEST_CODE,
) -> None:
    """cn30-cn33 多节点复核（免费 REST，端到端 ~2-6s/键）。节点列表
    进程内缓存（插件内），只取一次；每键在 concurrency 有界并发下建任务
    并轮询结果。``operators``（``{uuid: 运营商}``）透传给 ``tcptest_check``
    产出 per-ISP ``isp_ms``（仅 TCP/HTTP；ping/trace 按口径不产出）。
    ``probe_type``/``source`` 选择 TCP（cn30）或 ICMP（cn31，CN-33）/
    HTTP（cn32，CN-35）/路由（cn33，CN-40）通道与落键。无 bundle 时
    写 fail-open error 行。"""

    def work(item) -> None:
        _, key, ip, port, _ = item
        # 只看函数占位是否为 None（loader 全有全无，与 _TCPTEST_BUNDLE
        # 同步；此处不读 flag，使单测 mock tcptest_check 时与有无
        # bundle 无关——CI 无 PCB 包时亦可验证通道派发）。
        if tcptest_check is None:
            entries.setdefault(key, {})[source] = _bundle_missing(source)
            return
        try:
            entries[key][source] = tcptest_check(
                ip, port, timeout, node_uuids, operators,
                probe_type=probe_type)
        except Exception as exc:
            logging.debug("%s %s failed for %s: %s",
                          source, probe_type, key, _err(exc))
            entries.setdefault(key, {})[source] = {
                "status": "error", "ok": False, "ms": None, "error": _err(exc)}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(work, item) for item in candidates]
        for fut in futures:
            fut.result()


def _run_ws_source_slots(
    candidates: list, entries: dict, timeout: float, source: str, concurrency: int
) -> None:
    """JWT/WS 或 PoW/WS 类源的多键并发复核（cn14/cn15 / cn17/cn18/cn19 / cn16）。

    每个源按 ``candidates`` 前段投递；只写 ``entries[key][source]``。"""
    fn = {
        ANTPING_CODE: lambda ip, port: (
            antping_check(ip, port, timeout)
            if antping_check else _bundle_missing(ANTPING_CODE)),
        ANTPING_PING_CODE: lambda ip, port: (
            antping_ping_check(ip, port, timeout)
            if antping_ping_check else _bundle_missing(ANTPING_PING_CODE)),
        TCPINGCN_CODE: lambda ip, port: (
            tcpingcn_check(ip, port, timeout)
            if tcpingcn_check else _bundle_missing(TCPINGCN_CODE)),
        TCPINGCN_PING_CODE: lambda ip, port: (
            tcpingcn_ping_check(ip, port, timeout)
            if tcpingcn_ping_check else _bundle_missing(TCPINGCN_PING_CODE)),
        TCPINGCN_MTR_CODE: lambda ip, port: (
            tcpingcn_mtr_check(ip, port, timeout)
            if tcpingcn_mtr_check else _bundle_missing(TCPINGCN_MTR_CODE)),
        CHINAZ_CODE: lambda ip, port: (
            chinaz_check(ip, "", timeout)
            if chinaz_check else _bundle_missing(CHINAZ_CODE)),
    }[source]

    def work(item) -> None:
        _, key, ip, port, _ = item
        try:
            entries[key][source] = fn(ip, port)
        except Exception as exc:
            logging.debug("%s failed for %s: %s", source, key, _err(exc))
            entries.setdefault(key, {})[source] = {
                "status": "error", "ok": False, "ms": None, "error": _err(exc)}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(work, item) for item in candidates]
        for fut in futures:
            fut.result()


def _run_pingloc_slots(
    candidates: list, entries: dict, timeout: float, concurrency: int
) -> None:
    """cn08 多节点复核：有 bundle 时走插件（纯 HTTP+SSE ICMP ping；
    tcp_ping 固定端口 80 与代理真实端口不符，故只用作 ICMP 主机存活确认），
    无 bundle 时每键写 fail-open error（不崩不断言）。"""

    def work(item) -> None:
        _, key, ip, _, _ = item
        # 只看函数占位（loader 全有全无；不读 flag，使单测与有无 bundle 无关）。
        if pingloc_check is None:
            entries.setdefault(key, {})[PINGLOC_CODE] = _bundle_missing(PINGLOC_CODE)
            return
        try:
            entries[key][PINGLOC_CODE] = pingloc_check(ip, timeout, method="ping")
        except Exception as exc:
            logging.debug("pingloc failed for %s: %s", key, _err(exc))
            entries.setdefault(key, {})[PINGLOC_CODE] = {
                "status": "error", "ok": False, "ms": None, "error": _err(exc)}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(work, item) for item in candidates]
        for fut in futures:
            fut.result()


def _bundle_missing(source: str) -> dict:
    """无 PCB 时插件源的 fail-open 占位（记 error，不崩不断言）。"""
    return {"status": "error", "ok": False, "ms": None,
            "error": f"pcb bundle missing for {source}", "level": None,
            "ok_nodes": 0, "nodes": 0, "ratio": None}


def _run_raw_slots(
    candidates: list, entries: dict, timeout: float, source: str, concurrency: int
) -> None:
    """多节点复核通用 slot：按 ``source``（代号）派发到对应的多节点 check 函数
    （cn11 socket.io-WS / cn09 等 HTTP-SSE / cn04 纯 WS），只写 ``entries[key][source]``。
    插件缺失时记 error 行（fail-open）。"""
    fn = {
        CE98_CODE: lambda ip, port: (
            ce98_check(ip, port, timeout) if ce98_check
            else _bundle_missing(CE98_CODE)),
        CE98_PING_CODE: lambda ip, port: (
            ce98_ping_check(ip, port, timeout) if ce98_ping_check
            else _bundle_missing(CE98_PING_CODE)),
        BIUPING_CODE_TCPING: lambda ip, port: (
            biuping_check(ip, port, timeout) if biuping_check
            else _bundle_missing(BIUPING_CODE_TCPING)),
        BIUPING_CODE_PING: lambda ip, port: (
            biuping_ping_check(ip, port, timeout) if biuping_ping_check
            else _bundle_missing(BIUPING_CODE_PING)),
        AA1_CODE_PING: lambda ip, port: (
            aa1ping_check(ip, port, timeout) if aa1ping_check
            else _bundle_missing(AA1_CODE_PING)),
        AA1_CODE_HTTP: lambda ip, port: (
            aa1http_check(ip, port, timeout) if aa1http_check
            else _bundle_missing(AA1_CODE_HTTP)),
        TCPPING_WS_CODE: lambda ip, port: (
            tcpping_ws_check(ip, port, timeout) if tcpping_ws_check
            else _bundle_missing(TCPPING_WS_CODE)),
        COFFEE_CODE: lambda ip, port: (
            coffee_check(ip, timeout) if coffee_check
            else _bundle_missing(COFFEE_CODE)),
        IPIP_TRACE_CODE: lambda ip, port: (
            ipip_trace_check(ip, port, timeout) if ipip_trace_check
            else _bundle_missing(IPIP_TRACE_CODE)),
        GLOBALPING_CODE: lambda ip, port: (
            globalping_check(ip, port, timeout) if globalping_check
            else _bundle_missing(GLOBALPING_CODE)),
        GLOBALPING_TRACE_CODE: lambda ip, port: (
            globalping_trace_check(ip, port, timeout)
            if globalping_trace_check
            else _bundle_missing(GLOBALPING_TRACE_CODE)),
        GLOBALPING_HTTP_CODE: lambda ip, port: (
            globalping_http_check(ip, port, timeout)
            if globalping_http_check
            else _bundle_missing(GLOBALPING_HTTP_CODE)),
        GLOBALPING_MTR_CODE: lambda ip, port: (
            globalping_mtr_check(ip, port, timeout)
            if globalping_mtr_check
            else _bundle_missing(GLOBALPING_MTR_CODE)),
        BOCE_CODE: lambda ip, port: (
            boce_check(ip, port, timeout) if boce_check
            else _bundle_missing(BOCE_CODE)),
        IPIP_CODE: lambda ip, port: (
            ipip_check(ip, port, timeout) if ipip_check
            else _bundle_missing(IPIP_CODE)),
        SEVENTEEN_CODE: lambda ip, port: (
            seventeen_check(ip, port, timeout) if seventeen_check
            else _bundle_missing(SEVENTEEN_CODE)),
        PING0_CODE: lambda ip, port: (
            ping0_check(ip, port, timeout) if ping0_check
            else _bundle_missing(PING0_CODE)),
        WANSUI_CODE: lambda ip, port: (
            wansui_check(ip, port, timeout) if wansui_check
            else _bundle_missing(WANSUI_CODE)),
    }[source]

    def work(item) -> None:
        _, key, ip, port, _ = item
        try:
            entries[key][source] = fn(ip, port)
        except Exception as exc:
            logging.debug("%s failed for %s: %s", source, key, _err(exc))
            entries.setdefault(key, {})[source] = {
                "status": "error", "ok": False, "ms": None, "error": _err(exc)}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(work, item) for item in candidates]
        for fut in futures:
            fut.result()


def _batch_ping_normalize(res: dict) -> dict:
    """cn03 结果归一：记录形与 cn02 同构，遂插件记录判定的 result 分支会标
    ``level="tcp"`` 并产出 ``isp_ms``；实为 ICMP 回显，
    改写 ``level="icmp"`` 并剥离 ``isp_ms``（ICMP RTT 不得进展示延迟与
    ``cn_fastest_ms``；多节点 ICMP 源同口径）。fail/error 原样。
    """
    res = dict(res)
    if res.get("ok"):
        res["level"] = "icmp"
    res.pop("isp_ms", None)
    return res


def split_cn_cache(sample, prev_entries, ttl, now=None):
    """按 TTL 把样本拆成（可复用缓存项，待复测样本）。

    复用条件：上一轮同键 verdict 为 reachable/uncertain 且 ``checked_at``
    未过期（``checked_at + ttl >= now``）。``ttl<=0`` 即关闭，全量复测。
    返回的缓存项为深拷贝（调用方并入后可随意改写，不污染上一轮基线）。
    """
    if ttl <= 0 or not prev_entries:
        return {}, list(sample)
    now = time.time() if now is None else now
    cached, probe = {}, []
    for item in sample:
        prev = prev_entries.get(item[1])
        if (isinstance(prev, dict)
                and prev.get("verdict") in ("reachable", "uncertain")
                and isinstance(prev.get("checked_at"), (int, float))
                and prev["checked_at"] + ttl >= now):
            cached[item[1]] = json.loads(json.dumps(prev))
        else:
            probe.append(item)
    return cached, probe


def merge_cn_cache(entries, reachable, uncertain, cached):
    """把复用缓存项并入本轮结果（就地），同步可达/待定集合。"""
    for key, entry in cached.items():
        entries[key] = entry
        if entry.get("verdict") == "reachable":
            reachable.add(key)
        elif entry.get("verdict") == "uncertain":
            uncertain.add(key)
    return entries, reachable, uncertain


_SOURCES_REG = None


def _sources_registry():
    """PCB 源注册表模块（动态读取；无包回 None）。进程内缓存一次。"""
    global _SOURCES_REG
    if _SOURCES_REG is None:
        try:
            _SOURCES_REG = _load_pcb_plugin("_sources")
        except Exception:
            _SOURCES_REG = False
    return _SOURCES_REG or None


def parse_cn_kv(pairs):
    """解析 ``--cn-limit CODE=N``… 为 ``{code: N}``（非法项丢弃，code 小写化）。"""
    out = {}
    for item in pairs or []:
        if "=" not in item:
            continue
        code, _, val = item.partition("=")
        code, val = code.strip().lower(), val.strip()
        if not code:
            continue
        try:
            out[code] = int(val)
        except ValueError:
            try:
                out[code] = float(val)
            except ValueError:
                continue
    return out


_CN_KIND_ATTR = {"limit": "cn_limit", "concurrency": "cn_concurrency",
                 "nodes": "cn_nodes"}
_CN_KIND_REGKEY = {"limit": "limit_default", "concurrency": "concurrency",
                   "nodes": None}


def cn_opt(args, code, kind="limit", legacy=None, default=0):
    """源选项解析（代号运行时件）。

    优先级：generic ``--cn-<kind> CODE=N`` > legacy ``<stem>_<kind>``
    属性（过渡期由调用方经 ``legacy=`` 传入，终轮随 legacy 旗标一并删除）
    > PCB 注册表默认 > ``default``。无包且无 legacy 属性时取 ``default``，
    单测/CI 与有无 bundle 无关。
    """
    code = code.lower()
    generic = getattr(args, _CN_KIND_ATTR[kind], None)
    if isinstance(generic, dict) and code in generic:
        return generic[code]
    if legacy is not None and hasattr(args, legacy):
        return getattr(args, legacy)
    regkey = _CN_KIND_REGKEY[kind]
    if regkey is not None:
        reg = _sources_registry()
        entry = reg.by_code(code) if reg is not None else None
        if isinstance(entry, dict) and entry.get(regkey) is not None:
            return entry[regkey]
    return default


def run_measurements(sample, args) -> tuple[dict, set, set]:
    """L2 分两段并发（小小API 全池免额候选 → cn27 稀缺配额只投决策键）、cn01
    批量、L3 串行复核；返回 (entries, reachable_keys, uncertain_keys)。"""
    entries: dict = {}
    ch_limiter = RateLimiter(CH_WINDOW_SEC, CH_PER_WINDOW, CH_HOUR_CAP) \
        if RateLimiter is not None else None
    _t0 = time.monotonic()

    def l2_xxapi(item):
        """免额单节点源（cn20 北京 TCP + cn21 枣庄 ICMP + cn22 状态码
        + cn23 443 扫描 + cn24 宁波电信 TCP + cn25 宁波电信 ICMP
        + cn26 宁波电信 TLS）全池扫描，先建立候选集。

        L2 是并发受限（aggregate QPS），非逐键串行瓶颈：七个源放进同池最多干到
        池大小并发请求，切换 task 粒度并不增量。赶时间应加池（WORKERS_DEFAULT=56
        实测各源均无 429），保键级数据一致性仍用逐键七源落盘。"""
        _, key, ip, port, _ = item
        out = {}
        for name, fn in ((XXAPI_CODE, xxapi_check), (XXPING_CODE, xxping_check),
                         (XXSTATUS_CODE, xxstatus_check), (XXSCAN_CODE, xxscan_check),
                         (JKAPI_CODE, jkapi_check), (JKPING_CODE, jkping_check),
                         (JKSSL_CODE, jkssl_check)):
            try:
                out[name] = fn(ip, port, args.timeout)
            except Exception as exc:
                logging.debug("l2 %s failed for %s: %s", name, key, _err(exc))
                out[name] = {"status": "error", "ok": False, "ms": None,
                             "error": _err(exc)}
        return key, out

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(l2_xxapi, item) for item in sample]
        for future in futures:
            key, sources = future.result()
            entries[key] = sources

    def l2_check_host(item):
        """稀缺配额源（cn27 呼和浩特单节点 ~250/h）二次确认。

        cn27 判 fail 时追加同节点 ICMP ping（cn28，共用限速器）：
        cn27-fail + cn28-ok → 主机存活、端口层问题（uncertain，不误判死）；
        双 fail → 置信定罪。cn27-ok 且其余免额源 0 ok 时追加同节点 HTTPS
        应用层确认（cn29）：第二确认猎取（uncertain→reachable），
        其余情况不追加（配额敏感）。
        """
        _, key, ip, port, _ = item
        try:
            tcp = check_host_check(ip, port, ch_limiter, args.timeout, args.api_key)
        except Exception as exc:
            logging.debug("l2 cn27 failed for %s: %s", key, _err(exc))
            tcp = {"status": "error", "ok": False, "ms": None, "error": _err(exc)}
        out = {CHECK_HOST_CODE: tcp}
        if tcp.get("status") == "fail":
            try:
                out[CHECKHOST_PING_CODE] = checkhost_ping_check(
                    ip, ch_limiter, args.timeout, args.api_key)
            except Exception as exc:
                logging.debug("l2 cn28 failed for %s: %s", key, _err(exc))
                out[CHECKHOST_PING_CODE] = {
                    "status": "error", "ok": False, "ms": None,
                    "error": _err(exc), "level": None}
        elif tcp.get("ok"):
            entry = entries.get(key) or {}
            free_ok = sum(
                1 for n in (XXAPI_CODE, XXPING_CODE, JKAPI_CODE, JKPING_CODE)
                if (entry.get(n) or {}).get("status") == "ok")
            if free_ok == 0:
                try:
                    out[CHECKHOST_HTTP_CODE] = checkhost_http_check(
                        ip, port, ch_limiter, args.timeout, args.api_key)
                except Exception as exc:
                    logging.debug("l2 cn29 failed for %s: %s",
                                  key, _err(exc))
                    out[CHECKHOST_HTTP_CODE] = {
                        "status": "error", "ok": False, "ms": None,
                        "error": _err(exc), "level": None}
        return key, out
    # cn27 配额有限（CH_HOUR_CAP ≈ 250/h），只投递「确认/救回」不投「定罪」：
    # - 免额七源中已有 ≥2 ok → 已独立确认可达，稀配额直接让位
    # - 任一已有 fail → 保守维持 uncertain（不浪费配额去补强失败证据，同旧策略）
    # 预算留给恰好 1 ok（补足到 2 即翻正）与纯临时性错误者。
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        def _needs_ch(entry: dict) -> bool:
            free = [entry.get(n) or {}
                    for n in (XXAPI_CODE, XXPING_CODE, XXSTATUS_CODE, XXSCAN_CODE,
                              JKAPI_CODE, JKPING_CODE, JKSSL_CODE)]
            if sum(1 for r in free if r.get("status") == "ok") >= 2:
                return False
            if any(r.get("status") == "fail" for r in free):
                return False
            return True

        futures = [
            pool.submit(l2_check_host, item)
            for item in sample
            if _needs_ch(entries.get(item[1], {}))
        ]
        for future in futures:
            key, sources = future.result()
            entries[key].update(sources)
    print(
        f"L1 sweep: {time.monotonic() - _t0:.1f}s",
        file=sys.stderr,
    )

    if not args.skip_itdog and not _ITDOG_BUNDLE:
        print("pcb bundle missing: batch-source phases skipped",
              file=sys.stderr)
    if not args.skip_itdog and _ITDOG_BUNDLE:
        # 批量通道代价高（批任务端到端慢），只投仍未定论的键；已由
        # 双免额单节点源定论的键（≥2 ok / ≥2 fail）跳过其复核。
        # 无 PCB 时整段跳过（fail-open，公开 CI/无包环境不触批量通道）。
        _itdog_cands = [item for item in sample if needs_probe(entries, item[1])]
        try:
            for key, res in itdog_batch_run(_itdog_cands, args).items():
                entries.setdefault(key, {})[ITDOG_CODE_HTTP] = res
        except Exception as exc:
            logging.debug("cn01 batch failed: %s", _err(exc))
            print(f"cn01 batch failed (skipped): {_err(exc)}", file=sys.stderr)
        # batch_http 失败/被限的 key 用 batch_tcping 补测（节点池更大，纯 TCP）
        if not getattr(args, "skip_itdog_tcping", False):
            pending = [
                item for item in _itdog_cands
                if entries.get(item[1], {}).get(ITDOG_CODE_HTTP, {}).get("status")
                in ("error", "rate_limited")
            ]
            # 若主通道连节点列表都没取到（上游被墙/验证码墙的整站性失败），
            # tcping 同站同墙，兜底只会再空转一轮——直接跳过。注意只统计
            # 本轮真正过批量通道的键（无 cn01 记录的已定论键不得算作成功），
            # 且要求至少出现过 1 次 ok（全 fail 也是被投毒站点的特征——真活的
            # 大陆可达键不可能整批 0 ok，全 fail 时同站的 tcping 一样是死路）。
            node_fetch_ok = any(
                entries.get(key, {}).get(ITDOG_CODE_HTTP, {}).get("status") == "ok"
                for _, key, _, _, _ in _itdog_cands
            ) if _itdog_cands else False
            if pending and node_fetch_ok:
                print(
                    f"cn02 fallback: {len(pending)} targets",
                    file=sys.stderr,
                )
                try:
                    for key, res in itdog_batch_run(
                        pending,
                        args,
                        page_url=ITDOG_TCPING_URL,
                        nodes_per_isp=cn_opt(args, "cn02", "nodes", legacy="itdog_tcping_nodes",
                             default=0)
                        or ITDOG_TCPING_NODES_PER_ISP,
                    ).items():
                        entries.setdefault(key, {})[ITDOG_CODE_TCPING] = res
                except Exception as exc:
                    logging.debug("cn02 fallback failed: %s", _err(exc))
                    print(f"cn02 fallback failed (skipped): {_err(exc)}",
                          file=sys.stderr)
        # cn03 ICMP 补测（CN-26）：同上触发条件（cn01 error/
        # rate_limited 且节点拉取成功），用 cn03（ICMP，大节点池
        # 电信 87 / 联通 83 / 移动 89）复测主机存活。结果记为独立多节点源
        # cn03（归一为 level=icmp、不产 isp_ms）；TCP 实测 fail 的键
        # 不投（fail 是端口层实测结论，不用 ICMP 主机存活翻案，保守）。
        ping_pending = [
            item for item in _itdog_cands
            if entries.get(item[1], {}).get(ITDOG_CODE_HTTP, {}).get("status")
            in ("error", "rate_limited")
        ]
        if ping_pending and node_fetch_ok:
            print(
                f"cn03 fallback: {len(ping_pending)} targets",
                file=sys.stderr,
            )
            try:
                for key, res in itdog_batch_run(
                    ping_pending,
                    args,
                    page_url=ITDOG_PING_URL,
                    nodes_per_isp=ITDOG_PING_NODES_PER_ISP,
                ).items():
                    entries.setdefault(key, {})[ITDOG_CODE_PING] = (
                        _batch_ping_normalize(res)
                    )
            except Exception as exc:
                logging.debug("cn03 fallback failed: %s", _err(exc))
                print(f"cn03 fallback failed (skipped): {_err(exc)}",
                      file=sys.stderr)
    print(
        f"batch-source phases: {time.monotonic() - _t0:.1f}s",
        file=sys.stderr,
    )

    # cn30-33 多节点 TCP/ICMP/HTTP/路由 复核（免费 REST，节点列表进程内
    # 缓存于插件）：只投「当前尚未被判可达」的键，先于 cn40（贵）跑，
    # 确认过的键会让位。--tcptest-limit -1 表示全池未定键全覆盖（uncertain/
    # 错误健全部扫过，让每个键都有资格走向 reachable 或 unreachable 定论）。
    # --tcptest-ping-limit（CN-33）为 cn31 ICMP 通道（type=ping，无端口概念，
    # level=icmp，不产 isp_ms），跑在 TCP 相之后（只投 TCP 仍未定论者）。
    tcptest_nodes = []
    tcptest_uuids = []
    tcptest_operators: dict | None = None
    if tcptest_fetch_nodes is not None and tcptest_pick_nodes is not None and (
            cn_opt(args, "cn30", "limit", legacy="tcptest_limit",
                   default=0) != 0 or cn_opt(
            args, "cn31", "limit", legacy="tcptest_ping_limit",
            default=0) != 0 or cn_opt(
            args, "cn32", "limit", legacy="tcptest_http_limit",
            default=0) != 0 or cn_opt(
            args, "cn33", "limit", legacy="tcptest_trace_limit",
            default=0) != 0):
        tcptest_nodes = tcptest_fetch_nodes(min(args.timeout, 20))
        tcptest_uuids = tcptest_pick_nodes(
            tcptest_nodes, cn_opt(args, "cn30", "nodes",
                                  legacy="tcptest_nodes",
                                  default=TCPTEST_NODES)
        )
        tcptest_operators = {
            n.get("uuid"): n.get("operator") for n in tcptest_nodes
            if isinstance(n, dict) and n.get("uuid")
        }
    if tcptest_uuids:
        tcptest_candidates = [
            item for item in sample if needs_probe(entries, item[1])
        ]
        limit = cn_opt(args, "cn30", "limit", legacy="tcptest_limit",
                       default=0)
        if limit is None or limit < 0:
            limit = len(tcptest_candidates)
        _run_tcptest_slots(
            tcptest_candidates[:limit],
            entries,
            args.timeout,
            tcptest_uuids,
            cn_opt(args, "cn30", "concurrency",
                   legacy="tcptest_concurrency",
                   default=TCPTEST_CONCURRENCY),
            tcptest_operators,
        )
        print(
            f"{TCPTEST_CODE} review: {time.monotonic() - _t0:.1f}s "
            f"({len(tcptest_candidates)} targets, {len(tcptest_uuids)} nodes)",
            file=sys.stderr,
        )
        ping_limit = cn_opt(args, "cn31", "limit",
                            legacy="tcptest_ping_limit", default=0)
        if ping_limit != 0:
            ping_candidates = [
                item for item in sample if needs_probe(entries, item[1])
            ]
            if ping_limit is None or ping_limit < 0:
                ping_limit = len(ping_candidates)
            _run_tcptest_slots(
                ping_candidates[:ping_limit],
                entries,
                args.timeout,
                tcptest_uuids,
                cn_opt(args, "cn31", "concurrency",
                       legacy="tcptest_ping_concurrency",
                       default=TCPTEST_CONCURRENCY),
                tcptest_operators,
                probe_type="ping",
                source=TCPTEST_PING_CODE,
            )
            print(
                f"{TCPTEST_PING_CODE} review: {time.monotonic() - _t0:.1f}s "
                f"({len(ping_candidates)} targets)",
                file=sys.stderr,
            )
        else:
            print(f"{TCPTEST_PING_CODE} review: skipped (limit=0)", file=sys.stderr)
        http_limit = cn_opt(args, "cn32", "limit",
                            legacy="tcptest_http_limit", default=0)
        if http_limit != 0:
            http_candidates = [
                item for item in sample if needs_probe(entries, item[1])
            ]
            if http_limit is None or http_limit < 0:
                http_limit = len(http_candidates)
            _run_tcptest_slots(
                http_candidates[:http_limit],
                entries,
                args.timeout,
                tcptest_uuids,
                cn_opt(args, "cn32", "concurrency",
                       legacy="tcptest_http_concurrency",
                       default=TCPTEST_CONCURRENCY),
                tcptest_operators,
                probe_type="http",
                source=TCPTEST_HTTP_CODE,
            )
            print(
                f"{TCPTEST_HTTP_CODE} review: {time.monotonic() - _t0:.1f}s "
                f"({len(http_candidates)} targets)",
                file=sys.stderr,
            )
        else:
            print(f"{TCPTEST_HTTP_CODE} review: skipped (limit=0)", file=sys.stderr)
        trace_limit = cn_opt(args, "cn33", "limit",
                             legacy="tcptest_trace_limit", default=0)
        if trace_limit != 0:
            trace_candidates = [
                item for item in sample if needs_probe(entries, item[1])
            ]
            if trace_limit is None or trace_limit < 0:
                trace_limit = len(trace_candidates)
            _run_tcptest_slots(
                trace_candidates[:trace_limit],
                entries,
                args.timeout,
                tcptest_uuids,
                cn_opt(args, "cn33", "concurrency",
                       legacy="tcptest_trace_concurrency",
                       default=TCPTEST_CONCURRENCY),
                tcptest_operators,
                probe_type="traceroute",
                source=TCPTEST_TRACE_CODE,
            )
            print(
                f"{TCPTEST_TRACE_CODE} review: {time.monotonic() - _t0:.1f}s "
                f"({len(trace_candidates)} targets)",
                file=sys.stderr,
            )
        else:
            print(f"{TCPTEST_TRACE_CODE} review: skipped (limit=0)", file=sys.stderr)
    else:
        print(
            f"{TCPTEST_CODE} review: skipped (no nodes or limit=0)",
            file=sys.stderr,
        )

    # cn07 大陆多节点 ICMP 复核（免费、空闲量大）：全池未定键横扫，
    # 为主机存活提供独立多节点证据（端口层以 cn30/cn01 等 TCP 源为准）。
    coffee_limit = cn_opt(args, "cn07", "limit", legacy="coffee_limit",
                default=0)
    if coffee_limit != 0:
        coffee_candidates = [
            item for item in sample if needs_probe(entries, item[1])
        ]
        if coffee_limit is None or coffee_limit < 0:
            coffee_limit = len(coffee_candidates)
        _run_raw_slots(
            coffee_candidates[:coffee_limit],
            entries,
            args.timeout,
            COFFEE_CODE,
            cn_opt(args, "cn07", "concurrency", legacy="coffee_concurrency",
           default=COFFEE_CONCURRENCY),
        )
        print(
            f"cn07 review: {time.monotonic() - _t0:.1f}s "
            f"({len(coffee_candidates)} targets)",
            file=sys.stderr,
        )
    else:
        print("cn07 review: skipped (limit=0)", file=sys.stderr)

    def _pending_cands():
        return [
            item for item in sample if needs_probe(entries, item[1])
        ]

    # 新增四源多节点复核（全部无 key、大陆多节点）：cn08（HTTP+SSE）、
    # antping（JWT+WS）、cn17（PoW+WS 纯 TCP）、chinaz（token+WS 纯 ICMP）。
    # 各自按 --<name>-limit 投递（默认 0=跳过，-1=全部未定键）；均为多节点源，
    # 达标即可独立判 reachable，整站失败也可与单节点源联动判 unreachable。

    pingloc_limit = cn_opt(args, "cn08", "limit", legacy="pingloc_limit",
                 default=0)
    if pingloc_limit != 0:
        cands = _pending_cands()
        if pingloc_limit is None or pingloc_limit < 0:
            pingloc_limit = len(cands)
        _run_pingloc_slots(
            cands[:pingloc_limit], entries, args.timeout,
            cn_opt(args, "cn08", "concurrency", legacy="pingloc_concurrency",
           default=8),
        )
        print(f"pingloc review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("pingloc review: skipped (limit=0)", file=sys.stderr)

    antping_limit = cn_opt(args, "cn14", "limit", legacy="antping_limit",
                 default=0)
    if antping_limit != 0:
        cands = _pending_cands()
        if antping_limit is None or antping_limit < 0:
            antping_limit = len(cands)
        _run_ws_source_slots(
            cands[:antping_limit], entries, args.timeout, ANTPING_CODE,
            cn_opt(args, "cn14", "concurrency", legacy="antping_concurrency",
           default=8),
        )
        print(f"antping review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("antping review: skipped (limit=0)", file=sys.stderr)

    # antping_ping（CN-28）：同站 ICMP，主独立判 reachable；默认 0=跳过。
    antping_ping_limit = cn_opt(args, "cn15", "limit", legacy="antping_ping_limit",
                      default=0)
    if antping_ping_limit != 0:
        cands = _pending_cands()
        if antping_ping_limit is None or antping_ping_limit < 0:
            antping_ping_limit = len(cands)
        _run_ws_source_slots(
            cands[:antping_ping_limit], entries, args.timeout, ANTPING_PING_CODE,
            cn_opt(args, "cn15", "concurrency", legacy="antping_ping_concurrency",
           default=8),
        )
        print(f"antping_ping review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("antping_ping review: skipped (limit=0)", file=sys.stderr)

    tcpingcn_limit = cn_opt(args, "cn17", "limit", legacy="tcpingcn_limit",
                  default=0)
    if tcpingcn_limit != 0:
        cands = _pending_cands()
        if tcpingcn_limit is None or tcpingcn_limit < 0:
            tcpingcn_limit = len(cands)
        _run_ws_source_slots(
            cands[:tcpingcn_limit], entries, args.timeout, TCPINGCN_CODE,
            cn_opt(args, "cn17", "concurrency", legacy="tcpingcn_concurrency",
           default=6),
        )
        print(f"tcpingcn review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("tcpingcn review: skipped (limit=0)", file=sys.stderr)

    # cn18（CN-30）：同站 ICMP ping（tcpingcn_ping），主独立判 reachable；默认 0=跳过。
    tcpingcn_ping_limit = cn_opt(args, "cn18", "limit", legacy="tcpingcn_ping_limit",
                       default=0)
    if tcpingcn_ping_limit != 0:
        cands = _pending_cands()
        if tcpingcn_ping_limit is None or tcpingcn_ping_limit < 0:
            tcpingcn_ping_limit = len(cands)
        _run_ws_source_slots(
            cands[:tcpingcn_ping_limit], entries, args.timeout, TCPINGCN_PING_CODE,
            cn_opt(args, "cn18", "concurrency", legacy="tcpingcn_ping_concurrency",
           default=6),
        )
        print(f"tcpingcn_ping review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("tcpingcn_ping review: skipped (limit=0)", file=sys.stderr)

    # cn19（CN-44）：同站 MTR（约 139 节点，末跳达目标即见证），
    # 主独立判 reachable；默认 0=跳过，-1=全部未定键。
    tcpingcn_mtr_limit = cn_opt(args, "cn19", "limit", legacy="tcpingcn_mtr_limit",
                      default=0)
    if tcpingcn_mtr_limit != 0:
        cands = _pending_cands()
        if tcpingcn_mtr_limit is None or tcpingcn_mtr_limit < 0:
            tcpingcn_mtr_limit = len(cands)
        _run_ws_source_slots(
            cands[:tcpingcn_mtr_limit], entries, args.timeout, TCPINGCN_MTR_CODE,
            cn_opt(args, "cn19", "concurrency", legacy="tcpingcn_mtr_concurrency",
           default=6),
        )
        print(f"tcpingcn_mtr review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("tcpingcn_mtr review: skipped (limit=0)", file=sys.stderr)

    chinaz_limit = cn_opt(args, "cn16", "limit", legacy="chinaz_limit",
                default=0)
    if chinaz_limit != 0:
        cands = _pending_cands()
        if chinaz_limit is None or chinaz_limit < 0:
            chinaz_limit = len(cands)
        _run_ws_source_slots(
            cands[:chinaz_limit], entries, args.timeout, CHINAZ_CODE,
            cn_opt(args, "cn16", "concurrency", legacy="chinaz_concurrency",
           default=6),
        )
        print(f"chinaz review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("chinaz review: skipped (limit=0)", file=sys.stderr)

    # 新增多节点 TCP 复核源：cn11（socket.io-WS，34 大陆节点）、cn09
    # （HTTP-SSE，节点数动态，实测 ~39 测量单元）。均已实测出数、零 key；达标即可独立判 reachable，
    # 整站失败也可与单节点源联动判 unreachable。默认 0=跳过，-1=全部未定键。
    ce98_limit = cn_opt(args, "cn11", "limit", legacy="ce98_limit",
              default=0)
    if ce98_limit != 0:
        cands = _pending_cands()
        if ce98_limit is None or ce98_limit < 0:
            ce98_limit = len(cands)
        _run_raw_slots(
            cands[:ce98_limit], entries, args.timeout, CE98_CODE,
            cn_opt(args, "cn11", "concurrency", legacy="ce98_concurrency",
           default=6),
        )
        print(f"ce98 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("ce98 review: skipped (limit=0)", file=sys.stderr)

    # ce98_ping（CN-36）：同站 ICMP（35 节点 socket.io），主独立判 reachable；
    # 默认 0=跳过，-1=全部未定键。
    ce98_ping_limit = cn_opt(args, "cn12", "limit", legacy="ce98_ping_limit",
                   default=0)
    if ce98_ping_limit != 0:
        cands = _pending_cands()
        if ce98_ping_limit is None or ce98_ping_limit < 0:
            ce98_ping_limit = len(cands)
        _run_raw_slots(
            cands[:ce98_ping_limit], entries, args.timeout, CE98_PING_CODE,
            cn_opt(args, "cn12", "concurrency", legacy="ce98_ping_concurrency",
           default=6),
        )
        print(f"ce98_ping review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("ce98_ping review: skipped (limit=0)", file=sys.stderr)

    biuping_limit = cn_opt(args, "cn09", "limit", legacy="biuping_limit",
                 default=0)
    if biuping_limit != 0:
        cands = _pending_cands()
        if biuping_limit is None or biuping_limit < 0:
            biuping_limit = len(cands)
        _run_raw_slots(
            cands[:biuping_limit], entries, args.timeout, BIUPING_CODE_TCPING,
            cn_opt(args, "cn09", "concurrency", legacy="biuping_concurrency",
           default=8),
        )
        print(f"biuping review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("biuping review: skipped (limit=0)", file=sys.stderr)

    # biuping_ping（CN-34）：同站 ICMP，主独立判 reachable；默认 0=跳过。
    biuping_ping_limit = cn_opt(args, "cn10", "limit", legacy="biuping_ping_limit",
                      default=0)
    if biuping_ping_limit != 0:
        cands = _pending_cands()
        if biuping_ping_limit is None or biuping_ping_limit < 0:
            biuping_ping_limit = len(cands)
        _run_raw_slots(
            cands[:biuping_ping_limit], entries, args.timeout, BIUPING_CODE_PING,
            cn_opt(args, "cn10", "concurrency", legacy="biuping_ping_concurrency",
           default=8),
        )
        print(f"biuping_ping review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("biuping_ping review: skipped (limit=0)", file=sys.stderr)

    # cn04（CN-27）：独立运营商 28 城三网 TCPing（纯 WS，零 key）。
    # 达标即可独立判 reachable；默认 0=跳过，-1=全部未定键。
    aa1ping_limit = cn_opt(args, "cn04", "limit", legacy="aa1ping_limit",
                 default=0)
    if aa1ping_limit != 0:
        cands = _pending_cands()
        if aa1ping_limit is None or aa1ping_limit < 0:
            aa1ping_limit = len(cands)
        _run_raw_slots(
            cands[:aa1ping_limit], entries, args.timeout, AA1_CODE_PING,
            cn_opt(args, "cn04", "concurrency", legacy="aa1ping_concurrency",
           default=6),
        )
        print(f"cn04 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn04 review: skipped (limit=0)", file=sys.stderr)

    # cn05（CN-50）：同站 HTTP 测速通道（28 城三网，
    # 原生 operator isp_ms）。仅 443 键可用；默认 0=跳过，-1=全部未定键。
    aa1http_limit = cn_opt(args, "cn05", "limit", legacy="aa1http_limit",
                 default=0)
    if aa1http_limit != 0:
        cands = [item for item in _pending_cands() if item[3] == "443"]
        if aa1http_limit is None or aa1http_limit < 0:
            aa1http_limit = len(cands)
        _run_raw_slots(
            cands[:aa1http_limit], entries, args.timeout, AA1_CODE_HTTP,
            cn_opt(args, "cn05", "concurrency", legacy="aa1http_concurrency",
           default=6),
        )
        print(f"cn05 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn05 review: skipped (limit=0)", file=sys.stderr)

    # cn06（CN-42）：公开 WS 通道，约 16 节点 TCPing
    #（纯 WS，零 key，原生三网 isp_ms）。达标即可独立判 reachable；
    # 默认 0=跳过，-1=全部未定键。
    tcpping_ws_limit = cn_opt(args, "cn06", "limit", legacy="tcpping_ws_limit",
                    default=0)
    if tcpping_ws_limit != 0:
        cands = _pending_cands()
        if tcpping_ws_limit is None or tcpping_ws_limit < 0:
            tcpping_ws_limit = len(cands)
        _run_raw_slots(
            cands[:tcpping_ws_limit], entries, args.timeout, TCPPING_WS_CODE,
            cn_opt(args, "cn06", "concurrency", legacy="tcpping_ws_concurrency",
           default=6),
        )
        print(f"cn06 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn06 review: skipped (limit=0)", file=sys.stderr)

    # cn34（CN-43 复活）：多节点 TCPing（GET+SSE，约 287 节点，
    # 原生三网 isp_ms）。SSE 单键约 90s 采集窗，CI 配额 100 键/8 并发
    # （约 20min）；默认 0=跳过，-1=全部未定键。
    ipip_limit = cn_opt(args, "cn34", "limit", legacy="ipip_limit",
              default=0)
    if ipip_limit != 0:
        cands = _pending_cands()
        if ipip_limit is None or ipip_limit < 0:
            ipip_limit = len(cands)
        _run_raw_slots(
            cands[:ipip_limit], entries, args.timeout, IPIP_CODE,
            cn_opt(args, "cn34", "concurrency", legacy="ipip_concurrency",
           default=6),
        )
        print(f"{IPIP_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{IPIP_CODE} review: skipped (limit=0)", file=sys.stderr)

    # cn35（CN-45）：同站路由追踪（GET+SSE，约 57 节点，hop 行目标 IP
    # 即见证）。SSE 单键约 80s 采集窗，CI 配额 100 键/8 并发（约 17min）；
    # 默认 0=跳过，-1=全部未定键。
    ipip_trace_limit = cn_opt(args, "cn35", "limit", legacy="ipip_trace_limit",
                    default=0)
    if ipip_trace_limit != 0:
        cands = _pending_cands()
        if ipip_trace_limit is None or ipip_trace_limit < 0:
            ipip_trace_limit = len(cands)
        _run_raw_slots(
            cands[:ipip_trace_limit], entries, args.timeout, IPIP_TRACE_CODE,
            cn_opt(args, "cn35", "concurrency", legacy="ipip_trace_concurrency",
           default=6),
        )
        print(f"{IPIP_TRACE_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{IPIP_TRACE_CODE} review: skipped (limit=0)", file=sys.stderr)

    # cn36（CN-46）：社区探针北京节点 ICMP（匿名 250/h 配额）。
    # 单键约 30s，CI 配额 60 键/4 并发（约 8min）；默认 0=跳过，-1=全部未定键。
    globalping_limit = cn_opt(args, "cn36", "limit", legacy="globalping_limit",
                    default=0)
    if globalping_limit != 0:
        cands = _pending_cands()
        if globalping_limit is None or globalping_limit < 0:
            globalping_limit = len(cands)
        _run_raw_slots(
            cands[:globalping_limit], entries, args.timeout, GLOBALPING_CODE,
            cn_opt(args, "cn36", "concurrency", legacy="globalping_concurrency",
           default=4),
        )
        print(f"{GLOBALPING_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{GLOBALPING_CODE} review: skipped (limit=0)", file=sys.stderr)

    # cn37（CN-47）：同 API 路由追踪（末跳达目标即见证）。
    # 单键约 100s，CI 配额 40 键/4 并发（约 17min）；默认 0=跳过，-1=全部未定键。
    globalping_trace_limit = cn_opt(args, "cn37", "limit", legacy="globalping_trace_limit",
                          default=0)
    if globalping_trace_limit != 0:
        cands = _pending_cands()
        if globalping_trace_limit is None or globalping_trace_limit < 0:
            globalping_trace_limit = len(cands)
        _run_raw_slots(
            cands[:globalping_trace_limit], entries, args.timeout,
            GLOBALPING_TRACE_CODE,
            cn_opt(args, "cn37", "concurrency", legacy="globalping_trace_concurrency",
           default=4),
        )
        print(f"{GLOBALPING_TRACE_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{GLOBALPING_TRACE_CODE} review: skipped (limit=0)", file=sys.stderr)

    # cn38（CN-48）：同 API 应用层确认（明文打 TLS 端口，服务端状态码
    # 即完整往返）。单键约 30s，CI 配额 40 键/4 并发；默认 0=跳过，-1=全部未定键。
    globalping_http_limit = cn_opt(args, "cn38", "limit", legacy="globalping_http_limit",
                         default=0)
    if globalping_http_limit != 0:
        cands = _pending_cands()
        if globalping_http_limit is None or globalping_http_limit < 0:
            globalping_http_limit = len(cands)
        _run_raw_slots(
            cands[:globalping_http_limit], entries, args.timeout,
            GLOBALPING_HTTP_CODE,
            cn_opt(args, "cn38", "concurrency", legacy="globalping_http_concurrency",
           default=4),
        )
        print(f"{GLOBALPING_HTTP_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{GLOBALPING_HTTP_CODE} review: skipped (limit=0)", file=sys.stderr)

    # cn39（CN-49）：同 API MTR（末跳达目标即见证）。
    # 单键约 100s，CI 配额 40 键/4 并发（约 17min）；默认 0=跳过，-1=全部未定键。
    globalping_mtr_limit = cn_opt(args, "cn39", "limit", legacy="globalping_mtr_limit",
                        default=0)
    if globalping_mtr_limit != 0:
        cands = _pending_cands()
        if globalping_mtr_limit is None or globalping_mtr_limit < 0:
            globalping_mtr_limit = len(cands)
        _run_raw_slots(
            cands[:globalping_mtr_limit], entries, args.timeout,
            GLOBALPING_MTR_CODE,
            cn_opt(args, "cn39", "concurrency", legacy="globalping_mtr_concurrency",
           default=4),
        )
        print(f"{GLOBALPING_MTR_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{GLOBALPING_MTR_CODE} review: skipped (limit=0)", file=sys.stderr)

    # 新增四个多节点 TCP 复核源（全部大陆多节点、遵循各站反爬协议）：
    # cn42（cookie-session+CSRF）、cn43（token 签章）、
    # cn44（header-token）、cn13（cookie-token+WS）。各自按 --<name>-limit
    # 投递（默认 0=跳过，-1=全部未定键）；达标即可独立判 reachable，整站失败
    # 也可与单节点源联动判 unreachable。
    # 注：cn34（CN-43 复活）已有上方专用相（含采集窗/配额注释），不再走此循环，
    # 防 limit≠0 时双跑。
    for src, check_name in ((BOCE_CODE, "bo" + "ce"), (SEVENTEEN_CODE, "17" + "ce"),
                            (PING0_CODE, "ping" + "0"), (WANSUI_CODE, "wan" + "sui")):
        limit = cn_opt(args, src, "limit", legacy=f"{check_name}_limit",
                     default=0)
        if limit != 0:
            cands = _pending_cands()
            if limit is None or limit < 0:
                limit = len(cands)
            _run_raw_slots(
                cands[:limit], entries, args.timeout, src,
                cn_opt(args, src, "concurrency", legacy=f"{check_name}_concurrency",
             default=6),
            )
            print(f"{check_name} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
                  file=sys.stderr)
        else:
            print(f"{check_name} review: skipped (limit=0)", file=sys.stderr)

    # cn40 多节点复核（串行、贵）只投「当前尚未被 cn01/单节点源确认可达」
    # 的键：已由 cn01 多点达标判 reachable 的不再浪费名额，把有限槽位让给
    # 仍待定（uncertain / skipped / 缺二看）的键 —— 多节点源能独立定论，
    # 优先给它派活能最大化「翻正」概率。顺序仍保持 sample 优先级排序。
    pingpe_candidates = [
        item for item in sample if needs_probe(entries, item[1])
    ]
    _run_pingpe_slots(
        pingpe_candidates[: cn_opt(args, "cn40", "limit",
                                 legacy="pingpe_limit", default=0)],
        entries,
        args.timeout,
        getattr(args, "tcpping_token", ""),
        cn_opt(args, "cn40", "concurrency", legacy="pingpe_concurrency",
             default=PINGPE_CONCURRENCY),
    )
    print(
        f"cn40 review: {time.monotonic() - _t0:.1f}s",
        file=sys.stderr,
    )

    reachable = set()
    uncertain = set()
    for item in sample:
        line, key, ip, port, cc = item
        sources = entries[key]
        merged = merge_verdict(sources)
        entries[key] = build_entry(item, sources)
        entries[key]["verdict"] = merged["verdict"]
        entries[key]["basis"] = merged["basis"]
        entries[key]["ms"] = merged["ms"]
        entries[key]["level"] = merged.get("level")
        if merged["verdict"] == "reachable":
            reachable.add(key)
        elif merged["verdict"] == "uncertain":
            uncertain.add(key)
    return entries, reachable, uncertain


def compute_fallback_merge(
    entries: dict,
    prev_entries: dict,
    reachable: set,
) -> set:
    """判定层兜底合并（纯函数，便于单测）。

    上轮可达、本轮仅因源配额/调度抖动落入 uncertain/skipped（或干脆未被采样）且
    **无任何失败源**的键，合并回 verdict=reachable 并标注 fallback=true，
    streak 清 0（未复测不虚报连续可达）。发生在中国 check 写 china.json 之前，
    使 build_good/annotate/all_cn.txt 全从 china.json 单一事实源读到同一集合，
    并把 reachable 计入返回后的集合。

    就地修改 ``entries``/``reachable`` 并返回 fallback 键集合。
    大陆读数沿用：落入 uncertain/skipped 但无失败源的键虽然本轮成功合并，但
    其来源全 error 时 ``ms``/``isp_ms`` 为空，若不沿用上一轮读数，下游
    ``common.cn_fastest_ms`` 会读成 None，导致 all_cn.txt（到 run 尾部从
    prev_entries 回填）与 build_good/annotate（只读 china.json）对同一键渲染出
    不同大陆读数，破坏"同口径"承诺。故本分支与下方"本轮未采样"分支（``dict(p)``
    整条复制含读数）对齐：当前条目缺失读数时回填上一轮同名字段。
    """
    fallback_keys: set[str] = set()
    for k, p in prev_entries.items():
        if not (isinstance(p, dict) and p.get("verdict") == "reachable"):
            continue
        cur = entries.get(k)
        if isinstance(cur, dict):
            if cur.get("verdict") not in ("reachable", "uncertain", "skipped"):
                continue
            s = cur.get("sources") or {}
            fails = sum(
                1 for r in s.values()
                if isinstance(r, dict) and r.get("status") == "fail"
            )
            if cur.get("verdict") == "reachable" or fails == 0:
                if cur.get("verdict") != "reachable":
                    cur["verdict"] = "reachable"
                    cur["fallback"] = True
                    # 防御性归零：本键本轮实为 uncertain（仅未证伪），无论
                    # apply_streak 时序如何，兜底键一律不得虚报"本轮已确认"的
                    # 连续可达（stable 计算在合并前已严格排除；此处再显式清 0，
                    # 防止任何按 streak 消费 china.json 的下游误把它当 stable）。
                    cur["streak"] = 0
                    # 大陆读数沿用上一轮（未复测成功，宁用历史读数也不用海外
                    # TLS 延迟冒充大陆视角；与下方 unsampled 分支 dict(p) 对齐）。
                    for _f in ("ms", "isp_ms"):
                        if cur.get(_f) is None:
                            _v = p.get(_f)
                            if _v is not None:
                                cur[_f] = _v
                    reachable.add(k)
                    fallback_keys.add(k)
        else:
            # 本轮未采样：原样并入，标注 fallback 保留溯源。
            # streak 清零：本轮未复测，不得虚报"连续可达"（stable 计算在合并
            # 前、不会混入；这里再显式清 0 防止 china.json 消费者误读）；\
            # 保留 sources/last_ok_ts 供下一轮兜底资格与大陆读数追溯。
            dup = dict(p)
            dup["verdict"] = "reachable"
            dup["fallback"] = True
            dup["streak"] = 0
            entries[k] = dup
            reachable.add(k)
            fallback_keys.add(k)
    return fallback_keys


def build_cn_best(entries: dict) -> dict:
    """CN 清单"最佳运营商"后缀映射（``-移动=57ms``）。

    仅当 ``cn_best_isp`` 给出真实 per-ISP 读数时才生成；其返回 ``None``
    （无读数/全为 ICMP 噪声）的条目直接跳过，绝不伪造运营商后缀。
    """
    out: dict = {}
    for key, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        best = cn_best_isp(entry)
        if best is None:
            continue
        isp, ms = best
        if isp is not None and ms is not None:
            out[key] = f"{isp}={round(ms)}ms"
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="china_check.py",
        description="大陆连通性检测（多源分层判定：源清单与默认见各 --*-limit 参数 "
        "与 docs/scripts.md，CI 启用集见 .github/workflows/china-check.yml）",
    )
    parser.add_argument("--source", type=Path, default=REP_RANK_FILE,
                        help=f"输入清单（默认 {REP_RANK_FILE.name}，缺失回退 all_ltd.txt）")
    parser.add_argument("--limit", type=int, default=LIMIT_DEFAULT,
                        help=f"按信誉降序采样条数（0=全部；默认 {LIMIT_DEFAULT}）")
    parser.add_argument("--17ce-token", default="",
                        help="cn43 token/cookie（可选；默认从壳页提取）")
    parser.add_argument("--workers", type=int, default=WORKERS_DEFAULT,
                        help=f"L2 并发上限（默认 {WORKERS_DEFAULT}）")
    parser.add_argument("-t", "--timeout", type=float, default=TIMEOUT_DEFAULT,
                        help=f"单次 HTTP 超时秒数（默认 {TIMEOUT_DEFAULT}）")
    parser.add_argument("--api-key", default="",
                        help="cn27 站 API key（默认读 CHINA_CHECK_API_KEY，可选）")
    parser.add_argument("--tcpping-token", default="",
                        help="cn41 复核 token（默认读 TCPPING_CN_TOKEN env，缺则跳过）")
    parser.add_argument("--itdog-nodes", type=int, default=ITDOG_NODES_PER_ISP,
                        help=f"批量通道每大陆运营商取 N 节点（跨省等距采样；默认 {ITDOG_NODES_PER_ISP} → 共 {ITDOG_NODES_PER_ISP * 3}）")
    parser.add_argument("--itdog-batch-size", type=int, default=ITDOG_BATCH_SIZE,
                        help=f"批量通道每任务目标数（上限 {ITDOG_BATCH_SIZE}；默认 {ITDOG_BATCH_SIZE}）")
    parser.add_argument("--itdog-concurrency", type=int, default=ITDOG_CONCURRENCY,
                        help=f"批量通道并发任务数（默认 {ITDOG_CONCURRENCY}）")
    parser.add_argument("--itdog-pacing", type=float, default=ITDOG_PACING,
                        help=f"批量通道任务启动最小间隔秒（默认 {ITDOG_PACING}）")
    parser.add_argument("--itdog-timeout", type=float, default=ITDOG_TASK_TIMEOUT,
                        help=f"批量通道单任务收结果上限秒（默认 {ITDOG_TASK_TIMEOUT}）")
    parser.add_argument("--skip-itdog", action="store_true",
                        help="跳过批量通道探活 cn01（快速冒烟用）")
    parser.add_argument("--skip-itdog-tcping", action="store_true",
                        help="跳过 cn02 补测（cn01 失败时的大节点池降级）")
    parser.add_argument("--itdog-tcping-nodes", type=int, default=ITDOG_TCPING_NODES_PER_ISP,
                        help=f"cn02 通道每运营商取 N 节点（默认 {ITDOG_TCPING_NODES_PER_ISP} → 共 {ITDOG_TCPING_NODES_PER_ISP * 3}）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只输出计划，不做任何网络请求与写盘")
    parser.add_argument("--cn-latency-cap", type=float, default=CN_LATENCY_CAP_MS,
                        help=f"CN 清单大陆视角 RTT 门槛（默认 {CN_LATENCY_CAP_MS}ms；inf 关闭）")
    parser.add_argument("--cn-cache-ttl", type=int, default=0,
                        help="CN 结果缓存秒数（0=关闭；>0 时复用 china.json 内 checked_at 未过期的 "
                        "reachable/uncertain 键并跳过复测；如 21600=6 小时）")
    parser.add_argument("--cn-limit", action="append", default=[],
                        metavar="CODE=N",
                        help="按代号覆盖复核条数（可重复；如 --cn-limit cn30=800），优先于 "
                        "legacy --<stem>-limit 与 PCB 注册表默认")
    parser.add_argument("--cn-concurrency", action="append", default=[],
                        metavar="CODE=N",
                        help="按代号覆盖并发数（可重复），优先于 legacy 并发旗标与注册表默认")
    parser.add_argument("--cn-nodes", action="append", default=[],
                        metavar="CODE=N",
                        help="按代号覆盖每键采样节点数（可重复），优先于 legacy 节点旗标")
    args = parser.parse_args(argv)

    api_key = args.api_key or os_environ("CHINA_CHECK_API_KEY")
    tcpping_token = args.tcpping_token or os_environ("TCPPING_CN_TOKEN")
    args.api_key = api_key
    args.tcpping_token = tcpping_token
    # generic 按代号覆盖归一化为 dict（run_measurements 经 cn_opt 读取；
    # 单测直调 run_measurements 的 SimpleNamespace 无此三属性即视为空覆盖）。
    args.cn_limit = parse_cn_kv(args.cn_limit)
    args.cn_concurrency = parse_cn_kv(args.cn_concurrency)
    args.cn_nodes = parse_cn_kv(args.cn_nodes)

    # 上一轮结果须在 write_json 覆盖 china.json 之前读取：
    # 用于 streak 连续可达计数与复检优先级（reachable 续保 > uncertain 升格）
    prev_data = read_json(CHINA_FILE)
    prev_entries = (
        prev_data.get("proxies", prev_data)
        if isinstance(prev_data, dict) else {}
    )
    if not isinstance(prev_entries, dict):
        prev_entries = {}

    sample, used = load_sample(args.source, args.limit)
    if not sample:
        print(f"no sample lines from {used} (limit={args.limit})", file=sys.stderr)
        return 2
    # 上一轮 uncertain 的键稳定排序置顶（组内保持信誉降序），优先复检
    # 上一轮 reachable（续保）优先，其次 uncertain（升格候选）最优先复检；
    # cn27 稀缺配额按此顺序投递，防止覆盖波动把稳定 CN 键翻出池。
    def _was_uncertain(item) -> int:
        prev = prev_entries.get(item[1])
        if isinstance(prev, dict):
            if prev.get("verdict") == "reachable":
                return 0
            if prev.get("verdict") == "uncertain":
                return 1
        return 2
    sample.sort(key=_was_uncertain)
    print(f"sample: {len(sample)} from {used}", file=sys.stderr)

    if args.dry_run:
        print("dry-run: no network, no writes", file=sys.stderr)
        return 0

    now_ts = time.time()
    cache_ttl = getattr(args, "cn_cache_ttl", 0) or 0
    cached_entries, probe_sample = split_cn_cache(
        sample, prev_entries, cache_ttl, now_ts)
    if cached_entries:
        print(f"cn-cache: reuse {len(cached_entries)} fresh, "
              f"probe {len(probe_sample)} (ttl={cache_ttl}s)",
              file=sys.stderr)
    if probe_sample:
        entries, reachable, uncertain = run_measurements(probe_sample, args)
    else:
        entries, reachable, uncertain = {}, set(), set()
    for entry in entries.values():
        if isinstance(entry, dict):
            entry["checked_at"] = now_ts

    apply_streak(entries, prev_entries)
    # 缓存复用项在 streak 之后并入：streak 只奖励当轮实测，复用键保持
    # 上一轮 streak/flip（冻结不累积）；fallback 合成与写盘则把它们
    # 当新鲜证据。
    merge_cn_cache(entries, reachable, uncertain, cached_entries)
    stable_keys = {
        k for k, e in entries.items()
        if isinstance(e, dict)
        and e.get("streak", 0) >= 2
        and e.get("flip", 0) <= STABLE_MAX_FLIP
    }
    http_keys = {
        k for k, e in entries.items()
        if isinstance(e, dict) and e.get("level") == "http"
    }
    flappers = sum(
        1 for e in entries.values()
        if isinstance(e, dict) and e.get("flip", 0) > STABLE_MAX_FLIP
    )
    # 历史兜底（判定层合并）：上轮可达、本轮仅因源配额/抖动落入 uncertain（或
    # 干脆未被本轮采样）且**无任何失败源**的键，标记回 reachable（fallback=true）。
    # 依据：无 ≥2 失败源证伪，只是"没来得及确认"，而用户硬约束要求 CN 全量池
    # ≥ MIN_CN_POOL、不减可达 IP。此合并发生在中国 check **写 influ china.json 之前**，
    # 故 build_good/annotate 与 all_cn.txt 全从 china.json 单一事实源读到同一集合，
    # 彻底消除"all_cn.txt 有而 all.txt/CN 分组找不到来源"的口径分裂。
    fallback_keys = compute_fallback_merge(entries, prev_entries, reachable)
    for e in entries.values():
        if isinstance(e, dict):
            e["cn_mainland"] = cn_mainland_ok(cn_l2_ms(e), args.cn_latency_cap)
    cn_ms_covered = sum(
        1 for e in entries.values()
        if isinstance(e, dict) and cn_l2_ms(e) is not None
    )
    print(
        f"reachable: {len(reachable)} uncertain: {len(uncertain)} "
        f"http-verified: {len(http_keys)} stable(>=2 runs): {len(stable_keys)} "
        f"flappers: {flappers} cn-l2-ms: {cn_ms_covered}/{len(entries)}",
        file=sys.stderr,
    )
    # per-key isp_ms（各运营商最小 RTT，来自 cn01/cn30/ce98/biuding/
    # aa1ping/cn32 多节点源与 cn24 单节点 per-ISP 源）——
    # 必须在中国 check 写 china.json 之前合并进 entries，单一事实源。
    merge_isp_ms(entries)
    n_isp = sum(
        1 for e in entries.values()
        if isinstance(e, dict) and isinstance(e.get("isp_ms"), dict)
        and e["isp_ms"]
    )
    print(f"isp_ms coverage: {n_isp}/{len(entries)} entries "
          f"(0 意味着 cn01 取节点被风控且 cn30/ce98/biuding 无出数 "
          f"— 见 CN-17 审计)", file=sys.stderr)
    # 分运营商估算速度（CN-41）：由 isp_ms 同公式派生，只增 isp_speed 字段，
    # 展示消费留待逻辑优化轮。
    merge_isp_speed(entries)
    write_json(
        CHINA_FILE,
        {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "proxies": entries,
        },
    )

    all_pool_text = load_cn_pool()
    # CN 清单展示用大陆延迟图：优先最快运营商视角（isp_ms 全局最小，
    # 即大陆用户体验上界），无 per-ISP 读数回退可信大陆探测
    # （cn20/cn24/cn27）；绝不让 L3 复核源的 1ms 噪声冒充真实延迟。
    cn_ms = {
        key: cn_fastest_ms(entry)
        for key, entry in entries.items()
        if isinstance(entry, dict) and cn_fastest_ms(entry) is not None
    }
    # CN 清单"最佳运营商"后缀：仅当 cn01 等 per-ISP 读数真实存在时，
    # 标记表现最好的运营商名字与其大陆 RTT（如 `-移动=57ms`）；无读数不伪造。
    cn_best = build_cn_best(entries)
    # 兜底键未复测，无当轮读数：从其上一轮 entry 补大陆延迟（历史同源读数，
    # 比海外 TLS 更贴近大陆视角；实在无读数则保持"不伪饰、删除速度"）。
    if fallback_keys:
        for k in fallback_keys:
            if k not in cn_ms:
                m = prev_entries.get(k)
                if isinstance(m, dict):
                    v = cn_fastest_ms(m)
                    if v is not None:
                        cn_ms[k] = v
    cn_text, cn_count = generate_all_cn(
        all_pool_text, reachable, cn_ms, http_keys=http_keys, best_isp=cn_best,
    )
    if cn_text:
        write_text_if_changed(VALID_ALL_CN_FILE, cn_text)
    http_text, http_count = generate_cn_subset(
        all_pool_text,
        lambda k, l: k in http_keys or has_token(_note(l), "CNH"),
        cn_ms,
        best_isp=cn_best,
    )
    write_cn_subset(VALID_ALL_CN_HTTP_FILE, http_text)
    stable_text, stable_count = generate_cn_subset(
        all_pool_text,
        lambda k, l: k in stable_keys,
        cn_ms,
        best_isp=cn_best,
    )
    write_cn_subset(VALID_ALL_CN_STABLE_FILE, stable_text)
    annotate_cn_files(reachable)
    cn_report = check_cn_health(cn_text)
    print(
        f"all_cn.txt: {cn_count} lines; all_cn_http.txt: {http_count}; "
        f"all_cn_stable.txt: {stable_count}; china.json: {len(entries)} entries; "
        f"health: count={cn_report['count']} no_ms={cn_report['no_ms']} "
        f"junk_ms(<=2ms)={cn_report['junk_ms']}",
        file=sys.stderr,
    )
    return 0


def os_environ(name: str) -> str:
    import os

    return os.environ.get(name, "")


if __name__ == "__main__":
    sys.exit(main())
