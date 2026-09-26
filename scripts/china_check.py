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

检测分层（均为无账号/免登录；每层通道身份/端点在 PCB 私有包中）：

- L2 批量通道实测（主源，全量，PCB 插件）：多节点、多运营商跨省
  等距采样，经 WebSocket 收结果，TCP 连通即判可达；节点返回 http_code>0
  时计应用层确认（level=http）——TLS 端口上明文探测收到的非 200 响应同样
  证明完整数据往返无 TCP 层干扰。
- L2 补测（降级通道）：主源对某目标失败/被限时，改用纯 TCP 复测，
  节点池更大（默认同口 8×3=24 节点），结果记为独立多节点源。
- L2 补测（ICMP 主机存活通道）：同上触发条件，改用 ICMP 复测——
  结果记为独立多节点源（``level`` 归一为 ``icmp`` 且不产
  ``isp_ms``，ICMP 不得进展示延迟，多节点 ICMP 源同口径）。
- L2 单节点实测（并发）：受限速单节点搭配 TCP、ICMP（echo 校验防垃圾
  回显）、HTTP 状态码（`level="http"`）、多端口扫描（仅授权端口产出
  证据）、TLS 握手（`level="tcp"` 保守，只作布尔见证）、ICMP 消歧、
  HTTPS 应用层确认——多只免额单节点源中任 2 ok 即双确认
  （single_ok≥2→reachable），受限速源不再是判定瓶颈。
- L3 多节点复核（有界并发小样本）：大陆节点池（多数决可达即判可达）；
  免费 REST（大陆节点取子集做 TCP 探测，按节点成功率判定）；持续
  TCPing（多运营商节点）；多节点 TCPing（HTTP SSE 测量单元）；
  ICMP（`level=icmp`，不产 `isp_ms`）；可选多运营商源（需站长签发
  token，缺则自动跳过）；独立运营商多城三网 TCPing（节点原生
  per-ISP，端口直连）；应用层确认（`status>0` 即确认，`level=http`，
  ms 取 connect_ms）；多 TCP 节点＋同通道 ICMP/MTR。
- 已于历史轮次评估并放弃若干通道（API 404 / 验证墙 / 路由迁移 / 无中国
  节点等）；完整身份与弃用记录见 PCB 文档，公开树不展开。

保守判定逻辑（merge_verdict）：
     多节点源任一 ok 且成功率达标 → reachable；
   单节点源 ≥2 个 ok → reachable；仅 1 个 ok → uncertain；
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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    cn_public_id,
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
from checks_bundle import require_bundle as _require_pcb_bundle

# 批量通道协议细节已迁入私有包（PCB）：有 bundle 时从插件取，无 bundle 时
# 该系源整段跳过（fail-open；调参回退为历史公开值，仅用于 CLI 默认展示）。
_CN01_BUNDLE = False
try:
    _cn01 = _load_pcb_plugin("cn01")
    CN03_NODES_PER_ISP = _cn01.PING_NODES_PER_ISP
    CN03_PAGE_URL = _cn01.PING_URL
    CN02_NODES_PER_ISP = _cn01.TCPING_NODES_PER_ISP
    CN02_PAGE_URL = _cn01.TCPING_URL
    cn01_batch_run = _cn01.batch_run
    _CN01_BUNDLE = True
except Exception:
    CN03_NODES_PER_ISP = 8
    CN03_PAGE_URL = None
    CN02_NODES_PER_ISP = 8
    CN02_PAGE_URL = None
    cn01_batch_run = None
WS_MAX_BUF = _WS_MAX_BUF
del _WS_MAX_BUF

# 双通道实现已迁入 PCB 私有插件：有 bundle 时取实现，
# 无 bundle 时对应源 fail-open（_run_raw_slots 写 error 行，不崩）。
_CN04_BUNDLE = False
try:
    _cn04 = _load_pcb_plugin("cn04")
    cn04_check = _cn04.ping_check
    cn05_check = _cn04.http_check
    _CN04_BUNDLE = True
except Exception:
    cn04_check = None
    cn05_check = None
# 该通道实现已迁入 PCB 私有插件：有 bundle 时取实现，
_CN06_BUNDLE = False
try:
    _cn06 = _load_pcb_plugin("cn06")
    cn06_check = _cn06.check
    CN06_CODE = _cn06.CODE
    _CN06_BUNDLE = True
except Exception:
    cn06_check = None
    CN06_CODE = "cn06"

# 该通道实现已迁入 PCB 私有插件：有 bundle 时取实现（内部含快速重试），
# 无 bundle 时 fail-open（_run_raw_slots 写 error 行）。
_CN07_BUNDLE = False
try:
    _cn07 = _load_pcb_plugin("cn07")
    cn07_check = _cn07.check
    CN07_CODE = _cn07.CODE
    CN07_CONCURRENCY = _cn07.CONCURRENCY
    _CN07_BUNDLE = True
except Exception:
    cn07_check = None
    CN07_CODE = "cn07"
    CN07_CONCURRENCY = 24

def _err(e: Exception) -> str:
    """异常类型名（不带 ``str(e)``：URLError 的 str 含完整 URL 与 token）。"""
    return err_name(e)


FALLBACK_SOURCE = DEFAULT_SOURCE

LIMIT_DEFAULT = 250
CN40_LIMIT_DEFAULT = 300
CN40_CONCURRENCY = 6  # 该 L3 相有界并发（每键端到端 ~20-40s，串行太慢）
CN40_SLOT_GAP = 2.0  # 单 worker 键间最小间隔（对上游礼貌）
WORKERS_DEFAULT = 56  # L2 免额单节点源并发（基准 1000 键：48w≈108s / 64w≈86s / 无 429；取中保守）
TIMEOUT_DEFAULT = 10
POLL_DEADLINE = 75.0
POLL_INTERVAL = 3.0

# 单节点三端点源族（应用层 TCP/ICMP/HTTPS，免 key，匿名限速）已迁入
# PCB 私有插件（协议细节见私有包文档）。名额由 run_measurements
# 用公共数值常量构造共享
# 限速器；无 bundle 时三 check 为 None → 调用 TypeError → except → error
# 行 fail-open。
CN27_WINDOW_SEC = 10.0
CN27_PER_WINDOW = 5  # 匿名限速 5/10s
CN27_HOUR_CAP = 250
_CN27_BUNDLE = False
try:
    _cn27 = _load_pcb_plugin("cn27")
    cn27_check = _cn27.tcp_check
    cn28_check = _cn27.ping_check
    cn29_check = _cn27.http_check
    RateLimiter = _cn27.RateLimiter
    RateLimited = _cn27.RateLimited
    CN27_CODE = _cn27.CODE
    CN28_CODE = _cn27.CODE_PING
    CN29_CODE = _cn27.CODE_HTTP
    _CN27_BUNDLE = True
except Exception:
    cn27_check = None
    cn28_check = None
    cn29_check = None
    RateLimiter = None
    RateLimited = None
    CN27_CODE = "cn27"
    CN28_CODE = "cn28"
    CN29_CODE = "cn29"

# 单节点源族（TCP / ICMP / 状态码 / 端口扫描，免 key JSON）已迁入
# PCB 私有插件（协议细节见私有包文档）。
# 无 bundle 时 l2 循环写 fail-open（attr 为 None，except 兜底）。
_CN20_BUNDLE = False
try:
    _cn20 = _load_pcb_plugin("cn20")
    cn20_check = _cn20.tcp_check
    cn21_check = _cn20.ping_check
    cn22_check = _cn20.status_check
    cn23_check = _cn20.scan_check
    CN20_CODE = _cn20.CODE
    CN21_CODE = _cn20.CODE_PING
    CN22_CODE = _cn20.CODE_STATUS
    CN23_CODE = _cn20.CODE_SCAN
    _CN20_BUNDLE = True
except Exception:
    cn20_check = None
    cn21_check = None
    cn22_check = None
    cn23_check = None
    CN20_CODE = "cn20"
    CN21_CODE = "cn21"
    CN22_CODE = "cn22"
    CN23_CODE = "cn23"


# 单节点源族（TC ping / ICMP ping / TLS 握手，免 key）已迁入
# PCB 私有插件（协议细节见私有包文档）。
# 无 bundle 时卡死源（None），L2 循环跳过。
_CN24_BUNDLE = False
try:
    _cn24 = _load_pcb_plugin("cn24")
    cn24_check = _cn24.tcp_check
    cn25_check = _cn24.ping_check
    cn26_check = _cn24.ssl_check
    CN24_CODE = _cn24.CODE
    CN25_CODE = _cn24.CODE_PING
    CN26_CODE = _cn24.CODE_SSL
    _CN24_BUNDLE = True
except Exception:
    cn24_check = None
    cn25_check = None
    cn26_check = None
    CN24_CODE = "cn24"
    CN25_CODE = "cn25"
    CN26_CODE = "cn26"


# 大陆节点池源（约 13 节点）已迁入 PCB 私有插件（协议细节见私有包文档）。
# 无 bundle 时对应 runner 写 fail-open。
_CN40_BUNDLE = False
try:
    _cn40 = _load_pcb_plugin("cn40")
    cn40_check = _cn40.check
    CN40_CODE = _cn40.CODE
    _CN40_BUNDLE = True
except Exception:
    cn40_check = None
    CN40_CODE = "cn40"
from china_engine import (
    DEFAULT_MIN_RATIO, MULTI_MIN_NODES, _SOURCE_MIN_RATIO,
    merge_verdict, CN01_CODE, CN02_CODE, CN03_CODE,
    CN04_CODE, CN05_CODE, _cn_isp_label,
)  # 判定引擎（拆分单向依赖；cc.* 名字保持可用）
# 多运营商 TCPing 源（需站长签发的 token，缺则跳过）已迁入 PCB 私有插件
# （协议细节见私有包文档）。token 为运行期凭证，
# 仍由公开 CLI 注入（--tcpping-token / TCPPING_CN_TOKEN env），本站不藏 key。
_CN41_BUNDLE = False
try:
    _cn41 = _load_pcb_plugin("cn41")
    cn41_check = _cn41.check
    CN41_CODE = _cn41.CODE
    _CN41_BUNDLE = True
except Exception:
    cn41_check = None
    CN41_CODE = "cn41"

# 多节点 REST 源族（TCP/ICMP/HTTP/路由，免 key，大陆节点取子集均衡采样）
# 已迁入 PCB 私有插件（协议细节见私有包文档）。节点列表进程内缓存
# （插件内）；无 bundle 时三函数为 None → run_measurements 跳过节点拉取，
# 对应 runner
# 写 fail-open error 行。配置常量（NODES/CONCURRENCY/LIMIT_DEFAULT）
# 由插件回绑，供 CLI 默认值与并发上界使用。
_CN30_BUNDLE = False
try:
    _cn30 = _load_pcb_plugin("cn30")
    cn30_fetch_nodes = _cn30.fetch_nodes
    cn30_pick_nodes = _cn30.pick_nodes
    cn30_check = _cn30.tcp_check
    CN30_CODE = _cn30.CODE
    CN31_CODE = _cn30.CODE_PING
    CN32_CODE = _cn30.CODE_HTTP
    CN33_CODE = _cn30.CODE_TRACE
    CN30_NODES = _cn30.NODES
    CN30_CONCURRENCY = _cn30.CONCURRENCY
    CN30_LIMIT_DEFAULT = _cn30.LIMIT_DEFAULT
    _CN30_BUNDLE = True
except Exception:
    cn30_fetch_nodes = None
    cn30_pick_nodes = None
    cn30_check = None
    CN30_CODE = "cn30"
    CN31_CODE = "cn31"
    CN32_CODE = "cn32"
    CN33_CODE = "cn33"
    CN30_NODES = 10
    CN30_CONCURRENCY = 8
    CN30_LIMIT_DEFAULT = 150

# 多节点 ICMP 源（REST+轮询）协议细节已迁入 PCB 私有插件；
# 无 bundle 时该源 fail-open（_run_raw_slots 记 error 行）。

# 该源实现已迁入 PCB 私有插件：有 bundle 时取实现（纯 HTTP+SSE 零鉴权，
# 协议细节见私有包文档），无 bundle 时对应 runner 写 fail-open。
_CN08_BUNDLE = False
try:
    _cn08 = _load_pcb_plugin("cn08")
    cn08_check = _cn08.check
    CN08_CODE = _cn08.CODE
    _CN08_BUNDLE = True
except Exception:
    cn08_check = None
    CN08_CODE = "cn08"

try:
    _cn14 = _load_pcb_plugin("cn14")
    cn14_check = _cn14.tcp_check
    cn15_check = _cn14.ping_check
    CN14_CODE = _cn14.CODE
    CN15_CODE = _cn14.CODE_PING
except Exception:
    cn14_check = None
    cn15_check = None
    CN14_CODE = "cn14"
    CN15_CODE = "cn15"

try:
    _cn16 = _load_pcb_plugin("cn16")
    cn16_check = _cn16.check
    CN16_CODE = _cn16.CODE
except Exception:
    cn16_check = None
    CN16_CODE = "cn16"

# 单键多节点 TCP 探测源族（同站 ICMP/MTR；会话 + PoW + WS 共享）已迁入
# PCB 私有插件（协议细节见私有包文档）。无 bundle 时对应 runner 写 fail-open。
_CN17_BUNDLE = False
try:
    _cn17 = _load_pcb_plugin("cn17")
    cn17_check = _cn17.tcp_check
    cn18_check = _cn17.ping_check
    cn19_check = _cn17.mtr_check
    CN17_CODE = _cn17.CODE
    CN18_CODE = _cn17.CODE_PING
    CN19_CODE = _cn17.CODE_MTR
    _CN17_BUNDLE = True
except Exception:
    cn17_check = None
    cn18_check = None
    cn19_check = None
    CN17_CODE = "cn17"
    CN18_CODE = "cn18"
    CN19_CODE = "cn19"
# 免费大陆多节点持续 TCPing 源（WebSocket，零 key）已迁入 PCB 私有插件
# （协议细节见私有包文档）。无 bundle 时对应 runner 记 fail-open。
_CN11_BUNDLE = False
try:
    _cn11 = _load_pcb_plugin("cn11")
    cn11_check = _cn11.tcp_check
    cn12_check = _cn11.ping_check
    CN11_CODE = _cn11.CODE
    CN12_CODE = _cn11.CODE_PING
    _CN11_BUNDLE = True
except Exception:
    cn11_check = None
    cn12_check = None
    CN11_CODE = "cn11"
    CN12_CODE = "cn12"

# 同族二通道 —— 免费大陆多节点 TCPing/Ping（纯 HTTP + SSE，零 key）：
# 协议细节已迁 PCB（该源 插件 + 私有包对应插件文档）。
# 同族二通道 已迁入 PCB 插件 该源：有 bundle 时取实现（纯 HTTP+SSE 零鉴权，
# 壳页 CSRF → /probe_sse.php 事件流，协议细节见 私有包对应插件文档），无 bundle
# 时 _run_raw_slots 记 fail-open。
_CN09_BUNDLE = False
try:
    _cn09 = _load_pcb_plugin("cn09")
    cn09_check = _cn09.tcp_check
    cn10_check = _cn09.ping_check
    CN09_CODE = _cn09.CODE_TCPING
    CN10_CODE = _cn09.CODE_PING
    _CN09_BUNDLE = True
except Exception:
    cn09_check = None
    cn10_check = None
    CN09_CODE = "cn09"
    CN10_CODE = "cn10"

# 同族多通道（社区探针：ICMP/路由追踪/应用层/MTR，匿名免 key
# 单节点冗余票）已迁入 PCB 插件 该源（协议细节见
# 私有包对应插件文档）。无 bundle 时四函数为 None → _run_raw_slots
# 写 fail-open error 行。四路匿名 250/h 配额；CI 配额 60/40/40/40 键@4
# 并发由 CI 行经 --cn-limit CODE=N 显式启用。
_CN36_BUNDLE = False
try:
    _cn36 = _load_pcb_plugin("cn36")
    cn36_check = _cn36.ping_check
    cn37_check = _cn36.trace_check
    cn38_check = _cn36.http_check
    cn39_check = _cn36.mtr_check
    CN36_CODE = _cn36.CODE
    CN37_CODE = _cn36.CODE_TRACE
    CN38_CODE = _cn36.CODE_HTTP
    CN39_CODE = _cn36.CODE_MTR
    _CN36_BUNDLE = True
except Exception:
    cn36_check = None
    cn37_check = None
    cn38_check = None
    cn39_check = None
    CN36_CODE = "cn36"
    CN37_CODE = "cn37"
    CN38_CODE = "cn38"
    CN39_CODE = "cn39"

# 该源 同站 ICMP 复用（CN-34）：该源的 check 别名（私有包对应插件）
# 即 ping 模式（type=ping，level=icmp）。单列 该源 源走
# ICMP，与 TCP 同站同节点池（约 39 测量单元）、不同协议层（低增益-同站）。
# ping 原生 ms 已实证（广东电信 7.578ms），但为与全部 ICMP 源一致仍剥离
# isp_ms（防 1~8ms 进展示；多节点 ICMP 源同口径）。

# 该源 同站 ICMP 复用（CN-36，见 私有包对应插件（ICMP 通道））：35 节点（电信 11/
# 移动 10/联通 8/多线 4/港澳台 1/海外 1，原生 isp 字段），结果帧与 TCP
# 同形（ok/loss/latest/average）；level=icmp，不产 isp_ms。


# —— 多节点 TCPing 复核族（cookie-session + CSRF token 反爬）：
# 同族二通道/该源 三源（多节点 TCPing，免 key，
# cookie-session+CSRF / HMAC token / header-token 反爬）已迁入 PCB 插件
# legacy 复核相（协议细节与休眠状态见 私有包对应插件文档）。
# 2026-09 复核：三族端点分别 404／路由迁移／反爬墙 —— 全部休眠，
# 公开树禁绕过验证墙（须人复核解除）。

# 同族二通道（GET+SSE 多节点 TCPing/路由追踪，免 key，
# 原生三网 isp_ms）已迁入 PCB 插件 （协议细节见 私有包对应插件文档）。
# 无 bundle 时两函数为 None → _run_raw_slots 写 fail-open error 行。
# 常数（探测端点/采集窗/探针数）由插件持有；CI 配额 100/100 键@8 并发
# 经 --cn-limit CODE=N 显式启用。
_CN34_BUNDLE = False
try:
    _cn34 = _load_pcb_plugin("cn34")
    cn34_check = _cn34.tcp_check
    cn35_check = _cn34.trace_check
    CN34_CODE = _cn34.CODE
    CN35_CODE = _cn34.CODE_TRACE
    _CN34_BUNDLE = True
except Exception:
    cn34_check = None
    cn35_check = None
    CN34_CODE = "cn34"
    CN35_CODE = "cn35"

_LEGACY_REVIEW_BUNDLE = False
try:
    _cn42 = _load_pcb_plugin("cn42")
    cn42_check = _cn42.check1
    cn43_check = _cn42.check2
    cn44_check = _cn42.check3
    CN42_CODE = _cn42.CODE_SLOT_1
    CN43_CODE = _cn42.CODE_SLOT_2
    CN44_CODE = _cn42.CODE_SLOT_3
    _LEGACY_REVIEW_BUNDLE = True
except Exception:
    cn42_check = None
    cn43_check = None
    cn44_check = None
    CN42_CODE = "cn42"
    CN43_CODE = "cn43"
    CN44_CODE = "cn44"

# 该源 已迁入 PCB 插件 该源（cookie token + WS 推送 TCPing，休眠态；
# 协议细节见 私有包对应插件文档）。无 bundle 时 _run_raw_slots 记 fail-open。
_CN13_BUNDLE = False
try:
    _cn13 = _load_pcb_plugin("cn13")
    cn13_check = _cn13.check
    CN13_CODE = _cn13.CODE
    _CN13_BUNDLE = True
except Exception:
    cn13_check = None
    CN13_CODE = "cn13"

# 批量多节点探活的节点规模、任务大小、并发、节流和收结果上限均由 PCB
# 注册表提供；任务级结果另出 per-ISP 最小 RTT。

CN_TOKEN = "CN"


# ------------------------------------------------------------ 解析函数（纯）


# ------------------------------------------------------------ 探测 I/O（网络）

# ------------------------------------------------------------ socket.io / SSE 族


# 大陆节点名运营商关键词 → 该源 口径归一（电信/联通/移动），供各源
# isp_ms 跨源合并；云厂商/裸地名/未知返回 None（不贡献运营商视角）。


# ------------------------------------------------------------ 判定合成

_CARRIER_KEYS = ("中国电信", "中国联通", "中国移动")


def _has_complete_carrier_data(entry) -> bool:
    """是否同时有三家运营商的当前正延迟读数。"""
    if not isinstance(entry, dict):
        return False
    values = entry.get("isp_ms")
    if not isinstance(values, dict):
        return False
    return all(
        isinstance(values.get(key), (int, float)) and values[key] > 0
        for key in _CARRIER_KEYS
    )


def _has_complete_carrier_evidence(entry) -> bool:
    """是否在当前 sources 原始结果中覆盖三家运营商。"""
    if not isinstance(entry, dict) or not isinstance(entry.get("sources"), dict):
        return False
    values: dict[str, float] = {}
    for result in entry["sources"].values():
        if not isinstance(result, dict) or not isinstance(result.get("isp_ms"), dict):
            continue
        for key in _CARRIER_KEYS:
            value = result["isp_ms"].get(key)
            if isinstance(value, (int, float)) and value > 0:
                values[key] = min(values.get(key, value), value)
    return all(key in values for key in _CARRIER_KEYS)


def _carrier_probe_limit(args=None) -> int:
    """从 PCB 注册表读取每轮缺失运营商补测上限（默认不额外补测）。"""
    if args is not None:
        override = getattr(args, "carrier_probe_limit", None)
        return override if isinstance(override, int) else 0
    reg = _sources_registry()
    if reg is None:
        return 0
    for entry in getattr(reg, "SOURCES", ()):
        extra = entry.get("extra", {})
        value = extra.get("carrier_probe_limit")
        if isinstance(value, int):
            return value
    return 0


def _carrier_probe_items(sample, entries, args=None) -> list:
    """挑选缺失三运营商读数的候选，按注册表上限截取。"""
    incomplete = [
        item for item in sample
        if not _has_complete_carrier_data(entries.get(item[1]))
    ]
    limit = _carrier_probe_limit(args)
    if limit == 0:
        return []
    return incomplete if limit < 0 else incomplete[:limit]


def merge_isp_ms(entries: dict) -> None:
    """就地合并各源 ``isp_ms`` 到 per-key ``entry["isp_ms"]``（各运营商最小 RTT）。

    每次先丢弃旧顶层派生值，只接受当前 sources 的原始读数；这样缓存或
    fallback 不会把过期/单运营商数据伪装成当前三运营商数据。源结果只需
    带 ``isp_ms``，跨源按运营商取最小；无任何当前 per-ISP 读数则不写字段。
    """
    for e in entries.values():
        if not isinstance(e, dict):
            continue
        e.pop("isp_ms", None)
        e.pop("isp_speed", None)
        sources = e.get("sources")
        merged: dict[str, float] = {}
        if not isinstance(sources, dict):
            continue
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
        e.pop("isp_speed", None)
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
    """返回 ``([(line, key, ip, port, cc), ...], used_path)``，按信誉降序截取。

    跨工作流回退：上游未产出 ``source``（如首轮无 all_rep.txt）时读
    ``FALLBACK_SOURCE``；两者皆无时返回空样本（调用方走
    ``no sample lines`` 退出 2，而非 FileNotFoundError 崩溃，R96）。
    """
    path = source if source.exists() else FALLBACK_SOURCE
    if not path.exists():
        return [], source
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

    def _key(item) -> tuple:
        v = cn_ms.get(line_to_key(item[1]))
        return (float("inf") if v is None else v, item[0])

    indexed = list(enumerate(lines))
    indexed.sort(key=_key)
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
# 个位数），≤2ms 即是 L3 复核源 1ms 噪声（该源 等）漏网的信号。
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

def _drain_futures(futures) -> None:
    """等全部槽位任务完成（fire-and-forget 型 join）。

    按**完成序**而非提交序等待，消除慢键队头阻塞（结果按 key 落盘，
    与等待顺序无关）。worker 内异常已就地收敛为 error 行；若未来有
    异常逃逸，此处 ``result()`` 原样上抛（与旧循环语义一致）。
    有界性说明：worker 内全部网络 I/O 带超时，进程级另有 CI 作业
    超时兜底；本函数不设局部 deadline（慢但健康的长尾不容误杀）。
    后续如需相位级 deadline，只改这一处。
    """
    for fut in as_completed(futures):
        fut.result()


def _run_cn40_slots(
    candidates: list, entries: dict, timeout: float,
    cn41_token: str, concurrency: int,
) -> None:
    """L3 cn40 多节点复核：串行→有界并发。每键端到端 ~20-40s（AJAX 启动
    + 轮询），串行 40 键 ≈ 26min；并发受控后同槽位耗时 ~7min，覆盖翻倍而
    不增加对上游的访问总量。并发数默认 `CN40_CONCURRENCY`。"""

    def work(item) -> None:
        _, key, ip, port, _ = item
        try:
            # 只看函数占位（loader 全有全无，与 _CN40_BUNDLE 同步；
            # 不读 flag，使单测 mock cn40_check 时与有无 bundle 无关）。
            if cn40_check is None:
                entries.setdefault(key, {})[CN40_CODE] = _bundle_missing(CN40_CODE)
            else:
                entries[key][CN40_CODE] = cn40_check(ip, port, timeout)
            if cn41_check is None:
                if cn41_token:
                    entries.setdefault(key, {})[CN41_CODE] = _bundle_missing(CN41_CODE)
            else:
                cn41_res = cn41_check(ip, port, cn41_token, timeout)
                if cn41_res["status"] != "skipped":
                    entries[key][CN41_CODE] = cn41_res
        except Exception as exc:
            logging.debug("cn40 failed for %s: %s", key, _err(exc))
            entries.setdefault(key, {})[CN40_CODE] = {
                "status": "error", "ok": False, "ms": None, "error": _err(exc)}
        time.sleep(CN40_SLOT_GAP)

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        _drain_futures([pool.submit(work, item) for item in candidates])


def _run_cn30_slots(
    candidates: list, entries: dict, timeout: float,
    node_uuids: list[str], concurrency: int,
    operators: dict | None = None,
    probe_type: str = "tcping", source: str = CN30_CODE,
) -> None:
    """同族四通道多节点复核（免费 REST，端到端 ~2-6s/键）。节点列表
    进程内缓存（插件内），只取一次；每键在 concurrency 有界并发下建任务
    并轮询结果。``operators``（``{uuid: 运营商}``）透传给该源 check 别名
    产出 per-ISP ``isp_ms``（仅 TCP/HTTP；ping/trace 按口径不产出）。
    ``probe_type``/``source`` 选择 TCP / ICMP / HTTP / 路由四通道与落键。
    无 bundle 时写 fail-open error 行。"""

    def work(item) -> None:
        _, key, ip, port, _ = item
        # 只看函数占位是否为 None（loader 全有全无，与 _CN30_BUNDLE
        # 同步；此处不读 flag，使单测 mock cn30_check 时与有无
        # bundle 无关——CI 无 PCB 包时亦可验证通道派发）。
        if cn30_check is None:
            entries.setdefault(key, {})[source] = _bundle_missing(source)
            return
        try:
            entries[key][source] = cn30_check(
                ip, port, timeout, node_uuids, operators,
                probe_type=probe_type)
        except Exception as exc:
            logging.debug("%s %s failed for %s: %s",
                          source, probe_type, key, _err(exc))
            entries.setdefault(key, {})[source] = {
                "status": "error", "ok": False, "ms": None, "error": _err(exc)}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        _drain_futures([pool.submit(work, item) for item in candidates])


def _run_ws_source_slots(
    candidates: list, entries: dict, timeout: float, source: str, concurrency: int
) -> None:
    """JWT/WS 或 PoW/WS 类源的多键并发复核（含 ICMP 与 MTR 子通道）。

    每个源按 ``candidates`` 前段投递；只写 ``entries[key][source]``。"""
    fn = _build_slot_table(timeout)[source]

    def work(item) -> None:
        _, key, ip, port, _ = item
        try:
            entries[key][source] = fn(ip, port)
        except Exception as exc:
            logging.debug("%s failed for %s: %s", source, key, _err(exc))
            entries.setdefault(key, {})[source] = {
                "status": "error", "ok": False, "ms": None, "error": _err(exc)}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        _drain_futures([pool.submit(work, item) for item in candidates])


def _run_cn08_slots(
    candidates: list, entries: dict, timeout: float, concurrency: int
) -> None:
    """cn08 多节点复核：有 bundle 时走插件（纯 HTTP+SSE ICMP ping；
    tcp_ping 固定端口 80 与代理真实端口不符，故只用作 ICMP 主机存活确认），
    无 bundle 时每键写 fail-open error（不崩不断言）。"""

    def work(item) -> None:
        _, key, ip, _, _ = item
        # 只看函数占位（loader 全有全无；不读 flag，使单测与有无 bundle 无关）。
        if cn08_check is None:
            entries.setdefault(key, {})[CN08_CODE] = _bundle_missing(CN08_CODE)
            return
        try:
            entries[key][CN08_CODE] = cn08_check(ip, timeout, method="ping")
        except Exception as exc:
            logging.debug("cn08 failed for %s: %s", key, _err(exc))
            entries.setdefault(key, {})[CN08_CODE] = {
                "status": "error", "ok": False, "ms": None, "error": _err(exc)}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        _drain_futures([pool.submit(work, item) for item in candidates])


def _bundle_missing(source: str) -> dict:
    """无 PCB 时插件源的 fail-open 占位（记 error，不崩不断言）。"""
    return {"status": "error", "ok": False, "ms": None,
            "error": f"pcb bundle missing for {source}", "level": None,
            "ok_nodes": 0, "nodes": 0, "ratio": None}


def _build_slot_table(timeout):
    """注册表驱动的 slot 派发表（M4b-core；与 _run_raw_slots 内手写表同构）。

    键为运行时代号（registry codes，无字面）；调用形态读条目 ``bind``
    （缺省标准三参；特形见 registry）。插件/函数缺失即 _bundle_missing
    桩。纯构造，无网络。

    无注册表时（无 PCB 包）按代号区间算法铺满槽位，但**同族解析规则不放
    松**：仍先取本模块已注册的 ``<code>_check`` 公开别名，取不到才落
    fail-open 桩。插件安装后实现即以该别名挂在模块上，故此路径既保旧
    回退语义（全槽位、缺实现即桩、不崩），又与有注册表路径的解析优先级
    一致——否则注册表缺席时会把已就位的实现静默降级为桩（派发契约丢失）。
    """
    try:
        reg = _sources_registry()
        entries = list(reg.SOURCES) if reg is not None else []
    except Exception:
        entries = []
    if not entries:
        module = sys.modules[__name__]
        table = {}
        for i in range(1, 45):
            code = f"cn{i:02d}"
            fn = getattr(module, f"{code}_check", None)
            if callable(fn):
                table[code] = (lambda ip, port, _f=fn, _t=timeout:
                               _f(ip, port, _t))
            else:
                table[code] = (lambda ip, port, _c=code:
                               _bundle_missing(_c))
        return table
    table = {}
    mods = {}
    module = sys.modules[__name__]
    for e in entries:
        code = e["code"]
        fn = getattr(module, f"{code}_check", None)
        try:
            plugin = e["plugin"]
            if not callable(fn):
                if plugin not in mods:
                    try:
                        mods[plugin] = _load_pcb_plugin(plugin)
                    except Exception:
                        mods[plugin] = None
                mod = mods[plugin]
                if mod is not None:
                    fn = getattr(mod, e["func"], None)
        except Exception:
            fn = None
        bind = e.get("bind", "ip-port-timeout")
        if fn is None:
            table[code] = (lambda ip, port, _c=code: _bundle_missing(_c))
        elif bind == "ip-timeout":
            table[code] = (lambda ip, port, _f=fn, _t=timeout:
                            _f(ip, _t))
        elif bind == "ip-empty-timeout":
            table[code] = (lambda ip, port, _f=fn, _t=timeout:
                            _f(ip, "", _t))
        else:
            table[code] = (lambda ip, port, _f=fn, _t=timeout:
                            _f(ip, port, _t))
    return table


def _run_raw_slots(
    candidates: list, entries: dict, timeout: float, source: str, concurrency: int
) -> None:
    """多节点复核通用 slot：按 ``source``（代号）派发到对应的多节点 check 函数
    （socket.io-WS / HTTP-SSE / 纯 WS 等传输），只写 ``entries[key][source]``。
    插件缺失时记 error 行（fail-open）。"""
    fn = _build_slot_table(timeout)[source]

    def work(item) -> None:
        _, key, ip, port, _ = item
        try:
            entries[key][source] = fn(ip, port)
        except Exception as exc:
            logging.debug("%s failed for %s: %s", source, key, _err(exc))
            entries.setdefault(key, {})[source] = {
                "status": "error", "ok": False, "ms": None, "error": _err(exc)}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        _drain_futures([pool.submit(work, item) for item in candidates])


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

    复用条件：上一轮同键 verdict 为 reachable/uncertain、当前 sources
    原始结果覆盖三家运营商且 ``checked_at`` 未过期（``checked_at + ttl >= now``）。
    ``ttl<=0`` 即关闭，全量复测。返回的缓存项为深拷贝（调用方并入后
    可随意改写，不污染上一轮基线）。
    """
    if ttl <= 0 or not prev_entries:
        return {}, list(sample)
    now = time.time() if now is None else now
    cached, probe = {}, []
    for item in sample:
        prev = prev_entries.get(item[1])
        if (isinstance(prev, dict)
                and prev.get("verdict") in ("reachable", "uncertain")
                and _has_complete_carrier_evidence(prev)
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


def list_cn_sources() -> int:
    """`--list-cn`：打印 PCB 注册表代号表（R100 可发现性）。

    动态读取（零硬编码，以 _sources 注册表为唯一真相源）；
    无包时 fail-open 提示并返回 2。只读注册表，无网络无写盘。
    """
    reg = _sources_registry()
    if reg is None:
        print("list-cn: PCB bundle missing (see docs/scripts.md 代号表)",
              file=sys.stderr)
        return 2
    print("code family limit concurrency")
    for e in reg.SOURCES:
        print(f"{e['code']} {e['family']} "
              f"{e['limit_default']} {e['concurrency']}")
    return 0


def _sources_registry():
    """PCB 源注册表模块（动态读取；无包回 None）。进程内缓存一次。"""
    global _SOURCES_REG
    if _SOURCES_REG is None:
        try:
            _SOURCES_REG = _load_pcb_plugin("_sources")
        except Exception:
            _SOURCES_REG = False
    return _SOURCES_REG or None


def _add_registry_cli_options(parser) -> int:
    """从 PCB 注册表安装源特有 argparse 选项；返回安装数。

    旗标、目标属性、类型、默认值和帮助文本均来自私有注册表。公开源码
    不保存资源代号或调参副本；无包或旧注册表无该接口时零安装。
    """
    reg = _sources_registry()
    getter = getattr(reg, "cli_options", None) if reg is not None else None
    if not callable(getter):
        return 0
    specs = getter()
    for spec in specs:
        parser.add_argument(*spec["flags"], **spec["kwargs"])
    return len(specs)


def parse_cn_kv(pairs):
    """解析 ``--cn-limit CODE=N``… 为 ``{code: N}``（非法项丢弃，code 小写化）。

    R87：丢弃项同步打 stderr warn（返回值不变，存量测试锁定），助用户
    发现 ``缺 =N``/``非数字`` 等笔误；未知代号由 warn_unknown_cn_codes
    在 registry 上下文中二次提示（此处无 registry 不判未知）。
    """
    out = {}
    for item in pairs or []:
        if "=" not in item:
            print(f"warn: ignoring malformed CODE=N {item!r}", file=sys.stderr)
            continue
        code, _, val = item.partition("=")
        code, val = code.strip().lower(), val.strip()
        if not code:
            print(f"warn: ignoring malformed CODE=N {item!r}", file=sys.stderr)
            continue
        try:
            out[code] = int(val)
        except ValueError:
            try:
                out[code] = float(val)
            except ValueError:
                print(f"warn: ignoring malformed CODE=N {item!r}", file=sys.stderr)
                continue
    return out


def warn_unknown_cn_codes(args) -> None:
    """对三组 generic 覆盖中的未知代号打 stderr warn（R87 用户侧体验）。

    有包时以 PCB 注册表为准；无包回退 cn01-cn44 模式。仅提示不丢弃
    （cn_opt 对未知码本就回 default），返回值 None。
    """
    reg = _sources_registry()
    known = None
    if reg is not None:
        try:
            known = set(reg.codes())
        except Exception:
            known = None
    if known is None:
        known = {f"cn{i:02d}" for i in range(1, 45)}
    for kind in ("cn_limit", "cn_concurrency", "cn_nodes"):
        mapping = getattr(args, kind, None)
        if not isinstance(mapping, dict):
            continue
        for code in sorted(mapping):
            if code not in known:
                print(f"warn: unknown CN code {code!r} ignored", file=sys.stderr)


# R99：泛型覆盖生效集合（须与 R89 适用矩阵一致，矩阵测试锁派线，
# 此处锁提示语义；双锁同源，漂移时两边同时变红）。
_NODES_HONORING_CODES = frozenset({"cn02", "cn30"})


def warn_inapplicable_cn_codes(args) -> None:
    """对已知但无泛型 knob 概念的代号打 stderr warn（R99 验证正确性）。

    判定（与 R89 矩阵同构）：limit/concurrency 仅 slot 家族（除搭车
    复核相）生效——batch 走 legacy 旗标、L2 常开全池、搭车相挂宿主相；
    nodes 仅两处采样通道可调。无包时注册表不可用则跳过（fail-open
    少提示，不多报错）。仅提示不丢弃，返回值 None。
    """
    reg = _sources_registry()
    if reg is None:
        return
    for kind, attr in (("limit", "cn_limit"), ("concurrency", "cn_concurrency"),
                       ("nodes", "cn_nodes")):
        mapping = getattr(args, attr, None)
        if not isinstance(mapping, dict):
            continue
        for code in sorted(mapping):
            try:
                entry = reg.by_code(code)
            except Exception:
                continue
            if entry is None:
                continue  # 未知码已由 warn_unknown_cn_codes 提示
            if kind == "nodes":
                honored = code in _NODES_HONORING_CODES
            else:
                honored = entry.get("family") == "slot" and code != "cn41"
            if not honored:
                print(f"warn: --cn-{kind} for {code!r} has no effect",
                      file=sys.stderr)


_CN_KIND_ATTR = {"limit": "cn_limit", "concurrency": "cn_concurrency",
                 "nodes": "cn_nodes"}
_CN_KIND_REGKEY = {"limit": "limit_default", "concurrency": "concurrency",
                   "nodes": None}


def cn_opt(args, code, kind="limit", legacy=None, default=0):
    """源选项解析（代号运行时件）。

    优先级：generic ``--cn-<kind> CODE=N`` > legacy ``<stem>_<kind>``
    属性（仅单测直调时传入；生产命名空间已无 legacy 属性）> PCB 注册表
    默认 > ``default``。无包且无属性时取 ``default``，单测/CI 与有无
    bundle 无关。
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
    cn27_limiter = RateLimiter(CN27_WINDOW_SEC, CN27_PER_WINDOW, CN27_HOUR_CAP) \
        if RateLimiter is not None else None
    _t0 = time.monotonic()

    def l2_cn20(item):
        """免额单节点源族（TCP / ICMP 存活 / 应用层状态码 / 443 端口扫描 /
        TCP / ICMP 存活 / TLS 握手，节点地域见私有包）全池扫描，先建立候选集。

        L2 是并发受限（aggregate QPS），非逐键串行瓶颈：七个源放进同池最多干到
        池大小并发请求，切换 task 粒度并不增量。赶时间应加池（WORKERS_DEFAULT=56
        实测各源均无 429），保键级数据一致性仍用逐键七源落盘。"""
        _, key, ip, port, _ = item
        out = {}
        for name, fn in ((CN20_CODE, cn20_check), (CN21_CODE, cn21_check),
                         (CN22_CODE, cn22_check), (CN23_CODE, cn23_check),
                         (CN24_CODE, cn24_check), (CN25_CODE, cn25_check),
                         (CN26_CODE, cn26_check)):
            try:
                out[name] = fn(ip, port, args.timeout)
            except Exception as exc:
                logging.debug("l2 %s failed for %s: %s", name, key, _err(exc))
                out[name] = {"status": "error", "ok": False, "ms": None,
                             "error": _err(exc)}
        return key, out

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(l2_cn20, item) for item in sample]
        for future in futures:
            key, sources = future.result()
            entries[key] = sources

    def l2_cn27(item):
        """稀缺配额源（单节点，约 250/h）二次确认。

        主通道判 fail 时追加同节点 ICMP ping（共用限速器）：
        主 fail + ICMP ok → 主机存活、端口层问题（uncertain，不误判死）；
        双 fail → 置信定罪。主 ok 且其余免额源 0 ok 时追加同节点 HTTPS
        应用层确认：第二确认猎取（uncertain→reachable），
        其余情况不追加（配额敏感）。
        """
        _, key, ip, port, _ = item
        try:
            tcp = cn27_check(ip, port, cn27_limiter, args.timeout, args.api_key)
        except Exception as exc:
            logging.debug("l2 cn27 failed for %s: %s", key, _err(exc))
            tcp = {"status": "error", "ok": False, "ms": None, "error": _err(exc)}
        out = {CN27_CODE: tcp}
        if tcp.get("status") == "fail":
            try:
                out[CN28_CODE] = cn28_check(
                    ip, cn27_limiter, args.timeout, args.api_key)
            except Exception as exc:
                logging.debug("l2 cn28 failed for %s: %s", key, _err(exc))
                out[CN28_CODE] = {
                    "status": "error", "ok": False, "ms": None,
                    "error": _err(exc), "level": None}
        elif tcp.get("ok"):
            entry = entries.get(key) or {}
            free_ok = sum(
                1 for n in (CN20_CODE, CN21_CODE, CN24_CODE, CN25_CODE)
                if (entry.get(n) or {}).get("status") == "ok")
            if free_ok == 0:
                try:
                    out[CN29_CODE] = cn29_check(
                        ip, port, cn27_limiter, args.timeout, args.api_key)
                except Exception as exc:
                    logging.debug("l2 cn29 failed for %s: %s",
                                  key, _err(exc))
                    out[CN29_CODE] = {
                        "status": "error", "ok": False, "ms": None,
                        "error": _err(exc), "level": None}
        return key, out
    # 该源 配额有限（CN27_HOUR_CAP ≈ 250/h），只投递「确认/救回」不投「定罪」：
    # - 免额七源中已有 ≥2 ok → 已独立确认可达，稀配额直接让位
    # - 任一已有 fail → 保守维持 uncertain（不浪费配额去补强失败证据，同旧策略）
    # 预算留给恰好 1 ok（补足到 2 即翻正）与纯临时性错误者。
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        def _needs_ch(entry: dict) -> bool:
            free = [entry.get(n) or {}
                    for n in (CN20_CODE, CN21_CODE, CN22_CODE, CN23_CODE,
                              CN24_CODE, CN25_CODE, CN26_CODE)]
            if sum(1 for r in free if r.get("status") == "ok") >= 2:
                return False
            if any(r.get("status") == "fail" for r in free):
                return False
            return True

        futures = [
            pool.submit(l2_cn27, item)
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

    if not getattr(args, "skip_primary_batch", False) and not _CN01_BUNDLE:
        print("pcb bundle missing: batch-source phases skipped",
              file=sys.stderr)
    if not getattr(args, "skip_primary_batch", False) and _CN01_BUNDLE:
        # 批量通道代价高（批任务端到端慢），只投仍未定论的键；已由
        # 双免额单节点源定论的键（≥2 ok / ≥2 fail）跳过其复核。
        # 无 PCB 时整段跳过（fail-open，公开 CI/无包环境不触批量通道）。
        _must_probe = [item for item in sample if needs_probe(entries, item[1])]
        _must_keys = {item[1] for item in _must_probe}
        _carrier_probe = [
            item for item in _carrier_probe_items(sample, entries, args)
            if item[1] not in _must_keys
        ]
        _cn01_cands = _must_probe + _carrier_probe
        if _carrier_probe:
            print(
                f"carrier probe: {len(_carrier_probe)} targets "
                f"(limit={_carrier_probe_limit(args)})",
                file=sys.stderr,
            )
        try:
            for key, res in cn01_batch_run(_cn01_cands, args).items():
                entries.setdefault(key, {})[CN01_CODE] = res
        except Exception as exc:
            logging.debug("cn01 batch failed: %s", _err(exc))
            print(f"cn01 batch failed (skipped): {_err(exc)}", file=sys.stderr)
        # batch_http 失败/被限的 key 用 batch_tcping 补测（节点池更大，纯 TCP）
        if not getattr(args, "skip_fallback_batch", False):
            pending = [
                item for item in _cn01_cands
                if entries.get(item[1], {}).get(CN01_CODE, {}).get("status")
                in ("error", "rate_limited")
            ]
            # 若主通道连节点列表都没取到（上游被墙/验证码墙的整站性失败），
            # tcping 同站同墙，兜底只会再空转一轮——直接跳过。注意只统计
            # 本轮真正过批量通道的键（无 该源 记录的已定论键不得算作成功），
            # 且要求至少出现过 1 次 ok（全 fail 也是被投毒站点的特征——真活的
            # 大陆可达键不可能整批 0 ok，全 fail 时同站的 tcping 一样是死路）。
            node_fetch_ok = any(
                entries.get(key, {}).get(CN01_CODE, {}).get("status") == "ok"
                for _, key, _, _, _ in _cn01_cands
            ) if _cn01_cands else False
            if pending and node_fetch_ok:
                print(
                    f"cn02 fallback: {len(pending)} targets",
                    file=sys.stderr,
                )
                try:
                    for key, res in cn01_batch_run(
                        pending,
                        args,
                        page_url=CN02_PAGE_URL,
                        nodes_per_isp=cn_opt(args, "cn02", "nodes",
                             default=0)
                        or CN02_NODES_PER_ISP,
                    ).items():
                        entries.setdefault(key, {})[CN02_CODE] = res
                except Exception as exc:
                    logging.debug("cn02 fallback failed: %s", _err(exc))
                    print(f"cn02 fallback failed (skipped): {_err(exc)}",
                          file=sys.stderr)
        # 该源 ICMP 补测（CN-26）：同上触发条件（该源 error/
        # rate_limited 且节点拉取成功），用 该源（ICMP，大节点池
        # 电信 87 / 联通 83 / 移动 89）复测主机存活。结果记为独立多节点源
        # （归一为 level=icmp、不产 isp_ms）；TCP 实测 fail 的键
        # 不投（fail 是端口层实测结论，不用 ICMP 主机存活翻案，保守）。
        ping_pending = [
            item for item in _cn01_cands
            if entries.get(item[1], {}).get(CN01_CODE, {}).get("status")
            in ("error", "rate_limited")
        ]
        if ping_pending and node_fetch_ok:
            print(
                f"cn03 fallback: {len(ping_pending)} targets",
                file=sys.stderr,
            )
            try:
                for key, res in cn01_batch_run(
                    ping_pending,
                    args,
                    page_url=CN03_PAGE_URL,
                    nodes_per_isp=CN03_NODES_PER_ISP,
                ).items():
                    entries.setdefault(key, {})[CN03_CODE] = (
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

    # 该源-33 多节点 TCP/ICMP/HTTP/路由 复核（免费 REST，节点列表进程内
    # 缓存于插件）：只投「当前尚未被判可达」的键，先于 （贵）跑，
    # 确认过的键会让位。--cn-limit <代号>=-1 表示全池未定键全覆盖（uncertain/
    # 错误健全部扫过，让每个键都有资格走向 reachable 或 unreachable 定论）。
    # 同族 ICMP 复核通道（type=ping，无端口概念，level=icmp，不产 isp_ms）
    # 跑在 TCP 相之后（只投 TCP 仍未定论者）。
    cn30_nodes = []
    cn30_uuids = []
    cn30_operators: dict | None = None
    if cn30_fetch_nodes is not None and cn30_pick_nodes is not None and (
            cn_opt(args, "cn30", "limit",
                   default=0) != 0 or cn_opt(
            args, "cn31", "limit",
            default=0) != 0 or cn_opt(
            args, "cn32", "limit",
            default=0) != 0 or cn_opt(
            args, "cn33", "limit",
            default=0) != 0):
        cn30_nodes = cn30_fetch_nodes(min(args.timeout, 20))
        cn30_uuids = cn30_pick_nodes(
            cn30_nodes, cn_opt(args, "cn30", "nodes",
                                  default=CN30_NODES)
        )
        cn30_operators = {
            n.get("uuid"): n.get("operator") for n in cn30_nodes
            if isinstance(n, dict) and n.get("uuid")
        }
    if cn30_uuids:
        cn30_candidates = [
            item for item in sample if needs_probe(entries, item[1])
        ]
        limit = cn_opt(args, "cn30", "limit",
                       default=0)
        if limit is None or limit < 0:
            limit = len(cn30_candidates)
        _run_cn30_slots(
            cn30_candidates[:limit],
            entries,
            args.timeout,
            cn30_uuids,
            cn_opt(args, "cn30", "concurrency",
                   default=CN30_CONCURRENCY),
            cn30_operators,
        )
        print(
            f"{CN30_CODE} review: {time.monotonic() - _t0:.1f}s "
            f"({len(cn30_candidates)} targets, {len(cn30_uuids)} nodes)",
            file=sys.stderr,
        )
        ping_limit = cn_opt(args, "cn31", "limit",
                            default=0)
        if ping_limit != 0:
            ping_candidates = [
                item for item in sample if needs_probe(entries, item[1])
            ]
            if ping_limit is None or ping_limit < 0:
                ping_limit = len(ping_candidates)
            _run_cn30_slots(
                ping_candidates[:ping_limit],
                entries,
                args.timeout,
                cn30_uuids,
                cn_opt(args, "cn31", "concurrency",
                       default=CN30_CONCURRENCY),
                cn30_operators,
                probe_type="ping",
                source=CN31_CODE,
            )
            print(
                f"{CN31_CODE} review: {time.monotonic() - _t0:.1f}s "
                f"({len(ping_candidates)} targets)",
                file=sys.stderr,
            )
        else:
            print(f"{CN31_CODE} review: skipped (limit=0)", file=sys.stderr)
        http_limit = cn_opt(args, "cn32", "limit",
                            default=0)
        if http_limit != 0:
            http_candidates = [
                item for item in sample if needs_probe(entries, item[1])
            ]
            if http_limit is None or http_limit < 0:
                http_limit = len(http_candidates)
            _run_cn30_slots(
                http_candidates[:http_limit],
                entries,
                args.timeout,
                cn30_uuids,
                cn_opt(args, "cn32", "concurrency",
                       default=CN30_CONCURRENCY),
                cn30_operators,
                probe_type="http",
                source=CN32_CODE,
            )
            print(
                f"{CN32_CODE} review: {time.monotonic() - _t0:.1f}s "
                f"({len(http_candidates)} targets)",
                file=sys.stderr,
            )
        else:
            print(f"{CN32_CODE} review: skipped (limit=0)", file=sys.stderr)
        trace_limit = cn_opt(args, "cn33", "limit",
                             default=0)
        if trace_limit != 0:
            trace_candidates = [
                item for item in sample if needs_probe(entries, item[1])
            ]
            if trace_limit is None or trace_limit < 0:
                trace_limit = len(trace_candidates)
            _run_cn30_slots(
                trace_candidates[:trace_limit],
                entries,
                args.timeout,
                cn30_uuids,
                cn_opt(args, "cn33", "concurrency",
                       default=CN30_CONCURRENCY),
                cn30_operators,
                probe_type="traceroute",
                source=CN33_CODE,
            )
            print(
                f"{CN33_CODE} review: {time.monotonic() - _t0:.1f}s "
                f"({len(trace_candidates)} targets)",
                file=sys.stderr,
            )
        else:
            print(f"{CN33_CODE} review: skipped (limit=0)", file=sys.stderr)
    else:
        print(
            f"{CN30_CODE} review: skipped (no nodes or limit=0)",
            file=sys.stderr,
        )

    # 该源 大陆多节点 ICMP 复核（免费、空闲量大）：全池未定键横扫，
    # 为主机存活提供独立多节点证据（端口层以 同族二通道 等 TCP 源为准）。
    cn07_limit = cn_opt(args, "cn07", "limit",
                default=0)
    if cn07_limit != 0:
        cn07_candidates = [
            item for item in sample if needs_probe(entries, item[1])
        ]
        if cn07_limit is None or cn07_limit < 0:
            cn07_limit = len(cn07_candidates)
        _run_raw_slots(
            cn07_candidates[:cn07_limit],
            entries,
            args.timeout,
            CN07_CODE,
            cn_opt(args, "cn07", "concurrency",
           default=CN07_CONCURRENCY),
        )
        print(
            f"cn07 review: {time.monotonic() - _t0:.1f}s "
            f"({len(cn07_candidates)} targets)",
            file=sys.stderr,
        )
    else:
        print("cn07 review: skipped (limit=0)", file=sys.stderr)

    def _pending_cands():
        return [
            item for item in sample if needs_probe(entries, item[1])
        ]

    # 新增多节点复核（全部无 key、大陆多节点）：各自按 --cn-limit CODE=N 投递
    # （默认 0=跳过，-1=全部未定键）；均为多节点源，
    # 达标即可独立判 reachable，整站失败也可与单节点源联动判 unreachable。

    cn08_limit = cn_opt(args, "cn08", "limit",
                 default=0)
    if cn08_limit != 0:
        cands = _pending_cands()
        if cn08_limit is None or cn08_limit < 0:
            cn08_limit = len(cands)
        _run_cn08_slots(
            cands[:cn08_limit], entries, args.timeout,
            cn_opt(args, "cn08", "concurrency",
           default=8),
        )
        print(f"cn08 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn08 review: skipped (limit=0)", file=sys.stderr)

    cn14_limit = cn_opt(args, "cn14", "limit",
                 default=0)
    if cn14_limit != 0:
        cands = _pending_cands()
        if cn14_limit is None or cn14_limit < 0:
            cn14_limit = len(cands)
        _run_ws_source_slots(
            cands[:cn14_limit], entries, args.timeout, CN14_CODE,
            cn_opt(args, "cn14", "concurrency",
           default=8),
        )
        print(f"cn14 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn14 review: skipped (limit=0)", file=sys.stderr)

    # 该源 ICMP 复核：独立判 reachable；默认 0=跳过。
    cn15_limit = cn_opt(args, "cn15", "limit",
                      default=0)
    if cn15_limit != 0:
        cands = _pending_cands()
        if cn15_limit is None or cn15_limit < 0:
            cn15_limit = len(cands)
        _run_ws_source_slots(
            cands[:cn15_limit], entries, args.timeout, CN15_CODE,
            cn_opt(args, "cn15", "concurrency",
           default=8),
        )
        print(f"cn15 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn15 review: skipped (limit=0)", file=sys.stderr)

    cn17_limit = cn_opt(args, "cn17", "limit",
                  default=0)
    if cn17_limit != 0:
        cands = _pending_cands()
        if cn17_limit is None or cn17_limit < 0:
            cn17_limit = len(cands)
        _run_ws_source_slots(
            cands[:cn17_limit], entries, args.timeout, CN17_CODE,
            cn_opt(args, "cn17", "concurrency",
           default=6),
        )
        print(f"cn17 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn17 review: skipped (limit=0)", file=sys.stderr)

    # （CN-30）：同站 ICMP ping（该源 通道），主独立判 reachable；默认 0=跳过。
    cn18_limit = cn_opt(args, "cn18", "limit",
                       default=0)
    if cn18_limit != 0:
        cands = _pending_cands()
        if cn18_limit is None or cn18_limit < 0:
            cn18_limit = len(cands)
        _run_ws_source_slots(
            cands[:cn18_limit], entries, args.timeout, CN18_CODE,
            cn_opt(args, "cn18", "concurrency",
           default=6),
        )
        print(f"cn18 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn18 review: skipped (limit=0)", file=sys.stderr)

    # （CN-44）：同站 MTR（约 139 节点，末跳达目标即见证），
    # 主独立判 reachable；默认 0=跳过，-1=全部未定键。
    cn19_limit = cn_opt(args, "cn19", "limit",
                      default=0)
    if cn19_limit != 0:
        cands = _pending_cands()
        if cn19_limit is None or cn19_limit < 0:
            cn19_limit = len(cands)
        _run_ws_source_slots(
            cands[:cn19_limit], entries, args.timeout, CN19_CODE,
            cn_opt(args, "cn19", "concurrency",
           default=6),
        )
        print(f"cn19 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn19 review: skipped (limit=0)", file=sys.stderr)

    cn16_limit = cn_opt(args, "cn16", "limit",
                default=0)
    if cn16_limit != 0:
        cands = _pending_cands()
        if cn16_limit is None or cn16_limit < 0:
            cn16_limit = len(cands)
        _run_ws_source_slots(
            cands[:cn16_limit], entries, args.timeout, CN16_CODE,
            cn_opt(args, "cn16", "concurrency",
           default=6),
        )
        print(f"cn16 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn16 review: skipped (limit=0)", file=sys.stderr)

    # 新增多节点 TCP 复核源：（socket.io-WS，34 大陆节点）
    # （HTTP-SSE，节点数动态，实测 ~39 测量单元）。均已实测出数、零 key；达标即可独立判 reachable，
    # 整站失败也可与单节点源联动判 unreachable。默认 0=跳过，-1=全部未定键。
    cn11_limit = cn_opt(args, "cn11", "limit",
              default=0)
    if cn11_limit != 0:
        cands = _pending_cands()
        if cn11_limit is None or cn11_limit < 0:
            cn11_limit = len(cands)
        _run_raw_slots(
            cands[:cn11_limit], entries, args.timeout, CN11_CODE,
            cn_opt(args, "cn11", "concurrency",
           default=6),
        )
        print(f"cn11 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn11 review: skipped (limit=0)", file=sys.stderr)

    # （CN-36）：同站 ICMP（35 节点 socket.io），主独立判 reachable；
    # 默认 0=跳过，-1=全部未定键。
    cn12_limit = cn_opt(args, "cn12", "limit",
                   default=0)
    if cn12_limit != 0:
        cands = _pending_cands()
        if cn12_limit is None or cn12_limit < 0:
            cn12_limit = len(cands)
        _run_raw_slots(
            cands[:cn12_limit], entries, args.timeout, CN12_CODE,
            cn_opt(args, "cn12", "concurrency",
           default=6),
        )
        print(f"cn12 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn12 review: skipped (limit=0)", file=sys.stderr)

    cn09_limit = cn_opt(args, "cn09", "limit",
                 default=0)
    if cn09_limit != 0:
        cands = _pending_cands()
        if cn09_limit is None or cn09_limit < 0:
            cn09_limit = len(cands)
        _run_raw_slots(
            cands[:cn09_limit], entries, args.timeout, CN09_CODE,
            cn_opt(args, "cn09", "concurrency",
           default=8),
        )
        print(f"cn09 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn09 review: skipped (limit=0)", file=sys.stderr)

    # 该源 ICMP 复核：主独立判 reachable；默认 0=跳过。
    cn10_limit = cn_opt(args, "cn10", "limit",
                      default=0)
    if cn10_limit != 0:
        cands = _pending_cands()
        if cn10_limit is None or cn10_limit < 0:
            cn10_limit = len(cands)
        _run_raw_slots(
            cands[:cn10_limit], entries, args.timeout, CN10_CODE,
            cn_opt(args, "cn10", "concurrency",
           default=8),
        )
        print(f"cn10 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn10 review: skipped (limit=0)", file=sys.stderr)

    # （CN-27）：独立运营商 28 城三网 TCPing（纯 WS，零 key）。
    # 达标即可独立判 reachable；默认 0=跳过，-1=全部未定键。
    cn04_limit = cn_opt(args, "cn04", "limit",
                 default=0)
    if cn04_limit != 0:
        cands = _pending_cands()
        if cn04_limit is None or cn04_limit < 0:
            cn04_limit = len(cands)
        _run_raw_slots(
            cands[:cn04_limit], entries, args.timeout, CN04_CODE,
            cn_opt(args, "cn04", "concurrency",
           default=6),
        )
        print(f"cn04 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn04 review: skipped (limit=0)", file=sys.stderr)

    # （CN-50）：同站 HTTP 测速通道（28 城三网，
    # 原生 operator isp_ms）。仅 443 键可用；默认 0=跳过，-1=全部未定键。
    cn05_limit = cn_opt(args, "cn05", "limit",
                 default=0)
    if cn05_limit != 0:
        cands = [item for item in _pending_cands() if item[3] == "443"]
        if cn05_limit is None or cn05_limit < 0:
            cn05_limit = len(cands)
        _run_raw_slots(
            cands[:cn05_limit], entries, args.timeout, CN05_CODE,
            cn_opt(args, "cn05", "concurrency",
           default=6),
        )
        print(f"cn05 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn05 review: skipped (limit=0)", file=sys.stderr)

    # （CN-42）：公开 WS 通道，约 16 节点 TCPing
    #（纯 WS，零 key，原生三网 isp_ms）。达标即可独立判 reachable；
    # 默认 0=跳过，-1=全部未定键。
    cn06_limit = cn_opt(args, "cn06", "limit",
                    default=0)
    if cn06_limit != 0:
        cands = _pending_cands()
        if cn06_limit is None or cn06_limit < 0:
            cn06_limit = len(cands)
        _run_raw_slots(
            cands[:cn06_limit], entries, args.timeout, CN06_CODE,
            cn_opt(args, "cn06", "concurrency",
           default=6),
        )
        print(f"cn06 review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print("cn06 review: skipped (limit=0)", file=sys.stderr)

    # （CN-43 复活）：多节点 TCPing（GET+SSE，约 287 节点，
    # 原生三网 isp_ms）。SSE 单键约 90s 采集窗，CI 配额 100 键/8 并发
    # （约 20min）；默认 0=跳过，-1=全部未定键。
    cn34_limit = cn_opt(args, "cn34", "limit",
              default=0)
    if cn34_limit != 0:
        cands = _pending_cands()
        if cn34_limit is None or cn34_limit < 0:
            cn34_limit = len(cands)
        _run_raw_slots(
            cands[:cn34_limit], entries, args.timeout, CN34_CODE,
            cn_opt(args, "cn34", "concurrency",
           default=6),
        )
        print(f"{CN34_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{CN34_CODE} review: skipped (limit=0)", file=sys.stderr)

    # （CN-45）：同站路由追踪（GET+SSE，约 57 节点，hop 行目标 IP
    # 即见证）。SSE 单键约 80s 采集窗，CI 配额 100 键/8 并发（约 17min）；
    # 默认 0=跳过，-1=全部未定键。
    cn35_limit = cn_opt(args, "cn35", "limit",
                    default=0)
    if cn35_limit != 0:
        cands = _pending_cands()
        if cn35_limit is None or cn35_limit < 0:
            cn35_limit = len(cands)
        _run_raw_slots(
            cands[:cn35_limit], entries, args.timeout, CN35_CODE,
            cn_opt(args, "cn35", "concurrency",
           default=6),
        )
        print(f"{CN35_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{CN35_CODE} review: skipped (limit=0)", file=sys.stderr)

    # （CN-46）：社区探针北京节点 ICMP（匿名 250/h 配额）。
    # 单键约 30s，CI 配额 60 键/4 并发（约 8min）；默认 0=跳过，-1=全部未定键。
    cn36_limit = cn_opt(args, "cn36", "limit",
                    default=0)
    if cn36_limit != 0:
        cands = _pending_cands()
        if cn36_limit is None or cn36_limit < 0:
            cn36_limit = len(cands)
        _run_raw_slots(
            cands[:cn36_limit], entries, args.timeout, CN36_CODE,
            cn_opt(args, "cn36", "concurrency",
           default=4),
        )
        print(f"{CN36_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{CN36_CODE} review: skipped (limit=0)", file=sys.stderr)

    # （CN-47）：同 API 路由追踪（末跳达目标即见证）。
    # 单键约 100s，CI 配额 40 键/4 并发（约 17min）；默认 0=跳过，-1=全部未定键。
    cn37_limit = cn_opt(args, "cn37", "limit",
                          default=0)
    if cn37_limit != 0:
        cands = _pending_cands()
        if cn37_limit is None or cn37_limit < 0:
            cn37_limit = len(cands)
        _run_raw_slots(
            cands[:cn37_limit], entries, args.timeout,
            CN37_CODE,
            cn_opt(args, "cn37", "concurrency",
           default=4),
        )
        print(f"{CN37_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{CN37_CODE} review: skipped (limit=0)", file=sys.stderr)

    # （CN-48）：同 API 应用层确认（明文打 TLS 端口，服务端状态码
    # 即完整往返）。单键约 30s，CI 配额 40 键/4 并发；默认 0=跳过，-1=全部未定键。
    cn38_limit = cn_opt(args, "cn38", "limit",
                         default=0)
    if cn38_limit != 0:
        cands = _pending_cands()
        if cn38_limit is None or cn38_limit < 0:
            cn38_limit = len(cands)
        _run_raw_slots(
            cands[:cn38_limit], entries, args.timeout,
            CN38_CODE,
            cn_opt(args, "cn38", "concurrency",
           default=4),
        )
        print(f"{CN38_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{CN38_CODE} review: skipped (limit=0)", file=sys.stderr)

    # （CN-49）：同 API MTR（末跳达目标即见证）。
    # 单键约 100s，CI 配额 40 键/4 并发（约 17min）；默认 0=跳过，-1=全部未定键。
    cn39_limit = cn_opt(args, "cn39", "limit",
                        default=0)
    if cn39_limit != 0:
        cands = _pending_cands()
        if cn39_limit is None or cn39_limit < 0:
            cn39_limit = len(cands)
        _run_raw_slots(
            cands[:cn39_limit], entries, args.timeout,
            CN39_CODE,
            cn_opt(args, "cn39", "concurrency",
           default=4),
        )
        print(f"{CN39_CODE} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
              file=sys.stderr)
    else:
        print(f"{CN39_CODE} review: skipped (limit=0)", file=sys.stderr)

    # 新增四个多节点 TCP 复核源（全部大陆多节点、遵循各站反爬协议）：
    # （cookie-session+CSRF）、（token 签章）、
    # （header-token）、（cookie-token+WS）。各自按 --cn-limit CODE=N
    # 投递（默认 0=跳过，-1=全部未定键）；达标即可独立判 reachable，整站失败
    # 也可与单节点源联动判 unreachable。
    # 注：（CN-43 复活）已有上方专用相（含采集窗/配额注释），不再走此循环，
    # 防 limit≠0 时双跑。
    for src, check_name in ((CN42_CODE, "bo" + "ce"), (CN43_CODE, "17" + "ce"),
                            (CN44_CODE, "ping" + "0"), (CN13_CODE, "wan" + "sui")):
        limit = cn_opt(args, src, "limit",
                     default=0)
        if limit != 0:
            cands = _pending_cands()
            if limit is None or limit < 0:
                limit = len(cands)
            _run_raw_slots(
                cands[:limit], entries, args.timeout, src,
                cn_opt(args, src, "concurrency",
             default=6),
            )
            print(f"{src} review: {time.monotonic() - _t0:.1f}s ({len(cands)} targets)",
                  file=sys.stderr)
        else:
            print(f"{src} review: skipped (limit=0)", file=sys.stderr)

    # 该源 多节点复核（串行、贵）只投「当前尚未被 该源/单节点源确认可达」
    # 的键：已由 该源 多点达标判 reachable 的不再浪费名额，把有限槽位让给
    # 仍待定（uncertain / skipped / 缺二看）的键 —— 多节点源能独立定论，
    # 优先给它派活能最大化「翻正」概率。顺序仍保持 sample 优先级排序。
    cn40_candidates = [
        item for item in sample if needs_probe(entries, item[1])
    ]
    _run_cn40_slots(
        cn40_candidates[: cn_opt(args, "cn40", "limit",
                                 default=0)],
        entries,
        args.timeout,
        getattr(args, "tcpping_token", ""),
        cn_opt(args, "cn40", "concurrency",
             default=CN40_CONCURRENCY),
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
            dup = _drop_legacy_source_keys(dict(p))
            dup["verdict"] = "reachable"
            dup["fallback"] = True
            dup["streak"] = 0
            entries[k] = dup
            reachable.add(k)
            fallback_keys.add(k)
    return fallback_keys


def _known_source_keys() -> set | None:
    """当前注册表的合法源键集合；无包返回 None（不净化，fail-open）。"""
    reg = _sources_registry()
    if reg is None:
        return None
    codes = getattr(reg, "codes", None)
    if not callable(codes):
        return None
    try:
        ks = set(codes())
    except Exception:
        return None
    # R237：``sources``/``basis`` 的键形态可能是裸代号（旧文件）或
    # ``src_*`` 不透明 id（新文件）。净化白名单须**同时**含两者，否则重跑
    # 切换那一刻会把新写入的 id 全判为「非法 legacy 键」而删掉。
    for c in list(ks):
        pid = cn_public_id(c)
        if pid:
            ks.add(pid)
    return ks


def _drop_legacy_source_keys(entry: dict) -> dict:
    """剔除上一轮遗留的**非法** ``sources``/``basis`` 键（R225）。

    实测事故：``data/quality/china.json`` 自首个提交（2026-09-21）起就有
    21.2% 的条目以**插件名**而非代号作 ``sources``/``basis`` 键（可点名到
    12 个真实来源名）——那是代号化迁移**之前**的写法。迁移改了新写入路径，
    却没清理已落盘的数据；而本函数的"本轮未采样"分支是 ``dict(p)`` 整条
    复制，于是这批 legacy 键被逐轮原样搬运、永久存活，等于把来源真名
    通过公开数据产物持续对外泄漏。

    此处按当前注册表的合法代号集净化：不在集合内的键一律丢弃。这些键本就
    无法参与派发（``_build_slot_table`` 只认注册表代号），留着只有泄漏与
    计数失真两个坏处；而它们携带的顶层 ``ms``/``isp_ms`` 仍按原逻辑沿用
    （那是给人看的大陆读数，与键名无关）。

    无包时不净化（``None``）——没有真相源可比对，宁可原样搬运也不误删。
    """
    known = _known_source_keys()
    if known is None:
        return entry
    src = entry.get("sources")
    if isinstance(src, dict):
        kept = {k: v for k, v in src.items() if k in known}
        if len(kept) != len(src):
            if kept:
                entry["sources"] = kept
            else:
                entry.pop("sources", None)
    basis = entry.get("basis")
    if isinstance(basis, (list, tuple)):
        kept_b = [b for b in basis if b in known]
        if len(kept_b) != len(basis):
            if kept_b:
                entry["basis"] = kept_b
            else:
                entry.pop("basis", None)
    return entry


def _seal_cn_source_keys(entries: dict) -> dict:
    """把 ``entries`` 各条目的 ``sources`` 键由代号换成不透明 id（R237）。

    **只换键、不换值**，也不改 ``basis``/``verdict`` 等其余字段——那些字段
    的键空间另有归属（``basis`` 的真名问题见 R225/R232）。无 PCB 包时
    ``cn_public_id`` 恒返回 ``None``，此时**原样返回**（fail-open：宁可
    落裸代号，也不得因为缺包而丢数据或崩流程）。
    """
    out = {}
    for key, entry in entries.items():
        if not isinstance(entry, dict):
            out[key] = entry
            continue
        src = entry.get("sources")
        if not isinstance(src, dict):
            out[key] = entry
            continue
        sealed = {}
        for k, v in src.items():
            pid = cn_public_id(k) if isinstance(k, str) else None
            sealed[pid or k] = v
        new_entry = dict(entry)
        new_entry["sources"] = sealed
        # ``basis`` 是同一族的另一个载体（实测 1227 处代号，占 0.8%）：
        # 语义为「本条判定依据了哪些通道」。只换**能换的**——``cn_public_id``
        # 对非代号（理论上已被 R225 的净化剔除）返回 None，原样保留。
        basis = entry.get("basis")
        if isinstance(basis, (list, tuple)):
            new_entry["basis"] = [
                (cn_public_id(b) or b) if isinstance(b, str) else b
                for b in basis
            ]
        out[key] = new_entry
    return out


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
    parser.add_argument("--workers", type=int, default=WORKERS_DEFAULT,
                        help=f"L2 并发上限（默认 {WORKERS_DEFAULT}）")
    parser.add_argument("-t", "--timeout", type=float, default=TIMEOUT_DEFAULT,
                        help=f"单次 HTTP 超时秒数（默认 {TIMEOUT_DEFAULT}）")
    parser.add_argument("--api-key", default="",
                        help="cn27 站 API key（默认读 CHINA_CHECK_API_KEY，可选）")
    parser.add_argument("--tcpping-token", default="",
                        help="cn41 复核 token（默认读 TCPPING_CN_TOKEN env，缺则跳过）")
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
                        "PCB 注册表默认（有效代号见 --list-cn）")
    parser.add_argument("--cn-concurrency", action="append", default=[],
                        metavar="CODE=N",
                        help="按代号覆盖并发数（可重复），优先于注册表默认（有效代号见 --list-cn）")
    parser.add_argument("--cn-nodes", action="append", default=[],
                        metavar="CODE=N",
                        help="按代号覆盖每键采样节点数（可重复），优先于 legacy 节点旗标（有效代号见 --list-cn）")
    parser.add_argument("--list-cn", action="store_true",
                        help="列出 PCB 注册表全部代号与默认（code/plugin/"
                        "family/limit/concurrency；不含插件内部函数名），"
                        "无网络无写盘")
    _add_registry_cli_options(parser)
    args = parser.parse_args(argv)

    # CI 显式要求私有包：checkout/pin 缺失即 fail-fast，禁止 44 源静默
    # fail-open 后写出看似成功的空证据数据；本地默认仍保留无包降级。
    if os_environ("PROXYIP_REQUIRE_PCB") == "1":
        _require_pcb_bundle()

    api_key = args.api_key or os_environ("CHINA_CHECK_API_KEY")
    cn41_token = args.tcpping_token or os_environ("TCPPING_CN_TOKEN")
    args.api_key = api_key
    args.tcpping_token = cn41_token
    # generic 按代号覆盖归一化为 dict（run_measurements 经 cn_opt 读取；
    # 单测直调 run_measurements 的 SimpleNamespace 无此三属性即视为空覆盖）。
    args.cn_limit = parse_cn_kv(args.cn_limit)
    args.cn_concurrency = parse_cn_kv(args.cn_concurrency)
    args.cn_nodes = parse_cn_kv(args.cn_nodes)
    warn_unknown_cn_codes(args)
    warn_inapplicable_cn_codes(args)

    if args.list_cn:
        return list_cn_sources()

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
    # 该源 稀缺配额按此顺序投递，防止覆盖波动把稳定 CN 键翻出池。
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
        print(f"dry-run plan: sample={len(sample)} from {used} "
              f"limit={args.limit} latency_cap={args.cn_latency_cap} "
              f"cache_ttl={args.cn_cache_ttl} overrides="
              f"limit:{args.cn_limit} concurrency:{args.cn_concurrency} "
              f"nodes:{args.cn_nodes}", file=sys.stderr)
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
    # per-key isp_ms（各运营商最小 RTT，来自按 ISP 布点的多节点源与
    # 单节点 per-ISP 源；具体源清单见私有包）——
    # 必须在中国 check 写 china.json 之前合并进 entries，单一事实源。
    merge_isp_ms(entries)
    n_isp = sum(
        1 for e in entries.values()
        if isinstance(e, dict) and isinstance(e.get("isp_ms"), dict)
        and e["isp_ms"]
    )
    print(f"isp_ms coverage: {n_isp}/{len(entries)} entries "
          f"(0 意味着 cn01 取节点被风控且 cn30/cn11/cn09 无出数 "
          f"— 见 CN-17 审计)", file=sys.stderr)
    # 分运营商估算速度（CN-41）：由 isp_ms 同公式派生，只增 isp_speed 字段，
    # 展示消费留待逻辑优化轮。
    merge_isp_speed(entries)
    write_json(
        CHINA_FILE,
        {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            # R237：落盘前把每条目 ``sources`` 子字典的**键**由代号换成
            # ``src_*`` 不透明 id（值原样）。内存侧全程用代号，故本函数之前
            # 的所有逻辑零改动；只在此处做序列化边界映射。读侧经
            # ``common.cn_source_variants()`` 同时接受两种形态，故未重跑的
            # 旧文件仍被正确读取。
            "proxies": _seal_cn_source_keys(entries),
        },
    )

    all_pool_text = load_cn_pool()
    # CN 清单展示用大陆延迟图：优先最快运营商视角（isp_ms 全局最小，
    # 即大陆用户体验上界），无 per-ISP 读数回退可信大陆探测
    # （可信大陆视角探测源）；绝不让 L3 复核源的 1ms 噪声冒充真实延迟。
    cn_ms = {
        key: cn_fastest_ms(entry)
        for key, entry in entries.items()
        if isinstance(entry, dict) and cn_fastest_ms(entry) is not None
    }
    # CN 清单"最佳运营商"后缀：仅当 per-ISP 读数真实存在时，
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
