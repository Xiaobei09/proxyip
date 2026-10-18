# 可用性校验流程（Availability Validation）

本文件说明「一个 IP 如何被判为可用」的链路、判定阈值与**可点击的复核入口**。
只使用公开工件与 Actions 记录即可复现结论；上游私有端点/凭证/真名从不出现于
本仓库（模式只能由 `PRIVATE_SOURCE_IDENTIFIER_PATTERN` 环境变量注入）。

## 链路总览

1. ip 源抓取：`pcb/scripts/download_proxies.py`
2. 存活 + 出口：`pcb/scripts/validate_proxies.py`、`pcb/scripts/quality_probe.py`（`check_external_api` 外部回显出口）
3. 出口家族/多出口：`exit_family.json`
4. 大陆可达与分运营商：`china_check.py`、`china_engine.py`
5. 缓存：`pool_cache.py`（7 天，单轮 ≤ 1000）
6. 质量与 good/premium：`quality_*.py`、`build_good.py`

## 工件与入口（具体链接）

| 环节 | 工作流 | 产物 |
|---|---|---|
| 采集去重 | [update-proxies.yml](https://github.com/Xiaobei09/proxyip/actions/workflows/update-proxies.yml) | `data/download/all.txt` |
| 存活/延迟 | [quality-check.yml](https://github.com/Xiaobei09/proxyip/actions/workflows/quality-check.yml) | `data/valid/all.txt`、`data/quality/` |
| 综合最优 | [build-good.yml](https://github.com/Xiaobei09/proxyip/actions/workflows/build-good.yml) | `data/valid/all_good*.txt`、`all_premium*.txt` |
| 大陆可达 | [china-check.yml](https://github.com/Xiaobei09/proxyip/actions/workflows/china-check.yml) | `data/valid/all_cn*.txt`、`data/quality/china.json` |
| 深度测速 | [deep-speed.yml](https://github.com/Xiaobei09/proxyip/actions/workflows/deep-speed.yml) | `data/valid/speed.json` |
| 出口地理 | [exit-family.yml](https://github.com/Xiaobei09/proxyip/actions/workflows/exit-family.yml) / [annotate-classify.yml](https://github.com/Xiaobei09/proxyip/actions/workflows/annotate-classify.yml) | `data/valid/exit_family.json`、`data/quality/` |
| 统计出图 | [stats.yml](https://github.com/Xiaobei09/proxyip/actions/workflows/stats.yml) | `data/output/stats.json`、`chart_*.svg` |
| 泄漏门禁 | [leak-guard.yml](https://github.com/Xiaobei09/proxyip/actions/workflows/leak-guard.yml) | 通过/失败结论 |

直链复核（`main` 分支）：

- 存活清单：<https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/all.txt>
- 大陆可达：<https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/all_cn.txt>
- 连续两轮大陆可达：<https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/all_cn_stable.txt>
- 综合最优：<https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/all_good.txt>
- 实测速度：<https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/speed.json>
- 结构化索引：<https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/index.json>
- 汇总统计：<https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json>
- 数据目录：<https://github.com/Xiaobei09/proxyip/tree/main/data>
- 格式规范：[docs/data-spec.md](https://github.com/Xiaobei09/proxyip/blob/main/docs/data-spec.md)

## 分阶段判定（逐级收窄）

1. **去重入库**：汇总 `ip:port`，统一为 `ip:port#国家` 数字序；入库 ≠ 可用。
   入库前**剔除落在 Cloudflare 官方公布段（AS13335）内的条目**（R695）：池的目标是
   「非 CF 段 + CF 边缘端口」的可直连连接池，而官方 CF 段在 Worker 出站 `connect()`
   中被禁止直连、对自建链路无用。该判据此前仅靠「只收自证第三方来源」+ 人工抽样
   把关（R215 曾因此整源回退官方段榜单），R695 起由**离线段门**保证，混合来源亦可
   安全收纳（官方段条目不进池、非官方段照收，剔除量在下载日志单行可见）。
   **R704 补**：若某来源的条目**全部**落在官方段内，则它是「结构性死源」——
   红线后每轮净留 0 条，却每轮照付一次抓取，且来源统计里长期留一行 0，看起来
   像抓取故障。下载日志现对「剔除量>0 且净留 0」单行列明并提示按源接入规则第
   5 条下线；该规则已实际执行过一次（源变更记录留档在私有侧，公开树不含源名）。
2. **传输层存活（L1）**：TLS/TCP 握手与握手延迟测量，失败即弃。
3. **应用层确认（`-CNH`）**：大陆侧 TCP 可达后再发真实 HTTP，2xx 才算应用层确认。
4. **全链路测速（`*_verified`）**：TLS + HTTP 2xx + 真实下载全部通过。
5. **跨轮稳定（`*_stable`）**：上一轮与本轮存活取交集，对抗 churn。
6. **综合最优（`all_good.txt`）**：大陆可达 + 有信誉记录 + 非高风险 + 有速度读数。

行尾 token 见 [README「行内备注速查」](https://github.com/Xiaobei09/proxyip/blob/main/README.md#中国大陆使用建议)：
`-CN` 大陆可达、`-CNH` 应用层确认、`←CC` 实测出口地区、`≈XMB/s` 国内速度。

## 具体端点

- 出口 IP：`http://httpbin.org/get`、`https://api.ipify.org?format=json`、Cloudflare `cf-ray`、`ip-api.com/json`
- 分运营商 RTT 异常下限：境内 1ms / 港澳 5ms / 台 8ms / 日韩 12ms / 东南亚 25ms / 其他 40ms。
- 分运营商数据超过 1 天清除（携带侧 `china_check.ISP_MS_CARRY_TTL_SEC=86400`；
  CN 侧缓存窗口同为 1 天，`common.CN_CACHE_WINDOW_SEC=86400`）。**读、写、调度三侧同一 24h 口径**：
  读侧 `common.fresh_isp_ms` 剔除过期读数；写侧 `merge_isp_ms` 按 TTL 丢弃/携带；
  调度侧「证据齐全」判据（`_has_complete_carrier_data`/`_trinet_missing`）同按 24h 账龄——
  全过期的键视为缺口、重回补测候选，避免「raw 齐全但全过期」的键被永久排除在补测外（R686）。
- **源失败隔离可见**：配置内上游源本轮抓取异常或解析为空时仍记 `0` 行
  （`source_stats.json` 的 `total=0` + `source_history.json` 计数 `0`），使
  `health_alert.check_sources` 的骤降判据能看见「源整体停摆」而非因 label 消失而静默（R687）。
- **时效看门狗对坏时间戳 fail-closed**：产物 / 历史 / CN 快照的时效判据在
  timestamp 字段**存在却不可解析**（或为空）时告警，不再按 `_now()` 误判成新鲜；
  字段**整体缺失**（旧格式）仍静默以兼容过渡期（`health_alert._ts_strict`，R690）。
- 出口多源对比（**目标** ≥10 个独立来源）：`exit_geo_multi.json`（exit-family
  工作流）按**出口 IP** 逐族查国，当前 9 个远程族（`ip-api`、`ipwhois`、`ip-sb`、
  `ipinfo`、`ipapi.co`、`geojs`、`ip2location`、`ipbase`、`ipquery`；`geolocation-db`
  保留观测但 weight=0 不计票）+ DB-IP LITE 本地库族（`TARGET_FAMILIES=10`，
  逐轮配置族数见 `summary.families_configured`、本轮**真有票**族数见
  `summary.families_active`（逐端点 `ok` 数见 `summary.providers`，源限流/
  失败致族退场可发现并归因，R693））；多族共识（`top_votes ≥ 2`）
  作为 `←CC` 强票、单族弱票次之，再回退 `external_check.json`、
  `upstream_meta.json`、`ipinfo.json` 三源（`common.build_exit_cc_map` 按优先级
  汇聚为每个键的出口地区）；`multi_region_exit=true` 在观测到 ≥2 个互异出口
  地区时置真。

## 超时

- 网络 ≤ 30s；脚本 ≤ 5min；测试 ≤ 5min；git ≤ 60s。

## CN 探测调度要求 (用户指令)

- 每轮 CN 探测结束后应尽量安排下一轮（不与在跑实例冲突）。
- 探测新数据优先当前 CN 源无数据（可达/不可达）的 key；顺序为
  续保桶 → 无数据 key → uncertain → 已有数据键（`china_check.cn_probe_priority` 四档）。
- 分运营商读数超过 1 天清除；4 运营商可用读数目标均衡。
- **命名消歧（三个不同的「1000」）**：用户指令「总测试项 <= 1000」指的是**测试套件**
  规模（`tests/` + `tests_pipeline/` 的**测试函数数 + 测试类数**）上限，与 §缓存 的
  `pool_cache` **单轮补回 ≤1000**、以及部分探测通道内部的 `limit=1000` 硬上限
  是**互相独立**的三个数值，勿混用。
- 出口 multi-source comparison 至少 10 个独立来源（R607 后达 10 族：9 远程 +
  DB-IP LITE 本地库；`reputation*.json` 无地理字段、不可直接复用，但其 vendor
  的独立免 key 地理端点（如 ipquery）已按族接入）。

## 三层清单的成员关系与相位差（R688）

`all.txt`（主池）→ `all_cn.txt`（主池 ∩ 当期 `china.json` 判可达）→
`all_good.txt` / `all_premium.txt`（在其上叠加信誉/速度/住宅等条件）。**同一次运行内**
`all_cn ⊆ all.txt`、`all_good/premium ⊆ all_cn` 恒成立；但三层由**不同工作流、不同节奏**
产出并各自提交——[quality-check.yml](https://github.com/Xiaobei09/proxyip/actions/workflows/quality-check.yml)
频繁重写 `all.txt` 而 [china-check.yml](https://github.com/Xiaobei09/proxyip/actions/workflows/china-check.yml)
间隔更疏，故任一提交点上会带出**一轮相位差**（实测 `cn_not_in_all=593`
`good_not_in_cn=3`）。该漂移由 annotate 步骤的 `verify_cn_lists` 逐轮打印计数
（`WARN: CN lists drift from all.txt (...)`，**不阻断**，仅作趋势可见化）。

**复现口径**：判「某 IP 是否当前可用」请**同一提交点**取三层，或直接以
`all.txt` + `china.json.meta.carrier_breakdown`/`proxies[key].verdict` 为准——
跨清单做集合推论时须容忍上面的一轮相位差，勿把 3~600 的量级差当作单独缺陷。

## 独立复现（本地命令）

```bash
# 当前大陆可达清单（含延迟/运营商/出口标记）
curl -fsSL https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/all_cn.txt | head

# 最近一轮总量与运营商分布
curl -fsSL https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json

# 工作流最近运行结论
#   https://github.com/Xiaobei09/proxyip/actions/workflows/china-check.yml
```

复现「某 IP 为何被判可用」：候选是否存在 → `all.txt` 是否有延迟 → `all_cn.txt`
是否有 `-CN`/`-CNH` → 是否进入 `all_good.txt`。

## 安全与门禁

- 泄漏门禁扫描**公开树**的文本文件（含 `docs/`、`.github/`、`README.md` 与已发布
  的 `data/`），**跳过**私有嵌套库 `pcb/` 与 `.git/`、`.opencode/`——判据同
  `pcb/tests_pipeline/test_checks_bundle.py` 的 `_SKIP_DIRS`。
  `scripts/`、`tests/` 已随代码切流迁入私有仓，不在公开面内。
- `.github/scripts/leak_scan.sh` 未得到模式注入时**拒绝运行**（fail-closed），
  不会输出「干净」的假结论；其跳过集合与上面的 `_SKIP_DIRS` 逐条一致（R525）。
