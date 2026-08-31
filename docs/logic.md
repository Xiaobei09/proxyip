# 检测逻辑

本文档详细描述 IP 质量检测系统的核心算法与判定逻辑，供维护者理解代码实现。

## 1. 整体架构

```
download_proxies.py → validate_proxies.py → quality_check.py
                                             ├─ quality_probe.py
                                             ├─ quality_reputation.py
                                             └─ reorg_country.py
                           ↓
                   china_check.py (+ china_itdog.py)
                   exit_family.py
                   annotate_classify.py
                           ↓
                   generate_stats.py
```

每个阶段产出 `data/quality/*.json` 中间数据，最终阶段读取所有 JSON 生成带注释的 `data/valid/*.txt`。

## 2. 可用性验证（validate_proxies.py）

### 2.1 TLS 握手检测

对每个代理做 TLS 握手（SNI=`cdnjs.cloudflare.com`），成功即判定存活。Cloudflare 边缘代理在 443/8443/2053/2083/2087/2096 端口提供 TLS 服务，握手成功即说明代理可用。

### 2.2 速度测试

每个存活代理在新建 TLS 连接上做真实下载测速：

- 目标：`GET /ajax/libs/three.js/r128/three.js`（约 530 KB），**稳态测量**
- 响应门控：先读响应头，仅接受 HTTP 2xx；403 错误页 / 非 HTTP 垃圾数据 → 测速失败
- 稳态窗口：前 `--speed-warmup-bytes`（默认 256 KB）为预热段，覆盖 TCP 慢启动爬坡，
  不计入计时；速度 = 稳态窗口字节量 ÷ 耗时；预热段内即 EOF/超时时回退全程平均
- 读取上限：`--speed-bytes`（默认 1 MB）
- 超时：5s
- 并发上限：30（独立于判活的 500 并发）
- 最小有效字节：16384（低于此值视为测速失败，速度置空）

速度仅用于排序与统计，不做二次筛选。

### 2.3 自动重试

TCP 能连通但 TLS 检测超时的代理，短暂间隔后重试一次，降低单次丢包误杀。

## 3. 出口探测引擎（quality_probe.py）与已移除的流媒体解锁

> **流媒体解锁检查已于本轮整体移除**（NF/D+/YT/MX/PV/GPT 不再产生新观测）。
> 历史行上的这些 token 由 `normalize_note` 作为遗留段继续容忍解析，
> 随节点自然轮换逐渐消失。原 `quality_streaming.py` 拆分为：
>
> - `quality_probe.py` —— 通用 TLS 探测引擎：`tls_get_direct`（SNI 直连 GET）、
>   外部出口地理回显 API（`check_external_api`，exit_cc 第一数据源）、
>   ip-api 批量地理查询（`batch_ipapi`）；
> - 流媒体服务表、各服务解析器与 `finalize_streaming`/`streaming_tokens`
>   一并删除。

### 3.1 滚动可用率跟踪（uptime.py）

质量链每轮把存活节点按 UTC 日期记入 `data/quality/node_seen.json`
（滚动 45 天窗口），并维护全局"运行日计数器"作为分母：

- `uptime7 / uptime30`：窗口内出现天数 ÷ 运行轮数 → 存活率百分比；
- 结果写入 `data/quality/uptime.json`，注解链为命中的行追加 `-U<NN>`
  备注（如 `-U92`），build-good 产出 `_uptime` 可靠性子集（pct7 ≥ 80）。

### 3.2 深测带宽写回信誉分

deep-speed 深测（多流大样本）结果聚合出每节点最优目标的
`agg_mbps`；quality_check 计算信誉分时叠加线性加成：
`bonus = round(min(agg/50, 1) × 10)`，封顶 +10 分且**只对已有信誉分
的节点生效**（深测是抽样，不产生幽灵分）。加成记录在
`reputation.json` 条目的 `deep_bonus` 字段。

## 4. IP 信誉评分（quality_reputation.py）

### 4.0 出口 IP 解析（resolve_exit_ips）

信誉 / 地理 / 滥用查询一律使用**真实出口 IP**，按优先级解析：

1. `external_check.exit_geo.ip` —— 外部探测回显的出口
2. `exit_family.json` 的 `exit_v4` / `exit_v6` —— 专用双栈探测实测
3. 代理自身 IP（兜底；仅当无任何出口观测）

> CF 中转代理的入口恒为 Cloudflare 边缘 IP——查入口会得到千篇一律的
> "干净"结果，完全失真。`exit_ip_source` 字段记录取值来源。

### 4.1 评分公式

**多源加权合成**：

```
score = round(Σ(w_i × s_i) / Σ(w_i))
```

其中 `w_i` 为源权重，`s_i` 为源给出的 0-100 干净分（越大越干净），仅计入实际响应的源。

**滥用分优先级**：若 AbuseIPDB/IPQS 滥用分可用，直接取 `100 - abuse_score`，不走多源合成。

### 4.2 风险等级

| 分数区间 | 风险 |
|---|---|
| < 30 | high |
| 30 ≤ x < 75 | medium |
| ≥ 75 | low |

### 4.3 各源评分逻辑

#### API 源（per-IP 查询）

| 源 | 权重 | 评分逻辑 |
|---|---|---|
| netcoffee | 20 | 直接取 `trust_score`（0-100）；无 score 时按标志罚分：abuser -40 / tor -35 / proxy -30 / vpn -25 / datacenter -15，机房 ASN/公司类型再 -15，abuser_score≥0.1 再 -20 |
| ncgy | 10 | MaxMind 标志罚分：tor -45 / proxy -30 / vpn -25 / anonymous -10 |
| ip-api | 15 | 本地批量地理：proxy -25 / hosting -10 / mobile +10；有 `countryCode` 即计入 |
| ipquery | 12 | `risk_score` 直用或标志罚分（取较大者）：tor -45 / vpn -30 / proxy -25 / datacenter -15 |
| ffraud | 12 | `fraud_score` 直用或标志罚分（取较大者）：tor -45 / vpn -30 / proxy -25 / hosting -15 / abuser -20 / recent_abuse -15 |
| blackbox | 10 | 按分类给分：residential 95 / mobile 90 / business 85 / hosting 60 / vpn 55 / privacy_relay 50 / tor 10 / bogon 5 / unknown 50；suspicious -20 |
| otx | 8 | `100 - (min(reputation×5,80) + min(pulse_count×2,20))` |
| ipapi_is | 8 | 标志罚分：tor -45 / vpn -30 / proxy -25 / datacenter -15 / abuser -20，机房 ASN/公司类型 -15，abuser_score≥0.1 -20 |
| ipdata | 8 | 标志罚分 + `threat_score`：tor -45 / proxy -30 / vpn -25 / anonymous -10 |
| whatismyip | 3 | `security.score` 直用或标志罚分（取较大者）：vpn -30 / proxy -25 / tor -45 / hosting -15 / blacklisted -30 |
| getipintel | 5 | `100 - probability×100`（opt-in，需邮箱） |
| proxycheck | 12 | `risk` score 直用或标志罚分（取较大者）：proxy -45 / vpn -45 / tor -45 / hosting -30 / scraper -20 |
| ip2location | 5 | `is_proxy` 标志 -30 |
| freeipapi | 6 | `isProxy` 标志 -30（附 ASN/org，全免费免 key） |
| scamalytics | 8 | 免费风险页 `Fraud Score`（0-100）直扣；`is_blacklisted_external` 投 listed 票 |
| iplocation | 3 | `is_proxy` 标志 -30（附 isp，全免费免 key） |

#### 静态列表源（每 run 重拉）

| 源 | 权重 | 命中时分数 |
|---|---|---|
| ipsum | 8 | 55（命中 3+ 黑名单） |
| abuse_list | 5 | 60（历史滥用） |
| dc_asn | 5 | 85（机房/数据中心 ASN） |
| vpn_asn | 3 | 70（VPN 服务商 ASN） |
| resproxy_asn | 2 | 75（住宅代理骨干 ASN） |
| cins | 5 | 50（CINS 活跃滥用/拒绝服务 IP） |
| et_compromised | 4 | 45（EmergingThreats 被入侵主机回连） |

未命中 → 该项不计入合分（不误判满分）。

### 4.4 缓存机制

- 按 IP 的 API 源信号缓存在 `data/quality/reputation_cache.json`
- TTL 默认 7 天，TTL 内复用缓存信号重新计算分数
- 只查询缺失/过期的 IP
- 静态列表不缓存，每轮重拉

## 5. 大陆连通性检测（china_check.py）

### 5.1 四层检测架构

#### L1 启发式（零网络）

行备注已带 `-CF`（Cloudflare 边缘 tls 代理）→ 记录 `heuristic` 源，但**不自动判 reachable**。CF 启发式仅作为 basis 标注。

#### L2 批量实测（主源）

**itdog.cn 批量 HTTP 探活**：

- 每任务 5 个目标 × 每 ISP 6 个节点（电信/联通/移动共 18 节点，池子 ~80/ISP，跨省等距采样）
- 通过 WebSocket 收集结果
- TCP 连通即判可达；节点返回 `http_code>0` 时另计**应用层确认**（`level=http`）。
  注意：TLS 端口（443 等）上 itdog 发明文 HTTP，CF 边缘会回 `400`——这同样
  证明完整数据往返、路径无 TCP 层干扰，故计入应用层确认（但不验证 TLS 内容）
- 限速：8 并发任务，0.5s 间隔
- 熔断：连续 8 次失败后停止

**单节点实测（并发）**：

- `check-host.cc`：呼和浩特阿里云节点，匿名限速 5/10s、250/h
- `xxapi.cn`：北京节点，免 key

**batch_tcping 补测（降级通道）**：

- batch_http 对某目标失败/被限时（captcha、风控、熔断），改用
  `itdog.cn/batch_tcping` 纯 TCPING 复测
- 节点池大得多（电信/联通/移动各 ~75-88 个，默认等距取 6×3=18 节点）
- 结果记为独立多节点源 `itdog_tcping`（`result>0` → 可达，`-1` → 失败），
  单独 ok 即可判 reachable

#### L3 多节点复核（串行小样本）

- `ping.pe`：约 13 个大陆节点，≥7/13 可达即判可达，报告不足 5 节点 → inconclusive
- `tcpping.cn`：多运营商，需 token，缺则跳过

已评估并放弃的补充源：`api.hostmonit.com/check_port`（已 404）、`ping.chinaz.com`
（表单 POST 仅返回渲染壳页，结果经混淆 JS 加载，反爬成本过高）。

### 5.2 合成判定逻辑（merge_verdict）

```
输入：sources = {check_host: {status, ok, ms, level}, xxapi: {...}, itdog: {...}, pingpe: {...}, ...}
      cf = True/False（是否 CF 边缘代理）

规则：
1. 多节点源（pingpe/itdog/itdog_tcping/tcpping）任一 ok → reachable
2. 单节点源（check_host/xxapi）≥2 个 ok → reachable
3. 仅 1 个单节点源 ok → uncertain（单点不可靠）
4. check_host + xxapi 均 fail → unreachable
5. pingpe fail + 任一单节点源 fail → unreachable
6. itdog fail + 任一其他源 fail → unreachable
7. 仅部分源 fail → uncertain
8. 全部 error/skip → skipped（不误判）
9. CF 启发式仅记录在 basis 中，不改变判定

证据分级 level：
- 任一成功源给出应用层（HTTP）确认 → "http"
- 有成功源但全部仅传输层（TCP）→ "tcp"
- 无成功源 → None
```

### 5.3 跨轮稳定性

写 `china.json` 前读取上一轮结果：

- **streak**：per-key 连续可达轮数（reachable 且上轮也 reachable 且
  观测间隔 ≤3h → 累加；否则清零/置 1）。`last_ok_ts` 记录最近可达时间，
  用于时间窗判定——即使 china.json 被并发提交短暂回滚，连续计数不丢
- **uncertain 优先复检**：上一轮 uncertain 的键在本轮采样中稳定排序置顶
  （limit 截断时优先覆盖）

### 5.4 输出

- `data/quality/china.json`：逐条明细，含各源 status/ms/level 与合成 verdict/basis/ms/level/streak
- `data/valid/all_cn.txt`：全量大陆可达清单（本次 reachable + 历史 -CN），按大陆实测延迟升序；
  应用层确认行追加 `-CNH` 备注
- `data/valid/all_cn_http.txt`：应用层确认子集（本轮 level=http 或历史已带 `-CNH`）
- `data/valid/all_cn_stable.txt`：跨轮稳定子集（连续 ≥2 轮 reachable，不含历史兜底）
- `data/valid/*.txt`：可达者追加 `-CN` 备注

## 6. 出口 IP 家族检测（exit_family.py）

### 6.1 检测方法

所有代理使用 **双栈出口探测** 方法：分别请求仅 IPv4（`ipv4.icanhazip.com`，仅 A 记录）与仅 IPv6（`ipv6.icanhazip.com`，仅 AAAA 记录）的回显服务——走得通即证明代理具备对应家族的**出口能力**，两者皆通判 `dual`。回显为纯 IP 文本；若两者均失败，尝试通用目标 `cloudflare.com/cdn-cgi/trace` 兜底。注意：入口 socket 家族（AF_INET/AF_INET6）无法反映出口家族——它只约束客户端→代理一跳；CF 边缘代理的出口由 Worker fetch() 决定、与入口和目标主机名均无关（对单族目标也返回同一出口 IP），故 CF 类代理 `dual` 恒为 0 属架构固有行为。

### 6.2 家族判定

| 结果 | 条件 |
|---|---|
| ipv4 | 仅 v4 回显成功 |
| ipv6 | 仅 v6 回显成功 |
| dual | v4 + v6 均成功 |
| unknown | 全部失败 |

### 6.3 交叉验证

对照 `data/quality/upstream_meta.json` 的真实出口 `clientIp`，在 `exit_family.json` 中补充 `upstream_match` 字段。

## 7. 后缀填充与分类（annotate_classify.py）

读取 7 个 JSON 数据源，向所有 `data/valid/*.txt` 文件填充缺失后缀并追加分类 token。

### 7.0 统一备注规范器（common.normalize_note）

所有工作流**禁止**直接 `line += "-TOK"` 拼接备注；必须经由
`normalize_note` / `merge_note_tokens`（追加）/ `clear_note_buckets`
（互斥桶先清后设）。规范段顺序：

```
入口CC[→出口CC] - 延迟ms - 速度MB/s - 流媒体(并集) - 类型 - CF标 - 速度档 - 家族 - CN/CNH - 信誉分
```

- 单值桶（类型/档位/家族/分数）取最右（最新）；多轮 CI 堆叠的历史快照自动收敛。
- `CF`（边缘标记）与出口类型正交：出现过即保留，不参与类型互斥。
- 流媒体为并集去重；`CNH` 蕴含 `CN`。
- 互斥桶由权威源"先清后设"：ipinfo 类型覆盖历史类型，exit_family 家族覆盖旧家族，
  重算的速度档替换旧档——避免 `-DC-…-RES` 新旧并存。

### 7.1 Token 追加顺序

1. 出口国家标记：`→CC`（有出口观测即标注，含同国）
2. 大陆可达：`-CN`
3. IP 家族：`-V4` / `-V6` / `-DS`
4. 信誉评分：`-<score>`（如 `-72`）
5. IP 类型：`-DC` / `-RES` / `-MOB` / `-PROXY`
6. 速度等级：`-fast`（≥5 MB/s）/ `-mid`（1-5 MB/s）/ `-slow`（<1 MB/s）
7. 滚动可用率：`-U<NN>`（uptime.json 的 pct7，如 `-U92`；无观测不加）
   （流媒体解锁 token 已停止生成——历史遗留 token 被规范器容忍）

### 7.1.1 `ms` 与 `MB/s` 的测量语义（按清单视图区分）

- **速度 `MB/s`** 一律来自海外测速：GitHub Actions runner（美区）经代理
  下载 `cdnjs.cloudflare.com` 固定样本（≤1MB、5s 超时、丢弃前 256KB
  warmup）。它反映"代理入口机 ↔ 其本地 CF PoP"的吞吐 + runner 侧瓶颈，
  **与大陆链路无关**；同国数值聚集是因为条目多来自同几家主机商的同规格
  端口，且 CDN 本地化使路径极短。绝对档位阈值全局统一，因此弱供给国家
  可能整国无 `fast`——请配合组内相对最优 `good_top.txt` 使用。
- **延迟 `ms`** 分两种视图：
  * CN 系清单（`all_cn*`、各国/各集合 `cn*.txt`）：行内 ms 已替换为
    **大陆实测 RTT**——优先取可信大陆探测源（xxapi 北京 / jkapi 宁波 /
    checkhost 呼市）的 ok 最小 RTT，无读数时在全部 ok 源中取 ≥2ms 的最小
    可信值再回退行内值，杜绝 L3 复核源 1ms 噪声冒充真实延迟（见
    `common.cn_display_ms`）。速度 token 同步改写为大陆视角估算
    `≈XMB/s`（海外实测与按大陆 RTT 推算的单流上限取小）；
  * 其他清单（`all.txt`、国家全量等）：ms 为海外 runner 的 TLS 握手延迟。
- CN 系清单**保持完整**：`all_cn*` 与 CN good-tier 收录当期全可达集
  （正常水平 ≥1 万），不按大陆延迟门槛精简；下落即有运行时自检
  （`check_cn_health`）保证行数 ≥1 万、无 ≤2ms 噪声、无缺 ms 行，不达标告警。
- 大陆**带宽**目前无法实测（第三方探测仅提供延迟/可达性），故不存在
  "CN 测速"；挑选高带宽节点请看海外 MB/s + `good_top`，选低延迟请看
  CN 清单的 ms 排序。

### 7.2 出口国家标记的三数据源

`→CC` 由统一构建器 `common.build_exit_cc_map` 多源汇聚（annotate_classify
与 reorg_country 共用），优先级从高到低：

1. `external_check.json` —— 外部探测接口直接回显的出口地理；
2. `upstream_meta.json` —— 自有 CF Worker 观测到的代理出口国。其键为
   裸出口 IP，经 `common.build_exit_ip_map`（external 回显 `exit_geo.ip`
   > exit_family 实测 `exit_v4`/`exit_v6`）解析到行键后命中；
3. `ipinfo.json` —— 出口 IP 的 ip-api 地理。历史轮次可能是入口 IP 的
   地理，仅作末位兜底。
   （原第 3 层 streaming 解锁国已随流媒体检查移除。）

已有 `→CC` 但与新观测不同视为陈旧出口（出口会漂移），直接替换。

### 7.2.1 入口/出口冲突处理

- **入口 CC**（行内 `#<emoji><CC>`）：订阅源自带标签，全链路不改写——
  它是溯源标识，也是全 pipeline 键的组成部分（`line_to_key` 含 `#CC`），
  改写会撕裂所有 quality JSON 的历史对应。准确性无保证，以出口实测为准。
- **出入口不一致**：入口标注保留原样，行内追加实测出口 `→OC`，
  `countries/` 下目录迁移到出口国；sets/ports 混国文件只标注不迁移。
- **多源出口观测互相冲突**：按上述优先级取高者。

### 7.3 行格式示例

```
1.2.3.4:443#🇺🇸US→US-120ms-0.44MB/s-GPT-CF-72-DC-fast-V4-CN
```

## 8. 并发与容错

### 8.1 阶段隔离

各阶段通过 CI workflow 顺序执行，互不干扰：

1. `update-proxies.yml`（每 2 小时，`0 */2 * * *`）→ download + validate
2. `quality-check.yml`（触发于 1）→ reputation + uptime + reorg
3. `china-check.yml` → 大陆连通性。双触发：quality 完成后 + **每小时独立
   心跳**（`11 * * * *`）。streak 依赖"连续多轮可达"，独立心跳保证上游
   失败或 IP 长期未变更时 stable 仍按小时累积
4. `exit-family.yml`（触发于 2）→ 出口家族
5. `annotate-classify.yml`（触发于 2）→ 后缀填充 + 分类

### 8.2 取消机制

- `update-proxies.yml`：`cancel-in-progress: true`（主更新优先）
- 其他下游 workflow：`cancel-in-progress: false`（保护已完成的检测结果）

### 8.3 门控逻辑

下游 workflow 仅做**竞态去重**：用 `gh run list` 查同工作流是否有更新的
in_progress/queued 运行，有则让位（旧运行自动跳过），防止积压排队。

刻意**不因触发者失败而跳过**：下游脚本从仓库 checkout 的自洽数据运行
（all.txt 与各 JSON 均为上次成功轮的完整快照），quality 单次失败不应
冻结 CN 连通性追踪与后缀应用——否则 IP 未变更期间 stable 永远无法累积、
信誉/家族等新数据也无法及时反映到清单后缀。
