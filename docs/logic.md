# 检测逻辑

本文档详细描述 IP 质量检测系统的核心算法与判定逻辑，供维护者理解代码实现。

## 1. 整体架构

```
download_proxies.py → validate_proxies.py → quality_check.py
                                             ├─ quality_streaming.py
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

## 3. 流媒体解锁检测（quality_streaming.py）

### 3.1 检测方法

对每个代理建立 TLS 直连（SNI=服务域名），发送 GET 请求，解析响应判断解锁状态：

| 服务 | 主机 | 路径 | 判定方法 |
|---|---|---|---|
| Netflix | `www.netflix.com` | `/title/80018499` | 响应中找 `countryCode` JSON 字段 |
| Disney+ | `www.disneyplus.com` | `/` | 响应中找 `countryCode`/`country`/`region` |
| YouTube Premium | `www.youtube.com` | `/premium` | 响应中找 `countryCode` JSON 字段 |
| Max (HBO) | `www.max.com` | `/` | 重定向 `country=` 或响应 `countryCode` |
| Prime Video | `www.primevideo.com` | `/` | 重定向 `country=` 或响应 `currentTerritory` |
| OpenAI | `chat.openai.com` | `/cdn-cgi/trace` | 解析 `loc=` 字段（同时用于出口地区标注） |

### 3.2 状态判定

- **ok**：响应中成功解析到区域码 → `{status: "ok", region: "US"}`
- **blocked**：403/404 或明确的区域限制消息 → `{status: "blocked"}`
- **error**：其他错误（超时、解析失败）→ `{status: "error"}`

### 3.3 Netflix 原生判定

当 Netflix 解锁区域与出口 IP 地理区域一致时，标记为 `native: true`（原生 IP），否则为 `native: false`（解锁 IP）。

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

#### 静态列表源（每 run 重拉）

| 源 | 权重 | 命中时分数 |
|---|---|---|
| ipsum | 8 | 55（命中 3+ 黑名单） |
| abuse_list | 5 | 60（历史滥用） |
| dc_asn | 5 | 85（机房/数据中心 ASN） |
| vpn_asn | 3 | 70（VPN 服务商 ASN） |
| resproxy_asn | 2 | 75（住宅代理骨干 ASN） |

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

- **streak**：per-key 连续可达轮数（reachable 且上轮也 reachable → 累加；否则清零/置 1）
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
4. 流媒体解锁：`-NF(US) -D+ -YT -MX -PV -GPT`
5. 信誉评分：`-<score>`（如 `-72`）
6. IP 类型：`-DC` / `-RES` / `-MOB` / `-PROXY`
7. 速度等级：`-fast`（≥5 MB/s）/ `-mid`（1-5 MB/s）/ `-slow`（<1 MB/s）

### 7.2 出口国家标记的四数据源

`→CC` 由统一构建器 `common.build_exit_cc_map` 多源汇聚（annotate_classify
与 reorg_country 共用），优先级从高到低：

1. `external_check.json` —— 外部探测接口直接回显的出口地理；
2. `upstream_meta.json` —— 自有 CF Worker 观测到的代理出口国。其键为
   裸出口 IP，经 `common.build_exit_ip_map`（external 回显 `exit_geo.ip`
   > exit_family 实测 `exit_v4`/`exit_v6`）解析到行键后命中；
3. `streaming.json` —— 经代理观测的服务解锁国；openai 为 CF trace
   `loc`（最接近真实出口），其余服务按序兜底。覆盖面最大（98%+）；
4. `ipinfo.json` —— 出口 IP 的 ip-api 地理。历史轮次可能是入口 IP 的
   地理，仅作末位兜底。

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
2. `quality-check.yml`（触发于 1）→ streaming + reputation + reorg
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
