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

- 每任务 5 个目标 × 每 ISP 3 个节点（电信/联通/移动共 9 节点，跨省等距采样）
- 通过 WebSocket 收集结果
- TCP 连通即判可达；节点返回 `http_code>0` 时另计**应用层确认**（`level=http`），
  仅 TCP 连通记为 `level=tcp`
- 限速：8 并发任务，0.5s 间隔
- 熔断：连续 8 次失败后停止

**单节点实测（并发）**：

- `check-host.cc`：呼和浩特阿里云节点，匿名限速 5/10s、250/h
- `xxapi.cn`：北京节点，免 key

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
1. 多节点源（pingpe/itdog/tcpping）任一 ok → reachable
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

所有代理使用 **双栈探测** 方法：分别以 `socket.AF_INET`（IPv4）和 `socket.AF_INET6`（IPv6）各发起一次 TLS + SNI → `cloudflare.com/cdn-cgi/trace`，取回显 `ip=` 判定出口家族。若两次均失败，尝试通用（不限地址族）连接兜底。

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

读取 5 个 JSON 数据源，向所有 `data/valid/*.txt` 文件填充缺失后缀并追加分类 token。

### 7.1 Token 追加顺序

1. 出口国家标记：`→CC`（出口 ≠ 列出国家时）
2. 大陆可达：`-CN`
3. IP 家族：`-V4` / `-V6` / `-DS`
4. 流媒体解锁：`-NF(US) -D+ -YT -MX -PV -GPT`
5. 信誉评分：`-<score>`（如 `-72`）
6. IP 类型：`-DC` / `-RES` / `-MOB` / `-PROXY`
7. 速度等级：`-fast`（≥5 MB/s）/ `-mid`（1-5 MB/s）/ `-slow`（<1 MB/s）

### 7.2 行格式示例

```
1.2.3.4:443#🇺🇸US→US-120ms-0.44MB/s-NF(US) D+ YT GPT-CF-72-V4-DC-fast
```

## 8. 并发与容错

### 8.1 阶段隔离

各阶段通过 CI workflow 顺序执行，互不干扰：

1. `update-proxies.yml`（每 30 分钟）→ download + validate
2. `quality-check.yml`（触发于 1）→ streaming + reputation + reorg
3. `china-check.yml`（触发于 2）→ 大陆连通性
4. `exit-family.yml`（触发于 2）→ 出口家族
5. `annotate-classify.yml`（触发于 2）→ 后缀填充 + 分类

### 8.2 取消机制

- `update-proxies.yml`：`cancel-in-progress: true`（主更新优先）
- 其他下游 workflow：`cancel-in-progress: false`（保护已完成的检测结果）

### 8.3 门控逻辑

下游 workflow 使用 `git merge-base --is-ancestor` 检查前次运行状态：

```bash
LAST_DOWNSTREAM=$(git log --oneline -1 --grep="<commit message>" --format=%H)
LAST_UPSTREAM=$(git log --oneline -1 --grep="proxyip" --format=%H)
if [ -n "$LAST_DOWNSTREAM" ] && git merge-base --is-ancestor "$LAST_DOWNSTREAM" "$LAST_UPSTREAM"; then
    echo "No new upstream data since last run, skipping"
    exit 0
fi
```

防止前次被取消/跳过时，后续 workflow 因文件无变化而误跳过。
