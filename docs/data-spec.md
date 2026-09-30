# 数据规范

本文件只描述**如何消费本仓数据**：行格式、备注段 token 语义、文件组织与排序、各 JSON
产物的字段含义。数据的采集与处理方式不在公开树内。

目录浏览入口（层级视图与工件索引）见 [`../data/README.md`](../data/README.md)。

## 行格式

- 未验证目录每行一条 `ip:port#国家代号`，例如 `1.2.3.4:443#US`
- `data/valid/` 每行一条 `ip:port#🇺🇸US-120ms-0.44MB/s`：`#` 后为 emoji 国旗 + 国家代号 +
  `-` + 延迟毫秒 + `-` + 速度（MB/s，两位小数）；测速失败时省略速度段
  （`ip:port#🇺🇸US-120ms`）
- **入口/出口地区**：已标注出口的行会在国家代号后插入 `→<出口>`
  （如 `1.2.3.4:443#🇺🇸US→US-120ms-0.44MB/s`）。出口地区为 2 位 ISO 国家码
  （`US`/`JP`/`DE`…）。入口未知的 `#ALL` 行同样标注出口
  （`1.2.3.4:443#ALL→US-120ms-0.44MB/s`），`ALL` 作为伪国家不会与阿尔巴尼亚 `AL` 混淆
- **质量检测备注**：被检测的行在既有后缀后追加若干 `-` 分隔的 token。完整示例：
  `1.2.3.4:443#🇺🇸US→US-120ms-0.44MB/s-RES-fast-V4-CN-29-U35`
- **去重**：同一 `ip:port` 组合在**同一国家标签内**唯一；同一入口可能被不同订阅标为多国
  出口（此时保留多国条目，池中存在少量跨标签重复属设计内）
- **排序**：
  - 未验证目录按 IP 数字序（八位组数值比较，`1.2.3.4 < 10.0.0.1`）
  - `data/valid/` 按延迟升序（`all_cn*.txt` 及其 http/stable 可靠性子集按**大陆实测延迟**
    升序；`all_cn4/6/46` 沿用全量池序）
  - `data/valid/*_ltd.txt`（及各目录 `ltd.txt`）按速度降序
  - `rep.txt` 按信誉分降序（同分按延迟升序）
  - `good.txt` 按综合分降序（同分按延迟升序再按 IP 序）

## 备注段（note）与 token 语义

`ip:port#<cc><note>` 中 `key = ip:port#<cc>`；`note` 为国家代号之后直至行尾的剩余部分
（含 `→<出口>`，因为 `→` 非 `A-Z`，国家码扫描会跳过它）。

token 是 note 中以**段首或 `-` 为界**的独立子串，即 `(?:^|-)TOKEN(?:$|-)`。因此
`-RES-fast-V4-CN-29-U35` 含 token `RES`、`fast`、`V4`、`CN`、`29`、`U35`。
token 分隔符统一为 `-`（空格不是维护态分隔符）。

| token | 含义 |
|---|---|
| `<N>ms` | 实测延迟（毫秒） |
| `<N.MB>/s` | 实测速度（MB/s，两位小数） |
| `≈<N>MB/s` | 大陆视角速度估算（CN 系清单内，语义见下） |
| `DC` / `RES` / `MOB` / `PROXY` | 出口类型：机房 / 住宅 / 移动 / 匿名 |
| `DS` / `V6` | 双栈 / 纯 IPv6 |
| `V4` | 出口为 IPv4-only |
| `fast` / `mid` / `slow` | 速度档 |
| `CN` | 大陆可达 |
| `CNH` | 大陆**应用层**确认（粘性标：反映最近一次应用层确认，非逐轮新鲜） |
| `<score>` | 信誉分 0-100（越大越干净），如 `-29` |
| `U<NN>` | 7 天滚动存活率百分比，如 `-U35` |

token 顺序：`<出口类型>` 后依次为速度档、家族、大陆标记、信誉分、`U<NN>`。
无结果的行保持原样。

**历史 token**：流媒体标记 `NF(区域)` / `D+` / `YT` / `MX` / `PV` / `GPT` 仍被解析器容忍，
但**已停止生成**；`CF` 曾作为死标记生成，现已归一化丢弃，新行不含该 token。
消费时建议忽略这些 token。

`CNH` 恒蕴含 `CN`：弱确认键的池行可能显示为 `-CN-CNH`，但不会进入仅含本轮确认行的清单。

### 信誉分口径（勿跨文件混用）

存在两个不同口径的信誉分：

- 行尾 `-<score>` 注解与 `data/quality/reputation.json` 的 `score`：**不含**地理信号的
  静态信号分
- `data/quality/ipinfo.json` 的 `reputation`：**含**地理信号的运行维度分

两数在启用外部评分服务时差距可能不止单个来源的权重，**不可跨文件混用**。

## 国家集合

| 集合 | 覆盖国家/地区 | 用途 |
|---|---|---|
| `europe` | AL AT BE BG BY CH CY CZ DE DK EE ES FI FR GB GR HR HU IE IS IT LT LV MD MK NL NO PL PT RO RS RU SE SI SK UA（36） | 欧洲全域 |
| `asia` | AE AM AZ BH CN GE HK ID IL IN JP KG KH KR KZ MO MY OM PH SA SG TH TR TW UZ VN（26） | 亚洲全域 |
| `north_america` | CA MX US VG（4） | 北美 |
| `south_america` | AR BR CL CO EC（5） | 南美 |
| `oceania` | AU NZ（2） | 大洋洲 |
| `africa` | EG NA NG ZA（4） | 非洲 |
| `middle_east` | AE BH IL OM SA TR（6） | 中东 |
| `hot` | AU CA DE FR GB HK JP KR NL SG TW US RU（13） | 热门线路 |
| `cn_common` | HK TW SG JP KR US DE GB FR NL RU CA AU（13） | 中国大陆常用 |
| `hk_us_jp_sg_tw_kr` | HK US SG TW JP KR（6） | 港美日新台韩 |

## 限量版 `_ltd`

`*_ltd.txt` 是同目录 `all.txt` 的**限量版**，每国最多 20 条：按实测下载速度取最快
（速度并列或无速度时按延迟兜底），集合内与全量池按速度降序。
未验证目录侧的 `all_ltd.txt` 同理按 IP 序取每国前 20 条，`#ALL` 条目单独取前 20 条。

## 输出文件布局

- `data/valid/all.txt`、`all_ltd.txt`：全量存活池，格式
  `ip:port#🇺🇸US-120ms-0.44MB/s`；`all.txt` 按延迟升序，`all_ltd.txt` 按速度降序。
  `#ALL` 条目（入口未知）只出现在这两个文件，不进入 `countries/`
- `data/valid/countries/<国家>/`、`data/valid/sets/<集合>/`：按**出口国**分组（行内
  `#<入口>` 不参与目录归属）与按集合分组的存活列表，每目录含
  - `all.txt`（全量，延迟升序）、`ltd.txt`（限量，速度降序）
  - `rep.txt`（信誉排序）、`good.txt`（综合最优）
  - `ports/` 为按端口分组的平铺存活列表
  - 家族 × 大陆可达派生的清单（各带 `*_ltd.txt` 限量版，规则同 `ltd.txt`）：
    `v4.txt`（出口 IPv4-only）、`v6.txt`（IPv6-only）、`46.txt`（双栈 v4+v6）、
    `cn.txt`（大陆可达）、`cn4.txt`/`cn6.txt`/`cn46.txt`（大陆可达 × 对应家族）
  - **可靠性变体**：上述家族×大陆分组清单同步派生 `*_verified.txt` 与 `*_stable.txt`
    （如 `countries/US/cn4_verified.txt`）。其余根级清单（`all_cn`、
    `all_ipv4`/`all_ipv6`）无此直接变体
- 根级另有 `all_46.txt` / `all_cn4.txt` / `all_cn6.txt` / `all_cn46.txt`（及 `*_ltd.txt`）；
  v4/v6 复用既有 `all_ipv4.txt` / `all_ipv6.txt`

**空清单不落盘**（并清理上轮残留），故某文件不存在即表示该分组本轮为空。

### 可靠性变体语义

- `*_verified` — **全链路验证**子集：本轮测速成功（TLS 握手 + HTTP 2xx + 真实下载全部
  通过），过滤"能握手但不吐数据"的半死代理
- `*_stable` — **连续两轮存活**交集：上一轮索引与本轮存活的交集，对抗代理池快速 churn；
  首轮无上一轮数据时不生成

**CN 系清单（`cn*` / `all_cn*`）的行内 ms 为大陆实测 RTT、速度为 `≈XMB/s` 大陆估算**，
与 `all_cn.txt` 口径一致：优先取最快运营商视角（各运营商最小 RTT 的全局最小）。

## 数据文件参考

### `data/output/stats.json`

统计汇总（供徽章与外部消费）：

| 字段 | 含义 |
|---|---|
| `ts` | 生成时间 |
| `updated_at` | 数据最后更新时间 |
| `unique` / `total` | 去重代理数 / 上游原始条目数 |
| `countries` / `ports` | 国家数 / 端口数 |
| `sets` | 各集合条数 |
| `alive` / `alive_checked` / `alive_rate` | 存活数 / 检测数 / 存活率 |
| `alive_countries` / `alive_sets` | 存活国家数 / 存活集合条数 |
| `latency` | 延迟统计（`avg_ms`/`median_ms`/`p90_ms`/`max_ms`，毫秒） |
| `latency_dist` | 延迟分桶直方图（如 `0-100`、`1000+`，毫秒） |
| `speed` | 测速统计（`avg_mbps`/`median_mbps`/`p90_mbps`/`max_mbps`，MB/s） |
| `speed_dist` | 速度分桶直方图（如 `0-0.5`、`5+`，MB/s） |
| `ip_type` / `family` / `dual_stack` / `country_mismatch` | 出口 IP 类型分布 / 地址族分布 / 双栈数 / 错区数 |
| `age_s` / `updated_ago` / `stale` | 数据年龄（秒）/ 可读年龄（如 `4h ago`）/ 是否过期（超过 3h） |
| `history_records` / `alive_history_records` | 历史记录条数 |
| `cn_reachable` / `cn_http` / `cn_stable` / `cn_served` / `cn_ts` | CN 池规模：`reachable` = 当前判定可达数（真相；且须同时存在于当前 `data/valid/all.txt` 池，已淘汰节点不计数）；`http`/`stable`/`served` = 实际落盘 `all_cn_http.txt`/`all_cn_stable.txt`/`all_cn.txt` 行数（空组不落盘、波动后旧子集短暂残留属设计，消费此口径所见即所得）；`ts` = 生成时间 |

### `data/output/badge.json`

Status 徽章端点数据（shields.io `endpoint` 格式，供 README 徽章与外部 `![](…badge.json)`
消费）：

| 字段 | 含义 |
|---|---|
| `schemaVersion` | 恒为 `1` |
| `label` | 恒为 `status` |
| `message` | `fresh`（数据未过期）或 `stale`（年龄超过 3 小时） |
| `color` | 对应 `brightgreen` / `red` |

### `data/output/country_speed.json`

按国家（ISO2 代码）的出口测速分布。键为 `cc`，值为：

| 字段 | 含义 |
|---|---|
| `n` | 该国参与测速的代理数 |
| `p25` / `p50` / `p75` | 速度分位数（MB/s） |
| `max` | 该国测速最大值（MB/s） |
| `spread_pct` | 国内容量差异度：`round((p75-p25)/p50×100)`，取整 |

示例：`"US": {"max": 47.64, "n": 2000, "p25": 3.43, "p50": 3.94, "p75": 6.2, "spread_pct": 70}`

### `data/quality/cn_history.jsonl`

CN 分运营商趋势，每行一快照 `{ts, cn_reachable, cn_by_isp}`；`cn_by_isp` 为
`{运营商: {sampled, reachable, min_ms, median_ms}}`（无读数时为 `{}`）。保留最近 8 天。

### `data/valid/meta.json`

| 字段 | 含义 |
|---|---|
| `total` / `checked` / `alive` / `dead` | 总条目 / 实际检测数（含重试）/ 存活 / 失效 |
| `elapsed_s` / `checked_per_s` | 耗时（秒）/ 吞吐（条/秒） |
| `by_method` | 各判定方法的存活数 |
| `latency` | 延迟统计（`avg_ms`/`median_ms`/`p90_ms`/`max_ms`） |
| `latency_dist` | 延迟分桶直方图（毫秒） |
| `speed` | 测速统计（`avg_mbps`/`median_mbps`/`p90_mbps`/`max_mbps`） |
| `speed_dist` | 速度分桶直方图（MB/s） |
| `per_country` / `per_port` | 各国 / 各端口存活数 |
| `prefiltered` | 进入完整检测的条目数 |
| `sets` | 各集合存活条数 |
| `ext_check` | 外部 API 检测汇总（启用多源验证时出现）：`ext_check_total`/`ext_check_ok`/`ext_check_uncertain`/`ext_check_dead`/`ext_avg_response_ms` |

### `data/valid/index.json`

单行 JSON，键为 `ip:port#国家`，值为 `[延迟ms, 检测方法]`，按延迟升序：

```json
{"proxies": {"1.2.3.4:443#US": [640.1, "tls"], "5.6.7.8:8443#JP": [80.1, "tls"]}}
```

### `data/valid/speed.json`

单行 JSON，键为 `ip:port#国家`，值为实测速度（MB/s，两位小数），按速度降序
（仅含测速成功的代理）：

```json
{"proxies": {"5.6.7.8:8443#JP": 1.25, "1.2.3.4:443#US": 0.44}}
```

数据未变化时文件不变（避免无意义提交）。运行时间见 `meta.json` 的 `ts`。

### `data/valid/ext_check.json`

外部 API 多源验证逐条结果（仅启用时生成），单行 JSON，键为 `ip:port#国家`：

```json
{
  "sources": ["<源1>", "<源2>"],
  "alive": true,
  "response_ms": 120.5,
  "colo": "LAX",
  "ipv4_ok": true,
  "ipv6_ok": false,
  "dual_stack": false,
  "inferred_stack": "ipv4",
  "exit_geo": {"countryCode": "US", "city": "Los Angeles", "asn": 13335, "org": "Example Networks"}
}
```

| 字段 | 含义 |
|---|---|
| `sources` | 确认存活的源数量（共识需 ≥2 个） |
| `alive` | 共识结果：`true`/`"uncertain"`（仅 1 源确认）/`false` |
| `response_ms` | 最快响应时间（毫秒） |
| `colo` | 边缘机房 IATA（仅部分源回报） |
| `ipv4_ok` / `ipv6_ok` | IPv4/IPv6 出口可达 |
| `dual_stack` | 双栈出口 |
| `inferred_stack` | 推断出口栈类型：`ipv4`/`ipv6`/`dual` |
| `exit_geo` | 出口地理信息（`countryCode`、`city`、`asn`、`org`） |

数据未变化时文件不变。

### `data/quality/external_check.json`

外部出口地理回显探测结果（**单一来源**）：顶层 `proxies` 键为 `ip:port#国家`，值为
`{success, response_ms, colo, ipv4_ok, ipv6_ok, exit_geo}`。与
`data/valid/ext_check.json` 不同：本文件**不写** `sources`/`dual_stack`
（双栈权威在 `exit_family.json`）。

### `data/quality/ipinfo.json`

单行 JSON，顶层 `proxies` 键为 `ip:port#国家`，值为出口 IP 信息：

`exit_ip`、`country`/`country_code`/`region`/`city`（出口地理）、`asn`/`org`/`isp`、
`proxy`/`hosting`/`mobile` 标志、`ip_type`（DC/RES/MOB/PROXY）、`listed_country` 与
`country_match`（是否错区）、`geo_checked`（是否查到出口地理）、
`reputation`（0-100 运行维度分，口径见上）、`rep_flags`（共识确定的语义维度：
proxy/vpn/tor/hosting/mobile/abuse/listed/scraper/crawler/anonymous）、
`reputation_source`（取值真相源在私有注册表，公开树只存不透明 id；多源时为 `multi`）、
`risk`（由信誉分推导）。

注：地址族（`family`）与双栈（`dual_stack`）信息在 `exit_family.json` 中，不在本文件。

### `data/quality/exit_family.json`

出口家族探测结果。顶层 `ts` + `proxies`：每个 `ip:port#国家` 的值为
`{method, ts, family(ipv4/ipv6/dual/unknown), evidence, v4_src/v6_src, exit_v4/exit_v6,
shared_exit, upstream_client_ip, upstream_family, upstream_absent, upstream_match}`。

**部分字段按需填充**：`upstream_*` 只在有 v6 出口探测结果时出现，`shared_exit` 在
ipv4/unknown/dual 有值；缺字段视为无上游数据。探测字段之外（line/ip/port/cc 等可推导项）
刻意不落盘。`family` 是分组/清单的**权威来源**（优先于行内 `-V4`/`-V6`/`-DS` 备注）。

### `data/quality/node_seen.json` 与 `data/quality/uptime.json`

`node_seen.json`：`{runs: {<YYYY-MM-DD>: 轮次计数}, proxies: {<key>: [出现日期…]}}`
——滚动 45 天窗口的按轮存活记录。

`uptime.json`：`{proxies: {<key>: {pct7, pct30, hits7, hits30, last_seen}}, runs7, runs30, ts}`。
pct 为窗口内存现天数 ÷ **窗口内实际有质量轮的日期数**（去重，同日多轮算 1 天）的百分比
——存现与分母同按日粒度，每个运行日都在场即 100%，缺一天按比例扣分。

### `data/valid/all.json`

结构化代理池导出，数组元素：
`{line, key, ip, port, flag, cc, exit, latency_ms, speed_mbps, family(V4|V6|DS|null), cn(bool), type, tier, rep, uptime7}`。

`cn` 为该行 note 中存在 `CN`/`CN4`/`CN6`/`CN46`/`CNH` 任一 token 即 true；
`exit` 为 `→CC` 后的实测出口 CC（无 `→` 时为 `null`）；
`latency_ms`/`speed_mbps` 只取 note 中首个 `Nms`/`N.MB/s` token——
`≈XMB/s` 大陆估算 token 因 `≈` 前缀无法经 `float()` 解析，`speed_mbps` 记 `null`。

### `data/valid/all_diverse.txt`

出口多样性视图：按实测出口 IP（缺省回退入口 /24 网段）分组，每组仅保留综合分最高一条，
全表按分数降序。

### `data/quality/quality_meta.json`

质量检测汇总：`ts`（ISO-8601）、`total`（代理总数）、`tls`（参与本轮质量检测的键数）、
`by_type`（IP 类型分布）、`ext_check_total`/`ext_check_ok`、`country_mismatch`（错区数）、
`risk`、`abuse_checked`、`reputation_checked`（获分条数）、`rep_dist`（0-25/25-50/50-75/75-100
分桶）、`rep_avg`/`rep_median`、`skipped`（本轮因时间预算耗尽而未执行的相位名列表；
空列表=完整批次，供下游识别降级批）。

### `data/quality/abuse.json`

滥用分与标志（启用该服务时输出），键为 `ip:port#国家`，值为 `{service, score, risk, ...}`。

### `data/quality/entry_audit.json`

入口国家标签审计：顶层 `generated_at`/`total`/`summary`（verdict 计数），`proxies` 键为
`ip:port#国家`，值为 `{listed, exit_cc, entry_ip, entry_geo, verdict, asn}`：
`listed` 为订阅行内 `#CC` 标签，`exit_cc` 为汇聚后的出口国（无观测时 `None`），
`entry_ip` 为入口 IP（域名入口时为 `null`），`entry_geo`/`asn` 为实测出口信息，
`verdict` 取值 `ok`/`ok_with_drift`/`tag_mismatch`/`cf_fronted`/`domain_entry`/`entry_unknown`。
只读不改行、不参与门控。

### `data/quality/entry_geo.json`

入口地理缓存：顶层 `updated_at`（ISO-8601）与 `ips`（`{ip: {cc, asn}}`）。`ips` 仅保留
当前批存在的入口，过期 IP 随批次自然淘汰。

### `data/quality/premium_meta.json`

`{ts, file_count, proxy_count}`——生成时间与落盘的 `premium*.txt` 文件数/总行数
（空清单时 `proxy_count=0`）。

### `data/quality/reputation.json`

单行 JSON，顶层 `proxies` 键为 `ip:port#国家`，值为
`{score, risk, source, sources, flags, numeric[, deep_bonus]}`：`score` 为 0-100 信誉分
（越大越干净），`risk` 为 `high`（<30）/`medium`（<75）/`low`（≥75），
`source` 取值真相源在私有注册表（公开树只存不透明 id；多源时为 `multi`）、
`sources` 为实际参与合分的源列表，`flags` 为共识确定的语义维度列表，
`numeric` 为参与连续型罚分的源列表，`deep_bonus` 为有深测带宽加成时的 +0~10 值（无则缺省）。
按分数降序、同分按键序排列。

### `data/quality/reputation_cache.json`

单行 JSON，顶层 `proxies` 键为**出口 IP**，值为 `{<source>: {"ts": …, "data": …}}`
——每个源独立记录最近一次查询的 epoch 秒时间戳与原始信号（逐源独立 TTL，默认 7 天）。
过期条目不删除：每轮尝试刷新，失败则回退最近一次缓存信号，直至被新条目挤出缓存上限
（表按每个 IP 最近信号时间封顶 4 万条，超限裁剪最旧）。

### `data/valid/all_rep.txt`

全量存活池的**信誉排行**：按信誉分降序（同分按延迟升序再按 IP 序），无分数条目排在末尾
保持原序；每行携带完整备注。每国/每集合目录下的 `rep.txt` 用同样排序规则。

### `data/valid/all_good.txt` 及各目录 `good.txt`

**综合最优清单**：从对应池（根级 / 各国家、集合目录 `all.txt`）中筛选同时满足：

1. 大陆可达（当轮判定 `reachable`）
2. 信誉分 ≥ 80
3. 非高风险（`risk != high`）

每个来源池都派生全套变体：`_verified`、`_stable`、`_uptime`、`_top`（组内前 25% 分位）、
`_fast`/`_mid`/`_slow`（行备注速度档）——全池与 `_ltd` 限量池一视同仁；
家族维度另出 `good_{g}` / `good_{g}_ltd`。

按综合分降序（乘积，越大越好）。缺大陆实测 RTT 或该出口国无有效基准 ⇒ 整行剔除；
缺速度读数只令速度因子为 0。同分依次按大陆延迟升序、IP 序。

**每一份 `good` 清单都是仅含大陆可达行的 CN 列表，因此全部输出统一渲染 CN 视图**：
行内 ms 为大陆实测 RTT、速度 token 改写为 `≈XMB/s`；无大陆 RTT 数据时行保持原样。

### `data/valid/all_premium.txt` 及各目录 `premium.txt`

**高端优质清单**（比 `good` 更严格）：

1. 大陆可达（同 `good` 规则）
2. 信誉分 ≥ 95
3. 真实住宅 IP（`ip_type == "RES"` **且** `geo_checked == true`——查不到出口地理时不得
   当作实测住宅）
4. 非高风险

综合分与 `good` **不同**：加权和 `round(0.6×信誉分 + 0.2×延迟分 + 0.2×速度分)`（信誉为主），
按综合分降序。同样统一渲染 CN 视图。同步派生 `_verified.txt`/`_stable.txt`/`_uptime.txt`
可靠性变体与 `_<tier>.txt` 速度档变体；另按出口家族派生 `*_v4.txt`/`*_v6.txt`/`*_46.txt`
分支。

### `data/quality/china.json`

顶层含 `ts`（本轮检测完成时间），`proxies` 为逐条检测明细，键为 `ip:port#国家`，值为：

| 字段 | 含义 |
|---|---|
| `ip` / `port` / `cc` | 基本标识 |
| `verdict` | `reachable` / `unreachable` / `uncertain` / `skipped` |
| `basis` | 判据源代号（取值域为私有注册表枚举的运行时代号） |
| `ms` | 可达延迟（大陆实测 RTT） |
| `level` | 证据分级：任一成功源给出应用层 HTTP 确认 → `http`；仅传输层 TCP → `tcp`；无成功源 → `null` |
| `streak` | 连续可达轮数（跨轮累计） |
| `sources` | 各源原始结果；批量源含 `level` |
| `ts` | 检测时间 |
| `fallback` | 上一轮可达、本轮未获确认而经历史兜底并入的键置位 |
| `flip` | 本轮起连续翻转计数（稳定子集准入排除慢性抖动） |
| `cn_mainland` | 大陆视角 RTT 是否低于门槛 |
| `isp_ms` | 各运营商最小 RTT 汇聚，`{运营商: ms}`，取值域为 `中国电信`/`中国联通`/`中国移动`/`中国多线` 四类；取 fastest-isp 时即最快运营商视角。无读数则不写该字段 |

**`isp_ms` 只增不改**：新增运营商表现为新增键，不得改动或移除既有键。

非 `reachable` 键无 `ms`/`isp_ms` 字段属预期——`ms` 缺失仅出现在未确认可达的行，
可达清单才保证逐行有 ms。

### `data/valid/all_cn.txt`

**全量大陆可达清单**：从全量存活池中筛出本轮判 `reachable` 的行，统一追加 `-CN` 备注
（应用层确认行再追加 `-CNH`）；按**大陆实测延迟升序**（缺失垫底、同值稳定）。
清单保持完整（正常水平 ≥1 万），不按大陆延迟门槛精简。

每行的 ms 为大陆视角读数（最快运营商视角优先，即各运营商最小 RTT 的全局最小），
速度 token 同步改写为 `≈XMB/s` 大陆视角估算。落地自带健康自检（行数 ≥1 万、
无 ≤2ms 噪声、无缺 ms 行）。

### `data/valid/all_cn_http.txt` / `data/valid/all_cn_stable.txt`

两个可靠性子集（均按大陆实测延迟升序）：

- `all_cn_http.txt` — **应用层确认**子集：本轮任一成功源给出 HTTP 级确认
  （`level=http`）或历史已带 `-CNH` 的行。TCP 通但应用层被干扰的代理不会进入此清单
- `all_cn_stable.txt` — **跨轮稳定**子集：连续 ≥2 轮判 `reachable` 的行（strict，
  不含历史 `-CN` 兜底），对抗单轮误判与快速 churn

**推荐消费顺序**：`all_cn_stable.txt` > `all_cn_http.txt` > `all_cn.txt`。

### `data/valid/all_46.txt` / `all_cn4.txt` / `all_cn6.txt` / `all_cn46.txt`

根级分组文件：`all_46.txt` 为全部出口双栈（v4+v6）代理，
`all_cn4.txt`/`all_cn6.txt`/`all_cn46.txt` 为大陆可达 × 对应家族；顺序沿用全量池
（延迟升序）。家族判定优先 `exit_family.json`，无记录回退行内 `-V4`/`-V6`/`-DS`，
记录 `unknown` 不回落。对应 `all_*_ltd.txt` 为按每国限量的速度降序版。

### `data/quality/history.jsonl`（每行一条）

`ts`、`total`、`unique`、`countries`、`ports`、`sets`、`added`、`removed`。
数据未变化时跳过，最多保留最近 1000 条。

### `data/valid/history.jsonl`（每行一条）

`ts`、`total`、`checked`、`alive`、`dead`。与上一条完全相同则跳过，最多 1000 条。

### `data/quality/source_history.json`

每次更新**追加**一轮各来源的 `unique` 数快照：
`{"runs": [{"ts": <ISO-8601>, "counts": {<来源标识>: 去重数}}]}`，保留最近 14 轮。
来源标识口径同 `ip_sources.json`（内置补充源为不透明公开 id）。

### `data/quality/upstream_meta.json`

上游导出的逐 IP 元数据（keyed by 代理 IP）。每个值含 `clientIp`（该代理的真实出口 IP）、
`family`（由 `clientIp` 派生，ipv4/ipv6）、`asn`、`asOrganization`、`country`、`city`、
`region`、`continent`、`colo_iata`。

### `data/quality/ip_sources.json`

逐 IP 下载源归属。键为 `ip:port#CC`，值为**来源标识**：

- `"main"`（主源）、`"multi"`（多来源重叠）、`"unknown"`、`mirror-*/all`（通用清单名消歧）
  ——这些是**语义哨兵**，可读
- 内置补充来源一律记为其**不透明公开 id**（`dsrc_` + 12 位十六进制）。id 与来源标签无可逆
  关系，公开侧与本文档均不出现来源真名。同站多文件只记一个 id，故一个 id 可对应多个抓取地址

来源 id 全集**不在本文档逐条列举**（会与私有清单二次漂移）。

### `data/quality/source_quality.json`

各来源质量指标。顶层含 `ts`、`total_proxies`、`total_alive`、`sources`（逐源指标）。
每个源含：`total`/`alive`/`survival_rate`、`avg_latency`/`median_latency`、
`avg_speed`/`median_speed`、`avg_reputation`、`reputation_dist`、
`china_reachable_count`/`china_reachable_rate`（= 大陆可达数 ÷ 该源**存活数**，
反映存活代理的大陆可用占比）、`family_dist`、`country_dist`/`port_dist`。

### `data/quality/deep_speed.json`

深测结果。顶层含 `generated`（`YYYY-MM-DDTHH:MM:SSZ` 生成时间，超 10 天过期）、
`proxies`（逐键明细）与 `meta`（参数快照）三个平级键。
`proxies[key]` 结构为 `{tls_ms: <TLS 建连耗时 ms>, <target>: {"agg_mbps": <该目标多流总吞吐
MB/s>, "streams_ok": <成功流数>, "streams_total": <并发流总数>, "samples": [<逐流 MB/s 或
null>]}, …}`——`tls_ms` 与各 target 平级置于顶层（最先测得）。

### `data/diff/`

- `data/diff/latest.json`：最近一次 `added`/`removed` 列表
- `data/diff/<时间戳>.json`：有变化时按次归档，最多保留最近 50 份
- `data/quality/history.jsonl`：每条记录含 `added`/`removed` 计数

`data/diff/` 每次更新写在工作树，但**刻意不进版本库**；它只留存于 CI/本地磁盘供审计。

## 消费防御约定

所有 `data/quality/` 与 `data/valid/` 下的 JSON 一律按**「解析失败或缺文件返回空对象」**
的约定读取，且**合法非对象顶层**（数组/字符串/数字/布尔/null）也被规范化为空对象——
一处防御覆盖全部 `.get("proxies", {}).items()` 消费点，避免 `None.get`/`str.get` 崩溃。
消费侧另加 entry 级 `isinstance(entry, dict)` 守卫，形成顶层 + 条目双层防御。
