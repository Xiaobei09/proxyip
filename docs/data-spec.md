# 数据规范

本文件只描述**如何消费本仓数据**：行格式、备注段 token 语义、文件组织与排序、各 JSON
产物的字段含义。数据的采集与处理方式不在公开树内。

目录浏览入口（层级视图与工件索引）见 [`../data/README.md`](../data/README.md)。

## 行格式

- 未验证目录每行一条 `ip:port#国家代号`，例如 `1.2.3.4:443#US`
- `data/valid/` 每行一条 `ip:port#🇺🇸US←HK-多线-120ms-0.44MB/s`：`#` 后为 emoji 国旗 + **出口**国家代号 +
  箭头 `←` 后为**入口**国家代号 + 可选运营商短名段 + `-` + 延迟毫秒 + `-` + 速度（MB/s，两位小数）；
  测速失败时省略速度段（`ip:port#🇺🇸US←HK-120ms`）。**行首国家码恒为出口、`←` 后恒为入口标签**。
- **入口/出口地区（R1746 方案 B：出口优先）**：已标注出口的行把出口国旗+出口 ISO 写在 `#` 后**首位**
  （如 `1.2.3.4:443#🇺🇸US←HK-120ms-0.44MB/s`），箭头 `←` 后写**入口标签**。首个国家码是**出口**
  （目录分组与导出 `exit` 字段依据），箭头后为**入口标签**（去重键 `key` 依据；出口漂移不重键质量 JSON）。
  出口地区为 2 位 ISO 国家码（`US`/`JP`/`DE`…）。入口未知的 `#ALL` 行写 `#<出口>←ALL`
  （`ALL` 作为伪国家不会与阿尔巴尼亚 `AL` 混淆），**无出口观测的行不写箭头**——此时
  首个国家码是**入口标签**（非出口），导出 `exit` 字段为 `null`；「无箭头」表示**出口未观测**，
  **不等价于「出口 == 入口」**（出口==入口的真观测会写成 `#XX←XX`）。存量旧箭头 `→`（读取端长期兼容）
  与旧式「入口在前」行由一次性迁移脚本迁移为出口优先。
- **运营商段（R1746 方案 B）**：中国可达的行在入口 ISO 后写独立运营商短名段
  （`电信`/`联通`/`移动`/`多线`，取该 key `china.json.isp_ms` 最小 RTT 经 `CN_ISP_SHORT` 归一）；非 CN
  可达则省略。旧式末尾 `-<运营商>=<ms>ms` 复合 token 已废弃并删除。海外实测速度保持裸值，`≈XMB/s`
  仅表示大陆视角估算。
- **质量检测备注**：被检测的行在既有后缀后追加若干 `-` 分隔的 token。完整示例：
  `1.2.3.4:443#🇺🇸US←HK-多线-120ms-0.44MB/s-RES-fast-V4-CN-29-U35`
- **去重**：同一 `ip:port` 组合在**同一国家标签内**唯一；同一入口可能被不同订阅标为多国
  出口（此时保留多国条目，池中存在少量跨标签重复属设计内）
- **排序**：
  - 未验证目录按 IP 数字序（八位组数值比较，`1.2.3.4 < 10.0.0.1`）
  - `data/valid/` 按延迟升序（`all_cn*.txt` 及其 http/stable 可靠性子集按**大陆实测延迟**
    升序；`all_cn4/6/46` 沿用全量池序）
  - `data/valid/*_ltd.txt`（及各目录 `ltd.txt`）按速度降序
  - `rep.txt` 按信誉分降序（同分按延迟升序）
  - `good.txt` 按应用层确认优先、再综合分降序（同层同分按延迟升序再按 IP 序）

## 备注段（note）与 token 语义

`ip:port#<出口><←入口标签><note>` 中 `key = ip:port#<入口标签>`（有箭头时取箭头后的国家码，无箭头时取首个国家码）；
`note` 为**标签国家码之后**直至行尾的剩余部分（含运营商段与延迟/速度 token，如
`1.2.3.4:443#🇺🇸US←HK-多线-120ms-RES-fast-V4-CN-29-U35` 的 note 为 `-多线-120ms-RES-fast-V4-CN-29-U35`）。
首个国家码（出口）不进入 key，故出口漂移不重键质量 JSON。

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

`CN`/`CNH` 是**键级（`ip:port#入口`）全局可达标记**，同一键在任意清单里
取值一致：可达即带 `CN`，应用层确认即再带 `CNH`（`CNH` 恒蕴含 `CN`）。该标记
由每轮可达检测刷新，并强制同步到全部视图（`all*`、`countries/*`、`sets/*` 及其
家族/good 变体），故消费方无需担心某清单落后一轮而出现「CN 视图速度 `≈` 却无
`CN`」的矛盾。

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

`*_ltd.txt` 是同目录 `all.txt` 的**限量版**，每国最多 10 条（下游小时级出口重观测可使个别国家短暂略超，下次验证回归）：按实测下载速度取最快
（速度并列或无速度时按延迟兜底），集合内与全量池按速度降序。
未验证目录侧的 `all_ltd.txt` 同理按 IP 序取每国前 10 条，`#ALL` 条目单独取前 10 条。

## 输出文件布局

- `data/valid/all.txt`、`all_ltd.txt`：全量存活池，格式
  `ip:port#🇺🇸US←HK-120ms-0.44MB/s`（行首=出口、`←` 后=入口标签）；`all.txt` 按延迟升序，`all_ltd.txt` 按速度降序。
  入口未知的行（`←ALL`）只出现在这两个文件，不进入 `countries/`
- `data/valid/countries/<国家>/`、`data/valid/sets/<集合>/`：按**国家目录**与**集合**
  分组的存活列表。国家目录按**出口国**（行首**首个国家码**；`←` 后的入口标签不参与
  **国家目录**归属）归属；集合目录成员按**入口标签且出口**同属集合（入口取 `←` 后
  国家码、出口取行首国家码，R313 用户裁决「set 内部不应出现他国出口」）归属，每目录含
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

CN 系清单（`cn*`/`all_cn*`）的**成员**只含当轮判定大陆可达的键：一旦某键被显式判为
非可达（`unreachable`/`uncertain`），即从全部 CN 系清单剔除（每小时可达刷新后即生效，
无需等 2h 全量重建）；无判定记录（未采样）的键不因此剔除。唯一例外是
`all_cn_http.txt`——它是应用层确认视图，对可达性**故意粘滞**（历史 HTTP 确认不因一次
失败重测而清除）。

### 可靠性变体语义

- `*_verified` — **全链路验证**子集：本轮测速成功（TLS 握手 + HTTP 2xx + 真实下载全部
  通过），过滤"能握手但不吐数据"的半死代理
- `*_stable` — **连续两轮存活**交集：上一轮索引与本轮存活的交集，对抗代理池快速 churn；
  首轮无上一轮数据时不生成

**CN 系清单（`cn*` / `all_cn*`）的行内 ms 为大陆实测 RTT、速度为 `≈XMB/s` 大陆估算**，
与 `all_cn.txt` 口径一致：优先取最快运营商视角（各运营商最小 RTT 的全局最小）。
ms 另过**出口地理下限**——大陆出发到某出口国的 RTT 物理上不可能低于该地区下限
（境内 1ms / 港澳 5ms / 台 8ms / 日韩 12ms / 东南亚 25ms / 其他 40ms），低于者视为
噪声或共址假象剔除，杜绝 `US-15ms` 式失真行（用户 2026-10-10「部分国内延迟过低」）。

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
| `cn_by_isp` / `cn_by_isp_oldest_age_h` | **分运营商** CN 可达/延迟：键为运营商短名（`电信`/`联通`/`移动`/`多线`），值为 `{sampled, reachable, min_ms, median_ms}`（与分运营商图**同一**计算：池限、逐运营商读数读侧按 **24h 账龄剔除**、延迟过噪声带与出口地理范围门）；`_oldest_age_h` = 参与读数的**最旧**条目年龄（小时，无则 `null`）。无 per-ISP 读数时 `cn_by_isp` 为空对象 |
| `cn_isp_pool` / `cn_isp_coverage` | 分运营商 **24h 覆盖率仪表**（用户「目标 24h 内 4 运营商全覆盖」）：`cn_isp_pool` = 当前存活池键数（分母）；`cn_isp_coverage` = `{短名: sampled/池规模}`（0~1，与 `cn_by_isp` **同一**池限口径；池空 ⇒ `{}`）。使「每个运营商已覆盖池内多少比例」成为可直接展示/告警的一条（R683） |
| `exit_multi_ip` / `exit_multi_region` / `exit_shared` / `exit_geo_ips` / `exit_geo_multi_region` / `exit_geo_families` | 出口多源/多出口计数（复用 `exit_family.json` 与 `exit_geo_multi.json` 的 `summary`，**不新增探测**）：多出口 IP（同族多源出口不一致）/ 多地区出口（互斥出口国并存）/ 共享出口 / 出口地理已裁决的出口 IP 数 / **出口 IP 级**多地区出口数 / 出口地理对比来源族数（只报**数量**，来源真名不入公开产物，缺失回退 0） |
| `exit_tagged` / `exit_untagged` / `exit_untagged_ratio` | 出口标注覆盖率（只读 `data/valid/all.txt`）：含箭头 `←` 的行数（有出口地区观测）/ 无箭头的行数（**尚无任何出口观测**，即"没有出口标志"）及其占比（`untagged/total`，缺失回退 0）。用于跟踪"部分 IP 无出口标志"收敛进度 |
| `exit_marked_multi_region` / `exit_marked_multi_exit` | 多出口/多地区**标记落盘量**（只读 `data/valid/all.txt`）：含 `⇋`（多地区出口）行数 / 含 `⇄`（同族多出口）行数（缺失回退 0） |
| `exit_multi_ip_published` / `exit_multi_region_published` | 与 `exit_marked_*` **同宇宙**（同一发布轮 `data/valid/all.json` 逐键标志）的**期望量**：`real_exit.multi_source` / `real_exit.multi_region_exit` 为真的条目数（缺失回退 0）。**同宇宙对账**：`exit_marked_multi_exit` ⇔ `exit_multi_ip_published`、`exit_marked_multi_region` ⇔ `exit_multi_region_published`（实测 101=101、31=31）。⚠ 勿与 `exit_multi_ip`/`exit_multi_region` 直接相减——后者取自 `exit_family.json` 的 `summary`，宇宙＝本轮 exit_family **全部键**（含 `carried` 存量键，可能不在当前存活清单），相减会幻读出「已成立但未标注」（口径错配，非滞后） |

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
`{运营商: {sampled, reachable, min_ms, median_ms}}`（无读数时为 `{}`），外加
顶层单值 `cn_wide`（R393/R418）为 CN 口径可达参考（池内 `verdict==reachable`
键数，含无分运营商读数的可达键）。R418 起 `cn_wide` 不再逐家复制——各运营商
`reachable`/`sampled` 为逐运营商实测，反映真实覆盖差异。保留最近 8 天。

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
`reputation_source`（取值真相源在私有注册表，公开树只存不透明 id（`rsrc_` 前缀）；多源时为 `multi`）、
`risk`（由信誉分推导）。

注：地址族（`family`）与双栈（`dual_stack`）信息在 `exit_family.json` 中，不在本文件。

### `data/quality/exit_family.json`

出口家族探测结果。顶层 `ts` + `proxies`：每个 `ip:port#国家` 的值为**下列完整字段**
（探测字段之外的可推导项如 line/ip/port/cc 刻意不落盘；缺字段视为该维度无数据）：

- `method`（探测方式）、`ts`（该条目探测时刻）、`family`
  （ipv4/ipv6/dual/unknown；分组/清单的**权威来源**，优先于行内 `-V4`/`-V6`/`-DS` 备注）、
  `evidence`（回显证据强度，见 evidence 语法）。
- `v4_src` / `v6_src`（各家族获胜回显服务）、`exit_v4` / `exit_v6`（实测出口 IP）、
  `shared_exit`（复用同一出口的条数，>1 时出现）。
- **R415 多出口标记（只增字段）**：`v4_seen` / `v6_seen`（同族多源回显的**不同字面量数**，
  >1 即「同族多出口」硬证据）、`multi_exit`（`v4_seen>1` 或 `v6_seen>1`）。
- **R463 证据强度（只增字段）**：`v4_votes` / `v6_votes`（获胜字面量的共识**票数**）与
  `v4_total` / `v6_total`（**观测数**）——`v4_seen`/`v6_seen` 只说"有几种字面量"：
  2-2（两个出口各获两票）与 2-1（单个离群回显）的 `seen` 同为 2，只有票数/观测数
  能分辨；`votes == total` 即全源一致，`votes * 2 == total` 即等票对峙。
- **R597 多出口/多地区（只增字段）**：`v4_lits` / `v6_lits`（同族多源回显的**不同出口
  字面量清单**，仅在 `v4_seen`/`v6_seen` > 1 时出现——R415 只带计数，消费方无从知道
  是哪几个出口）、`carried`（True = 该条目**非本轮观测**，因运行级时间预算截断由上一轮
  产物并回；`ts` 仍为该次观测时刻，新鲜度按 `ts` 判龄）。
- 上游交叉验证（按需填充：`upstream_*` 只在有 v6 出口探测结果时出现）：
  `upstream_client_ip`（上游观测出口）、`upstream_family`、`upstream_absent`、
  `upstream_match`（家族级比较）、`upstream_ip_match`（实测出口**字面量**与上游
  `clientIp` 地址等价比较（IPv6 归一化）；True/False，任一侧未知时省略——
  比 `upstream_match` 的家族级比较更严）。
- 顶层 `summary` 计数块（R597）：`{total, probed, sample, partial, carried,
  time_budget_s, multi_exit, multi_region_exit, shared_exit}`——`probed`/`sample`
  为本轮实探/计划数，`partial=True` 即被时间预算截断（未探键按 `carried` 并回），
  `multi_exit`（同族多源出口不一致）/`multi_region_exit`（独立出口地理源互斥，
  与 `all.json` 的 `real_exit.multi_region_exit` 同源同口径）为产物全域计数。

### `data/quality/exit_geo_multi.json`

按**实测出口 IP** 逐族查国的多源共识（「出口需要多源对比，不要听信一家之言
（至少 10 个源）」；口径与源清单见 pcb `docs/exit_multi_source.md`）。
顶层 `{ts, ips, summary}`：

- `ips`：`{<出口 IP>: {votes, consensus, top_votes, total_votes, distinct_cc,
  multi_region, ok_sources, providers}}`——`votes` 为**族去重**一票制
  （同一供应商多端点合 1 票；低质源保留观测但不计票）；`consensus` 无唯一
  多数时为 `null`（宁缺勿假）；`multi_region`（`distinct_cc ≥ 2`，即互斥出口
  国并存）与 `all.json` 的 `real_exit.multi_region_exit` 及行尾 `⇋` 标记同源；
  `providers` 为逐端点原始观测（fail-open：单源失败不投票）。
- `summary`：`{ips, families_configured, families_target, multi_region}`——
  可用族数 < 目标（10）时运行日志出 `::warning::`（诚实告警，不判死）。
- 数据源按**族**计：API 族（`ip-api`、`ipwhois`、`ip-sb`、`ipinfo`、
  `ipapi.co`、`geojs`、`geolocation-db`〔低质，0 票〕）+ 本地库族
  （DB-IP Lite，运行时下载、不随仓库分发；© [DB-IP.com](https://db-ip.com)，
  数据 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)；脚本兼容
  IP2Location LITE 同型 CSV）。

### `data/quality/node_seen.json` 与 `data/quality/uptime.json`

`node_seen.json`：`{runs: {<YYYY-MM-DD>: 轮次计数}, proxies: {<key>: [出现日期…]}}`
——滚动 45 天窗口的按轮存活记录。

`uptime.json`：`{proxies: {<key>: {pct7, pct30, hits7, hits30, last_seen}}, runs7, runs30, ts}`。
pct 为窗口内存现天数 ÷ **窗口内实际有质量轮的日期数**（去重，同日多轮算 1 天）的百分比
——存现与分母同按日粒度，每个运行日都在场即 100%，缺一天按比例扣分。

### `data/valid/all.json`

结构化代理池导出，数组元素：
`{line, key, ip, port, flag, cc, exit, latency_ms, speed_mbps, family(V4|V6|DS|null), cn(bool), type, tier, rep, uptime7}`，
并按来源**按需**附加可选字段（命中才出现、缺省即整字段省略；只增不改不删）：

- `cn_isp_speed` / `cn_isp_ms` —— 分运营商大陆**速度/延迟**：值形如 `{"中国电信": 1.8}` / `{"中国电信": 202.1}`，运营商键域同 `china.json`，按 `ip:port#EXIT` 精确 join。两者均逐家过**出口地理下限**：低于该出口国物理 RTT 下限的读数（如大陆→US 12ms、→HK 1ms）地理上不可能，不导出；故某家可能只出现在 `cn_isp_ms` 而不在 `cn_isp_speed`，或两家皆无。`china.json` 原始 `isp_ms` 保留作证据，仅导出的 `all.json` 套用下限。
- `cn_level` / `cn_streak` / `cn_flip` —— 大陆**证据分级/连续可达轮数/翻转计数**：`cn_level ∈ http|tcp|icmp`，`"http"` 即应用层确认可用（区别于仅能 ping 通）。
- `real_exit` —— 实测**真实出口**元数据：`family`（ipv4/ipv6/dual/unknown）、`v4`/`v6`（实测出口 IP）、`shared`、`upstream_match`、`multi`（v4≠v6=多个出口）、`multi_source`（R415：同族多源回显**不一致**=同族多出口）、`upstream_ip_match`（R415：实测出口字面量与上游 `clientIp` 地址等价比较）、`differs`（出口 IP 均 ≠ 入口 IP = 出入 IP 不同）、`geo`（实测出口**地区** `{"country","city","colo"}`，来自 `upstream_meta.json` 按入口 IP join）、`region_differs`（出口地区国 ≠ 入口标签国 = 出入地区不同）、`exit_ccs`（R419：出口地理源观测国**集合**，跨 external_check 实测出口 ∪ upstream CF Worker 观测，排 ipinfo 入口地理）、`multi_region_exit`（R419：`exit_ccs` 含 ≥2 互斥出口国 = **多地区出口**）。**缺 `real_exit` 即省略该字段**：仅剩两类且均为刻意省略——①行内无 `←` 出口观测（`exit` 为 `null`）；②有 `←` 但出口国 == 入口国、且 `exit_family.json`/`external_check.json`/`upstream_meta.json` 均无该键观测（只知国家、不知出口 **IP**）。行内箭头是**国家**级观测，不会提升为 IP 级字段（实测 2026-10-13 快照 20358 键中仅 12 个缺 `real_exit`）。

`cn` 为该行 note 中存在 `CN`/`CN4`/`CN6`/`CN46`/`CNH` 任一 token 即 true；
`exit` 为行首**出口**国家码（有出口观测即 `←` 前的首个 CC，无箭头观测时为 `null`）；
`latency_ms`/`speed_mbps` 只取 note 中首个 `Nms`/`N.MB/s` token——
`≈XMB/s` 大陆估算 token 因 `≈` 前缀无法经 `float()` 解析，`speed_mbps` 记 `null`。

### `data/valid/all_diverse.txt`

出口多样性视图：按实测出口 IP（缺省回退入口 /24 网段）分组，每组仅保留综合分最高一条，
全表按分数降序。

### `data/quality/quality_meta.json`

质量检测汇总：`ts`（ISO-8601）、`total`（代理总数）、`tls`（参与本轮质量检测的键数）、
`by_type`（IP 类型分布）、`ext_check_total`/`ext_check_ok`、`country_mismatch`（错区数）、
`risk`、`abuse_checked`、`reputation_checked`（获分条数）、`rep_dist`（0-25/25-50/50-75/75-100
分桶）、`rep_avg`/`rep_median`、`skipped`（本轮**未执行或明显降级**的相位标记列表；限速/
截断轮次会追加一条「geo 相位限速」标记——此时实时解析率骤降、但 geo 覆盖率被上一版
有效回填托住仍在高位，须靠本列表而非覆盖率识别该降级；空列表=完整批次，供下游识别降级批）。

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

入口地理缓存：顶层 `updated_at`（ISO-8601）与 `ips`（`{ip: {cc, asn}}`）。`ips` 跨批
**只增不减**（无裁剪路径）：已离池的入口 IP 保留原实测值、不再复查（入口 geo 近乎静态）。

### `data/quality/premium_meta.json`

`{ts, file_count, proxy_count}`——生成时间与落盘的 `premium*.txt` 文件数/总行数
（空清单时 `proxy_count=0`）。

### `data/quality/reputation.json`

单行 JSON，顶层 `proxies` 键为 `ip:port#国家`，值为
`{score, risk, source, sources, flags, numeric[, deep_bonus]}`：`score` 为 0-100 信誉分
（越大越干净），`risk` 为 `high`（<30）/`medium`（<75）/`low`（≥75），
`source` 取值真相源在私有注册表（公开树只存不透明 id（`rsrc_` 前缀）；多源时为 `multi`）、
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
2. 信誉分无门槛（有 `reputation.json` 记录即可，分数仅作综合分输入；
   2026-10-08 起不再要求 ≥ 80，低信誉靠 `(信誉/80)³` 因子自然沉底——
   2026-10-10 用户指令把权重自 `(信誉/90)²` 收紧为 `(信誉/80)³`，高信誉优先）
3. 非高风险（`risk != high`）
4. 有国内速度（大陆视角 `≈XMB/s`；行内须带正速度读数——海外实测
   `N.MB/s` 或 CN 视图 `≈N.MB/s` 任一形态；2026-10-09 用户指令「good
   必须要国内速度」，无速度读数整行剔除）

每个来源池都派生全套变体：`_verified`、`_stable`、`_uptime`、`_top`（组内前 25% 分位）、
`_fast`/`_mid`/`_slow`（行备注速度档）——全池与 `_ltd` 限量池一视同仁；
家族维度另出 `good_{g}` / `good_{g}_ltd`——**仅家族轴 `v4/v6/46`**：每份 good 清单都只含大陆可达行，`cn` 轴（`cn/cn4/cn6/cn46`）与其家族轴孪生完全重叠，故不单独产出（用户 2026-10-10「good 和 goodcn 存在重叠」）。

按**应用层确认优先**（`china.json` 的 `level == "http"`，即 `-CNH`；确认行排在
未确认行前，层内再按综合分降序，用户 2026-10-10「优化 CN 可用」），层内综合分为
乘积（越大越好）。缺大陆实测 RTT、该出口国无有效基准，
或缺国内速度读数 ⇒ 整行剔除（good 同时要求有中国延迟和国内速度，不用 0 分
占位）。同层同分依次按大陆延迟升序、IP 序。

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
| `last_ok_ts` | 最近一次**连续可达确认**时刻（epoch）；非可达即清，消费方据此判续保 |
| `last_seen_ok_ts` | 最近一次**观测可达**时刻（epoch）；与 `last_ok_ts` 语义分离——非可达时**保留**上一轮值（如实变旧），供「可用 ip 缓存」按窗口把可用量平滑一个窗口，避免单轮探测抖动造成可用量大幅波动；旧格式缺省，不参与 `streak`/`flip`/stable 判定 |
| `cn_mainland` | 大陆视角 RTT 是否低于门槛 |
| `isp_ms` | 各运营商最小 RTT 汇聚，`{运营商: ms}`，取值域为 `中国电信`/`中国联通`/`中国移动`/`中国多线` 四类；取 fastest-isp 时即最快运营商视角。无读数则不写该字段 |
| `isp_ms_at` | 与 `isp_ms` 成对写的逐家落盘时刻；读侧据此执行 24h 新鲜度 TTL，账龄 >24h 的家在取值端被剔除 |
| `isp_speed` | 该条**逐运营商估算速度** `{运营商: MB/s}`，由 `isp_ms` 按与大陆清单 `≈XMB/s` 同口径派生；某家延迟低于其**实测出口**国物理 RTT 下限时不派生（避免把共址假象放大成物理上不可能的高速度，宁缺勿假）。无 `isp_ms` 则不写该字段 |
| `checked_at` | 本条**探测时刻**（epoch）；新鲜度账龄的条目级回退戳（逐家 `isp_ms_at` 缺失时读侧改用它，两者皆缺则不臆造年龄） |
| `exit_cc` | 仅当行内**实测出口**与标签国家不一致（跨出口标签，如 `#US←HK`）时落盘：供按实测出口取 RTT 下限，避免用标签国下限放过共址假象；一致或无箭头标记时**不写**（读侧回退 `cc`） |

**条目级字段只增不改**：上表为该产物**已发布条目字段的全集**——新增字段必须同时更新本表与产出代码；未列出的键消费方应按未知键自动降级、不参与判据。

**`isp_ms` 只增不改**：新增运营商表现为新增键，不得改动或移除既有键。

非 `reachable` 键无 `ms`/`isp_ms` 字段属预期——`ms` 缺失仅出现在未确认可达的行，
可达清单才保证逐行有 ms。

顶层另含两个 **additive** 键（读侧对未知键自动降级，不参与判据）：

- `isp_ms_sources` — 逐源 per-ISP 归属记账（键为不透明 `src_*` id）
- `meta` — **数据新鲜度/覆盖可见性**快照（`schema: "freshness-coverage/v1"`）：

  | 子键 | 含义 |
  |---|---|
  | `age` | 条目账龄分档 `{total, fresh(<=1d), mid(2-7d), stale(>7d), unparsable}`；`fresh` 即本轮实测比例 |
  | `pool_coverage` | 已发布条目 vs 可测候选池重合度 `{total, pool, in_pool, outside, outside_no_source, pool_usable}` |
  | `carrier_breakdown` | 逐运营商 `isp_ms` 覆盖 `{total, per, full, partial, zero}` |
  | `carrier_speed_breakdown` | 逐运营商 `isp_speed` 覆盖 `{total, per, ms_per, noise, floor, full, partial, zero, ms_only, speed_only}` |
  | `unsourced_reachable` | `reachable` 却零 `sources` 证据的条目数 `{total, reachable, unsourced_reachable, in_pool, outside_pool}`；后两项把该集合拆成「在可测候选池内（可被重测修复）」与「池外（不可测）」 |

  只追加、不改动、不删除既有键；`per` 等子字段的键为运营商取值域四类
  （`中国电信`/`中国联通`/`中国移动`/`中国多线`）。

### `data/valid/all_cn.txt`

**全量大陆可达清单**：从全量存活池中筛出本轮判 `reachable` 的行，统一追加 `-CN` 备注
（应用层确认行再追加 `-CNH`）；按**大陆实测延迟升序**（缺失垫底、同值稳定）。
清单保持完整（正常水平 ≥1 万），不按大陆延迟门槛精简。

每行的 ms 为大陆视角读数（最快运营商视角优先，即各运营商最小 RTT 的全局最小），
速度 token 同步改写为 `≈XMB/s` 大陆视角估算。落地自带健康自检（行数 ≥1 万、
无低于出口地理下限的 ms、无缺 ms 行）。

> **快照语义（R455 披露）**：本清单由**独立工作流**读**已提交**的
> `data/valid/all.txt` 生成，因此可能**滞后于当期池**——某节点若在后续轮次被
> 重写**入口标签**（键＝`ip:port#<入口标签>`，标签变则键变）或被淘汰，其旧键
> 仍会留在清单里，直到下一次 CN 链运行。实测一例：18345 行中 **344 个键不在
> 当期 `all.txt`**（其中 329 个 ip:port 整条不在池中），而这些键在当期
> `china.json` 中均存在且 `verdict=reachable`。故 `stats.json` 的
> `cn_reachable`（已按当期池过滤）与本清单行数（`cn_served`）本就可能不同；
> 若需要严格「当前池」语义，请自行与 `all.txt` 取交。
> **清单不含凭空构造的行**：每一行都曾是某轮真实池行。

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
- `"pool_cache"`：本轮由**仓库内 ip 池缓存**补回的键（不是本轮任何来源抓到的）。
  自 R684 起该缓存同时作为**一等来源**登记进 `source_stats.json`/
  `source_history.json`（`{total,unique,overlap}`，按裸 IP 去重；阀值常态为 0 ⇒ `total=0`）
- 内置补充来源一律记为其**不透明公开 id**：`dsrc_` 前缀 + 加盐派生、可逆编码的 token，
  长度不固定，**非十六进制摘要**（旧方案的定长 12 hex 已随单向哈希一并作废）。id 与来源
  标签**无 salt 不可反查**，公开侧与本文档均不出现来源真名。同站多文件只记一个 id，故一个
  id 可对应多个抓取地址

不透明 id 按 artifact 分族，前缀互不重叠、同一 salt 下不撞 id：下载源 `dsrc_`（本文件及
`source_stats.json`/`source_history.json`/`source_quality.json`）、信誉源 `rsrc_`
（`reputation.json`/`ipinfo.json`/`reputation_cache.json`）、CN 点位源 `src_`（`china.json`）。
三族同构（加盐、可逆、确定性 join key），安全边界是**私有仓不公开**而非 salt 保密。

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
