# 数据规范

本文件归档「数据规范 / 国家集合 / 可用性验证 / 更新差异 / 数据文件参考」，供仓库数据消费者查阅。

## 数据规范

### 格式

- 未验证目录每行一条 `ip:port#国家代号`，例如 `1.2.3.4:443#US`
- `data/valid/` 每行一条 `ip:port#🇺🇸US-120ms-0.44MB/s`：`#` 后为 emoji 国旗 + 国家代号 + `-` + 延迟毫秒 + `-` + 速度（MB/s，两位小数）；测速失败时省略速度段（`ip:port#🇺🇸US-120ms`）
- **入口/出口地区**：质量 CI 检测后，已知出口地区的行会在国家代号后插入 `→<出口>`（如 `1.2.3.4:443#🇺🇸US→US-120ms-0.44MB/s`）。出口地区为 2 位 ISO 国家码（`US`/`JP`/`DE`…），来自 `ipinfo.json` 的 `country_code` 字段。入口未知的 `#ALL` 行同样标注出口（如 `1.2.3.4:443#ALL→US-120ms-0.44MB/s`），`ALL` 作为伪国家不会与阿尔巴尼亚 `AL` 混淆
- **质量检测备注**：质量 CI 运行后，被检测的行在既有后缀后追加 `-[-<出口类型段>][-<信誉分>][-U<NN>]`。出口类型段为 `DC`/`RES`/`MOB`/`PROXY`（机房/住宅/移动/匿名）与可选 `DS`/`V6`（双栈/纯 IPv6），tls 方法（Cloudflare 边缘）标记 `CF`；信誉分为 0-100 整数（来自 `reputation.json`）；`U<NN>` 为 7 天滚动存活率百分比（来自 `uptime.json`，如 `-U92`）。示例：`1.2.3.4:443#🇺🇸US→US-120ms-0.44MB/s-CF-72-U92`。无结果的行保持原样。（历史行上的流媒体标记 `NF(区域)/D+/YT/MX/PV/GPT` 仍被解析器容忍但已停止生成）
- **去重**：同一 `ip:port` 组合全局唯一
- **排序**：未验证目录按 IP 数字序（八位组数值比较，`1.2.3.4 < 10.0.0.1`）；`data/valid/` 按延迟升序（`all_cn*.txt` 按**大陆实测延迟**升序），`data/valid/*_ltd.txt`（及各目录 `ltd.txt`）按速度降序；`rep.txt` 按信誉分降序（同分按延迟升序）；`good.txt` 按综合分降序（同分按延迟升序再按 IP 序）

### 备注段（note）与 token 规范

统一解析（`common.parse_line`）：`ip:port#<cc><note>` 中，`key = ip:port#<cc>`；`note` 为国家代号之后直至行尾的剩余部分（含 `→<出口>`，因为 `→` 非 `A-Z`，国家码扫描会跳过它，例如 `1.2.3.4:443#🇺🇸US→US-120ms-GPT-CF-63` 的 note 为 `→US-120ms-GPT-CF-63`）。

- token 是 note 中以**段首或 `-` 为界**的独立子串（`common.has_token(note, token)`，等价 `(?:^|-)TOKEN(?:$|-)`）。如 `-CF-63` 含 token `CF`、`63`；`-120ms-CN-V4` 含 token `CN`、`V4`，不含 `CF`。
- 单一职责：`is_cf_heuristic`（CF 边缘）、`exit_family.has_family_note`（`V4`/`V6`/`DS`）、`china_check.has_cn_note`（`CN`）均基于 `has_token` 实现，新增/判断 token 不得另写正则。
- token 分隔符统一为 `-`；流媒体段内用空格分隔（`NF(US) D+ YT`），不属于 token 匹配范围。
- 幂等：追加 token 前先 `has_token` 判重（`annotate_family`/`annotate_cn`），避免重复标注。

### 处理流程

主要来源为 `all.json`（JSON 数组，含逐 IP 元数据），zip 归档作为回退。脚本依次：

1. 下载 zip 归档（默认来源 `zip.cm.edu.kg`，可 `-u` 指定）
2. 解压并按 `data/raw/<port>/<country>.txt` 重新组织（含上游聚合文件 `ALL.txt` → `#ALL`；`raw/` 为可重建中间产物，git 不入库，仅下载侧在 CI 运行期生成）
3. 并行拉取并合并 CF 反代补充来源（见下方「CF 反代补充来源」；`--no-extra-sources` 跳过），无国家标签的条目经 `ip-api.com/batch` 尽力补齐国家码（失败保留 `#ALL`）；合并时同端口已有国家标注的重复 `#ALL` 条目会被剔除
4. 按国家汇总为 `data/download/countries/<country>.txt`（跨端口去重，不含 ALL）
5. 按端口汇总为 `data/download/ports/<port>.txt`（跨国家去重；`#ALL` 条目亦计入）
6. 按常用集合汇总为 `data/download/sets/<集合>.txt`（见下方集合表）
7. 去重合并为 `data/download/all.txt`（含 `#ALL` 条目）

### 限量版 `_ltd`

- 下载侧 `data/download/sets/<集合>_ltd.txt`、`data/download/all_ltd.txt`：每国最多取前 `--per-country-limit` 条（默认 20，按 IP 序）；`#ALL` 条目在 `all_ltd` 中单独取前 `--per-country-limit` 条
- 验证侧 `data/valid/*_ltd.txt` 及各国家/集合目录内 `ltd.txt`：每国取**实测下载速度最快**的 20 条（速度并列/无速度时按延迟兜底），集合内与 `all_ltd` 全局按速度降序
- `--per-country-limit 0` 时不生成限量文件

## 国家集合

| 集合 | 覆盖国家/地区 | 用途 |
|---|---|---|
| `europe` | AL AT BE BG BY CH CY CZ DE DK EE ES FI FR GB GR HR HU IE IS IT LT LV MD MK NL NO PL PT RO RS RU SE SI UA（35） | 欧洲全域 |
| `asia` | AE AM AZ CN GE HK ID IL IN JP KH KR KZ MY PH SA SG TH TR TW UZ VN（22） | 亚洲全域 |
| `north_america` | CA MX US VG（4） | 北美 |
| `south_america` | AR BR CL EC（4） | 南美 |
| `oceania` | AU NZ（2） | 大洋洲 |
| `africa` | EG NG ZA（3） | 非洲 |
| `middle_east` | AE IL SA TR（4） | 中东 |
| `hot` | AU CA DE FR GB HK JP KR NL SG TW US RU（13） | 热门线路 |
| `cn_common` | HK TW SG JP KR US DE GB FR NL RU CA AU（13） | 中国大陆常用 |
| `hk_us_jp_sg_tw_kr` | HK US JP SG TW KR（6） | 港美日新台韩 |

## 可用性验证

CI 每次更新后对 `data/download/all.txt` 做连通性检查，输出镜像 `data/` 结构的存活列表到 `data/valid/`。非限量清单**按延迟升序**（最快在前），`_ltd` 限量清单**按实测下载速度降序**。

### TLS 握手检测

对每个代理做 TLS 握手（SNI=`cdnjs.cloudflare.com`），成功即判定存活：

### 速度测试

每个存活代理在新建 TLS 连接上做真实下载测速：发送 `GET /ajax/libs/three.js/r128/three.js`（约 530 KB），
最多读取 `--speed-bytes`（默认 1 MB）字节或持续 `--speed-timeout`（默认 5s）秒，得到吞吐速度（MB/s，两位小数）。

测速为 **稳态测量**：响应头先解析，仅接受 HTTP 2xx（403 错误页等一律视为测速失败）；
前 `--speed-warmup-bytes`（默认 256 KB）字节覆盖 TCP 慢启动爬坡，不计入计时；
速度只按其后稳态窗口的字节量 ÷ 耗时计算，慢启动不再拉低读数，高/低延迟代理之间可比性更强。
稳态样本不足时（传输在预热段内即 EOF / 超时）回退为全程平均，覆盖率与旧版一致。
测速失败仅使速度置空，不影响存活判定。速度仅供排序与统计，不做二次筛选。

默认启用 **RTT 自适应下载窗口**：根据 TLS 握手测得的延迟动态调整测速时长和下载量，
使高延迟代理也能完成 TCP 慢启动进入稳态，消除延迟对速度测量的偏差。
延迟越低（≤100ms）窗口不变（5s / 5MB），延迟越高窗口越大（500ms → 15s / 15MB，1s → 30s / 30MB）。
可用 `--no-adaptive-speed` 关闭，回退到固定5s / 1MB。

下载测速受独立并发上限 `--speed-workers`（默认 30）约束——判活（TCP/TLS）仍以 `--workers`（默认 500）
高并发进行，但同一时刻最多 30 个测速下载在飞，避免 CI 出口带宽被打满导致测速值拉平、区分度下降。并发越低
测速越准确，但全量测速耗时越长（并发 30 时约 30-40 分钟）。

### 并发与容错

- **asyncio 并发**：默认 500 个在飞任务（`-w` 可调），有界任务池实现严格限时
- **超时**：单代理 5s（`-t`）
- **自动重试**：TCP 能连通但 TLS 检测超时的代理，短暂间隔后重试一次，降低单次丢包误杀
- **时间预算**：`--time-budget N` 到时立即停止，到期只取消少量在飞任务；CI 默认不设置（`0` = 跑完全部存活代理）

### 输出

- `data/valid/all.txt`、`all_ltd.txt`：存活代理，格式 `ip:port#🇺🇸US-120ms-0.44MB/s`；`all.txt` 按延迟排序，`all_ltd.txt` 按速度排序；`#ALL` 条目（入口未知）只出现在这两个文件，不进入 `countries/`
- `data/valid/countries/<国家>/`、`data/valid/sets/<集合>/`：按国家/集合分组的存活列表（同样含延迟/速度），每目录 `all.txt`（全量，延迟升序）、`ltd.txt`（限量，速度降序）、`rep.txt`（信誉排序，质量 CI 生成）、`good.txt`（综合最优，质量 CI 生成）；`ports/` 为按端口分组的平铺存活列表
 - 分组文件（每国家/集合目录，validation CI 生成）：在 `all.txt`/`ltd.txt`/`rep.txt` 之外，每个目录还按 **出口家族 × 大陆可达** 派生以下清单（各带 `*_ltd.txt` 限量版，规则同 `ltd.txt`）：
   - `v4.txt` — 出口为 IPv4-only 的代理；`v6.txt` — IPv6-only；`46.txt` — 双栈（v4+v6）
   - `cn.txt` — 大陆可达（`-CN` 备注）；`cn4.txt`/`cn6.txt`/`cn46.txt` — 大陆可达 × 对应家族
   - 家族判定优先 `exit_family.json`（`ipv4`/`ipv6`/`dual`），缺失时回退行内 `-V4`/`-V6`/`-DS` 备注；`unknown` 家族只可能进 `cn` 组。空组不落盘（并清理上轮残留）
   - 根级另有 `all_46.txt` / `all_cn4.txt` / `all_cn6.txt` / `all_cn46.txt`（及 `*_ltd.txt`）；v4/v6 复用既有 `all_ipv4.txt`/`all_ipv6.txt`，不重复生成
   - **可靠性变体**：上述每个清单（含根级 `all*.txt`）同步派生 `*_verified.txt` 与 `*_stable.txt` 两个维度，可与任意分组叠加（如 `countries/US/cn4_verified.txt`、根级 `all_cn4_stable.txt`）：
     - `*_verified` — **全链路验证**子集：本轮测速成功 = TLS 握手 + HTTP 2xx 响应 + 真实下载全部通过，过滤"能握手但不吐数据"的半死代理
     - `*_stable` — **连续两轮存活**交集：上一轮 `index.json` 与本轮存活的交集，对抗代理池快速 churn（首轮无上一轮数据时不生成）
     - 空清单不落盘（并清理上轮残留）；数量计入 `meta.json` 的 `sets.all_verified` / `sets.all_stable`
     - **跨家族联动**：`ltd` / `rep` / `good` 家族同样派生变体——验证 CI 写 `ltd_verified.txt` / `ltd_stable.txt`（每目录）与根级 `all_{g}_ltd_verified.txt` 等；质量 CI 为 rep 清单补齐（根级 `all_rep_ltd(+v/s)`、每目录 `rep_ltd(+v/s)`、`{g}_rep_ltd(_ltd 单维)`），good CI 写 `good_ltd(+_verified/_stable)`（根级与每目录，基于 ltd 池过滤）。质量侧 `_stable` 信号为 china.json streak≥2（连续两轮大陆可达），与验证侧"两轮存活"语义互补

- `data/valid/meta.json`：本次验证汇总（字段见下）
- `data/valid/index.json`：每存活代理的结构化索引（延迟 + 检测方法）
- `data/valid/speed.json`：每测速成功代理的实测速度（MB/s，按速度降序）
- `data/valid/history.jsonl`：每次验证的历史记录（最多 1000 条，供趋势图）

### 常用命令

```bash
python scripts/validate_proxies.py                    # 验证全部
python scripts/validate_proxies.py --limit 50         # 冒烟测试前 50 条
python scripts/validate_proxies.py --time-budget 180  # 最多跑 180 秒
```

## 更新差异

每次更新对比上一版（`git show HEAD:data/download/all.txt`）生成差异：

- `data/diff/latest.json`：最近一次 `added`/`removed` 列表
- `data/diff/<时间戳>.json`：有变化时按次归档，最多保留最近 500 份
- `data/quality/history.jsonl`：每条记录含 `added`/`removed` 计数

## 数据文件参考

### `data/output/stats.json`

统计汇总（供徽章与外部消费），字段：

| 字段 | 含义 |
|---|---|
| `ts` | 生成时间 |
| `updated_at` | 数据最后更新时间 |
| `unique` / `total` | 去重代理数 / 上游原始条目数 |
| `countries` / `ports` | 国家数 / 端口数 |
| `sets` | 各集合条数 |
| `alive` / `alive_checked` / `alive_rate` | 存活数 / 检测数 / 存活率 |
| `alive_countries` / `alive_sets` | 存活国家数 / 存活集合条数 |
| `latency` | 延迟统计（avg/median/p90/max，毫秒） |
| `latency_dist` | 延迟分桶直方图（如 `0-100`、`1000+`，毫秒） |
| `speed` | 测速统计（avg/median/p90/max，MB/s） |
| `speed_dist` | 速度分桶直方图（如 `0-0.5`、`5+`，MB/s） |
| `ip_type` / `family` / `dual_stack` / `country_mismatch` | 出口 IP 类型分布 / 地址族分布 / 双栈数 / 错区数 |
| `age_s` / `updated_ago` / `stale` | 数据年龄（秒）/ 可读年龄（如 `4h ago`）/ 是否过期（超过 3h） |
| `history_records` / `alive_history_records` | 历史记录条数 |

### `data/valid/meta.json`

| 字段 | 含义 |
|---|---|
| `total` / `checked` / `alive` / `dead` | 总条目 / 实际检测数（含重试）/ 存活 / 失效 |
| `elapsed_s` / `checked_per_s` | 耗时（秒）/ 吞吐（条/秒） |
| `by_method` | 各判定方法（tls）的存活数 |
| `latency` | 延迟统计（avg/median/p90/max） |
| `latency_dist` | 延迟分桶直方图（毫秒） |
| `speed` | 测速统计（avg/median/p90/max，MB/s） |
| `speed_dist` | 速度分桶直方图（MB/s） |
| `per_country` / `per_port` | 各国 / 各端口存活数 |
| `sets` | 各集合存活条数 |
| `ext_check` | 外部 API 检测汇总（仅 `--ext-check` 时出现）：`ext_check_total`/`ext_check_ok`/`ext_check_uncertain`/`ext_check_dead`/`ext_avg_response_ms` |

### `data/valid/index.json`

单行 JSON 结构化索引，键为 `ip:port#国家`，值为 `[延迟ms, 检测方法]`，按延迟升序：

```json
{"proxies": {"1.2.3.4:443#US": [640.1, "tls"], "5.6.7.8:8443#JP": [80.1, "tls"]}}
```

### `data/valid/speed.json`

单行 JSON，键为 `ip:port#国家`，值为实测速度（MB/s，两位小数），按速度降序（仅含测速成功的代理）：

```json
{"proxies": {"5.6.7.8:8443#JP": 1.25, "1.2.3.4:443#US": 0.44}}
```

数据未变化时文件不变（避免无意义提交）。运行时间见 `meta.json` 的 `ts`。

### `data/valid/ext_check.json`

外部 API 多源验证逐条结果（仅 `--ext-check` 时生成），单行 JSON，键为 `ip:port#国家`，值为：

```json
{
  "sources": ["090227", "cmliu"],
  "alive": true,
  "response_ms": 120.5,
  "colo": "LAX",
  "ipv4_ok": true,
  "ipv6_ok": false,
  "dual_stack": false,
  "inferred_stack": "ipv4",
  "exit_geo": {"countryCode": "US", "city": "Los Angeles", "asn": 13335, "org": "Cloudflare"}
}
```

| 字段 | 含义 |
|---|---|
| `sources` | 确认存活的 API 源列表（至少 2 个） |
| `alive` | 共识结果：`true`/`"uncertain"`（仅 1 源确认）/`false` |
| `response_ms` | 最快 API 响应时间（毫秒） |
| `colo` | Cloudflare datacenter IATA（仅 090227/cmliu 源） |
| `ipv4_ok` / `ipv6_ok` | IPv4/IPv6 出口可达 |
| `dual_stack` | 双栈出口 |
| `inferred_stack` | 推断出口栈类型：`ipv4`/`ipv6`/`dual` |
| `exit_geo` | 出口地理信息（`countryCode`、`city`、`asn`、`org`） |

数据未变化时文件不变（避免无意义提交）。

### `data/quality/ipinfo.json`（质量 CI 输出）

单行 JSON，键为 `ip:port#国家`，值为出口 IP 信息：`exit_ip`、`country`/`country_code`/`region`/`city`（出口地理）、`asn`/`org`/`isp`、`proxy`/`hosting`/`mobile` 标志、`ip_type`（DC/RES/MOB/PROXY）、`listed_country` 与 `country_match`（是否错区）、`geo_checked`（是否查到出口地理）、`reputation`（0-100 信誉分）、`rep_flags`（共识确定的语义维度：proxy/vpn/tor/hosting/mobile/abuse/listed/scraper/crawler/anonymous）、`rep_sources`（参与投票的源列表）、`numeric_sources`（参与连续型风险罚分的源列表）、`reputation_source`（netcoffee/ncgy/ip-api/ipquery/ffraud/blackbox/otx/ipsum/ipapi_is/ipdata/whatismyip/dc_asn/abuse_list/vpn_asn/resproxy_asn/proxycheck/ip2location/ipwhois/tor_exit/spamhaus/getipintel/abuseipdb/ipqs，多源时为 multi）、`risk_sources`（参与合分的源列表）、`risk`（由信誉分推导或滥用分）。注：地址族（`family`）和双栈（`dual_stack`）信息在 `exit_family.json` 中，不在本文件。

### `data/quality/node_seen.json` 与 `data/quality/uptime.json`

`node_seen.json`：`{runs: {<YYYY-MM-DD>: 轮次计数}, proxies: {<key>: [出现日期…]}}`——滚动 45 天窗口的按轮存活记录。

`uptime.json`：`{proxies: {<key>: {pct7, pct30, hits7, hits30, last_seen}}, runs7, runs30, ts}`。pct 为窗口内存现天数 ÷ 运行轮数的百分比。

### `data/valid/all.json`

结构化代理池导出（`export_json.py`），数组元素：
`{line, key, ip, port, flag, cc, exit, latency_ms, speed_mbps, family(V4|V6|DS|null), cn(bool), type, tier, rep, uptime7}`。

### `data/valid/all_diverse.txt`

出口多样性视图：按实测出口 IP（exit_family 的 `exit_v4`/`exit_v6`，缺省回退入口 /24 网段）分组，每组仅保留综合分最高一条，全表按分数降序。

### `data/quality/quality_meta.json`

质量检测汇总（供 stats 消费）：`ts`（生成时间戳 ISO-8601）、`total`（代理总数）、`tls`（TLS 方法代理数）、`by_type`（IP 类型分布）、`ext_check_total`/`ext_check_ok`（外部 API 检查计数）、`country_mismatch`（错区数）、`risk`、`abuse_checked`、`reputation_checked`（获分条数）、`rep_dist`（0-25/25-50/50-75/75-100 分桶）、`rep_avg`/`rep_median`。

### `data/quality/abuse.json`

提供滥用分 key 时输出：键为 `ip:port#国家`，值为 `{service, score, risk, ...}` 滥用分与标志。

### `data/quality/reputation.json`

单行 JSON，键为 `ip:port#国家`，值为 `{score, risk, source, sources, flags, numeric}`：`score` 为 0-100 信誉分（越大越干净），`risk` 为 `high`（<30）/`medium`（<75）/`low`（≥75），`source` 为 `netcoffee`/`ncgy`/`ip-api`/`ipquery`/`ffraud`/`blackbox`/`otx`/`ipsum`/`ipapi_is`/`ipdata`/`whatismyip`/`dc_asn`/`abuse_list`/`vpn_asn`/`resproxy_asn`/`proxycheck`/`ip2location`/`ipwhois`/`tor_exit`/`spamhaus`/`getipintel`/`abuseipdb`/`ipqs`（多源时为 `multi`），`sources` 为实际参与合分的源列表，`flags` 为共识确定的语义维度列表，`numeric` 为参与连续型罚分的源列表。按分数降序、同分按键序排列。

### `data/quality/reputation_cache.json`

单行 JSON，按 IP 缓存各按 IP 信誉 API 源的原始信号，键为出口 IP，值为 `{ts, signals: {source: signal}}`：`ts` 为查询时间戳（epoch 秒），TTL 内（默认 7 天）复用缓存信号重新计算分数，只对缺失/过期的 IP 发起外部查询；静态列表信号不缓存。`--rep-cache-ttl` 调整有效期，`--no-rep-cache` 禁用缓存；表按每个 IP 最近信号时间封顶 4 万条，超限裁剪最旧。

### `data/valid/all_rep.txt`

与 `all.txt` 同源（全量存活池）的**信誉排行**：被检测的行按信誉分降序（同分按延迟升序再按 IP 序），无分数条目排在末尾保持原序；每行携带完整备注（流媒体/类型/信誉分）。每国/每集合目录下的 `rep.txt` 用同样的排序规则，源为对应目录的 `all.txt`（全量存活集）。

### `data/valid/all_good.txt` 及各目录 `good.txt`

**综合最优清单**（质量 CI 生成，`build_good.py`）：从对应池（根级 `all.txt` / 各国家、集合目录 `all.txt`）中筛选同时满足以下条件的代理：

1. 大陆可达（`china.json` 判定 `reachable`，或行内已带历史 `-CN` 备注，与 `all_cn.txt` 同规则）
2. 信誉分 ≥ 80（存在于 `reputation.json` 且 `score >= 80`）
3. 非高风险（`reputation.json` 的 `risk != high`）

按综合分降序排列：`round(0.6×信誉分 + 0.2×延迟分 + 0.2×速度分)`；延迟分 ≤100ms 记 100、≥1500ms 记 0 线性递减，速度分 `min(MB/s÷5, 1)×100`，缺失均记 0；同分依次按延迟升序、IP 序。行内容为源池原行（含全部备注），不改动。

### `data/quality/china.json`（china-check CI 输出）

单行 JSON，键为 `ip:port#国家`，值为大陆连通性逐条检测明细：`ip`/`port`/`cc`/`cf_heuristic`（是否 CF 边缘启发式）、`verdict`（`reachable`/`unreachable`/`uncertain`/`skipped`）、`basis`（判据源，如 `check_host`/`xxapi`/`itdog`/`itdog_tcping`/`pingpe`/`heuristic`；保守判定需 ≥2 方法确认才标 reachable，多节点源单独 ok 即可达）、`ms`（可达延迟）、`level`（证据分级：任一成功源给出应用层 HTTP 确认 → `http`，仅传输层 TCP → `tcp`，无成功源 → `null`）、`streak`（连续可达轮数，跨轮累计）、`sources`（各源原始结果，itdog 源含 `level`；batch_http 失败时由 `itdog_tcping` 大节点池补测）、`ts`（检测时间）。

### `data/valid/all_cn.txt`

**全量大陆可达清单**（china-check CI）：从 `data/valid/all.txt` 全量存活池中筛出本次判 `reachable` 或历史已带 `-CN` 的行（缺 all.txt 时回退 `all_ltd.txt`），统一追加 `-CN` 备注（应用层确认行再追加 `-CNH`）；按**大陆实测延迟升序**（缺失垫底、同值稳定）。逐条检测明细见 `china.json`。

### `data/valid/all_cn_http.txt` / `data/valid/all_cn_stable.txt`

china-check CI 派生的两个可靠性子集（均按大陆实测延迟升序）：

- `all_cn_http.txt` — **应用层确认**子集：本轮任一成功源给出 HTTP 级确认（`level=http`）或历史已带 `-CNH` 的行。TCP 通但应用层被干扰的代理不会进入此清单
- `all_cn_stable.txt` — **跨轮稳定**子集：连续 ≥2 轮判 `reachable` 的行（strict，不含历史 `-CN` 兜底），对抗单轮误判与快速 churn

推荐消费顺序：`all_cn_stable.txt` > `all_cn_http.txt` > `all_cn.txt`。

### `data/valid/all_46.txt` / `all_cn4.txt` / `all_cn6.txt` / `all_cn46.txt`

**根级分组文件**（validation CI 生成）：`all_46.txt` 为全部出口双栈（v4+v6）代理，`all_cn4.txt`/`all_cn6.txt`/`all_cn46.txt` 为大陆可达 × 对应家族；顺序沿用全量池（延迟升序），家族判定同国家目录分组（优先 `exit_family.json`，回退行内 `-V4`/`-V6`/`-DS`）。对应 `all_*_ltd.txt` 为按每国限量的速度降序版。v4/v6 分组复用既有 `all_ipv4.txt`/`all_ipv6.txt`，根级不重复生成。

### `data/quality/history.jsonl`（每行一条）

`ts`、`total`、`unique`、`countries`、`ports`、`sets`、`added`、`removed`。数据未变化时跳过，最多保留最近 1000 条。

### `data/valid/history.jsonl`（每行一条）

`ts`、`total`、`checked`、`alive`、`dead`。与上一条完全相同则跳过，最多 1000 条。

### `data/quality/source_history.json`

每次 download 运行向该文件**追加**一轮各上游源的 `unique` 数快照：`{"runs": [{"ts": <ISO-8601>, "counts": {<源标签>: 去重数}}]}`，保留最近 14 轮（`SOURCE_HISTORY_MAX`），内容不变不重写。供 `health_alert.check_sources` 检测上游源覆盖率骤降（相对近 8 轮中位数下降 > 55% 且历史规模 ≥ 500 触发告警）。

### `data/quality/upstream_meta.json`

上游 `all.json` 导出的逐 IP 元数据（keyed by 代理 IP），由 `download_proxies.py` 生成，供下游（如 exit-family 交叉验证）消费。每个值含 `clientIp`（该代理的真实出口 IP，Cloudflare 视角）、`family`（由 `clientIp` 派生，ipv4/ipv6）、`asn`、`asOrganization`、`country`、`city`、`region`、`continent`、`colo_iata`。使用旧版 zip 回退源时本文件不更新。

### `data/quality/ip_sources.json`

逐 IP 下载源归属（由 `download_proxies.py` 生成）。键为 `ip:port#CC`，值为来源标签：`"main"`（主源 zip.cm.edu.kg）、补充源文件名 stem（`fdip`/`vlid`/`yxip`/`list`/`proxy`/`bestproxy&country`/`proxyip`）、`"multi"`（多源重叠）或 `"unknown"`。供 `analyze_sources.py` 消费。

### `data/quality/source_quality.json`

各下载源质量指标（由 `analyze_sources.py` 生成）。顶层含 `ts`（生成时间）、`total_proxies`（总代理数）、`total_alive`（存活数）、`sources`（逐源指标）。每个源含：`total`/`alive`/`survival_rate`（存活率）、`avg_latency`/`median_latency`（延迟 ms）、`avg_speed`/`median_speed`（速度 MB/s）、`avg_reputation`（信誉分 0-100）、`reputation_dist`（风险分布）、`china_reachable_rate`（大陆可达率）、`family_dist`（出口家族分布）、`country_dist`/`port_dist`（国家/端口分布）。