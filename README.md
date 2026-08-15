# proxyip

定期从 <https://zip.cm.edu.kg> 下载代理 IP 列表并通过 CI 自动解压、整理、验证、提交回仓库；附带一个浏览器指纹生成工具。整个流程零第三方 Python 依赖，仅需标准库。

[![Unique Proxies](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=unique&label=Unique%20Proxies&color=blue)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/all.txt)
[![Alive](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=alive&label=Alive&color=green)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/all.txt)
[![Alive Rate](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=alive_rate&label=Alive%20Rate&color=orange)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/meta.json)
[![Updated](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=updated_ago&label=Updated&color=informational)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json)
[![Status](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/badge.json)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json)

![Trend](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart.svg)
![Alive rate](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_alive_rate.svg)
![Country distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_country.svg)
![Port distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_port.svg)
![Churn](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_churn.svg)
![Composite trend](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_combo.svg)
![Latency distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_latency.svg)
![Speed distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_speed.svg)
![Streaming unlock](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_streaming.svg)

## 功能特性

- **自动抓取整理**：下载上游 zip → 按端口/国家/常用集合/全量多维度汇总，去重合并
- **可用性验证**：HTTP CONNECT + TLS 双重检测，asyncio 高并发测活，并在判活连接内**真实下载测速**（MB/s）；非限量输出**按延迟升序**，**`_ltd` 限量清单按实测速度取每国最快**
- **流媒体解锁 + 出口 IP 质量检测**（独立 CI）：对每国最快的限量存活集做 Netflix（含原生 IP 判定）/ Disney+ / YouTube Premium / Max / Prime Video / ChatGPT 解锁检测、出口 IP 地理与类型（机房/住宅/移动）、双栈判定与可选滥用分，结果按既有格式以 `-` 段追加备注到 `data/valid/*.txt`
- **大陆连通性检测**（独立 CI）：以大陆视角实测代理池是否可用（GFW 视角 TCP 可达性），启发式 CF 边缘判定 + check-host.cc / xxapi.cn 单节点实测 + ping.pe 多运营商复核，产出 `china.json` 明细与 `all_cn.txt` 大陆可达清单，并在 `data/valid/*.txt` 追加 `-CN` 备注
- **实际出口家族检测**（独立 CI）：探测每个存活代理的真实出口 IP 家族（IPv4/IPv6）——CF 边缘代理虽以 v4 地址呈现，实际出口常为 v6；按家族分离保存 `all_ipv4.txt` / `all_ipv6.txt`（双栈双入）并在 `data/valid/*.txt` 追加 `-V4`/`-V6`/`-DS` 备注
- **更新差异**：每次更新自动对比上一版，产出 `added`/`removed` 并归档
- **统计与趋势**：生成 `stats.json`（供徽章消费）与零依赖 SVG 图表组：趋势、存活率、国家/端口分布、延迟/速度分布、更新增量与双轴复合图
- **结构化索引**：`valid/index.json` 提供每存活代理的延迟与检测方法索引，`valid/speed.json` 提供实测速度索引，便于程序直接消费
- **CI 自动化**：每 30 分钟全自动执行下载→验证→统计→提交，无需人工干预；提交前自动跑测试套件（stdlib `unittest`）
- **浏览器指纹生成**：生成内部自洽、同一设备配置的 UA/分辨率/时区/WebGL 等指纹

## 快速开始

### 系统要求

- Python 3.11+（使用了 `asyncio.timeout` 与 `dict[str, ...]` 等新语法）
- 无任何第三方依赖，仅标准库

### 运行

```bash
git clone https://github.com/Xiaobei09/proxyip.git
cd proxyip

python -m unittest discover -s tests -v     # 0. 运行测试套件（可选）
python scripts/download_proxies.py          # 1. 下载解压整理
python scripts/validate_proxies.py             # 2. 连通性验证与测速（默认不设时间限制，跑完为止）
python scripts/generate_stats.py            # 3. 统计与趋势图
python scripts/quality_check.py             # 4. 流媒体解锁 + 出口 IP 质量检测（可选）
```

### 消费数据

未验证目录统一 `ip:port#国家` 格式（如 `1.2.3.4:443#US`），按 IP 数字序排列；`data/valid/` 内为
`ip:port#🇺🇸US-120ms-0.44MB/s`（国旗+国家-延迟毫秒-速度 MB/s，测速失败时省略速度段），**按延迟升序**（`_ltd` 按速度降序）。

```bash
head -1 data/valid/all.txt                  # 当前延迟最低的存活代理（延迟升序）
data/valid/all_ltd.txt                      # 每国按实测速度最快的 20 条限量清单
data/valid/countries/US.txt                 # 仅美国的存活代理（含延迟/速度）
data/valid/ports/443.txt                    # 仅 443 端口的存活代理
data/valid/speed.json                       # 每存活代理的实测速度（MB/s，按速度降序）
data/sets/hot.txt                           # 热门国家集合
data/all.txt                                # 全量去重清单（未验证）
```

## 数据规范

### 格式

- 未验证目录每行一条 `ip:port#国家代号`，例如 `1.2.3.4:443#US`
- `data/valid/` 每行一条 `ip:port#🇺🇸US-120ms-0.44MB/s`：`#` 后为 emoji 国旗 + 国家代号 + `-` + 延迟毫秒 + `-` + 速度（MB/s，两位小数）；测速失败时省略速度段（`ip:port#🇺🇸US-120ms`）
- **质量检测备注**：质量 CI 运行后，被检测的行在既有后缀后追加 `-<流媒体段>[-<出口类型段>][-<信誉分>]`。流媒体段为空格分隔的解锁标记：`NF(区域)`（Netflix+解锁区域，原生判定见 `streaming.json`）、`D+`（Disney+）、`YT`（YouTube Premium）、`MX`（Max）、`PV`（Prime Video）、`GPT`（ChatGPT/OpenAI）；出口类型段为 `DC`/`RES`/`MOB`/`PROXY`（机房/住宅/移动/匿名）与可选 `DS`/`V6`（双栈/纯 IPv6），tls 方法（Cloudflare 边缘）标记 `CF`；信誉分为 0-100 整数（来自 `reputation.json`）。示例：`1.2.3.4:443#🇺🇸US-120ms-0.44MB/s-NF(US) D+ YT GPT-DC-72`、`9.9.9.9:443#🇺🇸US-8ms-5.86MB/s-GPT-CF-63`。无结果的行保持原样
- **去重**：同一 `ip:port` 组合全局唯一
- **排序**：未验证目录按 IP 数字序（八位组数值比较，`1.2.3.4 < 10.0.0.1`）；`data/valid/` 按延迟升序，`data/valid/*_ltd.txt` 按速度降序

### 处理流程

压缩包结构为 `<port>/<country>.txt`，每个文件内每行一个 IP。脚本依次：

1. 下载 zip 归档（默认来源 `zip.cm.edu.kg`，可 `-u` 指定）
2. 解压并按 `data/raw/<port>/<country>.txt` 重新组织（含上游聚合文件 `ALL.txt` → `#ALL`）
3. 按国家汇总为 `data/countries/<country>.txt`（跨端口去重，不含 ALL）
4. 按端口汇总为 `data/ports/<port>.txt`（跨国家去重，不含 ALL 派生条目）
5. 按常用集合汇总为 `data/sets/<集合>.txt`（见下方集合表）
6. 去重合并为 `data/all.txt`

### 限量版 `_ltd`

- 下载侧 `data/sets/<集合>_ltd.txt`、`data/all_ltd.txt`：每国最多取前 `--per-country-limit` 条（默认 20，按 IP 序）
- 验证侧 `data/valid/*_ltd.txt`：每国取**实测下载速度最快**的 20 条（速度并列/无速度时按延迟兜底），集合内与 `all_ltd` 全局按速度降序
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

CI 每次更新后对 `data/all.txt` 做连通性检查，输出镜像 `data/` 结构的存活列表到 `data/valid/`。非限量清单**按延迟升序**（最快在前），`_ltd` 限量清单**按实测下载速度降序**。

### 双重检测算法

对每个代理依次尝试两种方法，任一成功即判定存活：

1. **HTTP CONNECT 隧道**：向代理发送 `CONNECT cdnjs.cloudflare.com:443 HTTP/1.1`，响应 `200` 即通
2. **TLS 握手兜底**：对代理自身做 TLS 握手（SNI=`cdnjs.cloudflare.com`），用于 Cloudflare 边缘代理——这类代理在 443/8443/2053/2083/2087/2096 提供 TLS 服务但拒绝纯 CONNECT

### 速度测试

每个存活代理在判活连接上继续做真实下载测速：发送 `GET /ajax/libs/three.js/r128/three.min.js`（约 530 KB），
最多读取 `--speed-bytes`（默认 256 KB）字节或持续 `--speed-timeout`（默认 5s）秒，得到吞吐速度（MB/s，两位小数）。
CONNECT 隧道与 TLS 连接共用同一目标主机与路径；测速失败仅使速度置空，不影响存活判定。速度仅供排序与统计，
不做二次筛选。

下载测速受独立并发上限 `--speed-workers`（默认 10）约束——判活（TCP/TLS/CONNECT）仍以 `--workers`（默认 500）
高并发进行，但同一时刻最多 10 个测速下载在飞，避免 CI 出口带宽被打满导致测速值拉平、区分度下降。并发越低
测速越准确，但全量测速耗时越长（并发 10 时约 30-40 分钟）。

### 并发与容错

- **asyncio 并发**：默认 500 个在飞任务（`-w` 可调），有界任务池实现严格限时
- **超时**：单代理 5s（`-t`）；CONNECT 响应读取独立 3s 上限
- **自动重试**：TCP 能连通但两项检测均超时的代理，短暂间隔后重试一次，降低单次丢包误杀
- **时间预算**：`--time-budget N` 到时立即停止，到期只取消少量在飞任务；CI 默认不设置（`0` = 跑完全部存活代理）

### 输出

- `data/valid/all.txt`、`all_ltd.txt`：存活代理，格式 `ip:port#🇺🇸US-120ms-0.44MB/s`；`all.txt` 按延迟排序，`all_ltd.txt` 按速度排序
- `data/valid/countries/`、`ports/`、`sets/`：按国家/端口/集合分组的存活列表（同样含延迟/速度）
- `data/valid/meta.json`：本次验证汇总（字段见下）
- `data/valid/index.json`：每存活代理的结构化索引（延迟 + 检测方法）
- `data/valid/speed.json`：每测速成功代理的实测速度（MB/s，按速度降序）
- `data/valid/history.jsonl`：每次验证的历史记录（最多 1000 条，供趋势图）

### 常用命令

```bash
python scripts/validate_proxies.py                    # 验证全部
python scripts/validate_proxies.py --limit 50         # 冒烟测试前 50 条
python scripts/validate_proxies.py                    # 验证全部（默认不设限）
python scripts/validate_proxies.py --limit 50         # 冒烟测试前 50 条
python scripts/validate_proxies.py --time-budget 180  # 最多跑 180 秒
```

## 更新差异

每次更新对比上一版（`git show HEAD:data/all.txt`）生成差异：

- `data/diff/latest.json`：最近一次 `added`/`removed` 列表
- `data/diff/<时间戳>.json`：有变化时按次归档，最多保留最近 500 份
- `data/history.jsonl`：每条记录含 `added`/`removed` 计数

## 数据文件参考

### `data/stats.json`

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
| `streaming` / `streaming_ok` | 各服务解锁计数（来自 `quality_meta.json`）/ 任一解锁条目数 |
| `ip_type` / `family` / `dual_stack` / `country_mismatch` | 出口 IP 类型分布 / 地址族分布 / 双栈数 / 错区数 |
| `age_s` / `updated_ago` / `stale` | 数据年龄（秒）/ 可读年龄（如 `4h ago`）/ 是否过期（超过 3h） |
| `history_records` / `alive_history_records` | 历史记录条数 |

### `data/valid/meta.json`

| 字段 | 含义 |
|---|---|
| `total` / `checked` / `alive` / `dead` | 总条目 / 实际检测数（含重试）/ 存活 / 失效 |
| `elapsed_s` / `checked_per_s` | 耗时（秒）/ 吞吐（条/秒） |
| `by_method` | 各判定方法（connect/tls）的存活数 |
| `latency` | 延迟统计（avg/median/p90/max） |
| `latency_dist` | 延迟分桶直方图（毫秒） |
| `speed` | 测速统计（avg/median/p90/max，MB/s） |
| `speed_dist` | 速度分桶直方图（MB/s） |
| `per_country` / `per_port` | 各国 / 各端口存活数 |
| `sets` | 各集合存活条数 |

### `data/valid/index.json`

单行 JSON 结构化索引，键为 `ip:port#国家`，值为 `[延迟ms, 检测方法]`，按延迟升序：

```json
{"proxies": {"1.2.3.4:443#US": [640.1, "tls"], "5.6.7.8:8443#JP": [80.1, "connect"]}}
```

### `data/valid/speed.json`

单行 JSON，键为 `ip:port#国家`，值为实测速度（MB/s，两位小数），按速度降序（仅含测速成功的代理）：

```json
{"proxies": {"5.6.7.8:8443#JP": 1.25, "1.2.3.4:443#US": 0.44}}
```

数据未变化时文件不变（避免无意义提交）。运行时间见 `meta.json` 的 `ts`。

### `data/valid/ipinfo.json`（质量 CI 输出）

单行 JSON，键为 `ip:port#国家`，值为出口 IP 信息：`exit_ip`、`family`（ipv4/ipv6/dual）、`dual_stack`、`country`/`country_code`/`region`/`city`（出口地理）、`asn`/`org`/`isp`、`proxy`/`hosting`/`mobile` 标志、`ip_type`（DC/RES/MOB/PROXY）、`listed_country` 与 `country_match`（是否错区）、`geo_checked`（是否查到出口地理）、`reputation`（0-100 信誉分）、`reputation_source`（netcoffee/ncgy/ip-api/ipdata/torlist/getipintel/ipapi_is/abuseipdb/ipqs，多源时为 multi）、`risk_sources`（参与合分的源列表）、`risk`（由信誉分推导或滥用分）。

### `data/valid/streaming.json`

单行 JSON，键为 `ip:port#国家`，值为各服务检测结果：`{netflix: {status, region, native}, disney: {...}, youtube: {...}, max: {...}, prime: {...}, openai: {...}}`。`status` ∈ `ok`/`blocked`/`error`；Netflix 的 `native` 表示解锁区域与出口地理一致（原生 IP）。

### `data/valid/quality_meta.json`

质量检测汇总（供 stats 消费）：`streaming`（各服务 ok/blocked/error 计数）、`streaming_ok`（任一解锁条目数）、`by_type`（IP 类型分布）、`family`/`dual_stack`（地址族分布）、`country_mismatch`（错区数）、`risk`、`abuse_checked`、`reputation_checked`（获分条数）、`rep_dist`（0-25/25-50/50-75/75-100 分桶）、`rep_avg`/`rep_median`。

### `data/valid/abuse.json`

提供滥用分 key 时输出：键为 `ip:port#国家`，值为 `{service, score, risk, ...}` 滥用分与标志。

### `data/valid/reputation.json`

单行 JSON，键为 `ip:port#国家`，值为 `{score, risk, source, sources}`：`score` 为 0-100 信誉分（越大越干净），`risk` 为 `high`（<30）/`medium`（<75）/`low`（≥75），`source` 为 `netcoffee`/`ncgy`/`ip-api`/`ipdata`/`torlist`/`getipintel`/`ipapi_is`/`abuseipdb`/`ipqs`（多源时为 `multi`），`sources` 为实际参与合分的源列表。按分数降序、同分按键序排列。

### `data/valid/all_rep.txt`

与 `all_ltd.txt` 同源（每国最快存活集）的**信誉排行**：被检测的行按信誉分降序（同分按延迟升序再按 IP 序），无分数条目排在末尾保持原序；每行携带完整备注（流媒体/类型/信誉分）。

### `data/history.jsonl`（每行一条）

`ts`、`total`、`unique`、`countries`、`ports`、`sets`、`added`、`removed`。数据未变化时跳过，最多保留最近 1000 条。

### `data/valid/history.jsonl`（每行一条）

`ts`、`total`、`checked`、`alive`、`dead`。与上一条完全相同则跳过，最多 1000 条。

## 脚本与 CLI

### `scripts/download_proxies.py`

下载、解压并整理代理列表。

| 参数 | 说明 | 默认 |
|---|---|---|
| `-u, --url` | 源压缩包地址 | `zip.cm.edu.kg` |
| `-t, --timeout` | 下载超时（秒） | 60 |
| `--per-country-limit` | 限量版每国条数（0 = 不生成） | 20 |

### `scripts/validate_proxies.py`

连通性验证与测速（asyncio）。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--source` | 输入代理列表 | `data/all.txt` |
| `--host` / `--target-port` | CONNECT 目标 | `cdnjs.cloudflare.com` / `443` |
| `--sni` | TLS 握手 SNI | `cdnjs.cloudflare.com` |
| `--speed-host` / `--speed-path` | 测速下载主机 / 路径 | `cdnjs.cloudflare.com` / `/ajax/libs/three.js/r128/three.min.js` |
| `--speed-bytes` | 测速单次读取字节上限 | 262144 |
| `--speed-timeout` | 测速单次时长上限（秒） | 5 |
| `--speed-workers` | 同时进行的下载测速并发上限 | 10 |
| `--no-speed` | 跳过速度测试（`_ltd` 回退按延迟） | 关 |
| `-t, --timeout` | 单代理超时（秒） | 5 |
| `-w, --workers` | asyncio 并发上限 | 500 |
| `--limit` | 只检测前 N 条（0 = 全部） | 0 |
| `--time-budget` | 最多执行秒数（0 = 不限） | 0 |
| `--per-country-limit` | `_ltd` 输出每国条数 | 20 |

### `scripts/generate_stats.py`

读取历史与验证汇总，生成统计与一组零依赖 SVG 图表。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--out` | 输出目录 | `data/` |
| `--data-dir` | 输入数据目录（含 `history.jsonl` 与 `valid/`） | `data/` |

| 输出文件 | 内容 |
|---|---|
| `chart.svg` | unique / alive 趋势折线图 |
| `chart_alive_rate.svg` | 存活率（%）随时间变化 |
| `chart_country.svg` | 存活代理按国家 top-15 横向条形图 |
| `chart_port.svg` | 存活代理按端口纵向条形图 |
| `chart_churn.svg` | 每次更新 added / removed 分组条形图 |
| `chart_combo.svg` | 双轴复合趋势（unique/alive 左轴 + 存活率右轴） |
| `chart_latency.svg` | 存活代理延迟分桶条形图（毫秒） |
| `chart_speed.svg` | 存活代理速度分桶条形图（MB/s） |
| `chart_streaming.svg` | 流媒体各服务解锁数条形图（质量 CI） |
| `chart_streaming.svg` | 流媒体各服务解锁数条形图（质量 CI 生成） |

### `scripts/quality_check.py`

流媒体解锁 + 出口 IP 质量检测（独立 CI 运行）。默认对 `data/valid/all_ltd.txt`（每国最快存活集）检测，按 `index.json` 记录的方法分流：

- **connect 方法**（标准 HTTP CONNECT 代理）：出口 IP 回显（`api.ipify.org`/`api6.ipify.org` 双栈）→ 本地 `ip-api.com/batch` 批量查地理/ASN/IP 类型 → 各流媒体服务经 CONNECT + TLS 隧道逐项检测
- **tls 方法**（Cloudflare 边缘）：仅能按 SNI 路由到 CF 托管域名，只做 ChatGPT/OpenAI（`chat.openai.com/cdn-cgi/trace`，取边缘机房 `loc`），备注 `CF`

| 参数 | 说明 | 默认 |
|---|---|---|
| `--source` | 输入代理列表 | `data/valid/all_ltd.txt` |
| `--services` | 检测服务（netflix disney youtube max prime openai） | 全部 |
| `--abuse-service` | 滥用分服务（none/abuseipdb/ipqs） | none |
| `--reputation-provider` | 信誉策略（multi/netcoffee/ip-api/none） | multi |
| `--reputation-sources` | multi 时启用的源（逗号分隔，见下） | netcoffee,ncgy,ip-api,ipdata,torlist |
| `--reputation-weights` | 权重覆盖，如 `netcoffee:40,ncgy:20` | 见下 |
| `-t, --timeout` | 单代理超时（秒） | 6 |
| `--read-cap` | 单次响应读取上限（字节） | 524288 |
| `-w, --workers` | asyncio 并发上限 | 40 |
| `--limit` | 只检测前 N 条（0 = 全部） | 0 |
| `--time-budget` | 最多执行秒数（0 = 不限） | 0 |

滥用分 key 从环境变量 `ABUSEIPDB_KEY`（abuseipdb）或 `IPQS_KEY`（ipqualityscore）读取，缺 key 时自动跳过。信誉分（0-100）多因子加权合成：abuse 分存在时取 `100 - score`（最高优先级）；否则按源分别计算 0-100 干净分 `s_i`，再按权重合并 `round(Σ w_i·s_i / Σ w_i)`（按实际响应源归一化）。默认源与权重：

| 源 | 权重 | 说明 |
|---|---|---|
| `netcoffee` | 35 | `ip.net.coffee/api/iprisk/{ip}`，`trust_score` 直用，标志罚分：abuser 40 / tor 35 / proxy 30 / vpn 25 / datacenter 15 |
| `ncgy` | 25 | `ip.nc.gy`（MaxMind 匿名 IP 库），`is_tor` 45 / `is_proxy` 30 / `is_vpn` 25 / `is_anonymous` 10 |
| `ip-api` | 15 | 本地批量地理的标志：proxy -25 / hosting -10（有标志才计入） |
| `ipdata` | 10 | `api.ipdata.co`，限速 50 次/分；tor 45 / proxy 30 / vpn 25 / anonymous 10 + `threat_score` |
| `torlist` | 5 | 官方 Tor 出口列表（`check.torproject.org/exit-addresses` + `dan.me.uk/torlist`），命中 -25 |

可选源（opt-in）：`getipintel`（5 权重，需环境变量 `GETIPINTEL_EMAIL`，1 worker、4s 间隔、上限 300 次/运行，得分 `100 - prob×100`）；`ipapi_is`（5 权重，`ipapi.is`，tor 45 / vpn 30 / proxy 25 / datacenter 15 / abuser 20）。单源响应时直接取该源分数；无任何信号则该项无分（不误判满分）。风险等级：`<30` high、`<75` medium、其余 low。`tls` 方法代理无出口回显，直接用代理自身 IP 查信誉。结果写入 `reputation.json` 与 `all_rep.txt`（按信誉降序），分数也追加进 `#` 备注末尾。检测结果见下方数据文件；备注写入按 `#` 后格式追加。

### `scripts/china_check.py`

大陆连通性检测（独立 CI 运行）。默认对 `data/valid/all_rep.txt` 按信誉降序采样前 250 条（缺失时回退 `all_ltd.txt`），从大陆视角实测 TCP 可达性，分三层判定：

- **L1 启发式（零网络）**：行备注已带 `-CF`（Cloudflare 边缘 tls 代理）即判大陆可达——这类代理走 CF 边缘节点，不依赖源站回程
- **L2 单节点实测（并发）**：`check-host.cc`（呼和浩特阿里云节点，匿名限速 6/10s、250/h，配置 key 可放宽）+ `xxapi.cn`（北京节点，免 key）。**任一成功 → reachable；二者均失败 → unreachable；单方失败 → uncertain（不误判）**
- **L3 多节点复核（串行小样本）**：`ping.pe`（约 13 个大陆节点，多数可达即判可达，报告不足则 inconclusive）；可选 `tcpping.cn`（多运营商，需 `TCPPING_CN_TOKEN`，缺 key 自动跳过）

| 参数 | 说明 | 默认 |
|---|---|---|
| `--source` | 输入代理列表 | `data/valid/all_rep.txt` |
| `--limit` | 按信誉降序采样条数（0=全部） | 250 |
| `--pingpe-limit` | ping.pe 多节点复核条数（串行） | 40 |
| `--workers` | L2 并发上限 | 8 |
| `-t, --timeout` | 单次 HTTP 超时（秒） | 10 |
| `--api-key` | check-host.cc key（读 `CHINA_CHECK_API_KEY`） | 空 |
| `--tcpping-token` | tcpping.cn token（读 `TCPPING_CN_TOKEN`） | 空 |
| `--skip-pingpe` | 跳过 ping.pe 复核（本地快速冒烟） | 关 |
| `--dry-run` | 只输出计划，不发请求不写盘 | 关 |

结果写入 `china.json`（keyed 明细，含各源 status/ms 与合成 verdict）与 `all_cn.txt`（大陆可达清单，含历史已判可达者）；可达者在 `all.txt`/`all_ltd.txt` 追加 `-CN` 备注（幂等）。

### `scripts/exit_family.py`

实际出口 IP 家族（IPv4/IPv6）检测（独立 CI 运行）。默认对 `data/valid/all.txt`（全量存活池）逐条探测真实出口家族，按方法分流：

- **tls 方法**（Cloudflare 边缘）：直连 TLS + SNI → `cloudflare.com/cdn-cgi/trace`，取回显 `ip=` 判 v4/v6（这类代理无法 CONNECT 到任意主机，只能经 CF 边缘回显）
- **connect 方法**（标准 HTTP CONNECT 代理）：经隧道双回显 `api.ipify.org`(v4) 与 `api6.ipify.org`(v6)，成功者分别判定对应家族

家族判定：仅 v4 → `ipv4`；仅 v6 → `ipv6`；双通 → `dual`；探测全失败 → `unknown`。结果写入：

- `all_ipv4.txt` / `all_ipv6.txt` — 按家族分离的代理清单（**双栈同时计入两个文件**，`unknown` 不入任何文件）
- `exit_family.json` — 逐条明细（keyed，含 `family`、`exit_v4`/`exit_v6`、`method`）
- 并在 `all.txt`/`all_ltd.txt` 对应行追加 `-V4`/`-V6`/`-DS` 备注（幂等，`DS` 与质量检测已有的双栈 token 一致）

| 参数 | 说明 | 默认 |
|---|---|---|
| `--source` | 输入代理列表 | `data/valid/all.txt` |
| `--limit` | 只检测前 N 条（0=全部） | 0 |
| `--workers` | 并发上限 | 16 |
| `-t, --timeout` | 单次连接超时（秒） | 10 |
| `--dry-run` | 只输出计划，不发请求不写盘 | 关 |

### `scripts/generate_fingerprint.py`

生成内部自洽的浏览器指纹（浏览器指纹生成工具）。

| 参数 | 说明 | 默认 |
|---|---|---|
| `-n, --count` | 生成数量 | 1 |
| `-s, --seed` | 随机种子（可复现） | 无 |
| `--pretty` | 格式化 JSON 输出 | 关 |

支持 5 类操作系统（windows/macos/linux/android/ios），每个指纹的 UA、平台、分辨率、时区、语言、WebGL 渲染器、canvas 哈希均取自同一设备配置：

```bash
python scripts/generate_fingerprint.py
python scripts/generate_fingerprint.py -n 5
python scripts/generate_fingerprint.py -n 1 -s 42 --pretty
```

示例输出：

```json
{"os": "macos", "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...", "platform": "MacIntel", "language": "en-US", "languages": ["en-US", "en"], "timezone": "Europe/Paris", "screen": {"width": 2560, "height": 1440, "colorDepth": 24, "devicePixelRatio": 2.0}, "hardwareConcurrency": 10, "deviceMemory": 16, "webgl": {"renderer": "ANGLE (Apple, Apple M1, OpenGL 4.1)", "vendor": "Apple"}, "canvasHash": "9f3b2c1d4e5a6b7c"}
```

## CI 自动更新

`.github/workflows/update-proxies.yml`：

- **触发**：每 30 分钟定时（`cron: */30 * * * *`）；支持 `workflow_dispatch` 手动触发；推送 `scripts/*.py` 时也会执行
- **流程**：跑测试（`unittest`）→ 下载整理 → 验证与测速（默认不设时间限制，跑完为止）→ 生成统计 → 展示统计 → 有变更则自动提交并推送回仓库
- **细节**：作业超时 60 分钟；`concurrency` 组防重入；`contents: write` 权限；以 `github-actions[bot]` 身份提交
- **徽章**：四个徽章分别取 `stats.json` 的 `unique`、`alive`、`alive_rate`、`updated_ago`；`badge.json` 驱动状态徽章（fresh/stale，超过 3 小时变红）

`.github/workflows/quality-check.yml`（流媒体/出口质量独立 CI）：

- **触发**：主更新工作流完成后自动执行（`workflow_run`）；支持 `workflow_dispatch`；每 3 小时 cron 兜底（主更新失败/未触发时仍出质量数据）
- **流程**：跑测试（`unittest`）→ `quality_check.py`（默认 `--time-budget 1800` 兜底）→ `generate_stats.py`（含 streaming 统计与 `chart_streaming.svg`）→ 有变更则自动提交并推送
- **细节**：作业超时 60 分钟；`concurrency` 组防重入；`contents: write` 权限；滥用分 key 经 secrets 注入 `ABUSEIPDB_KEY`/`IPQS_KEY`（未配置自动跳过）
- **说明**：主更新每 30 分钟重写 `data/valid/*.txt` 为无备注行，质量 CI 紧随其后重新加备注——两状态间存在短暂窗口，属独立 CI 固有节奏

`.github/workflows/china-check.yml`（大陆连通性独立 CI）：

- **触发**：每 6 小时定时（`cron: 17 */6 * * *`）；支持 `workflow_dispatch` 手动触发
- **流程**：跑测试（`unittest`）→ `china_check.py`（`--limit 250`，启发式 CF + check-host.cc + xxapi.cn + ping.pe 分层判定）→ 有变更则自动提交并推送
- **细节**：作业超时 60 分钟；`concurrency` 组防重入；`contents: write` 权限；check-host.cc key 与 tcpping.cn token 经 secrets 注入 `CHINA_CHECK_API_KEY`/`TCPPING_CN_TOKEN`（未配置自动跳过/降级）
- **说明**：复用质量 CI 的冲突容错提交（rebase `-X theirs`），与主更新/质量 CI 的并发 `data/` 提交安全共存

`.github/workflows/exit-family.yml`（实际出口家族独立 CI）：

- **触发**：每 6 小时定时（`cron: 31 */6 * * *`，与 china-check 错开）；支持 `workflow_dispatch` 手动触发
- **流程**：跑测试（`unittest`）→ `exit_family.py`（全量存活池按家族分离）→ 有变更则自动提交并推送
- **细节**：作业超时 60 分钟；`concurrency` 组防重入；`contents: write` 权限；无第三方依赖、无密钥
- **说明**：CF 边缘代理真实出口常为 IPv6（尽管呈现为 v4 地址），分离清单供按家族选路使用

## 目录结构

```
.github/workflows/update-proxies.yml   CI 自动更新（下载、验证、统计）
.github/workflows/quality-check.yml    独立 CI：流媒体解锁 + 出口 IP 质量检测
.github/workflows/china-check.yml       独立 CI：大陆连通性检测
.github/workflows/exit-family.yml       独立 CI：实际出口 IPv4/IPv6 分离
scripts/download_proxies.py            下载与解压整理
scripts/validate_proxies.py            可用性验证与测速
scripts/generate_stats.py              统计与趋势图
scripts/quality_check.py               流媒体解锁与出口 IP 质量检测
scripts/china_check.py                 大陆连通性检测（CF 启发式 + check-host + xxapi + ping.pe）
scripts/exit_family.py                 实际出口 IP 家族检测与分离（tls trace + connect 双回显）
scripts/generate_fingerprint.py        浏览器指纹生成
data/raw/<port>/<country>.txt          按端口+国家的原始组织（含 #ALL，ip:port#国家）
data/countries/<country>.txt           按国家汇总（跨端口去重）
data/ports/<port>.txt                  按端口汇总（跨国家去重）
data/sets/<集合>.txt                   常用国家集合（europe、asia、hot、cn_common 等）
data/sets/<集合>_ltd.txt               限量版（每国 --per-country-limit 条）
data/all.txt                           全量去重 ip:port#国家（IP 数字序）
data/all_ltd.txt                       全部国家每国限量后的并集
data/valid/                            存活代理（结构同 data/，按延迟排序，_ltd 按速度排序，含 meta.json、index.json、speed.json、history.jsonl）
data/valid/ipinfo.json                 出口 IP 地理 / 类型 / 双栈 / 信誉分（质量 CI）
data/valid/streaming.json              各服务流媒体解锁结果（质量 CI）
data/valid/quality_meta.json           质量检测汇总（质量 CI）
data/valid/abuse.json                  滥用分结果（配置 key 时生成，质量 CI）
data/valid/reputation.json             信誉分索引（0-100，质量 CI）
data/valid/all_rep.txt                 信誉排行（按分数降序，质量 CI）
data/valid/china.json                  大陆连通性检测明细（keyed，china-check CI）
data/valid/all_cn.txt                  大陆可达清单（china-check CI）
data/valid/all_ipv4.txt                出口为 IPv4 的代理清单（exit-family CI，双栈双入）
data/valid/all_ipv6.txt                出口为 IPv6 的代理清单（exit-family CI，双栈双入）
data/valid/exit_family.json            实际出口家族明细（keyed，exit-family CI）
data/diff/latest.json                  最近一次更新差异（added/removed）
data/diff/<时间戳>.json                按次归档的差异（最多 500 份）
data/stats.json                        统计汇总（供徽章与外部消费）
data/chart.svg                         趋势折线图（unique 与 alive 随时间变化）
data/chart_alive_rate.svg              存活率（%）随时间变化折线图
data/chart_country.svg                 存活代理按国家 top-15 条形图
data/chart_port.svg                    存活代理按端口条形图
data/chart_churn.svg                   每次更新 added/removed 条形图
data/chart_combo.svg                   双轴复合趋势（计数 + 存活率）
data/chart_latency.svg                 存活代理延迟分桶条形图
data/chart_speed.svg                   存活代理速度分桶条形图（MB/s）
data/history.jsonl                     更新历史记录（每行一条，最多 1000 条）
tests/                                 标准库 unittest 测试套件
```

## 免责声明

本项目提供的代理 IP 列表来自公开来源，仅限学习与研究用途。使用代理访问网络时请遵守当地法律法规及目标网站的服务条款；本项目不对列表内容的可用性、合法性及由此产生的任何后果负责。
