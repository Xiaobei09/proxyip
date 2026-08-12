# proxyip

定期从 <https://zip.cm.edu.kg> 下载代理 IP 列表并通过 CI 自动解压、整理、验证、提交回仓库；附带一个浏览器指纹生成工具。整个流程零第三方 Python 依赖，仅需标准库。

[![Unique Proxies](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=unique&label=Unique%20Proxies&color=blue)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/all.txt)
[![Alive](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=alive&label=Alive&color=green)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/all.txt)
[![Alive Rate](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=alive_rate&label=Alive%20Rate&color=orange)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/meta.json)
[![Updated](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=updated_at&label=Updated&color=informational)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json)

![Trend](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart.svg)
![Alive rate](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_alive_rate.svg)
![Country distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_country.svg)
![Port distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_port.svg)
![Churn](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_churn.svg)
![Composite trend](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart_combo.svg)

## 功能特性

- **自动抓取整理**：下载上游 zip → 按端口/国家/常用集合/全量多维度汇总，去重合并
- **可用性验证**：HTTP CONNECT + TLS 双重检测，asyncio 高并发测活与测速，输出**按延迟升序**
- **更新差异**：每次更新自动对比上一版，产出 `added`/`removed` 并归档
- **统计与趋势**：生成 `stats.json`（供徽章消费）与零依赖 SVG 图表组：趋势、存活率、国家/端口分布、更新增量与双轴复合图
- **CI 自动化**：每 30 分钟全自动执行下载→验证→统计→提交，无需人工干预
- **浏览器指纹生成**：生成内部自洽、同一设备配置的 UA/分辨率/时区/WebGL 等指纹

## 快速开始

### 系统要求

- Python 3.11+（使用了 `asyncio.timeout` 与 `dict[str, ...]` 等新语法）
- 无任何第三方依赖，仅标准库

### 运行

```bash
git clone https://github.com/Xiaobei09/proxyip.git
cd proxyip

python scripts/download_proxies.py          # 1. 下载解压整理
python scripts/validate_proxies.py --time-budget 180   # 2. 连通性验证（限时 180s）
python scripts/generate_stats.py            # 3. 统计与趋势图
```

### 消费数据

所有文件统一 `ip:port#国家` 格式（如 `1.2.3.4:443#US`），按 IP 数字序排列。

```bash
head -1 data/valid/all.txt                  # 当前最快的存活代理（延迟升序）
data/valid/all_ltd.txt                      # 每国最快 20 条的限量清单
data/valid/countries/US.txt                 # 仅美国的存活代理
data/valid/ports/443.txt                    # 仅 443 端口的存活代理
data/sets/hot.txt                           # 热门国家集合
data/all.txt                                # 全量去重清单（未验证）
```

## 数据规范

### 格式

- 每行一条 `ip:port#国家代号`，例如 `1.2.3.4:443#US`
- **去重**：同一 `ip:port` 组合全局唯一
- **排序**：按 IP 数字序（八位组数值比较，`1.2.3.4 < 10.0.0.1`；`data/valid/` 内按延迟升序）

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
- 验证侧 `data/valid/*_ltd.txt`：每国取延迟最低的 20 条
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

CI 每次更新后对 `data/all.txt` 做连通性检查，输出镜像 `data/` 结构的存活列表到 `data/valid/`，全部**按延迟升序**（最快在前）。

### 双重检测算法

对每个代理依次尝试两种方法，任一成功即判定存活：

1. **HTTP CONNECT 隧道**：向代理发送 `CONNECT www.gstatic.com:443 HTTP/1.1`，响应 `200` 即通
2. **TLS 握手兜底**：对代理自身做 TLS 握手（SNI=`cdnjs.cloudflare.com`），用于 Cloudflare 边缘代理——这类代理在 443/8443/2053/2083/2087/2096 提供 TLS 服务但拒绝纯 CONNECT

### 并发与容错

- **asyncio 并发**：默认 500 个在飞任务（`-w` 可调），有界任务池实现严格限时
- **超时**：单代理 5s（`-t`）；CONNECT 响应读取独立 3s 上限
- **自动重试**：TCP 能连通但两项检测均超时的代理，短暂间隔后重试一次，降低单次丢包误杀
- **时间预算**：`--time-budget N` 到时立即停止（CI 用 180s），到期只取消少量在飞任务

### 输出

- `data/valid/all.txt`、`all_ltd.txt`：存活代理（保持 `ip:port#国家` 格式，按延迟排序）
- `data/valid/countries/`、`ports/`、`sets/`：按国家/端口/集合分组的存活列表
- `data/valid/meta.json`：本次验证汇总（字段见下）
- `data/valid/history.jsonl`：每次验证的历史记录（最多 1000 条，供趋势图）

### 常用命令

```bash
python scripts/validate_proxies.py                    # 验证全部
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
| `history_records` / `alive_history_records` | 历史记录条数 |

### `data/valid/meta.json`

| 字段 | 含义 |
|---|---|
| `total` / `checked` / `alive` / `dead` | 总条目 / 实际检测数（含重试）/ 存活 / 失效 |
| `elapsed_s` / `checked_per_s` | 耗时（秒）/ 吞吐（条/秒） |
| `by_method` | 各判定方法（connect/tls）的存活数 |
| `latency` | 延迟统计（avg/median/p90/max） |
| `per_country` / `per_port` | 各国 / 各端口存活数 |
| `sets` | 各集合存活条数 |

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
| `--host` / `--target-port` | CONNECT 目标 | `www.gstatic.com` / `443` |
| `--sni` | TLS 握手 SNI | `cdnjs.cloudflare.com` |
| `-t, --timeout` | 单代理超时（秒） | 5 |
| `-w, --workers` | asyncio 并发上限 | 500 |
| `--limit` | 只检测前 N 条（0 = 全部） | 0 |
| `--time-budget` | 最多执行秒数（0 = 不限） | 0 |
| `--per-country-limit` | `_ltd` 输出每国条数 | 20 |

### `scripts/generate_stats.py`

读取历史与验证汇总，生成统计与一组零依赖 SVG 图表。参数：`--out`（输出目录，默认 `data/`）。

| 输出文件 | 内容 |
|---|---|
| `chart.svg` | unique / alive 趋势折线图 |
| `chart_alive_rate.svg` | 存活率（%）随时间变化 |
| `chart_country.svg` | 存活代理按国家 top-15 横向条形图 |
| `chart_port.svg` | 存活代理按端口纵向条形图 |
| `chart_churn.svg` | 每次更新 added / removed 分组条形图 |
| `chart_combo.svg` | 双轴复合趋势（unique/alive 左轴 + 存活率右轴） |

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
- **流程**：下载整理 → 验证（`--time-budget 180`）→ 生成统计 → 展示统计 → 有变更则自动提交并推送回仓库
- **细节**：作业超时 20 分钟；`concurrency` 组防重入；`contents: write` 权限；以 `github-actions[bot]` 身份提交
- **徽章**：四个徽章分别取 `stats.json` 的 `unique`、`alive`、`alive_rate`、`updated_at`

## 目录结构

```
.github/workflows/update-proxies.yml   CI 自动更新（下载、验证、统计）
scripts/download_proxies.py            下载与解压整理
scripts/validate_proxies.py            可用性验证与测速
scripts/generate_stats.py              统计与趋势图
scripts/generate_fingerprint.py        浏览器指纹生成
data/raw/<port>/<country>.txt          按端口+国家的原始组织（含 #ALL，ip:port#国家）
data/countries/<country>.txt           按国家汇总（跨端口去重）
data/ports/<port>.txt                  按端口汇总（跨国家去重）
data/sets/<集合>.txt                   常用国家集合（europe、asia、hot、cn_common 等）
data/sets/<集合>_ltd.txt               限量版（每国 --per-country-limit 条）
data/all.txt                           全量去重 ip:port#国家（IP 数字序）
data/all_ltd.txt                       全部国家每国限量后的并集
data/valid/                            存活代理（结构同 data/，按延迟排序，含 meta.json、history.jsonl）
data/diff/latest.json                  最近一次更新差异（added/removed）
data/diff/<时间戳>.json                按次归档的差异（最多 500 份）
data/stats.json                        统计汇总（供徽章与外部消费）
data/chart.svg                         趋势折线图（unique 与 alive 随时间变化）
data/chart_alive_rate.svg              存活率（%）随时间变化折线图
data/chart_country.svg                 存活代理按国家 top-15 条形图
data/chart_port.svg                    存活代理按端口条形图
data/chart_churn.svg                   每次更新 added/removed 条形图
data/chart_combo.svg                   双轴复合趋势（计数 + 存活率）
data/history.jsonl                     更新历史记录（每行一条，最多 1000 条）
```

## 免责声明

本项目提供的代理 IP 列表来自公开来源，仅限学习与研究用途。使用代理访问网络时请遵守当地法律法规及目标网站的服务条款；本项目不对列表内容的可用性、合法性及由此产生的任何后果负责。
