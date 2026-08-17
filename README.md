# proxyip

定期从 <https://zip.cm.edu.kg> 下载代理 IP 列表并通过 CI 自动解压、整理、验证、提交回仓库；附带一个浏览器指纹生成工具。整个流程零第三方 Python 依赖，仅需标准库。

[![Unique Proxies](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json&query=unique&label=Unique%20Proxies&color=blue)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/download/all.txt)
[![Alive](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json&query=alive&label=Alive&color=green)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/all.txt)
[![Alive Rate](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json&query=alive_rate&label=Alive%20Rate&color=orange)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/meta.json)
[![Updated](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json&query=updated_ago&label=Updated&color=informational)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json)
[![Status](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/badge.json)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json)

![Trend](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_combo.svg)
![Country distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_country.svg)
![Port distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_port.svg)
![Churn](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_churn.svg)
![Latency & Speed distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_latency_speed.svg)
![Streaming unlock](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_streaming.svg)
![Sets](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_sets.svg)
![Mainland China reachability](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_cn.svg)
![Exit IP family](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_family.svg)
![IP source availability](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_source_avail.svg)
![IP source stats](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_source_stats.svg)
![Reputation score](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_rep.svg)

## 功能特性

- **自动抓取整理**：下载上游 `all.json`（失败自动回退 zip）→ 按端口/国家/常用集合/全量多维度汇总，去重合并；并把上游真实出口 IP、ASN、地理等元数据落盘为 `data/quality/upstream_meta.json` 供下游消费
- **可用性验证**：TLS 双重检测，asyncio 高并发测活，并在判活连接内**真实下载测速**（MB/s）；非限量输出**按延迟升序**，**`_ltd` 限量清单按实测速度取每国最快**
- **流媒体解锁 + 出口 IP 质量检测**（独立 CI）：对每国最快的限量存活集做 Netflix（含原生 IP 判定）/ Disney+ / YouTube Premium / Max / Prime Video / ChatGPT 解锁检测、出口 IP 地理与类型（机房/住宅/移动）、双栈判定与可选滥用分，结果按既有格式以 `-` 段追加备注到 `data/valid/*.txt`
- **大陆连通性检测**（独立 CI）：以大陆视角实测代理池是否可用（GFW 视角 TCP 可达性），启发式 CF 边缘判定 + itdog.cn 批量 + check-host.cc / xxapi.cn 单节点实测 + ping.pe 多运营商复核，产出 `data/quality/china.json` 全量明细与 `data/valid/all_cn.txt` 全量大陆可达清单，并在 `data/valid/*.txt` 追加 `-CN` 备注
- **实际出口家族检测**（独立 CI）：探测每个存活代理的真实出口 IP 家族（IPv4/IPv6）——CF 边缘代理虽以 v4 地址呈现，实际出口常为 v6；按家族分离保存 `all_ipv4.txt` / `all_ipv6.txt`（双栈双入）并在 `data/valid/*.txt` 追加 `-V4`/`-V6`/`-DS` 备注；同时对照上游 `data/quality/upstream_meta.json` 的真实出口 `clientIp` 交叉验证（`data/quality/exit_family.json` 记录 `upstream_match`）
- **更新差异**：每次更新自动对比上一版，产出 `added`/`removed` 并归档
- **统计与趋势**：生成 `data/output/stats.json`（供徽章消费）与零依赖 SVG 图表组：趋势、存活率、国家/端口分布、延迟/速度分布、更新增量、双轴复合图、集合规模、大陆可达性、出口家族与信誉分分布
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
`ip:port#🇺🇸US-120ms-0.44MB/s`（国旗+国家-延迟毫秒-速度 MB/s，测速失败时省略速度段），**按延迟升序**（`_ltd` 按速度降序）。被质量 CI 检测后行内追加 `→` 出口地区与备注段（见下方格式）。

```bash
head -1 data/valid/all.txt                  # 当前延迟最低的存活代理（延迟升序）
data/valid/all_ltd.txt                      # 每国按实测速度最快的 20 条限量清单
data/valid/countries/US/all.txt            # 仅美国的存活代理（含延迟/速度）
data/valid/countries/US/ltd.txt            # 该国限量（每国最快 20 条，速度降序）
data/valid/countries/US/v4.txt             # 该国出口为 IPv4 的代理（仅 v4-only，不含双栈）
data/valid/countries/US/46.txt             # 该国出口为双栈（v4+v6）的代理
data/valid/countries/US/cn.txt             # 该国大陆可达的代理
data/valid/countries/US/cn4.txt            # 该国大陆可达且出口为 IPv4 的代理
data/valid/countries/US/rep.txt            # 该国按信誉分降序（质量 CI 生成）
data/valid/sets/europe/all.txt             # 欧洲集合存活代理（集合也是目录多件套）
data/valid/all_46.txt                      # 全部出口为双栈的代理（根级分组）
data/valid/ports/443.txt                    # 仅 443 端口的存活代理
data/valid/speed.json                       # 每存活代理的实测速度（MB/s，按速度降序）
data/valid/sets/hot/all.txt                 # 热门国家集合（验证后）
data/download/all.txt                       # 全量去重清单（未验证）
```
## 文档

- [数据规范与数据文件参考](docs/data-spec.md) — 行格式与备注段、限量版规则、国家集合、验证算法、各数据文件字段
- [脚本与 CLI 参考](docs/scripts.md) — 全部入口脚本的参数/默认值/行为、`common.py` 与拆分子模块说明


## CI 自动更新

`.github/workflows/update-proxies.yml`：

- **触发**：每 30 分钟定时（`cron: */30 * * * *`）；支持 `workflow_dispatch` 手动触发；推送 `scripts/*.py` 时也会执行
- **流程**：跑测试（`unittest`）→ 下载整理（上游 `all.json`，失败回退 zip，产出 `data/quality/upstream_meta.json`）→ 验证与测速（默认不设时间限制，跑完为止）→ 生成统计 → 展示统计 → 有变更则自动提交并推送回仓库
- **细节**：作业超时 60 分钟；`concurrency` 组防重入；`contents: write` 权限；以 `github-actions[bot]` 身份提交
- **徽章**：四个徽章分别取 `data/output/stats.json` 的 `unique`、`alive`、`alive_rate`、`updated_ago`；`data/output/badge.json` 驱动状态徽章（fresh/stale，超过 3 小时变红）

`.github/workflows/quality-check.yml`（流媒体/出口质量独立 CI）：

- **触发**：每次 `Update proxy list` 完成后自动触发（`workflow_run`）；支持 `workflow_dispatch` 手动触发
- **流程**：跑测试（`unittest`）→ `quality_check.py`（`--source data/valid/all.txt` 全量存活池；`--time-budget 5400` 兜底；信誉信号按 IP 缓存 7 天，见上文信誉缓存）→ `reorg_country.py`（按出口国家重组 country/set/port 文件，改写 `#CC`）→ `generate_stats.py`（含 streaming 统计与 `chart_streaming.svg`）→ 有变更则自动提交并推送
- **细节**：作业超时 120 分钟；`concurrency` 组防重入；`contents: write` 权限；滥用分 key 经 secrets 注入 `ABUSEIPDB_KEY`/`IPQS_KEY`（未配置自动跳过）
- **说明**：主更新每 30 分钟重写 `data/valid/*.txt`，但会保留旧行已有备注（流媒体/出口/信誉/`-CN`），故质量/大陆连通性标注可跨重生成存续；仅新增存活行在下次质量/连通性 CI 前暂缺备注，属独立 CI 固有节奏

`.github/workflows/china-check.yml`（大陆连通性独立 CI）：

- **触发**：每次 `Update proxy list` 完成后自动触发（`workflow_run`）；支持 `workflow_dispatch` 手动触发
- **流程**：跑测试（`unittest`）→ `china_check.py`（对 `data/valid/all.txt` 全量池，`--limit 0`，启发式 CF + itdog 批量 + check-host.cc + xxapi.cn + ping.pe 分层判定）→ 有变更则自动提交并推送
- **细节**：作业超时 180 分钟；`concurrency` 组防重入；`contents: write` 权限；check-host.cc key 与 tcpping.cn token 经 secrets 注入 `CHINA_CHECK_API_KEY`/`TCPPING_CN_TOKEN`（未配置自动跳过/降级）
- **说明**：各工作流按文件所有权范围提交 `data/`（update-proxies 不触碰 `data/quality/china.json`/`data/valid/all_cn.txt`），与主更新/质量 CI 的并发提交安全共存

`.github/workflows/exit-family.yml`（实际出口家族独立 CI）：

- **触发**：每次 `Update proxy list` 完成后自动触发（`workflow_run`）；支持 `workflow_dispatch` 手动触发
- **流程**：跑测试（`unittest`）→ `exit_family.py`（全量存活池按家族分离，并对照 `data/quality/upstream_meta.json` 交叉验证）→ 有变更则自动提交并推送
- **细节**：作业超时 60 分钟；`concurrency` 组防重入；`contents: write` 权限；无第三方依赖、无密钥
- **说明**：CF 边缘代理真实出口常为 IPv6（尽管呈现为 v4 地址），分离清单供按家族选路使用；上游交叉验证仅作参照，实时探测仍是判定依据

`.github/workflows/annotate-classify.yml`（后缀填充 + 节点分类）：

- **触发**：quality-check 完成后自动触发（`workflow_run`）；支持 `workflow_dispatch` 手动触发
- **流程**：跑测试（`unittest`）→ `annotate_classify.py`（读取 5 个 JSON 数据源，填充缺失后缀 + 追加分类 token）→ `generate_stats.py` → 有变更则自动提交并推送
- **细节**：作业超时 30 分钟；`concurrency` 组防重入；`contents: write` 权限；无第三方依赖、无密钥
- **说明**：分类维度：IP 类型（DC/RES/MOB/PROXY，来自 ipinfo.json）+ 速度等级（fast≥5MB/s / mid 1-5 / slow<1，来自行内 speed 解析）。行格式：`...-DC-fast`

## 目录结构

```
.github/workflows/update-proxies.yml     CI 自动更新（下载、验证、统计）
.github/workflows/quality-check.yml      独立 CI：流媒体解锁 + 出口 IP 质量检测
.github/workflows/china-check.yml        独立 CI：大陆连通性检测
.github/workflows/exit-family.yml        独立 CI：实际出口 IPv4/IPv6 分离
.github/workflows/annotate-classify.yml  独立 CI：后缀填充 + 节点分类
scripts/download_proxies.py              下载与解压整理
scripts/validate_proxies.py              可用性验证与测速
scripts/generate_stats.py                统计与趋势图
scripts/quality_check.py                 流媒体解锁与出口 IP 质量检测（入口）
scripts/quality_reputation.py            信誉分/滥用分模块（quality_check 拆分）
scripts/quality_streaming.py             流媒体解锁模块（quality_check 拆分）
scripts/reorg_country.py                 按出口国家重组 country/set/port 文件
scripts/china_check.py                   大陆连通性检测（CF 启发式 + check-host + xxapi + ping.pe）
scripts/china_itdog.py                   itdog.cn 批量探活模块（china_check 拆分）
scripts/exit_family.py                   实际出口 IP 家族检测与分离（tls trace + connect 双回显）
scripts/generate_fingerprint.py          浏览器指纹生成
scripts/annotate_classify.py             后缀填充 + 节点分类（CI 自动运行）
scripts/common.py                        共享常量与助手（data 布局、HTTP/JSON 探测）

data/download/                           下载产出（原始代理列表）
data/download/all.txt                    全量去重 ip:port#国家（IP 数字序）
data/download/all_ltd.txt                全部国家每国限量后的并集
data/download/countries/<CC>.txt         按国家汇总（跨端口去重）
data/download/ports/<port>.txt           按端口汇总（跨国家去重）
data/download/sets/<集合>.txt            常用国家集合（europe、asia、hot、cn_common 等）
data/download/sets/<集合>_ltd.txt        限量版（每国 --per-country-limit 条）

data/valid/                              验证后代理数据
data/valid/all.txt                       存活代理（按延迟排序）
data/valid/all_ltd.txt                   限量版（每国最快 20 条，速度降序）
data/valid/all_cn*.txt                   变体（cn、cn4、cn6、cn46、cn46_ltd 等）
data/valid/all_ipv4.txt                  出口为 IPv4 的代理清单（exit-family CI，双栈双入）
data/valid/all_ipv6.txt                  出口为 IPv6 的代理清单（exit-family CI，双栈双入）
data/valid/all_rep.txt                   信誉排行（按分数降序，质量 CI）
data/valid/all_cn.txt                    全量大陆可达清单（全量池，china-check CI）
data/valid/countries/<CC>/               按国家分组（all.txt、ltd.txt、v4.txt、v6.txt、46.txt、cn.txt、rep.txt 等）
data/valid/ports/<port>.txt              按端口分组
data/valid/sets/<name>/                  按集合分组
data/valid/index.json                    代理索引（延迟与检测方法）
data/valid/speed.json                    实测速度索引
data/valid/meta.json                     验证摘要
data/valid/history.jsonl                 验证历史

data/quality/                            质量/检测元数据
data/quality/ipinfo.json                 出口 IP 地理/类型/信誉分（质量 CI）
data/quality/streaming.json              各服务流媒体解锁结果（质量 CI）
data/quality/abuse.json                  滥用分结果（配置 key 时生成，质量 CI）
data/quality/quality_meta.json           质量检测汇总（质量 CI）
data/quality/reputation.json             信誉分索引（0-100，质量 CI）
data/quality/reputation_cache.json       信誉信号缓存（7 天 TTL）
data/quality/external_check.json         外部 API 验证结果
data/quality/china.json                  大陆连通性检测明细（keyed，china-check CI）
data/quality/exit_family.json            实际出口家族明细（keyed，含上游交叉验证，exit-family CI）
data/quality/upstream_meta.json          上游 all.json 逐 IP 元数据（真实出口 clientIp / ASN / 地理 / colo）
data/quality/source_stats.json           下载源统计（各源 IP 数与重叠）
data/quality/history.jsonl               更新历史记录（每行一条，最多 1000 条）

data/output/                             展示输出
data/output/stats.json                   统计汇总（供徽章与外部消费）
data/output/badge.json                   状态徽章（fresh/stale）
data/output/chart_combo.svg              代理计数 + 存活率双轴折线图
data/output/chart_country.svg            存活代理按国家 top-15 条形图
data/output/chart_port.svg               存活代理按端口条形图
data/output/chart_churn.svg              每次更新 added/removed 条形图
data/output/chart_latency_speed.svg      延迟与速度分桶双面板条形图
data/output/chart_streaming.svg          各服务流媒体解锁 ok/blocked/error 堆叠条形图
data/output/chart_sets.svg               各命名集合存活代理条形图
data/output/chart_cn.svg                 大陆连通性 verdict 分布条形图
data/output/chart_family.svg             实际出口 IP 家族分布条形图
data/output/chart_source_avail.svg       IP 来源可用性图表
data/output/chart_rep.svg                信誉分分布条形图

data/raw/<port>/<CC>.txt                 下载中间产物（不入库，可重建）
data/diff/                               更新差异归档（不入库）
tests/                                   标准库 unittest 测试套件
archive/Check_Proxy.js                   遗留的单节点连通性检查脚本（已停用归档）
```

## 免责声明

本项目提供的代理 IP 列表来自公开来源，仅限学习与研究用途。使用代理访问网络时请遵守当地法律法规及目标网站的服务条款；本项目不对列表内容的可用性、合法性及由此产生的任何后果负责。
