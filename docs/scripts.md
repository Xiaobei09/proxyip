# 脚本与 CLI

本文件归档全部入口脚本的参数、默认值与行为说明（含 `common.py` 共享模块与拆分子模块）。各脚本仍以 `python scripts/<name>.py` 独立运行。

## 脚本与 CLI

### `scripts/download_proxies.py`

下载、解压并整理代理列表。主源为上游 `all.json`（含每条代理的真实出口 `clientIp`、ASN、地理、colo 元数据）；`all.json` 不可达时自动回退旧版 zip 归档，保证定时 CI 不中断。解析后除输出多维清单外，还将按 IP 汇总的元数据写为 `data/quality/upstream_meta.json`。

| 参数 | 说明 | 默认 |
|---|---|---|
| `-u, --url` | 源地址（默认上游 `all.json`，失败回退 zip） | `zip.cm.edu.kg` |
| `-t, --timeout` | 下载超时（秒） | 60 |
| `--per-country-limit` | 限量版每国条数（0 = 不生成） | 20 |
| `--extra-source KIND,URL` | 追加一个补充来源（`plain`/`ip`/`csv`，可重复） | 无 |
| `--no-extra-sources` | 跳过内置 CF 反代补充来源 | 关 |

#### CF 反代补充来源

除主源外，默认还会拉取一批 **Cloudflare 反代（非官方 CF 段）** 来源并合并：`wentao883/TG-wxgqlfx_ZBDW`（`fdip`/`vlid`/`yxip`）、`ChatBotPlus/cf-proxyips`、`ymyuuu/IPDB`（`BestProxy/proxy.txt` 与 `bestproxy&country.txt`）、`mountain787/Lunch-Bag-ip`。解析方式分三种：`plain`（`ip:port#国家`/`ip:port#中文`）、`ip`（裸 IP，统一按 443 端口）、`csv`（`IP,端口,地区,延迟`，地区为机场码或国家码）。中文名与机场码经映射表归一为 ISO2；仍无国家的条目经 `ip-api.com/batch` 尽力补齐（每批 100、失败保留 `#ALL`）。单个来源失败仅告警跳过，不影响整体运行。

### `scripts/validate_proxies.py`

连通性验证与测速（asyncio）。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--source` | 输入代理列表 | `data/download/all.txt` |
| `--sni` | TLS 握手 SNI | `cdnjs.cloudflare.com` |
| `--speed-host` / `--speed-path` | 测速下载主机 / 路径 | `cdnjs.cloudflare.com` / `/ajax/libs/three.js/r128/three.js` |
| `--speed-bytes` | 测速单次读取字节上限 | 1048576 |
| `--speed-timeout` | 测速单次时长上限（秒） | 5 |
| `--speed-workers` | 同时进行的下载测速并发上限 | 30 |
| `--no-speed` | 跳过速度测试（`_ltd` 回退按延迟） | 关 |
| `-t, --timeout` | 单代理超时（秒） | 5 |
| `-w, --workers` | asyncio 并发上限 | 500 |
| `--limit` | 只检测前 N 条（0 = 全部） | 0 |
| `--time-budget` | 最多执行秒数（0 = 不限） | 0 |
| `--per-country-limit` | `_ltd` 输出每国条数 | 20 |

除 `all.txt`/`ltd.txt` 外，每个国家/集合目录还会按 **出口家族 × 大陆可达** 生成分组文件 `v4.txt`/`v6.txt`/`46.txt`/`cn.txt`/`cn4.txt`/`cn6.txt`/`cn46.txt`（含对应 `*_ltd.txt`），根级另生成 `all_46.txt`/`all_cn4.txt`/`all_cn6.txt`/`all_cn46.txt`（含 `*_ltd.txt`）。家族优先取自 `exit_family.json`（缺失时回退行内 `-V4`/`-V6`/`-DS`），大陆可达取自行内 `-CN`；空组不落盘并清理残留。详见 `docs/data-spec.md`「分组文件」。

### `scripts/generate_stats.py`

读取历史与验证汇总，生成统计与一组零依赖 SVG 图表。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--out` | 输出目录 | `data/output/` |
| `--data-dir` | 输入数据目录（含 `quality/history.jsonl` 与 `valid/`） | `data/` |

| 输出文件 | 内容 |
|---|---|
| `chart_combo.svg` | 代理计数 + 存活率双轴折线图 |
| `chart_country.svg` | 存活代理按国家 top-15 横向条形图 |
| `chart_port.svg` | 存活代理按端口纵向条形图 |
| `chart_churn.svg` | 每次更新 added / removed 分组条形图 |
| `chart_latency_speed.svg` | 延迟与速度分桶双面板条形图 |
| `chart_streaming.svg` | 流媒体各服务 ok/blocked/error 堆叠条形图 |
| `chart_sets.svg` | 各命名集合存活代理条形图 |
| `chart_cn.svg` | 大陆连通性 verdict 分布条形图 |
| `chart_family.svg` | 实际出口 IP 家族分布条形图 |
| `chart_source_avail.svg` | IP 来源覆盖率 + 每代理源数量分布 |
| `chart_source_stats.svg` | 每下载来源 IP 数量与重叠分布 |
| `chart_rep.svg` | 信誉分分布条形图 |

### `scripts/quality_check.py`

流媒体解锁 + 出口 IP 质量检测（独立 CI 运行）。默认对 `data/valid/all.txt`（全量存活池）检测，所有代理使用统一的 TLS 直连方法：

- 对每个代理建立 TLS 直连（SNI=服务域名），检测 ChatGPT/OpenAI（`chat.openai.com/cdn-cgi/trace`，取边缘机房 `loc`），备注 `CF`；`loc` 机场码同时写入行备注的 `→` 出口地区段
- 批量查出口 IP 地理（`ip-api.com/batch`）与 ASN/IP 类型

| 参数 | 说明 | 默认 |
|---|---|---|
| `--source` | 输入代理列表 | `data/valid/all.txt` |
| `--services` | 检测服务（netflix disney youtube max prime openai） | 全部 |
| `--abuse-service` | 滥用分服务（none/abuseipdb/ipqs） | none |
| `--reputation-provider` | 信誉策略（multi/netcoffee/ip-api/none） | multi |
| `--reputation-sources` | multi 时启用的源（逗号分隔，见下） | netcoffee,ncgy,ip-api,ipquery,ffraud,blackbox,otx,ipsum,ipapi_is,ipdata,whatismyip,dc_asn,abuse_list,torlist,vpn_asn,resproxy_asn |
| `--reputation-weights` | 权重覆盖，如 `netcoffee:40,ncgy:20` | 见下 |
| `--rep-cache-ttl` | 信誉信号缓存有效期（秒） | 604800（7 天） |
| `--no-rep-cache` | 禁用信誉信号缓存 | 关 |
| `-t, --timeout` | 单代理超时（秒） | 6 |
| `--read-cap` | 单次响应读取上限（字节） | 524288 |
| `-w, --workers` | asyncio 并发上限 | 60 |
| `--limit` | 只检测前 N 条（0 = 全部） | 0 |
| `--time-budget` | 最多执行秒数（0 = 不限） | 0 |

滥用分 key 从环境变量 `ABUSEIPDB_KEY`（abuseipdb）或 `IPQS_KEY`（ipqualityscore）读取，缺 key 时自动跳过。信誉分（0-100）多因子加权合成：abuse 分存在时取 `100 - score`（最高优先级）；否则按源分别计算 0-100 干净分 `s_i`，再按权重合并 `round(Σ w_i·s_i / Σ w_i)`（按实际响应源归一化）。查到出口地理（`countryCode`）即把 `ip-api` 计入（干净 IP 得 100）；无任何信号则该项无分（不误判满分）。默认源与权重：

| 源 | 权重 | 说明 |
|---|---|---|
| `netcoffee` | 20 | `ip.net.coffee/api/iprisk/{ip}`，`trust_score` 直用；标志罚分：abuser 40 / tor 35 / proxy 30 / vpn 25 / datacenter 15，另加 `company_type`/`asn_kind` 机房 +15、`abuser_score`≥0.1 +20 |
| `ncgy` | 10 | `ip.nc.gy`（MaxMind 匿名 IP 库），`is_tor` 45 / `is_proxy` 30 / `is_vpn` 25 / `is_anonymous` 10 |
| `ip-api` | 15 | 本地批量地理的标志：proxy -25 / hosting -10；`countryCode` 存在即计入 |
| `ipquery` | 12 | `api.ipquery.io/{ip}`，免 key；`risk_score` 直用，或标志罚分：tor 45 / vpn 30 / proxy 25 / datacenter 15（取二者较大罚分） |
| `ffraud` | 12 | `api.ffraud.com/public/ip/{ip}`，免 key；`fraud_score` 直用，或 tor/vpn/proxy/hosting/abuser/recent_abuse 罚分（取较大者） |
| `blackbox` | 10 | `blackbox.ipinfo.app/{ip}`，免 key；`abuse`/`tor`/`vpn`/`proxy`/`datacenter` 标志罚分 |
| `otx` | 8 | `otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general`，免 key；`reputation` 与 `threat_score` 综合 |
| `ipsum` | 8 | `ipsum.ai/api/{ip}`，免 key；`abuse Confidence Score` 直用 |
| `ipapi_is` | 8 | `api.ipapi.is`，tor 45 / vpn 30 / proxy 25 / datacenter 15 / abuser 20，另加 `company.type`/`asn.type` 机房 +15、`abuser_score`≥0.1 +20 |
| `ipdata` | 8 | `api.ipdata.co`，限速 50 次/分；tor 45 / proxy 30 / vpn 25 / anonymous 10 + `threat_score` |
| `whatismyip` | 3 | `whatismyip.ai/api/lookup/{ip}`，免 key；`security.score` 直用，或 vpn/proxy/tor/hosting/blacklist 罚分（取较大者） |
| `dc_asn` | 5 | iplogs `datacenter-asns.csv` 静态机房 ASN 表，出口 `asn` 命中即 -15（fail-open） |
| `abuse_list` | 5 | FireHOL `firehol_abusers_1d` 静态滥用 IP/CIDR 表，命中即 -40（fail-open） |
| `torlist` | 5 | 官方 Tor 出口列表（`check.torproject.org/exit-addresses` + `dan.me.uk/torlist`），命中 -25 |
| `vpn_asn` | 3 | iplogs `vpn-providers.csv` 静态 VPN 服务商 ASN 表，命中 -30（fail-open） |
| `resproxy_asn` | 2 | iplogs `residential-proxy-backbones.csv` 住宅代理骨干 ASN 表，命中 -25（fail-open） |

可选源（opt-in）：`getipintel`（5 权重，需环境变量 `GETIPINTEL_EMAIL`，1 worker、4s 间隔、上限 300 次/运行，得分 `100 - prob×100`）。静态列表每 run 拉取一次，失败即跳过；按 IP 的免 key 源各自限速（ipquery/ffraud/whatismyip：4 worker、0.25s；netcoffee/ncgy/ipapi_is：6 worker、0.25s）避免限流掉单。**信誉缓存**：各按 IP API 源的信号写入 `data/quality/reputation_cache.json`，TTL 内（默认 7 天，`--rep-cache-ttl` 可调）复用缓存、只查询缺失/过期的 IP；`--no-rep-cache` 禁用；静态列表不缓存、每轮重拉。单源响应时直接取该源分数。风险等级：`<30` high、`<75` medium、其余 low。`tls` 方法代理无出口回显，直接用代理自身 IP 查信誉（不走 `ip-api` 地理）。结果写入 `reputation.json` 与 `all_rep.txt`（按信誉降序），分数也追加进 `#` 备注末尾。检测结果见下方数据文件；备注写入按 `#` 后格式追加。

### `scripts/reorg_country.py`

按出口 IP 国家重组 country/set/port 文件。读取 `quality_check.py` 生成的 `ipinfo.json`，将出口国家与列出国家不一致（`country_match=False`）的代理行移动到出口国家目录，同时改写行内 `#<emoji><CC>` 为出口国家的 emoji + CC。幂等：重复运行不产生变化。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--data-dir` | 数据根目录 | `data/` |
| `--ipinfo` | ipinfo.json 路径 | `<data-dir>/quality/ipinfo.json` |

影响目录：`countries/*/all.txt`、`sets/*/all.txt`、`ports/*.txt`。子分组文件（`cn.txt`、`v4.txt` 等）不处理，由下次 `annotate_classify.py` 刷新。

### `scripts/china_check.py`

大陆连通性检测（独立 CI 运行）。CI 以 `--source data/valid/all.txt --limit 0` 全量池检测；本地缺省按 `data/valid/all_rep.txt` 信誉降序采样前 250 条（缺失时回退 `all_ltd.txt`）。从大陆视角实测 TCP 可达性，分四层判定：

- **L1 启发式（零网络）**：行备注已带 `-CF`（Cloudflare 边缘 tls 代理）记录 heuristic 源，但不自动判 reachable——CF 启发式仅作为 basis 标注，需其他源确认
- **L2 itdog.cn 批量实测（主源）**：每任务 5 目标 × 电信/联通/移动各 2 节点（共 6 节点），经 WebSocket 收结果，TCP 连通即判可达
- **L2 单节点实测（并发）**：`check-host.cc`（呼和浩特阿里云节点，匿名限速 5/10s、250/h，配置 key 可放宽）+ `xxapi.cn`（北京节点，免 key）。**保守判定：多节点源（pingpe/itdog）单独确认 → reachable；单节点源 ≥2 个确认 → reachable；仅 1 个确认 → uncertain；均失败 → unreachable**
- **L3 多节点复核（串行小样本）**：`ping.pe`（约 13 个大陆节点，≥7/13 可达即判可达，报告不足 5 节点 → inconclusive）；可选 `tcpping.cn`（多运营商，需 `TCPPING_CN_TOKEN`，缺 key 自动跳过）

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

结果写入 `china.json`（keyed 明细，含各源 status/ms 与合成 verdict）与 `all_cn.txt`（全量大陆可达清单，源为 `data/valid/all.txt`，含历史已判可达者；缺 all.txt 时回退 all_ltd.txt）；可达者在 `all.txt`/`all_ltd.txt` 追加 `-CN` 备注（幂等）。

### `scripts/exit_family.py`

实际出口 IP 家族（IPv4/IPv6）检测（独立 CI 运行）。默认对 `data/valid/all.txt`（全量存活池）逐条探测真实出口家族（统一 TLS trace）：

- 直连 TLS + SNI → `cloudflare.com/cdn-cgi/trace`，取回显 `ip=` 判 v4/v6

家族判定：仅 v4 → `ipv4`；仅 v6 → `ipv6`；双通 → `dual`；探测全失败 → `unknown`。结果写入：

- `all_ipv4.txt` / `all_ipv6.txt` — 按家族分离的代理清单（**双栈同时计入两个文件**，`unknown` 不入任何文件）
- `exit_family.json` — 逐条明细（keyed，含 `family`、`exit_v4`/`exit_v6`、`method`）
- 并在 `all.txt`/`all_ltd.txt` 对应行追加 `-V4`/`-V6`/`-DS` 备注（幂等，`DS` 与质量检测已有的双栈 token 一致）

交叉验证：若 `data/quality/upstream_meta.json` 存在（由 `download_proxies.py` 生成），逐条对照上游记录的真实出口 `clientIp`，在 `exit_family.json` 中补充 `upstream_client_ip` / `upstream_family` / `upstream_match` 字段，并在结束时输出对照统计（命中数、一致/不一致数、未命中数）；文件缺失时静默跳过，不影响实时探测结果。

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

### `scripts/annotate_classify.py`

后缀填充 + 节点分类（CI 在 quality-check 完成后自动运行）。读取 5 个 JSON 数据源，向所有 `data/valid/*.txt` 文件填充缺失后缀并追加分类 token。幂等设计：多次运行结果一致。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--data-dir` | 数据根目录（含 `valid/` 子目录） | `data` |

**输入 JSON 数据源**：

| 文件 | 填充内容 |
|---|---|
| `ipinfo.json` | IP 类型 token（DC/RES/MOB/PROXY） |
| `reputation.json` | 信誉评分（仅缺失时追加） |
| `china.json` | 大陆可达 token（CN） |
| `exit_family.json` | IP 家族 token（V4/V6/DS） |
| `streaming.json` | 流媒体解锁 tokens（NF/D+/YT/MX/PV/GPT） |

**分类 token**：

| Token | 含义 | 来源 |
|---|---|---|
| DC | Datacenter（数据中心） | `ipinfo.json` → `ip_type` |
| RES | Residential（住宅） | `ipinfo.json` → `ip_type` |
| MOB | Mobile（移动网络） | `ipinfo.json` → `ip_type` |
| PROXY | Proxy（代理） | `ipinfo.json` → `ip_type` |
| fast | 快速（≥5 MB/s） | 行内 speed 值解析 |
| mid | 中速（1-5 MB/s） | 行内 speed 值解析 |
| slow | 慢速（<1 MB/s） | 行内 speed 值解析 |

**行格式变化**：

```
Before: 1.2.3.4:443#🇺🇸US→US-30ms-10.82MB/s-CN-V6-GPT-CF-77
After:  1.2.3.4:443#🇺🇸US→US-30ms-10.82MB/s-CN-V6-GPT-CF-77-DC-fast
```

**处理范围**：`data/valid/all.txt`、`all_ltd.txt`、`countries/*/all.txt`、`countries/*/ltd.txt`、`sets/*/all.txt`、`sets/*/ltd.txt`、`ports/*.txt`

```bash
python scripts/annotate_classify.py
python scripts/annotate_classify.py --data-dir /path/to/data
```