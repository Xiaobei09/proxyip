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
| `--extra-source KIND,URL` | 追加一个补充来源（`plain`/`ip`/`csv`/`json`，可重复） | 无 |
| `--no-extra-sources` | 跳过内置 CF 反代补充来源 | 关 |

#### CF 反代补充来源

除主源外，默认还会拉取一批 **Cloudflare 反代（非官方 CF 段）** 来源并合并：`wentao883/TG-wxgqlfx_ZBDW`（`fdip`/`vlid`/`yxip`）、`ChatBotPlus/cf-proxyips`、`ymyuuu/IPDB`（`BestProxy/proxy.txt`、`bestproxy&country.txt`、`bestproxy.txt`，以及优选云池 `BestAli/bestaliv4`、`BestGC/bestgcv4`+`bestgcv6`、`BestEDG/bestedgv4` —— 全部非 CF，属阿里/谷歌/腾讯等云段，提升可用性）、`mountain787/Lunch-Bag-ip`、`ipdb.api.030101.xyz`（`?type=proxy` 全量反代池 + `?type=bestproxy` 优选反代池，同源族、互为补充，扩大可用性）。解析方式分四种：`plain`（`ip:port#国家`/`ip:port#中文`）、`ip`（裸 IP，统一按 443 端口）、`csv`（`IP,端口,地区,延迟`，地区为机场码或国家码）、`json`（`all.json` 格式镜像，缺失国家字段的条目归入 `ALL`，畸形载荷容忍）。中文名与机场码经映射表归一为 ISO2；仍无国家的条目经 `ip-api.com/batch` 尽力补齐（每批 100、失败保留 `#ALL`）。单个来源失败仅告警跳过，不影响整体运行。来源标签：`json` 镜像若为通用清单名（`all.json`/`all.zip` 等，多镜像会共用 `all` 这一名字），会自动以注册域前缀消歧（如 `mirror-a/all`、`mirror-b/all`），避免不同镜像在来源统计/逐 IP 归属/健康监控中互覆；其余来源保持文件名主干。

**维护宗旨：只保留「非 Cloudflare AS13335 + Cloudflare 边缘端口」连接池。** 因此不收录 Cloudflare 官方边缘 IP（如 `byJoey/cfnew-ipdb`——其 IP 全属 AS13335，而 Workers 出站 `connect()` 禁止直连 CF IP 网段，无法用于自建链路）。最终产物经端口白名单 `443/8443/2053/2083/2087/2096` 过滤，其余端口桶一律丢弃——可用于 Worker 内部 `connect()` 直连。

主源 `all.json` 采用 **3 次线性退避重试**（1.5s/3s）后才回退 zip 镜像（镜像同样 3 次尝试）；附加 `.json`/`.zip` 源分别 3/2 次重试。`ip-api` 国籍批量按批重试 2 次，终失败仅跳过该批继续后续批次，网络抖动不再中断整次国籍填充。

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
| `--speed-warmup-bytes` | 稳态测速预丢弃字节数（TCP 慢启动爬坡，不计入计时；0 = 从首字节起算） | 262144 |
| `--no-speed` | 跳过速度测试（`_ltd` 回退按延迟） | 关 |
| `--no-adaptive-speed` | 关闭 RTT 自适应下载窗口（固定 5s / 1MB） | 关 |
| `-t, --timeout` | 单代理超时（秒） | 5 |
| `-w, --workers` | asyncio 并发上限 | 500 |
| `--limit` | 只检测前 N 条（0 = 全部） | 0 |
| `--time-budget` | 最多执行秒数（0 = 不限） | 0 |
| `--per-country-limit` | `_ltd` 输出每国条数 | 20 |
| `--quick-prefilter` | 上一轮未存活的条目先做廉价 TCP 连通预筛：连不通（RAW 入口必然死）直接跳过，避免空耗 TLS 超时；通者再走全检 | 开 |
| `--quick-timeout` | 预筛 TCP 连接超时（秒） | 2 |
| `--ext-check` | 启用外部 API 多源验证（出口地理 + 双栈标注 + TLS 失败兜底） | 关 |
| `--ext-timeout` | 外部 API 单源超时（秒） | 10 |
| `--ext-workers` | 外部 API 并发上限 | 10 |

除 `all.txt`/`ltd.txt` 外，每个国家/集合目录还会按 **出口家族 × 大陆可达** 生成分组文件 `v4.txt`/`v6.txt`/`46.txt`/`cn.txt`/`cn4.txt`/`cn6.txt`/`cn46.txt`（含对应 `*_ltd.txt`），根级另生成 `all_46.txt`/`all_cn4.txt`/`all_cn6.txt`/`all_cn46.txt`（含 `*_ltd.txt`）。家族优先取自 `exit_family.json`（缺失时回退行内 `-V4`/`-V6`/`-DS`），大陆可达取自行内 `-CN`；空组不落盘并清理残留。详见 `docs/data-spec.md`「分组文件」。

每个清单（含根级 `all*.txt` 与全部分组）同步派生两个可靠性维度：`*_verified.txt`（本轮测速成功 = TLS + HTTP 2xx + 真实下载全链路通过，过滤半死代理）与 `*_stable.txt`（上一轮 `index.json` 与本轮存活的交集，抗 churn；首轮无上一轮数据时不生成）。可与任意分组叠加，如 `countries/US/cn4_verified.txt`、根级 `all_cn4_stable.txt`；`ltd` 家族同样派生（`ltd_verified.txt`、根级 `all_ltd_stable.txt`）。空清单不落盘并清理残留，数量计入 `meta.json` 的 `sets.all_verified` / `sets.all_stable`。

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
| `chart_sets.svg` | 各命名集合存活代理条形图 |
| `chart_cn.svg` | 大陆连通性 verdict 分布条形图 |
| `chart_family.svg` | 实际出口 IP 家族分布条形图 |
| `chart_source_avail.svg` | IP 来源覆盖率 + 每代理源数量分布 |
| `chart_source_stats.svg` | 每下载来源 IP 数量与重叠分布 |
| `chart_rep.svg` | 信誉分分布条形图 |

### `scripts/quality_check.py`

出口 IP 质量检测（独立 CI 运行，探测引擎拆分于 `quality_probe.py`：TLS GET / 外部出口地理回显 / ip-api 批量）。默认对 `data/valid/all.txt`（全量存活池）检测：

- TLS 直连（Cloudflare 边缘）测活，备注 `CF`
- **滚动可用率**：质量链每轮运行后由 `uptime.py` 更新 `node_seen.json`/`uptime.json`，注解链为节点追加 `-U<NN>` 备注
- **深测带宽加成**：`deep_speed.json` 的最优目标 `agg_mbps` 线性加成分数（封顶 +10，仅对已有信誉分节点生效）；深测数据超过 10 天（`DEEP_SPEED_TTL_DAYS`）视为过期，不再参与加分
- **出口 IP 解析**：信誉/地理/滥用查询使用真实出口 IP——优先外部探测回显，其次 `exit_family.json` 实测，兜底代理自身 IP（见 logic.md §4.0）
- 批量查出口 IP 地理（`ip-api.com/batch`）与 ASN/IP 类型

| 参数 | 说明 | 默认 |
|---|---|---|
| `--source` | 输入代理列表 | `data/valid/all.txt` |
| `--abuse-service` | 滥用分服务（none/abuseipdb/ipqs） | none |
| `--reputation-provider` | 信誉策略（multi/netcoffee/ip-api/none） | multi |
| `--reputation-sources` | multi 时启用的源（逗号分隔，见下） | netcoffee,ncgy,ip-api,ipquery,ffraud,blackbox,otx,ipsum,ipapi_is,ipdata,whatismyip,dc_asn,abuse_list,vpn_asn,resproxy_asn,proxycheck,ip2location,ipwhois,tor_exit,spamhaus,freeipapi,hackmyip,scamalytics,iplocation,cins,et_compromised,feodo |
| `--reputation-weights` | 权重覆盖，如 `netcoffee:40,ncgy:20` | 见下 |
| `--rep-cache-ttl` | 信誉信号缓存有效期（秒） | 604800（7 天） |
| `--no-rep-cache` | 禁用信誉信号缓存 | 关 |
| `-t, --timeout` | 单代理超时（秒） | 6 |
| `--read-cap` | 单次响应读取上限（字节） | 524288 |
| `-w, --workers` | asyncio 并发上限 | 60 |
| `--limit` | 只检测前 N 条（0 = 全部） | 0 |
| `--time-budget` | 最多执行秒数（0 = 不限） | 0 |

滥用分 key 从环境变量 `ABUSEIPDB_KEY`（abuseipdb）或 `IPQS_KEY`（ipqualityscore）读取，缺 key 时自动跳过。信誉分（0-100）**跨源共识合成**：abuse 分存在时取 `100 - score`（最高优先级）；否则先把各源的布尔标记归一为语义维度（`tor`/`proxy`/`vpn`/`hosting`(数据中心)/`mobile`/`abuse`/`listed`/`scraper`/`crawler`/`anonymous`），按源权重做**加权多数投票**——正票总权重 > 负票总权重才认定该维度为真，打平视为无结论（不扣分），避免单源误报独断与大权重单源主导；再叠加连续型风险源的加权罚分（`trust_score`、`probability`、`risk_score`、`fraud_score`、`score`、otx reputation/pulse、proxycheck risk）。查到出口地理（`countryCode`）即把 `ip-api` 计入（代理/机房/移动标志直接参与投票）；无任何信号则该项无分（不误判满分）。共识扣分表：tor 40 / abuse 35 / listed 30 / proxy 28 / vpn 22 / scraper 12 / hosting 10 / anonymous 8 / crawler 5；仅当 mobile 与其余风险维度均不成立时有 +5 加分。默认源与权重：

| 源 | 权重 | 说明 |
|---|---|---|
| `netcoffee` | 20 | `ip.net.coffee/api/iprisk/{ip}`，`trust_score` 直用；标志罚分：abuser 40 / tor 35 / proxy 30 / vpn 25 / datacenter 15，另加 `company_type`/`asn_kind` 机房 +15、`abuser_score`≥0.1 +20 |
| `ncgy` | 10 | `ip.nc.gy`（MaxMind 匿名 IP 库），`is_tor` 45 / `is_proxy` 30 / `is_vpn` 25 / `is_anonymous` 10 |
| `ip-api` | 15 | 本地批量地理的标志：proxy -25 / hosting -10 / mobile +10；`countryCode` 存在即计入 |
| `ipquery` | 12 | `api.ipquery.io/{ip}`，免 key；`risk_score` 直用，或标志罚分：tor 45 / vpn 30 / proxy 25 / datacenter 15（取二者较大罚分） |
| `ffraud` | 12 | `api.ffraud.com/public/ip/{ip}`，免 key；`fraud_score` 直用，或 tor/vpn/proxy/hosting/abuser/recent_abuse 罚分（取较大者） |
| `blackbox` | 10 | `blackbox.ipinfo.app/api/v3beta/{ip}`，免 key；分类评分：residential 95 / mobile 90 / business 85 / hosting 60 / vpn 55 / privacy_relay 50 / tor 10 / bogon 5 / unknown 50；suspicious -20 |
| `otx` | 8 | `otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general`，免 key；`100 - (min(reputation×5,80) + min(pulse_count×2,20))` |
| `ipsum` | 8 | GitHub 静态 IP 列表（stamparm/ipsum levels/3+），命中 3+ 黑名单 → 55 分 |
| `ipapi_is` | 8 | `api.ipapi.is`，tor 45 / vpn 30 / proxy 25 / datacenter 15 / abuser 20，另加 `company.type`/`asn.type` 机房 +15、`abuser_score`≥0.1 +20 |
| `ipdata` | 8 | `api.ipdata.co`，限速 50 次/分；tor 45 / proxy 30 / vpn 25 / anonymous 10 + `threat_score` |
| `whatismyip` | 3 | `whatismyip.ai/api/lookup/{ip}`，免 key；`security.score` 直用，或 vpn/proxy/tor/hosting/blacklist 罚分（取较大者） |
| `dc_asn` | 5 | iplogs `datacenter-asns.csv` 静态机房 ASN 表，出口 `asn` 命中即 -15（fail-open） |
| `abuse_list` | 5 | FireHOL `firehol_abusers_1d` 静态滥用 IP/CIDR 表，命中即 -40（fail-open） |
| `vpn_asn` | 3 | iplogs `vpn-providers.csv` 静态 VPN 服务商 ASN 表，命中 -30（fail-open） |
| `resproxy_asn` | 2 | iplogs `residential-proxy-backbones.csv` 住宅代理骨干 ASN 表，命中 -25（fail-open） |
| `proxycheck` | 12 | `proxycheck.io/v3/{ip}`，免 key（100/天）；proxy/vpn/tor/hosting/scraper 标志罚分 + risk score |
| `ip2location` | 5 | `api.ip2location.io/?ip={ip}`，免 key（1000/天）；`is_proxy` 标志 -30 |
| `ipwhois` | 6 | `ipwho.is/{ip}`，免 key；`security.proxy/vpn/tor/hosting` 标志各 -25，`security.anonymous` -8，`connection.type` 为 residential 且无风险标志时 +5 |
| `tor_exit` | 5 | check.torproject.org 出口节点实时列表（免费），命中即投 `tor` 票 |
| `spamhaus` | 4 | Spamhaus DROP + EDROP 端用户高风险网段静态表（免费，`<cidr> ; 描述`），命中即投 `listed` 票 |
| `freeipapi` | 6 | `freeipapi.com/api/json/{ip}`，免 key；`isProxy` 标志 -30，附 ASN/org |
| `hackmyip` | 6 | `hackmyip.com/api/lookup?ip={ip}`，免 key；`data.privacy` 的 hosting/proxy/mobile 标志参与投票，附 ASN |
| `scamalytics` | 8 | `scamalytics.com/ip/{ip}` 免费风险页；`Fraud Score` 0-100 直扣，`is_blacklisted_external` 投 `listed` 票 |
| `iplocation` | 3 | `api.iplocation.net/?ip={ip}`，免 key；`is_proxy` -30，附 isp |
| `cins` | 5 | CINS Army `ci-badguys.txt` 静态活跃滥用/拒绝服务 IP（免费），命中投 `listed` 票 |
| `et_compromised` | 4 | EmergingThreats `compromised-ips.txt` 被入侵主机（免费），命中投 `abuse` 票 |
| `feodo` | 4 | abuse.ch Feodo Tracker `ipblocklist.txt` 僵尸网络 C2 IP（免费），命中投 `abuse` 票 |

可选源（opt-in）：`getipintel`（5 权重，需环境变量 `GETIPINTEL_EMAIL`，1 worker、4s 间隔、上限 300 次/运行，得分 `100 - prob×100`）。静态列表每 run 拉取一次，失败即跳过；按 IP 的免 key 源各自限速（netcoffee/ncgy：10 worker、0.15s；blackbox/proxycheck：8 worker、0.2s；ipapi_is：8 worker、0.2s；otx：6 worker、0.3s；ipquery/ffraud/whatismyip/ip2location/ipwhois：6 worker、0.2s；freeipapi：8 worker、0.15s（上限 3000/轮）；hackmyip：6 worker、0.2s；iplocation：8 worker、0.12s（上限 3000/轮）；scamalytics：4 worker、0.5s（上限 1500/轮），新源按轮次上限 + 7 天缓存逐回填覆盖，避免首轮撑爆作业预算）避免限流掉单。**信誉缓存**：各按 IP API 源的信号写入 `data/quality/reputation_cache.json`，TTL 内（默认 7 天，`--rep-cache-ttl` 可调）复用缓存、只查询缺失/过期的 IP；`--no-rep-cache` 禁用；静态列表不缓存、每轮重拉。缓存表按每个 IP 最近一次信号时间封顶 `REP_CACHE_MAX`（4 万条），超限自动裁剪最旧条目防无限膨胀。风险等级：`<30` high、`<75` medium、其余 low。`tls` 方法代理无出口回显，直接用代理自身 IP 查信誉（不走 `ip-api` 地理）。结果写入 `reputation.json` 与 `all_rep.txt`（按信誉降序），`ipinfo.json` 每个键含 `rep_flags`/`rep_sources`/`risk_sources`，`reputation.json` 含 `flags`/`numeric`。分数也追加进 `#` 备注末尾。rep 交叉矩阵（`all_{g}_rep.txt`、`all_{g}_rep_ltd.txt`、子目录 `rep.txt` 等）同步派生 `*_verified.txt`（speed.json 全链路验证）与 `*_stable.txt`（china.json streak≥2 跨轮稳定）变体；子目录分组 rep 保持单维度以控制文件数量。检测结果见下方数据文件；备注写入按 `#` 后格式追加。

### `scripts/reorg_country.py`

按出口 IP 国家重组 country/set/port 文件。出口国观测经三源汇聚
（`common.build_exit_cc_map`：`external_check.json` > `upstream_meta.json` >
`ipinfo.json`，见 logic.md §7.2），命中观测的行一律
upsert `→OC` 标记（同国也标注，陈旧出口直接替换）；仅当位于
`countries/<CC>/` 且与出口国不同时才迁移目录，sets/ports 混国文件只标注
不移动。幂等：重复运行不产生变化。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--data-dir` | 数据根目录 | `data/` |
| `--ipinfo` | ipinfo.json 路径 | `<data-dir>/quality/ipinfo.json` |

影响目录：`countries/*/all.txt`、`sets/*/all.txt`、`ports/*.txt`。子分组文件（`cn.txt`、`v4.txt` 等）不处理，由下次 `annotate_classify.py` 刷新。

### `scripts/audit_entry_cc.py`

入口国家标签准确性审计。订阅标签（`#CC`）此前无从验证，本脚本以两个
独立信号交叉对比：① 入口 IP 地理（ip-api batch，含 ASN）；② 出口国观测
（四源 exit map）。判定写入 `data/quality/entry_audit.json`
（`proxies[key].verdict`）并打印汇总：

| verdict | 含义 |
|---|---|
| `ok` | 标签 == 入口实测，出口缺失或一致 |
| `ok_with_drift` | 标签 == 入口实测，但出口在别国（正常漂移） |
| `tag_mismatch` | 标签 != 入口实测（原始标签可疑，实测约 8%） |
| `cf_fronted` | 入口为 CF 边缘（AS13335），入口验证不适用 |
| `domain_entry` | 入口为域名，无 IP 可查 |
| `entry_unknown` | geo 查询失败 |

只读不改行、不影响门控；CI 中 `continue-on-error`。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--data-dir` | 数据根目录 | `data/` |
| `--source` | 代理列表 | `<data-dir>/valid/all.txt` |
| `--timeout` | 单批 HTTP 超时（秒） | 15 |
| `--delay` | 批间延时（秒），ip-api 免费档限 45 req/min | 1.5 |

### `scripts/china_check.py`

大陆连通性检测（独立 CI 运行）。CI 以 `--source data/valid/all.txt --limit 0` 全量池检测；本地缺省按 `data/valid/all_rep.txt` 信誉降序采样前 250 条（缺失时回退 `all_ltd.txt`）。从大陆视角实测 TCP 可达性，分四层判定：

- **L1 启发式（零网络）**：行备注已带 `-CF`（Cloudflare 边缘 tls 代理）记录 heuristic 源，但不自动判 reachable——CF 启发式仅作为 basis 标注，需其他源确认
- **L2 itdog.cn 批量实测（主源）**：每任务 5 目标 × 电信/联通/移动各 2 节点（共 6 节点），经 WebSocket 收结果，TCP 连通即判可达
- **L2 单节点实测（并发）**：`check-host.cc`（呼和浩特阿里云节点，匿名限速 5/10s、250/h，配置 key 可放宽）+ `xxapi.cn`（北京节点，免 key）。**保守判定：多节点源（pingpe/itdog/tcptest/coffee/pingloc/antping/tcpingcn/chinaz）单独确认 → reachable；单节点源 ≥2 个确认 → reachable；仅 1 个确认 → uncertain；均失败 → unreachable**
- **L3 多节点复核（有界并发小样本）**：`tcptest.cn`（免费 REST，~146 大陆节点按运营商均衡采样 10 个，TCP `ip:port` 直连，节点成功率达 50% 即判可达）先于 ping.pe 跑——免费、端到端 ~2-6s/键，确认过的键自动让位；`ip.net.coffee`（18 ICMP 节点，成功率达 50% 判可达，专测中国大陆主机存活）；`pingloc.com`（~12 节点 ICMP ping，纯 HTTP+SSE 零鉴权）；`antping.com`（~155 节点，JWT+WS，ICMP ping / TCP `ip:port` 均可）；`tcping.cn`（~163 TCP 节点，SHA-256 PoW 纯 Python 求解 + WS，真实端口直连）；`ping.chinaz.com`（~53 ICMP 节点，服务端渲染 token + WS）；随后 `ping.pe`（约 13 个大陆节点，≥7/13 可达即判可达，报告不足 5 节点 → inconclusive），各源均只投「当前尚未被 itdog/单节点源判可达」的键且按 `--<name>-limit` 有界；多节点源须「≥ `MULTI_MIN_NODES`（5）个节点 + 成功率达标」才可独立判 reachable，防限流残缺样本假阳性；可选 `tcpping.cn`（多运营商，需 `TCPPING_CN_TOKEN`，缺 key 自动跳过）

| 参数 | 说明 | 默认 |
|---|---|---|
| `--source` | 输入代理列表 | `data/valid/all_rep.txt` |
| `--limit` | 按信誉降序采样条数（0=全部） | 250 |
| `--pingpe-limit` | ping.pe 多节点复核条数（有界并发） | 200 |
| `--tcptest-limit` | tcptest.cn 多节点复核条数（0=跳过；-1=全部未定键） | 150 |
| `--tcptest-concurrency` | tcptest.cn 并发复核数 | 4 |
| `--tcptest-nodes` | tcptest.cn 每键采样节点数 | 10 |
| `--coffee-limit` | ip.net.coffee 多节点复核条数（0=跳过；-1=全部未定键） | 0 |
| `--coffee-concurrency` | ip.net.coffee 并发复核数 | 16 |
| `--pingloc-limit` | pingloc.com 多节点复核条数（0=跳过；-1=全部未定键） | 0 |
| `--pingloc-concurrency` | pingloc.com 并发复核数 | 8 |
| `--antping-limit` | antping.com 多节点复核条数（0=跳过；-1=全部未定键） | 0 |
| `--antping-concurrency` | antping.com 并发复核数 | 8 |
| `--tcpingcn-limit` | tcping.cn 多节点复核条数（0=跳过；-1=全部未定键） | 0 |
| `--tcpingcn-concurrency` | tcping.cn 并发复核数 | 6 |
| `--chinaz-limit` | ping.chinaz.com 多节点复核条数（0=跳过；-1=全部未定键） | 0 |
| `--chinaz-concurrency` | ping.chinaz.com 并发复核数 | 6 |
| `--workers` | L2 并发上限 | 16 |
| `-t, --timeout` | 单次 HTTP 超时（秒） | 10 |
| `--api-key` | check-host.cc key（读 `CHINA_CHECK_API_KEY`） | 空 |
| `--tcpping-token` | tcpping.cn token（读 `TCPPING_CN_TOKEN`） | 空 |
| `--skip-pingpe` | 跳过 ping.pe 复核（本地快速冒烟） | 关 |
| `--skip-itdog` | 跳过 itdog.cn 批量探测 | 关 |
| `--dry-run` | 只输出计划，不发请求不写盘 | 关 |

结果写入 `china.json`（keyed 明细，含各源 status/ms 与合成 verdict）与 `all_cn.txt`（全量大陆可达清单，源为 `data/valid/all.txt`，含历史已判可达者；缺 all.txt 时回退 all_ltd.txt）；可达者在 `all.txt`/`all_ltd.txt` 追加 `-CN` 备注（幂等）。

### `scripts/exit_family.py`

实际出口 IP 家族（IPv4/IPv6）检测（独立 CI 运行）。默认对 `data/valid/all.txt`（全量存活池）逐条 **双栈探测** 真实出口家族：

- 分别请求仅 IPv4（`ipv4.icanhazip.com`，仅 A 记录）与仅 IPv6（`ipv6.icanhazip.com`，仅 AAAA）的回显服务（纯 IP 文本），走得通即具备对应家族出口能力；两者均失败则尝试 `cloudflare.com/cdn-cgi/trace` 兜底。注意：CF 边缘代理的出口由 Worker fetch() 决定、与入口/目标主机名无关，故 CF 类代理 `dual` 恒为 0 属架构固有行为

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

后缀填充 + 节点分类（CI 在 quality-check 完成后自动运行）。读取 7 个 JSON 数据源，向所有 `data/valid/*.txt` 文件填充缺失后缀并追加分类 token。幂等设计：多次运行结果一致。所有备注写入统一经 `common.normalize_note` / `merge_note_tokens` / `clear_note_buckets` 处理（规范段序 + 互斥桶先清后设），禁止裸拼接。

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
| `external_check.json` | 出口国标记 →CC（优先级最高） |
| `upstream_meta.json` | 出口国标记 →CC（CF Worker 观测） |
| `uptime.json` | 滚动可用率 token `-U<NN>`（7d 存活率） |

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
Before: 1.2.3.4:443#🇺🇸US→US-30ms-10.82MB/s-CN-V6-CF-77
After:  1.2.3.4:443#🇺🇸US→US-30ms-10.82MB/s-CN-V6-CF-77-DC-fast-U92
```

**处理范围**：`data/valid/all.txt`、`all_ltd.txt`、`countries/*/all.txt`、`countries/*/ltd.txt`、`sets/*/all.txt`、`sets/*/ltd.txt`、`ports/*.txt`

```bash
python scripts/annotate_classify.py
python scripts/annotate_classify.py --data-dir /path/to/data
```

### `scripts/build_good.py`

构建综合最优 `good.txt` 清单（策略组/国家组/集合组各一份）。从验证池（`data/valid/all.txt`、`countries/*/all.txt`、`sets/*/all.txt`）中筛选同时满足以下条件的代理，按综合分降序输出（行内容原样保留）：

1. **大陆可达**：`china.json` 判定 `reachable`，或行内已带历史 `-CN` 备注（与 `all_cn.txt` 同规则）
2. **信誉分 ≥ 80**：存在于 `reputation.json` 且 `score >= 80`
3. **非高风险**：`reputation.json` 的 `risk != high`

综合分公式（信誉为主）：`round(0.6×信誉分 + 0.2×延迟分 + 0.2×速度分)`；延迟分 ≤100ms 记 100、≥1500ms 记 0 线性递减，速度分 `min(MB/s÷5, 1)×100`，缺失均记 0。同分依次按延迟升序、key 升序。质量 JSON 缺失时优雅降级为空清单。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--data-dir` | 数据根目录（含 `valid/` 与 `quality/`） | `data` |

输出文件：`data/valid/all_good.txt`、`data/valid/countries/<CC>/good.txt`、`data/valid/sets/<name>/good.txt`。每份同步派生 `*_verified.txt`（speed.json 全链路验证）与 `*_stable.txt`（china.json streak≥2 跨轮稳定）可靠性变体；对同目录 `ltd.txt` 池额外产出 `good_ltd(+_verified/_stable)`（每国最快的优质子集）。CI 在 quality-check / china-check / exit-family / annotate-classify 四个 workflow 的后缀填充步骤后自动运行。

```bash
python scripts/build_good.py
python scripts/build_good.py --data-dir /path/to/data
```

### `scripts/analyze_sources.py`

分析各下载源的质量。读取 `ip_sources.json`（逐 IP 来源归属）并与验证/信誉/大陆可达性数据交叉引用，产出每个源的存活率、延迟、速度、信誉分、大陆可达率等指标。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--data-dir` | 数据根目录 | `data/` |

输出文件：
- `data/quality/source_quality.json`：逐源质量指标 JSON
- `data/output/source_quality_report.txt`：人类可读汇总表

```bash
python scripts/analyze_sources.py
python scripts/analyze_sources.py --data-dir /path/to/data
```

### `scripts/health_alert.py`

池健康看门狗：读取仓库内的数据快照，检查多项异常条件，有告警时发往 `ALERT_WEBHOOK_URL`（未配置时仅打印并正常退出）。每一项都带各自的最小样本/阈值门槛，避免小样本抖动误报；诊断状态持久化于 `data/quality/alert_state.json`（上次 CN 可达数、各国家池快照）；相同告警组合在 6 小时冷却窗口内不重复投递（`last_alert_at` / `last_alert_hash`），防止持续故障期间刷屏 webhook。有告警时还会改写 `data/output/badge.json` 将 README 状态徽章标红为对应告警名（在 stats 同 job 内 render 之后顺序执行，无竞态）；无告警不改动徽章。

| 检查 | 触发条件 |
|---|---|
| `check_pool` | 池 `alive` 相对近 8 轮中位数下降 ≥30%（样本足够时评估） |
| `check_cn` | 上次 CN 可达数 ≥20 时，本轮相对上一轮下降 ≥50% |
| `check_cn_stale` | `china.json` 超过 `CN_STALE_HOURS`(12h) 未刷新且曾有 ≥20 可达样本（CN 专链静默停机时总体数据仍新鲜，仅此检查暴露） |
| `check_artifact_stale` | 任一产物 JSON 超龄（泛化时效检查）；`require_proxies=True` 用于 keyed 产物（`exit_family.json`：12h / ≥100 条目），`require_proxies=False` 用于 summary 产物（`quality_meta.json`、`good_meta.json`：各 12h；`valid/meta.json`：5h，此时效早于 8h 的 history 兜底告警）——分别暴露 exit-family / 质量链 / build-good 链 / validate(update) 链静默停机 |
| `check_countries` | 单国上一轮 alive ≥60 时，本轮相对下降 ≥60%（区域性断网/上游国家文件丢失） |
| `check_sources` | 某上游源 unique 覆盖相对近 8 轮中位数下降 ≥55%（样本 ≥8 轮且规模 ≥500） |
| `check_stale` | `data/valid/history.jsonl` 最新轮距今超过 8 小时 |

```bash
ALERT_WEBHOOK_URL=https://example.com/hook python scripts/health_alert.py
```