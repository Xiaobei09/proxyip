# 脚本与 CLI

本文件归档全部入口脚本的参数、默认值与行为说明（含 `common.py` 共享模块与拆分子模块）。各脚本仍以 `python3 scripts/<name>.py` 独立运行。

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

除主源外，默认还会拉取一批 **自称 Cloudflare 第三方反代 proxyip 的来源**（非官方 CF 段）并合并：`wentao883/TG-wxgqlfx_ZBDW`（`fdip`/`vlid`/`yxip`，`plain`）、`ChatBotPlus/cf-proxyips`（`plain`）、`ymyuuu/IPDB`（`BestProxy/proxy.txt`、`bestproxy&country.txt`、`bestproxy.txt`，`ip`；IP-05 起加 `BestProxy/proxy.csv` 测速榜，首列裸 IP 经 `ipcsv` 分支提取；IP-OPT-4 起加根 `proxy.txt`（372 裸 IP，306 独立），均并入 `ymyuuu` 同一来源；`bestcf*` 系官方 CF 段排除）、`mountain787/Lunch-Bag-ip`（`csv`）、`LeilaoMi/cf-proxyip-us`（`docs/all.txt`，逐台人工/脚本实测收录的非 CF 反代池，同样排除官方 CF 段；IP-OPT-3 起加 `docs/best.txt` 精选裸 IP 与 `docs/base64.txt` 全量榜 base64，均并入 `leilao_cfproxy` 同一来源；IP-OPT-8 起摘除 `ipdb.api.030101.xyz` 三接口——14 轮生产 unique 恒 0 且与 ymyuuu 文件逐字节镜像）、`Wwuyi123/CF-Proxyip`（`proxyip.txt`、`proxyip_with_country.txt`（`IP#速度地区`）、`ips/all_ips.txt`，`ip`；IP-02 起加 `Manual_input_IP.txt` 手工精选裸 IP，多国别 VPS；IP-OPT-2 起加 `ips/allowed_ips.txt` 准入白名单裸 IP，均并入 `wwuyi` 同一来源）、`wanwushequ/ProxyIP`（`US.txt`/`JP.txt`/`HK.txt`/`SG.txt`/`KR.txt`/`DE.txt`/`GB.txt`/`FI.txt`/`FR.txt`/`CH.txt`/`NL.txt`/`LV.txt`/`PL.txt`/`SE.txt`/`RU.txt`/`CA.txt`/`IN.txt`/`TW.txt` 等地区优选榜，`ip`；IP-01 起纳入香港榜，IP-03 起纳入新加坡榜，IP-04 起纳入韩国榜，IP-06 起纳入德国榜，IP-07 起纳入英国榜，IP-08 起纳入芬兰榜，IP-09 起纳入法国榜，IP-10 起纳入瑞士榜，IP-11 起纳入荷兰榜，IP-12 起纳入拉脱维亚榜，IP-13 起纳入波兰榜，IP-14 起纳入瑞典榜，IP-15 起纳入俄罗斯榜，IP-16 起纳入加拿大榜，IP-17 起纳入印度榜，IP-18 起纳入台湾榜）、`svip-s/cloudflare_ip`（`best_ips.txt`，`ip:port#CC [注解]`，`ipnote`；实测 IP 属第三方反代 VPS、非 CF 官方 AS13335 段，与池政策「非 AS13335」一致；IP-OPT-3 起加 `full_ips.txt` 全量榜并入 `svip_cfip` 同一来源）、`afrcloud07/ListProxy`（`proxyip.txt` 日更测速榜，`IP,port,CC,ISP`，`csv`；IP-OPT-6 起纳入，独立 `afr` 来源）、`wangallen123/proxyip`（`all_ips.txt` 精选裸 IP `#中文国家签`，`ip`；IP-OPT-7 起纳入，独立 `wangallen` 来源）、`FarelRA/proxyip-tracker`（`result/ips.csv` 追踪榜，`IP,Colo,Region` 经 `colocsv` 分支按 Colo 派生国家归 443；IP-OPT-7 起纳入，独立 `farel` 来源）、`cmliu/WorkerVless2sub`（`addressescsv.csv` 2244 行含延迟/速度实测榜经 `dccsv` 分支取 IP/端口/数据中心派生国家 + `addressesapi.txt` 4 行精选，`ip:port#CC`；IP-OPT-9 起纳入，均并入 `cmliu` 同一来源）。**同源合并（IP-OPT-1 起）**：43 个文件在储存层只记 12 个来源——`wentao`（wentao883 三榜）、`list`（ChatBotPlus）、`ymyuuu`（IPDB 三 txt+一 csv+根 proxy.txt）、`leilao_cfproxy`（all/best/base64）、`proxyip`（mountain787 csv）、`wwuyi`（Wwuyi123 五文件）、`wanwu`（wanwushequ 十八地区榜）、`svip_cfip`（best+full）、`afr`、`wangallen`、`farel`、`cmliu`；抓取仍按文件并行，`source_stats`/归属/健康历史以来源为键（同站重复不算交叉佐证）。解析方式分九种：`plain`（`ip:port#国家`/`ip:port#中文`）、`ip`（裸 IP，统一按 443 端口）、`ipcsv`（CSV 首列裸 IP，末列两位字母国家码作备注否则归 ALL，IP-05 起用于 ymyuuu 测速榜）、`csv`（`IP,端口,地区,延迟`，地区为机场码或国家码）、`b64ip`（base64 解码后按裸 IP 解析，IP-OPT-3 起用于 LeilaoMi 全量榜）、`colocsv`（`IP,Colo,Region` 追踪榜按 Colo 派生国家，IP-OPT-7 起用于 FarelRA）、`dccsv`（`IP,端口,…,数据中心` 实测榜按数据中心派生国家，IP-OPT-9 起用于 cmliu）、`json`（`all.json` 格式镜像，缺失国家字段的条目归入 `ALL`，畸形载荷容忍）、`ipnote`（`ip:port#CC [注解]` 榜单行，CC 为两位字母，尾部方括号注解或旗标一并剥离，适用 LancelotRar/svip-s 等榜单格式）。

> **池政策红线**：`EXTRA_SOURCES` 只收录 **非 Cloudflare AS13335** 的第三方 CF 反代/proxyip 池，**官方 CF 段优选 IP**（如 byJoey/cfnew-ipdb 的 172.69.x、LancelotRar 的 CF 边缘段）一律不入池——否则 18k 池会瞬间膨胀到 10 万+，冲击全链路逐键作业的 CI 预算，且违背引擎设计意图。新增源须先采样核验 ASN 非 13335、端口 ∈ CF 边缘端口。**单源体积守卫**：`MAX_EXTRA_SOURCE_BYTES`（默认 4MB）超限的源整体跳过并告警，防任何未来源（或上游异常放大）拖垮标准抓取/解析开销。中文名与机场码经映射表归一为 ISO2（`proxyip_with_country.txt` 的 `IP#速度地区` 注释先剥离速度前缀再提取地区，如 `222.32(MB/s)HK香港`→`HK`；`#ALL` 为「无国家」哨兵，不会被误判为国别）；仍无国家的条目经 `ip-api.com/batch` 尽力补齐（每批 100、失败保留 `#ALL`）。单个来源失败仅告警跳过，不影响整体运行。来源标签：`json` 镜像若为通用清单名（`all.json`/`all.zip` 等，多镜像会共用 `all` 这一名字），会自动以注册域前缀消歧（如 `mirror-a/all`、`mirror-b/all`），避免不同镜像在来源统计/逐 IP 归属/健康监控中互覆；其余来源保持文件名主干。

**维护宗旨：只保留「非 Cloudflare AS13335 + Cloudflare 边缘端口」连接池。** 因此不收录 Cloudflare 官方边缘 IP（如 `byJoey/cfnew-ipdb`——其 IP 全属 AS13335，而 Workers 出站 `connect()` 禁止直连 CF IP 网段，无法用于自建链路）。最终产物经端口白名单 `443/8443/2053/2083/2087/2096` 过滤，其余端口桶一律丢弃——可用于 Worker 内部 `connect()` 直连。

主源 `all.json` 采用 **3 次线性退避重试**（1.5s/3s）后才回退 zip 镜像（镜像同样 3 次尝试）；附加 `.json`/`.zip` 源分别 3/2 次重试。`ip-api` 国籍批量按批重试 2 次，终失败仅跳过该批继续后续批次，网络抖动不再中断整次国籍填充。所有下载统一带**整体 wall-clock 截止**：`fetch_with_deadline`（daemon 线程 + `join(timeout)`）用于「返回 bytes」路径，`deadline_open`（上下文管理器、`resp.read()` 返回已读完整 body）用于 `with urlopen(...) as resp:` 形态的逐 IP 信仰抓取——覆盖 download 主源/`ip-api`、quality 探活与全部信誉 API（netcoffee/ncgy/greynoise/ipdata/getipintel/ipapi_is/ipquery/ffraud/whatismyip/blackbox/otx/proxycheck/ip2location/ipwhois/freeipapi/hackmyip/iplocation/scamalytics/stopforumspam/maltiverse）、external 校验、audit 国籍批量、健康 webhook。单次 `urlopen` 的 socket 超时只约束单次读写，遇到只回 200 头、响应体永不结束的上游仍会挂死管线——现在一律在 `timeout` 内按错误处理并走重试/兜底，任何上游都无法无限拖住流程（china_check 的 SSE 长连接轮询除外——其分块读取由内部 deadline 循环控制，不套用）。

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

除 `all.txt`/`ltd.txt` 外，每个国家/集合目录还会按 **出口家族 × 大陆可达** 生成分组文件 `v4.txt`/`v6.txt`/`46.txt`/`cn.txt`/`cn4.txt`/`cn6.txt`/`cn46.txt`（含对应 `*_ltd.txt`），根级另生成 `all_46.txt`/`all_cn4.txt`/`all_cn6.txt`/`all_cn46.txt`（含 `*_ltd.txt`）。家族优先取自 `exit_family.json`（无记录时回退行内 `-V4`/`-V6`/`-DS`；记录为 `unknown` 时判定无家族、不回落行内旧 token），大陆可达取自行内 `-CN` 或 `china.json` `verdict==reachable`（含 fallback 兜底）；空组不落盘并清理残留。详见 `docs/data-spec.md`「分组文件」。

每个清单（含根级 `all*.txt` 与全部分组）同步派生两个可靠性维度：`*_verified.txt`（本轮测速成功 = TLS + HTTP 2xx + 真实下载全链路通过，过滤半死代理）与 `*_stable.txt`（上一轮 `index.json` 与本轮存活的交集，抗 churn；首轮无上一轮数据时不生成）。可与任意分组叠加，如 `countries/US/cn4_verified.txt`、根级 `all_cn4_stable.txt`；`ltd` 家族同样派生（`ltd_verified.txt`、根级 `all_ltd_stable.txt`）。空清单不落盘并清理残留，数量计入 `meta.json` 的 `sets.all_verified` / `sets.all_stable`。

### `scripts/generate_stats.py`

读取历史与验证汇总，生成统计与一组零依赖 SVG 图表。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--out` | 输出目录 | `data/output/` |
| `--data-dir` | 输入数据目录（含 `quality/history.jsonl` 与 `valid/`） | `data/` |

| 输出文件 | 内容 |
|---|---|
| `chart_combo.svg` | 代理计数 + 存活率双轴折线图（近 7 天窗口） |
| `chart_country.svg` | 存活代理按国家 top-15 横向条形图 |
| `chart_port.svg` | 存活代理按端口纵向条形图 |
| `chart_churn.svg` | 每次更新 added / removed 分组条形图（近 7 天窗口） |
| `chart_latency_speed.svg` | 延迟与速度分桶双面板条形图 |
| `chart_sets.svg` | 各命名集合存活代理条形图 |
| `chart_cn.svg` | 大陆连通性分运营商状态（可达/覆盖 + min/中位延迟 ms；无 cn01 运营商数据时回退 verdict 分布） |
| `chart_cn_7d.svg` | 分运营商可达数折线趋势（近 7 天窗口，数据源 `cn_history.jsonl`） |
| `chart_family.svg` | 实际出口 IP 家族分布条形图 |
| `chart_source_avail.svg` | IP 来源覆盖率 + 每代理源数量分布 |
| `chart_source_stats.svg` | 每下载来源 IP 数量与重叠分布 |
| `chart_rep.svg` | 信誉分分布条形图 |
| `chart_exit.svg` | 出口国 Top15（common.build_exit_cc_map 三源 →CC 汇聚）条形图 |
| `chart_entry_audit.svg` | 入口国家标签审计 verdict 分布（audit_entry_cc 汇总） |
| `chart_ip_type.svg` | IP 类型（DC/RES/MOB/PROXY）分布条形图 |
| `chart_country_speed.svg` | 各国中位速度（Top20）条形图，附 Top5 的 p25–p75 区间文本注释 |
| `chart_speed_spread.svg` | 同国内部分化 Top-20（四分位差 `(p75-p25)/p50` 百分比） |

另生成 `country_speed.json`（各国 `n`/`p25`/`p50`/`p75`/`max`/`spread_pct`，样本 <5 的国家不收录）。

### `scripts/quality_check.py`

出口 IP 质量检测（独立 CI 运行，探测引擎拆分于 `quality_probe.py`：TLS GET / 外部出口地理回显 / ip-api 批量）。默认对 `data/valid/all.txt`（全量存活池）检测：

- **外部出口地理回显判活**（quality 链不做本地 TLS 握手，是以外部 API 回显为真相的独立证据链，与 validate 本地探测互不交叉；TLS 死键可用外部 API 结果复活，质量链同以其回显为准——`090227` 单源抖动时整池 `ext_check_ok` 会同降，属已知风险）
- **滚动可用率**：质量链每轮运行后由 `uptime.py` 更新 `node_seen.json`/`uptime.json`，注解链为节点追加 `-U<NN>` 备注
- **深测带宽加成**：`deep_speed.json` 的最优目标 `agg_mbps` 线性加成分数（封顶 +10，仅对已有信誉分节点生效）；深测数据超过 10 天（`DEEP_SPEED_TTL_DAYS`）视为过期，不再参与加分
- **出口 IP 解析**：信誉/地理/滥用查询使用真实出口 IP——优先外部探测回显，其次 `exit_family.json` 实测，兜底代理自身 IP（见 logic.md §4.0）
- 批量查出口 IP 地理（`ip-api.com/batch`）与 ASN/IP 类型

| 参数 | 说明 | 默认 |
|---|---|---|
| `--source` | 输入代理列表 | `data/valid/all.txt` |
| `--abuse-service` | 滥用分服务（none/abuseipdb/ipqs） | none |
| `--reputation-provider` | 信誉策略（multi/netcoffee/ip-api/none） | multi |
| `--reputation-sources` | multi 时启用的源（逗号分隔，见下）；**未知/拼错的源名打印警告并丢弃，杜绝 typo 静默变全量默认** | netcoffee,ncgy,ip-api,ipquery,ffraud,blackbox,otx,ipsum,ipdata,dc_asn,abuse_list,vpn_asn,resproxy_asn,proxycheck,ip2location,tor_exit,spamhaus,freeipapi,scamalytics,hackmyip,stopforumspam,cins,et_compromised,feodo,blocklist_de,blocklist_de_ssh,blocklist_de_apache,danmeuk_tor,tor_bulk,greynoise,urlhaus,threatfox,firehol_level1,binarydefense,c2_tracker,botscout,greensnow,sslproxies,socks_proxy,bruteforceblocker,dataplane_vncrfb,drb_c2,nordvpn_exits,blackhole_monster,myipms_blacklist,ipnoise,dshield,firehol_level2,dnsbl,spamcop,dronebl,abuseipdb_public,wwuyi_unreachable,wwuyi_blocked |
| `--reputation-weights` | 权重覆盖，如 `netcoffee:40,ncgy:20`；**未知源名/格式错误打印警告并丢弃** | 见下 |
| `--rep-cache-ttl` | 信誉信号缓存有效期（秒） | 604800（7 天） |
| `--no-rep-cache` | 禁用信誉信号缓存 | 关 |
| `-t, --timeout` | 单代理超时（秒） | 6 |
| `--read-cap` | 单次响应读取上限（字节） | 524288 |
| `-w, --workers` | asyncio 并发上限 | 60 |
| `--limit` | 只检测前 N 条（0 = 全部） | 0 |
| `--time-budget` | 最多执行秒数（0 = 不限）；到点停止开启新相位、已得结果仍落盘提交（探测相位让出 600s 余量，且 probe / ip-api geo / reputation / abuse **四个相位均受绝对 deadline 硬门控**：超龄不再新开任务、已提交结果照常落盘，防止某相位把 job 拖过 CI 超时硬杀） | 0 |

滥用分 key 从环境变量 `ABUSEIPDB_KEY`（abuseipdb）或 `IPQS_KEY`（ipqualityscore）读取，缺 key 时自动跳过。信誉分（0-100）**跨源共识合成**：abuse 分存在时取 `100 - score`（最高优先级）；否则先把各源的布尔标记归一为语义维度（`tor`/`proxy`/`vpn`/`hosting`(数据中心)/`mobile`/`abuse`/`listed`/`scraper`/`crawler`/`anonymous`），按源权重做**加权多数投票**——正票总权重 > 负票总权重才认定该维度为真，打平视为无结论（不扣分），避免单源误报独断与大权重单源主导；再叠加连续型风险源的加权罚分（`trust_score`、`probability`、`risk_score`、`fraud_score`、`score`、otx reputation/pulse、proxycheck risk）。查到出口地理（`countryCode`）即把 `ip-api` 计入（代理/机房/移动标志直接参与投票）；无任何信号则该项无分（不误判满分）。共识扣分表：tor 40 / abuse 35 / listed 30 / proxy 28 / vpn 22 / scraper 12 / hosting 10 / anonymous 8 / crawler 5；仅当 mobile 与其余风险维度均不成立时有 +5 加分。greynoise 源例外：经其确认的恶意类别直接按「60=恶意 / 35=僵尸(bot, riot) / 15=噪音」差异化罚分（覆盖 consensus 通用维度折算；同 IP 恶意确认时不再叠加噪音罚分）。**下表『说明』中的标志罚分/直用均为 legacy 单源口径；主路径统一折算为 consensus 语义维度 + 权重投票 + 共识扣分表（见上文），数值可能不同，以 consensus 为准。`ip-api` 的 mobile 奖励固定为 +5**。默认源与权重：

| 源 | 权重 | 说明 |
|---|---|---|
| `netcoffee` | 20 | `ip.net.coffee/api/iprisk/{ip}`，`trust_score` 直用；标志罚分：abuser 40 / tor 35 / proxy 30 / vpn 25 / datacenter 15，另加 `company_type`/`asn_kind` 机房 +15、`abuser_score`≥0.1 +20 |
| `ncgy` | 10 | `ip.nc.gy`（MaxMind 匿名 IP 库），`is_tor` 45 / `is_proxy` 30 / `is_vpn` 25 / `is_anonymous` 10 |
| `ip-api` | 15 | 本地批量地理的标志：proxy / hosting 判负、mobile 奖励 +5；`countryCode` 存在即计入 |
| `ipquery` | 12 | `api.ipquery.io/{ip}`，免 key；`risk_score` 直用，或标志罚分：tor 45 / vpn 30 / proxy 25 / datacenter 15（取二者较大罚分） |
| `ffraud` | 12 | `api.ffraud.com/public/ip/{ip}`，免 key；`fraud_score` 直用，或 tor/vpn/proxy/hosting/abuser/recent_abuse 罚分（取较大者） |
| `blackbox` | 10 | `blackbox.ipinfo.app/api/v3beta/{ip}`，免 key；分类评分：residential 95 / mobile 90 / business 85 / hosting 60 / vpn 55 / privacy_relay 50 / tor 10 / bogon 5 / unknown 50；suspicious -20 |
| `otx` | 8 | `otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general`，免 key；`100 - (min(reputation×5,80) + min(pulse_count×2,20))` |
| `ipsum` | 8 | GitHub 静态 IP 列表（stamparm/ipsum levels/3+），命中 3+ 黑名单 → 55 分 |
| `ipapi_is` | 8 | `api.ipapi.is`，**已退出默认源**（opt-in）——CI 生成的 `reputation_cache.json` 自加入以来 5 个版本中该源条目恒为 0（其余按 IP 源均有 ~1.8 万条），即 GitHub runner 从未成功拿到响应；疑似上游对云/机房出口限流或 TCP 丢弃，而每次失败要空等到 `IPAPI_IS_TIMEOUT=8s`，会显著吞噬信誉相位预算（疑为 92min 运行中 ~56min 空档的主因之一）。解析器与权重保留，出口可达时可用 `--reputation-sources` 重新启用。tor 45 / vpn 30 / proxy 25 / datacenter 15 / abuser 20，另加 `company.type`/`asn.type` 机房 +15、`abuser_score`≥0.1 +20 |
| `ipdata` | 8 | `api.ipdata.co`，限速 50 次/分；tor 45 / proxy 30 / vpn 25 / anonymous 10 + `threat_score` |
| `whatismyip` | 3 | `whatismyip.ai/api/lookup/{ip}`，免 key；`security.score` 直用，或 vpn/proxy/tor/hosting/blacklist 罚分（取较大者） |
| `dc_asn` | 5 | iplogs `datacenter-asns.csv` 静态机房 ASN 表，出口 `asn` 命中即 -15（fail-open） |
| `abuse_list` | 5 | FireHOL `firehol_abusers_1d` 静态滥用 IP/CIDR 表，命中即 -40（fail-open） |
| `vpn_asn` | 3 | iplogs `vpn-providers.csv` 静态 VPN 服务商 ASN 表，命中 -30（fail-open） |
| `resproxy_asn` | 2 | iplogs `residential-proxy-backbones.csv` 住宅代理骨干 ASN 表，命中 -25（fail-open） |
| `proxycheck` | 12 | `proxycheck.io/v3/{ip}`，免 key（100/天）；proxy/vpn/tor/hosting/scraper 标志罚分 + risk score |
| `ip2location` | 5 | `api.ip2location.io/?ip={ip}`，免 key（1000/天）；`is_proxy` 标志 -30 |
| `ipwhois` | 6 | `ipwhois.app/json/{ip}`，免 key；**已退出默认源**（opt-in）——免费层不再返回 `connection`/`security` 字段，纯信号为 0 却每轮仍产生 HTTP 调用；解析器保留，若上游恢复字段可用 `--reputation-sources` 重新启用。`security.proxy/vpn/tor/hosting` 各 -25、`security.anonymous` -8 |
| `tor_exit` | 5 | check.torproject.org 出口节点实时列表（免费），命中即投 `tor` 票 |
| `spamhaus` | 4 | Spamhaus DROP + EDROP 端用户高风险网段静态表（免费，`<cidr> ; 描述`），命中即投 `listed` 票 |
| `freeipapi` | 6 | `freeipapi.com/api/json/{ip}`，免 key；`isProxy` 标志 -30，附 ASN/org |
| `hackmyip` | 6 | `hackmyip.com/api/lookup?ip={ip}`，免 key；`data.privacy` 的 hosting/proxy/mobile 标志参与投票，附 ASN |
| `scamalytics` | 8 | `scamalytics.com/ip/{ip}` 免费风险页；`Fraud Score` 0-100 直扣，`is_blacklisted_external` 投 `listed` 票 |
| `iplocation` | 3 | `api.iplocation.net/?ip={ip}`，免 key；`is_proxy` -30，附 isp。**R269 起退出默认源**（最低权重、proxy 维度被 hackmyip/freeipapi/scamalytics 覆盖），opt-in 可用 |
| `stopforumspam` | 4 | `api.stopforumspam.org/api?ip={ip}&json`，免 key；`appears=1`（被举报的 HTTP 垃圾/滥用来源）投 `abuse` 票并 -50，`torexit=1` 额外投 `tor` 票；无记录返回空（负缓存） |
| `maltiverse` | 6 | `api.maltiverse.com/ip/{ip}`，免 key；`classification=malicious`/`suspicious` 投 `abuse` 票（-60/-35），`is_open_proxy`/`is_tor_node`/`is_vpn_node` 各投对应票（-25），`is_cnc`/`is_distributing_malware`/`is_iot_threat`/`is_known_scanner`/`is_mining_pool`/近 30 天黑名单命中投 `abuse` 票（-40）；**刻意忽略历史脏数据 `is_known_attacker` 与 `is_hosting`**；全空返回空（负缓存） |
| `cins` | 5 | CINS Army `ci-badguys.txt` 静态活跃滥用/拒绝服务 IP（免费），命中投 `listed` 票 |
| `et_compromised` | 4 | EmergingThreats `compromised-ips.txt` 被入侵主机（免费），命中投 `abuse` 票 |
| `feodo` | 4 | abuse.ch Feodo Tracker `ipblocklist.txt` 僵尸网络 C2 IP（免费），命中投 `abuse` 票 |
| `blocklist_de` | 4 | blocklist.de `all.txt` 僵尸/暴力破解/扫描滥用 IP（免费），命中投 `abuse` 票 |
| `blocklist_de_ssh` | 3 | blocklist.de `ssh.txt` SSH 暴力破解源 IP（免费，独立攻击类别），命中投 `abuse` 票 |
| `bruteforceblocker` | 3 | BruteForceBlocker `blist.php` SSH 爆破榜（`IP # …` 行内注释取首列，免费），命中投 `abuse` 票 |
| `dataplane_vncrfb` | 3 | dataplane.org `vncrfb.txt` VNC 爆破榜（`count | org | IP | …` 取第 3 字段，免费），命中投 `abuse` 票 |
| `drb_c2` | 4 | drb-ra C2IntelFeeds `IPC2s-30day.csv` 30 天审核 C2（`IP,描述` 取首列，免费），命中投 `abuse` 票 |
| `nordvpn_exits` | 3 | drb-ra `vpn/NordVPNIPs.csv` NordVPN 出口表（`IP,描述` 取首列，日更，免费），命中投 `vpn` 票 |
| `blackhole_monster` | 4 | blackhole.monster `blackhole-today` 每日攻击者裸 IP（免费，Maltrail 定性 known attacker），命中投 `abuse` 票 |
| `myipms_blacklist` | 4 | myip.ms `latest_blacklist.txt` 10 天攻击源（`deny from IP` 取第 3 列，免费），命中投 `abuse` 票 |
| `ipnoise` | 4 | IPnoise `7d.txt` 7 天蜜罐攻击者裸 IP（免费，蜜罐无合法服务），命中投 `abuse` 票 |
| `blocklist_de_apache` | 3 | blocklist.de `apache.txt` Web 探测/攻击源 IP（免费，独立攻击类别），命中投 `abuse` 票 |
| `danmeuk_tor` | 5 | dan.me.uk Tor 节点列表（免费，覆盖较 check.torproject 更全，独立权威），命中投 `tor` 票 |
| `tor_bulk` | 4 | check.torproject.org TorBulkExitList 出口节点（免费，tor 信号冗余），命中投 `tor` 票 |
| `greynoise` | 8 | `api.greynoise.io/v3/community/{ip}`（免 key）；特判罚分（见扣分表下方）：`classification=malicious` 60 / `riot`（僵尸网络成员）35 / 噪声扫描 15 |
| `urlhaus` | 5 | abuse.ch URLhaus 恶意软件分发托管列表（免费，静态），命中投 `abuse` 票 |
| `threatfox` | 5 | abuse.ch ThreatFox 恶意软件 IOC/C2（免费，静态），命中投 `abuse` 票 |
| `firehol_level1` | 5 | FireHOL level1 最严封禁集（静态），命中投 `listed` 票 |
| `firehol_level2` | 4 | FireHOL level2（L1 超集，裸 IP + CIDR，静态），命中投 `listed` 票（更广更噪，口径略弱） |
| `binarydefense` | 4 | Binary Defense 恶意 IP 封禁集（静态），命中投 `abuse` 票 |
| `c2_tracker` | 4 | C2 命令与控制基础设施名单（静态），命中投 `abuse` 票 |
| `botscout` | 3 | 僵尸网络/抓取机器人名单（静态），命中投 `abuse` 票 |
| `greensnow` | 4 | GreenSnow 活跃攻击/DDoS/扫描名单（静态），命中投 `abuse` 票 |
| `sslproxies` | 3 | 活跃 SSL 代理列表（独立代理族证据），命中投 `proxy` 票 |
| `socks_proxy` | 3 | 活跃 SOCKS 代理列表（独立代理族证据），命中投 `proxy` 票 |
| `vpn_ips` | 3 | X4BNet lists_vpn VPN 出口 IP/CIDR（静态），命中投 `vpn` 票 |
| `dshield` | 3 | FireHOL dshield_1d（DShield 攻击 /24 子网），命中投 `abuse` 票 |
| `dnsbl` | 8 | Spamhaus ZEN 实时 DNSBL（免 key，DNS-over-HTTPS）——SBL 2/3（劫持/垃圾网段）、XBL 4/5（被入侵主机）→ `listed` 票；PBL 6/7（邮件策略）与 CSS 8/9（snowshoe 弱信号）忽略 |
| `spamcop` | 5 | SpamCop `[REDACTED_PRIVATE_RESOURCE]` 社区实时 DNSBL（免 key，DNS-over-HTTPS）——`<rev-ip>.[REDACTED_PRIVATE_RESOURCE]` A 记录命中 `127.0.0.2` → `listed` 票；复用 dnsbl 的 DoH 端点回退/sticky/并发与负缓存，上限 9000/轮 |
| `dronebl` | 5（默认） | DroneBL `[REDACTED_PRIVATE_RESOURCE]` 社区僵尸/失陷主机实时 DNSBL（免 key，DNS-over-HTTPS）——命中码 2~13 → `listed` 票；复用 dnsbl 通路，上限 9000/轮（R269 新增） |
| `spamrats` | 5（opt-in） | SpamRats `[REDACTED_PRIVATE_RESOURCE]` 社区双通路实时 DNSBL（免 key，DNS-over-HTTPS）——`127.0.0.2`（AUTO）/`127.0.0.3`（AUTH）→ `listed` 票，DYN `127.0.0.4` 忽略；复用 dnsbl 通路，上限 9000/轮（R270 新增；R271 补接 `_flag_opinions`/`source_score` 计分接线；R272/R282 test-point＋NS 复测无结论，维持 opt-in 观察） |
| `sorbs` | 5（opt-in） | SORBS `[REDACTED_PRIVATE_RESOURCE]` 社区 open-proxy 实时 DNSBL（免 key，DNS-over-HTTPS）——`127.0.0.2`（SOCKS）/`127.0.0.7`（HTTP）→ `listed` 票，动态住宅段忽略；复用 dnsbl 通路，上限 9000/轮（R271 新增；R272/R282 test-point＋NS 复测无结论，维持 opt-in 观察） |
| `uceprotect` | 5（opt-in） | UCEPROTECT Level 1 `[REDACTED_PRIVATE_RESOURCE]` 社区发送者黑名单（免 key，DNS-over-HTTPS）——`127.0.0.2` → `listed` 票，仅用 L1（L2/L3 升级名单刻意不用）；复用 dnsbl 通路，上限 9000/轮（R272 新增；test-point `2.0.0.127` 经 DoH 实测回包 `127.0.0.2`，分区存活实证） |
| `psbl` | 5（opt-in） | PSBL `[REDACTED_PRIVATE_RESOURCE]` 被动垃圾邮件黑名单（免 key，DNS-over-HTTPS）——`127.0.0.2` → `listed` 票；复用 dnsbl 通路，上限 9000/轮（R273 新增；test-point `2.0.0.127` 经 DoH 实测回包 `127.0.0.2`）。R273 起七源 lookup 共用 `_dnsbl_listed_lookup_sync` 骨架，各源仅保留 qname/码表/ docstring 差异 |
| `abuseipdb_public` | 5 | AbuseIPDB 公共黑名单（近 30 天置信举报，社区镜像，静态），命中投 `abuse` 票 |
| `wwuyi_unreachable` | 2 | Wwuyi123 实测不可达 IP（裸 IP 小表，静态），命中投 `listed` 票（温和：失联证据非滥用） |
| `wwuyi_blocked` | 2 | Wwuyi123 维护者拉黑 IP（裸 IP 小表，静态），命中投 `listed` 票（主动拒绝，略强，仍非滥用） |

> **cleanip.io 结论（信誉专场勘察）**：`cleanip.io` 的 `/check` 页面对外展示 0-100 纯净度 + 欺诈分（模型 `proxypurity`），其维度与上方源高度重叠（aggregates ipquery/ipdata/scamalytics/maltiverse/greynoise/threatfox + **DNSBL** + HTTP 蜜罐）。但其后端 `api/v2/*` 一律返回 `401 {"code":"need_token","error":"anti-bot token required"}`，按 IP 查询需登录/anti-bot token，**不可作为开源免 key 数据源直接接入**；本轮新增的 `dnsbl` / `abuseipdb_public` 即补齐其模型中的 DNSBL 与恶意举报维度，缩小与在线评分差额。ipwho.is 免费层 security 已退化 null、ipapi.co 被 Cloudflare 挑战墙拦截，均不可用。
>
> **dnsbl 实证命中（R252，实时 DoH）**：当前出口集中 `109.120.176.0/24`、`109.120.179.0/24`（疑似回连 Spamhaus SBL 网段）经 `dnsbl_lookup_sync` 实测返回 SBL `127.0.0.2`，但旧数据对 `109.120.176.4:443#DE` 与 `109.120.179.35:2053#FR` 均评 **89（flags=anonymous）**——与 cleanip 侧「垃圾段重罚」的判据明显背离。接入 dnsbl 后此类命中按 consensus `listed` 维度扣 **30**（89→59，进入 <75 high 风险带），即向 cleanip 判据收敛的量级。全链路 `lookup_all_risk(sources=['dnsbl'])` 于本地 28 个出口 IP 烟测 5.0s、命中 1、负缓存哨兵 27，确认 per-IP 路径与负缓存语义正确。

可选源（opt-in）：`getipintel`（5 权重，需环境变量 `GETIPINTEL_EMAIL`，1 worker、4s 间隔、上限 2000 次/运行，得分 `100 - prob×100`）。静态列表每 run 拉取一次，失败即跳过（运行日志打印 `Reputation static lists: <name>=<n>…`，**已启用但为空/拉取失败 fail-open 的源亦以 `<name>=0` 显式列出**，区别于未启用；网关把错误页以 200 原样吐出（HTML/JSON）会被内容门槛识别并告警 `non-list content`，不再静默滤成空表假「干净」；约 8MB 的 abuseipdb_public 使用放宽的 45s 超时避免慢网统一 15s 截断吞空，其余列表维持 15s）；按 IP 的免 key 源各自限速见下表，新源按轮次上限 + 7 天缓存逐回填覆盖，避免首轮撑爆作业预算；带上限（如 dnsbl 12000）的源在 need 超限时日志显式标注 `cap-truncated N`，避免超限截断被静默吞掉误导覆盖率审计；cap 压力下（首轮回填/缓存大面积失效）优先查询从未有过信号的 IP，有过期旧缓存的 IP 让位（其旧信号以 fallback 注入兜底、下轮补查），保证无覆盖 IP 不被反复挤掉）避免限流掉单。R302 实测七分区 test-point DoH 延迟：41~425ms（psbl/spamcop/sorbs 最快，spamrats 425ms），dronebl 2.5s 最慢仍低于单端点 4s 超时；sticky 首命中即复用 alidns。sorbs/spamrats 为快速 definitive 空应答（非超时），查询通路存活、测试点未列入，不做生死判定，维持 opt-in 观察。**信誉缓存**：各按 IP API 源的信号写入 `data/quality/reputation_cache.json`，TTL 内（默认 7 天，`--rep-cache-ttl` 可调）复用缓存、只查询缺失/过期的 IP；**成功但无信号的源以 `data:{}` 负缓存**（如 greynoise 干净 IP），TTL 内不重查且不进入共识投票（负缓存 TTL 上限 `NEG_CACHE_TTL` 默认 1 天，短于正 TTL）；无信号不重试（仅异常重试）；**过期条目不删除**——过期后每轮尝试刷新，若刷新失败回退使用最近缓存信号（保持数据最新而非过期即丢），直至被新条目挤出上限；`--no-rep-cache` 禁用；静态列表不缓存、每轮重拉。缓存表按每个 IP 最近一次信号时间封顶 `REP_CACHE_MAX`（4 万条），超限自动裁剪最旧条目防无限膨胀。风险等级：`<30` high、`<75` medium、其余 low。`tls` 方法代理无出口回显，直接用代理自身 IP 作为出口参与检测与 `ip-api` 地理（入口即出口，`ip-api` 计入规则与其源相同）。结果写入 `reputation.json` 与 `all_rep.txt`（按信誉降序），`ipinfo.json` 每个键含 `rep_flags`/`rep_sources`/`risk_sources`（存在 abuse 分时经 `derive_risk` 直接分解、不逐源列出），`reputation.json` 含 `flags`/`numeric`（有 deep_speed 带宽加成时另有 `deep_bonus`）。分数也追加进 `#` 备注末尾。rep 交叉矩阵（`all_{g}_rep.txt`、`all_{g}_rep_ltd.txt`、子目录 `rep.txt` 等）同步派生 `*_verified.txt`（speed.json 全链路验证）与 `*_stable.txt`（china.json streak≥2 跨轮稳定）变体；子目录分组 rep 保持单维度以控制文件数量。检测结果见下方数据文件；备注写入按 `#` 后格式追加。

| 源 | 并发/间隔 | 上限与备注 |
|---|---|---|
| `netcoffee/ncgy` | 10 worker、0.15s |  |
| `blackbox/proxycheck` | 8 worker、0.2s |  |
| `ipapi_is` | 8 worker、0.2s |  |
| `otx` | 6 worker、0.3s |  |
| `ipquery/ffraud/whatismyip/ip2location/ipwhois` | 6 worker、0.2s |  |
| `freeipapi` | 8 worker、0.15s | （上限 3000/轮） |
| `hackmyip` | 6 worker、0.2s |  |
| `scamalytics` | 4 worker、0.5s | （上限 1500/轮） |
| `stopforumspam` | 4 worker、0.3s | （上限 3000/轮） |
| `dnsbl` | 6 worker、0.2s | （上限 12000/轮，Spamhaus ZEN 实时 DoH，`dns.alidns.com`→`cloudflare-dns.com`→`dns.google/resolve` 端点回退且**进程内 sticky 复用最近成功端点**（TTL 600s，加锁保证多 worker 并发下无竞态，避免每查询空等慢/死端点），全部失败按失败重试、不误判干净） |
| `spamcop` | 6 worker、0.15s | （上限 9000/轮，[REDACTED_PRIVATE_RESOURCE] 社区实时 DNSBL） |
| `sorbs` | 6 worker、0.15s | （上限 9000/轮，`[REDACTED_PRIVATE_RESOURCE]` opt-in DNSBL，SOCKS/HTTP 代理码 127.0.0.2/7——**R271 新增 opt-in 源；R274 起 pacing 与其余 DNSBL 归一 0.15s**） |
| `dronebl` | 6 worker、0.15s | （上限 9000/轮，[REDACTED_PRIVATE_RESOURCE] 僵尸/失陷主机社区 DNSBL，命中码 2~13 均判 listed，复用 dnsbl 同一 DoH/负缓存/sticky 通路） |
| `spamrats` | 6 worker、0.15s | （上限 SPAMRATS_CAP=9000/轮，[REDACTED_PRIVATE_RESOURCE] 社区双通路 DoH，A 码 127.0.0.2/3 → listed，**DYN 127.0.0.4 忽略**，复用 dnsbl sticky/负缓存——**R270 新增 opt-in 源**；R272 实测 test-point 无响应，保持 opt-in 待验证） |
| `uceprotect` | 6 worker、0.15s | （上限 UCEPROTECT_CAP=9000/轮，[REDACTED_PRIVATE_RESOURCE] L1 社区发送者黑名单 DoH，A 码仅 127.0.0.2 → listed，L2/L3 不用，复用 dnsbl sticky/负缓存——**R272 新增 opt-in 源**，test-point `2.0.0.127` 实测回包 `127.0.0.2`） |
| `psbl` | 6 worker、0.15s | （上限 PSBL_CAP=9000/轮，[REDACTED_PRIVATE_RESOURCE] 被动垃圾名单 DoH，A 码仅 127.0.0.2 → listed，复用 dnsbl sticky/负缓存——**R273 新增 opt-in 源**，test-point 实测回包 `127.0.0.2`） |
| `maltiverse` | 4 worker、0.3s | （上限 MALTIVERSE_CAP=2500/轮，opt-in） |
| `greynoise` | 6 worker、0.3s | （无轮次上限，上游免费 40 req/min 限流） |
| `iplocation` | 8 worker、0.12s | （上限 IPLOCATION_CAP=3000/轮，opt-in） |


### `scripts/quality_probe.py`

TLS 探测引擎（quality_check 内部调用/独立运行）。对存活代理执行 TLS GET 握手，
支撑 `tls` 判定方法与外部出口地理探测（优先 `/exit` 明文回显、失败降级
`ip-api` 批量地理）。消费 `data/valid/all.txt` 本轮存活集，产出
`data/quality/ipinfo.json`（每键 `exit_geo`/`ipv4_ok`/`ipv6_ok` 等）与
`data/valid/ext_check.json`（`--ext-check` 时，单源 `090227` 外部出口回显）。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--timeout` | TLS 握手超时（秒） | 5 |
| `--ext-check` | 启用外部出口回显（引入 `ext_check.json` 产物） | 关 |
| `--quick-prefilter` | 先做 TCP 预筛再入完整 TLS 检测 | 关 |

### `scripts/quality_reputation.py`

信誉/滥用分模块（quality_check 拆出，仅被 `quality_check.py` import，无
独立 CLI `__main__`）。汇总免 key 风险源（`netcoffee`/`scamalytics`/
`ipapi_is`/`otx`/`ipquery`/`iplocation` 等）与可选 `getipintel` 信号，叠加
`deep_speed` 带宽加成（`deep_bonus`），产出 `data/quality/reputation.json`、
`all_rep.txt` 及各分组 `rep` 交叉矩阵；缓存写入 `reputation_cache.json`
（默认 7 天 TTL，`--rep-cache-ttl` 可调，`--no-rep-cache` 禁用；无信号源以
`data:{}` 负缓存、TTL 内不重查；过期条目保留为刷新失败时的兜底信号，
不随过期删除）。参数
（`--getipintel-email`/`--rep-cache-ttl`/`--no-rep-cache`）经 quality_check
透传生效。

### `scripts/reorg_country.py`

按出口 IP 国家重组 country/set/port 文件。出口国观测经三源汇聚
（`common.build_exit_cc_map`：`external_check.json` > `upstream_meta.json` >
`ipinfo.json`，见 logic.md §7.2），命中观测的行一律
upsert `→OC` 标记（同国也标注，陈旧出口直接替换）；仅当位于
`countries/<CC>/` 且与出口国不同时才迁移目录，sets/ports 混国文件只标注
不移动。幂等：重复运行不产生变化。全部处理完后剪除无 `all.txt` 的孤儿
国家目录（其全行已迁出，残留的 cn/rep/ltd 分支文件属过期数据，整树移除）。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--data-dir` | 数据根目录 | `data/` |
| `--ipinfo` | ipinfo.json 路径 | `<data-dir>/quality/ipinfo.json` |

影响目录：`countries/*/all.txt`、`sets/*/all.txt`、`ports/*.txt`。子分组文件（`cn.txt`、`v4.txt` 等）不处理，由下次 `annotate_classify.py` 刷新。

### `scripts/audit_entry_cc.py`

入口国家标签准确性审计。订阅标签（`#CC`）此前无从验证，本脚本以两个
独立信号交叉对比：① 入口 IP 地理（ip-api batch，含 ASN）；② 出口国观测
（三源 exit map：external_check/upstream_meta/ipinfo，exit_family 仅贡献候选键）。判定写入 `data/quality/entry_audit.json`（`proxies[key].verdict`）并打印汇总；入口地理以 `data/quality/entry_geo.json` 按轮缓存，仅查缺失 IP。

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
| `--timeout` | 单批 HTTP 超时（秒） | 10 |
| `--delay` | 批间延时（秒），ip-api 免费档限 45 req/min | 1.5 |

### `scripts/china_check.py`

大陆连通性检测（独立 CI 运行）。CI 以 `--source data/valid/all.txt --limit 0` 全量池检测；本地缺省按 `data/valid/all_rep.txt` 信誉降序采样前 250 条（缺失时回退 `all.txt`，`FALLBACK_SOURCE`）。从大陆视角实测 TCP 可达性，分三层判定（曾有的 **L1 启发式**基于行内 `-CF` 死标记记录 heuristic 源，随 CF token 废弃一并移除，china.json 不再写 `cf_heuristic` 字段）：

- **L2 批量通道 cn01 实测（主源）**：每任务 5 目标 × 电信/联通/移动各 6 节点（共 18 节点，`CN01_NODES_PER_ISP=6`），经 WebSocket 收结果，TCP 连通即判可达；节点按运营商归属（id 映射兜底节点名关键词），任务级另出 per-ISP 最小 RTT（`isp_ms`），落 china.json 后供 CN 清单取**最快运营商视角**（`common.cn_fastest_ms`）渲染展示延迟与 `≈XMB/s` 速度。cn01 失败/被限的键另有两条同站降级：纯 TCP 大节点池（记 `cn02` 源）；CN-26 ICMP 大节点池电信 87/联通 83/移动 89（记 `cn03` 源，归一 `level=icmp`、不产 `isp_ms`）
- **L2 单节点实测（并发）**：`cn27`（呼和浩特阿里云节点，匿名限速 5/10s、250/h，配置 key 可放宽；CN-31 起 TCP-fail 追加同节点 ICMP ping 消歧，CN-32 起 TCP-ok 且其余免额 0 ok 追加同节点 HTTPS 应用层确认，共用配额）+ `cn20`（北京节点 TCP，免 key）+ `cn21`（CN-29：山东枣庄 BGP 节点 ICMP，免 key，`level=icmp`，echo 校验，不产 `isp_ms`）+ `cn22`（CN-38：同站 HTTP 状态码，免 key，`level=http`，`-2` 判 fail，无 ms）+ `cn23`（CN-39：同站 8 端口扫描，仅 443 键产出，`level="tcp"` 布尔见证）+ `cn24`（浙江宁波电信 TCP，免 key 双镜像；CN-39 起 ok 附 `isp_ms={中国电信}`）+ `cn25`（CN-25 新增：同站同节点 ICMP 主机存活，免 key，`level=icmp`，不进延迟显示/不产 `isp_ms`，与 ICMP 源同口径；CN-26 起三端点主站异常自动 failover 同站镜像，429 不切换）+ `cn26`（CN-37 新增：同站同节点 TLS 握手，免 key，`level="tcp"` 保守，无 ms 只作布尔见证）+ `cn36`（CN-46 新增：社区探针北京节点 ICMP ping，匿名免 key（250/h 配额），`level="icmp"`，不产 `isp_ms`；CI 以 60 键/4 并发启用）+ `cn37`（CN-47 新增：同站同 API 路由追踪，末跳达目标即见证，`ms` 恒空，`level="icmp"`，不产 `isp_ms`；CI 以 40 键/4 并发启用）+ `cn38`（CN-48 新增：同站同 API 应用层确认，明文打 TLS 端口状态码即往返，`ms` 取 `timings.tcp`，`level="http"`，不产 `isp_ms`；CI 以 40 键/4 并发启用）+ `cn39`（CN-49 新增：同站同 API MTR，任一 hop 末跳达目标即见证，`ms` 恒空，`level="icmp"`，不产 `isp_ms`；CI 以 40 键/4 并发启用）。**保守判定：多节点源（cn40/cn01/cn41/cn02/cn03/cn30/cn31/cn32/cn07/cn08/cn14/cn15/cn17/cn18/cn16/cn11/cn12/cn09/cn10/cn04/cn34/cn42/cn43/cn44/cn13，与 `merge_verdict` 的 `multi_ok` 表一致）单独确认 → reachable；单节点源（cn27/cn28/cn29/cn20/cn21/cn22/cn23/cn24/cn25/cn26/cn36/cn37/cn38/cn39）≥2 个确认 → reachable；仅 1 个确认 → uncertain；均失败 → unreachable**
- **L3 多节点复核（有界并发小样本）**：`cn30`（免费 REST，~146 大陆节点按运营商均衡采样 10 个，TCP `ip:port` 直连，节点成功率达 50% 即判可达）先于 cn40 跑——免费、端到端 ~2-6s/键，确认过的键自动让位；`cn31`（CN-33：同站 `type=ping`，裸 IP 目标，`success`＋`avg_ms>0`，`level=icmp`，不产 `isp_ms`，与 TCP 共用节点采样跑在 TCP 相之后）；`cn32`（CN-35：同站 `type=http`，`http://ip:port/`，`success`＋`status>0` 即应用层确认，`level=http`，ms 取 `connect_ms`，与 TCP 同口径产 `isp_ms`，跑在 ping 相之后）；`cn33`（CN-40：同站 `type=traceroute`，裸 IP 目标，`success` 即达判，`ms` 恒空，`level=icmp`，不产 `isp_ms`，跑在 http 相之后）；`cn07`（18 ICMP 节点，成功率达 50% 判可达，专测中国大陆主机存活）；`cn08`（~12 节点 ICMP ping，纯 HTTP+SSE 零鉴权）；`cn14`（~155 节点，JWT+WS，ICMP ping / TCP `ip:port` 均可）；`cn17`（~163 TCP 节点，SHA-256 PoW + ALTCHA 会话复用纯 Python 求解 + WS，真实端口直连；CN-30 起同通道 `cn18` ICMP 并行，`level=icmp`，紧凑键 `r/q` 判定，不产 `isp_ms`；CN-44 起同基建 `cn19` MTR 通道，约 139 节点，末跳达目标即见证，`level=icmp`，不产 `ms`/`isp_ms`，同族 `traceroute` 型后端容量不稳不接入）；`cn16`（~53 ICMP 节点，服务端渲染 token + WS）；`cn11`（34 个大陆各省运营商节点持续 TCPing，socket.io v4 over WebSocket，CF 反爬用 HTTPS+Referer 壳页取节点、连 `wss://<源站>/socket.io` 发/收事件，零 key，实测 35/35 节点出数）；`cn12`（CN-36：同站 continuous-ping，35 节点 socket.io，事件与 TCP 全同形，`level=icmp`，不产 `isp_ms`，活体 35/35 出数）；`cn09`（约 39 个 ISP×节点 TCPing 测量单元，HTTP+SSE 零鉴权，协议细节已迁 PCB，实测 39/39 出数）；`cn10`（CN-34：同站 ICMP，复用 port="" 分支，`level=icmp`，剥离 `isp_ms`，活体 39/39 出数）；`cn04`（CN-27：28 城三网 TCPing，`level=tcp`，原生分 ISP；CI 200 键/6 并发启用）；`cn05`（CN-50：同站 HTTP 测速通道，`status_code>0` 即应用层确认，`level=http`，活体 27/28 出数；仅 443 键可用；CI 200 键/6 并发启用）；`cn06`（CN-42：公开 WS 通道约 16 节点 TCPing，原生分三网，活体 16 节点出数；CI 以 200 键/6 并发启用）；`cn34`（CN-43 复活：同路径 GET+SSE 新接口，约 287 节点 TCPing，`isp` 原生三网，活体 287 节点出数；CI 以 100 键/8 并发启用）＋`cn35`（CN-45：同站路由追踪，hop 行目标 IP 即见证，`level=icmp`，不产 `ms`/`isp_ms`，CI 以 100 键/8 并发启用）；`cn15`（CN-28：cn14 同站 ICMP，复用 code=3 分支，`level=icmp`，不产 `isp_ms`，活体 178/179 出数）；随后 `cn40`（约 13 个大陆节点，≥7/13 可达即判可达，报告不足 5 节点 → inconclusive），各源均只投「当前尚未被 cn01/单节点源判可达」的键且按 `--cn-limit CODE=N` 有界；多节点源须「≥ `MULTI_MIN_NODES`（5）个节点 + 成功率达标」才可独立判 reachable，防限流残缺样本假阳性；可选 `cn41`（多运营商，需站长签发 token（`--tcpping-token`/`TCPPING_CN_TOKEN` env），缺则自动跳过）

| 参数 | 说明 | 默认 |
|---|---|---|
| `--source` | 输入代理列表 | `data/valid/all_rep.txt` |
| `--limit` | 按信誉降序采样条数（0=全部） | 250 |
| `--workers` | L2 并发上限 | 56 |
| `-t, --timeout` | 单次 HTTP 超时（秒） | 10 |
| `--api-key` | cn27 站 key（读 `CHINA_CHECK_API_KEY`） | 空 |
| `--tcpping-token` | cn41 复核 token（读 `TCPPING_CN_TOKEN`） | 空 |
| `--cn01-nodes` | cn01 每大陆运营商取节点数（`--cn01-nodes`×3 → 跨省等距采样） | 6 |
| `--cn01-batch-size` | cn01 每任务目标数（上限 5） | 5 |
| `--cn01-concurrency` | cn01 并发任务数 | 8 |
| `--cn01-pacing` | cn01 两次任务启动最小间隔（秒） | 0.5 |
| `--cn01-timeout` | cn01 单任务收结果上限（秒） | 45 |
| `--skip-cn01` | 跳过 cn01 批量探测 | 关 |
| `--skip-cn02` | 跳过 cn02 大节点池补测 | 关 |
| `--dry-run` | 只输出计划，不发请求不写盘 | 关 |
| `--cn-latency-cap` | CN 清单大陆视角 RTT 门槛（ms，`inf` 关闭） | 150 |
| `--cn-cache-ttl` | CN 结果缓存秒数（复用 china.json 内 `checked_at` 未过期的 reachable/uncertain 键并跳过复测；CI 6 小时） | 0 |
| `--cn-limit` | 按代号覆盖复核条数（可重复，如 `--cn-limit cn30=800`；优先于注册表默认） | 空 |
| `--cn-concurrency` | 按代号覆盖并发数（可重复；优先于注册表默认） | 空 |
| `--cn-nodes` | 按代号覆盖每键采样节点数（可重复） | 空 |

各代号默认值（由 PCB 注册表自动生成，勿手改；条数 0=跳过，-1=全部未定键；`常开`=L2 常开/配额族无条数概念）：

| 代号 | 说明 | 条数 | 并发 |
|---|---|---|---|
| `cn01` | cn01 批量多节点复核主通道（HTTP 任务，三网聚合） | 常开 | — |
| `cn02` | cn02 批量多节点复核降级通道（cn01 失败时补测） | 常开 | — |
| `cn03` | cn03 批量多节点 ICMP 复核通道 | 常开 | — |
| `cn04` | cn04 WS 多节点 TCPing 复核 | 0 | 6 |
| `cn05` | cn05 HTTP 多节点应用层复核（仅 443 键） | 0 | 6 |
| `cn06` | cn06 公开 WS 通道多节点 TCPing 复核 | 0 | 6 |
| `cn07` | cn07 大陆多节点 ICMP 复核 | 0 | 24 |
| `cn08` | cn08 多节点存活复核（HTTP+SSE） | 0 | 8 |
| `cn09` | cn09 SSE 多节点 TCPing 复核 | 0 | 8 |
| `cn10` | cn10 SSE 多节点 ICMP 复核 | 0 | 8 |
| `cn11` | cn11 socket.io 多节点 TCPing 复核 | 0 | 6 |
| `cn12` | cn12 socket.io 多节点 ICMP 复核 | 0 | 6 |
| `cn13` | cn13 WS 多节点 TCPing 复核（休眠态保留） | 0 | 6 |
| `cn14` | cn14 WS 多节点 TCPing 复核 | 0 | 8 |
| `cn15` | cn15 WS 多节点 ICMP 复核 | 0 | 8 |
| `cn16` | cn16 WS 多节点存活复核 | 0 | 6 |
| `cn17` | cn17 WS 多节点 TCPing 复核 | 0 | 6 |
| `cn18` | cn18 WS 多节点 ICMP 复核 | 0 | 6 |
| `cn19` | cn19 WS 多节点 MTR 复核（末跳见证） | 0 | 6 |
| `cn20` | cn20 单节点 TCP 复核（L2 常开） | 常开 | — |
| `cn21` | cn21 单节点 ICMP 复核（L2 常开） | 常开 | — |
| `cn22` | cn22 单节点状态码复核（L2 常开） | 常开 | — |
| `cn23` | cn23 单节点端口扫描复核（L2 常开） | 常开 | — |
| `cn24` | cn24 单节点 TCP 复核（L2 常开） | 常开 | — |
| `cn25` | cn25 单节点 ICMP 复核（L2 常开） | 常开 | — |
| `cn26` | cn26 单节点 TLS 握手复核（L2 常开） | 常开 | — |
| `cn27` | cn27 单节点 TCP 二次确认（配额） | 常开 | — |
| `cn28` | cn28 单节点 ICMP 存活确认（配额，共用限速器） | 常开 | — |
| `cn29` | cn29 单节点应用层确认（配额） | 常开 | — |
| `cn30` | cn30 多节点 TCPing 复核 | 150 | 8 |
| `cn31` | cn31 多节点 ICMP 复核 | 0 | 8 |
| `cn32` | cn32 多节点应用层复核 | 0 | 8 |
| `cn33` | cn33 多节点路由追踪复核 | 0 | 8 |
| `cn34` | cn34 多节点 TCPing 复核 | 0 | 6 |
| `cn35` | cn35 路由追踪复核（末跳见证） | 0 | 6 |
| `cn36` | cn36 社区探针 ICMP 复核 | 0 | 4 |
| `cn37` | cn37 社区探针路由追踪复核 | 0 | 4 |
| `cn38` | cn38 社区探针应用层复核 | 0 | 4 |
| `cn39` | cn39 社区探针 MTR 复核 | 0 | 4 |
| `cn40` | cn40 多节点 TCP 复核（有界并发小样本） | 300 | 6 |
| `cn41` | cn41 多运营商 TCP 复核（搭 pingpe 相，需 token） | 常开 | — |
| `cn42` | cn42 多节点 TCPing 复核（休眠） | 0 | 6 |
| `cn43` | cn43 多节点 TCPing 复核（休眠） | 0 | 6 |
| `cn44` | cn44 多节点 TCPing 复核（休眠） | 0 | 6 |

结果写入 `china.json`（keyed 明细，含各源 status/ms 与合成 verdict；cn01 源另含每运营商最小 RTT `isp_ms`）与 `all_cn.txt`（全量大陆可达清单，源为 `data/valid/all.txt`，仅含本轮判定 reachable 的行，历史累积 `-CN` 不再自动纳入；缺 all.txt 时回退 all_ltd.txt）；可达者在 `all.txt`/`all_ltd.txt` 追加 `-CN` 备注（幂等，当前不可达者撤销失效 `-CN`）。

**代号注册表终态**（R13 结论）：源元数据唯一真相源为 PCB `pcb/plugins/_sources.py`（44 代号：family/runner/channel/level/flag/limit/concurrency/min_ratio/verdict/desc）；公开侧旗标默认值、dispatch 码、engine 判定集/比率表、本表默认值、毕业链配额校验（`TestWorkflowCodesInRegistry`/`TestRegistryDocsTable`）全部由其派生（帮助文案仍为手写，由 `TestChinaHelpFlagsMatchDocs` 锁与本表对等）。以下三类字面保留，属结构必需而非硬编码信息：① `cn_opt(args, "cn30", …)` 类调用点代号（join key；通用 phase 循环可收敛但徒增间接层，另议）；② 无包回退静态表（CI 无 PCB 时 fail-open 的基石，移除条件＝CI 直连 PCB 即 `BUNDLE_PAT` 落地）；③ workflow 配额与 china.json 键中的代号（算子配置引用 ID，非代码硬编码；一致性由上锁测试保证）。

**稳定子集准入**（`*_stable.txt` 系清单）：`china.json` 连续可达轮数 `streak` ≥ 2 **且** 历史翻转计数 `flip` ≤ `STABLE_MAX_FLIP`（1，排除可达↔不可达慢性振荡源）；`streak` 跨轮累计，间隔 ≤ 6h 容差（`STREAK_GAP_TOLERANCE_S=6×3600`）内延续计数，超容差重新从 1 起算。

### `scripts/exit_family.py`

由 `exit-family.yml` 在 **Quality check 完成时触发**（`workflow_run` type `completed`），并发组 `exit-family`（`cancel-in-progress: false`——不抢占在跑的家族轮，排队串行）。因此 `exit_family.json` 对齐的是**上一轮已完成**的 Quality 批次而非当前 in-progress 轮（批次错位属预期时序，对账时应取同一批快照）。**触发者失败也照常运行**：与 `annotate-classify` 同策略——它 checkout 仓库自洽快照（上次成功轮），上游单次失败不应冻结家族判定（`-V4`/`-V6`/`-DS` token 与 `exit_family.json` 是后续分组/清单的权威来源）。

实际出口 IP 家族（IPv4/IPv6）检测（独立 CI 运行）。默认对 `data/valid/all.txt`（全量存活池）逐条 **双栈探测** 真实出口家族：

- 分别请求仅 IPv4 与仅 IPv6 的回显服务（纯 IP 文本），**每族双服务商**：`ipv4.icanhazip.com` + `api4.ipify.org`（v4）、`ipv6.icanhazip.com` + `api6.ipify.org`（v6）。同族两源**按序尝试、首个成功者生效**（互备而非必双侧一致）；「双源互证」体现在跨家族：v4/v6 两族各自拿到非空字面量且**不同** → `evidence=cross` 硬 dual 证据，字面量**相同** → `single_path`（跨服务商一致的单栈强证据）；仅一族可达 → `one_sided`。`verify_pinning()` 对回显源做记录钉扎自检（仅诊断日志，不阻断探测）。两族全失败则尝试 `cloudflare.com/cdn-cgi/trace` 兜底。注意：CF 边缘代理的出口由 Worker fetch() 决定、与入口/目标主机名无关（trace 只回显单 IP），故 CF 类代理 `dual` 恒为 0 属架构固有行为

家族判定：仅 v4 → `ipv4`；仅 v6 → `ipv6`；双通 → `dual`；探测全失败 → `unknown`。结果写入：

- `all_ipv4.txt` / `all_ipv6.txt` — 按家族分离的代理清单（**双栈同时计入两个文件**，`unknown` 不入任何文件）
- `exit_family.json` — 逐条明细（keyed，含 `family`、`exit_v4`/`exit_v6`、`method`）
- 并在 `all.txt`/`all_ltd.txt` 对应行追加 `-V4`/`-V6`/`-DS` 备注（幂等，`DS` 与质量检测已有的双栈 token 一致）

`family=unknown`（探测全失败）时**不追加任何家族 token，并清掉行内旧 token**：宁可未知也不冒称单栈/双栈——旧轮残留的 `-V4`/`-V6`/`-DS` 会误导下游 `v4`/`v6`/`46` 分组与 `premium`/`validated` 分支划分（`annotate_classify` 对 `family_map` 显式记 `unknown` 的 key 一并清桶；整体缺 family 数据时保持行内 token 不变）。

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
python3 scripts/generate_fingerprint.py
python3 scripts/generate_fingerprint.py -n 5
python3 scripts/generate_fingerprint.py -n 1 -s 42 --pretty
```

示例输出：

```json
{"os": "macos", "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...", "platform": "MacIntel", "language": "en-US", "languages": ["en-US", "en"], "timezone": "Europe/Paris", "screen": {"width": 2560, "height": 1440, "colorDepth": 24, "devicePixelRatio": 2.0}, "hardwareConcurrency": 10, "deviceMemory": 16, "webgl": {"renderer": "ANGLE (Apple, Apple M1, OpenGL 4.1)", "vendor": "Apple"}, "canvasHash": "9f3b2c1d4e5a6b7c"}
```

### `scripts/annotate_classify.py`

后缀填充 + 节点分类（CI 在 quality-check 完成后自动运行）。读取 7 个 JSON 数据源，向所有 `data/valid/*.txt` 文件填充缺失后缀并追加分类 token。幂等设计：多次运行结果一致。所有备注写入统一经 `common.normalize_note` / `merge_note_tokens` / `clear_note_buckets` 处理（规范段序 + 互斥桶先清后设），禁止裸拼接。

**触发语义**：`annotate-classify.yml` 由 Quality check 完成触发，但 **gate 不因触发工作流失败而跳过**——它从仓库 checkout 的自洽数据（上次成功轮快照）运行，上游单次失败不应冻结 CN 连通性追踪（streak）与后缀应用，否则 IP 未变更期间 stable 永远无法累积。

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
| `uptime.json` | 滚动可用率 token `-U<NN>`（`pct7` 存活率四舍五入取整，来源 `uptime.py`：分母=窗口内实际有质量轮的天数） |

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
Before: 1.2.3.4:443#🇺🇸US→US-30ms-10.82MB/s-V6-CN-77
After:  1.2.3.4:443#🇺🇸US→US-30ms-10.82MB/s-DC-fast-V6-CN-77-U92
```

**处理范围**：`data/valid/all.txt`、`all_ltd.txt`、`countries/*/all.txt`、`countries/*/ltd.txt`、`sets/*/all.txt`、`sets/*/ltd.txt`、`ports/*.txt`

**分目录漂移防护**（`verify_country_split`）：以 `all.txt` 大师清单（剔除 `#ALL` 哨兵）为准，比对 `countries/*/all.txt` 的行键集，返回 `{master, countries, missing, excess, dup_endpoints, phantom}`：

| 字段 | 含义 | 处置 |
|---|---|---|
| `missing` | 大师有、分目录缺（新键待 validate 重切分） | 非空即漂移，阻断 |
| `excess` | 分目录有、大师无（死代残留漏裁） | 非空即漂移，阻断 |
| `dup_endpoints` | 同一 `ip:port` 出现在 ≥2 国目录（入口国标注矛盾，如 `#SG`/`#CO`） | 告警不阻断 |
| `phantom` | 同键在分目录行数**多于**大师（`reconcile_views` 仅按 `ip:port` 裁剪，同键幻影行剪不掉） | 告警不阻断 |

键集比对（`missing`/`excess`）等价于「无代理丢失/无越界残留」；行数等式非不变量——同端点可带不同入口国标注合法共存，三链并发 commit 亦会瞬时错位。

```bash
python3 scripts/annotate_classify.py
python3 scripts/annotate_classify.py --data-dir /path/to/data
```

### `scripts/build_good.py`

构建综合最优 `good.txt` 清单（策略组/国家组/集合组各一份）。从验证池（`data/valid/all.txt`、`countries/*/all.txt`、`sets/*/all.txt`）中筛选同时满足以下条件的代理，按综合分降序输出（行内容原样保留）：

1. **大陆可达**：`china.json` 判定 `reachable`（仅当期可达集，过期历史 `-CN` 不再兜底——与 `all_cn.txt` 同规则，见 `scripts/china_check.py`「严格交战」）
2. **信誉分 ≥ 80**：存在于 `reputation.json` 且 `score >= 80`
3. **非高风险**：`reputation.json` 的 `risk != high`

综合分公式（信誉为主）：`round(0.6×信誉分 + 0.2×延迟分 + 0.2×速度分)`；延迟分 ≤100ms 记 100、≥1500ms 记 0 线性递减，速度分 `min(MB/s÷5, 1)×100`，缺失均记 0。同分依次按延迟升序、key 升序。质量 JSON 缺失时优雅降级为空清单。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--data-dir` | 数据根目录（含 `valid/` 与 `quality/`） | `data` |

输出文件：`data/valid/all_good.txt`、`data/valid/countries/<CC>/good.txt`、`data/valid/sets/<name>/good.txt`。每份同步派生 `*_verified.txt`（speed.json 全链路验证）、`*_stable.txt`（china.json streak≥2 跨轮稳定）与 `*_uptime.txt`（uptime.json 滚动可用率）可靠性变体，`*_top.txt` 组内最优（前 25% 分位，按组内实测速度）与 `_<tier>.txt` 速度档变体；对同目录 `ltd.txt` 池额外产出 `good_ltd(+_verified/_stable)`（每国最快的优质子集）。另写 `data/valid/all_diverse.txt`（出口多样性视图：每实测出口/入口网段仅留综合分最高一条、全局按分降序，见 `data-spec.md`；非 CN 专属，保留海外视图）与 `data/quality/good_meta.json` 汇总（含 `ts`/`file_count`/`proxy_count`）。

每一份 `good` 清单都只含大陆可达行（仅 CN 列表），因此全部输出统一渲染 **CN 视图**：行内延迟改写为大陆实测 `china.json` 读数、速度令牌改写为 `≈XMB/s` 大陆估算值（语义与 `all_cn.txt` 一致）；无 `cn_ms` 数据时行保持原样。CI 在 `build-good.yml` 专职工作流中运行（与其后 `build_premium.py` 同 job）；`annotate-classify.yml` 与 `exit-family.yml` 的后缀填充步骤后亦运行。

**写入者与护栏**：`build_good.py`/`build_premium.py` 并非单一写入者——`annotate-classify` 与 `exit-family` 工作流也会调用它们，跨 runner 并发写 `data/valid/*.txt` 与 good 清单，各自后 push 胜出、数据链下一轮自愈（勿在别处声称「单一写入者」）。`build-good.yml` 在 `commit_data.sh` 提交前跑 `test_build_good.TestCommittedCnViewInvariant` 护栏：扫描仓库内全部 good/premium/tiers/`all_cn*` 文件，任一混入海外实测 `-\d+\.\d+MB/s` 纯速度即中止提交（防陈旧 `china.json`/空 `cn_ms` 让速度原样透传）；护栏由 `Quality check`/`China check` 任一成功完成触发，失败触发跳过。

```bash
python3 scripts/build_good.py
python3 scripts/build_good.py --data-dir /path/to/data
```

### `scripts/build_premium.py`

构建高端优质 `premium.txt` 清单（策略组/国家组/集合组各一份）。从验证池（`data/valid/all.txt`、`countries/*/all.txt`、`sets/*/all.txt`）中筛选同时满足以下条件的代理，按综合分降序输出（行内容原样保留）：

1. **大陆可达**：`china.json` 判定 `reachable`（与 `good` 同规则）
2. **信誉分 ≥ 95**：存在于 `reputation.json` 且 `score >= 95`
3. **真实住宅 IP**：`ipinfo.json` 的 `ip_type == "RES"` 且 `geo_checked == true`（查不到出口地理时 `classify_ip({})` 默认 RES 只是未知，不当作实测住宅）
4. **非高风险**：`reputation.json` 的 `risk != high`

综合分公式与 `good` 一致：`round(0.6×信誉分 + 0.2×延迟分 + 0.2×速度分)`；延迟分 ≤100ms 记 100、≥1500ms 记 0 线性递减，速度分 `min(MB/s÷5, 1)×100`，缺失均记 0。同分依次按延迟升序、key 升序。质量 JSON 缺失时优雅降级为空清单。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--data-dir` | 数据根目录（含 `valid/` 与 `quality/`） | `data` |

输出文件：`data/valid/all_premium.txt`、`data/valid/countries/<CC>/premium.txt`、`data/valid/sets/<name>/premium.txt`。每份同步派生 `*_verified.txt`（speed.json 全链路验证）、`*_stable.txt`（china.json streak≥2 跨轮稳定）与 `*_uptime.txt`（uptime.json 滚动可用率）可靠性变体，以及 `_<tier>.txt` 速度档变体。另按输出家族派生 **v4/v6/46 分支**：`*_v4.txt`、`*_v6.txt`、`*_46.txt`（含各自的派生变体），家族判定优先 `exit_family.json`（无记录时按行内 `-V4`/`-V6`/`-DS` 兜底、记录 `unknown` 不回落；与 `v4`/`v6`/`46` 组文件同规则），无对应家族时分支空则不留盘并清理残留。另写 `data/quality/premium_meta.json` 汇总（`ts`/`file_count`/`proxy_count`，见 data-spec.md）。

每一份 `premium` 清单都只含大陆可达行（仅 CN 列表），因此全部输出统一渲染 **CN 视图**：行内延迟改写为大陆实测 `china.json` 读数、速度令牌改写为 `≈XMB/s` 大陆估算值（语义与 `all_cn.txt` 一致）；无 `cn_ms` 数据时行保持原样。CI 在 `build-good.yml` 专职工作流中与 `build_good.py` 同 job 运行。

```bash
python3 scripts/build_premium.py
python3 scripts/build_premium.py --data-dir /path/to/data
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
python3 scripts/analyze_sources.py
python3 scripts/analyze_sources.py --data-dir /path/to/data
```

### `scripts/health_alert.py`

池健康看门狗：读取仓库内的数据快照，检查多项异常条件，有告警时发往 `ALERT_WEBHOOK_URL`（未配置时仅打印并正常退出）。每一项都带各自的最小样本/阈值门槛，避免小样本抖动误报；诊断状态持久化于 `data/quality/alert_state.json`（上次 CN 可达数、分运营商可达数 `cn_by_isp`、各国家池快照）；相同告警组合在 6 小时冷却窗口内不重复投递（`last_alert_at` / `last_alert_hash`），防止持续故障期间刷屏 webhook。CN 塌方检测除整体可达数骤降外，移动/电信/联通三运营商分别独立判定（`cn_by_isp` 上一轮基准回落 ≥50% → `CN collapse (<运营商>)`；仅当 per-key `isp_ms` 存在运营商维度读数时生效，无读数自动回退整体口径）。有告警时还会改写 `data/output/badge.json` 将 README 状态徽章标红为对应告警名（在 stats 同 job 内 render 之后顺序执行，无竞态）；无告警不改动徽章。投递硬约束：`ALERT_WEBHOOK_URL` 仅接受 `https://`（`http://` 明文会泄露 webhook token 与告警内容，一律拒绝并仅在 stderr 提示后跳过投递）；未配置或拒绝时不退出，仅打印。

| 检查 | 触发条件 |
|---|---|
| `check_pool` | 池 `alive` 相对近 24 轮中位数下降 ≥30%（样本足够时评估） |
| `check_cn` | 上次 CN 可达数 ≥20 时，本轮相对上一轮下降 ≥50% |
| `check_cn_stale` | `china.json` 超过 `CN_STALE_HOURS`(12h) 未刷新且曾有 ≥20 可达样本（CN 专链静默停机时总体数据仍新鲜，仅此检查暴露） |
| `check_artifact_stale` | 任一产物 JSON 超龄（泛化时效检查）；`require_proxies=True` 用于 keyed 产物（`exit_family.json`：12h / ≥100 条目），`require_proxies=False` 用于 summary 产物（`quality_meta.json`、`good_meta.json`：各 12h；`valid/meta.json`：5h，此时效早于 8h 的 history 兜底告警）——分别暴露 exit-family / 质量链 / build-good 链 / validate(update) 链静默停机 |
| `check_countries` | 单国上一轮 alive ≥60 时，本轮相对下降 ≥60%（区域性断网/上游国家文件丢失） |
| `check_sources` | 某上游源 unique 覆盖相对近 8 轮中位数下降 **>55%**（样本 ≥8 轮且规模 ≥500；实现为严格大于） |
| `check_stale` | `data/valid/history.jsonl` 最新轮距今超过 8 小时 |

```bash
ALERT_WEBHOOK_URL=https://example.com/hook python3 scripts/health_alert.py
```

- `--strict`：默认无论有无告警都正常退出（0），供例行检查使用；加 `--strict` 后有告警以非零码退出，用于 CI 门控（如关键行为中断时让工作流失败）。
- `--data-dir`：数据根目录（含 `data/valid/`、`data/quality/`），默认自动定位（脚本所在目录的上级），本地复刻/非标准布局时指定。

### `scripts/uptime.py`

滚动节点可用率跟踪（质量链在 `quality_check.py` 之后、提交之前运行）。读取本轮存活键集，按
UTC 日期记入 `data/quality/node_seen.json`，滚动裁剪 `WINDOW_DAYS`(45) 天的运行日计数，
再以「窗口内实际有质量轮的日期数」为分母产出 7d/30d 存活率写入 `data/quality/uptime.json`
（字段见 `docs/data-spec.md`）。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--alive-file` | 本轮存活键所在 JSON（其顶层 `proxies` 键集即为存活集） | `data/quality/ipinfo.json` |
| `--out-dir` | `node_seen.json` / `uptime.json` 输出目录 | `data/quality/` |

### `scripts/deep_speed.py`

深测带宽：对**选定国家**的候选节点做大样本（默认 20 MB / 30s 上限）× 多并发流（默认 3）的
多目标下载深测，稳态窗口远大于慢启动，用于同一国家内拉开真实带宽差异。结果写
`data/quality/deep_speed.json`（keyed，含每流明细与 `tls_ms`；`meta` 记录本次参数快照），
**不改动清单行备注**——深测结论供人工/下游参考，与全局档位语义解耦。Ci 为 weekly workflow
`deep-speed.yml`（每周六 `7 3 * * 6`）。quality_check 消费最优目标 `agg_mbps`
（`min(agg/50,1)×10`，封顶 +10，仅对已有信誉分节点生效；数据超 `DEEP_SPEED_TTL_DAYS`(10)
天视为过期）。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--cc` | 逗号分隔国家码，选取该国之国池候选 | 空（配合 `--source` 使用） |
| `--source` | 显式池文件（优先于 `--cc`） | 无 |
| `--limit` | 每轮最多探测节点数（0=全部） | 30 |
| `--bytes-mb` | 单流下载上限（MB） | 20 |
| `--streams` | 每节点并发流数 | 3 |
| `--timeout` | 连接/下载超时（秒） | 30 |
| `--workers` | 同时深测的节点数 | 6 |
| `--sni` | 覆盖入口 SNI | 无 |
| `--targets` | 逗号分隔目标：`cf_speed`/`cdnjs`/`ovh`/`cf_trace` | `cdnjs` |

### `scripts/export_json.py`

结构化代理池导出：读取 `data/valid/` 全部带注解行，输出单行 JSON 数组到 `data/valid/all.json`
（字段：`line`/`key`/`ip`/`port`/`flag`/`cc`/`exit`/`latency_ms`/`speed_mbps`/
`family`/`cn`/`type`/`tier`/`rep`/`uptime7`，详见 `docs/data-spec.md`）。stats workflow 提交前运行。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--data-dir` | 数据根目录 | `data/` |

### cn01 批量探测（PCB 私有插件）

cn01 批量大陆可达性探测已迁入私有检查包（PCB 私有仓，代号 cn01，不进公开 git）：节点抓取 → 批量任务提交 → WebSocket 收集 → 聚合成源判定；8 次连续批量失败触发断路器暂停，任务带 pacing + 并发上限。公开侧经 `scripts/checks_bundle.py` 按 `INTERFACE_VERSION` 加载，无包时 cn01 系源整段 fail-open 跳过。参数经 `china_check.py` 透传生效（无包时仅作默认值展示）。

| 参数 | 说明 | 默认 |
|---|---|---|
| `--cn01-batch-size` | 每任务目标数 | 5 |
| `--cn01-concurrency` | 同时批量任务数 | 见 china_check 表 |
| `--cn01-nodes` | 抓取节点数 | 见 china_check 表 |
| `--cn01-pacing` | 任务间隔节流（秒） | 见 china_check 表 |
| `--skip-cn01` | 跳过 cn01 批量探测 | 关 |
| `--skip-cn02` | 跳过 cn02 大节点池补测 | 关 |

## `common.py` 共享模块：错误日志脱敏约定

`common.err_name(e)` 返回异常类型名（`type(e).__name__`）。**捕获异常后
写入日志/错误字段时一律用它，禁止 `str(e)`/`str(exc)`/`format_exc`**——
`URLError`/`HTTPError` 与 `fetch_with_deadline` 的 `TimeoutError` 其字符串
表示会内嵌完整请求 URL；CI 的 `?token=`、`?key=` 等查询参数随 URL 泄漏。
各脚本日志与 `{... "error": ...}` 字段统一经此 helper 取类别名；异常具体
细节（errno 等）需保留时用 `type(exc).__name__ + (errno/strerror 白名单)`
显式拼接，不得整串透传。`china_check.py` 另有本地别名
`_err` 转调 `err_name`（PCB 插件内同理）。

## 退出码约定（R281 补记）

- `0`：正常完成（含部分失败的降级完成：失败隔离后其余产出照常落盘）。
- `1`：输入缺失或硬失败（如 quality_check 源文件不存在；health_alert 仅 `--strict` 且有告警时返回 1 供 CI 门控）。
- `2`：`china_check.py` 输入样本为空（`--source` 无可用行；`--dry-run` 仍先过此检查，无网络动作即退出）。
- `--help`：CLI 脚本退出 0（`common.py` 纯库模块除外，退出 2 并提示）。