# 检测逻辑

本文档详细描述 IP 质量检测系统的核心算法与判定逻辑，供维护者理解代码实现。

## 1. 整体架构

```
download_proxies.py → validate_proxies.py → quality_check.py
                                             ├─ quality_probe.py
                                             ├─ quality_reputation.py
                                             └─ reorg_country.py
                           ↓
                   china_check.py (+ PCB 批量插件 cn01)
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

## 3. 出口探测引擎（quality_probe.py）与已移除的流媒体解锁

> **流媒体解锁检查已于本轮整体移除**（NF/D+/YT/MX/PV/GPT 不再产生新观测）。
> 历史行上的这些 token 由 `normalize_note` 作为遗留段继续容忍解析，
> 随节点自然轮换逐渐消失。原 `quality_streaming.py` 拆分为：
>
> - `quality_probe.py` —— 通用 TLS 探测引擎：`tls_get_direct`（SNI 直连 GET）、
>   外部出口地理回显 API（`check_external_api`，exit_cc 第一数据源）、
>   ip-api 批量地理查询（`batch_ipapi`）；
> - 流媒体服务表、各服务解析器与 `finalize_streaming`/`streaming_tokens`
>   一并删除。

### 3.1 滚动可用率跟踪（uptime.py）

质量链每轮把存活节点按 UTC 日期记入 `data/quality/node_seen.json`
（滚动 45 天窗口），并维护全局"运行日计数器"作为分母：

- `pct7 / pct30`：窗口内出现天数 ÷ **窗口内实际有质量轮的日期数**（去重，同日多轮算 1 天）→ 存活率百分比，每个运行日都在场即 100%；
- 结果写入 `data/quality/uptime.json`，注解链为命中的行追加 `-U<NN>`
  备注（如 `-U92`），build-good 产出 `_uptime` 可靠性子集（pct7 ≥ 80）。

### 3.2 深测带宽写回信誉分

deep-speed 深测（多流大样本）结果聚合出每节点最优目标的
`agg_mbps`；quality_check 计算信誉分时叠加线性加成：
`bonus = round(min(agg/50, 1) × 10)`，封顶 +10 分且**只对已有信誉分
的节点生效**（深测是抽样，不产生幽灵分）。加成记录在
`reputation.json` 条目的 `deep_bonus` 字段。

## 4. IP 信誉评分（quality_reputation.py）

### 4.0 出口 IP 解析（resolve_exit_ips）

信誉 / 地理 / 滥用查询一律使用**真实出口 IP**，按优先级解析：

1. `external_check.exit_geo.ip` —— 外部探测回显的出口
2. `exit_family.json` 的 `exit_v4` / `exit_v6` —— 专用双栈探测实测
3. 代理自身 IP（兜底；仅当无任何出口观测）

> CF 中转代理的入口恒为 Cloudflare 边缘 IP——查入口会得到千篇一律的
> "干净"结果，完全失真。`exit_ip_source` 字段记录取值来源。

### 4.1 评分公式

**跨源共识合成**（默认 `--reputation-provider multi`，实现 `quality_reputation.vote_reputation`）：

1. 先把各源的布尔标记归一为语义维度（`tor`/`proxy`/`vpn`/`hosting`(数据中心)/`mobile`/`abuse`/`listed`/`scraper`/`crawler`/`anonymous`）。
2. 按源权重做**加权多数投票**：正票总权重 > 负票总权重才认定该维度为真，打平视为无结论（不扣分），避免单源误报独断与大权重单源主导。
3. 叠加连续型风险源（`trust_score`、`probability`、`risk_score`、`fraud_score`、`score`、otx reputation/pulse、proxycheck risk）的加权罚分。
4. 查到出口地理（`countryCode`）即把 `ip-api` 计入投票；无任何信号则该项无分（不误判满分）。

扣分表与默认源/权重见 `docs/scripts.md`「scripts/quality_check.py」段的「跨源共识合成」说明与「默认源与权重」表（tor 40 / abuse 35 / listed 30 / proxy 28 / vpn 22 / scraper 12 / hosting 10 / anonymous 8 / crawler 5；仅 mobile 与其余风险维度均不成立时有 +5 加分）。

**滥用分优先级**：若 AbuseIPDB/IPQS 滥用分可用，直接取 `100 - abuse_score`，不走多源合成。滥用相位受墙钟预算门控；被跳过/截断时以最近 `abuse.json`（≤1 天）补齐缺失键兜底，避免静默降级为纯共识分；仅当滥用服务启用时该相位才算「可跳过」。

**密钥防护约束**：滥用/信誉 key 只经环境变量注入（`ABUSEIPDB_KEY`/`IPQS_KEY`，
不进 CLI 参数与配置文件）；key 不得进入任何日志、`TimeoutError`/异常文本或
traceback——IPQS 分支超时异常已净化（`from None` 断开因果链），后继改动该
分支时须保持此面不变（另见 R212/R213）。

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
| ip-api | 15 | 本地批量地理：proxy -25 / hosting -10 / mobile +5（与共识 `_mobile_clean_bonus` 一致）；有 `countryCode` 即计入 |
| ipquery | 12 | `risk_score` 直用或标志罚分（取较大者）：tor -45 / vpn -30 / proxy -25 / datacenter -15 |
| ffraud | 12 | `fraud_score` 直用或标志罚分（取较大者）：tor -45 / vpn -30 / proxy -25 / hosting -15 / abuser -20 / recent_abuse -15 |
| blackbox | 10 | 按分类给分：residential 95 / mobile 90 / business 85 / hosting 60 / vpn 55 / privacy_relay 50 / tor 10 / bogon 5 / unknown 50；suspicious -20 |
| otx | 8 | `100 - (min(reputation×5,80) + min(pulse_count×2,20))` |
| ipapi_is | 8 | 标志罚分：tor -45 / vpn -30 / proxy -25 / datacenter -15 / abuser -20，机房 ASN/公司类型 -15，abuser_score≥0.1 -20 |
| ipdata | 8 | 标志罚分 + `threat_score`：tor -45 / proxy -30 / vpn -25 / anonymous -10 |
| whatismyip | 3（opt-in） | `security.score` 直用或标志罚分（取较大者）：vpn -30 / proxy -25 / tor -45 / hosting -15 / blacklisted -30。**R270 起退出默认源**（一增一减轮换，保留权重/派发作 opt-in；`--reputation-sources` 显式启用仍可用） |
| getipintel | 5 | `100 - probability×100`（opt-in，需邮箱） |
| proxycheck | 12 | `risk` score 直用或标志罚分（取较大者）：proxy -45 / vpn -45 / tor -45 / hosting -30 / scraper -20 |
| ip2location | 5 | `is_proxy` 标志 -30 |
| freeipapi | 6 | `isProxy` 标志 -30（附 ASN/org，全免费免 key） |
| scamalytics | 8 | 免费风险页 `Fraud Score`（0-100）直扣；`is_blacklisted_external` 投 listed 票 |
| iplocation | 3（opt-in） | `is_proxy` 标志 -30（附 isp，全免费免 key）。**R269 起退出默认源**：权重最低（3）且 proxy 维度被 hackmyip(6)/freeipapi(6)/scamalytics(8) 全超集覆盖，属重复低置信信号；`--reputation-sources` 显式启用仍可用 |
| dnsbl | 8 | Spamhaus ZEN 实时 DNSBL，DNS-over-HTTPS 免 key：`<rev-ip>.[REDACTED_PRIVATE_RESOURCE]` A 记录返回 SBL 2/3、XBL 4/5 码 → `listed` 扣 30；PBL 6/7 与 CSS 8/9 忽略；未列出/解析失败返回 None 进负缓存；三镜像 `dns.alidns.com`→`cloudflare-dns.com`→`dns.google/resolve` 失败回退且进程内 sticky 复用最近成功端点（TTL 600s），全部失败按失败重试、不误判干净 |
| spamcop | 5 | SpamCop `[REDACTED_PRIVATE_RESOURCE]` 社区实时 DNSBL（独立权威、与 Spamhaus 互补），复用 dnsbl 的 DoH/sticky/并发与负缓存：`<rev-ip>.[REDACTED_PRIVATE_RESOURCE]` A 记录命中 `127.0.0.2` → `listed` 扣 30；其余返回视为未列出；上限 SPAMCOP_CAP=9000/轮 |
| sorbs | 5 | SORBS `[REDACTED_PRIVATE_RESOURCE]` 社区 open-proxy 实时 DNSBL：SOCKS/HTTP 代理码 `127.0.0.2`/`127.0.0.7` → `listed` 扣 30；动态住宅段 `127.0.0.4/8/9` 忽略（与 spamhaus PBL 同口径）；复用 dnsbl 的 DoH/sticky/并发与负缓存；opt-in 不入默认；上限 SORBS_CAP=9000/轮。**R271 新增**。**R272 实测**：test-point `2.0.0.127.[REDACTED_PRIVATE_RESOURCE]` 经 DoH 无响应（不断言死亡，保持 opt-in 待验证；若长期零命中且确认停服则注释停用）。**R282 复测**：test-point 仍无响应；zone NS 查询亦空——但对照 `[REDACTED_PRIVATE_RESOURCE]` 有响应而无 NS，NS 空不能证伪，维持 opt-in 观察 |
| dronebl | 5 | DroneBL `[REDACTED_PRIVATE_RESOURCE]` 社区僵尸/失陷主机实时 DNSBL（独立权威，命中多为被控主机/开代理人），复用 dnsbl 通路：`<rev-ip>.[REDACTED_PRIVATE_RESOURCE]` A 记录命中码 `127.0.0.2~13`（abuse/爆破/垃圾/重犯/模糊等）→ `listed` 扣 30；上限 DRONEBL_CAP=9000/轮 |
| spamrats | 5 | SpamRats `[REDACTED_PRIVATE_RESOURCE]` 社区双通路实时 DNSBL（第四独立权威，与 Spamhaus/SpamCop/DroneBL 四家同构为免 key 社区派对）。复用 dnsbl 通路：`<rev-ip>.[REDACTED_PRIVATE_RESOURCE]` A 记录命中码 `127.0.0.2`（AUTO 自动化自录）与 `127.0.0.3`（AUTH 社区人工确认）→ `listed` 扣 30；**`127.0.0.4`（DYN 动态住宅线）刻意忽略**——与 spamhaus PBL/iplocation 同口径：动态住宅段是正常合法用户基线，不按代理罪证处理；上限 SPAMRATS_CAP=9000/轮。**R270 新增，opt-in**（默认不进 DEFAULT，`--reputation-sources` 显式启用）。**R271 补接**：`_flag_opinions`/`source_score` 缺分支导致命中零扣分，现已与 spamcop/dronebl 同口径。**R272/R282 实测**：test-point 经 DoH 无响应，zone NS 查询亦空（对照组 spamcop 有响应无 NS，故不断言死亡），保持 opt-in 待验证 |
| uceprotect | 5 | UCEPROTECT Level 1 `[REDACTED_PRIVATE_RESOURCE]` 社区发送者黑名单（第五独立权威，UCEPROTECT-Network 运营）：`<rev-ip>.[REDACTED_PRIVATE_RESOURCE]` A 记录命中 `127.0.0.2` → `listed` 扣 30；**仅用 L1**（具体发送 IP），L2/L3 升级名单（整段/AS 列入）争议大、刻意不用；复用 dnsbl 的 DoH/sticky/并发与负缓存；opt-in 不入默认；上限 UCEPROTECT_CAP=9000/轮。**R272 新增**（test-point `2.0.0.127` 经 DoH 实测回包 `127.0.0.2`，分区存活实证） |
| psbl | 5 | PSBL `[REDACTED_PRIVATE_RESOURCE]` 被动垃圾邮件黑名单（第六独立权威，陷阱网络运营）：`<rev-ip>.[REDACTED_PRIVATE_RESOURCE]` A 记录命中 `127.0.0.2` → `listed` 扣 30；复用 dnsbl 的 DoH/sticky/并发与负缓存；opt-in 不入默认；上限 PSBL_CAP=9000/轮。**R273 新增**（test-point `2.0.0.127` 经 DoH 实测回包 `127.0.0.2`，分区存活实证；同轮 DNSBL 查询骨架去重为通用 helper，七源行为零变更） |
| ipwhois | 6 | `security` 块标志罚分：tor -45 / vpn -30 / proxy -25 / hosting -15 / anonymous -10；`connection.type` 命中机房类另投 hosting；无罚分且无 ASN 则 None |
| maltiverse | 6（opt-in） | `classification`（malicious/suspicious）或结构布尔（open_proxy / tor_node / vpn_node / cnc / malware 分发 / iot / scanner / mining）+ 近 MALTIVERSE_RECENT_DAYS 天黑名单；刻意忽略 `is_known_attacker` 与 `is_hosting`（防叠噪）；全空 → None。**R268 起退出默认源**：实域 18127 出口的 `rep_sources` 中参与共识仅 3 次（每轮 cap 2500 查询），判识增量近零而调用成本不低，故降级为 opt-in（`--reputation-sources` 显式启用） |
| stopforumspam | 4 | `is_abuse` → abuse -35、Tor exit → tor -40（HTTP 垃圾评论/僵尸出口） |
| hackmyip | 6 | `data.privacy` 块：hosting / proxy / mobile（附 ASN）；全空 payload → None |
| greynoise | 8 | `is_abuse` -60（恶意扫描）/ `is_riot` bot -35 / `is_noise` -15；免费 40 req/min 限流 |

#### 静态列表源（每 run 重拉）

| 源 | 权重 | 命中分数 | 信号旗 | 说明 |
|---|---|---|---|---|
| ipsum | 8 | 55 | `is_listed` | 命中 3+ 黑名单 |
| abuse_list | 5 | 60 | `is_abuse` | 历史滥用 |
| abuseipdb_public | 5 | 55 | `is_abuse` | AbuseIPDB 近 30 天高置信滥用举报（社区镜像） |
| wwuyi_unreachable | 2 | 70 | `is_listed` | Wwuyi123 实测不可达（第三方失联证据，非滥用，温和） |
| wwuyi_blocked | 2 | 65 | `is_listed` | Wwuyi123 维护者拉黑（主动拒绝，略强，仍非滥用） |
| cins | 5 | 50 | `is_listed` | CINS 活跃滥用/拒绝服务 IP |
| danmeuk_tor | 5 | 40 | `is_tor` | Dan.me.uk Tor 出口 |
| dc_asn | 5 | 85 | `is_hosting` | 机房/数据中心 ASN |
| firehol_level1 | 5 | 60 | `is_listed` | FireHOL 最严封禁集 |
| firehol_level2 | 4 | 50 | `is_listed` | FireHOL L1 超集（更广更噪，口径略弱） |
| threatfox | 5 | 55 | `is_abuse` | ThreatFox IOC |
| tor_exit | 5 | 45 | `is_tor` | Tor 出口节点 |
| urlhaus | 5 | 55 | `is_abuse` | URLhaus 恶意软件分发 |
| binarydefense | 4 | 55 | `is_abuse` | Binary Defense 蜜罐 |
| blocklist_de | 4 | 50 | `is_abuse` | Blocklist.de 全量滥用 |
| c2_tracker | 4 | 55 | `is_abuse` | C2 Tracker 命令控制 |
| et_compromised | 4 | 45 | `is_abuse` | EmergingThreats 被入侵主机回连 |
| feodo | 4 | 40 | `is_abuse` | Feodo Tracker 银行木马 C2 |
| greensnow | 4 | 50 | `is_abuse` | GreenSnow 蜜罐 |
| spamhaus | 4 | 55 | `is_listed` | Spamhaus DROP/EDROP 高风险网段 |
| tor_bulk | 4 | 35 | `is_tor` | Tor 批量出口 |
| blocklist_de_apache | 3 | 45 | `is_abuse` | Blocklist.de Apache 攻击 |
| blocklist_de_ssh | 3 | 45 | `is_abuse` | Blocklist.de SSH 暴力破解 |
| bruteforceblocker | 3 | 45 | `is_abuse` | BruteForceBlocker SSH 爆破榜（同信号族） |
| dataplane_vncrfb | 3 | 45 | `is_abuse` | dataplane.org VNC 爆破榜（新信号族） |
| drb_c2 | 4 | 50 | `is_abuse` | drb-ra 30 天审核 C2（单研究员，口径略弱） |
| nordvpn_exits | 3 | 55 | `is_vpn` | drb-ra NordVPN 出口表（日更） |
| blackhole_monster | 4 | 50 | `is_abuse` | blackhole.monster 每日攻击者（Maltrail 定性） |
| myipms_blacklist | 4 | 50 | `is_abuse` | myip.ms 10 天攻击源（自家基础设施扫描/机器人） |
| ipnoise | 4 | 50 | `is_abuse` | IPnoise 7 天蜜罐攻击者（无合法服务，连即敌对） |
| botscout | 3 | 45 | `is_abuse` | BotScout 机器人 |
| dshield | 3 | 50 | `is_abuse` | DShield 攻击源 |
| socks_proxy | 3 | 60 | `is_proxy` | SOCKS 代理 |
| sslproxies | 3 | 60 | `is_proxy` | SSL 代理 |
| vpn_asn | 3 | 70 | `is_vpn` | VPN 服务商 ASN |
| vpn_ips | 3（opt-in） | 55 | `is_vpn` | X4BNet VPN 出口 CIDR。**R271 起退出默认源**：静态 VPN 出口表与 `vpn_asn` 机房 ASN 判据高度重叠，属重复低增益信号；`--reputation-sources` 显式启用仍可用 |
| resproxy_asn | 2 | 75 | `is_proxy` | 住宅代理骨干 ASN |

未命中 → 该项不计入合分（不误判满分）。

### 4.4 缓存机制

- 按 IP 的 API 源信号缓存在 `data/quality/reputation_cache.json`
- TTL 默认 7 天，TTL 内复用缓存信号重新计算分数
- 只查询缺失/过期的 IP；过期条目不删除——每轮尝试刷新，刷新失败时
  回退使用最近缓存信号（保持数据最新而非过期即丢），直至被新条目
  挤出缓存上限（`REP_CACHE_MAX`）
- **负缓存**：源成功响应但无信号（`None`，如 greynoise 对干净 IP 返回
  404/clean、ip2location 非代理）以 `data: {}` 哨兵写入缓存，TTL 内不再
  重查；空哨兵不进入 `risk_data`、不参与共识投票，也不误当「可回退信号」。
  负缓存用更短的 TTL 上限 `NEG_CACHE_TTL`（默认 1 天 `<` `--rep-cache-ttl`），
  限制「干净→恶意」的检测时延
- **无信号 ≠ 失败**：只有抛异常的查询才重试；`None` 结果不重试
- 静态列表不缓存，每轮重拉

### 4.5 执行相位与墙钟预算门控

`quality_check.py run()` 依序执行下列相位（探测定序、网络相位后处理）：

1. **探测相位**（`quality_probe.run_checks`，TLS 判定 + 出口地理回显）
2. **出口解析**（`resolve_exit_ips`，本地映射，无网络）
3. **geo 相位**（`batch_ipapi`，批量地理位置）
4. **信誉相位**（`lookup_all_risk`，按 IP 风险源 + ASN 归一）
5. **滥用相位**（`run_abuse`，key 存在时才开启）
6. **本地收尾**（建 ipinfo/rep_map、写 reputation.json/all_rep*.txt、
   ipinfo.json、quality_meta.json、注解 valid 文件——均无网络，总是执行）

`--time-budget N`（N>0）时套用**墙钟预算门控**：

- 探测相位拿到 `max(1, N - POST_RESERVE_S)` 作为自己的 `time_budget`
  （`POST_RESERVE_S = 600`s 为后处理预留窗口，使预算内仍能产出信誉分）；
- 三个网络相位各自在进入前检查 `_within_budget(start, N)`
  （`elapsed < N` 才允许开启），超时则跳过该相位并 stderr 警告（含合并汇总）；
- 相位内部同样止损：`batch_ipapi` 的分块与 per-IP 兜底循环、`run_abuse`
  的出口 IP 顺序查询都接受绝对 `deadline`（`start + N`），上游全挂时不再
  逐 IP 空转 1.5s/0.3s 睡满无限时长，到龄即提前退出（防 ip-api/滥用 API
  停机把网络相位拖到 CI 硬杀）；截断发生且结果不全时，stderr 会各发一条
  归因警告（`Warning: ip-api geo truncated by time deadline; returning
  partial results (N/M)` / `Warning: abuse scores truncated by time
  deadline; returning partial results (N/M)`），`N/M` 为已得/应得数量——
  批量相位部分成功即返回（互斥短路，per-IP 兜底不再触发）；
- 本地收尾不受门控，保证已得结果照常落盘——**提交部分结果而非整链丢失**；
- `N=0`（默认）不设门控，行为与历史完全一致。

超时跳过后 `quality_meta.reputation_checked` 为 0、`rep_avg` 为 `null`，
旧轮 `reputation.json`/`all_rep*.txt` 保持上一轮快照（charts 显示"暂无信誉
分数据"占位），不产生脏数据。

## 5. 大陆连通性检测（china_check.py）

### 5.1 三层检测架构

**L1 启发式（零网络）已移除**：曾基于行内 `-CF` 死标记记录 heuristic
源作为 basis 标注；CF token 现已废弃（池子全为 CF 边缘端口恒真，
归一化时丢弃），零网络层不再存在，china.json 不再写 `cf_heuristic` 字段。

#### L2 批量实测（主源）

**cn01 批量探活**：

- 每任务 5 个目标 × 每 ISP 8 个节点（电信/联通/移动共 24 节点，池子 ~80/ISP，跨省等距采样）
- 通过 WebSocket 收集结果
- TCP 连通即判可达；节点返回 `http_code>0` 时另计**应用层确认**（`level=http`）。
  注意：TLS 端口（443 等）上 cn01 发明文 HTTP，CF 边缘会回 `400`——这同样
  证明完整数据往返、路径无 TCP 层干扰，故计入应用层确认（但不验证 TLS 内容）
- 限速：8 并发任务，0.5s 间隔
- 熔断：连续 8 次失败后停止

**单节点实测（并发）**：

- `cn27`：呼和浩特阿里云节点，匿名限速 5/10s、250/h，配置 `--api-key` 可放宽
- `cn28`（CN-31）：同节点 ICMP ping，仅 TCP 判 fail 时追加
  消歧（TCP-fail＋ping-ok→uncertain，主机存活；双 fail→置信定罪），共用
  250/h 配额，`level=icmp`，不产 `isp_ms`
- `cn29`（CN-32）：同节点 HTTPS 应用层确认，首个 http 级
  单节点源（CF 边缘回 4xx 亦算完整往返）；仅 TCP-ok 且其余免额 0 ok 时
  追加猎取第二确认（uncertain→reachable），共用配额，不产 `isp_ms`
- `cn20`：北京节点 TCP，免 key
- `cn21`（CN-29）：山东枣庄 BGP 节点 ICMP，免 key（JSON；
  `level=icmp`，echo 校验防垃圾回显，不产 `isp_ms`）。同运营商、不同城市
  服务器＋不同协议（地理＋协议双差异，中增益）
- `cn22`（CN-38）：同站 HTTP 状态码，免 key（JSON；
  `level=http`，`-2` 判 fail、`-4` 拒绝按 error，无 ms，不产 `isp_ms`）。
  同站第四端点（TCP/ICMP/状态码）
- `cn23`（CN-39）：同站 8 端口扫描，免 key（JSON；
  固定集合仅含 443 一档池端口，非 443 键恒 skipped；`level="tcp"`，
  布尔见证，无 ms，不产 `isp_ms`）
- `cn24`（无铭 API tcping）：浙江宁波电信 TCP 1 节点，免 key（纯文本报告；
  CN-26 起主站异常自动 failover 同站镜像，429 不切换；
  CN-39 起 ok 附 `isp_ms={中国电信}`，L2 全池电信放量）
- `cn25`（无铭 API ping，CN-25 新增）：同站同节点 ICMP 主机存活，免 key
  （纯文本报告；`level=icmp`，不进 `cn_display_ms`/`isp_ms`，与 ICMP 源
  同口径；同镜像 failover）。同站不同协议：TCP 握手与 ICMP 回显失效模式正交（端口封 vs
  禁 Ping），独立性评级低增益-同站（新增协议层证据，非地理/ISP 覆盖）
- `cn26`（无铭 API ssl，CN-37 新增）：同站同节点 TLS 握手，免 key（JSON，
  双镜像 failover；`level="tcp"` 保守，无 ms 只作布尔见证，不产 `isp_ms`）。
  同站第三协议：TCP/ICMP/TLS 失效模式正交（端口封/禁 Ping/握手失败）
- `cn36`（CN-46 新增）：社区探针北京节点 ICMP ping，匿名免 key
  （250/h 配额，单次 cost 1；`level="icmp"`，不产 `isp_ms`；单北京点，
  作单节点冗余票；服务端拒私有/保留目标时判 error 不污染；CI 以 60 键/4
  并发启用，约 8min）。
- `cn37`（CN-47 新增）：同站同 API 路由追踪，末跳 `resolvedAddress`
  精确等于目标即见证（活体双目标末跳到达；死体结构上恒 fail），`ms` 恒空，
  `level="icmp"`，不产 `isp_ms`；CI 以 40 键/4 并发启用。
- `cn38`（CN-48 新增）：同站同 API 应用层确认（明文打 TLS 端口，
  服务端状态码即完整往返；`ms` 取 `timings.tcp`，connect_ms 同口径），
  `level="http"`，不产 `isp_ms`；CI 以 40 键/4 并发启用。
- `cn39`（CN-49 新增）：同站同 API MTR，任一 hop `resolvedAddress`
  精确等于目标即见证（活体末跳到达；不可解析目标 result failed；死体无响应
  跳结构上恒 fail），`ms` 恒空，`level="icmp"`，不产 `isp_ms`；CI 以 40 键/4
  并发启用。

**batch_tcping 补测（降级通道）**：

- batch_http 对某目标失败/被限时（captcha、风控、熔断），改用
  `cn02` 纯 TCPING 复测
- 节点池大得多（电信/联通/移动各 ~75-88 个，默认等距取 8×3=24 节点）
- 结果记为独立多节点源 `cn02`（`result>0` → 可达，`-1` → 失败），
  单独 ok 即可判 reachable

**batch_ping 补测（CN-26，ICMP 主机存活通道）**：

- 同上触发条件（仅 error/rate_limited 键；TCP 实测 fail 的键不用 ICMP
  翻案，保守），改用 `cn03` ICMP 复测
- 节点池电信 87 / 联通 83 / 移动 89（默认等距取 8×3=24 节点）；提交参数、
  WS 收数与 batch 系完全同构，活体实证
- 结果记为独立多节点源 `cn03`，归一为 `level=icmp` 且不产 `isp_ms`
  （ICMP 不得进展示延迟，多节点 ICMP 源同口径），强确认单独 ok
  即可判 reachable

#### L3 多节点复核（有界并发小样本）

按序接入多节点复核源补强，各源只投「当前尚未被 cn01/单节点源判可达」的键、按 `--cn-limit CODE=N` 有界，先免费/低鉴权源再复杂源：

- `cn30`：免费 REST，~146 大陆节点按运营商均衡采样 10 个，TCP 直连，节点成功率达 50% 即判可达
- `cn31`（CN-33）：同站 `type=ping`（裸 IP 目标，无端口概念），节点成功 = `success`＋`avg_ms>0`，`level=icmp`，不产 `isp_ms`；与 TCP 共用节点采样，跑在 TCP 相之后（只投仍未定论者），CI 400 键/20 并发
- `cn32`（CN-35）：同站 `type=http`（`http://ip:port/`，明文打 TLS 端口收 CF 400 即完整往返，cn01 同口径），节点成功 = `success`＋`status>0`，`level=http`，ms 取 `connect_ms`，与 TCP 同口径产 `isp_ms`；跑在 ping 相之后（只投仍未定论者），CI 200 键/8 并发
- `cn33`（CN-40）：同站 `type=traceroute`（裸 IP 目标，多跳轨迹），节点成功 = 后端判定 `success`（活体 98/100，拒测 0/100），`ms` 恒空（轨迹时长非 RTT，布尔见证），`level=icmp`，不产 `isp_ms`；跑在 http 相之后；mtr 型因 cost 高 375 倍不接入；CI 200 键/6 并发
- `cn07`：18 ICMP 节点，成功率达 50% 判可达（专测大陆主机存活）
- `cn08`（已迁 PCB，~12 大陆 ICMP 节点，纯 HTTP+SSE 零鉴权）、`cn14`（~155 节点，JWT+WS，TCP `ip:port`）、`cn15`（CN-28：cn14 同站 ICMP ping，复用 code=3 分支，`level=icmp`，不产 `isp_ms`；CI 200 键/8 并发）、`cn17`（~163 TCP 节点，SHA-256 PoW + ALTCHA 会话复用纯 Python 求解 + WS，真实端口直连；CN-30 起同通道 `cn18` ICMP 并行；CN-44 起同基建 `cn19` MTR 通道，约 139 节点末跳见证，不产 `ms`/`isp_ms`）、`cn16`（~53 ICMP 节点，服务端渲染 token + WS）、`cn11`（34 大陆省市节点 TCPing，socket.io）、`cn12`（CN-36：同站 continuous-ping，35 节点 socket.io，结果帧与 TCP 同形，`level=icmp`，不产 `isp_ms`；CI 200 键/6 并发）、`cn09`（约 39 ISP×节点 TCPing，HTTP+SSE 零鉴权）、`cn10`（CN-34：同站 ICMP，复用 port="" 分支，`level=icmp`，剥离 `isp_ms`；CI 200 键/8 并发）、`cn04`（CN-27：28 城三网 TCPing，原生分 ISP；CI 以 200 键/6 并发启用）、`cn05`（CN-50：同站 HTTP 测速通道，应用层确认，`level=http`，活体 27/28 出数；仅 443 键可用；CI 以 200 键/6 并发启用）、`cn06`（CN-42：公开 WS 通道约 16 节点 TCPing，原生分三网，活体 16 节点出数；CI 以 200 键/6 并发启用）、`cn34`（CN-43 复活：tools.ipip.net 同路径 GET+SSE 新接口，约 287 节点 TCPing，`isp` 原生三网经 `_cn_isp_label` 聚合，活体 287 节点出数，死体 0 出数完美区分；SSE 单键约 90s 采集窗，CI 以 100 键/8 并发启用）＋`cn35`（CN-45：同站路由追踪，hop 行目标 IP 即见证，`level=icmp`，不产 `ms`/`isp_ms`，CI 以 100 键/8 并发启用）、`cn42`（休眠）、`cn43`（休眠）、`cn44`（休眠）、`cn13`：各含多大陆节点，默认 0（跳过），由 `--cn-limit CODE=N` 启用（cn13 已迁 PCB）
- `cn40`：约 13 个大陆节点，≥7/13 可达即判可达，报告不足 5 节点 → inconclusive
- `cn41`：多运营商 TCPing，token 由 CLI 注入（`--tcpping-token`/`TCPPING_CN_TOKEN` env），缺则自动跳过

多节点源须「报告 ≥ `MULTI_MIN_NODES`（5）个节点 + 各自成功率达标」才可独立判 reachable（`strong_valid`），防限流残缺样本假阳性退化为单点。

已评估并放弃的补充源：`api.hostmonit.com/check_port`（已 404）。
2026-09 穷尽复核（CN-19/21/22，CN-43 更新）：`cn42`（API 404＋新页挂 AliyunCaptcha）、
`cn34`（tools.ipip.net 旧 POST 405 下线，CN-43 起同路径 GET+SSE 新接口复活；逆向细节已迁 PCB）、`cn43`（/api.php 404，
工具路由迁移无迹可循）、`cn44`（Turnstile＋`/api/probe` 404 双重出局）、
`cn13`（TLS 主机名错乱无 SAN）、
`ping.aizhan.com`（AliyunCaptcha，API 签名未知）、站长测速（captcha＋JS
内聚无 API 面）、`check-host.net`（59 节点零 CN）、dnschecker（403）、
pingtool（404 且无 CN）、oioweb/uomg（TLS 坏）。CN-25 在同站内再挖一层：
`cn25`（无铭 API ICMP ping，与 tcping 同站同节点、不同协议层）证实同运营者
仍可产出正交证据；用户已授权逆向与反爬对抗（2026-09-19，源越多越好），
下一阶段按此新口径复活 captcha 墙后休眠源（boce 新路由/17ce 新端点/
aizhan 签名/ping0），此前"新源唯一现实路径为用户 key"的结论作废。
CN-26 首轮逆向复核（均为活体探针实证）：
`cn42`（`/tcping` 页 200 存活但提交链为 AliyunCaptcha＋`encryptFun`
加密提交，匿名无协议旁路，仍阻塞）、`cn43`（提交签名为静态盐 SHA1
可复刻，但匿名提交强制图片验证码 `/site/verify` 且 TCPing 路由
`/site/tcping` 404 无 TCP 能力，仍阻塞）、`ping.sx`（421KB 前端包零
China/节点提及，`public-us` 美区 playground，无 CN 覆盖，不接入）、
小小API 根域无第二 vantage（TLS 中断/404；四端点已入 cn20-cn23）。
同轮产出：`cn03`（提交/WS/记录与 batch 系全同构，无新增
反爬动作）；无铭 API 双镜像 failover。
CN-27 逆向复核（活体探针实证）：`ping.aizhan.com`（提交协议裸露：`POST
/api/node` 会话 CSRF＋`POST /api/node-data` 轮询，全程无 captcha 参数，
但匿名仅返回 1 个赞助节点广东深圳[电信]且 12s 轮询无数据，`type=tcping`
亦同单节点、无真实 TCP 能力，仍阻塞）；`ping.cn`（TLS 主机名错乱，
oioweb 同类，不接入）；`cn42` 的 api 域（404）；同站另两通道 batch_https/dns
（软 404 回首页，不存在）。
同轮产出：`cn04`（28 城三网，CI 200 键/6 并发启用；逆向细节见 PCB 包内文档）。
CN-28 逆向复核（活体探针实证）：`api.qqsuu.cn`（`dm-ping` 需 ApiKey 登录，
key 墙；`dm-tcping` 接口不存在。不接入）/`tool.lu`（首页零 ping/tcp
提及，无网络测量工具。不接入）/`api.oick.cn`（聚合站 ping 路径猜测 404，
无目录可循，停损）。
同轮产出：`cn14` code=3（PING）分支此前已实现但无调用方，单列
`cn15` 源（同站同节点、不同协议层，低增益-同站；`level=icmp`、
不产 `isp_ms`；活体 223.5.5.5→178/179、192.0.2.1→186 全 fail；CI 200 键/
8 并发启用）。
CN-29 逆向复核（活体探针实证）：`cn17` 确认死亡——`/api/probe/task`
现回 403 `{"captcha":"altcha"}`（tcping/ping 双类型同墙）；ALTCHA 半破解
（challenge 为标准 ALTCHA：SHA-256、maxNumber 50000、~0.1s 解出；
payload 须 base64，solve 200 `ok:true`；但会话绑定未过，verify/task 仍
403；续攻方向：task 体回显 payload / 对 widget 源码 payload 字段 /
TLS 指纹差；验证方法：同脚本复测 solve→verify→task 全链）。CI 配额
`--tcpingcn-limit 400→0` 停烧（代码保留待复活，锁测试
`test_tcpingcn_stays_disabled_until_altcha`）。
`api.qqsuu.cn`（`dm-ping` 需 ApiKey、`dm-tcping` 不存在。不接入）/
`tool.lu`（无测量工具）/`api.oick.cn`（路径 404）/`ping-qyc`（WS-only）。
同轮产出：`cn21`（小小API `api/ping`，`?url=` 参数经文档查得；山东枣庄 BGP
ICMP，活体 223.5.5.5→8.239ms、8.8.8.8→42ms，TEST-NET 回显失配判 fail，
私网 -4 拒绝按 error）接入为 `cn21` 源（地理＋协议双差异，中增益；
L2 全池；`level=icmp`、不产 `isp_ms`）。
CN-30 逆向决战 cn17（活体全链路打通）：ALTCHA 为标准规范纯计算
（challenge：SHA-256、maxNumber 50000、~0.1s；solve 载荷须 base64，
裸对象回 400），会话绑定铁律——只带 `probe_captcha_pass`（忌预载壳页
`ip_page_token`）、全站高频握手触发静默升级（短时 ~20 次即 403；
进程级缓存会话 TTL 1800s、任务 403 自愈重试一次）。`type=ping` 同通道
可用（结果帧紧凑键经前端 a2 映射确认：`r`=rtt_avg、`m`=rtt_min、
`q`=loss、`i`=isp、`a`=地域；`complete` 帧收尾）。
同轮产出：`cn17` 复活（CI 400 恢复，会话复用＋403 重试）＋新源
`cn18`（同站 ICMP，`level=icmp`，地域|ISP 去重，不产 `isp_ms`；
显示语义未定前宁缺勿假；CI 200 键/6 并发）。
CN-34 逆向复核（活体探针实证）：`cn09 type=ping`（SSE 同端点，39/39
出数，原生 ms；节点 `isp`/`country_group` 富模式）接入为 `cn10` 源
（同站 ICMP，`level=icmp`，剥离 `isp_ms`；CI 200 键/8 并发）。`cn11`（其 /httptest 为 URL 型网站测速，非 ip:port TCP，
不接入）。同站 batch 通道族（WS 即关，节点表小，不接入；待验证法：浏览器抓包）。
CN-36 逆向复核（活体探针实证）：`cn12/continuous-ping`（同站 JS
`continuous_ping.js`，事件族与 TCP 全同形，仅 start 载荷无 port；
35 节点原生 isp：电信 11/移动 10/联通 8/多线 4/港澳台 1/海外 1；
活体 35/35 出数）接入为 `cn12` 源（参数化复用 socket.io 通道；
`level=icmp`，不产 `isp_ms`；CI 200 键/6 并发）。
CN-37 逆向复核（活体探针实证）：无铭 API ssl 端点（`?domain=&port=`，
存活回完整证书链＋协议/套件/有效期，死亡回 `success:false`；双镜像
同形存活）接入为 `cn26` 源（同站第三协议 TCP/ICMP/TLS；
`level="tcp"` 保守，无 ms；L2 全池；双镜像 failover）。
CN-38 逆向复核（活体探针实证）：websearch 挖出 `kkce`（openapi 需点数，
付费墙；web 端 WS 403＋登录门，不接入）/`dnspup`（WAF 硬拦截 403，
不接入）/`tance`（TLS 握手失败，不接入）；小小API 目录深挖出
`api/speed`（需 Key，不接入）＋`api/status`（免 key，`?url=`，
400/404 均为应用层应答，`-2` 死、`-4` 拒）接入为 `cn22` 源
（同站第四端点；`level=http`，无 ms；L2 全池）。
CN-39 逆向复核（活体探针实证）：小小API 目录续挖出 `api/portscan`
（`?address=`，固定 8 端口，443:true/全关两态）接入为 `cn23` 源
（仅 443 键产出，其余 skipped；`level="tcp"` 布尔见证；L2 全池）。
分运营商放量：实测 china.json 23139 条仅 500 带 `isp_ms`；`cn24
`（宁波电信归属明确）ok 即附 `isp_ms={中国电信}`，L2 全池
每键一个电信样本（北京/呼和浩特/BGP 节点归属不明，继续豁免；
ICMP 全系继续豁免，规则：TCP/HTTP 产出、ICMP 豁免）。
CN-33 逆向复核（活体探针实证）：`cn31 通道 type=ping`（202 建任务，
158 节点，`avg_ms`/`packets_received`  schema 与 tcping 同构）接入为
`cn31` 源（同站 ICMP，裸 IP 目标；`level=icmp`、不产 `isp_ms`；
与 TCP 共用节点采样，跑在 TCP 相之后；CI 400 键/20 并发）。
`cn17 type=http/https`（http→403 墙、https→400 未知类型，不接入；
站方频率敏感，不再深耗）/同站另一 batch 通道
（同族 WS 即关史，不再深耗）。
CN-35 逆向复核（活体探针实证）：`cn32 通道 type=http`（202 建任务，
全字段 `status/connect_ms/speed_mbps/resolved_ip`；`https://` 型被拒，
仅 `http://ip:port/` 可用；192.0.2.1 以 success=false＋prohibited 干脆
拒绝）接入为 `cn32` 源（同站应用层；`level=http`；ms 取
`connect_ms`；与 TCP 同口径产 `isp_ms`——HTTP 层与 cn01 一致，ICMP 才
豁免；跑在 ping 相之后；CI 200 键/8 并发）。
`http.ping.pe`（530 源站死）/`cn07`（纯 ICMP ping 站，无 TCP 端点）/`tool.lu`（无测量工具）/`yunaq`（非测量站）/`speedtest.cn`
（自测站，无 ip:port 探针），不接入。
CN-40 逆向复核（活体探针实证）：`cn33 通道 type=traceroute`（202 建任务，
158 节点；`hops[]` 逐跳 avg/loss；mtr 型 cost 高 375 倍不接入）接入为
`cn33` 源（同站路由追踪；`success` 即达判，`ms` 恒空布尔见证；
`level=icmp`，不产 `isp_ms`；跑在 http 相之后；CI 200 键/6 并发）。
`pingcz.cn`（OAuth 登录门）/`iptrace.net`（API 需 Key），不接入。
CN-42 逆向复核（活体探针实证）接入为 `cn06` 源（约 16 节点 TCPing；`level=tcp`；`isp_ms` 只收电信/联通/移动；CI 200 键/6 并发；逆向细节见 PCB 包内文档）。
CN-43 逆向复活（活体探针实证）接入为 `cn34`（tools.ipip.net GET+SSE 新接口，约 287 节点 TCPing，`isp` 原生三网经 `_cn_isp_label` 聚合；严格口径 `rtt_avg>0` 且 `loss==0`；采集窗上限 95s；`v` 按目标冒号切换 6/4；CI 100 键/8 并发约 20min；逆向细节见 PCB 包内文档）。
CN-46 独立厂商（活体探针实证）接入为 `cn36`（globalping 社区探针，`locations=[{country:CN}]` 实证命中北京探针 ICMP；`192.0.2.1` 被服务端 validation 拒收故判 error 不污染；匿名 250/h 配额；`level=icmp`，不产 `isp_ms`；与 cn22 交叉即 reachable；CI 60 键/4 并发约 8min；逆向细节见 PCB 包内文档）。同轮排除：`cn27` 站内 MTR（建任务成功但 MTR 节点池无 CN 节点，`region:[CN]` 0 出数）；`host.tools`（文档化免 key API，但后端 dispatcher 持续失联）；`uptimia`（14 站点无 CN）；`traceroute.dev`（亚洲站无大陆）；`cn42` 的 aliyun 镜像（控制台登录门）；Globalping 异步社区模型不适配批量（仅作小配额单点票）。
CN-47 同站追踪（活体探针实证）接入为 `cn37`（globalping 同 API 路由追踪，末跳 `resolvedAddress` 精确等于目标即见证，双活体目标末跳到达；死体无响应跳结构上恒 fail；`ms` 恒空/`level=icmp`/不产 `isp_ms`；CI 40 键/4 并发；逆向细节见 PCB 包内文档）。
CN-48 同站应用层（活体探针实证）接入为 `cn38`（globalping 同 API `type=http`，明文打 TLS 端口收服务端 400 即完整往返，cn32 同口径；闭端口 failed＋timings 全空，完美区分；`ms` 取 `timings.tcp`；`level=http`；不产 `isp_ms`；CI 40 键/4 并发；逆向细节见 PCB 包内文档）。
CN-49 同站 MTR（活体探针实证）接入为 `cn39`（globalping 同 API `type=mtr`，末跳 `resolvedAddress` 精确等于目标即见证；活体 223.5.5.5/8.8.8.8 末跳到达；死体无响应跳结构上恒 fail；`ms` 恒空/`level=icmp`/不产 `isp_ms`；CI 40 键/4 并发；逆向细节见 PCB 包内文档）。
CN-50 同站 HTTP（活体探针实证）接入为 `cn05` 源（仅 443 键；`level=http`；CI 200 键/6 并发；逆向细节见 PCB 包内文档）。CN-50 收官：50 轮 CN 检查源任务完成（CN-25…CN-50 连贯链，见各轮逆向记录）。
CN-45 同站追踪（活体探针实证）接入为 `cn35`（tools.ipip.net 同族路由追踪，hop 行目标 IP 精确相等即见证；活体 37/42 达目标、死体 0 出数；`ms` 恒空/`level=icmp`/不产 `isp_ms`；采集窗 80s；CI 100 键/8 并发；逆向细节见 PCB 包内文档）。同轮修复 CN-43 遗留 bug：专用相与五源通用循环双跑（循环摘除 cn34，回归锁覆盖）。
CN-44 逆向复核（活体探针实证）：`cn17` 同基建 `u.type` 枚举——`trace` 被拒（无效类型），`traceroute` 建任务成功但后端回"任务暂不可用"（容量不稳，不接入，待复测），`mtr` 建任务＋WS 出数（约 139 节点，`event: result` 行含 `mtr_text` 全轨迹）——活体 138/139 末跳达目标、死体 0/169，接入为 `cn19` 源（末跳见证布尔判定，子串防误判；后端"暂不可用"判 error 不污染 unreachable；`ms` 恒空/`level=icmp`/不产 `isp_ms`，cn33 同口径；CI 200 键/6 并发）。
CN-41 分运营商速度维（活体探针实证）：`cn32 type=http` 结果行虽带
`speed_mbps`（100/100 有值），但目标为 48 字节 400 错误页，中位仅
0.01Mbps——实为 RTT 倒数，无带宽意义，不接入（宁缺勿假）。改由
`isp_ms` 套用与 CN 清单 `≈XMB/s` 完全相同的单流参考上限公式逐运营商
派生 `isp_speed`（`common.cn_isp_speed` 单一事实源，≤2ms 噪声同门剔除），
只增 `china.json` 字段，展示消费留待逻辑优化轮。
CN-31 逆向复核（活体探针实证）：同站 batch_ping 通道（WS 即关，不接入）/小小API `api/netCheck`
（需 Key，不接入）。同轮产出：`cn28`（同节点 ICMP，
活体出数：`checks[0]={status,connectiontime}`）接入为 `cn28`
源（仅 TCP-fail 追加消歧，共用配额；`level=icmp`、不产 `isp_ms`）。
CN-32 事故复盘（更新链连续失败）：`data/download/countries/` 下 75 个
valid 式 `<CC>/all.txt` 目录（f5725f9f4 误入库）炸掉 `write_outputs`
残留清理（`stale.unlink()` 遇目录抛 IsADirectoryError；worktree 实证
复现＋修复验证 exit 0）。根因：`reconcile_views` 的回填按 valid 布局
写分裂，`reconcile_download_tree` 误将其用于扁平 download 树。修复：
75 目录删除＋回填加 `backfill` 开关（download 侧 False）＋残留清理
遇目录跳过告警（fail-open）。创建向量未完全锁定（提交信息为
annotate 系，待验证），机制已根治。
同轮产出：`cn29`（同节点 HTTPS 应用层确认，
活体：404 亦完整往返）接入为 `cn29` 源（同节点第三协议；
仅 TCP-ok 且其余免额 0 ok 时猎取第二确认；`http_status>0`→`level=http`
首个 http 单节点源，无应答但连通→`tcp`；不产 `isp_ms`）。
（`cn16` 的公共表单端反爬成本高，但对应实验性 REST 通道已由 WS 版 `cn16` 源替代并接入上述列表。）

### 5.2 合成判定逻辑（merge_verdict）

```
输入：sources = {cn27: {status, ok, ms, level}, cn20: {...}, cn24: {...},
       cn25: {...}, cn01: {...}, cn40: {...}, cn30: {...}, ...}

规则（merge_verdict，与 china_check 实现逐条对应）：
1. 多节点源（cn40/cn01/cn02/cn03/tcpping/cn30/cn31/cn32/cn33/tcpping_ws/cn07/cn08/
   cn14/cn15/cn17/cn18/cn19/cn16/cn11/cn12/cn09/cn10/cn04/cn05/cn34/cn35/cn42/cn43/cn44/cn13）任一
   强确认（`strong_valid`：成功率达各自阈值且报告 ≥5 节点）→ reachable
2. 单节点源（cn27/cn28/cn29/cn20/cn21/cn22/cn23/cn24/cn25/cn26/cn36/cn37/cn38/cn39）≥2 个 ok → reachable
3. 多节点源仅弱确认（如 cn01 仅 1/24 节点）+ 无 ≥2 单节点 ok → uncertain
4. 有任意 ok 源但未达上述 → uncertain
5. 单节点源 ≥2 个 fail → unreachable；或多节点源 ≥2 个 fail、
   或多节点源 ≥1 fail 且单节点源 ≥1 fail → unreachable
6. 全部 error/skip → skipped（不误判）

证据分级 level：
- 任一成功源给出应用层（HTTP）确认 → "http"
- 有成功源但全部仅传输层（TCP）→ "tcp"
- 无成功源 → None
```

### 5.3 跨轮稳定性

写 `china.json` 前读取上一轮结果：

- **streak**：per-key 连续可达轮数（reachable 且上轮也 reachable 且
  观测间隔 ≤6h → 累加；否则清零/置 1）。容差取 6h 因 GitHub schedule
  实测每 ~2.5-4h 才实际起一轮，过紧会让 streak 每轮清零、stable 永不累积。
  `last_ok_ts` 记录最近可达时间，用于时间窗判定——即使 china.json 被
  并发提交短暂回滚，连续计数不丢
- **uncertain 优先复检**：上一轮 uncertain 的键在本轮采样中稳定排序置顶
  （limit 截断时优先覆盖）

### 5.4 输出

- `data/quality/china.json`：逐条明细，含各源 status/ms/level 与合成 verdict/basis/ms/level/streak
- `data/valid/all_cn.txt`：全量大陆可达清单（仅本次 reachable，历史累积 `-CN` 不再自动纳入），按大陆实测延迟升序；
  应用层确认行追加 `-CNH` 备注
- `data/valid/all_cn_http.txt`：应用层确认子集（本轮 level=http 或历史已带 `-CNH`）
- `data/valid/all_cn_stable.txt`：跨轮稳定子集（连续 ≥2 轮 reachable，不含历史兜底）
- `data/valid/*.txt`：可达者追加 `-CN` 备注
- **CN 视图行内指标统一大陆口径**：validate_proxies 的 `cn*`/`all_cn*` 分组与
  build_good 的 CN 集合（`sets/cn*`、`countries/CN`）写出的行，`ms` 均替换为
  `common.cn_display_ms`（可信大陆探测优先、L3 复核源 ≤2ms 噪声不作数）、
  `速度` 替换为 `≈XMB/s` 大陆估算——与 `all_cn.txt` 完全同源同口径，杜绝
  "海外 6ms/117MB/s 冒充大陆速度"的陈旧视图；无大陆读数的键速度 token 删除。
- **cn16（纯 ICMP）不构成大陆延迟证据**：其 1~8ms 是到国内 IP 边缘的 ping
  假象、与真实代理/隧道延迟无关且反直觉地极小。`cn_display_ms` 回退时显式剔除
  cn16，且回退 entry 合并 ms 时拒绝 ≤2ms（该值可能正是被 ICMP 污染的合并结果），
  宁缺勿假——避免产出 `US-2ms` 之类失真行。
- **CN 全量清单兜底 ≥1 万（判定层合并，单一事实源）**：上轮可达、本轮仅因源
  配额/调度抖动落入 uncertain（或未被采样）且**无任何失败源**的键，在写
  china.json 前合并回 ``verdict=reachable`` 并标注 ``fallback:true``。因此
  build_good/annotate/all_cn.txt 全从 china.json 读到**同一集合**，杜绝
  "all_cn.txt 有而 all.txt/CN 分组找不到来源"的口径分裂，且维持全量池规模
  （用户硬约束）。兜底键若本轮无大陆读数（来源全 error），沿用其上一轮条目
  的 ``ms``/``isp_ms`` 读数写入 china.json，保证 build_good（只读 china.json）
  与 all_cn.txt（run 尾从 prev 回填）对同一键渲染同一大陆读数——兜底行仍经
  大陆延迟/速度重写，且 read-only 下游不会因读数缺口退化为海外 TLS 延迟。

## 6. 出口 IP 家族检测（exit_family.py）

### 6.1 检测方法

所有代理使用 **双栈出口探测** 方法：分别请求仅 IPv4（`ipv4.icanhazip.com`，仅 A 记录）与仅 IPv6（`ipv6.icanhazip.com`，仅 AAAA 记录）的回显服务——走得通即证明代理具备对应家族的**出口能力**，两者皆通判 `dual`。回显为纯 IP 文本；若两者均失败，尝试通用目标 `cloudflare.com/cdn-cgi/trace` 兜底。注意：入口 socket 家族（AF_INET/AF_INET6）无法反映出口家族——它只约束客户端→代理一跳；CF 边缘代理的出口由 Worker fetch() 决定、与入口和目标主机名均无关（对单族目标也返回同一出口 IP），故 CF 类代理 `dual` 恒为 0 属架构固有行为。

### 6.2 家族判定

| 结果 | 条件 |
|---|---|
| ipv4 | 仅 v4 回显成功 |
| ipv6 | 仅 v6 回显成功 |
| dual | v4 + v6 均成功 |
| unknown | 全部失败 |

`unknown` 的行内 `-V4`/`-V6`/`-DS` 旧 token 会被清桶（R165：宁可未知不冒称）；
无权威记录的行保留既有 token（数据集缺失≠该行未知），下游分组对
`unknown` 不做 v4/v6/46 分支（不回落行内 token，R166）。

### 6.3 交叉验证

对照 `data/quality/upstream_meta.json` 的真实出口 `clientIp`，在 `exit_family.json` 中补充 `upstream_match` 字段。

## 7. 后缀填充与分类（annotate_classify.py）

读取 7 个 JSON 数据源，向所有 `data/valid/*.txt` 文件填充缺失后缀并追加分类 token。

### 7.0 统一备注规范器（common.normalize_note）

所有工作流**禁止**直接 `line += "-TOK"` 拼接备注；必须经由
`normalize_note` / `merge_note_tokens`（追加）/ `clear_note_buckets`
（互斥桶先清后设）。规范段顺序：

```
入口CC[→出口CC] - 延迟ms - 速度MB/s - 流媒体(并集) - 类型 - 速度档 - 家族 - CN/CNH - 信誉分 - U<NN>
```

- 单值桶（类型/档位/家族/分数）取最右（最新）；多轮 CI 堆叠的历史快照自动收敛。
- `CF`（边缘标记）已废弃：池子全为 CF 边缘端口恒真、无信息量，`normalize_note`
  归一化时直接丢弃，历史行含 `CF` 也不再保留，新行不再生成该 token；故其不参与
  出口类型互斥判断，本规范段序中也无 `CF` 位。
- 流媒体为并集去重；`CNH` 蕴含 `CN`。
- 互斥桶由权威源"先清后设"：ipinfo 类型覆盖历史类型，exit_family 家族覆盖旧家族，
  重算的速度档替换旧档——避免 `-DC-…-RES` 新旧并存。

### 7.1 Token 追加顺序

> 本节描述各 token 的**处理追加先后**；任何追加都经 `merge_note_tokens`
> （内部先 `normalize_note`）落盘，最终行内布局一律重建为 §7.0 的规范段序，
> 故追加顺序不影响落盘顺序。下面的编号顺序已按当前 annotate_classify
> 实现核对。

1. 出口国家标记：`→CC`（有出口观测即标注，含同国）
2. 大陆可达：`-CN`
3. IP 家族：`-V4` / `-V6` / `-DS`
4. 信誉评分：`-<score>`（如 `-72`）
5. IP 类型：`-DC` / `-RES` / `-MOB` / `-PROXY`
6. 速度等级：`-fast`（≥5 MB/s）/ `-mid`（1-5 MB/s）/ `-slow`（<1 MB/s）
7. 滚动可用率：`-U<NN>`（uptime.json 的 pct7，如 `-U92`；无观测不加）
   （流媒体解锁 token 已停止生成——历史遗留 token 被规范器容忍）

### 7.1.1 `ms` 与 `MB/s` 的测量语义（按清单视图区分）

- **速度 `MB/s`** 一律来自海外测速：GitHub Actions runner（美区）经代理
  下载 `cdnjs.cloudflare.com` 固定样本（≤1MB、5s 超时、丢弃前 256KB
  warmup）。它反映"代理入口机 ↔ 其本地 CF PoP"的吞吐 + runner 侧瓶颈，
  **与大陆链路无关**；同国数值聚集是因为条目多来自同几家主机商的同规格
  端口，且 CDN 本地化使路径极短。绝对档位阈值全局统一，因此弱供给国家
  可能整国无 `fast`——请配合组内相对最优 `good_top.txt` 使用。
- **延迟 `ms`** 分两种视图：
  * CN 系清单（`all_cn*`、各国/各集合 `cn*.txt`）：行内 ms 已替换为
    **大陆实测 RTT**——优先取**最快运营商视角**（`common.cn_fastest_ms`：
    各运营商最小 RTT 取全局最小，如 cn01 电信/联通/移动节点分别聚合后的
    最低值，即大陆用户体验上界）；无 per-ISP 读数（`isp_ms`）时回退可信
    大陆探测源（cn20 北京 / cn24 宁波 / cn27 呼市）的 ok 最小 RTT，
    再回退全部 ok 源 ≥2ms 最小可信值及行内值，杜绝 L3 复核源 1ms 噪声
    冒充真实延迟。速度 token 同步改写为大陆视角估算 `≈XMB/s`——以最新
    **最快运营商 RTT** 推算单流上限，与海外实测取小；`china.json` 另存
    分运营商估算速度 `isp_speed`（CN-41：`isp_ms` 同公式逐运营商派生，
    只增字段，供逻辑优化轮消费）；
  * 其他清单（`all.txt`、国家全量等）：ms 为海外 runner 的 TLS 握手延迟。
- CN 系清单**保持完整**：`all_cn*` 与 CN good-tier 收录当期全可达集
  （正常水平 ≥1 万），不按大陆延迟门槛精简；下落即有运行时自检
  （`check_cn_health`）保证行数 ≥1 万、无 ≤2ms 噪声、无缺 ms 行，不达标告警。
- 大陆**带宽**目前无法实测（第三方探测仅提供延迟/可达性），故不存在
  "CN 测速"；挑选高带宽节点请看海外 MB/s + `good_top`，选低延迟请看
  CN 清单的 ms 排序。

### 7.2 出口国家标记的三数据源

`→CC` 由统一构建器 `common.build_exit_cc_map` 多源汇聚（annotate_classify
与 reorg_country 共用），优先级从高到低：

1. `external_check.json` —— 外部探测接口直接回显的出口地理；
2. `upstream_meta.json` —— 自有 CF Worker 观测到的代理出口国。其键为
   代理（接入）裸 IP，值的 `country` 即该代理出站地理；经 `common.
   build_exit_cc_map` 按行键的入口 IP 部分（`ip:port#CC` → 裸 `ip`）命中；
3. `ipinfo.json` —— 出口 IP 的 ip-api 地理。历史轮次可能是入口 IP 的
   地理，仅作末位兜底。
   （原第 3 层 streaming 解锁国已随流媒体检查移除。）

已有 `→CC` 但与新观测不同视为陈旧出口（出口会漂移），直接替换。

### 7.2.1 入口/出口冲突处理

- **入口 CC**（行内 `#<emoji><CC>`）：订阅源自带标签，全链路不改写——
  它是溯源标识，也是全 pipeline 键的组成部分（`line_to_key` 含 `#CC`），
  改写会撕裂所有 quality JSON 的历史对应。准确性无保证，以出口实测为准。
- **出入口不一致**：入口标注保留原样，行内追加实测出口 `→OC`，
  `countries/` 下目录迁移到出口国；sets/ports 混国文件只标注不迁移。
- **多源出口观测互相冲突**：按上述优先级取高者。

### 7.3 行格式示例

```
1.2.3.4:443#🇺🇸US→US-120ms-0.44MB/s-GPT-DC-fast-V4-CN-72
```

## 8. 并发与容错

### 8.1 阶段隔离

各阶段通过 CI workflow 顺序执行，互不干扰：

1. `update-proxies.yml`（每 2 小时，`0 */2 * * *`）→ download + validate
2. `quality-check.yml`（触发于 1）→ reputation + uptime + reorg
3. `china-check.yml` → 大陆连通性。双触发：quality 完成后 + **每小时独立
   心跳**（`11 * * * *`）。streak 依赖"连续多轮可达"，独立心跳保证上游
   失败或 IP 长期未变更时 stable 仍按小时累积
4. `exit-family.yml`（触发于 2）→ 出口家族
5. `annotate-classify.yml`（触发于 2）→ 后缀填充 + 分类

### 8.2 取消机制

- `update-proxies.yml`：`cancel-in-progress: true`（主更新优先）
- 其他下游 workflow：`cancel-in-progress: false`（保护已完成的检测结果）

### 8.3 门控逻辑

所有 workflow 共用两层门控（`gh run list` 竞态去重 + 可选触发者状态闸）：

1. **竞态去重**：用 `gh run list` 查同工作流是否有更新的 in_progress/queued
   运行，有则让位（旧运行自动跳过），防止积压排队。
2. **触发者状态闸（仅 `workflow_run` 链）**：quality-check（←update-proxies）、
   exit-family / annotate-classify（←quality-check）、build-good（←quality/
   china）、stats（←quality/china/exit-family/build-good）在触发工作流
   conclusion 非 success 时**跳过**——上游失败说明本轮没有新的数据产物，
   无需浪费一次下游重算。

刻意**不因触发者失败而跳过**的只有 `china-check.yml`：它已改为纯 schedule
驱动（每小时 11 分自启，见 8.1），不再挂 `workflow_run` 链——因此它没有
"触发者"概念。独立心跳保证上游失败或 IP 长期未变更时 stable 仍按小时
累积，否则 IP 未变更期间 stable 永远无法累积、信誉/家族等新数据也无法
及时反映到清单后缀。该链从仓库 checkout 的自洽数据运行（all.txt 与各
JSON 均为上次成功轮的完整快照），单次失败不冻结 CN 连通性追踪。
