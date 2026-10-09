# proxyip

公开的代理 IP 数据集。定期更新，提供按延迟/速度排序的存活清单、按国家/端口/集合分组的
子集、大陆可达性清单，以及结构化 JSON 导出与统计图表。本仓库只发布数据。

[![Unique Proxies](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json&query=unique&label=Unique%20Proxies&color=blue)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/download/all.txt)
[![Alive](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json&query=alive&label=Alive&color=green)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/all.txt)
[![Alive Rate](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json&query=alive_rate&label=Alive%20Rate&color=orange)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/meta.json)
[![Updated](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json&query=updated_ago&label=Updated&color=informational)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json)
[![Status](https://img.shields.io/badge/endpoint?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/badge.json)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json)
[![CN Reachable](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/stats.json&query=cn_reachable&label=CN%20Reachable&color=red)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/all_cn.txt)

![Trend](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_combo.svg)
<details>
<summary>📈 趋势与存活（点击展开 3 图）</summary>

![Country distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_country.svg)
![Port distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_port.svg)
![Churn](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_churn.svg)

</details>
<details>
<summary>🌍 地理与速度分布（点击展开 4 图）</summary>

![Latency & Speed distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_latency_speed.svg)
![Sets](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_sets.svg)
![Country speed distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_country_speed.svg)
![Within-country speed spread](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_speed_spread.svg)

</details>
<details>
<summary>🇨🇳 大陆连通（点击展开 2 图）</summary>

![Mainland China reachability](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_cn.svg)
![CN reachability 7-day trend](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_cn_7d.svg)

</details>
<details>
<summary>🔍 出口与质量（点击展开 7 图）</summary>

![Exit IP family](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_family.svg)
![Exit country top 15](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_exit.svg)
![Entry CC label audit](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_entry_audit.svg)
![IP type distribution](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_ip_type.svg)
![IP source availability](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_source_avail.svg)
![IP source stats](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_source_stats.svg)
![Reputation score](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/output/chart_rep.svg)

</details>

## 我该用哪个文件？

| 需求 | 首选文件 | 说明 |
|---|---|---|
| 大陆日常使用（最稳） | `data/valid/all_cn_stable.txt` | 连续 ≥2 轮大陆可达，抗误判/churn（不满足时不生成） |
| 大陆 + 应用层确认 | `data/valid/all_cn_http.txt` | 过滤"TCP 通但被干扰"；无应用层证据时不生成 |
| 大陆全量 | `data/valid/all_cn.txt` | 全可达集，按大陆实测延迟升序 |
| 综合最优 | `data/valid/all_good.txt` | CN 可达 + 有信誉记录 + 非高风险 + 有国内速度（≈XMB/s） |
| 高端优质 | `data/valid/all_premium.txt` | CN 可达 + 信誉≥95 + 真实住宅 IP |
| 按国家/集合取用 | `data/valid/countries/<CC>/cn4.txt` 等 | 各目录 `all/ltd/v4/46/cn/rep/good/premium` 多件套 |
| 未验证全量 | `data/download/all.txt` | 去重清单，IP 数字序 |
| 程序化消费 | `data/valid/all.json`、`speed.json`、`index.json` | 结构化导出 + 速度/延迟索引 |

未验证目录统一 `ip:port#国家` 格式（如 `1.2.3.4:443#US`），按 IP 数字序排列；`data/valid/` 内为
`ip:port#🇺🇸US-120ms-0.44MB/s`（国旗+国家-延迟毫秒-速度 MB/s，测速失败时省略速度段），**按延迟升序**（`_ltd` 按速度降序）。被质量检测后行内追加 `←` 出口地区与备注段。

```bash
head -1 data/valid/all.txt                  # 当前延迟最低的存活代理（延迟升序）
data/valid/all_ltd.txt                      # 每国按实测速度最快的 20 条限量清单
data/valid/countries/US/all.txt            # 仅美国的存活代理（含延迟/速度）
data/valid/countries/US/ltd.txt            # 该国限量（每国最快 20 条，速度降序）
data/valid/countries/US/v4.txt             # 该国出口为 IPv4 的代理（仅 v4-only，不含双栈）
data/valid/countries/US/46.txt             # 该国出口为双栈（v4+v6）的代理
data/valid/countries/US/cn.txt             # 该国大陆可达的代理
data/valid/countries/US/cn4.txt            # 该国大陆可达且出口为 IPv4 的代理
data/valid/countries/US/rep.txt            # 该国按信誉分降序
data/valid/all_good.txt                     # 全局综合最优（CN 可达 + 有信誉记录 + 非高风险 + 有国内速度 ≈XMB/s）
data/valid/all_premium.txt                  # 全局高端优质（CN 可达 + 信誉≥95 + 真实住宅 IP）
data/valid/all_premium_v4.txt               # 高端优质（出口为 IPv4 的家族分支，另有 _v6 / _46）
data/valid/countries/US/premium.txt         # 该国高端优质
data/valid/sets/hot/premium.txt             # 热门集合高端优质
data/valid/sets/europe/all.txt             # 欧洲集合存活代理（集合也是目录多件套）
data/valid/all_46.txt                      # 全部出口为双栈的代理（根级分组）
data/valid/ports/443.txt                    # 仅 443 端口的存活代理
data/valid/speed.json                       # 每存活代理的实测速度（MB/s，按速度降序）
data/valid/sets/hot/all.txt                 # 热门国家集合（验证后）
data/download/all.txt                       # 全量去重清单（未验证）
```

## 中国大陆使用建议

- **优先消费**：`data/valid/all_cn_stable.txt`（连续 ≥2 轮大陆可达且历史判定翻转 ≤1，抗误判/churn）、
  `data/valid/all_cn_http.txt`（应用层 HTTP 确认，过滤"TCP 通但被干扰"；**条件产物——无应用层证据时不生成，属预期**）、
  `data/valid/all_cn.txt`（全量大陆可达，按**大陆实测延迟升序**）、
  `data/valid/all_good.txt`（综合最优：CN 可达 + 有信誉记录 + 非高风险 + 有速度读数；延迟分优先采用大陆实测值）、
  `data/valid/countries/<CC>/cn4.txt`（该国大陆可达且 IPv4 出口）
- **可靠性叠加**：代理池 churn 快（检测时活着、使用时可能已死），且"TLS 握手存活"≠"能用"。
  按家族分组清单（`v4`/`v6`/`46`/`cn`/`cn4`/`cn6`/`cn46`）派生两个可靠性维度
  （如 `countries/US/cn4_stable.txt`、根级 `all_cn4_verified.txt`）；根级
  `all_cn`/`all_ipv4`/`all_ipv6` 无此直接变体（`all_cn` 自带 http/stable 子集）：
  - `*_verified` — **全链路验证**：本轮测速成功 = TLS + HTTP 2xx + 真实下载全部通过，
    过滤"能握手但不吐数据"的半死代理
  - `*_stable` — **连续两轮存活**：上一轮与本轮存活的交集，对抗快速 churn
  - **跨家族联动**：`ltd`/`rep`/`good` 家族同样派生（如 `all_ltd_verified.txt`、
    `all_cn46_rep_ltd_verified.txt`、`all_good_stable.txt`）；质量侧 `_stable` =
    连续两轮大陆可达（翻转 ≤1）
- **行内备注速查**（`data/valid/*.txt` 行尾 token）：

  | token | 含义 |
  |---|---|
  | `-CN` | 大陆可达 |
  | `-CNH` | 大陆可达且应用层（HTTP）确认（蕴含 `-CN`） |
  | `-V4` / `-V6` / `-DS` | 实际出口家族（入口是 v4，实际出口常为 v6） |
  | `←CC` | 实测出口地区（如 `←US`） |
  | `-<N>` | 信誉分 0–100（越大越干净，如 `-29`；纯数字段，勿与前面的延迟毫秒段混淆） |
  | `-U<NN>` | 7 天滚动存活率（如 `-U35`） |
  | `-RES` / `-DC` / `-MOB` / `-PROXY` | IP 类型：住宅/机房/移动/匿名 |
  | `-fast` / `-mid` / `-slow` | 速度档（≥5 / 1–5 / <1 MB/s） |

## 读图说明

- `chart_combo.svg` — 代理计数与存活率双轴折线（近 7 天窗口）
- `chart_churn.svg` — 每次更新的 added/removed（近 7 天窗口）
- `chart_country.svg` / `chart_port.svg` — 存活代理按国家 / 按端口的 top 分布
- `chart_latency_speed.svg` — 延迟与速度分桶
- `chart_country_speed.svg` — 各国速度分布（p25–p75 区间）
- `chart_speed_spread.svg` — 同国内速度分化（四分位差/中位数）
- `chart_sets.svg` — 各命名集合的存活规模
- `chart_cn.svg` / `chart_cn_7d.svg` — 大陆连通判定分布与 7 天趋势
- `chart_family.svg` — 实际出口 IP 家族（v4/v6）分布
- `chart_ip_type.svg` — 出口 IP 类型（机房/住宅/移动）分布
- `chart_exit.svg` — 出口国家 top 15
- `chart_entry_audit.svg` — 入口国标签审计汇总
- `chart_rep.svg` — 信誉分分布

日常轮次里的 MB/s 是小文件短窗口采样：同一 CDN 本地化边缘下同国趋同，
跨国差异明显属正常现象。需要精确对比时以 `chart_country_speed.svg`（各国中位速度）
为准——它反映的是同一国家内的真实带宽差异，而国家之间的差距是主干网延迟/损耗，
无法用节点选择抹平。

## 数据格式

行格式、备注段含义、限量版规则与国家集合定义见 [数据规范](docs/data-spec.md)；
数据层级与工件索引见 [数据目录](data/README.md)。

## 免责声明

本项目提供的代理 IP 列表来自公开来源，仅限学习与研究用途。使用代理访问网络时请遵守当地法律法规及目标网站的服务条款；本项目不对列表内容的可用性、合法性及由此产生的任何后果负责。
