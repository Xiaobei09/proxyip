# data/ 数据目录索引

本目录**全部文件由 CI 脚本自动生成**（`.github/workflows/*.yml`），人工不要直接改
数据文件，需要重生成请运行对应脚本。`data/` 被 `.gitignore` 忽略，只有脚本产出的
差异会被 `commit_data.sh` 增量提交（基于 `.jobstart` 时间戳的 `find -newer`）。

契约与格式的权威定义见 [`../docs/data-spec.md`](../docs/data-spec.md)。本文档是
浏览入口（“立体化”导航），只做索引与层级说明，不重复契约细节。

---

## 1. 目录总览（tree）

```
data/
├── README.md            ← 本索引（人类导航）
├── raw/                 上游原始归档（zip/txt 快照，仅归档不消费）
├── download/            下载/切片产物（all.txt、countries/、ports/、sets/）
├── quality/             质量链路工件（探测、信誉、清单中间态）
├── valid/               全量/限量清单分层（all/rep/good/premium/cn + 变体）
└── output/              对外发布件（stats.json、badge.json、16+ 张图表 SVG）
```

## 2. 层级说明（四层“立体”视图）

数据可以按四个逻辑层阅读，与物理子目录一一对应：

| 层 | 物理目录 | 语义 | 典型消费者 |
|----|----------|------|-----------|
| 采集层（Ingest） | `raw/`, `download/` | 上游原始数据与切片 | 验证脚本、deep-speed |
| 判定层（Probe） | `quality/` | 可达性/延迟/信誉/大陆判定等探测明细 | china-check、build_good、health |
| 发布层（Release） | `valid/` | 整理后可直接使用的清单变体 | 各 `*.yml` 下游、仓库用户 |
| 观测层（Observe） | `output/` | 统计/图表/徽章，README 直接引用 | README、外部报表 |

> 三层以上的命名规范：`valid/` 下的文件按 `all_<组>[_<变体>].txt` 组合，变体后缀
> `_ltd/_verified/_stable/_rep` 表示限量/已链验证/连两轮存活/高信誉，可在括号内
> 组合（见 `docs/data-spec.md §限量版`）。

## 3. 工件索引

### 3.1 `data/output/`（观测层）

| 工件 | 生产者 | 说明 | 契约 |
|------|--------|------|------|
| `stats.json` | `generate_stats.py` | 全量统计快照（徽章 JSON 源） | data-spec.md §`output/stats.json` |
| `badge.json` | `generate_stats.py` | 徽章数值 | data-spec.md §`badge.json` |
| `country_speed.json` | `generate_stats.py` | 国别速度分布 | data-spec.md §`country_speed.json` |
| `chart_*.svg`（16+） | `generate_stats.py` | 图表：combo/country/port/churn/latency_speed/sets/cn/cn_7d/family/exit/entry_audit/ip_type/country_speed/speed_spread/source_avail/source_stats/rep | 图表列见 README 顶栏 |
| （无） | `analyze_sources.py` | 人类可读排版表**不发布**，写 `.cache/` | 见 `../quality/source_quality.json` |

### 3.2 `data/valid/`（发布层）

| 工件 | 生产者 | 说明 |
|------|--------|------|
| `all.txt`（18411 行基线） | `validate_proxies.py` | 全量可达清单（本次判定） |
| `all_<组>.txt` 系列 | `validate_proxies.py` | `_ltd/_verified/_stable/_rep` 变体 |
| `all_cn*.txt` | `china_check.py` | 大陆可达清单（含 best-ISP 后缀） |
| `all_diverse.txt` | `validate_proxies.py` | 覆盖多样化子集 |
| `meta.json` | `validate_proxies.py` | 行键元数据（国家/端口/延迟/速度） |
| `ext_check.json` | `validate_proxies.py` | TLS 复核结果 |
| `speed.json` | `deep_speed.py` | 大窗口真实测速 |
| `countries/<CC>/` | `validate_proxies.py` + `reorg_country.py` | 按出口国分目录（77 个国家目录，`all.txt` 1:1 切分） |
| `sets/<name>/` | `validate_proxies.py` | 常用集合目录（10 个） |
| `ports/*.txt` | `validate_proxies.py` | 按端口分组（6 个） |
| `tiers/`、`good*`、`premium*` | `build_good.py` / `build_premium.py` | 档位/优质清单 |

### 3.3 `data/quality/`（判定层）

| 工件 | 生产者 | 说明 |
|------|--------|------|
| `exit_family.json` | `exit_family.py` | 出口 IP 族（V4/V6/DS）划分 |
| `china.json` | `china_check.py` | 大陆探测明细（含 per-ISP `isp_ms`） |
| `cn_history.jsonl` | `health_alert.py` | 近 8 天分运营商可达历史（chart_cn_7d 数据源） |
| `quality_meta.json` | `quality_check.py` | 质量轮元信息（skipped 相位列表） |
| `alert_state.json` | `health_alert.py` | 健康告警状态机 |
| `entry_audit.json` / `entry_geo.json` | `audit_entry_cc.py` | 入口国家标签审计与地理缓存 |
| `external_check.json` | `validate_proxies.py` | 出口国复核 |
| `ipinfo.json` | 质量 CI | 入口 IP 地理 |
| `upstream_meta.json` | 下载链 | 上游出口元数据 |
| `deep_speed.json` | `deep_speed.py` | 真实吞吐 |
| `reputation.json` / `reputation_cache.json` | `quality_check.py` | 信誉打分与缓存 |
| `good_meta.json` / `premium_meta.json` | `build_good.py` / `build_premium.py` | 清单元数据 |
| `source_stats.json` / `source_history.json` / `source_quality.json` | 源健康追踪 | 源质量统计 |
| `uptime.json` / `node_seen.json` | `uptime.py` / quality CI | 存活率追踪 |
| `history.jsonl` | CI 历史 | 全量规模/存活历史（图表 combo 数据源） |

### 3.4 `data/raw/` 与 `data/download/`（采集层）

| 工件 | 生产者 | 说明 |
|------|--------|------|
| `raw/`（273 文件） | `download_proxies.py` | 上游原始归档（zip/txt），仅归档 |
| `download/`（104 文件） | `download_proxies.py` | 下载切片（all.txt、countries/…），供验证链消费 |

---

## 4. 立体化（重构）评估结论

采用“**导航先行、物理格局不动**”的两步走：

1. **本步（已完成）**：新增本索引 `data/README.md`，把 `data/` 由“黑盒目录”变为
   “四层可导航视图 + 工件表 + 生产者/消费者对照”，任何层级可直接跳读。
2. **路径重构（评估结论：暂不物理搬移）**：`valid/` 的变体多维度（组×限量×验证×信誉）
   已由命名规范表达；`quality/` 与 `output/` 职责清晰。物理搬移（如按四层建顶层
   子目录）需同步改 10+ 脚本路径、全部 workflow、`commit_data.sh` 排除规则与文档，
   收益低于风险。若后续确需其物理分层，可在 docs 再评估，本索引的“层级表”
   即未来重构目标。

## 5. 新鲜度

- 每份工件都有生产时间：`output/stats.json` 的 `ts`、`quality/quality_meta.json` 的 `ts`。
- 图表/徽章由 `stats.yml` 与 `quality-check.yml` 定时重建；README 引用的图表直链
  `raw.githubusercontent.com` 即时反映最新提交（2026-09-16 起已替换 jsDelivr 缓存源）。
- `countries/` 与根 `all.txt` 强制 1:1（回归测试 `test_sum_equals_all_txt`）。