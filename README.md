# proxyip

定期从 <https://zip.cm.edu.kg> 下载代理 IP 列表并通过 CI 自动解压、整理、验证、提交回仓库；附带一个浏览器指纹生成工具。

[![Unique Proxies](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=unique&label=Unique%20Proxies&color=blue)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/all.txt)
[![Alive](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=alive&label=Alive&color=green)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/all.txt)
[![Alive Rate](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=alive_rate&label=Alive%20Rate&color=orange)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/meta.json)
[![Updated](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json&query=updated_at&label=Updated&color=informational)](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/stats.json)

![Trend](https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/chart.svg)

## 数据

压缩包结构为 `<port>/<country>.txt`，每个文件内每行一个 IP。所有输出均采用 `ip:port#国家代号` 格式（如 `1.2.3.4:443#US`）。脚本会自动：

1. 下载 zip 归档
2. 解压并按 `data/raw/<port>/<country>.txt` 重新组织（含上游聚合文件 `ALL.txt` → `#ALL`）
3. 按国家汇总为 `data/countries/<country>.txt`（跨端口去重，不含 ALL）
4. 按端口汇总为 `data/ports/<port>.txt`（跨国家去重，不含 ALL 派生条目）
5. 按常用集合汇总为 `data/sets/<集合>.txt`（如 `europe`、`asia`、`north_america`、`south_america`、`oceania`、`africa`、`middle_east`、`hot`，以及小集合 `cn_common` 中国大陆常用、`hk_us_jp_sg_tw_kr`）
6. 去重合并为 `data/all.txt`（每行一个唯一 `ip:port#国家`）

每次更新追加一条历史记录到 `data/history.jsonl`（JSON Lines，每行一条：时间戳、总条目、去重数、国家/端口数、各集合条数、新增/移除数）；数据未变化时跳过，最多保留最近 1000 条。

### 可用性验证

CI 每次更新后对 `data/all.txt` 做连通性检查（HTTP CONNECT 到 `www.gstatic.com:443`，默认 5s 超时、100 并发），输出镜像 `data/` 结构的存活列表到 `data/valid/`：

```bash
python scripts/validate_proxies.py                    # 验证全部
python scripts/validate_proxies.py --limit 50         # 冒烟测试前 50 条
python scripts/validate_proxies.py --time-budget 180  # 最多跑 180 秒
```

- `data/valid/all.txt`、`all_ltd.txt` 存活代理（保持 `ip:port#国家` 格式）
- `data/valid/countries/`、`ports/`、`sets/` 按国家/端口/集合分组的存活列表
- `data/valid/meta.json` 汇总信息（checked/alive、平均/中位/P90 延迟、各国家/端口存活数）
- `data/valid/history.jsonl` 每次验证的历史记录（最多 1000 条，用于趋势图）

### 更新差异

每次更新对比上一版（`git show HEAD:data/all.txt`）生成差异：

- `data/diff/latest.json` 最近一次 `added`/`removed` 列表
- `data/diff/<时间戳>.json` 有变化时按次归档，最多保留最近 500 份
- `data/history.jsonl` 每条记录含 `added`/`removed` 计数

### 统计与趋势

`scripts/generate_stats.py` 读取历史生成 `data/stats.json`（唯一数/存活数/延迟/更新时间/各集合数）和 `data/chart.svg`（无第三方依赖的 SVG 折线图，unique 与 alive 随时间变化）。

每个集合另有限量版 `data/sets/<集合>_ltd.txt`，每国最多取前 `--per-country-limit` 条（默认 20）；全量汇总另有 `data/all_ltd.txt`（全部国家每国限量后的并集）。`--per-country-limit 0` 时不生成限量文件。例：`python scripts/download_proxies.py --per-country-limit 20`。

### 运行方式

```bash
python scripts/download_proxies.py
python scripts/download_proxies.py --help
```

### CI 自动更新

`.github/workflows/update-proxies.yml` 每 30 分钟自动运行一次（也可手动触发 `workflow_dispatch`）。有变更时自动提交并推送回仓库。

## 浏览器指纹生成

生成内部自洽的浏览器指纹：UA、平台、分辨率、时区、语言、WebGL 渲染器、canvas 哈希等属性均来自同一操作系统/设备配置。

```bash
python scripts/generate_fingerprint.py
python scripts/generate_fingerprint.py -n 5
python scripts/generate_fingerprint.py -n 1 -s 42 --pretty
```

示例输出：

```json
{"os": "macos", "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...", "platform": "MacIntel", "language": "en-US", "languages": ["en-US", "en"], "timezone": "Europe/Paris", "screen": {"width": 2560, "height": 1440, "colorDepth": 24, "devicePixelRatio": 2.0}, "hardwareConcurrency": 10, "deviceMemory": 16, "webgl": {"renderer": "ANGLE (Apple, Apple M1, OpenGL 4.1)", "vendor": "Apple"}, "canvasHash": "9f3b2c1d4e5a6b7c"}
```

## 目录结构

```
.github/workflows/update-proxies.yml   CI 自动更新（下载、验证、统计）
scripts/download_proxies.py            下载与解压
scripts/validate_proxies.py            可用性验证与测速
scripts/generate_stats.py              统计与趋势图
scripts/generate_fingerprint.py        浏览器指纹生成
data/raw/<port>/<country>.txt          按端口+国家的原始组织（ip:port#国家）
data/countries/<country>.txt           按国家汇总（跨端口去重）
data/ports/<port>.txt                  按端口汇总（跨国家去重）
data/sets/<集合>.txt                   常用国家集合（europe、asia、hot、cn_common 等）
data/sets/<集合>_ltd.txt               限量版（每国 --per-country-limit 条）
data/all.txt                           全量去重 ip:port#国家
data/all_ltd.txt                       全部国家每国限量后的并集
data/valid/                            存活代理（结构同 data/，含 meta.json、history.jsonl）
data/diff/latest.json                  最近一次更新差异（added/removed）
data/diff/<时间戳>.json                按次归档的差异（最多 500 份）
data/stats.json                        统计汇总（供徽章与外部消费）
data/chart.svg                         趋势折线图
data/history.jsonl                     更新历史记录（每行一条，最多 1000 条）
```
