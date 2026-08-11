# proxyip

定期从 <https://zip.cm.edu.kg> 下载代理 IP 列表并通过 CI 自动解压、整理、提交回仓库；附带一个浏览器指纹生成工具。

## 数据

压缩包结构为 `<port>/<country>.txt`，每个文件内每行一个 IP。所有输出均采用 `ip:port#国家代号` 格式（如 `1.2.3.4:443#US`）。脚本会自动：

1. 下载 zip 归档
2. 解压并按 `data/raw/<port>/<country>.txt` 重新组织（含上游聚合文件 `ALL.txt` → `#ALL`）
3. 按国家汇总为 `data/countries/<country>.txt`（跨端口去重，不含 ALL）
4. 按端口汇总为 `data/ports/<port>.txt`（跨国家去重，不含 ALL 派生条目）
5. 按常用集合汇总为 `data/sets/<集合>.txt`（如 `europe`、`asia`、`north_america`、`south_america`、`oceania`、`africa`、`middle_east`、`hot`）
6. 去重合并为 `data/all.txt`（每行一个唯一 `ip:port#国家`）

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
.github/workflows/update-proxies.yml   CI 自动更新
scripts/download_proxies.py            下载与解压
scripts/generate_fingerprint.py        浏览器指纹生成
data/raw/<port>/<country>.txt          按端口+国家的原始组织（ip:port#国家）
data/countries/<country>.txt           按国家汇总（跨端口去重）
data/ports/<port>.txt                  按端口汇总（跨国家去重）
data/sets/<集合>.txt                   常用国家集合（如 europe、asia、hot）
data/all.txt                           全量去重 ip:port#国家
```
