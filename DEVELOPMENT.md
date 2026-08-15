# DEVELOPMENT.md — 开发指南

面向仓库代码与文档维护者的详细开发文档。数据流水线由 CI 全自动运行，本文重点说明：仓库结构、脚本与数据规范、本地开发闭环、以及**修改后必提交必推送**的标准流程。

配套规则文件：[AGENTS.md](./AGENTS.md)（简短硬性规则，AI 协作时每次必读）。

---

## 1. 项目概览

代理池：从上游 `all.json` 抓取代理（失败回退 zip）→ 多维度整理 → 验证存活/测速 → 流媒体解锁与出口 IP 质量检测 → 统计图表。全部使用 **Python 标准库**，零第三方依赖，由 GitHub Actions 工作流全自动维护数据。

### 数据流水线

```
download_proxies.py ──▶ validate_proxies.py ──▶ quality_check.py ──▶ generate_stats.py
        │                      │                      │                      │
    data/all.txt          data/valid/*.txt      data/valid/            data/stats.json
    data/countries/       data/valid/meta.json  ipinfo.json            chart*.svg
    data/ports/           data/valid/index.json streaming.json         data/badge.json
    data/sets/            data/valid/speed.json reputation.json
    data/diff/                                    all_rep.txt
    data/upstream_meta.json
```

| 阶段 | 脚本 | CI 触发器 | 说明 |
|---|---|---|---|
| 1 下载整理 | `scripts/download_proxies.py` | `update-proxies.yml` 每 30 分钟 | all.json（失败回退 zip）→ 按端口/国家/集合/全量去重 + 上游元数据落盘 |
| 2 验证测速 | `scripts/validate_proxies.py` | 同上 | CONNECT + TLS 双检、真实下载测速 |
| 3 质量检测 | `scripts/quality_check.py` | `quality-check.yml`（依赖阶段 1 成功） | 流媒体解锁、出口 IP 地理/类型、多源信誉分 |
| 4 统计图表 | `scripts/generate_stats.py` | 阶段 2/3 之后 | `stats.json` + 9 张 SVG 图 |

CI 提交说明：两个工作流都以 `github-actions[bot]` 身份 **`git add -f data/`** 提交数据并推送（绕过 `.gitignore` 对 `data/` 的排除）。提交信息形如 `chore(data): update proxy list (...)` 与 `chore(data): streaming & exit IP quality check (...)`。

---

## 2. 仓库结构

```
scripts/
  download_proxies.py    阶段 1：下载（all.json + zip 回退）、解压、整理、去重、差异归档、上游元数据
  validate_proxies.py    阶段 2：存活验证 + 测速（asyncio）
  quality_check.py       阶段 3：流媒体解锁 + 出口 IP 质量 + 多源信誉
  generate_stats.py      阶段 4：统计与 SVG 图表
  china_check.py         独立 CI：大陆连通性检测（CF 启发式 + check-host + xxapi + ping.pe）
  exit_family.py         独立 CI：实际出口家族检测与分离（tls trace + connect 双回显 + 上游交叉验证）
  generate_fingerprint.py 独立工具：内部自洽的浏览器指纹
tests/                   stdlib unittest（discover -s tests）
  test_download.py  test_validate.py  test_quality.py
  test_stats.py    test_fingerprint.py  test_china_check.py  test_exit_family.py
data/                    CI 托管（本地 .gitignore，勿手动提交）
.github/workflows/       update-proxies.yml / quality-check.yml / china-check.yml / exit-family.yml
README.md                用户文档（数据规范 + CLI 参考）
AGENTS.md                AI 协作硬性规则（必提交必推送）
DEVELOPMENT.md           本文
```

---

## 3. 本地环境

```bash
git clone https://github.com/Xiaobei09/proxyip.git
cd proxyip
python3 --version        # 需 3.11+
```

无依赖安装步骤。虚拟环境可选（`.venv/` 已被 `.gitignore` 排除）。

## 4. 测试与检查

```bash
python3 -m unittest discover -s tests          # 全部测试（当前 171 个，须全绿）
python3 -m unittest tests/test_quality.py      # 单文件
python3 -m py_compile scripts/*.py             # 语法检查
```

- 修改 `scripts/*.py` 后必须同步更新 `tests/`，新增用例覆盖新逻辑边界。
- 修改 CI 工作流或新增输出文件后，跑一遍完整测试套件确认无回归。

## 5. 脚本与 CLI 速查

```bash
python3 scripts/download_proxies.py            # 阶段 1（默认上游 all.json，失败回退 zip）
python3 scripts/validate_proxies.py            # 阶段 2（跑完为止，可加 --time-budget）
python3 scripts/quality_check.py --help        # 阶段 3（勿直接全量跑，会改 data/valid）
python3 scripts/china_check.py --dry-run       # 大陆连通性（先用 --dry-run 看计划）
python3 scripts/exit_family.py --dry-run       # 实际出口家族检测（先用 --dry-run 看计划）
python3 scripts/generate_stats.py              # 阶段 4
python3 scripts/generate_fingerprint.py -n 5   # 指纹工具
```

### exit_family.py 关键参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--source` | `data/valid/all.txt` | 输入清单（全量存活池） |
| `--limit` | 0 | 只检测前 N 条（0=全部） |
| `--workers` | 16 | 并发上限 |
| `--dry-run` | 关 | 只输出计划，不发请求不写盘 |

tls 方法走 CF trace（`cloudflare.com/cdn-cgi/trace` 回显 `ip=`），connect 方法走 `api.ipify.org`/`api6.ipify.org` 双回显。产出 `all_ipv4.txt`/`all_ipv6.txt`（双栈双入）、`exit_family.json`，并向 `all.txt`/`all_ltd.txt` 追加 `-V4`/`-V6`/`-DS`。若 `data/upstream_meta.json` 存在，逐条对照上游真实出口 `clientIp` 交叉验证（`exit_family.json` 补充 `upstream_client_ip`/`upstream_family`/`upstream_match`）。详见 README「实际出口家族检测」章节。

### china_check.py 关键参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--source` | `data/valid/all_rep.txt` | 输入清单（缺失回退 `all_ltd.txt`） |
| `--limit` | 250 | 按信誉降序采样条数 |
| `--pingpe-limit` | 40 | ping.pe 多节点复核条数（串行） |
| `--skip-pingpe` | 关 | 跳过 ping.pe（本地快速冒烟） |
| `--dry-run` | 关 | 只输出计划，不发请求不写盘 |

分层判定：L1 启发式 CF（零网络）→ L2 check-host.cc + xxapi.cn（并发实测）→ L3 ping.pe/tcpping.cn（多节点复核）。任一实测源成功即判可达；check-host 与 xxapi 均失败才判不可达；单源失败归 uncertain。key 走环境变量 `CHINA_CHECK_API_KEY`、`TCPPING_CN_TOKEN`。产出 `china.json`、`all_cn.txt` 并向 `all.txt`/`all_ltd.txt` 追加 `-CN`。详见 README「大陆连通性检测」章节。

### quality_check.py 关键参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--source` | `data/valid/all_ltd.txt` | 输入清单 |
| `--services` | 全部 | netflix disney youtube max prime openai |
| `--abuse-service` | none | 滥用分：abuseipdb / ipqs（key 走 Secrets） |
| `--reputation-provider` | multi | multi / netcoffee / ip-api / none |
| `--reputation-sources` | netcoffee,ncgy,ip-api,ipdata,torlist | multi 的启用源 |
| `--reputation-weights` | 内置权重表 | 形如 `netcoffee:40,ncgy:20` 覆盖 |
| `--time-budget` | 0 | 最大秒数，CI 用 1800 |

信誉多源加权合分见 README「多因子信誉分」章节与 `REPUTATION_WEIGHTS` 常量。

## 6. 标准开发闭环

> 铁律：**任何修改在推送前任务不算完成。** 即便改的是注释/文档，同样走完整闭环。

```bash
# 1) 改代码（scripts/、tests/、README.md、docs）
# 2) 本地验证
python3 -m unittest discover -s tests
python3 -m py_compile scripts/*.py

# 3) 检查改动范围，只暂存意图内文件
git status --short
git diff --stat

# 4) 提交（英文、祈使句、带类型前缀）
git add scripts/quality_check.py tests/test_quality.py README.md
git commit -m "feat(quality): multi-source weighted IP reputation"

# 5) 推送（先 rebase 再推，规避并发 data 提交）
git pull --rebase origin main
git push
```

### 冒烟验证（可选，改逻辑时推荐）

小样本放 `/tmp`，不污染仓库数据：

```bash
head -4 data/valid/all_ltd.txt > /tmp/opencode/smoke.txt
python3 scripts/quality_check.py --source /tmp/opencode/smoke.txt \
    --time-budget 120 --services netflix
```

跑完若 `data/` 有改动，**不要提交**：

```bash
git checkout -- data/
```

### push 被拒时

远程 CI 可能刚提交了 `data/`。按序处理：

```bash
git pull --rebase origin main && git push    # 最多重试 3 次
```

禁止：`force push`、`--amend` 已推送提交、`-i` 交互式 rebase。

## 7. 提交规范

| 前缀 | 用途 | 示例 |
|---|---|---|
| `feat` | 新功能 | `feat(quality): multi-source weighted IP reputation` |
| `fix` | 修复 | `fix(validate): TLS check timeout leak` |
| `refactor` | 重构 | `refactor: extract batch_sync helper` |
| `test` | 测试 | `test: cover ncgy lookup parsing` |
| `docs` | 文档 | `docs: dev workflow and AGENTS rules` |
| `chore` | 杂项/数据 | `chore(data): update proxy list (2026-08-15T12:00:00Z)` |

- 类型可选作用域：`chore(data)`、`feat(quality)`。
- 一个提交只放一组相关改动；代码与文档可同属一个功能提交。
- 数据提交只允许由 CI 生成（`github-actions[bot]`）。

## 8. 本地与 CI 的分工

| 事项 | 归属 |
|---|---|
| `data/` 任何文件的生成与提交 | CI（`git add -f data/`） |
| `scripts/`、`tests/`、`README.md`、`.github/workflows/` 改动 | 本地人工/AI，走完整闭环 |
| 新增信誉源 / 调整权重 / 改 CI 行为 | 本地 + 测试 + 冒烟，改完必提交推送 |

## 9. 常见问题排查

- **push 被拒**：远程有新 `chore(data)` 提交 → `git pull --rebase` 后重推。
- **CI「Commit changes」失败、日志满屏 `CONFLICT (content): Merge conflict in data/...`**：两个工作流并发提交 `data/`，`git pull --rebase` 撞冲突。两个 workflow 的提交步骤已内置容错：`git fetch origin main` + `git rebase --autostash -X theirs origin/main`（冲突时保留本 run 新生成的数据，data/ 每次全量重生成，后写者胜），失败则 `git rebase --abort` 后重试，最多 5 次。若仍失败，多为网络/上游问题，下个调度周期会自动重试。
- **误提交 `data/`**：`git rm --cached -r data/` 移出暂存（`data/` 已被 gitignore），仅提交代码文件。
- **测试不过**：确认没改 `data/` 输入；`quality_check.py` 的单元测试全部用 fake `urlopen`，不依赖网络。
- **本地冒烟把 data 弄脏**：`git checkout -- data/`。
- **权限问题（secrets 缺 key）**：CI 环境变量在 `.github/workflows/*.yml` 的 `env:` 配置；本地缺 key 时脚本自动降级（跳过滥用分/GetIPIntel）。

## 10. 改动清单（历史）

| 日期 | 提交 | 说明 |
|---|---|---|
| 2026-08-15 | `feat(quality): all.json upstream meta + exit family cross-check` | 下载主源升级为上游 `all.json`（zip 回退），逐 IP 元数据（真实出口 clientIp/ASN/地理/colo）落盘 `upstream_meta.json`；exit_family 对照上游交叉验证并记录 `upstream_match` |
| 2026-08-15 | `ci: conflict-tolerant data commit in workflows` | 修复两个工作流并发提交 `data/` 导致的 rebase 冲突失败；升级 checkout/setup-python 消除 Node 20 告警 |
| 2026-08-15 | `feat(quality): multi-source weighted IP reputation` | 多源加权信誉（netcoffee/ncgy/ip-api/ipdata/torlist + opt-in getipintel/ipapi_is） |
| 2026-08-13 | `feat(quality): streaming & exit IP quality check with dedicated CI` | 质量检测独立 CI 与数据产物 |
