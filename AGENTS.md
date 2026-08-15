# AGENTS.md — 协作开发规则

本文件约束本仓库内的所有改动。每次开始任务前先阅读本文，结束时必须完成提交并推送。

## 项目简介

代理池仓库：定时拉取代理 → 验证存活/测速 → 流媒体解锁与出口 IP 质量检测 → 生成统计图表。数据由 GitHub Actions 自动维护，代码与文档为人工/AI 维护。

## 硬性规则：改完必提交必推送

**任何修改完成后，未推送前任务不算完成。** 标准收尾流程（逐条执行）：

1. 运行测试：`python3 -m unittest discover -s tests`（须全绿）。
2. 语法检查：`python3 -m py_compile scripts/*.py`。
3. 检查改动范围：`git status --short` 与 `git diff --stat`。
   - 只暂存本次意图内的文件；**禁止提交 `data/`、`__pycache__/`、`.venv/`、`*.pyc`**。
   - 若本地运行脚本产生了 `data/` 改动，用 `git checkout -- data/` 还原（数据由 CI 负责提交）。
4. 提交：`git add <文件> && git commit`，信息遵循提交规范（见下）。
5. 推送：`git pull --rebase origin main && git push`。push 被拒（远程有新提交）时先 rebase 再重试，最多 3 次。

## 提交规范

- 类型前缀：`feat`（新功能）、`fix`（修复）、`refactor`（重构）、`test`（测试）、`docs`（文档）、`chore`（杂项/数据）。可选作用域：`chore(data)`、`feat(quality)`。
- 英文、简洁、祈使句，如 `feat(quality): multi-source weighted IP reputation`。
- 不要把多个无关改动塞进一个提交。

## 测试与检查

```bash
python3 -m unittest discover -s tests          # 全部测试（当前 97 个）
python3 -m py_compile scripts/*.py             # 语法检查
python3 scripts/quality_check.py --help        # 查看 CLI（勿直接全量跑，会改 data/）
```

## 不要做的事

- 不提交 `data/` 下的任何文件（CI 用 `git add -f data/` 管理）。
- 不提交密钥/令牌；滥用分 key 走 GitHub Secrets + 环境变量。
- 不 `force push`、不 `--amend` 已推送的提交、不 `-i` 交互式 rebase。
- 不擅自改 CI 工作流（`.github/workflows/*`）之外的功能行为而不跑测试。
- 不在 `scripts/` 引入第三方依赖（纯标准库约束）。

## 数据流水线（CI 自动运行，本地不必手动）

`update-proxies.yml`（每 30 分钟）→ `quality-check.yml`（依赖前者成功）→ 二者均自动提交 `data/` 并推送。本地开发时以测试 + 小样本冒烟验证逻辑，样本放 `/tmp`，勿污染 `data/valid/all_ltd.txt`。
