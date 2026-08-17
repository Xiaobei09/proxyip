# AGENTS.md — 协作开发规则

本文件约束本仓库内的所有改动。每次开始任务前先阅读本文，结束时必须完成提交并推送。

## 项目简介

代理池仓库：定时拉取代理 → 验证存活/测速 → 流媒体解锁与出口 IP 质量检测 → 生成统计图表。数据由 GitHub Actions 自动维护，代码与文档为人工/AI 维护。

## 环境要点（本沙箱，开工前先读）

- **git 元数据不在项目内**：真实 git 目录在 `/root/proxyip-git/.git`（f2fs 持久盘）；项目内 `./.git` 只是指针文件（内容 `gitdir: /root/proxyip-git/.git`）。日常 git 命令在项目内照常使用，提交身份 `Xiaobei09 <235415509+Xiaobei09@users.noreply.github.com>`。
- **不要把 git 目录移进项目文件夹**：`/root/projects/proxyip` 挂载于 fuseblk（FUSE），`linkat`（git 发布对象所需）被拒；跨目录 `mv`/`cp -a` 对象目录会因 L2S 绝对路径符号链接断链而损坏仓库。若 git 目录损坏，用 `git clone --no-checkout --separate-git-dir=/root/proxyip-git/.git <origin>` 原地重建（见 DEVELOPMENT.md 排查节）。
- **严禁删除对象库内的 `.l2s.*` 文件**：它们是 L2S 层后备，真实对象可能是指向它们的符号链接，误删会损坏对象（曾致 33 个对象丢失）。`git fsck` 偶尔报 `.l2s.*` 属无害噪音，忽略。

## 硬性规则：改完必提交必推送

**任何修改完成后，未推送前任务不算完成。** 标准收尾流程（逐条执行）：

1. 运行测试：`python3 -m unittest discover -s tests`（须全绿）。
2. 语法检查：`python3 -m py_compile scripts/*.py`。
3. 检查改动范围：`git status --short` 与 `git diff --stat`。
   - 只暂存本次意图内的文件；**禁止提交 `data/`、`__pycache__/`、`.venv/`、`*.pyc`**。
   - 若本地运行脚本产生了 `data/` 改动，用 `git checkout -- data/` 还原（数据由 CI 负责提交）。
4. 提交：`git add <文件> && git commit`，信息遵循提交规范（见下）。
5. 推送：`git pull --rebase origin main && git push`。push 被拒（远程有新提交）时先 rebase 再重试，最多 3 次。
6. **会话记录（固化步骤）**：向仓库外文件 `/root/proxyip-sessions.md` 追加本次会话的详细记录（完成事项/提交 hash/关键决策/教训，格式见该文件头部）。该文件在仓库外，**绝不提交**。

## 提交规范

- 类型前缀：`feat`（新功能）、`fix`（修复）、`refactor`（重构）、`test`（测试）、`docs`（文档）、`chore`（杂项/数据）。可选作用域：`chore(data)`、`feat(quality)`。
- 英文、简洁、祈使句，如 `feat(quality): multi-source weighted IP reputation`。
- 不要把多个无关改动塞进一个提交。

## 测试与检查

```bash
python3 -m unittest discover -s tests          # 全部测试（当前 298 个）
python3 -m py_compile scripts/*.py             # 语法检查
python3 scripts/quality_check.py --help        # 查看 CLI（勿直接全量跑，会改 data/）
python3 scripts/annotate_classify.py --help    # 后缀填充+分类 CLI
```

## 不要做的事

- 不提交 `data/` 下的任何文件（CI 用 `git add -f data/` 管理）。
- 不提交密钥/令牌；滥用分 key 走 GitHub Secrets + 环境变量。
- 不 `force push`、不 `--amend` 已推送的提交、不 `-i` 交互式 rebase。
- 不擅自改 CI 工作流（`.github/workflows/*`）之外的功能行为而不跑测试。
- 不在 `scripts/` 引入第三方依赖（纯标准库约束）。
- 不删除 git 对象库内的 `.l2s.*` 文件；不在对象目录上做跨盘 `mv`/`cp -a`。

## 数据流水线（CI 自动运行，本地不必手动）

```
update-proxies.yml (*/30m)  →  quality-check.yml (*/4h 或 workflow_run)
                                     ↓
china-check.yml (*/6h)  ←  data/valid/*.txt  →  exit-family.yml (*/6h)
                                     ↓
                            annotate-classify.yml (workflow_run after quality-check)
```

- `update-proxies.yml`：拉取代理 → 验证存活/测速 → 生成图表
- `quality-check.yml`：流媒体解锁 + 出口 IP 质量 + 信誉评分
- `china-check.yml`：大陆可达性检测
- `exit-family.yml`：出口 IPv4/IPv6 家族检测
- `annotate-classify.yml`：后缀填充（CN/V4/streaming/rep）+ 节点分类（IP类型/速度等级）

本地开发时以测试 + 小样本冒烟验证逻辑，样本放 `/tmp`，勿污染 `data/valid/all_ltd.txt`。
