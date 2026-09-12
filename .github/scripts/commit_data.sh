#!/usr/bin/env bash
# 只提交本 job 实际写入的 data 文件；push 冲突时对齐 origin，不回滚他人更新。
#
# 背景（lost-update 修复）：此前各工作流 `git add -Af data/` 全量快照提交，
# 基于 checkout 时刻的工作树。当 job 运行期间其他工作流推送了新数据
# （如 china.json），本 job 的重试路径 `reset --mixed origin/main +
# add -Af` 会用陈旧副本覆盖他人更新——曾把 07:52 的 china.json 回退到
# 05:40 版本，导致 streak 连续计数清零、all_cn_stable.txt 近乎清空。
#
# 用法：
#   前置：checkout 后立即 `touch .jobstart`（早于任何脚本写盘）
#   提交：bash .github/scripts/commit_data.sh "<commit message>"
set -uo pipefail
MSG="${1:?usage: commit_data.sh <message>}"
MARKER=".jobstart"
EXCL='^(data/raw/|data/diff/)'

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

CHANGED=$(find data -type f -newer "$MARKER" 2>/dev/null | grep -Ev "$EXCL" | sort -u)

# 删除产物：checkout 基线（job 起点 HEAD）里存在、现工作树已消失的 data 文件。
# ``find -newer`` 只对现存文件按 mtime 判断，被 pipeline（validate/quality/
# annotate 的 unlink/rmtree 清理）删掉的文件没有 mtime，若不单列，删除永远
# 进不了提交——countries/sets/ports 越界视图与 rep/verified 残留会一直留在
# 发布树（曾累计 609 行死代残留）。注意按路径排除 raw/diff 归档。
WORKTREE_REF=$(git rev-parse HEAD)
DELETED=$(
  git ls-tree -r --name-only "$WORKTREE_REF" -- data/ 2>/dev/null \
    | grep -Ev "$EXCL" \
    | while IFS= read -r f; do [ ! -e "$f" ] && printf '%s\n' "$f"; done
)
PRODUCED=$(
  { printf '%s\n' "$CHANGED"; printf '%s\n' "$DELETED"; } | sed '/^$/d' | sort -u
)
if [ -z "$CHANGED" ] && [ -z "$DELETED" ]; then
  echo "No job-produced changes under data/"
  exit 0
fi

align_foreign() {
  # 工作树中非本产出的漂移文件对齐 index(=origin/main)，防回滚他人提交。
  # 本 job 的删除也属于产出，豁免恢复，否则删除会被 checkout -f 救回。
  # （reset --mixed 后 index=origin，diff 列出的 = 本产出 ∪ 陈旧外来文件）
  git diff --name-only -- data/ 2>/dev/null | grep -Ev "$EXCL" | sort \
    | comm -23 - <(printf '%s\n' "$PRODUCED") \
    | while IFS= read -r f; do
        git checkout -f -- "$f" 2>/dev/null || rm -f "$f"
      done
}

for attempt in 1 2 3 4 5; do
  git fetch origin main || { sleep 5; continue; }
  git reset -q --mixed origin/main || { echo "git reset failed" >&2; exit 1; }
  align_foreign
  # shellcheck disable=SC2086
  git add -Af -- $CHANGED || { echo "git add failed" >&2; exit 1; }
  # 暂存本 job 的删除：仅取 reset 后 index(=origin/main) 中仍存在的路径，
  # 避免 pathspec 不匹配（他人已同步删除时自然 no-op）。
  STAGE_DEL=$(
    printf '%s\n' "$DELETED" | sed '/^$/d' \
      | while IFS= read -r f; do git cat-file -e ":$f" 2>/dev/null && printf '%s\n' "$f"; done
  )
  if [ -n "$STAGE_DEL" ]; then
    # shellcheck disable=SC2086
    git add -Af -- $STAGE_DEL || { echo "git add deleted failed" >&2; exit 1; }
  fi
  if git diff --cached --quiet; then
    echo "Nothing to commit"
    exit 0
  fi
  git commit -q -m "$MSG" || { echo "git commit failed" >&2; exit 1; }
  if git push; then
    echo "Pushed on attempt $attempt"
    exit 0
  fi
  echo "Push attempt $attempt failed; syncing origin and retrying..."
  sleep 5
done
echo "Push failed after 5 attempts"
exit 1
