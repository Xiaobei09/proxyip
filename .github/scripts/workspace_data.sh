#!/usr/bin/env bash
# 中间数据工作区同步：把 data/{quality,raw,download,diff} 放到只读工作区的
# data 分支，公开仓只保留用户可直接消费的 data/{valid,output}。
#
# 工作区分支内容用**真名**：工作区不对外，真名才是人能读的形态。运行脚本仍以
# 不透明 id 做跨轮 join，故 checkout 时把真名**密封**回 id（seal），commit 时
# 把 id **反解**成真名（unseal）。翻译由 tools/scripts/workspace_alias.py
# 完成：seal 只看真正的来自身份位置（避免把 US/proxy 这类撞名值误封），
# unseal 无上下文；两侧都归一到紧凑 JSON，保证空跑不产生 diff。
#
# 为什么是「快照分支」而不是普通提交链：quality/ 里的缓存单文件可达
# 60MB（reputation_cache.json），普通提交链每天会堆出 GB 级历史。本脚本
# 每次用**单提交快照**（孤儿提交 + force-with-lease）替换分支内容：树是
# 完整快照，历史不累积。并发安全靠「fetch 远端 → 重放本 job 改过的路径 →
# 再 push」实现，未改的文件保留远端最新版本。
#
# 用法：
#   bash .github/scripts/workspace_data.sh checkout
#   bash .github/scripts/workspace_data.sh commit "<commit message>"
#
# 环境：
#   TOOLS_TOKEN / TOOLS_PAT / GH_TOKEN  推送令牌（至少一个）
#   TOOLS_REPO                           工作区远端仓库 slug（二选一）
#   WORKSPACE_REMOTE                    显式远端 URL（测试/自托管用，优先于 TOOLS_REPO）
#   WORKSPACE_DIR                      可选，默认 $RUNNER_TEMP/data-workspace
#   DATA_BRANCH                        可选，默认 data
#
# checkout 会在公开仓 data/ 下建符号链接；脚本自身（tools/scripts/*）通过
# common.DATA_DIR 读写这些路径，因此无需改任何脚本的路径常量。
set -uo pipefail

REPO="${TOOLS_REPO:-}"
BRANCH="${DATA_BRANCH:-data}"
WORKSPACE="${WORKSPACE_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/data-workspace}"
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
DATA_DIR="$ROOT/data"
DIRS=(quality raw download diff)

log() { printf '%s\n' "$*"; }

token() {
  # 防 secrets 粘贴带入换行/空白：URL/头部里任何空白都会让认证失败
  # （actions/checkout 会 trim 输入，裸 bash 不会）。
  printf '%s' "${TOOLS_TOKEN:-${TOOLS_PAT:-${GH_TOKEN:-}}}" | tr -d '[:space:]'
}

remote_url() {
  # 测试/自托管可显式指定远端（本地 bare 仓等）；生产走 TOOLS_REPO。
  # commit 是独立 step、拿不到 TOOLS_REPO，故最后回落到 checkout 已写入
  # origin 的 URL（工作区自己的 config）。
  if [ -n "${WORKSPACE_REMOTE:-}" ]; then
    printf '%s' "$WORKSPACE_REMOTE"
  elif [ -n "$REPO" ]; then
    printf 'https://github.com/%s.git' "$REPO"
  elif git -C "$WORKSPACE" remote get-url origin >/dev/null 2>&1; then
    git -C "$WORKSPACE" remote get-url origin
  else
    log "::error::TOOLS_REPO 未设置且无 WORKSPACE_REMOTE；无法定位工作区远端" >&2
    return 1
  fi
}

git_workspace() {
  git -C "$WORKSPACE" "$@"
}

# 与 actions/checkout 相同的认证方式：Authorization: basic(x-access-token:TOKEN)
# 通过 http.extraheader 注入，而不是把令牌嵌进 URL——后者在令牌含 URL 特殊
# 字符/空白时会被 GitHub 当成未认证（实测 TOOLS_PAT 报 404 Repository not
# found，而同一令牌的 actions/checkout 正常）。
#
# 写进**工作区自己的** .git/config，而不是每次调用临时 `-c`：checkout 与
# commit 是两个独立的 step/进程，commit step 并没有 `TOOLS_TOKEN`（secrets
# 不会自动跨 step 继承）。实测缺这一步时 push 会退化成交互式用户名提示并
# 失败（fatal: could not read Username），工作区 data 分支永远建不起来。
# 位置与 actions/checkout 的 persist-credentials 相同：只在 runner 临时目录
# 里的工作区 config，不碰公开仓，也不进任何提交。
configure_auth() {
  local t
  t="$(token)"
  [ -n "$t" ] || return 0
  git -C "$WORKSPACE" config \
    "http.https://github.com/.extraheader" \
    "AUTHORIZATION: basic $(printf 'x-access-token:%s' "$t" | base64 | tr -d '\n')"
}

# 真名 <-> id 翻译器位于工具目录。公开工作树可能根在仓库内，也可能像
# ip-cards 那样在 ./public 子检出里，故同时找 ./tools 与 ../tools。
find_alias() {
  local cand
  for cand in "${ALIAS_SCRIPT:-}" \
              "$ROOT/tools/scripts/workspace_alias.py" \
              "$ROOT/../tools/scripts/workspace_alias.py"; do
    [ -n "$cand" ] && [ -f "$cand" ] && { printf '%s' "$cand"; return 0; }
  done
  return 1
}

run_alias() {
  local action="$1" script
  if ! script="$(find_alias)"; then
    log "workspace_alias.py 不可得；跳过 $action（分支保持当前表示）"
    return 0
  fi
  python3 "$script" "$action" --data-root "$WORKSPACE"
}

init_repo() {
  local url
  if ! url="$(remote_url)"; then
    return 1
  fi
  if [ -d "$WORKSPACE/.git" ]; then
    git_workspace remote set-url origin "$url"
  else
    mkdir -p "$(dirname "$WORKSPACE")"
    git init -q -b "$BRANCH" "$WORKSPACE"
    git_workspace remote add origin "$url"
  fi
  # 令牌持久化到工作区 config，供后续 commit step 复用（它拿不到 secrets）。
  configure_auth
  git_workspace config user.name "github-actions[bot]"
  git_workspace config user.email "41898282+github-actions[bot]@users.noreply.github.com"
}

# 远端分支存在性：0=存在，2=不存在，其它=网络/鉴权错误。
# 不用 ``--exit-code``：它在部分环境/令牌下把「无匹配 ref」报成普通失败，
# 无法区分「分支尚未创建」与「令牌不可用」。改为看输出是否为空，并把
# stderr 脱敏后回显，避免 URL 里的 token 泄漏。
remote_state() {
  local t err rc out url
  if ! url="$(remote_url)"; then
    return 1
  fi
  t="$(token)"
  err="$(mktemp)"
  # 必须在工作区（-C）里跑：公开检出被 actions/checkout 持久化了
  # ``http.https://github.com/.extraheader``，在它里面直接 ls-remote 会让
  # 我们的 header 与它叠加成 "Duplicate header: Authorization"（400）。
  out="$(git_workspace ls-remote --heads "$url" \
    "refs/heads/$BRANCH" 2>"$err")"
  rc=$?
  if [ -n "$t" ]; then
    local line
    while IFS= read -r line; do
      printf '%s\n' "${line//"$t"/***}"
    done < "$err" > "$err.clean"
    mv "$err.clean" "$err"
  fi
  if [ "$rc" -eq 0 ]; then
    rm -f "$err"
    [ -n "$out" ] && return 0
    return 2
  fi
  # 不转发 git 的原始 stderr：远端 URL 带 token，错误行可能回显它。
  log "::error::无法访问工作区 data 分支（rc=$rc，网络或令牌问题）" >&2
  if [ -s "$err" ]; then
    log "$(cat "$err")" >&2
  fi
  rm -f "$err"
  return 1
}

china_base_path() {
  printf '%s/.git/china-base' "$WORKSPACE"
}

record_china_base() {
  # R909 同类保护：记录本 job 起点的 china.json blob，提交时若远端已前进
  # 则拒绝用本 job 的旧证据覆盖（与 commit_data.sh 的公开侧守卫对齐）。
  local blob
  blob="$(git_workspace rev-parse "FETCH_HEAD:quality/china.json" 2>/dev/null || true)"
  printf '%s' "$blob" > "$(china_base_path)"
}

checkout() {
  init_repo || return 1
  local state
  remote_state
  state=$?
  if [ "$state" -eq 1 ]; then
    log "::error::无法访问工作区 data 分支（网络或令牌问题）" >&2
    return 1
  fi
  if [ "$state" -eq 0 ]; then
    local ok=0 i
    for i in 1 2 3 4 5; do
      if git_workspace fetch -q --depth=1 origin "$BRANCH"; then
        git_workspace reset -q --hard FETCH_HEAD
        git_workspace clean -q -fdx
        record_china_base
        ok=1
        break
      fi
      sleep 5
    done
    if [ "$ok" -ne 1 ]; then
      log "::error::工作区 data 分支 fetch 连续失败（$i 次）" >&2
      return 1
    fi
  else
    log "工作区 $BRANCH 分支尚不存在，按空数据初始化（首次迁移由种子提交完成）"
    git_workspace update-ref -d "refs/heads/$BRANCH" 2>/dev/null || true
    printf '' > "$(china_base_path)"
  fi

  local d link
  mkdir -p "$DATA_DIR"
  for d in "${DIRS[@]}"; do
    mkdir -p "$WORKSPACE/$d"
    link="$DATA_DIR/$d"
    if [ -e "$link" ] && [ ! -L "$link" ]; then
      # 迁移期/本地旧检出可能仍有真实目录：若工作区为空则先收养，避免
      # 第一次切换时把本地数据删掉。工作区已有内容时以分支为准。
      if [ -z "$(ls -A "$WORKSPACE/$d" 2>/dev/null)" ]; then
        cp -a "$link/." "$WORKSPACE/$d/" 2>/dev/null || true
        log "adopted existing data/$d into workspace"
      fi
      rm -rf "$link"
    fi
    ln -sfn "$WORKSPACE/$d" "$link"
  done

  # 分支存真名，运行脚本要 id：checkout 后立刻 seal。若翻译器存在却失败，
  # 说明插件不可用——继续跑会让脚本拿到真名、破坏跨文件 join，
  # 故这一步是硬失败（而不是像旧 names/ 视图那样只告警）。
  if ! run_alias seal; then
    log "::error::workspace data seal 失败；拒绝以真名运行脚本" >&2
    return 1
  fi

  # 标记「本工作区已挂载中间数据」。commit_data.sh 只在此标记存在时才切换
  # 到工作区模式——否则单测在临时 git 仓里跑 commit_data.sh 时，会误把
  # RUNNER_TEMP 下真实工作区当成自己的（并破坏测试对 data/quality 的
  # 旧行为预期）。
  printf '%s\n' "$WORKSPACE" > "$ROOT/.data-workspace"
  log "workspace data ready: $WORKSPACE"
}

# 跳过官方 checkout 的 pathspec 风险：只把本 job **实际改过**的路径重放到
# 远端最新树之上。未改的路径取远端版本，因此并发 job 的更新不会互相覆盖。
commit() {
  local msg="${1:?usage: workspace_data.sh commit <message>}"
  if [ ! -d "$WORKSPACE/.git" ]; then
    log "workspace data absent; skip"
    return 0
  fi
  # 正常情况下 config 里的令牌由 checkout 写入；此调用兜住「同一 step 内
  # 直接 commit」的用法（step 自己带了 TOOLS_TOKEN 时）。
  configure_auth

  # 运行期写的是 id；推上前先反解成真名（分支的唯一表示）。unseal 失败只
  # 告警、继续提交：宁可先落一份 id 形态的数据，也不能丢掉本轮产出；下一轮
  # checkout/commit 会把它重新归一。
  if ! run_alias unseal; then
    log "::warning::workspace data unseal 失败；本轮将以不透明 id 提交" >&2
  fi

  git_workspace add -A
  if git_workspace diff --cached --quiet; then
    log "No workspace data changes"
    return 0
  fi

  # 保存本 job 的改动（内容 + 删除列表）。用 tar 复制，保留子目录结构。
  local save
  save="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$save'" RETURN
  git_workspace diff --cached --name-only -z > "$save/paths.z"
  while IFS= read -r -d '' rel; do
    if [ -e "$WORKSPACE/$rel" ]; then
      mkdir -p "$save/tree/$(dirname "$rel")"
      cp -a "$WORKSPACE/$rel" "$save/tree/$rel"
    else
      printf '%s\0' "$rel" >> "$save/deleted.z"
    fi
  done < "$save/paths.z"
  # 只有本 job 确实改动过 china.json（内容或删除）时才需要 R909 守卫；
  # 否则远端前进与本次提交无关，不应产生误导性的拒绝告警。
  local china_touched=0
  if [ -f "$save/tree/quality/china.json" ]; then
    china_touched=1
  elif [ -f "$save/deleted.z" ] \
      && tr '\0' '\n' < "$save/deleted.z" | grep -qxF 'quality/china.json'; then
    china_touched=1
  fi

  local attempts old_sha commit_sha tree base_china
  base_china="$(cat "$(china_base_path)" 2>/dev/null || true)"
  for attempts in 1 2 3 4 5; do
    local state
    remote_state
    state=$?
    if [ "$state" -eq 1 ]; then
      log "::error::无法访问工作区 data 分支（网络或令牌问题）" >&2
      return 1
    fi
    old_sha=""
    if [ "$state" -eq 0 ]; then
      if ! git_workspace fetch -q --depth=1 origin "$BRANCH"; then
        sleep 5
        continue
      fi
      old_sha="$(git_workspace rev-parse FETCH_HEAD)"
      git_workspace reset -q --hard FETCH_HEAD
    else
      git_workspace update-ref -d "refs/heads/$BRANCH" 2>/dev/null || true
      git_workspace read-tree --empty
    fi

    # R909 同类保护：china.json 是全体发布视图的证据基座。若远端在本 job
    # 起点之后已更新它，放弃本 job 的旧证据，绝不回滚已发布的新证据。
    local remote_china=""
    if [ "$state" -eq 0 ]; then
      remote_china="$(git_workspace rev-parse "FETCH_HEAD:quality/china.json" 2>/dev/null || true)"
    fi
    if [ "$state" -eq 0 ] && [ "$china_touched" = 1 ] \
        && [ "$remote_china" != "$base_china" ]; then
      if [ -f "$save/tree/quality/china.json" ]; then
        rm -f "$save/tree/quality/china.json"
      fi
      if [ -f "$save/deleted.z" ]; then
        : > "$save/deleted.filtered.z"
        while IFS= read -r -d '' rel; do
          [ "$rel" = "quality/china.json" ] \
            || printf '%s\0' "$rel" >> "$save/deleted.filtered.z"
        done < "$save/deleted.z"
        mv "$save/deleted.filtered.z" "$save/deleted.z"
      fi
      log "::warning::refusing stale quality/china.json overwrite: remote advanced after this job's base snapshot"
    fi

    # 重放本 job 改动到远端最新树。
    if [ -d "$save/tree" ]; then
      (cd "$save/tree" && tar cf - .) | (cd "$WORKSPACE" && tar xf -)
    fi
    if [ -f "$save/deleted.z" ]; then
      while IFS= read -r -d '' rel; do
        rm -f "$WORKSPACE/$rel"
      done < "$save/deleted.z"
    fi
    git_workspace add -A
    if git_workspace diff --cached --quiet; then
      log "Nothing to commit after merging remote"
      return 0
    fi
    tree="$(git_workspace write-tree)"
    commit_sha="$(printf '%s\n' "$msg" | git_workspace commit-tree "$tree")"
    git_workspace update-ref "refs/heads/$BRANCH" "$commit_sha"
    if [ -n "$old_sha" ]; then
      if git_workspace push -q --force-with-lease="$BRANCH:$old_sha" \
          origin "$commit_sha:refs/heads/$BRANCH"; then
        log "Pushed workspace data snapshot on attempt $attempts"
        return 0
      fi
    else
      if git_workspace push -q origin "$commit_sha:refs/heads/$BRANCH"; then
        log "Created workspace data branch on attempt $attempts"
        return 0
      fi
    fi
    log "workspace data push attempt $attempts failed; refetching and retrying..."
    sleep 5
  done
  log "::error::workspace data push failed after 5 attempts" >&2
  return 1
}

cmd="${1:-}"
case "$cmd" in
  checkout) checkout ;;
  commit) shift; commit "${1:-}" ;;
  *) echo "usage: $0 {checkout|commit <message>}" >&2; exit 2 ;;
esac
