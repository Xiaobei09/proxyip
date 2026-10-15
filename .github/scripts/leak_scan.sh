#!/usr/bin/env bash
# Private-source leak scan (public contract form).
#
# Usage:
#   PRIVATE_SOURCE_IDENTIFIER_PATTERN='<regex>' bash .github/scripts/leak_scan.sh
#
# The real names / URLs / credentials and their patterns are NEVER hard-coded in
# the public tree. The pattern must be injected from the environment (CI secret
# or a maintainer's local, git-ignored, dotenv file). Without it we cannot know
# what to look for, so we fail closed instead of pretending to be clean.
#
# Exit 0 = no match; exit 1 = potential leak found (scrub + roll back now).
set -uo pipefail

pattern="${PRIVATE_SOURCE_IDENTIFIER_PATTERN:-}"
if [ -z "$pattern" ]; then
    echo "::error::PRIVATE_SOURCE_IDENTIFIER_PATTERN is not set; refusing a vacuous scan." >&2
    exit 2
fi

matches=""
while IFS= read -r -d '' f; do
    # 跳过集合必须与**权威门禁** ``pcb/tests_pipeline/test_checks_bundle.py``
    # 的 ``_SKIP_DIRS = {"pcb", ".opencode", ".git"}`` **逐条一致**：那里是
    # 真名/端点/salt 扫描面的判据，本脚本只是同一契约的手动形态。
    #
    # R525：旧式 ``data/raw/*|data/diff/*`` 是**死模式**——``find .`` 产出的
    # 路径带 ``./`` 前缀，故这两条永不命中，``data/raw`` 实际一直被扫（且它
    # 本就该扫：权威门禁把 ``data/`` 纳入面内）。真正被漏掉的是 ``./pcb/*``：
    # ``pcb/`` 是本机内的私有嵌套版本库（公开 ``.gitignore`` 已忽略），
    # 权威门禁显式跳过它；旧式列表缺这一条，会把**私有树**一并扫进来（误报/越界）。
    # 故此处改为照抄 ``_SKIP_DIRS``。
    case "$f" in
        ./pcb/*|./.opencode/*|./.git/*) continue ;;
    esac
    out=$(grep -HnE "$pattern" "$f" 2>/dev/null || true)
    [ -n "$out" ] && matches="${matches}${out}"$'\n'
done < <(find . -type f -not -path './.git/*' -print0)
if [ -n "$matches" ]; then
    printf '%s\n' "$matches" | sed -n '1,50p' >&2
    exit 1
fi
echo "Leak scan clean."
