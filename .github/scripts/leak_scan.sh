#!/usr/bin/env bash
# Source-identifier leak scan (public contract form).
#
# Usage:
#   SOURCE_IDENTIFIER_PATTERN='<regex>' bash .github/scripts/leak_scan.sh
#
# Identifiers and their patterns are NEVER hard-coded in the public tree. The
# pattern must be injected from the environment (CI secret or a maintainer's
# local, git-ignored dotenv file). Without it we cannot know what to look for,
# so we fail closed instead of pretending to be clean.
#
# Exit 0 = no match; exit 1 = potential leak found (scrub + roll back now).
set -uo pipefail

pattern="${SOURCE_IDENTIFIER_PATTERN:-}"
if [ -z "$pattern" ]; then
    echo "::error::SOURCE_IDENTIFIER_PATTERN is not set; refusing a vacuous scan." >&2
    exit 2
fi

matches=""
while IFS= read -r -d '' f; do
    # 跳过集合必须与**权威门禁** ``tools/tests_pipeline/test_checks_bundle.py``
    # 的 ``_SKIP_DIRS = {"tools", ".opencode", ".git"}`` **逐条一致**：那里是
    # 真名/端点/salt 扫描面的判据，本脚本只是同一契约的手动形态。
    #
    # 注意 ``find .`` 产出的路径带 ``./`` 前缀；``data/`` 本来就在扫描面内，
    # 只有工具目录（公开 ``.gitignore`` 已忽略）需要显式跳过，否则会把
    # 工具目录一并扫进来（误报/越界）。
    case "$f" in
        ./tools/*|./.opencode/*|./.git/*) continue ;;
    esac
    out=$(grep -HnE "$pattern" "$f" 2>/dev/null || true)
    [ -n "$out" ] && matches="${matches}${out}"$'\n'
done < <(find . -type f -not -path './.git/*' -print0)
if [ -n "$matches" ]; then
    printf '%s\n' "$matches" | sed -n '1,50p' >&2
    exit 1
fi
echo "Leak scan clean."
