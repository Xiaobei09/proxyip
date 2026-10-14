#!/usr/bin/env bash
# 私有源泄露扫描（公开契约版）。
#
# 用法：
#   PRIVATE_SOURCE_IDENTIFIER_PATTERN='<regex>' bash .github/scripts/leak_scan.sh
#
# 无法在公开树 hard-code 真名/URL/凭证或其模式；模式只能由环境变量注入
#（CI secrets 或维护者本地 .env，后二者均被 .gitignore）。
# 返回 0 = 无命中；返回 1 = 发现潜在泄露（需立即脱敏/回滚）。
set -uo pipefail

pattern="${PRIVATE_SOURCE_IDENTIFIER_PATTERN:-}"
if [ -z "$pattern" ]; then
    echo "::warning::PRIVATE_SOURCE_IDENTIFIER_PATTERN 未配置——仅做公开仓 known-secret 兜底检查"
    pattern='(BUNDLE_PAT|ABUSEIPDB_KEY|IPQS_KEY|CHINA_CHECK_API_KEY|TCPPING_CN_TOKEN)'
fi

matches=""
while IFS= read -r -d '' f; do
    case "$f" in
        data/raw/*|data/diff/*|./.opencode/*) continue ;;
    esac
    out=$(grep -HnE "$pattern" "$f" 2>/dev/null || true)
    [ -n "$out" ] && matches="${matches}${out}"$'\n'
done < <(find . -type f -not -path './.git/*' -print0)
if [ -n "$matches" ]; then
    printf '%s\n' "$matches" | sed -n '1,50p' >&2
    exit 1
fi
echo "Leak scan clean."
