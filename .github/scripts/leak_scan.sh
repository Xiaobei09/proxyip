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
    case "$f" in
        data/raw/*|data/diff/*|./.opencode/*|./.git/*) continue ;;
    esac
    out=$(grep -HnE "$pattern" "$f" 2>/dev/null || true)
    [ -n "$out" ] && matches="${matches}${out}"$'\n'
done < <(find . -type f -not -path './.git/*' -print0)
if [ -n "$matches" ]; then
    printf '%s\n' "$matches" | sed -n '1,50p' >&2
    exit 1
fi
echo "Leak scan clean."
