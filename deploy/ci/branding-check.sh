#!/usr/bin/env bash
# Branding check, run in CI and before every release.
#
# 1. Sibling product names. Vaulty text, code and file names never mention another Steaan product. The only files that
#    may are the ones in ALLOWED_FILES (developer instructions and the branding scripts). Checked in every tracked and
#    untracked (not ignored) file.
# 2. The vocabulary of the web UI. User-visible text never says "client" (the term is "customer"), "device" or
#    "machine", "restore point" or "recovery point" (the term is "snapshot"), and never offers to "restore" Teams
#    messages (they are preserved and exported, not restored).
#    Scanned: Razor components, Razor pages and static HTML under src/Vaulty.Web (or the paths given as arguments).
#    Not counted as user-visible:
#      - Razor directives (@using, @inject, @namespace, @inherits, @implements, @attribute, @typeparam, @layout,
#        @rendermode, @page)
#      - Razor, HTML, C# block and C# line comments
#      - identifiers: the word glued to identifier characters or to . _ - / (ClientId, device-width, HttpClient)
#    A line can opt out with a trailing comment containing "branding-check: ignore" plus the reason.
#
# BRANDING_ROOT overrides the repository root (used by the self-test).
set -Eeuo pipefail

repo_root="${BRANDING_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
violations=0

# --- 1. Sibling product names ----------------------------------------------------------------------------------------
# Spelled in pieces so the pattern itself is not a match.
names_re="(Flee""to|Migra""vo|Tick""sy)"
ALLOWED_FILES=(
    "CLAUDE.md"
    "deploy/ci/branding-check.sh"
    "deploy/ci/branding-check-selftest.sh"
)

is_allowed_file() {
    local file="$1" pattern
    for pattern in "${ALLOWED_FILES[@]}"; do
        # shellcheck disable=SC2053 # the pattern is a glob on purpose
        [[ "$file" == $pattern ]] && return 0
    done
    return 1
}

cd "$repo_root"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    while IFS= read -r -d '' file; do
        [[ -f "$file" ]] || continue
        is_allowed_file "$file" && continue
        if [[ "$file" =~ $names_re ]]; then
            echo "$file: the file name mentions another product"
            violations=$((violations + 1))
        fi
        if matches="$(grep -InE "$names_re" -- "$file" 2>/dev/null)"; then
            while IFS= read -r line; do
                echo "$file:$line"
                violations=$((violations + 1))
            done <<<"$matches"
        fi
    done < <(git ls-files -z --cached --others --exclude-standard)
    if [[ "$violations" -gt 0 ]]; then
        echo "branding-check: another product is named above; Vaulty text and code only name Vaulty."
    fi
fi

# --- 2. UI vocabulary --------------------------------------------------------------------------------------------------
if [[ $# -gt 0 ]]; then
    paths=("$@")
else
    paths=("$repo_root/src/Vaulty.Web")
fi

files=()
existing=()
for p in "${paths[@]}"; do [[ -e "$p" ]] && existing+=("$p"); done
if [[ ${#existing[@]} -gt 0 ]]; then
    mapfile -d '' files < <(find "${existing[@]}" -type f \( -name '*.razor' -o -name '*.cshtml' -o -name '*.html' \) \
        -not -path '*/bin/*' -not -path '*/obj/*' -not -path '*/wwwroot/lib/*' -print0 2>/dev/null)
fi

if [[ ${#files[@]} -gt 0 ]]; then
    tmp="$(mktemp)"
    perl "$(dirname "${BASH_SOURCE[0]}")/branding-ui-vocabulary.pl" "${files[@]}" 2>"$tmp" || true
    ui="$(sed -n 's/^UI_VIOLATIONS=//p' "$tmp")"
    rm -f "$tmp"
    violations=$((violations + ${ui:-1}))
fi

if [[ "$violations" -gt 0 ]]; then
    echo ""
    echo "branding-check: $violations violation(s)."
    exit 1
fi
echo "branding-check: no violations."
