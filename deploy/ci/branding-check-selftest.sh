#!/usr/bin/env bash
# Self-test of branding-check.sh: it must fail on a sibling product name and on forbidden UI vocabulary,
# and pass on clean content.
set -Eeuo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

run() { BRANDING_ROOT="$work" bash "$here/branding-check.sh" "$work/src/Vaulty.Web" >/dev/null 2>&1; }

git -C "$work" init -q
mkdir -p "$work/src/Vaulty.Web"
printf '<p>Your mailboxes are protected.</p>\n<input @bind="HttpClient" />\n' >"$work/src/Vaulty.Web/Ok.razor"
printf 'A line about Vaulty.\n' >"$work/notes.txt"
run || { echo "selftest: clean content was rejected"; exit 1; }

sibling="Flee""to"
printf 'Copied from %s.\n' "$sibling" >"$work/notes.txt"
if run; then echo "selftest: a sibling product name was accepted"; exit 1; fi
printf 'A line about Vaulty.\n' >"$work/notes.txt"

for bad in '<p>Select a client</p>' '<p>Device list</p>' '<p>Choose a restore point</p>' \
    '<MudButton>Restore Teams messages</MudButton>'; do
    printf '%s\n' "$bad" >"$work/src/Vaulty.Web/Bad.razor"
    if run; then echo "selftest: accepted: $bad"; exit 1; fi
done
printf '<p>Teams messages can be viewed and exported, not restored.</p>\n' >"$work/src/Vaulty.Web/Bad.razor"
run || { echo "selftest: rejected the documented Teams limitation"; exit 1; }
echo "branding-check selftest: passed"
