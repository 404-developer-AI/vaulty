#!/usr/bin/env bash
# Vaulty confidentiality scanner.
#
# Blocks confidential material (secrets, internal docs, customer identifiers,
# commercial or strategic information) from reaching a public repository.
#
# Usage:
#   confidentiality-scan.sh --staged                 scan the staged changes (pre-commit)
#   confidentiality-scan.sh --range <from> <to>      scan commits from..to (pre-push, CI)
#
# Environment:
#   VAULTY_CONFIDENTIAL_TERMS   path to the confidential terms list
#                               (default: ~/.config/vaulty/confidential-terms.txt)
#   VAULTY_SCAN_STRICT=1        fail when the terms list or gitleaks is missing
#                               (used for pushes to a public remote and in CI)
#   VAULTY_SCAN_PUBLIC=1        treat the target as the public repository: block
#                               internal-only paths such as MD-DOCS/ (defaults to
#                               the value of VAULTY_SCAN_STRICT). Set to 0 in the
#                               private repository (vaulty-internal).
#   VAULTY_SCAN_QUIET_TERMS=1   report only file:line for term matches, never the
#                               term itself (used in CI where logs are public)
#
# Exit codes: 0 clean, 1 findings, 2 usage or configuration error.
#
# The terms list is NOT part of this repository on purpose: it is confidential
# itself. It lives in the private repository and is copied locally by each
# developer (see .githooks/install.sh) or injected from a secret in CI.

set -u

EMPTY_TREE="4b825dc642cb6eb9a060e54bf8d69288fbee4904"
TERMS_FILE="${VAULTY_CONFIDENTIAL_TERMS:-$HOME/.config/vaulty/confidential-terms.txt}"
STRICT="${VAULTY_SCAN_STRICT:-0}"
QUIET_TERMS="${VAULTY_SCAN_QUIET_TERMS:-0}"

findings=0
warnings=0

say()  { printf '%s\n' "$*" >&2; }
fail() { findings=$((findings + 1)); say "  BLOCK  $*"; }
warn() { warnings=$((warnings + 1)); say "  WARN   $*"; }

# ---------------------------------------------------------------------------
# Collect files, added lines and commit messages for the requested scope
# ---------------------------------------------------------------------------
# In the private repository the terms list itself is not scanned for its own terms.
CONTENT_PATHSPEC="."
if [ "$(git config --get vaulty.repo 2>/dev/null || echo public)" = "internal" ]; then CONTENT_PATHSPEC=":(exclude)confidential-terms.txt"; fi

MODE="${1:-}"
case "$MODE" in
  --staged)
    FILES=$(git diff --cached --name-only --diff-filter=ACMR)
    ADDED=$(git diff --cached --unified=0 --diff-filter=ACMR -- "$CONTENT_PATHSPEC" | grep -E '^\+' | grep -Ev '^\+\+\+' || true)
    MESSAGES=""
    SCOPE="staged changes"
    ;;
  --range)
    FROM="${2:-}"; TO="${3:-}"
    if [ -z "$FROM" ] || [ -z "$TO" ]; then say "usage: $0 --range <from> <to>"; exit 2; fi
    case "$FROM" in
      ""|0000000000000000000000000000000000000000) FROM="$EMPTY_TREE" ;;
    esac
    FILES=$(git diff --name-only --diff-filter=ACMR "$FROM" "$TO")
    ADDED=$(git diff --unified=0 --diff-filter=ACMR "$FROM" "$TO" -- "$CONTENT_PATHSPEC" | grep -E '^\+' | grep -Ev '^\+\+\+' || true)
    if [ "$FROM" = "$EMPTY_TREE" ]; then
      MESSAGES=$(git log --format='%H %s%n%b' "$TO")
    else
      MESSAGES=$(git log --format='%H %s%n%b' "$FROM..$TO")
    fi
    SCOPE="$FROM..$TO"
    ;;
  *)
    say "usage: $0 --staged | --range <from> <to>"; exit 2 ;;
esac

say "confidentiality scan: $SCOPE"

# ---------------------------------------------------------------------------
# 1. Paths and file types
#    always_blocked_path: never in ANY repository, public or private (secrets,
#                         local-only notes such as NOTFORCLAUDE.MD)
#    public_blocked_path: never in the PUBLIC repository (internal docs, infra,
#                         office documents); allowed in vaulty-internal
# ---------------------------------------------------------------------------
PUBLIC_MODE="${VAULTY_SCAN_PUBLIC:-$STRICT}"   # strict implies public unless overridden
# `git config vaulty.repo internal` marks a clone of the private repository: internal-only
# paths are then silently allowed (they still get blocked when pushing to a public remote).
REPO_KIND="$(git config --get vaulty.repo 2>/dev/null || echo public)"

always_blocked_path() {
  case "$1" in
    NOTFORCLAUDE.MD|NOTFORCLAUDE.md|notforclaude.md|*/NOTFORCLAUDE.MD|*/NOTFORCLAUDE.md|*/notforclaude.md) return 0 ;;
    *.local.md|*.private.md) return 0 ;;
    *.pfx|*.p12|*.pem|*.key|*.jks|*.keystore|*.asc|*.gpg) return 0 ;;
    .env|.env.*|*/.env|*/.env.*) case "$1" in *.env.example) return 1 ;; esac; return 0 ;;
    *appsettings.Production.json|*appsettings.Staging.json|*.secrets.json|*secrets.yaml|*secrets.yml) return 0 ;;
    *.tfstate|*.tfstate.*|*.tfvars) return 0 ;;
    *.sql.gz|*.dump|*.bak|*.rdb|*.ldf|*.mdf|*.pst|*.ost) return 0 ;;
  esac
  return 1
}

public_blocked_path() {
  case "$1" in
    MD-DOCS/*|*/MD-DOCS/*|docs/internal/*|deploy/iac/*|deploy/prod/*|deploy/production/*) return 0 ;;
    *.sops.yaml|*.sops.yml|*.sops.json|inventory|inventory.*|*/inventory/*) return 0 ;;
    *.xlsx|*.xls|*.docx|*.doc|*.pptx|*.ppt|*.pdf|*.eml|*.msg|*.one) return 0 ;;
  esac
  return 1
}

while IFS= read -r f; do
  [ -z "$f" ] && continue
  if always_blocked_path "$f"; then
    fail "path never allowed in any repository: $f"
  elif public_blocked_path "$f"; then
    if [ "$PUBLIC_MODE" = "1" ]; then
      fail "path not allowed in public repository: $f"
    elif [ "$REPO_KIND" != "internal" ]; then
      warn "path is internal-only, it will be refused on push to the public remote: $f"
    fi
  fi
  case "$f" in
    *.png|*.jpg|*.jpeg|*.gif|*.webp|*.mp4|*.mov)
      case "$f" in assets/brand/*|src/Vaulty.Web/wwwroot/*) ;; *) warn "image or video outside brand assets, check for real data: $f" ;; esac ;;
  esac
done <<EOF_FILES
$FILES
EOF_FILES

# ---------------------------------------------------------------------------
# 2. Built-in content patterns on added lines
# ---------------------------------------------------------------------------
check_pattern() {
  # $1 = label, $2 = extended regex, $3 = "block" or "warn", $4 = optional exclusion regex
  local label="$1" re="$2" level="$3" excl="${4:-}"
  local hits
  hits=$(printf '%s\n' "$ADDED" | grep -nE -- "$re" || true)
  if [ -n "$excl" ] && [ -n "$hits" ]; then
    hits=$(printf '%s\n' "$hits" | grep -Ev -- "$excl" || true)
  fi
  [ -z "$hits" ] && return 0
  local count; count=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
  if [ "$level" = block ]; then fail "$label ($count added line(s))"; else warn "$label ($count added line(s))"; fi
  if [ "$QUIET_TERMS" != "1" ]; then
    printf '%s\n' "$hits" | head -n 5 | sed 's/^/         /' >&2
  fi
}

check_pattern "private key material"          '-----BEGIN [A-Z ]*PRIVATE KEY-----' block
check_pattern "Microsoft tenant domain"       '[A-Za-z0-9-]+\.onmicrosoft\.com' block 'contoso\.onmicrosoft\.com'
# systemd template units (name@instance.service) look like e-mail addresses and are excluded.
check_pattern "e-mail address"                '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' block '@(example\.(com|org|net)|contoso\.example|[a-z0-9-]+\.example|users\.noreply\.github\.com)\b|@[A-Za-z0-9.%-]*\.(service|timer|target|socket|mount|path|slice)\b'
check_pattern "connection string password"    '(Password|Pwd)=[^;"'"'"' ]{4,}' block '(Password|Pwd)=(`|\$\{|\{\{|<|CHANGE_ME|placeholder|password\b)'
check_pattern "client secret"                 'client[_-]?secret["'"'"']?\s*[:=]\s*["'"'"']?[A-Za-z0-9~._-]{12,}' block
check_pattern "AWS/Wasabi access key id"      '\b(AKIA|ASIA)[0-9A-Z]{16}\b' block
check_pattern "Stripe live key"               '\b(sk|rk|pk)_live_[0-9a-zA-Z]{10,}' block
check_pattern "Slack/Teams webhook URL"       'https://(hooks\.slack\.com/services/|[a-z0-9-]+\.webhook\.office\.com/)' block
check_pattern "Azure storage key or SAS"      '(AccountKey=[A-Za-z0-9+/=]{40,}|[?&]sig=[A-Za-z0-9%+/=]{20,})' block
check_pattern "JWT token"                     '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' block
check_pattern "public IPv4 address"           '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' warn '\b(10\.|127\.|0\.0\.0\.0|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|255\.|169\.254\.|203\.0\.113\.|198\.51\.100\.|192\.0\.2\.)'

# ---------------------------------------------------------------------------
# 3. Confidential terms list (customers, hostnames, unreleased names, ...)
# ---------------------------------------------------------------------------
if [ -r "$TERMS_FILE" ]; then
  terms=$(grep -Ev '^\s*(#|$)' "$TERMS_FILE" || true)
  if [ -n "$terms" ]; then
    corpus=$(printf '%s\n--- files ---\n%s\n--- messages ---\n%s\n' "$ADDED" "$FILES" "$MESSAGES")
    while IFS= read -r term; do
      [ -z "$term" ] && continue
      hits=$(printf '%s\n' "$corpus" | grep -niF -- "$term" || true)
      if [ -n "$hits" ]; then
        count=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
        if [ "$QUIET_TERMS" = "1" ]; then
          fail "confidential term matched ($count line(s)); see the private terms list"
        else
          fail "confidential term '$term' matched ($count line(s))"
          printf '%s\n' "$hits" | head -n 3 | sed 's/^/         /' >&2
        fi
      fi
    done <<EOF_TERMS
$terms
EOF_TERMS
  fi
else
  if [ "$STRICT" = "1" ]; then
    fail "confidential terms list not found at $TERMS_FILE (required for public remotes and CI)"
  else
    warn "confidential terms list not found at $TERMS_FILE; copy it from the private repository"
  fi
fi

# ---------------------------------------------------------------------------
# 4. Commit messages: identifiers that never belong in a public history
# ---------------------------------------------------------------------------
if [ -n "$MESSAGES" ]; then
  # Co-author trailers with a no-reply address are attribution, not identifying data.
  msg_body=$(printf '%s\n' "$MESSAGES" | grep -viE '^Co-Authored-By: .*<(noreply@anthropic\.com|[A-Za-z0-9._+-]+@users\.noreply\.github\.com)>$' || true)
  if printf '%s\n' "$msg_body" | grep -qiE '[A-Za-z0-9-]+\.onmicrosoft\.com|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'; then
    fail "commit message contains a tenant domain or e-mail address"
  fi
fi

# ---------------------------------------------------------------------------
# 5. gitleaks for everything the patterns above do not know
# ---------------------------------------------------------------------------
if command -v gitleaks >/dev/null 2>&1; then
  if [ "$MODE" = "--staged" ]; then
    gitleaks protect --staged --redact --no-banner --exit-code 1 >/dev/null 2>&1 || fail "gitleaks found secrets in staged changes (run: gitleaks protect --staged --verbose)"
  else
    if [ "$FROM" = "$EMPTY_TREE" ]; then logopts="$TO"; else logopts="$FROM..$TO"; fi
    gitleaks detect --redact --no-banner --exit-code 1 --log-opts="$logopts" >/dev/null 2>&1 || fail "gitleaks found secrets in $logopts (run: gitleaks detect --log-opts=$logopts --verbose)"
  fi
else
  if [ "$STRICT" = "1" ]; then fail "gitleaks is not installed (required for public remotes and CI)"; else warn "gitleaks is not installed; install it from https://github.com/gitleaks/gitleaks"; fi
fi

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
if [ "$findings" -gt 0 ]; then
  say "confidentiality scan: $findings finding(s), $warnings warning(s). Nothing was pushed or committed."
  say "Move confidential material to the private repository, or fix the content, and try again."
  exit 1
fi
if [ "$warnings" -gt 0 ]; then
  say "confidentiality scan: clean with $warnings warning(s)."
else
  say "confidentiality scan: clean."
fi
exit 0
