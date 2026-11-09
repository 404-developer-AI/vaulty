#!/usr/bin/env bash
# Installs the Vaulty git hooks for this clone and checks the prerequisites.
# Run once after cloning:  bash .githooks/install.sh
set -eu

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

git config core.hooksPath .githooks
git update-index --chmod=+x .githooks/pre-commit .githooks/pre-push .githooks/confidentiality-scan.sh .githooks/install.sh 2>/dev/null || true
chmod +x .githooks/pre-commit .githooks/pre-push .githooks/confidentiality-scan.sh .githooks/install.sh 2>/dev/null || true
echo "core.hooksPath set to .githooks"

if command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks: $(gitleaks version 2>/dev/null || echo found)"
else
  echo "gitleaks: NOT installed. Install it (winget install gitleaks / brew install gitleaks / see github.com/gitleaks/gitleaks)."
  echo "          Pushes to the public remote will be refused until it is installed."
fi

TERMS_FILE="${VAULTY_CONFIDENTIAL_TERMS:-$HOME/.config/vaulty/confidential-terms.txt}"
mkdir -p "$(dirname "$TERMS_FILE")"
if [ -r "$TERMS_FILE" ]; then
  echo "confidential terms list: $TERMS_FILE ($(grep -cEv '^\s*(#|$)' "$TERMS_FILE" || echo 0) terms)"
else
  echo "confidential terms list: MISSING at $TERMS_FILE"
  echo "          Copy confidential-terms.txt from the private repository (vaulty-internal) to that path."
  echo "          Pushes to the public remote will be refused until it is present."
fi

EMAIL="$(git config user.email || true)"
echo "git user.email for this clone: ${EMAIL:-<not set>} (use your work address)"
echo "done."
