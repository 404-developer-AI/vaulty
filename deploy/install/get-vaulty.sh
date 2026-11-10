#!/usr/bin/env bash
# Vaulty bootstrap: installs or updates Vaulty on Ubuntu 24.04 LTS.
#
#   curl -fsSL https://<release-host>/get-vaulty.sh | sudo bash
#   curl -fsSL https://<release-host>/get-vaulty.sh | sudo bash -s -- --version 1.4.2
#   curl -fsSL https://<release-host>/get-vaulty.sh | sudo bash -s -- --answers /root/vaulty-answers.yaml
#
# This script deliberately does as little as possible: it checks the host, downloads the
# requested release, verifies its cosign signature and checksum, unpacks it and hands over to
# the signed `vaulty` CLI, which decides between a fresh install and an update.
#
# Environment overrides (for development and air-gapped mirrors):
#   VAULTY_REPO                   GitHub repository "owner/name" that publishes releases
#   VAULTY_RELEASE_BASE_URL       base URL of a mirror; defaults to GitHub Releases of VAULTY_REPO
#   VAULTY_VERSION                release version without the leading "v"; default "latest"
#   VAULTY_SKIP_SIGNATURE_CHECK   set to 1 to skip cosign verification (development only, loud warning)

set -euo pipefail

VAULTY_REPO="${VAULTY_REPO:-404-developer-AI/vaulty}"
VAULTY_VERSION="${VAULTY_VERSION:-latest}"
VAULTY_RELEASE_BASE_URL="${VAULTY_RELEASE_BASE_URL:-https://github.com/${VAULTY_REPO}/releases/download}"
COSIGN_VERSION="2.4.1"                                          # keep in sync with .github/workflows/release.yml
COSIGN_SHA256_AMD64="8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b"  # cosign_checksums.txt of v2.4.1
COSIGN_IDENTITY_RE="^https://github.com/${VAULTY_REPO}/\.github/workflows/release\.yml@refs/tags/v"
COSIGN_ISSUER="https://token.actions.githubusercontent.com"
INSTALL_ROOT="/opt/vaulty"
ARCH="x64"

say()  { printf '%s\n' "$*" >&2; }
die()  { say "ERROR: $*"; exit 1; }
warn() { say "WARNING: $*"; }

# ---------------------------------------------------------------------------
# Arguments: --version is consumed here, everything else is passed to the CLI
# ---------------------------------------------------------------------------
PASSTHROUGH=()
while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || die "--version needs a value"; VAULTY_VERSION="$2"; shift 2 ;;
    --version=*) VAULTY_VERSION="${1#--version=}"; shift ;;
    *) PASSTHROUGH+=("$1"); shift ;;
  esac
done
VAULTY_VERSION="${VAULTY_VERSION#v}"

# ---------------------------------------------------------------------------
# Host checks
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
else
  die "cannot read /etc/os-release"
fi
[ "${ID:-}" = "ubuntu" ] || die "Ubuntu 24.04 LTS is the only supported distribution (found ${ID:-unknown})"
[ "${VERSION_ID:-}" = "24.04" ] || die "Ubuntu 24.04 LTS is required (found ${VERSION_ID:-unknown})"
[ "$(uname -m)" = "x86_64" ] || die "x86-64 is the only supported architecture (found $(uname -m))"
command -v systemctl >/dev/null || die "systemd is required"

avail_kb=$(df --output=avail -k /opt | tail -1 | tr -d ' ')
[ "$avail_kb" -ge $((2 * 1024 * 1024)) ] || die "at least 2 GB free space is needed under /opt"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends curl ca-certificates tar coreutils >/dev/null

# ---------------------------------------------------------------------------
# cosign (release signature verification)
# ---------------------------------------------------------------------------
ensure_cosign() {
  if command -v cosign >/dev/null; then return 0; fi
  if [ -z "$COSIGN_SHA256_AMD64" ]; then
    die "cosign is not installed and this script has no pinned checksum to install it; install cosign first or set VAULTY_SKIP_SIGNATURE_CHECK=1 (development only)"
  fi
  local tmp; tmp=$(mktemp)
  curl -fsSL -o "$tmp" "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64"
  echo "${COSIGN_SHA256_AMD64}  ${tmp}" | sha256sum -c --quiet - || die "cosign download does not match the pinned checksum"
  install -m 0755 "$tmp" /usr/local/bin/cosign
  rm -f "$tmp"
}

if [ "${VAULTY_SKIP_SIGNATURE_CHECK:-0}" = "1" ]; then
  warn "signature verification is DISABLED (VAULTY_SKIP_SIGNATURE_CHECK=1). Never do this on a production host."
else
  ensure_cosign
fi

# ---------------------------------------------------------------------------
# Resolve version
# ---------------------------------------------------------------------------
if [ "$VAULTY_VERSION" = "latest" ]; then
  VAULTY_VERSION=$(curl -fsSL -H 'Accept: application/vnd.github+json' \
      "https://api.github.com/repos/${VAULTY_REPO}/releases/latest" \
    | sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)
  [ -n "$VAULTY_VERSION" ] || die "could not determine the latest release of ${VAULTY_REPO}"
fi
case "$VAULTY_VERSION" in
  *[!A-Za-z0-9._-]*|"") die "invalid version '${VAULTY_VERSION}'" ;;
esac

TARBALL="vaulty-${VAULTY_VERSION}-linux-${ARCH}.tar.gz"
BASE="${VAULTY_RELEASE_BASE_URL}/v${VAULTY_VERSION}"
RELEASE_DIR="${INSTALL_ROOT}/releases/${VAULTY_VERSION}"

if [ -x "${RELEASE_DIR}/bin/vaulty" ]; then
  say "Release ${VAULTY_VERSION} is already present at ${RELEASE_DIR}; reusing it."
else
  # -------------------------------------------------------------------------
  # Download and verify
  # -------------------------------------------------------------------------
  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT

  say "Downloading Vaulty ${VAULTY_VERSION} ..."
  curl -fsSL -o "${WORK}/${TARBALL}"          "${BASE}/${TARBALL}"
  curl -fsSL -o "${WORK}/SHA256SUMS"          "${BASE}/SHA256SUMS"
  if [ "${VAULTY_SKIP_SIGNATURE_CHECK:-0}" != "1" ]; then
    curl -fsSL -o "${WORK}/SHA256SUMS.sigstore.json" "${BASE}/SHA256SUMS.sigstore.json"
    say "Verifying release signature ..."
    cosign verify-blob \
      --bundle "${WORK}/SHA256SUMS.sigstore.json" \
      --certificate-identity-regexp "${COSIGN_IDENTITY_RE}" \
      --certificate-oidc-issuer "${COSIGN_ISSUER}" \
      "${WORK}/SHA256SUMS" >/dev/null \
      || die "signature verification of SHA256SUMS failed; refusing to install"
  fi

  say "Verifying checksum ..."
  (cd "$WORK" && grep -E "  ${TARBALL}\$" SHA256SUMS | sha256sum -c --quiet -) \
    || die "checksum of ${TARBALL} does not match SHA256SUMS"

  # -------------------------------------------------------------------------
  # Unpack
  # -------------------------------------------------------------------------
  install -d -m 0755 "${INSTALL_ROOT}/releases"
  rm -rf "${RELEASE_DIR}.partial"
  install -d -m 0755 "${RELEASE_DIR}.partial"
  tar -xzf "${WORK}/${TARBALL}" -C "${RELEASE_DIR}.partial" --strip-components=1
  [ -x "${RELEASE_DIR}.partial/bin/vaulty" ] || die "release archive does not contain bin/vaulty"
  mv "${RELEASE_DIR}.partial" "${RELEASE_DIR}"
fi

# ---------------------------------------------------------------------------
# Hand over to the CLI: it decides between install and update
# ---------------------------------------------------------------------------
say "Starting vaulty ${VAULTY_VERSION} bootstrap ..."
# With `curl ... | sudo bash` standard input is the pipe that carried this script, so the wizard
# would see no terminal. Reattach it to the controlling terminal when there is one.
if [ ! -t 0 ] && (exec </dev/tty) 2>/dev/null; then
  exec "${RELEASE_DIR}/bin/vaulty" bootstrap --release-dir "${RELEASE_DIR}" "${PASSTHROUGH[@]}" </dev/tty
fi
exec "${RELEASE_DIR}/bin/vaulty" bootstrap --release-dir "${RELEASE_DIR}" "${PASSTHROUGH[@]}"
