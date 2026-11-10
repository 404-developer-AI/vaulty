#!/usr/bin/env bash
# The installer test of CI on an ubuntu-24.04 runner (no TPM, no data disk): install with an answers file, doctor,
# update, update to a release whose health check fails (automatic rollback), secret scan, uninstall --purge.
# Runs as a user with passwordless sudo. Builds three local releases; signatures are skipped (local tarballs).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REL="$(mktemp -d)"
fail() { echo "INSTALLER TEST FAILED: $*" >&2; exit 1; }
step() { echo; echo "=== $*"; }

step "build releases"
for v in 0.0.0-ci.1 0.0.0-ci.2; do
  mkdir -p "$REL/v$v"
  "$ROOT/deploy/ci/build-release.sh" "$v" "$REL/v$v"
done
# A release whose web service cannot start: same content, Vaulty.Web replaced by a program that exits at once.
mkdir -p "$REL/v0.0.0-ci.3" "$REL/broken"
tar -xzf "$REL/v0.0.0-ci.2/vaulty-0.0.0-ci.2-linux-x64.tar.gz" -C "$REL/broken"
mv "$REL/broken/vaulty-0.0.0-ci.2" "$REL/broken/vaulty-0.0.0-ci.3"
printf '#!/bin/sh\necho "deliberately broken build" >&2\nexit 1\n' > "$REL/broken/vaulty-0.0.0-ci.3/bin/Vaulty.Web"
chmod 0755 "$REL/broken/vaulty-0.0.0-ci.3/bin/Vaulty.Web"
tar -C "$REL/broken" -czf "$REL/v0.0.0-ci.3/vaulty-0.0.0-ci.3-linux-x64.tar.gz" vaulty-0.0.0-ci.3
(cd "$REL/v0.0.0-ci.3" && sha256sum vaulty-0.0.0-ci.3-linux-x64.tar.gz > SHA256SUMS)

export VAULTY_RELEASE_BASE_URL="file://$REL"
export VAULTY_SKIP_SIGNATURE_CHECK=1
export VAULTY_INSTALL_VERBOSE=1

step "install with an answers file"
answers=$(mktemp)
cat > "$answers" <<'EOF'
profile: all-in-one
environment: development
fqdn: localhost
admin_email: admin@example.com
workers:
  instances: 1
EOF
sudo install -m 0600 -o root -g root "$answers" /root/vaulty-answers.yaml
sudo -E bash "$ROOT/deploy/install/get-vaulty.sh" --version 0.0.0-ci.1 --answers /root/vaulty-answers.yaml
sudo test ! -e /root/vaulty-answers.yaml || fail "the answers file was not removed"

step "all units active, health endpoints answer"
for unit in vaulty-web vaulty-api vaulty-worker@1 vaulty-gc vaulty-temporal postgresql@17-main caddy; do
  state=$(systemctl is-active "$unit" || true)
  [ "$state" = "active" ] || { sudo journalctl -u "$unit" -n 80 --no-pager; fail "$unit is $state"; }
done
curl -fsS http://127.0.0.1:5001/api/v1/healthz/ready | grep -q ready || fail "/api/v1/healthz/ready is not ready"
curl -fsS http://127.0.0.1:5000/healthz >/dev/null || fail "web /healthz does not answer"
curl -ksS -o /dev/null -w '%{http_code}' https://localhost/ | grep -qE '^(200|302)$' || fail "Caddy does not serve the web app"
[ "$(curl -ks -o /dev/null -w '%{http_code}' https://localhost/metrics)" = "404" ] || fail "/metrics is reachable through Caddy"

step "report present with mode 0600"
report=$(sudo sh -c 'ls /root/vaulty-install-report-*.txt' | head -1)
[ -n "$report" ] || fail "no installation report"
[ "$(sudo stat -c '%a %U' "$report")" = "600 root" ] || fail "the report is not 0600 root"

step "no secret in configuration, Compose file or unit environment"
temporal_pw=$(sudo sed -n 's/.*PostgreSQL role "temporal" \.* \([0-9a-f]\{48\}\).*/\1/p' "$report")
valkey_pw=$(sudo sed -n 's/.*Valkey \.* \([0-9a-f]\{48\}\).*/\1/p' "$report")
master=$(sudo sed -n 's/^ *base64 \.* \([A-Za-z0-9+/=]\{44\}\).*/\1/p' "$report")
[ -n "$temporal_pw" ] && [ -n "$valkey_pw" ] && [ -n "$master" ] || fail "the report does not list the secrets"
for secret in "$temporal_pw" "$valkey_pw" "$master"; do
  for file in /etc/vaulty/vaulty.json /opt/vaulty/current/compose/temporal.compose.yml /etc/caddy/Caddyfile; do
    sudo grep -qF "$secret" "$file" && fail "a secret is in $file"
  done
  for unit in vaulty-web vaulty-api vaulty-worker@1 vaulty-gc vaulty-temporal; do
    systemctl show -p Environment "$unit" | grep -qF "$secret" && fail "a secret is in the environment of $unit"
  done
  sudo docker inspect vaulty-temporal --format '{{json .Config.Env}}' | grep -qF "$valkey_pw" && fail "the Valkey password reached the Temporal container"
done
true

step "vaulty doctor: no findings, every unit 2.0 or better"
sudo /opt/vaulty/current/bin/vaulty doctor || fail "vaulty doctor has findings"

step "update to a second build"
sudo -E /opt/vaulty/current/bin/vaulty update --to 0.0.0-ci.2 || fail "the update failed"
[ "$(readlink /opt/vaulty/current)" = "/opt/vaulty/releases/0.0.0-ci.2" ] || fail "current does not point to 0.0.0-ci.2"
[ "$(readlink /opt/vaulty/previous)" = "/opt/vaulty/releases/0.0.0-ci.1" ] || fail "previous does not point to 0.0.0-ci.1"

step "update to a build with a failing health check rolls back"
set +e
sudo -E /opt/vaulty/current/bin/vaulty update --to 0.0.0-ci.3
code=$?
set -e
[ "$code" = "2" ] || fail "the failing update returned $code, expected 2"
[ "$(readlink /opt/vaulty/current)" = "/opt/vaulty/releases/0.0.0-ci.2" ] || fail "no rollback to 0.0.0-ci.2"
curl -fsS http://127.0.0.1:5001/api/v1/healthz/ready | grep -q ready || fail "not healthy after the rollback"

step "uninstall --purge leaves no users, units or data"
sudo /opt/vaulty/current/bin/vaulty uninstall --purge --confirm "$(hostname -f)"
for user in vaulty-web vaulty-api vaulty-worker vaulty-gc vaulty-migrator; do
  getent passwd "$user" >/dev/null && fail "user $user still exists"
done
getent group vaulty >/dev/null && fail "group vaulty still exists"
ls /etc/systemd/system/vaulty* >/dev/null 2>&1 && fail "Vaulty units remain"
for path in /opt/vaulty /etc/vaulty /var/lib/vaulty /srv/vaulty-data; do
  [ -e "$path" ] && fail "$path remains"
done
sudo docker ps -a --format '{{.Names}}' | grep -q vaulty && fail "Vaulty containers remain"
echo; echo "INSTALLER TEST PASSED"
