# Vaulty installer

Templates and the bootstrap script used to install and update Vaulty on a single Ubuntu 24.04 LTS host.
Everything here is generic: the `vaulty` CLI (project `Vaulty.Cli`) fills the `{{PLACEHOLDER}}` values at install
time from the answers you give in the interactive wizard or in an answers file.

## Install or update

```bash
curl -fsSL https://<release-host>/get-vaulty.sh | sudo bash
```

The same command installs a fresh host and updates an existing one. Options are passed after `--`:

```bash
curl -fsSL https://<release-host>/get-vaulty.sh | sudo bash -s -- --version 1.4.2
curl -fsSL https://<release-host>/get-vaulty.sh | sudo bash -s -- --answers /root/vaulty-answers.yaml
```

The bootstrap script only verifies and unpacks the signed release, then hands over to `vaulty bootstrap`. All
installation logic lives in the signed CLI, not in the script.

## What gets installed

| Component | How | Listens on |
|---|---|---|
| PostgreSQL 17 + pgBackRest | native packages (PGDG) | Unix socket, 127.0.0.1:5432 |
| Vaulty Web, API, Workers, GC | systemd units, self-contained .NET binaries, one OS user each | 127.0.0.1 only |
| Caddy | native package | 0.0.0.0:80 / 443 |
| Temporal server + UI, Valkey | Docker Compose started by a systemd unit | 127.0.0.1 only |

## Secrets

No secret is ever written to an environment file, a Compose file or `/etc/vaulty/vaulty.json`.

- One master key per host, stored as an encrypted systemd credential (`LoadCredentialEncrypted=`), bound to the
  TPM 2.0 and the host key when a TPM is present.
- All application secrets are stored encrypted (AES-256-GCM) in PostgreSQL and managed with `vaulty secrets`.
- Vaulty's database roles have no passwords: they authenticate with `peer` over the Unix socket, one OS user per
  role.

The installation report printed at the end contains the recovery copy of the master key and every other secret
you need to keep. Store it in your password manager and delete the file.

## Layout

```
get-vaulty.sh            bootstrap: verify signature and checksum, unpack, run `vaulty bootstrap`
answers.example.yaml     answers file for non-interactive installs
bin/                     helper scripts shipped in the release (pgBackRest wrapper)
systemd/                 unit templates and the PostgreSQL credentials drop-in
caddy/                   Caddyfile template
postgres/                postgresql.conf additions, pg_hba.conf, pg_ident.conf, roles.sql
compose/                 Temporal + Valkey Compose file (the only containers)
report.template.txt      installation report template
```

## CLI

```
vaulty install [--answers <file>] [--resume]
vaulty update [--check] [--to <version>] [--rollback] [--accept-format-change] [--force]
vaulty status [--json] | doctor | report
vaulty secrets list | set <name> | rotate <name> | prune <name> [--keep <n>] | rekey
vaulty master-key restore
vaulty db backup-now | verify | restore --target-time <ts>
vaulty logs [unit] [--since <ts>]
vaulty uninstall [--purge --confirm <hostname>]
```

Every installation step is idempotent; after a failure, fix the cause and run `vaulty install --resume`. An update
stops the workers first, migrates the database with the new binaries, switches `/opt/vaulty/current` and starts the
services again; when the health check fails it switches back to the previous release by itself.

Releases can be built locally with `deploy/ci/build-release.sh <version> <directory>`; container images are pinned
by digest in the release (`compose/images.json`, from `compose/images.versions`).
