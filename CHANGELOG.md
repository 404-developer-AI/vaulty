# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- Solution `Vaulty.slnx` with every service, connector, test and tool project; central build settings and package
  management; SDK pinned in `global.json`.
- Business Source License 1.1, security policy, contribution guide and issue templates.
- Continuous integration: build and tests against PostgreSQL 17, confidentiality scan, branding check, CodeQL,
  vulnerable-package check, Renovate configuration.
- Domain model: organizations, users, roles and the permission catalog with built-in roles, customers, tenants,
  policies, protected objects, snapshots, items, packs, chunk index, jobs, audit events, tenant keys, usage; state
  machines for snapshots, protected objects and jobs; interfaces for object storage, secrets and key wrapping.
- PostgreSQL schema `vaulty` (forward-only SQL migrations applied by `vaulty-migrate`): row-level security on every
  organization table, items and chunk index hash-partitioned on the tenant (64 partitions), per-role grants without
  DDL or `BYPASSRLS`, an append-only audit log with a per-organization SHA-256 hash chain and an independent verifier.
- Key hierarchy: host master key from a systemd credential (development key outside the repository), HKDF derivations
  for secrets, session key ring, export and KEK, per-tenant subkeys (protected object, chunk ids, metadata,
  repository); software key wrapper with a versioned, authenticated header; specification and test vectors in
  `docs/format/keys-v1.md`.
- Secrets store in PostgreSQL bound to name, version and host, with versions, pruning and a short cache; master key
  rekey that re-encrypts secrets, the session key ring and wrapped tenant keys in one transaction; session key ring
  stored sealed in the database; secrets are redacted in logs and JSON.
- Repository engine (format v1, `docs/format/repository-v1.md`): FastCDC chunking, keyed BLAKE3 chunk ids, zstd,
  AES-256-GCM per chunk with deterministic nonces, content-addressed packs with index files, sealed manifests and
  snapshot roots with a Merkle root, an index rebuildable from object storage alone; golden files of format v1.
- Object storage: S3 adapter with Object Lock (compliance mode), Content-MD5 and ETag verification, its own retries
  that honour Retry-After, version-aware deletes; in-memory store with simulated Object Lock for tests.
- Tenant data keys stored wrapped in the database and as immutable key files; daily audit chain anchors in object
  storage.
- Tests: property-based tests of chunker, codec and parsers, a 10,000-item roundtrip, 50 crash-injection runs, S3
  contract tests against WireMock; nightly fuzzing of the parsers with libFuzzer.
- Workflow foundation on Temporal: worker host under systemd with task queues `backup`, `restore`, `verify` and `gc`,
  OpenTelemetry tracing, shared activity policies where Retry-After takes precedence over backoff, page checkpoints in
  PostgreSQL, and a job mirror that records start, end and exact counts of every job workflow. Tests kill the worker
  process 20 times during a backup and require the same result as an undisturbed run.
- Microsoft Graph client core: certificate authentication per tenant (MSAL), a handler pipeline for telemetry,
  throttling (four requests per mailbox, an adaptive rate per tenant, a global cap, Retry-After honoured exactly),
  decoration and authentication; paging, delta with a resync route on 410, `$batch` that resends only throttled
  sub-requests, mailbox item export, and a separate download client that never sends a token.
- Tenant onboarding building blocks: a certificate per tenant, a PowerShell script and manual steps that create the app
  registration with its application permissions, and a permission probe with a readable report.
- Web app (Blazor, MudBlazor, Steaan design tokens) and API (`/api/v1/healthz`, `/api/v1/healthz/ready`,
  `/api/v1/openapi.json`): sign-in with passkeys or password plus authenticator app (no SMS or e-mail codes), a second
  factor required before anything else, first-administrator setup with a one-time token, "Confirm it's you" for
  sensitive actions, sessions of 8 hours with a 30-minute idle timeout, permission-based authorization on every page and
  endpoint, roles that allow restores or administration only for users with a second factor, users and roles page,
  audit log page, security headers with a strict Content Security Policy, systemd notification.
- Settings → Storage: a setup assistant that creates the backup bucket (Object Lock and versioning), the export bucket
  (one-day lifecycle) and three least-privilege identities with their keys, or entry of existing buckets and keys; key
  rotation; a connection test with six separate checks that must all pass before backups can be planned.
- Settings: SMTP with a test message, display time zone and webhook defaults. Settings never contain secrets; keys and
  passwords are in the encrypted secrets store.
- Customers (code, name, tags) and tenants: a two-step "connect a tenant" flow with a certificate per tenant (private key
  only in the secrets store), the PowerShell script and manual steps, entry of tenant and client id, a permission check,
  certificate rotation that switches only after the new certificate works, and refusal of a tenant that is connected
  elsewhere. An hourly health check marks a tenant "consent lost" when its app is disabled, removed, loses permissions or
  its certificate expires. Discovery finds mailboxes (user, shared, resource), OneDrives and archive mailboxes (shown as
  not protected yet), is idempotent and marks objects that left Microsoft 365 as source deleted.
- Exchange Online backup: folders and item delta from the mailbox import/export API, full-fidelity export in batches of
  at most 20 items and 32 MB, searchable metadata read separately and stored encrypted, a MIME fallback marked limited
  fidelity, one child workflow per folder with page checkpoints, removals and new versions applied only at the atomic
  commit, delta links stored only after the commit, post-write verification of new packs, per-folder count checks,
  partial snapshots that list every missing item with its reason, retries of earlier failures, poison items after three
  identical errors (retried once a day), resync after an expired delta token.
- Backup planning: a scheduler that starts due backups per tenant within budgets (20 mailboxes, 10 drives), only once the
  storage connection test passed and consent is granted; a default policy per tenant (every 6 hours, 90 days) that can be
  changed, with folder exclusions; "Back up now".
- OneDrive backup: drive delta of the whole drive with paging and page checkpoints, streaming downloads through the
  pre-authenticated download URL (never with a token) that resume with a Range request after a broken connection,
  QuickXorHash or SHA-256 checked for every file (a mismatch is recorded as an exception), up to three older versions of
  a changed file, sharing permissions and links as metadata, OneNote notebooks as packages, renamed or moved files kept
  without downloading them again, files under a deleted folder removed with it, long paths and refused characters
  flagged, files over 250 GB reported as exceptions; the same atomic commit and partial rules as mailboxes.
- Snapshot browser: the snapshots of every protected object with exact counts and verification time, the folder tree and
  items of any snapshot (point in time), newest first with paging that stays fast deep into large folders, item detail
  with metadata and older file versions, and search on subject, sender, file name and path across everything the user
  may browse, limited to the user's customers. Search tokens are kept per item; the fields themselves stay encrypted.
- Previews: the body of a message is stored as a separate preview at backup time and shown sanitized (no scripts, forms,
  frames or event handlers, links reduced to text, external images blocked) in a sandboxed iframe with its own
  Content Security Policy; images, PDF and text files under 20 MB are previewed as they are. Every preview is written to
  the audit log.
- Restores: select items, a folder or a single file version in the snapshot browser and restore them to a restore folder
  (`Vaulty Restore/<date time>/<original path>`, the default), to their original location, or to another mailbox or
  OneDrive of the same tenant. Mail, calendar items and contacts go through the mailbox import API, so calendar items are
  restored as they were and no invitation or update is ever sent; files go up in upload sessions with their original
  times, and an existing file is never replaced unless that was chosen (the default keeps both, the restored copy named
  "(restored date)"). Restores run in small batches that can be paused, resumed and cancelled; items restored so far stay
  restored. Every restore keeps a report per item for one year.
- Exports: a zip in store mode (messages as EML, events as ICS, contacts as VCF, files as they are, and a manifest with
  every item's metadata and result) written straight to the export bucket in parts, without temporary files. The
  download link is created after "Confirm it's you", works once, within 24 hours, only for the user who asked for the
  export; the zip is removed after the download.
- Restoring elsewhere and exporting need their own permissions and "Confirm it's you"; every request, link and download
  is written to the audit log.
- Verification (daily, in the gc service): a scrub re-reads whole packs, oldest scrub first and at least 1% of a
  tenant's packs per week; a restore drill rebuilds 10 random items in memory and checks their hash; the latest snapshot
  of every protected object is opened. A snapshot is marked verified only when all of that passed and the tenant had a
  scrub in the last 7 days. Anything that does not match raises a critical alert.
- Drift detection: a snapshot with more than 30% fewer items than the previous one raises an alert.
- Retention and garbage collection (daily, own database role and storage identity, the only ones that may delete):
  snapshots outside their policy's retention expire, except under legal hold and except the newest snapshot of an
  object that still exists; packs, index files, manifests and snapshot roots that no remaining snapshot needs are
  removed once their Object Lock has expired. Every run starts as a dry run with a report. A run is refused when the
  host clock differs more than 5 minutes from the database, while a backup of the tenant runs, or when it would remove
  more than 25% of a tenant's data.
- Legal hold per protected object or per tenant, set on the tenant page and written to the audit log.
- Deleting a tenant: one administrator requests it after "Confirm it's you" and its backups stop at once; a reminder is
  raised every day; a second administrator can confirm after 30 days; until then the request can be withdrawn. A tenant
  on legal hold cannot be deleted.
- Dashboard: every customer, tenant and protected object, worst status first, with exact counts and no percentages; a
  tenant takes the worst state of its objects and a customer the worst of its tenants. Partial is amber everywhere and
  never counts as protected; red is kept for genuine failure (no snapshot committed, a latest snapshot older than twice
  the interval, consent lost, verification failed). Open alerts are listed on top and can be resolved.
- Jobs page on the job mirror, filtered by status and type, with the request ID to quote to support.
- Tenant health on the tenant page: status, counts, the oldest latest snapshot, the last verification and its result, and
  Microsoft Graph requests and throttled responses of the last 24 hours.
- Alerts by e-mail to the users who may see reports for the customer (per-user opt-out), plain text with an HTML card,
  once per alert. A scheduled backup that has not started 10 minutes after its planned time raises a "missed run"
  alert; partial and failed backups raise alerts that a later clean snapshot resolves; lost consent raises an alert.
- Webhooks (Settings → Webhooks): events `backup.failed`, `backup.partial`, `backup.missed`, `backup.drift`,
  `tenant.consent_lost`, `verification.failed`, `restore.completed` and `tenant.deletion_pending`, JSON bodies signed
  with HMAC-SHA256 over timestamp and body (`Vaulty-Signature: t=...,v1=...`) with a delivery ID for replay protection,
  retries with backoff over about 15 hours, a delivery log and a test button. Webhooks go to https only and never to
  private, loopback or link-local addresses, checked again at connect time.
- A daily digest by e-mail at 07:00 in the display time zone with exact counts and every protected object that needs
  attention.
- Metrics: OpenTelemetry metrics in the workers (exported when an OTLP endpoint is set) and `/metrics` in Prometheus
  format on the API, reachable from the host only, aggregated without customer, tenant or object names.
- Recover CLI (`vaulty-recover`): rebuilds a tenant from object storage alone, without the database. With read access to
  the backup bucket (or a local copy) and the master key's recovery copy it unwraps the data keys from their key files,
  rebuilds the chunk index from the index files, takes the newest snapshot of every protected object (or a chosen one)
  and writes every item exactly as an export through the platform does: messages as EML, events as ICS, contacts as VCF,
  files as they are, a manifest per snapshot and a report per item. Every chunk is authenticated and every content hash
  checked; an item that fails is reported and never written half.
- Installer and updater (`vaulty`, run as root on Ubuntu 24.04): a wizard or an answers file (mode 0600, removed after
  success); idempotent steps with `--resume` for OS hardening and firewall, service users, an optional LUKS2 data disk
  enrolled to TPM 2.0, the master key and container passwords as encrypted systemd credentials (TPM-bound when
  present, host key with a warning otherwise), PostgreSQL 17 from PGDG with checksums and tuning from RAM and vCPU,
  optional pgBackRest, Docker for Temporal and Valkey with pinned image digests, schema setup with the Temporal SQL
  tool, systemd units with memory limits, migrations, Caddy with ACME, the first-administrator link, a health check and
  the installation report (0600, shown once). Secrets never appear on a command line or in a file.
- `vaulty update` stops workers first, migrates with the new binaries, switches the release link, starts in order and
  rolls back automatically when the health check fails; it refuses a repository format change without
  `--accept-format-change` and waits for running restores. Also `status`, `doctor` (secrets in files, hardening score per
  unit, database access, firewall), `report` without secrets, `secrets`, `master-key restore`, `db`, `logs` and
  `uninstall [--purge]`.
- A CI job installs, checks, updates, rolls back and purges a locally built release on an Ubuntu 24.04 runner.
- Release pipeline on `v*` tags: a self-contained linux-x64 tarball (`bin/`, `compose/`, `templates/`) with container
  images pinned by digest, a CycloneDX SBOM, `SHA256SUMS` signed keyless with cosign, size and start-up time in the
  release notes, a repository format-change flag, and a pre-release for versions with a suffix. A follow-up job
  installs the published release with `get-vaulty.sh` and its signature check, and proves that a manipulated
  `SHA256SUMS` is refused. `get-vaulty.sh` installs cosign with a pinned checksum. Renovate follows the image tags.

### Changed

- The repository engine reuses one pack buffer per writer and pooled chunk buffers, so streaming a 2 GB file adds less
  than 30 MB of memory. The stored format is unchanged.
- Each item's sealed metadata now also holds the reference to its stored preview, its limited-fidelity flag and its
  modification time (reserved key `_vaulty`, see `docs/format/repository-v1.md`), so object storage alone holds what a
  restore needs. The binary format is unchanged.
- Exported messages are deterministic: the original Message-Id (or one derived from the item) and the item's own date,
  so the same snapshot always exports to the same bytes.
- Services read the host configuration from `$VAULTY_CONFIG_DIR/vaulty.json`; `vaulty-migrate` is the name of the
  migration binary, as in its unit.
- The verifier and garbage collector run in the worker host with `--role gc` under the gc database role and storage
  identity; the worker processes serve only the backup and restore queues.

### Fixed

- The web app and API take the scheme and client address from the reverse proxy on the same host: redirects stay on
  https and the secure-only cookies work behind Caddy (sign-in no longer loops).
- Stylesheets, scripts and images are served to visitors who are not signed in, so the sign-in and set-up pages are
  styled; `/error` is a real page that needs no sign-in.
- A staging host gets a certificate from the trusted Let's Encrypt CA; only development hosts use the staging CA.
- The Caddy access log no longer records query strings, nor the Referer and Location headers that repeat them.
- `curl ... | sudo bash` starts the interactive wizard: the bootstrap script hands the terminal to the installer.
- The services run in the directory that holds their binaries, so the web app finds its `wwwroot` and serves its
  stylesheets, scripts and images on an installed host.
- An update also renders the Caddyfile of the new release, so a fixed template reaches hosts installed earlier.
- The customer list opens: a text array column is mapped by hand, as Npgsql reports it as `System.Array`.
- The audit log shows the user's name instead of the user id (the id stays in the tooltip); the role picker no longer
  shows an empty id; page headings no longer get a focus ring after navigation.
- A tenant that holds no backups (no snapshot, no stored data, no backup running) can be removed at once by one
  administrator with a fresh confirmation, also while a deletion request waits; a tenant with backups still needs the
  request, 30 days and a second administrator. Audited as `tenant.removed_without_backups`.
- The tenant ID and application ID of a connected tenant can be corrected; the tenant ID only while it holds no backups.
- A deleted tenant no longer blocks connecting the same Microsoft 365 tenant again (migration `0013`).
- Tenant certificates are valid to the whole second, and the onboarding and rotation scripts read the key end date
  from the certificate itself: Microsoft refused the key when the end date carried a fraction of a second. The
  onboarding script checks for the Microsoft Graph PowerShell SDK first and refuses to create a second app
  registration with the same name.
- Workers and garbage collection sign in to PostgreSQL with their own roles again: the shared `appsettings.json` no
  longer names a database user, which since the services run in `bin` made them all sign in as the API role and stopped
  every job. The installer test fails when a service cannot sign in.
- Empty storage keys are refused with a message by the storage page and the setup service, instead of ending the page;
  the connection test reports a stored key it cannot use.
- The snapshot browser shows the folder tree again: the tree view had no item template, and MudBlazor renders no items
  without one. A test requires an item template for every tree view of the web app.
- The installer prints `[ ok ]` when a step finishes.
- The installer test opens the sign-in page through Caddy and checks the https redirect, every linked stylesheet and
  that a query string never reaches the access log.
