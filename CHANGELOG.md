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

### Changed

- The repository engine reuses one pack buffer per writer and pooled chunk buffers, so streaming a 2 GB file adds less
  than 30 MB of memory. The stored format is unchanged.
