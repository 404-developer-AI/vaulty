# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- Dashboards per role (Settings > Dashboards). A user sees the first published dashboard in the order that is linked to
  one of their roles, or the default; "Needs attention" always stands above it and is never a tile. Tiles: protection
  summary, open alerts, customers and tenants, recent jobs and a note, each needing its own permission and each
  optionally narrowed to some customers or a tag; the data is the viewer's own, read in the viewer's session. The
  designer places tiles on a 12-column grid by dragging, resizing or with the keyboard, with undo; changes stay a draft
  until published, the last 20 published versions are kept and can come back as the draft, and a dashboard can be
  previewed as a role, exported and imported (JSON, at most 256 KB). A change made meanwhile by someone else is refused.
- Column layouts per role (Settings > Column layouts) for the lists of customers, tenants, protected objects, snapshots
  and jobs: which columns show and in which order. The name and status of a row always show, and a column that needs a
  permission shows only to viewers who hold it.
- New permissions "Manage dashboards" (`dashboards.manage`) and "Manage column layouts" (`columns.manage`), held by the
  built-in Organization admin role. Every change of a dashboard or column layout is in the audit log.
- Only a user who sees every customer can add a customer; a new customer is in no group yet.

- Roles decide what a user may do, groups decide where. A group is every customer (minus what it excludes) or the
  customers, single tenants and customer tags it includes; excludes win within a group, a user sees the union of their
  groups, and a user without a group sees no customer. A tag rule follows the tag, also for customers added later. The
  default group "All customers" is the one new users join; it cannot be deleted. Settings > Groups.
- Custom roles: create, change, copy and delete, under Settings > Roles. Built-in roles stay as they are and can be
  copied. The server checks every permission against the catalog and its dependencies; a role cannot be deleted while
  users hold it, and a permission that needs a second factor is not added while a holder has none.
- No escalation: nobody gives a role, or changes a role, group or user, with permissions or customers they do not hold
  or see themselves. Organization-wide permissions count only for users who see every customer, and the last
  Organization admin with every customer is kept; such changes run one at a time per organization.
- Row-level security on the scope: a user's session in the web limits every row of a customer or tenant, in every
  table, to the user's groups, on top of the checks in the pages and services. Workers and other system tasks are not
  limited beyond their organization. The policy reads the scope once per query and costs no measurable time on items.
- Pages that work on one tenant check the tenant, not only its customer; a user who sees part of a customer cannot act
  on the customer as a whole (its details, its deletion, connecting a tenant to it).
- Changes of roles and groups take effect at once. A restore or export whose starter can no longer run it is paused,
  and the audit log says why; someone who may run it resumes or cancels it.
- Entra group mappings (Settings > Sign-in): members of an Entra security group get roles and groups at each Microsoft
  sign-in and lose them when they leave the group. Vaulty reads the groups through Microsoft Graph at sign-in
  (`GroupMember.Read.All`); when it cannot, the mapped access is taken away. Mapped roles and groups are marked and
  are not removed by hand. Optionally, a member of a mapped group without a Vaulty user gets one at the first sign-in,
  in the mapped groups only.
- Settings > Users and roles shows each user's groups, and "Access" shows what a user may do and see in plain words; a
  customer page shows who has access to it. New permissions "Manage groups" (`groups.manage`) and "View access"
  (`access.view`), held by the built-in Organization admin role.
- Alert mail and the daily digest follow the groups: a user receives mail about a customer only when their groups
  include it, and the digest shows only those customers.
- Existing roles limited to customers become a group of exactly those customers per user, so nobody sees more or less
  than before; the old column is kept for a rollback to the previous version.

- Sign-in with Microsoft for the people of an organization, through its own "Vaulty sign-in" app registration in its
  own Microsoft tenant (single tenant, certificate only, asking for `openid profile email` and nothing else). Settings >
  Sign-in guides the set-up: Vaulty creates the certificate, shows each value for the Entra admin center, checks that
  the certificate signs in, reads which optional permissions the app holds, and checks with a test sign-in. With
  `Policy.Read.All` it also reports whether the tenant requires multi-factor authentication; with `User.Read.All` users
  are picked from the tenant, otherwise entered by object ID. Vaulty renews the certificate itself when it knows the
  app's object ID.
- A sign-in is the authorization code flow with PKCE, a one-time state and nonce, and a cookie that binds it to the
  browser that started it; the code is redeemed with the app's certificate and no token is kept. The id token must come
  from the organization's tenant, for the sign-in app, be current and name a member (guests are refused). Accounts are
  matched on tenant and object ID only, never on an e-mail address.
- Users are added from Microsoft or linked to their Microsoft account, by an administrator under Settings > Users and
  roles or by the users themselves (Account > Microsoft account). A linked user signs in with Microsoft only, so the
  tenant's Conditional Access and off-boarding apply to Vaulty too; linking, unlinking or switching sign-in off ends the
  user's sessions at once. The last local Organization admin cannot be linked.
- "Microsoft handles the second factor" (on by default, with a warning): the organization's tenant asks linked users
  for their second factor and Vaulty asks none of its own; switched off, they also need a passkey or authenticator app
  in Vaulty. A token that proves a second factor is recorded as such. "Confirm it's you" for a linked user is a new
  Microsoft sign-in of the same account no older than five minutes.
- "Microsoft sign-in only": local passwords and passkeys stop working except for local Organization admins kept for
  emergencies (at least one with a passkey is required); every emergency sign-in raises a critical alert.
- New permission "Manage sign-in" (`signin.manage`), held by the built-in Organization admin role.
- The audit log records how each sign-in came in (password, passkey or Microsoft, with the second-factor source and the
  short authentication method names Microsoft reports), refused sign-ins, links and every change of the sign-in settings.

- Connect a tenant from the browser: a Global Administrator of the customer signs in with Microsoft, and Vaulty
  creates the app registration "Vaulty" in the tenant with its own certificate, grants admin consent for its
  application permissions, saves the tenant and application IDs itself, checks the permissions and removes the
  setup app from the tenant again. The result is the same dedicated app per tenant as the script makes; the script
  stays available. The sign-in uses the authorization code flow with PKCE, a one-time state bound to the Vaulty user,
  a nonce, and no refresh token; the token is held in memory for the set-up only and never stored or logged. Each
  step is recorded, so signing in again after an interruption continues where it stopped and never creates a second
  app. A tenant already connected, or an account that cannot grant application permissions, is refused before
  anything is created; an app made by an account whose grant Microsoft refuses is removed again. Entra's replication
  delay after a create is retried. Technicians who work through GDAP enter the customer's tenant domain.
- Settings > Microsoft 365: a guided set-up of the "Vaulty setup" app (multi-tenant, delegated permissions only) in
  your own tenant. Vaulty creates its certificate, shows each value to enter in the Entra admin center with a copy
  button, checks that the certificate signs in, and reads the registration with a test sign-in to report every
  setting (account types, redirect URI, permissions, certificate, no client secret) in plain words.
- Repair a tenant's connection with a Microsoft sign-in: Vaulty puts back a removed app registration, its certificate
  and missing permissions, optionally with the restore permissions.
- Vaulty renews certificates itself 60 days before they expire, for tenants whose app it knows and for the setup app:
  it adds the new certificate with a proof signed by the current one, switches only once the new one signs in, and
  then removes the old key. "Rotate certificate" does the same; when Microsoft refuses, the script is shown.

- A redesigned web interface built on one set of shared components (page header with breadcrumbs, sections, status
  chips that say what happened, data tables with search, filters, sorting and loading, empty and error states,
  confirmation dialogs that announce "Confirm it's you", wizard steps). Text is 14px, every chip meets WCAG AA
  contrast, focus is always visible and the menu folds away on smaller screens.
- A search field in the top bar of every page (press `/` or Ctrl+K) that finds customers, tenants and mailboxes or
  OneDrives at once and searches messages and files on Enter. The search page groups names and items.
- The dashboard starts with what needs attention: exact counts, one row per problem (a tenant that lost consent, a
  failed or partial protected object) with what happened, what to do and a direct action, open alerts with a link to
  the affected tenant or object, then the customer, tenant and object rollup with only what needs attention open.
- Restore and export as a four-step wizard (what, snapshot, where to, confirm) with a restore folder as the default, a
  summary before anything starts and the limits where they apply. After "Confirm it's you" the restore starts without
  choosing again. The restore page states the outcome in one sentence and can show only failed or skipped items.
- A protected object lists the items its latest partial snapshot misses, grouped by reason, with what to do.
- Connecting a tenant is a guided page with steps; what was entered survives "Confirm it's you", and the tenant page
  shows a set-up checklist afterwards. The tenant page has tabs for protected objects, policy, connection, and legal
  hold and deletion; policy frequency and retention are chosen in plain words.
- A printable protection report per customer (print or save as PDF) to send to the customer.
- Confirmation before excluding objects, releasing a legal hold, shortening retention, deleting a tenant (type its
  name), deleting a webhook, removing a role and cancelling a job or restore.

- A job reconciler in the worker compares open backup and discovery jobs with the workflow engine every two minutes. A
  job whose workflow ended without recording it (terminated, timed out, removed) is closed with its staged snapshot,
  and raises a backup alert when it failed. A workflow whose task keeps failing is marked stuck on the jobs page and
  raises an alert instead of showing "Running" for good; when someone asked to cancel it, the reconciler stops it,
  because a stuck workflow cannot process that request itself. A cancellation that went to a run that no longer exists
  (older versions could record the run of a child step) is sent to the job's real run.
- Workflow changes are versioned: a change to the commands a workflow issues sits behind a marker, so a run that was
  going during an update replays its old path. A replay test checks recorded histories of earlier versions against the
  current code. The first marker covers the change that stopped child steps writing their parent's job, which left
  OneDrive backups that were running during that update stuck; after this update they continue (and stop, when asked).
- Excluding objects asks for confirmation, stops their running backups and settles their open failed, partial and
  missed backup alerts; the minute sweep settles them too for objects excluded earlier. The excluded status says its
  snapshots end with their retention and the data is then removed.
- Search and filter: on the tenant page by name or e-mail address, type and status, and the selection buttons act on
  the objects shown; on the jobs page by object, tenant or request ID, and by tenant, next to status and type.
- Running backups and discoveries can be cancelled from the jobs page, by anyone who may run backups; audited. A
  cancelled backup closes its snapshot (it never stays staged), raises no alert, and the next planned run starts as
  usual; a job that had not started yet is cancelled at once.
- A running first backup shows a progress bar with the share done and an estimate of the time left, from its own pace
  so far (which already reflects bandwidth, host load and other running backups); mailboxes count items, OneDrives
  bytes. The bar carries its percentage, the line below it what is done of the total ("4,431 / 10,547 items
  processed") and the time left with the expected finish ("about 1 h 20 min left · done around 14:35"). A run without a
  known total (an incremental run) shows the items processed so far. The jobs page refreshes running jobs every 15 seconds.
- Choose which mailboxes and OneDrives are backed up: a switch per protected object, "back up all" (all, mailboxes,
  OneDrives) and "exclude all" on the tenant page, and per tenant whether newly found ones are backed up at once or wait
  to be selected (the default; migration `0015`). An excluded object gets no new backups; all its snapshots, the newest too,
  end with their retention, and garbage collection removes the data once its Object Lock has ended (the tenant page
  shows from when); selecting it again before then keeps everything; excluding, or no longer backing up new ones automatically, needs a fresh confirmation and is
  audited. Excluded objects show as "Excluded", never as protected, and do not decide a tenant's status.
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

- Refreshing a session after the periodic security check kept the user's claims but restarted the session's own: the
  8-hour session limit counted from the last check instead of from the sign-in. The sign-in time, sign-in method and
  step-up time now carry over.
- Opening the second-factor set-up page created the authenticator key in a way that changed the account's security
  stamp, which ended the session at its next check while the user was still scanning the code.
- A second certificate rotation of a tenant wrote the new certificate over the one in use, before the new one was
  proven to work: after a rotation the current certificate had the name the next one was given. Every certificate now
  has its own name.
- The memory limits of the Vaulty services take effect: the installer wrote them as "680MB", which systemd does not
  parse and ignored. Units now get "680M" or "2G"; an update rewrites them, and the installer test checks that every
  service has a limit.
- The installer tries the package mirror again (up to three more times) when it cannot be reached, so a passing DNS or
  mirror failure on a fresh host no longer stops an installation; any other package failure still stops at once.
- Two test dependencies with a known denial-of-service issue are on fixed versions (`System.Formats.Cbor` 10.0.15, and
  `Microsoft.AspNetCore.WebUtilities` 2.3.14 pinned above what the HTTP mock brings in); the dependency check is green.
- Switches show their state at a glance: on is a solid track in the switch colour, off a grey one.
- The jobs page no longer lists records of runs that never began because one of the same object or tenant was already
  running (the records stay in the database).
- "Cancel" says when the request did not reach the job's run, instead of reporting a cancellation that never happened;
  the request is kept with the job for the reconciler. "About less than a minute left" reads "Less than a minute left".
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
- A OneDrive backup's job shows the outcome of the whole backup: its sync step, a child workflow with the same input,
  marked the job as succeeded without counts before the backup had committed, so a partial or failed drive backup
  could show as succeeded. Only the workflow that owns a job writes it now.
- A protected object without any snapshot is "awaiting first backup" for at most twice its backup interval (at least a
  day); after that it is failed, so a first backup that never runs is no longer a quiet wait. A tenant that waits for
  first backups says how many of its protected objects already have a snapshot.
- The menu and the users page no longer empty themselves for a moment when a page becomes interactive: what the
  prerendered page loaded is carried over to the circuit.
- The installation wizard asks for the host's time zone (default: the current one) and repeats the chosen environment
  on screen; a time zone in the answers file must exist in the host's zone database.
- Layout: body text at 15px, wider content (up to 1600px, 1800px on large screens), more room in panels and table rows,
  quieter table headers and one corner radius for tables, buttons and inputs, after the sibling product's style; simple
  key/value tables inside a panel stay flat.
- Detail pages (customer, tenant, protected object, snapshot, restore) show a loading bar while they load, instead of
  saying for a moment that the item does not exist.
- Status chips, table buttons and backup times stay on one line in tables; names keep whole words and get room, and a
  table wider than its frame scrolls sideways instead of cutting off its last column.
- A protected object waiting for a free place within its tenant's budget of concurrent backups (20 mailboxes, 10
  drives) is queued, not a missed run; a missed-run alert is settled as soon as the backup starts, and its text names
  the worker service and object storage as the causes to check.
- The jobs page shows for a running backup how many items it has stored so far, so a long first backup is visibly
  moving.
- Every backup after an object's first one starts again: the jobs table required a unique workflow id, while every
  run of an object uses the same one, so recording the start of a second run failed and was retried forever. Jobs are
  unique on their workflow run instead (migration `0014`). The test harness now uses the production workflow id.
- Committing a mailbox or drive snapshot heartbeats while it runs: a commit longer than the heartbeat timeout was
  declared dead and started again while still running, and failed the backup after its retries.
- The scheduler records no job for an object whose backup is still running, instead of a job cancelled at once.
- The installer prints `[ ok ]` when a step finishes.
- The installer test opens the sign-in page through Caddy and checks the https redirect, every linked stylesheet and
  that a query string never reaches the access log.
