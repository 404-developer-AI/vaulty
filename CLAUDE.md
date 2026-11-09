# CLAUDE.md — Vaulty

Vaulty is the Microsoft 365 backup platform for managed service providers (MSPs) by Steaan: one portal, many
customer tenants, an independent and immutable copy of mailboxes, files, sites and the directory, stored in the EU,
verified, and reported honestly. This file is the starting point for all development work in this repository.

## Two repositories, one rule

- **This repository (`vaulty`) is public.** It holds code, tests, the installer templates under `deploy/`, this
  file and a short README. Nothing else.
- **`vaulty-internal` is private** and lives next to this checkout at `C:\Development\vaulty-internal`. It holds all
  design documents (`MD-DOCS/`), decisions, the roadmap and build plan, spike reports, runbooks, branding and the
  list of confidential terms. Read from it freely; **never copy text, names, numbers or paths from it into this
  repository**, not in code, comments, tests, fixtures, commit messages or issues. When something from a design
  document needs to be in code, write it in your own words and in generic terms.
- The pre-commit and pre-push hooks (`.githooks/`, install with `bash .githooks/install.sh`) and a required CI check
  block secrets, internal paths and confidential terms. Never bypass them (`--no-verify` is not allowed towards the
  public remote).
- `vaulty-internal/NOTFORCLAUDE.MD` is the developer's private notes file. Never open, search or quote it.

## Where the plan is

The build plan is `vaulty-internal/MD-DOCS/07-roadmap.md`: decisions, working method, and the work packages of
phase 0 and phase 1 with their acceptance criteria. Start a run by reading the plan in full, then build the work
packages in order, reading the document sections each one references. `vaulty-internal/MD-DOCS/README.md` is the index of the design
documents.

## Working agreements

- **Language**: conversation with the developer is in Dutch. Code, comments, commit messages, log messages, UI text
  and everything in this repository are in English. Read `vaulty-internal/MD-DOCS/branding-vaulty.md` before writing
  any user-visible text; its vocabulary is binding (organization, customer, tenant, protected object, snapshot,
  item, partial, verified, restore, export, retention, legal hold).
- **One continuous run up to the alpha.** The developer asks for all work packages up to the release pipeline in one
  go. Build each one completely (code, tests, documentation, `CHANGELOG.md`), run `dotnet build` and `dotnet test`,
  execute its acceptance checks, report per criterion what is green and what is not, commit it (see Git) and continue
  with the next. Criteria marked "alfa" in the plan need the real object storage account or the real test tenant and
  are checked later on the test host; everything else is proven against the in-memory object store, WireMock and
  the local PostgreSQL and Temporal dev server. A failing crash-injection or worker-kill test is the only hard stop.
- **Git**: ask once at the start of a run for permission to commit each finished work package locally; always ask
  before pushing or tagging. No intermediate commits while a work package is being built. Conventional Commits. Default branch `main`. Public GitHub repository `404-developer-AI/vaulty`.
- **License**: Business Source License 1.1 (`LICENSE`): non-production use is granted, production use only by Steaan,
  each published version turns into Apache-2.0 on its Change Date.
- **Reuse from Fleeto** (`C:\Development\Fleeto`, the sibling RMM product, same company, same stack) is allowed and
  encouraged: Identity and two-factor set-up, theme and design tokens (`--mg-` becomes `--vy-`), layout, security
  middleware, CI and release patterns. Adapt, do not copy blindly, and never let Fleeto vocabulary ("client",
  "device", "endpoint", "machine") into Vaulty text. `deploy/ci/branding-check.sh` enforces this in CI.
- **Secrets never enter the repository**, not even in example files with real values. Configuration examples use
  fictitious values (`example.com`, `EXAMPLEACCESSKEY`).
- **Documentation in this repository** is limited to `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
  `docs/format/` (the public specification of the repository format and key derivations, with test vectors) and
  `deploy/install/README.md`. Everything else belongs in `vaulty-internal`.

## Priorities (in this order)

1. **Security and reliability.** A backup product is a top-tier target and a backup that cannot be restored is silent
   data loss. Assume breach. Per-tenant encryption, immutable storage, least privilege towards Microsoft 365, full
   audit trail. Every backup is counted per item and verified; `partial` is a first-class state and is never shown
   as green.
2. **Performance.** Throttling by Microsoft Graph is normal behaviour, never an error: honour `Retry-After`, budget
   per tenant, at most 4 concurrent requests per mailbox, incremental forever with delta tokens, fair scheduling so
   one large tenant never slows a small one.
3. **Everything else.** UI polish, integrations, white-label and reports come after 1 and 2 are demonstrably true.

When these conflict, the higher one wins. When in doubt, ask before implementing.

## Stack

| Layer | Choice |
|---|---|
| Language | C# 14 on .NET 10 LTS for every service, worker and CLI; `global.json` pins the SDK |
| Web | ASP.NET Core, Blazor Web App (Interactive Server), MudBlazor; tokens prefixed `--vy-` |
| API | ASP.NET Core Minimal APIs, OpenAPI 3.1, `/api/v1` |
| Orchestration | Temporal (self-hosted, PostgreSQL backend) with the Temporalio .NET SDK; local development uses the Temporal CLI dev server, no Docker |
| Database | PostgreSQL 17, EF Core for schema and CRUD, Dapper for hot paths, row-level security on every tenant table, `items` and `chunk_index` partitioned by tenant hash |
| Object storage | S3-compatible with Object Lock (compliance mode) behind `IObjectStore`; one S3 adapter on the AWS SDK for .NET; an in-memory store for unit tests |
| Crypto | .NET `AesGcm`, keyed BLAKE3 for chunk ids, HKDF, zstd compression; no home-made primitives |
| Key management | Envelope encryption: per-tenant DEK wrapped by a KEK behind `IKeyWrapper`; software wrapper first, HSM adapter later |
| Secrets on a host | One master key per host as an encrypted systemd credential; all other secrets AES-GCM encrypted in PostgreSQL (`ISecretStore`); never in environment variables or files |
| Microsoft Graph | Graph SDK models only; own `HttpClient` pipeline with handlers for certificate auth per tenant, throttling, decoration, telemetry and delta handling; Graph only, no EWS |
| Identity | ASP.NET Core Identity with passkeys and TOTP (no SMS, no e-mail OTP); Entra ID SSO later |
| Observability | OpenTelemetry (traces, metrics, structured logs without customer data) |
| Tests | xUnit, FsCheck, WireMock.Net, PostgreSQL 17 (local service or CI container), Temporal CLI dev server, Playwright later |
| Deployment | One interactive installer and updater (`vaulty` CLI, project `Vaulty.Cli`) on Ubuntu 24.04 LTS: services native under systemd with self-contained binaries, PostgreSQL native with peer authentication, only Temporal and Valkey in containers; templates in `deploy/install/` |
| Releases | GitHub Actions on `v*` tags: signed tarball (cosign keyless), `SHA256SUMS`, SBOM; `deploy/install/get-vaulty.sh` verifies before installing |

## Solution layout (`Vaulty.slnx`)

```
src/
  Vaulty.Core/                 domain, interfaces, permissions catalog, state machines
  Vaulty.Infrastructure/       PostgreSQL (EF Core + Dapper), object store adapters, key wrapper, secret store
  Vaulty.Graph/                Graph client core: auth, throttling, delta, batching, telemetry
  Vaulty.Connectors.Exchange/  mailboxes: folders, mail, calendar, contacts, tasks
  Vaulty.Connectors.Drive/     OneDrive and SharePoint libraries
  Vaulty.Connectors.SharePoint/  (phase 2)
  Vaulty.Connectors.Entra/       (phase 2)
  Vaulty.Connectors.Teams/       (phase 4)
  Vaulty.Repository/           chunking, dedup, compression, encryption, packs, manifests, snapshots, verify
  Vaulty.Workflows/            Temporal workflows and activities
  Vaulty.Workers/              worker host
  Vaulty.Api/                  REST API, OpenAPI, webhooks
  Vaulty.Web/                  Blazor + MudBlazor
  Vaulty.Migrate/              database migrations (runs as a systemd oneshot)
  Vaulty.Recover/              stand-alone recovery CLI: restores a tenant from object storage without PostgreSQL
  Vaulty.Cli/                  installer, updater and host management (`vaulty`)
tests/
  Vaulty.Core.Tests/  Vaulty.Repository.Tests/  Vaulty.Graph.Tests/  Vaulty.Integration.Tests/
tools/
  Vaulty.TestData/             seeder for edge cases in a test tenant
deploy/
  install/                     bootstrap script, systemd, Caddy, PostgreSQL, Compose and report templates
  ci/                          branding-check.sh and other CI helpers
docs/
  format/                      public specification of the repository format and key derivations
```

Naming: namespaces `Vaulty.*`, database `vaulty`, roles `vaulty_api`, `vaulty_worker`, `vaulty_gc`,
`vaulty_migrator`, OS users `vaulty-web`, `vaulty-api`, `vaulty-worker`, `vaulty-gc`, `vaulty-migrator`,
environment prefix `VAULTY_`, configuration sections `Vaulty__...`, object keys `tenants/{tenant_id}/...`.

## Product model

```
Organization (one MSP or IT team; never sees another organization)
└── Customer (customer code + customer name, tags)
    └── Tenant (one Microsoft 365 / Entra ID tenant; auth mode, consent state, health)
        ├── Policy (scope, frequency, retention, legal hold; the most specific one applies)
        └── Protected object (mailbox | drive | site | team | directory)
            └── Snapshot (point in time; succeeded | partial | failed; exact item counts; verified at)
                └── Items → chunks (content-addressed, encrypted per tenant, append-only, immutable)
```

- Access to a tenant in phase 1 is a **dedicated app registration inside the customer's tenant**, authenticated
  with a certificate that Vaulty generates per tenant (private key in the encrypted secret store). A shared
  multi-tenant app with an admin-consent flow comes in phase 2.
- **Everything an administrator configures is configured in the UI**, never through the CLI or a file: the object
  storage account (a setup assistant creates the buckets with Object Lock and the per-role IAM users, or accepts
  existing ones, and tests each identity), the app registration per tenant (certificate, script, tenant and client
  id, permission probe, rotation), SMTP and webhooks. The installer only asks what the host itself needs.
- A protected object stays protected after its source disappears from Microsoft 365 (`source deleted`); retention
  keeps running.
- Nothing in the platform can change or delete backup data within its retention: Object Lock on every pack, index,
  manifest and snapshot; workers have no delete right; garbage collection runs under its own identity on expired
  locks only; deleting a tenant is a soft delete with a 30-day wait and a second administrator.
- Restores never send calendar invitations, never overwrite newer files without an explicit choice, and go to a
  restore folder by default. Teams messages are preserved, searchable and exportable, never "restored".

## Versioning and changelog

Semantic versioning `MAJOR.MINOR.PATCH`, tags `vX.Y.Z`, pre-release builds `vX.Y.Z-alpha.N` for tests on the test
host. Phase 0 and phase 1 together are **0.1.0**; there are no tags before `v0.1.0-alpha.1`. `CHANGELOG.md` follows
Keep a Changelog: `Unreleased` on top, then the two most recent released versions; older entries move to
`CHANGELOG-ARCHIVE.md`. Every work package updates `Unreleased` in the same commit.

## Quality gates (CI)

Build and tests on every pull request; property-based tests of the repository engine; roundtrip and crash-injection
tests; Graph contract tests against recorded responses; CodeQL, dependency scanning, secret scanning; the
confidentiality check (`.githooks/confidentiality-scan.sh --range`) and the branding check as required status checks;
an installer job on an `ubuntu-24.04` runner that installs, updates, rolls back and uninstalls a build; releases
signed with cosign. Nothing that needs real tenants or real buckets runs with public logs.

## Local development

- Windows with the .NET 10 SDK, PostgreSQL 17 as a local service (connection via `VAULTY_TEST_PG`), the Temporal CLI
  (`temporal server start-dev`) and no Docker. Object storage integration tests use a development bucket whose
  credentials live in user secrets, never in the repository.
- The development master key lives outside the repository (see `Vaulty.Infrastructure` `IMasterKeySource`).
- `dotnet build`, `dotnet test`, `bash deploy/ci/branding-check.sh`, `bash .githooks/confidentiality-scan.sh --staged`.
