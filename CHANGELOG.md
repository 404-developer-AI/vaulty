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
