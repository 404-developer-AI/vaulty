# Vaulty

Vaulty backs up Microsoft 365 tenants (mailboxes, files, sites and the directory) for managed service providers to
immutable, encrypted object storage, verifies that every backup can be restored, and reports exactly what it did.
Vaulty is made by Steaan.

## Build and test

Requirements: the .NET 10 SDK (see `global.json`), PostgreSQL 17 and the Temporal CLI for the integration tests.

```
dotnet build Vaulty.slnx
dotnet test Vaulty.slnx
```

Tests that need PostgreSQL read the connection string from `VAULTY_TEST_PG`; they are skipped when it is not set.
Tests that need Temporal start the Temporal CLI dev server when `temporal` is on the `PATH`.

The repository format and key derivations are specified in [`docs/format/`](docs/format/).

## License

[Business Source License 1.1](LICENSE): non-production use is permitted; each version converts to the Apache License
2.0 on its Change Date. See [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request and
[SECURITY.md](SECURITY.md) to report a vulnerability.
