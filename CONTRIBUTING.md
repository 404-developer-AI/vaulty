# Contributing to Vaulty

Thank you for your interest. Vaulty is source-available under the [Business Source License 1.1](LICENSE).

## License of contributions

By submitting a pull request you agree that your contribution is licensed to Steaan under the same terms as the
project (BSL 1.1, converting to Apache License 2.0 on the Change Date of the version it ships in), and that Steaan may
also license it under other terms, including commercial ones. You confirm that you wrote the contribution yourself or
have the right to submit it.

## Before you open a pull request

- Run `bash .githooks/install.sh` once. The hooks block secrets and identifying data from being committed.
- Run `dotnet build Vaulty.slnx`, `dotnet test Vaulty.slnx` and `bash deploy/ci/branding-check.sh`.
- Use [Conventional Commits](https://www.conventionalcommits.org/) and add a line to `CHANGELOG.md` under `Unreleased`.
- Describe the change, not the situation that led to it.

## Never include real data

No tenant names or IDs, user names, e-mail addresses, file names, logs or screenshots from a real Microsoft 365 tenant
or storage account, not in code, tests, fixtures, issues or pull requests. Use `contoso.example` and `example.com`.

Security problems are reported privately, see [SECURITY.md](SECURITY.md).
