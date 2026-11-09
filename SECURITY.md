# Security policy

Vaulty holds copies of the mailboxes, files and directory of the Microsoft 365 tenants it protects. A vulnerability
here can expose data from many organizations at once, so reports are welcome and handled with priority.

## Reporting a vulnerability

Use **Report a vulnerability** under the Security tab of this repository (GitHub private vulnerability reporting). The
report stays private between you and Steaan until a fix is released.

Please do not open a public issue or pull request for a security problem, and only test against an installation you
run yourself, with a Microsoft 365 test tenant and storage account that you own.

A useful report states what an attacker can do, which component is affected (web, API, workers, repository format,
recovery CLI, installer or release verification), the version or commit you looked at, and the steps to reproduce it.

We aim to acknowledge a report within three working days and to keep you informed until it is fixed or explained.

## Supported versions

Vaulty is at `0.x`: only the latest release is supported. Fixes go into the next release.

## Scope

In scope: authentication, authorization and isolation between organizations and tenants; the repository format,
encryption and key handling; immutability of stored data; the handling of Microsoft 365 credentials; restore and export
paths; the installer, updater and release signature verification; the recovery CLI.

Out of scope: attacks that require an attacker to already hold the host master key or root on the host, and findings in
third-party products Vaulty depends on (report those to their vendor).
