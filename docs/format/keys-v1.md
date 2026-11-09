# Vaulty key derivations and wrapped keys, version 1

This document specifies how Vaulty derives and wraps keys. It contains no keys. Every value below is a test vector
that the test suite checks (`tests/Vaulty.Core.Tests/CryptoTests.cs`); a change to any of them is a format change.

Notation: `‖` is concatenation, `0x1F` is the unit separator byte, integers are big-endian, a UUID is written as its
16 bytes in RFC 4122 order (the order of its text form), strings are UTF-8 (labels are ASCII).

## 1. Hierarchy

```
host master key (32 bytes, systemd credential)
├── secrets          HKDF → AES-256-GCM key for the secrets table
├── dataprotection   HKDF → AES-256-GCM key for the web session key ring
├── export           HKDF → AES-256-GCM key for an export of the secrets store
└── kek              HKDF → key encryption key of the software key wrapper
                            └── tenant data key (32 random bytes per tenant and version, stored wrapped)
                                 ├── object:<id>   HKDF → key of one protected object
                                 ├── chunk-id      HKDF → key of the keyed BLAKE3 chunk ids
                                 ├── metadata      HKDF → key for item metadata in the database
                                 └── repository    HKDF → key for indexes, manifests and snapshots
```

All derivations are HKDF-SHA256 (RFC 5869) with a 32-byte output.

| Level | Input key material | Salt | Info |
|---|---|---|---|
| Host | master key | `vaulty-host-keys-v1` | `secrets`, `dataprotection`, `export` or `kek` |
| Tenant | tenant data key | `vaulty-tenant-keys-v1` | `object:` ‖ object UUID (16 bytes), `chunk-id`, `metadata` or `repository` |

A protected object whose id is on the tombstone list is never derived again (crypto-shredding): its data stays in
immutable storage until the lock expires, but nobody can read it.

## 2. Wrapped tenant data key

```
offset  size  field
0       4     magic "VYKW"
4       1     format version = 1
5       1     wrapper type (1 = software key wrapper)
6       4     KEK version (uint32 BE; the master key version for the software wrapper)
10      12    nonce
22      n     ciphertext (n = 32 for a data key)
22+n    16    GCM tag
```

Cipher: AES-256-GCM with the `kek` key. Authenticated data: the 10 header bytes ‖ tenant UUID (16 bytes) ‖ data key
version (uint32 BE). A wrapped key copied to another tenant or version fails authentication. Other wrapper types (a
hardware security module) use the same header with their own type number.

The wrapped key is stored in the database and as `tenants/{tenant_id}/keys/dek-{version}.json` in object storage, so a
tenant can be recovered without the database.

## 3. Sealed secrets

Each row of the secrets table holds nonce (12 bytes), ciphertext and tag (16 bytes) of AES-256-GCM with the `secrets`
key. Authenticated data: `vaulty-secret-v1` ‖ 0x1F ‖ name ‖ 0x1F ‖ version (decimal) ‖ 0x1F ‖ host id. A row copied to
another name, version or host does not decrypt.

## 4. Session key ring

Each key of the web session key ring is stored as nonce (12) ‖ ciphertext ‖ tag (16), AES-256-GCM with the
`dataprotection` key, authenticated data `vaulty-dataprotection-v1` ‖ 0x1F ‖ key name.

## 5. Test vectors

Inputs:

- master key: bytes `00 01 02 … 1f`
- tenant data key used for derivations: bytes `20 21 22 … 3f`
- object UUID and tenant UUID: `11111111-2222-3333-4444-555555555555`

Host keys:

| Info | Output |
|---|---|
| `secrets` | `e7501eceb1bd56f0d9469aa832dbd684522b11d17b101b4ba2a7c1a917edc0f6` |
| `dataprotection` | `d6bf680bcb637361f8c2faa3a56b938a05505d03796dc263922f59a8c5d6a8f1` |
| `export` | `b55e52dd842817edc472b4cdc5804833f8c023f353042baba68d999758423d93` |
| `kek` | `506e16cd548a7119ca2096991643722562a50a8c12cc68f15e57c1458f8ab2d5` |

Tenant keys:

| Info | Output |
|---|---|
| `object:` ‖ UUID | `f10f280b566035337a064dd513984cb5985a687b061e5d99b1be1ae266219d66` |
| `chunk-id` | `732fc2a0a43302c95099357f56a7b9dde2b8ef385d2b8f2016fb9b4da0c64967` |
| `metadata` | `f50b5ec5bef1706a753148adbf9f6ac4fd42eda7ee61daa8655c6251c0d49af3` |
| `repository` | `54af3c9a5cbb9b936bec6944cd2e7d02d5e38f3180f4506537a88407d18c4685` |

Wrapped key: data key `40 41 … 5f`, tenant UUID as above, data key version 1, KEK version 1, nonce `a0 a1 … ab`:

```
56594b57010100000001a0a1a2a3a4a5a6a7a8a9aaab573ed73c913e2955df41983e6218b478bfaf2e22e7e5cffe74ee5e673eb8a3594c37704dfea8d64de729640cd9cfc212
```

Sealed secret: name `smtp.password`, version 1, host id `host-a`, value `correct horse`, nonce `00 01 … 0b`;
ciphertext ‖ tag:

```
bff76430a22b20b0f92209bafdf383c7321ff810aff472a2f9fa470976
```
