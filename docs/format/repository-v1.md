# Vaulty repository format, version 1

This document specifies how Vaulty stores backup data in object storage, so that the data can be read without the
Vaulty database and without Vaulty itself. Keys and their derivations are specified in [keys-v1.md](keys-v1.md).
Golden files of a small repository written with fixed keys are in `tests/Vaulty.Repository.Tests/Golden/v1`; every
future version of Vaulty must read them.

Notation: integers are big-endian, a UUID is 16 bytes in RFC 4122 order, strings are UTF-8 with a 4-byte length
prefix, `‖` is concatenation.

## 1. Principles

- **Content-addressed**: chunks are identified by keyed BLAKE3 of their plaintext; packs by the SHA-256 of the file;
  indexes, manifests and snapshots by keyed BLAKE3 of their body. Writing the same content twice produces the same
  object, so a retried or crashed write is harmless.
- **Append-only and immutable**: every object except `LATEST` is written once, with Object Lock in compliance mode
  until the end of its retention plus a margin.
- **Encrypted per tenant**: AES-256-GCM with keys derived from the tenant data key. Deduplication happens only within
  a tenant.
- **Verifiable**: every chunk is checked against its id after decryption, every item against its content hash, every
  snapshot against the Merkle root of its manifests.
- **Versioned**: every structure carries a format version. Readers read all versions; writers never write ahead.

## 2. Layout

```
tenants/{tenant}/keys/dek-{version}.json                      wrapped data key (keys-v1.md §2)
tenants/{tenant}/packs/{h[0..2]}/{h}.pack                      h = hex SHA-256 of the pack file
tenants/{tenant}/indexes/{h}.idx                               index of pack h (sealed blob)
tenants/{tenant}/manifests/{m[0..2]}/{m}.manifest              m = hex blob id (sealed blob)
tenants/{tenant}/snapshots/{object}/{snapshot}.snap            snapshot root (sealed blob)
tenants/{tenant}/snapshots/{object}/LATEST                     id of the newest snapshot, text; mutable, a cache only
organizations/{organization}/audit/anchors/{yyyy-mm-dd}.json   daily audit chain anchor
```

## 3. Chunks and packs

**Chunking.** FastCDC with normalized chunking: minimum 256 KiB, average 1 MiB, maximum 4 MiB. Content shorter than
the minimum is one chunk. The rolling hash is `h = (h << 1) + Gear[byte]` (64-bit, wrapping), starting at zero at the
minimum size of each chunk. Up to the average size a boundary is placed after the first byte where
`h & maskS == 0`, after it where `h & maskL == 0`; at the maximum size a boundary is forced. With `b = log2(average)`,
`maskS` has the top `b + 2` bits set and `maskL` the top `b − 2` bits. The Gear table is 256 outputs of SplitMix64
seeded with `0x5641554c54590001`: for each entry `state += 0x9E3779B97F4A7C15`, then
`z = state; z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9; z = (z ^ (z >> 27)) * 0x94D049BB133111EB; z ^ (z >> 31)`.

**Chunk id.** Keyed BLAKE3 (32 bytes) of the plaintext with the tenant `chunk-id` key.

**Chunk record.**

```
offset  size  field
0       32    chunk id
32      1     flags (bit 0: zstd compressed; other bits zero)
33      4     data key version
37      4     plaintext length
41      4     stored length n (ciphertext including the 16-byte tag)
45      n     ciphertext ‖ tag
```

The plaintext is compressed with zstd level 3 when the result is smaller than 97 % of the plaintext. It is then
encrypted with AES-256-GCM under the data key of the stated version. Nonce: the first 12 bytes of the chunk id.
Authenticated data: tenant UUID ‖ chunk id ‖ format version (`01`) ‖ flags ‖ data key version.

A deterministic nonce is safe here because it is derived from the plaintext under a separate key: the same nonce is
only ever used for the same plaintext (which then encrypts to the same bytes), and two different plaintexts share a
nonce only if their keyed hashes collide in 96 bits. It makes chunk writes idempotent and needs no shared counter
between workers.

**Pack file.**

```
header   "VYPK" | 01 | 00 00 00 | tenant UUID                          24 bytes
records  chunk records, back to back
trailer  "VYPE" | record count (4) | SHA-256 of header and records      40 bytes
```

Packs are 16–64 MB. A pack holds only chunks of one tenant.

## 4. Sealed blobs

Indexes, manifests and snapshots are stored as sealed blobs:

```
offset  size  field
0       4     "VYBL"
4       1     format version (01)
5       1     type (1 index, 2 manifest, 3 snapshot)
6       1     key scope (0 tenant repository key, 1 protected object key)
7       4     data key version
11      16    protected object UUID (zero for scope 0)
27      32    blob id
59      n     ciphertext ‖ tag
```

The body is compressed with zstd level 3 and encrypted with AES-256-GCM. Blob id: keyed BLAKE3 with the `chunk-id`
key over type ‖ body. Nonce: the first 12 bytes of the blob id. Authenticated data: the 59-byte header ‖ tenant UUID.
Key: `repository` key of the stated data key version for scope 0, the `object:` key of the protected object for
scope 1. A protected object whose key is destroyed (crypto-shredding) loses its manifests and snapshots; chunks shared
with other objects stay readable for those objects.

## 5. Index body

```
"VYIX" | 01 | pack SHA-256 (32) | entry count (4) | entries
entry: chunk id (32) | record offset in the pack (8) | record length (4) | plaintext length (4)
```

## 6. Manifest body

The items of one folder or drive part at the time of a snapshot.

```
"VYMF" | 01 | protected object UUID | entry count (4) | entries
entry: source id (string) | has parent (1) | parent source id (string, empty if none) | kind (string)
       | metadata (string, JSON) | has content (1) | [content]
content: size (8) | content hash (32) | chunk count (4) | chunk ids (32 each)
```

The content hash is keyed BLAKE3 (`chunk-id` key) of the item's complete plaintext.

The metadata JSON object may hold the reserved key `_vaulty` with what a restore needs beyond the metadata itself, so
object storage alone is enough to rebuild an item (all fields optional):

```json
"_vaulty": {
  "modified_at": "2026-11-10T08:00:00.0000000Z",
  "limited_fidelity": true,
  "preview": { "size": 1234, "hash": "<64 hex>", "type": "text/html", "chunks": ["<64 hex>", "..."] }
}
```

`preview` references a separately stored rendition of the item (the body of a message), chunked and encrypted like any
content; `limited_fidelity` marks content that is a MIME copy instead of the source's own export format. Readers ignore
unknown fields inside `_vaulty` and remove the key before showing or exporting metadata. Adding it changed no byte of
the binary layout; manifests without it stay valid.

## 7. Snapshot body

```
"VYSN" | 01 | tenant UUID | protected object UUID | snapshot UUID | created at (8, microseconds since 1970 UTC)
| outcome (1: committed, 2: partial) | counts (string, JSON) | exceptions (string, JSON)
| manifest count (4) | manifest ids (32 each) | Merkle root (32)
```

Merkle root over the manifest ids in order: leaf = SHA-256(`00` ‖ id), node = SHA-256(`01` ‖ left ‖ right), an odd
node is promoted unchanged, the root of an empty list is SHA-256 of the empty string. A partial snapshot lists the
missing items with their reasons in `exceptions`.

## 8. Write order and recovery

A backup writes, in this order: packs, the index of each pack, then the chunk index in the database; manifests (only
after the packs they reference); the snapshot root; finally `LATEST`. The snapshot root is the commit point. A reader
that starts from object storage alone lists `indexes/` to rebuild the chunk index, lists `snapshots/{object}/` to find
snapshots, and ignores packs that no index references (left by a crash before the index was written; removed by
garbage collection once their lock expires).

`vaulty-recover` (project `Vaulty.Recover`) is this reader: with read access to the bucket (or a local copy), the data
key files under `keys/` and the host master key it unwraps the keys, rebuilds the index, picks the newest committed or
partial snapshot of every protected object and writes each item exactly as an export through the platform does,
authenticating every chunk and checking every content hash on the way.

## 9. Test vectors

With the data key `40 41 … 5f` (version 1) and tenant `11111111-2222-3333-4444-555555555555`:

- chunk id of the ASCII text `Vaulty repository format v1`:
  `397a10e74b0583651edcae8022cda24995f8b3ab71991a44d108f12a27acf074`
- its chunk record:
  `397a10e74b0583651edcae8022cda24995f8b3ab71991a44d108f12a27acf07400000000010000001b0000002bdd6207ad3fdcf78f65f01ffa3b47e011a938819bdf5a38c08e07bf88093ac9dc3ddc2522277888ee115d74`
- the golden repository's snapshot Merkle root:
  `fea422bbedef3dd790548ff9376575b353fe2343488d271decc84c8972d0fd59`
