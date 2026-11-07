# @cipherdrop/crypto

All of CipherDrop's end-to-end cryptography, in one isomorphic package. The same source runs unchanged in browsers, Web Workers and Node 22. It uses only `globalThis.crypto.subtle` (AES-256-GCM, HKDF-SHA-256, SHA-256), `crypto.getRandomValues`, and Argon2id from `hash-wasm`. No primitive is home-made: the custom part is the construction below, which is normative in `docs/DESIGN.md` section 7.

## Key hierarchy

```
drop key DK (32 random bytes; travels in the link #fragment, or wrapped under a password)
 |- fileKey(f)  = HKDF(DK, salt = fileId(f) bytes, "cipherdrop/v1/file-key")  -> STREAM chunks of file f
 '- manifestKey = HKDF(DK, salt = empty, "cipherdrop/v1/manifest-key")        -> encryptedManifest

password drop:  pk = Argon2id(NFKC(password), salt16, kdf)
 |- wrapKey = HKDF(pk, "cipherdrop/v1/drop-password-wrap") -> wrappedDropKey = wrap(wrapKey, DK, wrap/drop-password)
 '- authKey = HKDF-bits(pk, "cipherdrop/v1/drop-password-auth", 256) -> server keeps b64url(SHA-256(authKey))

account:        mk = Argon2id(NFKC(password), salt16, kdf)
 |- encKey  = HKDF(mk, "cipherdrop/v1/account-enc")  -> wrappedAccountKey = wrap(encKey, AK, wrap/account)
 '- authKey = HKDF-bits(mk, "cipherdrop/v1/account-auth", 256) -> server keeps Argon2id_server(authKey)

account key AK (32 random bytes; never changes, lives only in memory as a non-extractable CryptoKey)
 '- ownerWrappedKey = wrap(AK, DK, wrap/owner), one per drop: rebuilds links on any device

recovery key RK (20 random bytes, shown as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX)
 |- recoveryEnc  = HKDF(RK, "cipherdrop/v1/recovery-enc")  -> wrappedAccountKeyRecovery = wrap(recoveryEnc, AK, wrap/recovery)
 '- recoveryAuth = HKDF-bits(RK, "cipherdrop/v1/recovery-auth", 256) -> server keeps b64url(SHA-256(recoveryAuth))
```

A password change re-derives `mk` with a fresh salt and re-wraps the same AK, so no drop is re-encrypted. RK carries 160 bits of entropy, so a fast hash is enough for its server copy.

### HKDF labels

HKDF is WebCrypto HKDF-SHA-256 with the IKM imported as a raw `HKDF` key. The salt is empty unless stated.

| `info` label                       | IKM                     | Salt              | Output          | Used for                            |
| ---------------------------------- | ----------------------- | ----------------- | --------------- | ----------------------------------- |
| `cipherdrop/v1/file-key`           | DK                      | fileId bytes (16) | AES-256-GCM key | STREAM chunks of one file           |
| `cipherdrop/v1/manifest-key`       | DK                      | empty             | AES-256-GCM key | the encrypted manifest              |
| `cipherdrop/v1/drop-password-wrap` | pk = Argon2id(password) | empty             | AES-256-GCM key | wraps DK of a password drop         |
| `cipherdrop/v1/drop-password-auth` | pk                      | empty             | 256 bits        | `authKey` for `/unlock` and `/open` |
| `cipherdrop/v1/account-enc`        | mk = Argon2id(password) | empty             | AES-256-GCM key | wraps AK                            |
| `cipherdrop/v1/account-auth`       | mk                      | empty             | 256 bits        | `authKey` for login                 |
| `cipherdrop/v1/recovery-enc`       | RK                      | empty             | AES-256-GCM key | wraps AK for recovery               |
| `cipherdrop/v1/recovery-auth`      | RK                      | empty             | 256 bits        | `recoveryAuthKey` for recovery      |

Every derived AES key is non-extractable, with the `encrypt` and `decrypt` usages only.

### AES-GCM AAD labels

| AAD                                                                                           | Protects                  |
| --------------------------------------------------------------------------------------------- | ------------------------- |
| `cipherdrop/v1/chunk`                                                                         | every file chunk          |
| `cipherdrop/v1/manifest`                                                                      | the manifest              |
| `cipherdrop/v1/wrap/drop-password`, `.../wrap/account`, `.../wrap/recovery`, `.../wrap/owner` | the four wrapped-key uses |

`wrapKey`/`unwrapKey` accept only the four wrap labels and only 32-byte keys: `wrap(k, key, aad) = b64url(nonce(12, random) || ciphertext(32) || tag(16))`, always 80 characters. The manifest is `b64url(nonce(12, random) || AES-GCM(manifestKey, nonce, aad, utf8(JSON)))`, at most 64 KiB encoded, and it is validated with `ManifestSchema` on both sides.

## File encryption: the STREAM construction

A file of `size` bytes is split into `chunkCount = max(1, ceil(size / 4 MiB))` chunks (a 0-byte file is one empty chunk). Chunk `i` is sealed under the file's own key with a counter nonce:

```
nonce_i = 00 00 00 00 00 00 00 | uint32_be(i) | 01 if i == chunkCount - 1, else 00     (12 bytes)
ct_i    = AES-256-GCM(fileKey, nonce_i, aad = "cipherdrop/v1/chunk", pt_i)            (|pt_i| + 16 bytes)
```

- **Order, truncation and extension are authenticated.** Position and the last-chunk flag sit inside the nonce (Hoang, Reyhanitabar, Rogaway and Vizar, 2015). A swapped, duplicated or dropped chunk, a penultimate chunk passed off as the last, or a final chunk replayed as non-final all fail the GCM tag.
- **Nonces never repeat.** Every file has a unique key (HKDF salted with its random 128-bit fileId), so each (key, nonce) pair is used once. The counter is a uint32, so `chunkCount`/`chunkNonce` refuse more than 2^32 chunks. A (fileKey, index) pair must never encrypt two different plaintexts: the resume logic re-checks a chunk's hash before continuing (R11).
- **The decryptor fails closed.** `createChunkDecryptor(key, chunkCount)` takes `chunkCount` from the authenticated manifest and assigns positions in call order (overlapping calls are serialised). After the first failure it refuses every later chunk, so no plaintext is released from a stream that failed. A stream that ends before `done()` is an integrity failure, and the caller must treat it as one.
- `ciphertextSize(size) = size + 16 * chunkCount(size)`.

## Key-derivation bounds (Argon2id)

|               | memoryKiB | iterations | parallelism | Why                                                                                              |
| ------------- | --------- | ---------- | ----------- | ------------------------------------------------------------------------------------------------ |
| `KDF_MIN`     | 19 456    | 2          | 1           | the client **refuses** anything weaker: a malicious or breached server cannot downgrade the cost |
| `KDF_DEFAULT` | 65 536    | 3          | 1           | new drop passwords and accounts                                                                  |
| `KDF_MAX`     | 262 144   | 10         | 4           | the client refuses anything costlier: a server cannot make it exhaust memory or time             |

`assertKdfParams` checks each field (an integer within its bounds) before any work, and every derivation calls it. Server-provided salts must be the canonical b64url of exactly 16 bytes. Passwords are normalised with NFKC, so the "fi" ligature and "fi" give the same key. hash-wasm cannot hash an empty password, so an empty password is a `TypeError`.

## Encodings

- **b64url:** base64url without padding, decoded strictly. A decoder that accepted two spellings of the same bytes would make every b64url value malleable, so it rejects `+`, `/`, `=`, whitespace, impossible lengths and non-zero unused trailing bits (one canonical spelling per value, the same rule as the server's schemas).
- **UTF-8:** malformed input throws instead of becoming U+FFFD, and a leading BOM is preserved.
- **Recovery keys:** Crockford base32, 8 groups of 4. Parsing is case-insensitive and maps I and L to 1 and O to 0. It also ignores whitespace, any dash and zero-width characters, and applies NFKC (full-width letters). It throws `TypeError` on anything else, without echoing the key.
- **Share links:** `${origin}/d/${dropId}#${b64url(DK)}`. `parseShareFragment` strips a leading `#`, URL-decodes (keeping the raw text if that fails), strips trailing characters outside the base64url alphabet with a linear scan (no regex backtracking on hostile links), and requires exactly 43 characters decoding to 32 bytes. Otherwise it returns `null`. It never throws.

## Errors

| Class (`code`)                          | Thrown when                                                                                                                                                                    |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `IntegrityError` (`INTEGRITY`)          | a chunk or manifest fails authentication, is malformed or truncated, or arrives after the final chunk; a manifest fails `ManifestSchema`; an owner-wrapped key fails to unwrap |
| `WrongPasswordError` (`WRONG_PASSWORD`) | `unwrapKey` fails under the drop-password, account or recovery label (a wrong password or recovery key)                                                                        |
| `KdfParamsError` (`KDF_PARAMS`)         | Argon2id parameters or a salt are outside the allowed range                                                                                                                    |
| `InvalidLinkError` (`INVALID_LINK`)     | reserved for the UI: `parseShareFragment` returns `null` instead of throwing                                                                                                   |

Structured clone turns any `Error` subclass into a plain `Error` and drops `code`, so a Worker must post `{ code, message }` explicitly and the receiver maps it back by `code`. Misuse is a `TypeError` or `RangeError`, never a crypto error: a wrong key length, a non-Uint8Array, an unknown wrap label, a `null` manifest or an index out of range. Only a real WebCrypto authentication failure (`OperationError`) becomes `IntegrityError` or `WrongPasswordError`. `encryptManifest` throws a `ZodError` for an invalid manifest and a `RangeError` above 64 KiB.

## Tests and bench

```
npx vitest run                      # in packages/crypto
npx tsx packages/crypto/src/bench.ts
```

- `conformance.test.ts` re-implements section 7 with `node:crypto` and `@node-rs/argon2`, with every label typed from the spec. It pins a STREAM golden vector and checks every derivation, wrap and the manifest format byte for byte.
- `kdf.test.ts` holds the Argon2id regression vectors (R20). They are the reference implementation's published KATs (m=65536 and m=262144, t=2, p=1), plus cross-checks of hash-wasm against `@node-rs/argon2` `hashRaw` at KDF_MIN, p=2 and KDF_MAX.
- The other files cover the spec section 14 cases: chunk roundtrips (0 B to 3 chunks), bit flips, swapped, dropped and replayed chunks, wrong keys, manifest schema rejection, password and recovery flows, KDF bounds and link parsing.

Bench on an i7-1195G7 laptop, Node 22.12, one stream with sequential 4 MiB chunks. The laptop was shared with other jobs, so the table gives the fastest of three runs and the range across them:

| Operation                           | Fastest run | Range over 3 runs |
| ----------------------------------- | ----------- | ----------------- |
| STREAM encrypt, 64 MiB              | 864 MiB/s   | 611-864 MiB/s     |
| STREAM decrypt, 64 MiB              | 791 MiB/s   | 447-791 MiB/s     |
| SHA-256 of the ciphertext chunks    | 677 MiB/s   | 404-677 MiB/s     |
| Argon2id at KDF_DEFAULT (hash-wasm) | 319 ms      | 319-516 ms        |
| Argon2id at KDF_MIN (hash-wasm)     | 73 ms       | 73-95 ms          |

## Limits

- JavaScript cannot guarantee that secrets are wiped from memory, and strings (passwords, the formatted recovery key) cannot be wiped at all. The package zeroes the Argon2id outputs, password bytes and raw recovery keys it creates, and keeps every derived key non-extractable.
- AES-GCM is not key-committing. That does not help an attacker here: every key that a password protects is released only after a server-side `authKey` check, and the server already holds that `authKey` (or its hash) for offline guessing, which costs Argon2id work per guess.
