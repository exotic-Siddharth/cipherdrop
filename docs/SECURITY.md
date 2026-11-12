# Security

This document is the threat model of CipherDrop: what each adversary can and cannot learn or do, the
cryptographic design in brief, the metadata the server does see, account and session security, and the open
points accepted in the code review. The normative cryptographic specification is
[DESIGN.md section 7](DESIGN.md#7-cryptographic-design-packagescrypto-normative); this page summarises it and
does not override it.

The running app links this file from `/how-it-works` and serves it at `/SECURITY.md` as plain text.

## 1. What CipherDrop protects

| Asset | Protection |
|---|---|
| File contents | AES-256-GCM in the browser before upload, in a STREAM construction ([section 3](#3-cryptographic-design-in-brief)) |
| File names, MIME types, sizes of individual files, the note | Inside the encrypted manifest |
| The drop key (the link secret) | In the link's `#fragment`, which browsers do not send to servers; or wrapped under a drop password the server never sees |
| The account password | Never leaves the browser; the server receives a key derived from it with Argon2id |
| The account key (decrypts the owner's drop keys) | Stored only wrapped, under the password-derived key and under the recovery key |

The single rule behind the design: the server must not learn plaintext, file names, MIME types, notes, keys or
passwords, through storage, logs, errors or analytics. The Playwright suite enforces it for every API request the
browser makes, the upload worker's included: a leak guard (`apps/web/e2e/support/fixtures.ts`) scans URLs, headers
and bodies of every such request for the
test file names (raw, URL-encoded, JSON-escaped, base64, base64url), the plaintext bytes and the key material, and
fails the test on any hit. Its own self-test is `apps/web/e2e/leakguard.spec.ts`.

## 2. Adversaries

### 2.1 The server operator, or anyone who controls the server

| Can | Cannot |
|---|---|
| Read the metadata in [section 4](#4-metadata-the-server-sees) | Decrypt a drop without its link, its password, or the owner's password or recovery key |
| Delete or withhold ciphertext (availability is not protected) | Modify ciphertext without detection: any change, reorder, truncation or extension fails AES-GCM authentication and the browser saves nothing |
| Keep a copy of the ciphertext after a burn-after-read download or after expiry: download limits and expiry are enforced by an honest server, not by cryptography | Swap in other content under an existing link: the manifest and chunks are authenticated under keys derived from the drop key in the link |
| Run offline guessing against password-protected drops and accounts from its own database (one Argon2id derivation per guess, see [section 2.4](#24-a-stolen-database)) | Learn a drop password or account password directly: only Argon2id-derived values reach it |
| **Serve modified JavaScript** that exfiltrates keys or plaintext. This is the main limitation of any browser-based end-to-end encryption: the code that holds the keys comes from the server it protects against | |

Mitigations for the modified-JavaScript case: a strict CSP with no third-party origins
(`script-src 'self' 'wasm-unsafe-eval'`, `connect-src 'self'`), no CDNs, analytics or external fonts, and
self-hosting. Out of scope for v1: Subresource Integrity on a pinned build, reproducible builds that users can
verify, and code-signing browser extensions.

### 2.2 A network attacker

| Can | Cannot |
|---|---|
| See which hosts a user talks to, and transfer sizes and timing | Read anything inside TLS (the deployment terminates TLS in Caddy or your own proxy, [DEPLOYMENT.md](DEPLOYMENT.md)) |
| Without TLS: read and change everything, including the JavaScript. CipherDrop must be served over HTTPS; `NODE_ENV=production` refuses to start without `COOKIE_SECURE=true` | Change ciphertext undetected even if it can modify responses: the e2e tamper test (`apps/web/e2e/drops.spec.ts`, test 4) flips one byte of a chunk response, and the UI shows "This file was modified in transit or storage. Download blocked." and saves nothing |

### 2.3 A malicious or careless recipient (anyone holding the link)

| Can | Cannot |
|---|---|
| Download while downloads remain and the link has not expired; keep and re-share the plaintext (no system can prevent this) | Read other drops: drop ids are 16 random bytes, and every drop has its own random 32-byte key |
| Forward the full link: anyone with it can download. Keys in links also end up in chat logs and browser history. Password mode mitigates this: the link then carries no key | Get more downloads than the limit: `/open` is one conditional `UPDATE`, and with 10 concurrent opens on a 1-download link exactly one succeeds (API integration test) |
| Guess a drop password online, within the rate limits (5 failed attempts per 15 min per drop and IP, 20 failures per hour per drop). Using up the per-drop budget also blocks the real recipient until the window ends (accepted trade-off, review C-01) | Use `/open` as a password oracle outside those limits: `/open` and `/unlock` share the same failure counters (review C-01) |
| Report the drop, optionally attaching its key so an admin can review it | |

### 2.4 A stolen database

The database holds no plaintext, no file names and no drop keys of link-mode drops. With a copy of it an
attacker:

- **can** run offline guesses against password-protected drops: each guess costs one client-side Argon2id
  derivation (64 MiB, t=3, p=1; 328 ms median in Node on the benchmark laptop, [BENCHMARKS.md](BENCHMARKS.md)
  section 3), then a SHA-256 compare against the stored verifier;
- **can** run offline guesses against account passwords at the same per-guess cost: a guess is checked by trying
  to unwrap `wrappedAccountKey` (AES-GCM authenticates it). A correct guess yields the account key and with it the
  owner's drop keys. A strong password is the defence; the sign-up and drop-password forms require at least
  10 characters and a zxcvbn score of 2 or more;
- **can** decrypt drops that have an OPEN abuse report whose reporter attached the key, if it also has the blob
  storage. The key is deleted when the report is dismissed, when the drop is disabled and when its blobs are
  purged (review C-14);
- **can** see all metadata in [section 4](#4-metadata-the-server-sees);
- **cannot** log in with the stored `authKeyHash`: it is a server-side Argon2id hash (m=19456 KiB, t=2, p=1) of
  the client's authKey, so the hash is not the credential;
- **cannot** use stored tokens: refresh, upload, owner and download tokens are random 32 bytes stored as SHA-256
  hashes;
- **cannot** read TOTP secrets without `TOTP_ENC_KEY`, which is in the environment, not the database (AES-256-GCM
  at rest);
- **cannot** use the recovery data: the recovery key carries 160 bits of entropy, so its SHA-256 verifier is safe
  to store.

### 2.5 Cross-site scripting

An XSS in the SPA would run with the user's keys in memory, so XSS prevention is part of the crypto boundary:

- React escapes all rendered text, and there is no `innerHTML` on decrypted content (QR codes are drawn as SVG
  paths);
- the CSP allows scripts only from the app's own origin, with no inline scripts (`/theme-init.js` is a file for
  that reason), plus `'wasm-unsafe-eval'` for the Argon2id WebAssembly;
- file names are shown and saved through `sanitizeFilename`, which removes path separators, control and
  bidirectional-override characters and Windows-reserved names (review C-16: a name with a right-to-left override
  could otherwise disguise its extension);
- previews are rendered from the decrypted Blob for raster images (PNG, JPEG, GIF, WebP) and for text and JSON up
  to 1 MiB only; SVG is never previewed because it can carry script.

## 3. Cryptographic design in brief

Normative details, constants and labels: [DESIGN.md section 7](DESIGN.md#7-cryptographic-design-packagescrypto-normative)
and [packages/crypto/README.md](../packages/crypto/README.md). Primitives come from WebCrypto (AES-GCM, HKDF,
SHA-256) and `hash-wasm` (Argon2id); only the construction is CipherDrop's own.

- **Drop key.** 32 random bytes per drop. Each file gets its own AES-256-GCM key from HKDF-SHA-256 with a random
  16-byte file id as salt; the manifest (names, sizes, types, the note) gets another HKDF-derived key.
- **STREAM.** Files are encrypted in 4 MiB chunks. The 12-byte nonce of chunk `i` is 7 zero bytes, the 32-bit
  big-endian chunk index and a last-chunk flag byte. Reordering, truncation and extension therefore all fail
  authentication (Hoang, Reyhanitabar, Rogaway and Vizár, 2015). Nonces never repeat under one key because every
  file has a fresh key. The decryptor accepts chunks only in order and refuses everything after a failure.
- **Password drops.** Argon2id (64 MiB, t=3, p=1) of the password with a random 16-byte salt, then HKDF splits it
  into a wrapping key for the drop key and an auth key. The server stores SHA-256 of the auth key and releases the
  wrapped drop key only after a constant-time match, under rate limits.
- **Accounts.** The browser derives `authKey` and `encKey` from the password with Argon2id and HKDF. `encKey` wraps
  a random 32-byte account key; a 160-bit recovery key wraps it a second time. The account key wraps each owned
  drop key, which lets the dashboard show decrypted names and rebuild links on any device. Changing the password
  re-wraps the same account key, so no drop is re-encrypted.
- **Downgrade protection.** The client refuses KDF parameters from the server below 19 MiB / t=2 (and above
  256 MiB / t=10 / p=4), so a malicious server cannot make a password cheap to guess.
- **No user enumeration.** `prelogin` returns a deterministic fake salt (HMAC of the email under
  `PRELOGIN_SECRET`) for unknown emails, with the same response shape; login and recovery errors are generic.

Tests: `packages/crypto` has unit tests for every property above (bit flips, swapped and dropped chunks, a final
chunk replayed as non-final, weak and absurd KDF parameters), Argon2id known-answer vectors from the reference
implementation, and `conformance.test.ts`, which re-implements section 7 with `node:crypto` and pins a STREAM
golden vector.

## 4. Metadata the server sees

The server does see, and stores:

- the account email, account creation time, role, storage quota and usage;
- per drop: the random drop id, the number of files, each file's ciphertext size and chunk count (ciphertext size
  is the plaintext size plus 16 bytes per 4 MiB chunk, so **file sizes leak**; size padding is future work),
  creation, expiry and last-opened times, the download limit and count, whether it is password-protected, and the
  owner if the sender was signed in;
- IP addresses as **prefixes only** in the database (IPv4 /24, IPv6 /48) and user-agent strings: on sessions,
  download grants, audit events and abuse reports;
- full IPv4 addresses (and IPv6 /64 prefixes) as rate-limit keys in Redis, for the length of each limiter window
  (at most one hour);
- request logs with request id, method, path without query string, IP prefix and status; request bodies,
  headers, cookies and tokens are never logged, and a pino redaction list is a second line of defence;
- an abuse report's reason, details and, only if the reporter ticks the opt-in box, the drop key (kept while the
  report is OPEN).

The server never receives: plaintext, file names, MIME types, the note, drop keys of link-mode drops (the
fragment), drop passwords, account passwords, the account key or the recovery key.

The nginx in front of the API keeps its default access log, which records full client IP addresses and request
paths (never the fragment). Operators who want prefix-only logs must change `access_log` in
`deploy/nginx.conf`.

## 5. Accounts and sessions

| Control | Implementation |
|---|---|
| Password | Never sent; Argon2id in a Web Worker, so the UI stays responsive. Minimum 10 characters and zxcvbn score 2 or more for account and drop passwords |
| Account lockout | 10 consecutive failed logins (wrong authKey or wrong TOTP or backup code) lock the account for 15 minutes; the error stays generic |
| Two-factor | TOTP (SHA-1, 6 digits, 30 s, plus or minus one step) with replay protection (the last used step is stored), secrets AES-256-GCM-encrypted at rest; 10 single-use backup codes stored as SHA-256 hashes |
| Access token | JWT HS256, 15 minutes, kept in memory only (never in localStorage), sent as a Bearer header |
| Refresh token | Random 32 bytes in the `cd_rt` cookie (httpOnly, `SameSite=Strict`, `Path=/api/auth`, `Secure` in production), rotated on every refresh; presenting an already used token revokes the whole session (`SESSION_REUSE_DETECTED`) |
| Immediate revocation | A revoked session id goes on a Redis denylist for the access-token lifetime, so its access token stops working at once (logout, "revoke others", password change, recovery, account deletion) |
| CSRF | API calls authenticate with the Bearer header, which a cross-site page cannot set; the only cookie is `SameSite=Strict` and scoped to `/api/auth` |
| Vault | The account key lives only in memory as a non-extractable `CryptoKey`; a page reload locks it, and it auto-locks after 5, 15 or 60 minutes idle (default 15) |
| Recovery | The recovery key resets the password; it is rotated on use, all sessions are revoked, and TOTP is still required when enabled |
| Audit log | Logins, failures, lockouts, 2FA changes, password and recovery events, session revocations, and per drop: created, opened (with IP prefix and browser), unlock failures, expiry, reports. Visible to the user in Settings, Activity |
| Admin | Role checked again in the database on every admin request; admin review of a reported drop uses a non-consuming grant and is audited as `ADMIN_REVIEW_GRANT` |

Other server controls: zod validation of every request; a 1 MiB JSON body limit and an exact size check on
chunk uploads (4 MiB + 16 bytes, `X-Chunk-SHA256` must match); constant-time comparison of every token and hash;
`Cache-Control: no-store` on every `/api` response; helmet headers on the API and the CSP and related headers on
the SPA ([DESIGN.md section 12](DESIGN.md#12-security-requirements)). Rate limits and in-flight caps are listed
in [API.md](API.md#rate-limits).

**Losing both the password and the recovery key means the account's drops cannot be decrypted.** This is by
design: nobody, including the operator, can reset access.

## 6. KDF parameters

Argon2id with 64 MiB of memory, 3 iterations and parallelism 1 (`KDF_DEFAULT`) is above the OWASP minimum
(19 MiB, t=2, p=1, which is `KDF_MIN`). In the benchmark it takes a median 253 ms (warm worker) to 291 ms (cold)
in headless Chromium and 328 ms in Node on a 4-core laptop ([BENCHMARKS.md](BENCHMARKS.md) sections 3 and 5), a
delay a user accepts at sign-in and that multiplies the cost of every offline guess. Parameters are stored per
account and per password drop, so they can be raised later without breaking existing data, and the client
enforces the minimum.

## 7. Accepted open points

From the code review record ([review/2026-11-11-review.md](review/2026-11-11-review.md), "Open points"):

- **Server-side nonce reuse check (C-19).** A re-upload of an existing chunk overwrites it, as the spec and its
  tests define. A malicious client could reuse its own nonces; that only harms its own drop. The honest client
  refuses an ambiguous resume.
- **Per-drop unlock budget (C-01).** An attacker who uses up the per-drop failure budget also blocks recipients
  until the window ends.
- **Delayed deletion of expired drops (C-06).** Blobs of an expired drop are deleted once no download grant is
  live, at most about 24 hours after expiry.
- **Per-process caps (C-15, C-09).** The in-flight upload and download caps count per API process; several
  instances need connection limits in the reverse proxy (nginx has one, [DEPLOYMENT.md](DEPLOYMENT.md) section 4).
  Per-IP caps rely on `TRUST_PROXY` being set correctly.
- **Admin review of expired drops (C-R2-05).** Reports are accepted for expired drops until their blobs are purged,
  but the admin review grant refuses expired drops.
- **Orphaned blob versions (C-R2-01, C-R4-01).** A crash between a chunk write and its commit, or a storage error
  that outlasts all retries, can leave an unreferenced blob until the drop is purged; there is no storage sweep.
- **Slowest supported uplink (C-R3-01).** About 0.34 Mbit/s for the three-lane web uploader, set by Node's 300 s
  request timeout per 4 MiB chunk.
- **Shared per-IP shares (C-R3-03).** Clients behind one IPv4 NAT or one IPv6 /48 share the per-IP in-flight caps.
- **Test coverage.** Signing out mid-upload is covered by unit tests only; the resume flow after the round-4
  changes has one browser-level test.
- **Dependency advisories (`npm audit --omit=dev`, 2026-11-12).** Two are rated high, and both fixes are major
  upgrades. zod below 4.6.6 can exhaust memory on oversized collections; JSON bodies are capped at 1 MiB, and chunk
  uploads are raw bytes that zod never parses. Prisma 6 pulls in a vulnerable `deepmerge-ts` through
  `@prisma/config`, which runs when Prisma loads its configuration, not on request data. The fixes are the zod 4
  migration (with zod-to-openapi 8 or later) and the Prisma 7 migration.

Further limitations, also shown on `/how-it-works`:

- file sizes are visible to the server (no padding);
- a link with the key in the fragment is a bearer secret;
- the security of browser-delivered cryptography depends on the server delivering honest JavaScript
  ([section 2.1](#21-the-server-operator-or-anyone-who-controls-the-server));
- files above 256 MiB are saved through the File System Access API (`showSaveFilePicker`), which only Chromium-based
  browsers provide; elsewhere the receive page refuses before consuming a download (review C-03).

## 8. Reporting a vulnerability

This is a portfolio project without a bug bounty. Please report a vulnerability privately to the repository owner
rather than in a public issue, with steps to reproduce. Do not test against deployments you do not own.
