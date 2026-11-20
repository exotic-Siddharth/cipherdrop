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
passwords, through storage, logs, errors or analytics. Two kinds of test enforce it.

- **What the browser sends.** The Playwright suite runs a leak guard (`apps/web/e2e/support/fixtures.ts`) on every
  request of every browser context: document navigations, assets, worker scripts, the requests workers make (the
  upload worker's chunk PUTs) and the API calls. It scans the URL (without the `#fragment`, which is never sent),
  every header the browser sent (`request.allHeaders()`, so Cookie and the other headers the browser adds are
  included) and the body. It fails the test on any hit for the test file names (raw, URL-encoded as
  `encodeURIComponent`, `encodeURI` and an HTML form encode them, JSON-escaped, base64, base64url), the plaintext
  bytes (raw, base64, base64url, lower- and upper-case hex), and the keys and passwords. A key is forbidden as its
  link text in those encodings and as its 32 bytes raw, as base64 with and without padding (also URL-encoded and
  with JSON's `\/` escape), as base64url and as hex. It also fails on any request to an origin other than the web
  origin. `data:` and `blob:` URLs are skipped because they never leave the browser. A request whose full headers
  cannot be read is still scanned with the headers the page set, and the test gets a note; it is never dropped.
  Its self-tests are `apps/web/e2e/leakguard.spec.ts` (12 tests).
- **What the server logs.** `apps/api/src/modules/auth/logs.test.ts` and `apps/api/src/modules/drops/logs.test.ts`
  capture the API's pino output (the drops test also captures the console, stdout and stderr) while they run whole flows,
  and fail if a token, manifest, wrapped key, authKey or password proof, report key or file byte appears, also on
  forced 500s (a storage error, Prisma errors while a report with its key is stored). Prisma's warnings and errors
  go through pino; an error event is logged with only the call it came from (for example `report.create`), never
  its message. A Prisma error is logged as safe fields only: its class, its code, the schema names in `meta`
  (`modelName`, `target`, `constraint`, `field_name`) and the stack frames without the message
  (`apps/api/src/lib/logger.ts`). The reason: the message of a `PrismaClientValidationError` renders the arguments
  of the failed call, a reporter's key included, even with `errorFormat: 'minimal'`.

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
| Fetch the ciphertext more than once per counted download. The limit counts `/open` calls, not transfers: each open returns a download grant, valid for 30 minutes (`DOWNLOAD_GRANT_TTL_MIN`) and extended by every chunk GET, but never past 24 hours after the open. Until it ends, the grant serves every chunk of the drop as often as asked, also after the drop is used up or expired (not after a delete or an admin disable), because the blobs are kept while a grant lives | Use a grant for another drop: it is bound to its drop id |
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
  headers, cookies and tokens are never logged, a pino redaction list is a second line of defence, and Prisma
  errors are logged as safe fields only ([section 1](#1-what-cipherdrop-protects));
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
| Refresh token | Random 32 bytes in the `cd_rt` cookie (httpOnly, `SameSite=Strict`, `Path=/api/auth`, `Secure` in production), rotated on every refresh; presenting an already used token revokes the whole session (`SESSION_REUSE_DETECTED`), except a lost response: within 30 s of the rotation, while the successor is still unused, the successor is retired (kept as used, so presenting it later is reuse) and a fresh one issued in the same session |
| Immediate revocation | A revoked session id goes on a Redis denylist for the access-token lifetime, so its access token stops working at once (logout, "revoke others", password change, recovery, account deletion) |
| CSRF | API calls authenticate with the Bearer header, which a cross-site page cannot set; the only cookie is `SameSite=Strict` and scoped to `/api/auth` |
| Vault | The account key lives only in memory as a non-extractable `CryptoKey`; a page reload locks it, and it auto-locks after 5, 15 or 60 minutes idle (default 15). Each tab has its own vault: a tab starts locked, and Lock acts on the current tab only, so another tab the user unlocked stays unlocked until its own idle lock (after a sign-out, until its next API call finds the session revoked) |
| Recovery | The recovery key resets the password; it is rotated on use, all sessions are revoked, and a TOTP or backup code is still required when 2FA is enabled |
| Audit log | Logins, failures, lockouts, 2FA changes, password and recovery events, session revocations, and per drop: created, opened (with IP prefix and browser), unlock failures, expiry, reports. Visible to the user in Settings, Activity |
| Admin | Role checked again in the database on every admin request; admin review of a reported drop uses a non-consuming grant and is audited as `ADMIN_REVIEW_GRANT` |

Other server controls: zod validation of every request; a 1 MiB JSON body limit and an exact size check on
chunk uploads (4 MiB + 16 bytes, `X-Chunk-SHA256` must match); constant-time comparison of every token and hash;
`Cache-Control: no-store` on every `/api` response; helmet headers on the API and the CSP and related headers on
the SPA ([DESIGN.md section 12](DESIGN.md#12-security-requirements)). Rate limits and in-flight caps are listed
in [API.md](API.md#rate-limits).

**Losing both the password and the recovery key means the account's drops cannot be decrypted.** This is by
design: nobody, including the operator, can reset access.

**With 2FA on, losing both the authenticator and every unused backup code locks the account for good**, even with
the password and the recovery key in hand. Login asks for a TOTP or backup code, and so does recovery (by design: the
recovery key alone must not take over an account with 2FA). The app has no admin or operator reset of 2FA. Keep
the backup codes somewhere other than the authenticator. If the operator loses `TOTP_ENC_KEY`, every enrolled user
is in this position except those who still have a backup code: backup codes are hashed, not encrypted under that
key, so they still sign in and can turn 2FA off and on again.

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
- **Per-process caps (C-15, C-09).** The API's in-flight upload and download caps count per API process; several
  instances need connection limits in the reverse proxy. The bundled nginx has two: 64 in-flight `/api` requests
  per client (`limit_conn api_ip`, keyed by IPv4 address or IPv6 /48 like the API's per-IP shares) and 400 in total
  (`api_total`), answered with 429. With N API instances behind one nginx use 48 x N + 16 and about 400 x N
  ([DEPLOYMENT.md](DEPLOYMENT.md) section 4). Per-IP caps rely on `TRUST_PROXY`, which is `1` for the bundled stack
  with or without Caddy.
- **Admin review of expired drops (C-R2-05).** Reports are accepted for expired drops until their blobs are purged,
  but the admin review grant refuses expired drops.
- **Orphaned blob versions (C-R2-01, C-R4-01).** A crash between a chunk write and its commit, or a storage error
  that outlasts all retries, can leave an unreferenced blob until the drop is purged; there is no storage sweep.
- **Slowest supported uplink (C-R3-01).** About 0.34 Mbit/s for the three-lane web uploader, set by Node's 300 s
  request timeout per 4 MiB chunk. This holds end to end in the bundled stack: nginx streams chunk PUTs to the API
  and sets no deadline of its own (its 60 s limit on the gap between two reads of a chunk body is only a backstop
  behind the API's 30 s idle window), and Caddy streams request bodies too.
- **Shared per-IP shares (C-R3-03).** Clients behind one IPv4 NAT or one IPv6 /48 share the per-IP in-flight caps,
  and nginx's cap of 64 in-flight `/api` requests per client.
- **Slow clients at nginx.** nginx (open source) has no deadline for a whole request body: `client_body_timeout 15s`
  on JSON routes limits the gap between two reads. A JSON body dripped at one byte per 15 s therefore holds an nginx
  slot for as long as the client keeps it up. One address holds at most 64 slots, but about 7 addresses (or IPv6
  /48s) can still fill the 400; a distributed attack needs an edge proxy or CDN in front. After the API answers an
  unverified chunk uploader with 401, nginx reads and discards the rest of its body for up to `lingering_time`
  (30 s) and keeps the slot meanwhile. A slow request header is bounded only by `client_header_timeout 10s` and
  nginx's worker connections (1024 per worker, the base image's default), because `limit_conn` counts a request
  only once its header is complete.
- **IPv6 clients in the `tls` profile.** The compose network `edge` between Caddy and nginx has no IPv6. On a
  dual-stack host, IPv6 clients therefore reach Caddy through Docker's userland proxy and appear with the network's
  gateway address, so they share one bucket, for nginx's per-client cap and for the API's rate limits alike (as
  before the cap was added). Not tested: the verification environment had no IPv6.
- **Refresh grace window.** A refresh whose response is lost leaves the browser holding the old, already used
  token. So that this does not sign the user out, a replay of that token less than 30 s (`REFRESH_GRACE_MS`) after
  its rotation, while its successor has never been used, retires the unused successor and issues a new one in the
  same session instead of revoking the session. The retired successor is kept as a used token, not deleted: in a
  genuine lost response the browser never received it, so presenting it later is reuse and revokes the whole session
  (`SESSION_REUSE_DETECTED`), and logging out with it still ends the session. The trade-off: a thief holding the old
  token during those same 30 s can replay it and get a live token, but only until the user's next refresh (an open
  tab refreshes about every 15 minutes) or logout, which presents the retired successor and ends the session. The
  window is short, opens only while the successor is unused, and is not extended by re-issues; outside it, or once
  any successor was used, reuse revokes the whole session as before.
- **Test coverage.** Signing out mid-upload is covered by unit tests only; the resume flow after the round-4
  changes has one browser-level test.
- **Dependency advisories (`npm audit --omit=dev`).** Accepted advisories are listed in
  `scripts/audit-allowlist.json`, each with its GHSA id, package, reason, fix and a `reviewBy` date.
  `npm run audit:gate` (`scripts/audit-gate.mjs`) fails on any high or critical advisory missing from that list, on
  an entry that no longer matches anything and on an entry past its `reviewBy` date; `.github/workflows/audit.yml`
  runs it on pushes to main, on pull requests, every Monday and on demand. On 2026-11-20 three high advisories were
  listed, all with `reviewBy` 2027-02-20 and all fixed only by major upgrades:
  - zod below 4.6.6 (GHSA-mrhx-c7xc-m3w5) can exhaust memory on oversized collections. JSON bodies are capped at
    1 MiB, and chunk uploads are raw bytes that zod never parses. The fix is the zod 4 migration (with
    zod-to-openapi 8 or later).
  - `deepmerge-ts` (GHSA-ggr8-5vv4-36mx) and `effect` (GHSA-7589-6fvf-x4pw, a ReDoS in `Schema.TemplateLiteral`;
    first found by the gate on 2026-11-20) come in only through `@prisma/config`, a dependency of the Prisma CLI,
    which uses them to load and validate its own configuration (`prisma generate`, `migrate deploy`), never request
    data. The fix is the Prisma 7 migration.

  `npm audit` reads the repository lockfile, so it does not cover the Prisma CLI that the API image installs into
  `/opt/prisma` without a lockfile ([DEPLOYMENT.md](DEPLOYMENT.md) section 5).

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
