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
  `encodeURIComponent`, `encodeURI`, an HTML form and the browser's URL parser encode them, JSON-escaped, base64, base64url), the plaintext
  bytes (raw, base64, base64url, lower- and upper-case hex), and the keys and passwords. A key is forbidden as its
  link text in those encodings and as its 32 bytes raw, as base64 with and without padding (also URL-encoded and
  with JSON's `\/` escape), as base64url and as hex. It also fails on any request to an origin other than the web
  origin. `data:` and `blob:` URLs are skipped because they never leave the browser. A request whose full headers
  cannot be read is still scanned with the headers the page set, and the test gets a note; it is never dropped.
  In WebKit this is how document navigations are checked (their full headers cannot be read once the page or the
  test ends), so Chromium remains the full-header check. The guard also fails a test on any page error and on any
  CSP or Trusted Types message in the console, in Chromium's, Firefox's and WebKit's wording. Its self-tests are
  `apps/web/e2e/leakguard.spec.ts` (19 tests).
- **What the server logs.** `apps/api/src/modules/auth/logs.test.ts` and `apps/api/src/modules/drops/logs.test.ts`
  capture the API's pino output (the drops test also captures the console, stdout and stderr) while they run whole flows,
  and fail if a token, manifest, wrapped key, authKey or password proof, report key or file byte appears, also on
  forced 500s (a storage error, Prisma errors while a report with its key is stored). Prisma's warnings and errors
  go through pino. An event from a failed call (for example `report.create`) is logged with only that call, never
  its message; an engine event (a `quaint::` target, such as a lost database connection) keeps its message, which
  carries no call arguments. A Prisma error is logged as safe fields only: its class, its code, the schema names in `meta`
  (`modelName`, `target`, `constraint`, `field_name`) and the stack frames without the message
  (`apps/api/src/lib/logger.ts`); an initialization error keeps its message, which names the connection or startup
  failure. The same serializer is pino-http's, and the audit and cleanup jobs hand it the error itself rather than
  its message. The reason: the message of a `PrismaClientValidationError` renders the arguments
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
| Forward the full link: anyone with it can download. Keys in links also end up in chat logs and browser history. Password mode mitigates this: the link then carries no key. The receive page replaces its history entry with the same URL without the fragment as soon as it has read the key. That removes the key from the address bar, screen shares, copied addresses and the URL of the session-history entry. The entry's `history.state` keeps the key, so a reload or Back reopens the drop, until no downloads are left or the drop is gone (404, 410 or any status other than READY and UPLOADING). The key is **not** removed from the browser's global or synced history, which recorded the full URL at the first navigation (Mozilla bug 753264), and `history.state` can reach session-restore files until it is cleared. Forwarding goes through an explicit **Copy link** button; only if copying fails (no clipboard permission, some WebViews) does the page show the link, in a read-only, selected field | Get more downloads than the limit: `/open` is one conditional `UPDATE`, and with 10 concurrent opens on a 1-download link exactly one succeeds (API integration test) |
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
  purged (review C-14). While such a report is open, cleanup keeps the blobs of the drop past its expiry or last
  download for review, at most `REPORT_EVIDENCE_HOLD_DAYS` (14) after the drop expired or was used up, however
  many reports are filed (server-5, see [ABUSE.md](ABUSE.md)); an owner's delete is never held;
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
- saved files: a received file is saved through a same-origin `blob:` URL, and its Blob keeps the sender's declared
  type only if that type is on an inert allowlist (plain text, CSV, raster images, common audio and video formats).
  Everything else is saved as `application/octet-stream`: HTML, XHTML, SVG, XML and every `+xml` type, XSLT,
  JavaScript, CSS, WebAssembly, PDF, `multipart/*`, `message/*` and unknown types. The reason: some in-app browsers
  ignore `<a download>` and navigate to the `blob:` URL, which would render the sender's HTML or SVG as a document
  of the origin that holds the keys. The saved name keeps its extension, so the file opens as usual from disk;
- previews: the declared type only selects the renderer. Raster images (PNG, JPEG, GIF, WebP) are shown from a
  slice of the decrypted Blob typed with the allowlisted image type, never with the Blob's own type; text and JSON
  up to 1 MiB, HTML and XML included, are shown as source text in a `<pre>`; SVG is never previewed because it can
  carry script;
- Trusted Types run in report-only mode (`Content-Security-Policy-Report-Only: require-trusted-types-for 'script';
  trusted-types default`). The `default` policy in `/trusted-types.js`, which `index.html` loads first, allows only
  same-origin `/assets/*.js` script URLs and no HTML or script strings. There is deliberately no `report-to` or
  `report-uri`: a violation report carries a sample of the string that reached the sink, which could be decrypted
  plaintext. The e2e leak guard and the production smoke test are the reporter: they fail on any CSP or Trusted
  Types console message, and ignore only each engine's own notice that a report-only policy has no endpoint (WebKit:
  "...was delivered in report-only mode, but does not specify a 'report-to'...", Firefox: "...has a Report-Only
  policy without a report-uri directive nor a report-to directive..."). Enforcement is planned once the report-only
  policy has stayed clean in every supported browser;
- `worker-src 'self'` only: both workers are same-origin module files, and a source-scan test fails if an inline or
  `blob:` worker is ever added;
- Swagger UI, a large third-party script bundle, is never served on the SPA's origin in production: the API mounts
  it only with `API_DOCS_UI=true`, which `NODE_ENV=production` refuses, and nginx answers its own 404 for
  `/api/docs` and everything under it in any letter case (`location ~* ^/api/docs(?:/|$)`), because Express mounts
  are case-insensitive and `/api/DOCS/` would otherwise reach the API.

### 2.6 Sender identity

Anyone can create a drop, and a link authenticates its content only to whoever holds its key. "Integrity verified"
means that every chunk, and the manifest with the note, authenticated under keys derived from the link's key: the
bytes are exactly what was encrypted with that key, unchanged in transit and in storage. It does not identify the
sender, and it does not mean the file is safe: CipherDrop cannot scan what it cannot read. The receive page says so
in a line under **Decrypt & download** and in the badge's tooltip, and titles the note "Note from the sender (not
verified)". Sender signatures (for example Ed25519 in WebCrypto) would need a way to distribute and trust public
keys, which is out of scope. Recipients should confirm an unexpected link with the sender through another channel,
and use **Report abuse**.

### 2.7 Hosting abuse: the service as a free file host

Anonymous, end-to-end encrypted, auto-expiring drops are a channel for malware and phishing: Mozilla suspended
Firefox Send in July 2020 for this and later shut it down. The server cannot scan ciphertext, so the controls work on
cost and volume, not on content:

1. anonymous drop creates (10 per hour) and sign-ups (5 per hour) are counted per IPv4 address or IPv6 /48, not per
   /64 (a /48 holds 65,536 /64s);
2. a rolling byte budget per anonymous client, `ANON_BYTES_PER_CLIENT` (1 GiB) per `ANON_BYTES_WINDOW_HOURS` (24),
   counted in Redis in hourly buckets with each create rounded up to a whole MiB, answered with 429
   `UPLOAD_BUDGET_EXCEEDED` and `Retry-After`;
3. the anonymous pool, `ANON_TOTAL_PENDING_BYTES`, now 10 GiB by default (it used to be off);
4. new-account probation: `NEW_ACCOUNT_QUOTA_BYTES` (256 MiB) for the first `NEW_ACCOUNT_PROBATION_DAYS` (7), ended
   at once by an admin's quota edit;
5. `GLOBAL_STORAGE_CAP_BYTES` over all drops (off by default) and the `STORAGE_MIN_FREE_BYTES` free-disk floor of
   local storage (1 GiB), both answered with 507 `STORAGE_FULL`. The floor counts only active uploads (created, or
   stored a chunk, in the last 10 minutes), and cleanup deletes an upload that has stored no chunk one hour after
   its create;
6. the operator switches `ALLOW_ANONYMOUS_UPLOADS` and `ALLOW_REGISTRATION` (403 `FEATURE_DISABLED`);
7. the existing abuse reports and admin disable.

The arithmetic: before, one IPv4 address could keep about 10 x 100 MiB x 72 h, about 70 GiB, of anonymous drops
alive; now at most about 3 GiB (1 GiB per 24 hours, and links live up to 72 hours), and 10 GiB for all anonymous
senders together. A sender who also files keyed reports on their own drops can keep them, and their pool bytes,
for up to `REPORT_EVIDENCE_HOLD_DAYS` (14) more days after expiry (the evidence hold, server-5), so about 17 GiB
per IPv4 address at worst; an admin dismissing the reports ends that.

Residual risk, stated plainly:

- (a) Many IPv4 addresses or /48s (a botnet, cloud hosts) still get 1 GiB per day each, up to the pool and the global
  cap. Ten such clients fill the 10 GiB pool and lock other anonymous senders out until their drops expire or are
  purged.
- (b) The account path from **one** IPv4 address or /48: 5 sign-ups per hour, up to 120 accounts a day, each with
  256 MiB during probation (1.25 GiB per hour, about 30 GiB per day, with links of up to 30 days). Each account gets
  5 GiB once its 7 days are over, so one day of sign-ups is worth about 600 GiB. Only `GLOBAL_STORAGE_CAP_BYTES`
  bounds the total, and it is off by default: a public instance must set it.
- (c) Reservations: an upload counts against the floor while it is active, so an attacker can keep the floor tripped
  by refreshing reservations, either by trickling a small chunk into each every few minutes or by creating new drops
  within the rate limits (60 per hour per account). For example, 100 week-old accounts reserve 500 GiB with 100
  requests, each round counted for 10 minutes. The same pattern can hold the anonymous pool, and
  `GLOBAL_STORAGE_CAP_BYTES` when it is set, until cleanup deletes chunk-less reservations after one hour; a
  reservation that stored one small chunk lasts until the 24-hour stale-upload cleanup.
- (d) Nothing inspects content.

Considered and rejected: proof-of-work, which moves the cost onto honest (mobile) senders and is weak against botnets
and GPUs (Laurie and Clayton, 2004), and a CAPTCHA service, which would break the CSP's `'self'` rule and the
no-third-party anti-goal (DESIGN section 1).

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
- **No key commitment.** AES-GCM is not key-committing, so one ciphertext can be built to decrypt validly under two
  keys. What that means here is in [packages/crypto/README.md](../packages/crypto/README.md) (Limits).
- **Post-quantum.** What is stored is protected by symmetric primitives only (AES-256-GCM, HKDF-SHA-256, SHA-256,
  Argon2id). Grover's algorithm at best halves a key's security level, which leaves AES-256 at about 128 bits. A
  link's drop key never reaches the server, so it never crosses CipherDrop's TLS connections, except when a reporter
  chooses to attach it to an abuse report. What those connections do carry (ciphertext, wrapped keys, derived
  authKeys, tokens) is what a "record now, decrypt later" attacker could store. Tokens will have expired by then; an
  authKey could still sign in until the password changes, but it decrypts nothing, because the keys that unwrap the
  account key and a drop key are derived from the password separately, so each password guess still costs one
  Argon2id derivation. The TLS key exchange belongs to whatever terminates TLS. With the bundled Caddy (`--profile
  tls`) it is the X25519MLKEM768 hybrid by default: checked on 2026-11-21, the pinned `caddy:2-alpine` image (Caddy
  2.11.9) negotiated it with an OpenSSL 3.5 client. With your own proxy, it depends on that proxy.

Tests: `packages/crypto` has unit tests for every property above (bit flips, swapped and dropped chunks, a final
chunk replayed as non-final, weak and absurd KDF parameters), Argon2id known-answer vectors from the reference
implementation, and `conformance.test.ts`, which re-implements section 7 with `node:crypto` and pins a STREAM
golden vector.

## 4. Metadata the server sees

The server does see, and stores:

- the account email, account creation time, role, storage quota and usage, and the end of the new-account
  probation (`User.quotaProbationEndsAt`);
- per drop: the random drop id, the number of files, each file's ciphertext size and chunk count (ciphertext size
  is the plaintext size plus 16 bytes per 4 MiB chunk, so **file sizes leak**; size padding is future work),
  creation, expiry and last-opened times, the download limit and count, whether it is password-protected, and the
  owner if the sender was signed in;
- the time each chunk was last written (`DropChunk.storedAt`), kept with the chunk row until the drop's blobs are
  purged; the free-disk floor uses it to tell active uploads from idle ones;
- IP addresses as **prefixes only** in the database (IPv4 /24, IPv6 /48) and user-agent strings: on sessions,
  admin review grants, audit events and abuse reports (a recipient's download grant stores none since
  2026-11-22: the owner's audit event is the only record of an open);
- full IPv4 addresses and IPv6 /64 prefixes (/48 for the anonymous-create, register and failed-login-per-client
  limiters) as rate-limit keys in Redis, for the length of each limiter window (at most one hour);
- for each anonymous client key (an IPv4 address or an IPv6 /48), the MiB total of its anonymous drop creates per
  hour, kept in Redis for `ANON_BYTES_WINDOW_HOURS` (24 h by default) plus up to one hour, for the byte budget. These
  entries hold no drop id and no exact time or size, but whoever reads both Redis and the database (the operator, or
  anyone who owns the host) can match an hour bucket to `Drop.createdAt` and `totalCiphertextBytes`. On a quiet
  instance, where one anonymous drop is created in that hour, that ties a client address to that drop for the
  window;
- request logs with request id, method, path, IP prefix and status. The path is cut at the first `?`, `#` or `%23`,
  so neither a query string nor a fragment is logged: a browser never sends a share link's fragment, but a client
  that requests the link verbatim would put its key in the log. Request bodies, headers, cookies and tokens are
  never logged, a pino redaction list is a second line of defence, and Prisma errors are logged as safe fields only
  ([section 1](#1-what-cipherdrop-protects));
- an abuse report's reason, details and, only if the reporter ticks the opt-in box, the drop key (kept while the
  report is OPEN).

The server never receives: plaintext, file names, MIME types, the note, drop keys of link-mode drops (the
fragment), drop passwords, account passwords, the account key or the recovery key.

The nginx in front of the API keeps an access log in its own `privacy` format: the time, the client's IP prefix
(IPv4 /24, IPv6 /48, written like the audit log's), the method, the path cut the same way as the API's (at the first
`?`, `#` or `%23`), the status, the bytes sent and the duration. It records no user agent, referer or forwarded
addresses, and does not log hashed assets or `/healthz`. nginx's error log keeps its fixed format, which includes
the full client address and request line of the request-level errors it records (section 7). Retention: the
container logs (nginx's and the API's request log) are kept by Docker's json-file rotation, 3 x 10 MB per container.
That is bounded by size, not time: about 200,000 nginx requests. A time limit needs journald's `MaxRetentionSec` or a
log shipper that expires entries ([DEPLOYMENT.md](DEPLOYMENT.md), Operations).

## 5. Accounts and sessions

| Control | Implementation |
|---|---|
| Password | Never sent; Argon2id in a Web Worker, so the UI stays responsive. Minimum 10 characters and zxcvbn score 2 or more for account and drop passwords |
| Account lockout | 10 consecutive failed logins (wrong authKey or wrong TOTP or backup code) lock the account for 15 minutes; the error stays generic |
| Login cost | Each login, register, password change, recovery and re-authentication runs one server-side Argon2id. At most 2 run at once per API process and 32 wait (`ARGON2_MAX_CONCURRENT` / `ARGON2_MAX_QUEUE`). Beyond that the API answers 429 with `Retry-After: 1`, the same for known and unknown emails. Such a refusal counts as no attempt: no failed login and no per-client rate-limit hit, so an honest user who retries during a flood is not locked out afterwards. The API image sets `UV_THREADPOOL_SIZE=8`, so a login flood never takes the libuv threads that file I/O uses. Failed logins are also limited to 30 per 15 minutes per client (IPv4 address or IPv6 /48), and the bundled nginx allows 2 requests per second per client (burst 40) on the credential routes |
| Re-authentication | Every sensitive signed-in action needs the current password (as the derived authKey), plus a TOTP or backup code when 2FA is on: password change, recovery-key rotation, turning 2FA on or off, regenerating backup codes (TOTP code only), signing one session or all other sessions out, and account deletion. A stolen access token alone can do none of them. The budget is 10 attempts per 15 minutes per session, so a stolen session cannot use up the owner's budget and stop the owner from signing it out. Wrong proofs answer 403; the SPA checks the password locally first |
| Two-factor | TOTP (SHA-1, 6 digits, 30 s, plus or minus one step) with replay protection (the last used step is stored), secrets AES-256-GCM-encrypted at rest; 10 single-use backup codes stored as SHA-256 hashes. Turning TOTP on needs the password plus a code from the new authenticator, and it signs out every other session, because those were opened with the password alone. Admins cannot turn it off |
| Access token | JWT HS256, 15 minutes, kept in memory only (never in localStorage), sent as a Bearer header |
| Refresh token | Random 32 bytes in the `cd_rt` cookie (httpOnly, `SameSite=Strict`, `Path=/api/auth`, `Secure` in production), rotated on every refresh; presenting an already used token revokes the whole session (`SESSION_REUSE_DETECTED`), except a lost response: within 30 s of the rotation, while the successor is still unused, the successor is retired (kept as used, so presenting it later is reuse) and a fresh one issued in the same session. Sessions have an idle limit (`REFRESH_TOKEN_TTL_DAYS`, 30) and an absolute limit (`SESSION_MAX_LIFETIME_DAYS`, 30, counted from sign-in). At the absolute limit the refresh fails and the user signs in again, with the 2FA code when it is on; the cookie and the last access token end at the same moment |
| Immediate revocation | A revoked session id goes on a Redis denylist for the access-token lifetime, so its access token stops working at once (logout, "revoke others", password change, turning 2FA on, recovery, account deletion) |
| CSRF | API calls authenticate with the Bearer header, which a cross-site page cannot set; the only cookie is `SameSite=Strict` and scoped to `/api/auth` |
| Vault | The account key lives only in memory as a non-extractable `CryptoKey`; a page reload locks it, and it auto-locks after 5, 15 or 60 minutes idle (default 15). Each tab has its own vault: a tab starts locked, and Lock acts on the current tab only, so another tab the user unlocked stays unlocked until its own idle lock (after a sign-out, until its next API call finds the session revoked) |
| Recovery | The recovery key resets the password; it is rotated on use, all sessions are revoked, and a TOTP or backup code is still required when 2FA is enabled |
| Audit log | Logins, failures, lockouts, 2FA changes, password and recovery events, session revocations, and per drop: created, opened (with IP prefix and browser), unlock failures, expiry, reports. Visible to the user in Settings, Activity |
| Admin | Admin routes need role ADMIN and two-step verification on the account, both re-read from the database on every request. Without 2FA the answer is 403 `FORBIDDEN` with `details.reason` `MFA_REQUIRED`, because admin routes return reporter-supplied decryption keys. Only accounts with 2FA can be promoted (`PATCH /admin/users/:id` answers 409 otherwise), admins cannot turn 2FA off (409), and enabling 2FA signs out every other session, so every live admin session has passed the second factor. Admin review of a reported drop uses a non-consuming grant and is audited as `ADMIN_REVIEW_GRANT`. The admin audit log (`GET /admin/audit`) lists admin and operator actions only; admins cannot read an account's own events (sign-ins, opens of its drops), which only the owner sees in `/me/audit` |

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
the backup codes somewhere other than the authenticator. If the operator loses `TOTP_ENC_KEY`, no TOTP code works
any more. Backup codes are hashed, not encrypted under that key, so they still work, but each works once: signing in
uses one, turning 2FA off asks for the password and another, and new backup codes can only be issued against a TOTP
code. A user with at least two unused codes (or one, while still signed in) can therefore turn 2FA off and enrol
again; every other enrolled user is locked out.

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
  live, at most about 24 hours after expiry. The exception is the evidence hold: a drop with an open report that
  carries the key keeps its blobs (and its quota or anonymous pool bytes) until the report is resolved, at most
  `REPORT_EVIDENCE_HOLD_DAYS` (14) after expiry or the last download.
- **Per-process caps (C-15, C-09).** The API's in-flight upload and download caps count per API process; several
  instances need connection limits in the reverse proxy. The bundled nginx has two: 64 in-flight `/api` requests
  per client (`limit_conn api_ip`, keyed by IPv4 address or IPv6 /48 like the API's per-IP shares) and 400 in total
  (`api_total`), answered with 429. With N API instances behind one nginx use 48 x N + 16 and about 400 x N
  ([DEPLOYMENT.md](DEPLOYMENT.md) section 4). Per-IP caps rely on `TRUST_PROXY`, which is `1` for the bundled stack
  with or without Caddy.
- **Admin review of expired drops (C-R2-05).** Reports are accepted for expired and used-up drops until their
  blobs are purged, and the admin review grant works on them until then; the evidence hold is what keeps those
  blobs for a keyed report.
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

  The API image's Prisma CLI is installed from a lockfile cut out of `package-lock.json` at build time, so it is the
  tree `npm audit` checks ([DEPLOYMENT.md](DEPLOYMENT.md) section 5). The image layers themselves (Alpine packages,
  the npm CLI bundled with Node) are covered by the image scan below.

- **Supply chain.** Actions are pinned to commit SHAs, each checked against its version tag with `git ls-remote`.
  The images of the production stack, the Dockerfiles and CI are pinned to index digests, MinIO's excepted; the dev
  compose file, `docker-compose.yml`, stays on tags ([DEPLOYMENT.md](DEPLOYMENT.md) section 5). The Dockerfiles
  have no `# syntax=` directive, so no BuildKit frontend image is fetched. `scripts/image-pins.test.mjs` checks that
  CI's service images equal the production compose pins. Installs use `--ignore-scripts`; Dependabot proposes bumps,
  with a 7-day cooldown on new npm releases. CI scans each production image with Trivy: a CRITICAL finding with a
  fixed version fails the job, HIGH findings are reported (14 in the api image when the job was run locally on
  2026-11-21: 12 in the npm CLI bundled with Node, which the server never runs, and 2 already on the audit
  allowlist). Exceptions go in `.trivyignore` with a reason and an expiry date. Each image gets a CycloneDX SBOM as a
  build artifact. CodeQL (`security-extended`) runs on pushes to main, pull requests and weekly; gitleaks scans the
  whole history with an exact-value allowlist; zizmor audits the workflows. ESLint bans `Math.random` in
  `packages/crypto` and in the SPA's crypto and workers; `$queryRawUnsafe`, `$executeRawUnsafe` and `Prisma.raw` in
  the API (one helper for the runtime role's DDL, which PostgreSQL cannot take with bind parameters, carries the only
  exception, with its reason); `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` and
  `dangerouslySetInnerHTML` in the SPA; and requests to a literal absolute URL from the SPA.
  `eslint.config.test.mjs` proves that each ban fires. Limits: images are not published, signed or attested, and
  none of this makes the served JavaScript verifiable ([section 2.1](#21-the-server-operator-or-anyone-who-controls-the-server)
  stands). Turning on GitHub secret scanning with push protection, a repository setting, is recommended. As of
  2026-11-21 the new CI jobs (cross-engine e2e, production stack, secret scan, zizmor, CodeQL) had not yet run on
  GitHub.
- **Trusted Types are report-only.** The browser console is the only reporter: violations in production reach no
  endpoint, by design ([section 2.5](#25-cross-site-scripting)). The leak guard's handling of Firefox and WebKit
  was written from those engines' source; the cross-engine CI job runs it in Firefox, WebKit and mobile WebKit and
  passed on GitHub on 2026-11-21.
- **In-app browsers that ignore `<a download>`** were not tested; the `application/octet-stream` rule is covered by
  unit tests and a Chromium e2e test that records the type of every object-URL Blob.
- **nginx's error log.** It keeps nginx's fixed format, with the full client address and request line of the
  request-level errors it records (connection-cap and credential-route 429s, oversized bodies, upstream failures),
  so that upstream failures stay diagnosable. Raising `error_log` to `crit` would hide them.
- **Backups and snapshots keep deleted data.** The deletion guarantees (expiry, burn after reading, Delete now,
  account deletion) cover the live database and blob store. A `pg_dump`, a bucket backup or a volume snapshot taken
  before a deletion still holds that drop's rows and ciphertext, and a key that leaks later decrypts them. The S3
  driver refuses buckets where a delete would not be final: Object Lock always, versioning unless
  `S3_DELETE_ALL_VERSIONS=true` makes every delete remove each version by its id, and settings it cannot read.
- **Defence in depth on the host.** The API connects as a role with rights on rows only (`cipherdrop_app`), Redis
  needs a password, and Postgres, Redis and MinIO sit on an internal network that only the API and the one-shot
  `migrate` service join, so a compromised nginx cannot reach them and an injection in the API cannot change the
  schema. The audit log is append-only for that role (server-8): it has no UPDATE or DELETE on `AuditEvent`, and
  retention runs through the owner's `prune_audit_events()`, which keeps 90 days (a year for admin actions) whatever
  time it is given, so a compromised API cannot erase recent events (account deletion still removes the account's
  own events). It is not tamper-evident against the operator, who owns the database. Secrets are still passed only as environment variables (no `*_FILE` or Docker secrets), so they show in
  `docker inspect`; the API container no longer holds the database owner's password, but `migrate` and `postgres`
  do ([DEPLOYMENT.md](DEPLOYMENT.md) section 5).
- **Hosting abuse (server-1, ops-3).** The residual risks (a) to (d) of [section 2.7](#27-hosting-abuse-the-service-as-a-free-file-host).
  `GLOBAL_STORAGE_CAP_BYTES` is off by default and must be sized by the operator. The byte budget is not refunded
  when a drop is deleted, so create-and-delete cycles cannot reset it. The free-disk floor refuses only new drops and
  counts only active uploads, so an accepted upload that stalls for 10 minutes and then resumes can write below the
  floor. The global cap does not count an account drop that never reached READY and has left UPLOADING (deleted,
  disabled, expired) until its purge runs, within `CLEANUP_INTERVAL_SEC`. The budget's Redis buckets can be matched
  to drops on a quiet instance ([section 4](#4-metadata-the-server-sees)). A daily sign-up ceiling per IPv4 address
  or /48 is a possible follow-up (a policy choice: CGNAT and campus networks share addresses).
- **Admin step-up is per account, not per session.** Admin access is checked per account, and enrolment ends every
  other session, but there is no per-session recency (`auth_time`): a 30-day admin session needs no fresh second
  factor before it reads report keys.
- **Admins without 2FA from before this rule.** The seeded dev admin, and any account promoted to ADMIN before the
  upgrade that brought this rule (or by SQL without the `totpEnabledAt` condition), can still lack 2FA. Until its owner enrols, anyone who
  knows its password can enrol their own authenticator and open the console. Operators can list such accounts with
  `SELECT email FROM "User" WHERE role='ADMIN' AND "totpEnabledAt" IS NULL`.
- **The Argon2id limiter is per process.** N API instances run N x 2 hashes at once; under a distributed flood,
  honest logins can get 429 with `Retry-After: 1`, which does not count against them.
- **Shared-address login budget.** The 30 failed logins per 15 minutes per client are shared by everyone behind
  one IPv4 address (CGNAT, office NAT) or IPv6 /48. Anyone there can spend them and block correct logins for
  everyone behind it for 15 minutes. Successful logins and server-busy refusals are refunded. Accepted, because
  without it one client could make the server hash for every email it invents.
- **nginx's credential-route 429** is its own HTML page without `Retry-After`, like the connection caps. The limit
  stays above the API's own budgets, so honest clients meet the API's JSON 429 first.
- **The disclosure channel needs a repository setting.** GitHub private vulnerability reporting, the channel of
  [section 8](#8-reporting-a-vulnerability), `.github/SECURITY.md` and the default security.txt, exists only while
  the repository's Private vulnerability reporting setting is on. As of 2026-11-21 it was off
  (`gh api repos/exotic-Siddharth/cipherdrop/private-vulnerability-reporting` returned `{"enabled":false}`), so the
  reporting form was not available. The owner turns it on in the repository's security settings (or with
  `gh api -X PUT` on the same path) and checks that the call above returns `{"enabled":true}`.

Further limitations, also shown on `/how-it-works`:

- file sizes are visible to the server (no padding);
- a link with the key in the fragment is a bearer secret, and the browser's history keeps it (the receive page
  removes the key from the address bar, not from history);
- a link does not prove who sent it ([section 2.6](#26-sender-identity));
- the security of browser-delivered cryptography depends on the server delivering honest JavaScript
  ([section 2.1](#21-the-server-operator-or-anyone-who-controls-the-server));
- files above 256 MiB are saved through the File System Access API (`showSaveFilePicker`), which only Chromium-based
  browsers provide (MDN's compatibility data lists desktop Chrome and Edge, and Chrome for Android from version 132),
  and not all of them (Brave turns it off by default); elsewhere the receive page refuses a drop that contains such a
  file as a whole, before consuming a download (review C-03).

## 8. Reporting a vulnerability

This is a portfolio project without a bug bounty. Report a vulnerability privately through GitHub private
vulnerability reporting (<https://github.com/exotic-Siddharth/cipherdrop/security/advisories/new>), not in a public
issue, with steps to reproduce. The form exists only while the repository's setting for it is on, and as of
2026-11-21 it was off ([section 7](#7-accepted-open-points)). The policy is [.github/SECURITY.md](../.github/SECURITY.md): its scope, the
supported version (the latest commit on main), the aims (an acknowledgement within 7 days and a first assessment
within 14), publication after the fix or after 90 days, credit unless declined, and a safe-harbour statement for
good-faith research. Test only against an instance you run yourself.

Each deployment serves `/.well-known/security.txt` (RFC 9116) with its operator's contact (`SECURITY_TXT_CONTACT`;
by default this repository's reporting form). An instance whose security.txt points back at this repository has no
operator contact of its own: problems in the code are reported here, problems specific to that deployment to its
operator through the site. `.github/SECURITY.md` says the same, and the default security.txt says so in a comment.
