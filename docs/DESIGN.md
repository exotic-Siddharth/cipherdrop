# CipherDrop: Design Document

**CipherDrop** is a zero-knowledge file-sharing service. Files are encrypted **in the browser** before upload, using AES-256-GCM in an authenticated chunked stream. The server stores only ciphertext. The decryption key travels in the link's `#fragment`, which browsers never send to servers; alternatively it is wrapped under a password the server never learns. Links can expire, self-destruct after N downloads, or require a password.

Optional accounts are zero-knowledge too. The server never sees the user's password. It holds only a key wrapped under a password-derived key, which lets users manage their drops from any device.

Status: v1 design, 2026-11-07. This document is the source of truth for the build. Any deviation must be recorded in the "Decisions log".

---

## 1. Intent

CipherDrop is a portfolio project for a Cyber Security specialist. It must be demoable in two minutes, and every cryptographic decision must be defensible in an interview.

The hard problem is **applied cryptography done right in a real web app**. That covers:
- streaming authenticated encryption for multi-GB files;
- resistance to truncation and reordering;
- a key hierarchy that allows password changes without re-encrypting data;
- downgrade-resistant key derivation;
- concurrency-safe "burn after reading";
- a candid threat model.

### Goals
- A complete, polished product: send, receive, password links, burn-after-read, expiry, accounts with a dashboard, 2FA, sessions, audit log, admin moderation.
- Cryptography confined to one audited, isomorphic package (`packages/crypto`). The same code runs in the browser and in Node tests and the seed script.
- Tests that prove the security properties, including a Playwright test that tampers with ciphertext in flight and expects the UI to refuse it.
- Engineering hygiene: strict TypeScript, zod-validated contracts, OpenAPI docs, Docker, CI, metrics, and SECURITY.md with a threat model.

### Non-goals (v1)
Email sending of any kind, public file galleries, server-side previews or thumbnails, sharing with accounts (sharing is by link), mobile apps, CLI client, end-to-end encrypted chat, file versioning, passkeys/WebAuthn (possible future work), and size padding to hide lengths (documented as future work).

### Anti-goals
- **The server learns plaintext, file names, MIME types, notes, keys, or passwords**, through logs, analytics, errors or anything else. This is the one unforgivable bug.
- Home-made crypto primitives. Use WebCrypto (AES-GCM, HKDF, SHA-256) and Argon2id from `hash-wasm` only. The custom part is the *construction*, which is specified exactly below.
- Third-party scripts, CDNs, analytics, or external fonts. They break the threat model, so everything is self-hosted.
- Hard-coded secrets. Buttons that do nothing. Flaky tests.

---

## 2. Users & core journeys

Roles: **anonymous sender/recipient**, **user** (account), **admin**.

1. **Anonymous send**: on `/`, drop files and pick expiry (1 h – 3 d) and download limit (1 = burn after reading). Add an optional note, and optionally a password. Click **Encrypt & upload**. A progress view shows per-file encryption and upload, throughput, ETA, and a live hex strip of real ciphertext. When finished you get a share link with a copy button, a QR code, and "Delete now" (via owner token).
2. **Receive**: open `/d/:id#key` and see the decrypted file names, sizes and note. Click **Decrypt & download** (one download is consumed), and the files stream-decrypt and save. Afterwards you see "integrity verified" and previews for images and text. If the link has a password, you enter it first. Pages exist for missing-key, expired, exhausted and disabled links.
3. **Account**: register (the browser derives the keys). The browser shows a **recovery key** that must be saved, and the user ticks "I saved it". Log in, plus TOTP if enabled. A **vault unlock** screen appears after a reload, and the vault auto-locks after idle time. The dashboard lists your drops with decrypted names, status, downloads and expiry, plus copy-link and delete. Settings cover 2FA, sessions, password change, account deletion, and the activity (audit) log, which also shows "your drop was downloaded from 203.0.113.0/24, Chrome on Windows".
4. **Recovery**: if you forgot your password, enter your email and recovery key (plus a TOTP code if enabled), then set a new password. A new recovery key is issued.
5. **Admin**: stats with an uploads chart, the abuse-report queue (disable a drop, or dismiss), review a reported drop when the reporter voluntarily supplied its key (via a non-consuming admin grant), and users with quota and role edits.

---

## 3. Architecture

```mermaid
flowchart LR
  subgraph Browser
    UI[React SPA]
    UW[upload.worker<br/>slice → AES-GCM → PUT]
    KW[kdf.worker<br/>Argon2id WASM]
    C[packages/crypto<br/>WebCrypto]
    UI --> C
    UI --> UW --> C
    UI --> KW --> C
  end
  UI -- REST /api (ciphertext only) --> A[API · Express 5]
  UW -- PUT chunks --> A
  A -- Prisma --> P[(PostgreSQL 16)]
  A -- rate limits · session denylist · locks --> R[(Redis 7)]
  A -- blobs --> S[(Storage driver<br/>local disk · S3/MinIO)]
  A -- interval job --> CL[cleanup: expiry / exhausted / stale uploads]
```

The server **stores and returns opaque base64url blobs and byte streams**. It validates sizes, counts, tokens and quotas, but it never parses ciphertext.

---

## 4. Tech stack (pin these majors)

| Area | Choice |
|---|---|
| Runtime | Node 22 LTS, npm workspaces, TypeScript 5.x `strict`, ESM |
| API | Express **5**, Prisma **6** + PostgreSQL 16, ioredis 5, zod **3**, `@asteasolutions/zod-to-openapi` 7 + swagger-ui-express, pino + pino-http, helmet, cors, cookie-parser, express-rate-limit 7 + rate-limit-redis, jsonwebtoken (HS256), `@node-rs/argon2`, `otpauth` (TOTP), `@aws-sdk/client-s3` v3, prom-client |
| Crypto (shared) | WebCrypto (`globalThis.crypto.subtle`, available in browsers and Node 22) + `hash-wasm` (Argon2id) + zod (manifest validation) |
| Web | React 19, Vite 6+, React Router 7, TanStack Query 5, Zustand 5, Tailwind CSS **4**, lucide-react, `qrcode` (local QR generation), `@zxcvbn-ts/core` + `@zxcvbn-ts/language-common` (lazy-loaded strength meter), recharts (admin chart), date-fns, clsx + tailwind-merge, `@fontsource-variable/inter`, `@fontsource-variable/jetbrains-mono`, sonner |
| Tests | Vitest 3, Supertest 7, @testing-library/react + jsdom, Playwright (Chromium for every spec; Firefox, WebKit, mobile Chromium and mobile WebKit for the specs tagged @cross), `otpauth` in tests to compute TOTP codes |
| Tooling | ESLint 9 + typescript-eslint, Prettier 3, tsx, tsup |
| Infra | Docker Compose (`postgres:16-alpine`, `redis:7-alpine`, `cgr.dev/chainguard/minio`, used because `minio/minio` left Docker Hub; the S3 driver creates the bucket at startup), nginx (prod), GitHub Actions |

---

## 5. Repository layout

```
cipherdrop/
  package.json (workspaces)  tsconfig.base.json  eslint.config.js  .prettierrc  .editorconfig
  .gitattributes (* text=auto eol=lf)  .env.example  docker-compose.yml  docker-compose.prod.yml
  apps/
    api/
      prisma/ schema.prisma  migrations/  seed.ts
      src/
        index.ts  app.ts  config/env.ts  db/prisma.ts
        lib/          logger, errors, redis, jwt, hash (sha256, timingSafeEqualB64), ip (prefix),
                      tokens (random b64url), rateLimit, pagination, argon2, totp (otpauth + at-rest enc)
        middleware/   requestId, auth (optional/required + session denylist), requireRole,
                      validate, error, noStore
        modules/      auth/ me/ drops/ admin/ audit/      (routes.ts, service.ts, *.test.ts)
        storage/      index.ts (interface + factory), local.ts, s3.ts
        jobs/         cleanup.ts (runCleanup(now) + scheduler with Redis lock)
        openapi/
      test/
    web/
      index.html  vite.config.ts (dev proxy + preview headers incl. CSP)  playwright.config.ts
      src/
        main.tsx  router.tsx  styles/index.css
        lib/          api.ts, format.ts (bytes, durations), cn.ts, links.ts
        crypto/       kdfClient.ts (worker RPC), uploader.ts, downloader.ts, sinks.ts
        workers/      kdf.worker.ts, upload.worker.ts
        stores/       auth.ts, vault.ts, theme.ts, deviceDrops.ts
        components/ui/   Button, Input, PasswordInput, Textarea, Select, Switch, Badge, Card, Tabs,
                         Dialog, Table, Tooltip, Skeleton, Spinner, EmptyState, Pagination,
                         ProgressBar, CopyField, Kbd
        components/      layout/ (AppShell, Navbar, Footer, ThemeToggle, AdminLayout), Dropzone,
                         FileList, HexStream, QrCode, PasswordStrength, StatusBadge,
                         ExpiryBadge, RecoveryKeyCard, TotpSetup, ...
        features/        send/ receive/ auth/ dashboard/ settings/ howitworks/ admin/
      e2e/
  packages/
    crypto/src/   constants.ts, encoding.ts, kdf.ts, keys.ts, stream.ts, manifest.ts, wrap.ts,
                  account.ts, recovery.ts, links.ts, errors.ts, index.ts   (+ *.test.ts)
    shared/src/   zod schemas + types for every request/response, constants (limits, expiry options)
  docs/  DESIGN.md (this)  SECURITY.md (threat model)  ARCHITECTURE.md  API.md  DEPLOYMENT.md  screenshots/
  .github/workflows/ci.yml
  README.md  LICENSE (MIT)
```

---

## 6. Configuration (zod-validated env, fail fast)

| Var | Dev default | Notes |
|---|---|---|
| `API_PORT` | 4100 | |
| `WEB_ORIGIN` | http://localhost:5174 | |
| `DATABASE_URL` | postgresql://cipherdrop:cipherdrop@localhost:55433/cipherdrop?schema=public | |
| `REDIS_URL` | redis://localhost:56380/0 | |
| `JWT_ACCESS_SECRET` | dev value | ≥ 32 chars |
| `ACCESS_TOKEN_TTL_SEC` | 900 | |
| `REFRESH_TOKEN_TTL_DAYS` | 30 | idle limit: a session ends this long after its last refresh |
| `SESSION_MAX_LIFETIME_DAYS` | 30 (1-365) | absolute limit: a session ends this long after sign-in, however often it is refreshed; must be at least `REFRESH_TOKEN_TTL_DAYS` (checked in every environment) |
| `COOKIE_SECURE` | false | must be `true` when `NODE_ENV=production` |
| `TOTP_ENC_KEY` | dev value | 32 bytes base64; encrypts TOTP secrets at rest |
| `PRELOGIN_SECRET` | dev value | HMAC key for fake salts (no user enumeration) |
| `STORAGE_DRIVER` | local | `local` or `s3` |
| `STORAGE_DIR` | ./data/blobs | local driver root (gitignored) |
| `S3_ENDPOINT` `S3_REGION` `S3_BUCKET` `S3_ACCESS_KEY_ID` `S3_SECRET_ACCESS_KEY` `S3_FORCE_PATH_STYLE` | MinIO dev values (http://localhost:59000, us-east-1, cipherdrop, …, true) | |
| `S3_DELETE_ALL_VERSIONS` | false | delete every version and delete marker by its VersionId; without it the S3 driver refuses a versioned bucket at start-up, and it always refuses one with Object Lock |
| `ANON_MAX_DROP_BYTES` | 104857600 (100 MiB) | ciphertext bytes |
| `USER_MAX_DROP_BYTES` | 2147483648 (2 GiB) | |
| `USER_DEFAULT_QUOTA_BYTES` | 5368709120 (5 GiB) | |
| `NEW_ACCOUNT_QUOTA_BYTES` / `NEW_ACCOUNT_PROBATION_DAYS` | 268435456 (256 MiB) / 7 (0-365) | new-account probation: the quota is at most this for the first days (0 days = no probation); the end date is fixed at registration, and an admin's quota edit ends it |
| `ANON_MAX_EXPIRY_HOURS` | 72 | |
| `USER_MAX_EXPIRY_HOURS` | 720 | |
| `MAX_FILES_PER_DROP` | 20 | |
| `DOWNLOAD_GRANT_TTL_MIN` | 30 | |
| `CLEANUP_INTERVAL_SEC` | 60 | |
| `TRUST_PROXY` | false | true behind nginx (`1` for `docker-compose.prod.yml`, with or without its Caddy); in production it must be set explicitly (`0` = deliberate opt-out) |
| `CHUNK_IDLE_TIMEOUT_SEC` | 30 (1-3600) | a chunk GET whose socket sees no activity for this long is aborted (stalled readers cannot hold the storage pool) |
| `CHUNK_UPLOAD_IDLE_TIMEOUT_SEC` | 30 (1-3600) | a chunk PUT body with no data for this long is hung up (stalled body) |
| `CHUNK_UPLOAD_MIN_BYTES_PER_SEC` | 4096 (1-1048576) | minimum body rate per `CHUNK_UPLOAD_IDLE_TIMEOUT_SEC` window; stops slow-drip clients without cutting slow, steady uplinks. The effective floor for an honest client is Node's 300 s `requestTimeout` per 4 MiB chunk: about 14 KB/s per PUT, about 0.34 Mbit/s for the 3-lane web uploader |
| `MAX_CONCURRENT_CHUNK_UPLOADS` | 64 | per-process cap of in-flight chunk PUTs; above it the API answers 429 + `Retry-After` |
| `MAX_CHUNK_UPLOADS_PER_TOKEN` / `MAX_CHUNK_UPLOADS_PER_IP` | 8 / 16 | in-flight chunk PUTs per upload token and per client IP (the web uploader sends 3 at a time); above them 429 + `Retry-After`. The per-IP share is keyed per IPv4 address or IPv6 /48 (most rate limits stay per /64; `createDropAnon`, `register` and `loginIp` are per /48) |
| `MAX_CONCURRENT_CHUNK_DOWNLOADS` | 192 (max 224) | per-process cap of streaming chunk GETs; the maximum stays below the 256-socket S3 pool; above it 429 + `Retry-After` |
| `MAX_CHUNK_DOWNLOADS_PER_GRANT` / `MAX_CHUNK_DOWNLOADS_PER_IP` | 8 / 32 | in-flight chunk GETs per download grant and per client IP, keyed per IPv4 address or IPv6 /48 (the web downloader fetches one at a time) |
| `ANON_TOTAL_PENDING_BYTES` | 10737418240 (10 GiB) | ceiling on the bytes of all anonymous drops whose blobs are not purged (any status); 0 = no ceiling; check and insert are serialised by a Postgres advisory lock |
| `ANON_BYTES_PER_CLIENT` / `ANON_BYTES_WINDOW_HOURS` | 1073741824 (1 GiB) / 24 (1-720) | rolling budget of declared ciphertext bytes per anonymous client (IPv4 address or IPv6 /48), in Redis, counted in whole MiB per hour; 0 = off; beyond it 429 `UPLOAD_BUDGET_EXCEEDED` + `Retry-After`. Must be at least `ANON_MAX_DROP_BYTES` rounded up to a MiB |
| `GLOBAL_STORAGE_CAP_BYTES` | 0 (off) | ceiling on the bytes of all drops, anonymous and signed in, whose blobs are not purged; beyond it 507 `STORAGE_FULL` |
| `STORAGE_MIN_FREE_BYTES` | 1073741824 (1 GiB) | local storage only: a new drop gets 507 `STORAGE_FULL` when the blob volume's free space, minus the declared bytes of uploads active in the last 10 minutes and of the new drop, would fall below this; 0 = off |
| `ALLOW_ANONYMOUS_UPLOADS` / `ALLOW_REGISTRATION` | true / true | operator switches: false answers an anonymous `POST /drops` or `POST /auth/register` with 403 `FEATURE_DISABLED`; `GET /api/config` tells the SPA |
| `ARGON2_MAX_CONCURRENT` / `ARGON2_MAX_QUEUE` | 2 (1-64) / 32 (0-10000) | server-side Argon2id hashes running and waiting, per process; beyond the queue 429 `RATE_LIMITED` + `Retry-After: 1` |
| `UV_THREADPOOL_SIZE` | 4 (libuv's default) | read by libuv; parsed only so that `ARGON2_MAX_CONCURRENT` must stay below it (checked in every environment). The API image sets 8 |
| `API_DOCS_UI` | false | serves Swagger UI at `/api/docs`; the dev `.env.example` sets it to true; refused when `NODE_ENV=production` |
| `SEED_ADMIN_PASSWORD` / `SEED_DEMO_PASSWORD` | dev values | |

With `NODE_ENV=production` the API refuses to start unless `DATABASE_URL`, `REDIS_URL`, `WEB_ORIGIN` (a bare origin) and `TRUST_PROXY` are set explicitly and `COOKIE_SECURE=true`; it also refuses `RATE_LIMITS_ENABLED=false`, `API_DOCS_UI=true`, and a development, test or template placeholder in a secret or in the password of `DATABASE_URL` or `REDIS_URL`. `apps/api/.env` is not loaded in production.

Deployment-level variables, outside the API's schema: `POSTGRES_PASSWORD`, `POSTGRES_APP_PASSWORD` and `REDIS_PASSWORD` (`docker-compose.prod.yml`); `MIGRATE_ON_START` (default true) and `DB_RUNTIME_ROLE` / `DB_RUNTIME_PASSWORD` (the API image's entrypoint and its `migrate` command); `SECURITY_TXT_CONTACT` and `SECURITY_TXT_POLICY` (web build arguments for `/.well-known/security.txt`).

Ports: web **5174**, api **4100**, Postgres **55433**, Redis **56380**, MinIO **59000** (API) / **59001** (console). The Vite dev server proxies `/api` to the API, so the SPA is always same-origin. `vite preview` serves the production build **with the production security headers, including the CSP** (§12). The e2e tests run against preview, which proves the CSP doesn't break the app.

---

## 7. Cryptographic design (`packages/crypto`, normative)

All byte strings in JSON and URLs are **base64url without padding** (`b64url`). Text is UTF-8. Passwords are normalised with `.normalize('NFKC')` before KDF.

### 7.1 Constants
```
VERSION        = 1
CHUNK_SIZE     = 4 MiB (4 194 304 bytes of plaintext per chunk)
TAG_BYTES      = 16        NONCE_BYTES = 12        KEY_BYTES = 32       FILE_ID_BYTES = 16
KDF_DEFAULT    = { memoryKiB: 65536, iterations: 3, parallelism: 1 }      // Argon2id, 32-byte output
KDF_MIN        = { memoryKiB: 19456, iterations: 2, parallelism: 1 }      // client REFUSES weaker params (downgrade protection)
KDF_MAX        = { memoryKiB: 262144, iterations: 10, parallelism: 4 }    // client refuses absurd params (DoS)
HKDF info labels (UTF-8):
  "cipherdrop/v1/file-key"  "cipherdrop/v1/manifest-key"
  "cipherdrop/v1/drop-password-wrap"  "cipherdrop/v1/drop-password-auth"
  "cipherdrop/v1/account-auth"  "cipherdrop/v1/account-enc"
  "cipherdrop/v1/recovery-enc"  "cipherdrop/v1/recovery-auth"
AES-GCM AAD labels:
  chunk: "cipherdrop/v1/chunk"   manifest: "cipherdrop/v1/manifest"
  wrap:  "cipherdrop/v1/wrap/drop-password" | "…/wrap/account" | "…/wrap/recovery" | "…/wrap/owner"
```
HKDF is WebCrypto HKDF-SHA-256 with the IKM imported as a raw `HKDF` key. **The salt is empty unless stated otherwise.**

### 7.2 Drop keys and file encryption (STREAM construction)
- `dropKey` (DK) = 32 random bytes per drop. It is the link secret.
- `fileId` = b64url(16 random bytes), generated by the client and unique within the drop.
- `fileKey` = HKDF(ikm = DK, salt = b64urlDecode(fileId), info = "…/file-key") → an AES-256-GCM key (non-extractable).
- `manifestKey` = HKDF(ikm = DK, salt = ∅, info = "…/manifest-key").
- A file of `size` bytes is split into `chunkCount = max(1, ceil(size / CHUNK_SIZE))` chunks; a 0-byte file is a single empty chunk.
- Chunk `i` (0-based): `nonce_i = 0x00×7 ‖ uint32_be(i) ‖ (i == chunkCount−1 ? 0x01 : 0x00)` and `ct_i = AES-GCM(fileKey, nonce_i, aad = "…/chunk", pt_i)`, so each ciphertext chunk is plaintext length + 16 bytes. The position counter and the last-chunk flag sit inside the nonce, so **reordering, truncation and extension all fail authentication**: STREAM, Hoang–Reyhanitabar–Rogaway–Vizár 2015. Nonces never repeat, because every file has a unique key from its random `fileId` salt.
- `ciphertextSize(size) = size + 16 × chunkCount`.
- The decryptor must receive chunks in order. It uses `isLast = (i == chunkCount − 1)`, where `chunkCount` comes from the authenticated manifest, and it throws `IntegrityError` on any failure. A missing chunk is also an `IntegrityError`.

### 7.3 Manifest
```ts
Manifest = { v: 1, createdAt: number /*ms*/, note: string | null /*≤ 2000 chars*/,
  files: { id: string, name: string /*1..1024*/, size: number, type: string /*≤255, may be ""*/,
           lastModified: number, chunkSize: 4194304, chunkCount: number }[] /*1..20*/ }
```
`encryptedManifest = b64url(nonce(12 random) ‖ AES-GCM(manifestKey, nonce, aad = "…/manifest", utf8(JSON)))`, at most 64 KiB encoded. `decryptManifest` validates the result with zod.

### 7.4 Password-protected drops
1. The sender picks a password. `salt` = 16 random bytes.
2. `pk` = Argon2id(password, salt, KDF_DEFAULT, 32 bytes).
3. `wrapKey` = HKDF(pk, info = "…/drop-password-wrap"); `authKey` = HKDF-bits(pk, info = "…/drop-password-auth", 256).
4. `wrappedDropKey` = wrap(wrapKey, DK, aad = "…/wrap/drop-password"), where wrap(k, bytes, aad) = b64url(nonce ‖ AES-GCM(k, nonce, aad, bytes)).
5. The server stores `{kdf: {salt, memoryKiB, iterations, parallelism}, wrappedDropKey, authKeyHash = b64url(SHA-256(authKey))}`. The link has **no fragment**.
6. The recipient derives `authKey` and calls `POST /unlock`. The server compares SHA-256 of the presented key in constant time and only then releases `wrappedDropKey`, under a rate limit, which bounds online guessing. Offline guessing requires a database breach plus Argon2id work per guess (documented in SECURITY.md).

### 7.5 Zero-knowledge accounts
- **Prelogin**: `POST /auth/prelogin {email}` returns `{kdf}`. An unknown email gets a deterministic fake salt `HMAC-SHA256(PRELOGIN_SECRET, lower(email))[0..16]` with default params, so the response shape is identical and users cannot be enumerated.
- `mk` = Argon2id(password, kdf.salt, kdf params). `authKey` = HKDF-bits(mk, "…/account-auth"), sent to the server as b64url. `encKey` = HKDF(mk, "…/account-enc").
- **Registration**:
  - the client generates `accountKey` (AK, 32 random bytes) and computes `wrappedAccountKey` = wrap(encKey, AK, "…/wrap/account");
  - the **recovery key** RK = 20 random bytes, shown as Crockford base32 in 8 groups of 4 (`XXXX-XXXX-…`, 32 chars);
  - from RK: `recoveryEnc` = HKDF(RK, "…/recovery-enc") and `recoveryAuth` = HKDF-bits(RK, "…/recovery-auth");
  - `wrappedAccountKeyRecovery` = wrap(recoveryEnc, AK, "…/wrap/recovery") and `recoveryAuthHash` = b64url(SHA-256(recoveryAuth)). RK carries 160 bits of entropy, so a fast hash is fine.
- **Server storage**: it never sees the password. It stores `authKeyHash = Argon2id_server(authKey)` (`@node-rs/argon2`, m = 19456, t = 2, p = 1) as defence in depth, plus the kdf params, wrapped keys and recovery hash.
- **Owner wrapping**: a logged-in sender stores `ownerWrappedKey` = wrap(AK, DK, "…/wrap/owner") with the drop. The dashboard can then decrypt manifests and rebuild share links on any device.
- **Password change**: re-derive with a new salt and re-wrap the **same** AK. No drop is re-encrypted. The server verifies `currentAuthKey` and revokes all other sessions.
- **Recovery**:
  1. The client sends `recoveryAuth` and the server compares hashes in constant time.
  2. The server returns `wrappedAccountKeyRecovery` and a 10-minute recovery token.
  3. The client unwraps AK and sets a new password. It **must rotate the recovery key** (sending a new wrapped copy and hash).
  4. All sessions are revoked. TOTP is required if enabled.
- **Vault lifecycle**: AK lives **only in memory** (Zustand store, never persisted). After a page reload the session refreshes, but the vault is locked: `GET /auth/vault` → password prompt → local unwrap. Auto-lock after idle is configurable (5 / 15 / 60 min, default 15).

### 7.6 Links
- With a key: `${origin}/d/${dropId}#${b64url(DK)}` (43-char fragment).
- Password drops: `${origin}/d/${dropId}`.
- `parseShareFragment` strips a leading `#`, URL-decodes the fragment, and strips trailing characters outside the base64url alphabet (chat apps append `.`, `)` or `,`). It then requires exactly 43 chars, decoding to 32 bytes; anything else returns `null`, and the UI shows "this link is incomplete".

### 7.7 Public API of `packages/crypto` (exact names; the scaffold creates these signatures)
```ts
// encoding
b64urlEncode(b: Uint8Array): string; b64urlDecode(s: string): Uint8Array; utf8Encode/utf8Decode; randomBytes(n)
// keys & stream
generateDropKey(): Uint8Array; generateFileId(): string
deriveFileKey(dk, fileId): Promise<CryptoKey>; deriveManifestKey(dk): Promise<CryptoKey>
chunkCount(size, chunkSize?): number; ciphertextSize(size, chunkSize?): number; chunkNonce(i, isLast): Uint8Array
encryptChunk(key, i, isLast, pt): Promise<Uint8Array>; decryptChunk(key, i, isLast, ct): Promise<Uint8Array>
createChunkDecryptor(key, chunkCount): { decryptNext(ct: Uint8Array): Promise<Uint8Array>; done(): boolean }   // enforces order
// manifest
encryptManifest(dk, m: Manifest): Promise<string>; decryptManifest(dk, blob): Promise<Manifest>; ManifestSchema
// wrap / hashes / kdf
wrapKey(k: CryptoKey, bytes, aad): Promise<string>; unwrapKey(k, blob, aad): Promise<Uint8Array>
importAesKey(raw): Promise<CryptoKey>; sha256(b): Promise<Uint8Array>; hashForServer(authKey): Promise<string>
argon2id(password, salt, params): Promise<Uint8Array>; assertKdfParams(params): void  // KdfParamsError
// drop password
deriveDropPasswordKeys(password, kdf): Promise<{ wrapKey: CryptoKey; authKey: Uint8Array }>
createPasswordProtection(dk, password): Promise<{ kdf, wrappedDropKey, authKeyHash, authKey }>
// accounts
deriveAccountKeys(password, kdf): Promise<{ authKey: Uint8Array; encKey: CryptoKey }>
createAccountBundle(password): Promise<{ kdf, authKey, accountKey, wrappedAccountKey, recoveryKey /*formatted*/, wrappedAccountKeyRecovery, recoveryAuthHash }>
rewrapForNewPassword(accountKey, newPassword): Promise<{ kdf, authKey, wrappedAccountKey }>
generateRecoveryKey(): { raw: Uint8Array; formatted: string }; parseRecoveryKey(s): Uint8Array   // Crockford, case-insensitive, ignores - and spaces
deriveRecoveryKeys(raw): Promise<{ encKey: CryptoKey; authKey: Uint8Array }>
// links
buildShareLink(origin, dropId, dk | null): string; parseShareFragment(hash): Uint8Array | null
// errors
IntegrityError, WrongPasswordError, KdfParamsError, InvalidLinkError
```

---

## 8. Data model (Prisma)

```prisma
enum Role         { USER ADMIN }
enum DropStatus   { UPLOADING READY EXHAUSTED EXPIRED DELETED DISABLED }
enum ReportReason { MALWARE PHISHING ILLEGAL COPYRIGHT OTHER }
enum ReportStatus { OPEN RESOLVED DISMISSED }
enum AuditAction  {
  REGISTER LOGIN_SUCCESS LOGIN_FAILURE LOGIN_LOCKED MFA_CHALLENGE_FAILED MFA_ENABLED MFA_DISABLED
  BACKUP_CODE_USED BACKUP_CODES_REGENERATED PASSWORD_CHANGED RECOVERY_USED RECOVERY_KEY_ROTATED
  SESSION_REVOKED SESSION_REUSE_DETECTED LOGOUT ACCOUNT_DELETED
  DROP_CREATED DROP_COMPLETED DROP_OPENED DROP_UNLOCK_FAILED DROP_DELETED DROP_EXPIRED
  DROP_EXHAUSTED DROP_REPORTED DROP_DISABLED
}

model User {
  id                        String    @id @default(cuid())
  email                     String    @unique                 // lower-case
  role                      Role      @default(USER)
  authKeyHash               String
  kdfSalt                   String
  kdfMemoryKiB              Int
  kdfIterations             Int
  kdfParallelism            Int
  wrappedAccountKey         String
  wrappedAccountKeyRecovery String
  recoveryAuthHash          String
  totpSecretEnc             String?
  totpPendingSecretEnc      String?
  totpEnabledAt             DateTime?
  totpLastStep              Int?
  autoLockMinutes           Int       @default(15)
  storageQuotaBytes         BigInt
  storageUsedBytes          BigInt    @default(0)
  quotaProbationEndsAt      DateTime?                       // null = no probation; set at registration, cleared by an admin quota edit
  failedLoginCount          Int       @default(0)
  lockedUntil               DateTime?
  createdAt                 DateTime  @default(now())
  updatedAt                 DateTime  @updatedAt
  sessions    Session[]
  backupCodes BackupCode[]
  drops       Drop[]
  auditEvents AuditEvent[]
}

model Session {                       // one per login ("token family")
  id         String    @id @default(cuid())
  userId     String
  user       User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  userAgent  String?
  ipPrefix   String?
  createdAt  DateTime  @default(now())
  lastUsedAt DateTime  @default(now())
  expiresAt  DateTime
  revokedAt  DateTime?
  tokens     RefreshToken[]
  @@index([userId])
}

model RefreshToken {
  id        String    @id @default(cuid())
  sessionId String
  session   Session   @relation(fields: [sessionId], references: [id], onDelete: Cascade)
  tokenHash String    @unique              // sha256(token)
  createdAt DateTime  @default(now())
  expiresAt DateTime
  usedAt    DateTime?                      // set on rotation; presenting a used token = reuse → revoke session
}

model BackupCode {
  id       String    @id @default(cuid())
  userId   String
  user     User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  codeHash String
  usedAt   DateTime?
  @@index([userId])
}

model Drop {
  id                   String     @id                  // b64url(16 random bytes), server-generated
  ownerId              String?
  owner                User?      @relation(fields: [ownerId], references: [id], onDelete: Cascade)
  ownerTokenHash       String
  uploadTokenHash      String
  status               DropStatus @default(UPLOADING)
  encryptedManifest    String     @db.Text
  ownerWrappedKey      String?
  passwordProtected    Boolean    @default(false)
  pwKdfSalt            String?
  pwKdfMemoryKiB       Int?
  pwKdfIterations      Int?
  pwKdfParallelism     Int?
  wrappedDropKey       String?
  authKeyHash          String?
  totalCiphertextBytes BigInt
  fileCount            Int
  maxDownloads         Int
  downloadCount        Int        @default(0)
  expiresAt            DateTime
  createdAt            DateTime   @default(now())
  readyAt              DateTime?
  lastOpenedAt         DateTime?
  deletedAt            DateTime?
  blobsDeletedAt       DateTime?
  files   DropFile[]
  chunks  DropChunk[]
  grants  DownloadGrant[]
  reports Report[]
  @@index([status, expiresAt])
  @@index([ownerId, createdAt])
  @@index([ownerId, blobsDeletedAt])   // anonymous capacity sum (ownerId null) without a full scan
}

model DropFile {
  dropId          String
  id              String                // client fileId (b64url, 22 chars)
  drop            Drop    @relation(fields: [dropId], references: [id], onDelete: Cascade)
  ciphertextBytes BigInt
  chunkCount      Int
  @@id([dropId, id])
}

model DropChunk {
  dropId String
  fileId String
  index  Int
  size   Int
  sha256 String                         // hex of ciphertext
  blobVersion String?                   // storage key suffix <index>.<version>; null = legacy <index> key
  storedAt    DateTime @default(now())  // set by every chunk PUT; the free-disk floor's activity check
  drop   Drop   @relation(fields: [dropId], references: [id], onDelete: Cascade)
  @@id([dropId, fileId, index])
  @@index([dropId, storedAt])
}

model DownloadGrant {
  id        String   @id @default(cuid())
  dropId    String
  drop      Drop     @relation(fields: [dropId], references: [id], onDelete: Cascade)
  tokenHash String   @unique
  isAdmin   Boolean  @default(false)
  ipPrefix  String?
  createdAt DateTime @default(now())
  expiresAt DateTime
  @@index([dropId, expiresAt])
}

model Report {
  id               String       @id @default(cuid())
  dropId           String
  drop             Drop         @relation(fields: [dropId], references: [id], onDelete: Cascade)
  reason           ReportReason
  details          String?      @db.VarChar(1000)
  providedKey      String?                      // only if the reporter explicitly opted in
  reporterIpPrefix String?
  status           ReportStatus @default(OPEN)
  createdAt        DateTime     @default(now())
  resolvedAt       DateTime?
  resolvedById     String?
}

model AuditEvent {
  id        String      @id @default(cuid())
  userId    String?
  user      User?       @relation(fields: [userId], references: [id], onDelete: Cascade)
  dropId    String?
  action    AuditAction
  ipPrefix  String?
  userAgent String?
  metadata  Json?
  createdAt DateTime    @default(now())
  @@index([userId, createdAt])
  @@index([dropId])
}
```

`BigInt` columns are serialised as JSON numbers (all values stay below 2⁵³). IP addresses are stored only as prefixes: IPv4 /24 (`203.0.113.0/24`) and IPv6 /48.

---

## 9. Drop lifecycle & invariants

```
UPLOADING --complete (all chunks present)--> READY --open hits maxDownloads--> EXHAUSTED
    |                                          |                                  |
    | (24 h stale)                             | expiresAt passes                 | last grant expires
    v                                          v                                  v
  DELETED                                   EXPIRED                    blobs deleted (status stays EXHAUSTED)
owner/admin delete → DELETED; admin disable → DISABLED   (blobs deleted immediately in both cases)
```

- **Atomic consumption**: `/open` is a single conditional `UPDATE … SET downloadCount = downloadCount + 1 WHERE id = $1 AND status = 'READY' AND expiresAt > now() AND downloadCount < maxDownloads RETURNING …`. If that makes `downloadCount == maxDownloads`, the same transaction sets `status = EXHAUSTED`. With N concurrent opens on a 1-download link, **exactly one** succeeds (integration test).
- **Grants**: a successful open creates a `DownloadGrant`, an opaque token valid for `DOWNLOAD_GRANT_TTL_MIN`. Each chunk GET extends the expiry, up to 24 h after the grant was created. Chunk GETs need a valid grant for that drop, and the drop must not be DELETED or DISABLED. EXPIRED drops keep serving chunks to a live grant, and their blobs are deleted once no grant is live (at most about 24 h after expiry). EXHAUSTED drops stay downloadable while a grant lives, so a burn-after-read download can still resume. As built (2026-11-22, critic-2), a grant serves at most `DOWNLOAD_GRANT_BYTE_FACTOR` (3) times the drop's ciphertext size: each chunk GET adds the chunk's size to `DownloadGrant.servedBytes` in the same conditional update that slides the expiry, before the chunk streams, and a GET past the budget is 401.
- **Upload validation**:
  - `index < chunkCount`;
  - non-final chunks are exactly `CHUNK_SIZE + 16` bytes, and the final chunk is between `16` and `CHUNK_SIZE + 16` bytes;
  - `X-Chunk-SHA256` must match the body;
  - re-PUT of the same index overwrites, so retries are idempotent.

  `complete` requires every chunk and requires each file's chunk sizes to sum to its declared `ciphertextBytes`. It moves the drop to READY, adds the bytes to the owner's `storageUsedBytes`, and writes an audit record.
- **Quotas**: on create, enforce the per-drop byte limit (anon vs user), `MAX_FILES_PER_DROP`, the expiry ceiling, `maxDownloads ∈ {1,2,3,5,10,20,50,100}` (anonymous ≤ 10), and the user quota (`storageUsedBytes + new ≤ storageQuotaBytes`). Bytes are released when the drop's blobs are deleted.
- **Cleanup** (`runCleanup(now)`, every `CLEANUP_INTERVAL_SEC`, under a Redis lock `lock:cleanup`):
  - READY drops past `expiresAt` → EXPIRED (blobs are deleted once no grant is live, see Grants);
  - EXHAUSTED drops with no unexpired grant → delete blobs;
  - UPLOADING drops older than 24 h or past `expiresAt` → DELETED, delete blobs (chunk PUT, upload-status and complete answer 410 EXPIRED after expiry); as built (2026-11-21), also an UPLOADING drop that has stored no chunk one hour after its create, so a pure reservation frees the quota, the anonymous pool and the global cap it held;
  - release quota, write audit events (`DROP_EXPIRED` / `DROP_EXHAUSTED`) to the owner if there is one;
  - retention: sessions (cascading refresh tokens) and refresh tokens 7 days past expiry or revocation, audit events and closed reports 90 days old are deleted. Purging a drop scrubs its password verifier, wrapped drop key, KDF fields and chunk rows, plus the manifest and owner wrap for DELETED and anonymous drops. Drop rows themselves are kept.

  `runCleanup` is pure-ish (takes `now`) and unit/integration tested.

---

## 10. REST API (prefix `/api`)

Conventions:
- Errors: `{error:{code, message, details?}}` with codes `VALIDATION_ERROR|UNAUTHORIZED|FORBIDDEN|NOT_FOUND|CONFLICT|GONE|RATE_LIMITED|PAYLOAD_TOO_LARGE|QUOTA_EXCEEDED|INTERNAL`. As built (2026-11-21, hosting abuse): also `FEATURE_DISABLED` (403, `details.feature` `anonymousUploads` or `registration`), `UPLOAD_BUDGET_EXCEEDED` (429 + `Retry-After`, `details {limitBytes, windowHours}`) and `STORAGE_FULL` (507, no details). A 403 `FORBIDDEN` the user can fix carries `details.reason` (`ForbiddenReasonSchema`: `MFA_REQUIRED`), following the `GONE` pattern.
- Paging: `?page&pageSize` → `{items,total,page,pageSize}`.
- `Cache-Control: no-store` on every `/api` response.
- All schemas are zod in `packages/shared` and appear in `/api/openapi.json` (always) and in Swagger UI at `/api/docs` (only with `API_DOCS_UI=true`, development).

**Tokens:**
- Access token: JWT HS256, 15 min, claims `{sub, role, sid}`, sent as Bearer, kept in memory by the SPA. A revoked session id is added to the Redis denylist `revoked:sid:<sid>` (TTL = access TTL), and the auth middleware rejects it **immediately**.
- Refresh token: opaque 32 bytes in cookie `cd_rt` (httpOnly, SameSite=Strict, Path=/api/auth, Secure in prod). It rotates on every refresh. Presenting a used token revokes the session and writes `SESSION_REUSE_DETECTED`.
- `mfaToken` and `recoveryToken` are short-lived JWTs with a `purpose` claim (5 min and 10 min).

### Auth & account
| Method & path | Auth | Request → Response |
|---|---|---|
| POST /auth/prelogin | – | `{email}` → `{kdf: KdfParams}` |
| POST /auth/register | – | `{email, authKey, kdf, wrappedAccountKey, wrappedAccountKeyRecovery, recoveryAuthHash}` → 201 `AuthSuccess` + cookie. 409 if the email exists. The server checks `kdf` ≥ KDF_MIN |
| POST /auth/login | – | `{email, authKey}` → `{mfaRequired:false, ...AuthSuccess}` or `{mfaRequired:true, mfaToken}`. Generic 401. 10 consecutive failures lock the account for 15 min (still a generic error) |
| POST /auth/login/mfa | – | `{mfaToken, code}` (6-digit TOTP or backup code) → `AuthSuccess` + cookie |
| POST /auth/refresh | cookie | → `{user: Me, accessToken}` + rotated cookie |
| POST /auth/logout | cookie | → 204 |
| GET /auth/vault | user | → `{wrappedAccountKey, kdf}` |
| POST /auth/password | user | `{currentAuthKey, code?, newAuthKey, kdf, wrappedAccountKey}` → 204 (other sessions revoked); `code` (TOTP or backup) required when TOTP is on |
| POST /auth/recovery/start | – | `{email, recoveryAuthKey}` → `{recoveryToken, wrappedAccountKeyRecovery, mfaRequired}` (generic 401 on mismatch or unknown email) |
| POST /auth/recovery/complete | – | `{recoveryToken, code?, newAuthKey, kdf, wrappedAccountKey, wrappedAccountKeyRecovery, recoveryAuthHash}` → `AuthSuccess` + cookie |
| POST /auth/recovery/rotate | user | `{authKey, code?, wrappedAccountKeyRecovery, recoveryAuthHash}` → 204 (audited as `RECOVERY_KEY_ROTATED`; sessions stay signed in) |
| POST /auth/mfa/totp/setup | user | → `{secret, otpauthUrl}` (stored as pending, encrypted) |
| POST /auth/mfa/totp/enable | user | `{authKey, code}` (code from the new authenticator) → `{backupCodes: string[10]}`; signs out every other session |
| POST /auth/mfa/totp/disable | user | `{authKey, code}` → 204; 409 `CONFLICT` for admins |
| POST /auth/mfa/backup-codes | user | `{authKey, code}` (a TOTP code only) → `{backupCodes}` (regenerate) |
| GET /auth/sessions | user | → `SessionInfo[]` (`current` flag via sid) |
| DELETE /auth/sessions/:id | user | `{authKey, code?}` → 204; 403 on a wrong proof |
| POST /auth/sessions/revoke-others | user | `{authKey, code?}` → 204; 403 on a wrong proof |
| PATCH /me/settings | user | `{autoLockMinutes: 5|15|60}` → `{user: Me}` |
| DELETE /me | user | `{authKey, code?}` → 204 (deletes the user, their drops and blobs) |
| GET /me | user | → `{user: Me}`; `Me.storageQuotaBytes` is the quota that applies now, `Me.quotaProbationEndsAt` is ISO or null |
| GET /me/audit | user | `?action&page&pageSize` → Page<AuditEventDto> |
| GET /me/drops | user | `?status=active|expired|all&page&pageSize` → Page<OwnerDropSummary `{id, status, fileCount, totalBytes, maxDownloads, downloadCount, downloadsRemaining, expiresAt, createdAt, lastOpenedAt, passwordProtected, encryptedManifest, ownerWrappedKey}`>. active = UPLOADING/READY; expired = EXPIRED/EXHAUSTED/DISABLED; all = everything except DELETED |

TOTP uses `otpauth`: SHA1, 6 digits, a 30 s period, a ±1 step window, and replay protection via `totpLastStep`. Backup codes are 10 × 10 Crockford chars (`xxxxx-xxxxx`), stored as SHA-256 hashes and single-use.

As built (2026-11-21): every route above that changes how the account signs in, destroys data or ends sessions re-authenticates with one rule (`requireAccountProof`): the current `authKey`, plus a TOTP or backup code when TOTP is on. That covers password change, recovery-key rotation, TOTP enable and disable, backup codes, both session-revocation routes and `DELETE /me`. `PATCH /me/settings` and logout need no step-up.

### Drops
| Method & path | Auth | Request → Response |
|---|---|---|
| POST /drops | optional user | `CreateDropRequest {encryptedManifest, files:[{id, ciphertextBytes, chunkCount}], expiresInHours, maxDownloads, password?: {kdf, wrappedDropKey, authKeyHash}, ownerWrappedKey?}` → 201 `{dropId, ownerToken, uploadToken, expiresAt}`. As built: 403 `FEATURE_DISABLED` (anonymous, switched off), 413 `QUOTA_EXCEEDED` with `details {quotaBytes, usedBytes, probationEndsAt?}`, 429 `UPLOAD_BUDGET_EXCEEDED`, 507 `STORAGE_FULL` |
| PUT /drops/:id/files/:fileId/chunks/:index | `Bearer uploadToken` | body `application/octet-stream` (raw, limit CHUNK_SIZE + 16), header `X-Chunk-SHA256` (lowercase hex of the ciphertext) → 204 (429 `RATE_LIMITED` + `Retry-After` at the in-flight caps) |
| GET /drops/:id/upload-status | `Bearer uploadToken` | → `{files:[{id, chunkCount, received:[{index, sha256}]}]}` |
| POST /drops/:id/complete | `Bearer uploadToken` | → `{status:"READY"}` (409 with the missing chunks if incomplete) |
| GET /drops/:id | – | → `DropMeta {id, status, fileCount, totalBytes, expiresAt, maxDownloads, downloadsRemaining, passwordProtected, encryptedManifest: string\|null /*null when password-protected*/, passwordKdf: KdfParams\|null, createdAt}`. 404 if unknown; **410** `GONE` with `details.reason` ∈ EXPIRED/EXHAUSTED/DELETED/DISABLED |
| POST /drops/:id/unlock | – | `{authKey}` → `{wrappedDropKey, encryptedManifest}`. 401 on mismatch (audited to the owner as `DROP_UNLOCK_FAILED`). Rate limits: 5/15 min per drop+IP, 20/h per drop |
| POST /drops/:id/open | – | `{authKey?}` (required for password drops) → `{downloadToken, expiresAt, downloadsRemaining}`. Atomic consumption (§9). Audited to the owner as `DROP_OPENED` (with ipPrefix + UA) |
| GET /drops/:id/files/:fileId/chunks/:index | `Bearer downloadToken` | → ciphertext stream (`application/octet-stream`) (429 `RATE_LIMITED` + `Retry-After` at the in-flight caps) |
| DELETE /drops/:id | owner (`X-Owner-Token` or owner session) | → 204 (blobs deleted) |
| POST /drops/:id/report | – | `{reason, details?, decryptionKey?}` → 201. Rate limit 5/h per IP |

### Config
| Method & path | Auth | Response |
|---|---|---|
| GET /config | – | `{anonymousUploads, registration}`: the two operator switches (static environment), never how full the server is (as built, 2026-11-21) |

### Admin (`role=ADMIN`)
As built (2026-11-21): admin routes need role ADMIN **and** two-step verification on the account, both re-read from the database on every request; otherwise 403 `FORBIDDEN` with `details.reason` `MFA_REQUIRED` (non-admins still get a bare 403). Role ADMIN implies TOTP on: promoting an account without it, and TOTP disable by an admin, both answer 409 `CONFLICT`.

| Method & path | Purpose |
|---|---|
| GET /admin/stats | `{users, activeDrops, totalDrops, storageBytes, openReports, uploadsLast14d:[{date, drops, bytes}]}` |
| GET /admin/reports?status | Page<AdminReport `{id, reason, details, status, createdAt, hasKey, decryptionKey (only here), drop:{id, status, fileCount, totalBytes, ownerEmail, createdAt}}`> |
| POST /admin/reports/:id/resolve | `{action:"DISABLE_DROP"\|"DISMISS"}` → 204 |
| POST /admin/drops/:id/grant | non-consuming review grant → `{downloadToken, expiresAt, encryptedManifest}` (audited) |
| GET /admin/users?search · PATCH /admin/users/:id | `{role?, storageQuotaBytes?}`. `AdminUser.storageQuotaBytes` is the stored quota and `effectiveQuotaBytes` the one that applies now; a PATCH with `storageQuotaBytes` ends the probation; 409 when promoting an account without 2FA |

Health: `/healthz`, `/readyz` (DB + Redis + storage), `/metrics`.

**Rate limits** (Redis store, `Retry-After`):

| Endpoint | Limit |
|---|---|
| prelogin / login | 10 per 15 min per IP+email |
| loginIp (as built, 2026-11-21) | 30 failed logins per 15 min per IPv4 address or IPv6 /48, whatever the email; successful logins refunded |
| reauth (as built) | 10 per 15 min per session, shared by every route that re-authenticates (`DELETE /me` included) |
| register | 5/h per IP (as built: per IPv4 address or IPv6 /48) |
| recovery | 5/h per IP |
| create drop (anon) | 10/h per IP (as built: per IPv4 address or IPv6 /48) |
| create drop (user) | 60/h per user |
| chunk PUT / GET | 1200/min per upload/download token and 6000/min per IP, the IP limiter first so random tokens cannot dodge it (exempt from the global limit) |
| open | 30/h per IP |
| unlock | `unlockDropIp` 5 failures per 15 min per drop+IP and `unlockDrop` 20 failures per hour per drop. Only failed authKey checks count; `/unlock` and `/open` (password drops) share the budget. An attacker who uses up the per-drop budget also blocks recipients until the window ends |
| report | 5/h per IP |
| global | 600/min per IP |

Every route that runs a server-side Argon2id can answer 429 + `Retry-After: 1` when the per-process hash queue is full (`ARGON2_MAX_QUEUE`); `login`, `loginIp`, `register`, recovery complete and `reauth` do not count that answer. "Per IP" is the full IPv4 address or the IPv6 /64 unless stated.

---

## 11. Frontend

### 11.1 Design language ("paper, ink and teal")
- Light-first, with a dark theme toggle. CSS variables mapped into Tailwind 4 `@theme`.
- Light palette:
  - background `#f6f7f9`, surface `#ffffff`, border `#e4e7ec`, text `#0f172a`, muted `#64748b`;
  - **primary teal `#0f766e`** (hover `#115e59`), accent `#14b8a6`;
  - success `#15803d`, warning `#b45309`, danger `#dc2626`.
- Dark palette: background `#0b1014`, surface `#11181d`, border `#1f2a31`, text `#e2e8f0`, muted `#94a3b8`, primary `#2dd4bf`.
- Type: Inter Variable for the UI; JetBrains Mono Variable for links, keys, hashes, recovery codes and the hex strip.
- Motifs (lucide icons): Lock, KeyRound, ShieldCheck, Flame (burn after reading), Timer, FileLock2.
- One memorable touch: **HexStream**, a strip that shows real ciphertext bytes (the first 48 bytes of the latest encrypted chunk, in hex) scrolling during upload. It must respect `prefers-reduced-motion`.
- Accessibility and states: WCAG AA, visible focus, keyboard reachability, `aria-live` for progress and verdicts. Every view has loading, empty and error states. Toasts for mutations. Responsive from 360 px.
- Charts follow the repo's dataviz guidance: invoke the `dataviz` skill before writing chart code.

### 11.2 Pages
| Route | Content |
|---|---|
| `/` (Send) | Hero ("Share files only the recipient can read. Not even us.") + Dropzone (drag/drop or browse, multiple files, remove, totals, per-drop limit hint). Options card: expiry select, download-limit select ("1 — burn after reading" highlighted with Flame), password toggle (PasswordInput + lazy zxcvbn meter), note textarea. **Encrypt & upload** → progress (per-file bars with encrypt/upload phases, overall %, MB/s, ETA, HexStream, Cancel). Success card: CopyField with the link, a QR toggle, the summary (expires, downloads, password yes/no), the warning "The key after # never reaches our server. Anyone with the full link can download.", "Delete now", "Send another". Anonymous drops are saved to `deviceDrops` (dropId, ownerToken, createdAt, expiresAt; **no names, no keys**), shown in a small "Sent from this device" list with Delete |
| `/d/:id` (Receive) | States: loading · not found · gone (reason-specific copy: expired / downloads used up / deleted / disabled) · missing key · password prompt (wrong password → shake + message, rate-limit message) · ready: decrypted note, file list (name, size, type icon), "N of M downloads left · expires in …". **Decrypt & download** (a confirm dialog when it consumes the last download) → per-file progress → saved; files ≤ 256 MiB go through a Blob + `<a download>`, larger ones through `showSaveFilePicker` when available (otherwise a clear message that names the File System Access API) → "Integrity verified" badge, image (png/jpg/gif/webp) and text (≤ 1 MB) previews from the decrypted Blob. An integrity failure shows a prominent red "This file was modified in transit or storage. Download blocked." Report link (dialog: reason, details, an opt-in checkbox "include the decryption key so moderators can review"). `?review=1` for admins uses the admin grant. As built (2026-11-21): the key is read once and the history entry is replaced by the same URL without the fragment, which stays in that entry's `history.state` so a reload works, and is cleared once no downloads are left or the drop is gone; a **Copy link** action (not in review mode, not once no downloads are left), and if copying fails, the link in a read-only, selected "Link to this drop" field; a saved Blob keeps the declared type only if it is on an inert allowlist (text, CSV, raster images, common audio and video), else `application/octet-stream`; image previews are typed from the allowlist, HTML and XML are shown as source text, SVG is never previewed; a line under **Decrypt & download** says what "Integrity verified" means (the bytes are exactly what was encrypted with the link's key, not who sent them or that they are safe), and the note is titled "Note from the sender (not verified)" |
| `/register` | Email, password + strength meter, confirm → derive keys in kdf.worker (a progress spinner, "Deriving keys locally…") → **Recovery key** step (RecoveryKeyCard: monospace groups, Copy, Download .txt, checkbox "I saved my recovery key", Continue disabled until checked) → dashboard |
| `/login` | Email + password → (TOTP step if required: 6-digit input, "use a backup code" link) → dashboard. Links to /register and /recover |
| `/recover` | Email + recovery key (+ TOTP) → new password → new recovery key shown (same card) → dashboard |
| `/unlock` | Shown when signed in but the vault is locked (after reload or auto-lock): password → local unwrap; "Sign out" |
| `/dashboard` | Storage meter (used/quota); filter tabs (Active / Expired / All); a list of drops with decrypted file names (or "🔒 Locked", with an unlock CTA, if the vault is locked), status badge, downloads x/y, expiry, created; actions Copy link (rebuilds `/d/id#key`; password drops copy the keyless link), Delete (confirm). Empty state with CTA |
| `/settings` | Tabs: **Security** (2FA: setup → QR from `qrcode` + manual secret → verify code → backup codes shown once; disable; regenerate backup codes. Change password. Recovery key rotation. Auto-lock select) · **Sessions** (list with current badge, revoke, revoke others) · **Activity** (audit table: action icon + human text, IP prefix, UA summary, time; filter by action; pagination) · **Account** (delete account with a typed confirmation + password + TOTP) |
| `/how-it-works` | Plain-language explainer with inline SVG diagrams: (1) key in the fragment, (2) chunked STREAM encryption, (3) what the server stores vs never sees (two-column table), (4) the account key hierarchy, (5) honest limitations, linking to SECURITY.md |
| `/admin` | Stats cards + uploads chart (14 days); Reports table (reason, drop status, has key, actions Disable / Dismiss / Review); Users table (search, quota edit, role) |
| `*` | 404 |

### 11.3 Client pipelines
- **Upload**:
  - *Main thread*: generate DK and fileIds, compute chunk counts, build and encrypt the manifest, then (password mode) wrap via kdf.worker, then (logged in and vault unlocked) compute `ownerWrappedKey`, then `POST /drops`.
  - *`upload.worker.ts`* (a module worker): receives the Files, DK, ids, tokens and API base. For each chunk it slices the file, encrypts with `encryptChunk`, and PUTs with `X-Chunk-SHA256`. Up to 3 chunks are in flight. It retries 3 times with exponential backoff (0.5 s, 2 s, 8 s). It posts progress, cipher-preview and error messages, and supports cancel.
  - After the upload, `complete`, then the link is shown.
- **Download**: a `DownloadSession` on the main thread:
  - `open` → grant;
  - for each file, fetch the chunks sequentially;
  - `createChunkDecryptor` → write to the sink (Blob parts or a FileSystemWritableFileStream);
  - any failure aborts the file and shows the integrity error;
  - it reuses the grant while it is valid, rather than opening again.
- **Saved file names** are sanitised client-side by `sanitizeFilename`:
  - strip path separators and control chars;
  - replace Windows-reserved names (`CON`, `NUL`, `COM1`, …) with `_CON`;
  - cap at 200 chars while keeping the extension;
  - an empty result becomes `file`;
  - when names collide within a drop, de-duplicate as `name (2).ext`.

  The manifest keeps the original name for display.
- **Argon2id always runs in `kdf.worker.ts`** so the UI never freezes. The client validates server-provided KDF params with `assertKdfParams` before deriving (downgrade protection).
- **API client**: Bearer token in memory. A single-flight refresh on 401, then one retry. A silent refresh at boot. The vault store is never persisted.

---

## 12. Security requirements
- Production web headers, served by nginx and mirrored in `vite preview`:
  - `Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'; worker-src 'self' blob:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`. As built (2026-11-21): `worker-src 'self'` (`blob:` removed: both workers are same-origin module files);
  - as built (2026-11-21): `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'; trusted-types default`, with the `default` policy in `/trusted-types.js`, which `index.html` loads first. No report endpoint, on purpose (a report carries a sample of the sink string, which could be plaintext); the e2e leak guard is the reporter. The dev server sends neither CSP header;
  - `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, and HSTS (prod).
- API: helmet; CORS restricted to `WEB_ORIGIN`; `no-store` caching; `trust proxy` from env.
- Constant-time comparisons for every token and hash (`crypto.timingSafeEqual` on equal-length buffers).
- pino redaction of `authorization`, `cookie`, `x-owner-token`, and request bodies on auth and drop routes. **Never log** request bodies, authKeys, tokens, manifests or wrapped keys.
- Generic auth errors. No user enumeration (prelogin fake salts, identical recovery errors). Account lockout. Rate limits (§10).
- Tokens are random 32 bytes and stored only as SHA-256 hashes. Upload tokens are useless once the drop is READY.
- Validation everywhere with zod. Body limits: 1 MB JSON, `CHUNK_SIZE + 16` raw on chunk PUT.
- Admin: RBAC on every route. Admin review grants are audited. As built (2026-11-21): RBAC and two-step verification on every admin route; role ADMIN implies TOTP on (promotion and disable refuse otherwise); enabling 2FA ends every other session.
- As built (2026-11-21): every sensitive account action re-authenticates (`requireAccountProof`), with a budget of 10 per 15 min per session; sessions have an absolute lifetime (`SESSION_MAX_LIFETIME_DAYS`); server-side Argon2id is bounded per process.
- As built (2026-11-21): nginx answers 404 for `/api/docs` in any letter case, and the API refuses `API_DOCS_UI=true` in production.
- **SECURITY.md**:
  - an asset and adversary table (network attacker, malicious or breached server, link interceptor, XSS);
  - what the server can see (drop count, ciphertext sizes ≈ plaintext sizes, timestamps, IP prefixes, account email) and can't see;
  - limitations: a malicious server could serve modified JavaScript (mitigations discussed: CSP, SRI, reproducible builds; out of scope: code-signing extensions); keys in links leak through chat logs and browser history (password mode mitigates this; the receive page removes the key from the address bar, not from history); a link does not prove who sent it (sender identity); size metadata leaks; losing the recovery key means data loss by design; the KDF parameter rationale;
  - a responsible-disclosure blurb.

---

## 13. Seed data (`npm run db:seed`, idempotent)
The seed uses `packages/crypto` in Node to create zero-knowledge accounts and real encrypted drops through the storage driver:
- `admin@cipherdrop.local` (ADMIN, `SEED_ADMIN_PASSWORD`).
- `demo@cipherdrop.local` (`SEED_DEMO_PASSWORD`), owning these drops:
  - "welcome.txt + sample.csv": READY, 10 downloads, 7 days;
  - "diagram.png" (generated programmatically): READY, password `correct horse battery staple`;
  - "burn-note.txt": 1 download;
  - an EXPIRED drop (for status display).
- A few audit events and one OPEN report.

The seed prints the demo credentials and the share links of the non-password drops. As built (2026-11-21): the seeded admin has no TOTP and must enrol before it can open the console (the seed prints how); after that it cannot turn 2FA off while it is an admin.

---

## 14. Testing & definition of done

Scripts:
- `dev`: api + web;
- `build`, `typecheck`, `lint`;
- `test`: crypto unit tests + API integration; needs compose; each test file uses its own Postgres schema or truncates, and a temp `STORAGE_DIR`;
- `test:s3`: storage driver against MinIO, with `S3_TEST=1`;
- `e2e`: Playwright against `vite preview` (CSP on) + API;
- `db:migrate`, `db:seed`, `db:reset`;
- `bench`: crypto throughput (MB/s encrypt/decrypt in Node) + upload throughput against the local API, reported as a markdown table.

Required tests:
- **`packages/crypto`**:
  - chunk roundtrip (0 B, 1 B, CHUNK_SIZE−1, CHUNK_SIZE, CHUNK_SIZE+1, 3 chunks);
  - a flipped ciphertext bit → IntegrityError;
  - swapped chunks, a dropped final chunk, and a final chunk replayed as non-final → IntegrityError;
  - the wrong file key fails; the manifest roundtrips and schema rejection works;
  - password wrap/unwrap and wrong-password failure;
  - `assertKdfParams` rejects weak and absurd params;
  - account bundle → login derivation reproduces the same authKey; `rewrapForNewPassword` keeps AK;
  - the recovery key format/parse roundtrip (lower case, missing dashes, Crockford aliases);
  - `parseShareFragment` edge cases;
  - an Argon2id regression vector.
- **API integration** (real Postgres + Redis, local storage in a temp dir):
  - the full drop lifecycle;
  - chunk size and sha checks; idempotent re-PUT; complete with missing chunks → 409;
  - **N = 10 concurrent opens on maxDownloads = 1 → exactly one 200**;
  - expiry → 410 via `runCleanup(now + Δ)`; exhausted-blob deletion after grant expiry; stale UPLOADING cleanup;
  - password unlock success/failure and rate limit;
  - owner delete via token and via session; quota and limit enforcement;
  - prelogin fake-salt determinism with identical shape;
  - register/login/MFA (codes computed with otpauth), TOTP replay rejection, backup code single-use;
  - refresh rotation + **reuse detection revokes the session**; the session denylist rejects the access token immediately;
  - password change revokes other sessions; the recovery flow rotates the recovery key; sessions list/revoke;
  - audit events recorded for owners; admin RBAC 403 for users; admin resolve/disable; account deletion removes blobs;
  - OpenAPI covers all routes.
- **Storage drivers**: a shared contract test suite run against `local` (always) and `s3` (when `S3_TEST=1`).
- **E2E** (Playwright, preview build with CSP; every spec runs in desktop Chromium, and the specs tagged `@cross` also run in Firefox, WebKit, mobile Chromium (Pixel 7) and mobile WebKit (iPhone 14) through `apps/web/playwright.cross.config.ts`):
  1. Anonymous send of a 5 MB random file → open the link in a new context → download → the SHA-256 equals the original.
  2. Password drop: the wrong password shows an error; the right one downloads.
  3. Burn after reading: a second context gets the "downloads used up" page.
  4. **Tamper test**: `page.route` flips one byte of a chunk response → the UI shows the integrity error and no file is saved.
  5. Account: register (recovery key step) → send → the dashboard shows the decrypted filename → reload → unlock → filenames visible → enable TOTP (code computed from the secret shown) → logout → login requires TOTP.
  6. Recovery with the recovery key → new password works.

  As built (2026-11-21): the `@cross` subset is tests 1-4 of `drops.spec`, the 4 `states.spec` tests, a vault-unlock test, `large-drop.spec` (C-03: a file over 256 MiB is refused before `/open` where the browser cannot stream to disk), `layout.spec` (no sideways scroll at the phone viewport and at 360 px) and the leak guard's own CSP test, 12 tests per project. WebKit is Playwright's Linux build, not Safari; the phone projects only emulate viewport, user agent and touch.

  Capture **screenshots** (light and dark: send, progress, success, receive, dashboard, settings) into `docs/screenshots/`.

  As built (2026-11-21): `npm run media -w @cipherdrop/web` (`apps/web/playwright.media.config.ts`, specs `apps/web/e2e/*.media.ts`) regenerates every screenshot at device scale factor 2, adds six views (password prompt, used-up drop, recovery-key step, TOTP setup, second-factor sign-in, blocked download on a phone) and records `docs/screenshots/demo.gif`. It is opt-in: `npm run e2e` and CI never run it, because it writes into the repository ([DEMO.md, Recording the demo and the screenshots](DEMO.md#recording-the-demo-and-the-screenshots); decisions log 2026-11-21, media run).
- **CI** (as built, 2026-11-21; see the decisions log): `ci.yml` has these jobs. `static`: lint, `test:lint` (the ESLint security bans fire), format check, typecheck, unit tests. `integration`: API tests on Postgres and Redis service containers, then `db:check` (the migrations replayed into `cipherdrop_shadow` must build exactly `schema.prisma`), then `test:s3` against MinIO started with `docker run`. `e2e`: every spec, desktop Chromium, report uploaded on failure. `e2e-cross`: the `@cross` subset, one runner per project (firefox, webkit, mobile-chromium, mobile-webkit). `secrets`: gitleaks 8.30.1 over the full history. `workflows`: actionlint 1.7.12 and zizmor 1.32.0, pedantic, offline. `prod-stack`: replaces the build-only images job of 2026-11-12; both images are built with `docker compose build` from the Dockerfiles, `docker-compose.prod.yml` is booted with generated secrets, `smoke:prod` runs through nginx, then each image gets a Trivy scan (a fixable CRITICAL fails) and a CycloneDX SBOM. `codeql.yml` runs CodeQL `security-extended` for JavaScript and TypeScript on pushes, pull requests, weekly and on demand. `audit.yml` runs the scripts' tests (the image-pin check included) and the dependency audit gate on pushes, pull requests, weekly and on demand. As of 2026-11-21 the new jobs had not yet run on GitHub.

A feature is done when it has: its endpoint(s) with zod validation, auth rules and rate limits; tests; its UI wired to the real API, with loading, empty and error states; OpenAPI registration; zero TS or ESLint errors; and **no plaintext metadata reaching the server** (reviewers check request payloads in the e2e traces).

---

## 15. Observability & operations
- pino JSON logs with requestId and the redaction rules (§12).
- Prometheus metrics:
  - `http_request_duration_seconds`;
  - `drops_created_total{anon}`, `drop_opens_total`;
  - `chunk_bytes_uploaded_total`, `chunk_bytes_downloaded_total`;
  - `cleanup_runs_total`, `cleanup_deleted_drops_total`;
  - `storage_bytes` gauge;
  - as built: `storage_free_bytes` (refreshed by `/readyz`, 2026-11-11), `drops_refused_total{reason=client_budget|anon_pool|global_cap|disk_floor}`, and `argon2_active`, `argon2_queued` (gauges) and `argon2_rejected_total` (2026-11-21).
- Graceful shutdown (stop the server, the cleanup interval, Prisma and Redis).

## 16. Deployment (docs/DEPLOYMENT.md)
- `docker-compose.prod.yml` services:
  - `postgres` and `redis`;
  - `minio`, or external S3/R2 via env;
  - `api` (multi-stage image; `prisma migrate deploy` on start). As built (2026-11-21): a one-shot `migrate` service runs the migrations as the owner and provisions a DML-only role, `cipherdrop_app`; the API connects as that role with `MIGRATE_ON_START=false`. Postgres, Redis and MinIO are on an internal `backend` network that only the API and `migrate` join; Redis needs a password; every service has a `mem_limit` and a `pids_limit` (api 1g / 256), and no `cpus` limit;
  - `web` (nginx: SPA + headers from §12 + `/api` proxy with `client_max_body_size 5m`; as built, 5m only on the streamed chunk routes and 1m for JSON, decisions log 2026-11-20);
  - optional Caddy for TLS.
- Also document a split deployment: static SPA on any static host (with headers) + API on a container host + managed Postgres/Redis + R2. In that case the SPA and API must share a site, or `WEB_ORIGIN`/cookies must be configured correctly.

## 17. Left to the builder
Internal module structure beyond §5, component APIs, copywriting details, chart specifics (within §11.1), test organisation, and the migration name. Record deviations in the Decisions log.

## Decisions log
- 2026-11-07: Design approved for build (owner chose "build now"). Chunk PUTs are buffered (≤ 4 MiB + 16) rather than streamed, for simpler validation. Downloads stream from storage. Passkeys deferred.
- 2026-11-07 (plan): `parseShareFragment` now tolerates trailing punctuation and URL-encoding. `sanitizeFilename` rules are added (§11.3). After a password change, a recovery or "revoke others", the old sessions' access tokens are rejected immediately through the sid denylist.
- 2026-11-07 (pins): versions were checked on the npm registry. Use vite@7 (vite 8 needs Rolldown-only plugin-react@6), vitest@3.2, express-rate-limit@7 + rate-limit-redis@4, react-resizable-panels@2 and @zxcvbn-ts@3. The full list is in the plan's "Version pins".
- 2026-11-07 (builder check): an independent pre-build review raised about 25 questions per project. They are resolved in the plan's "Builder-check resolutions" (binding during the build), and the sections above are patched to match.
- 2026-11-07 (S-BACK, deps): every dependency is installed with an explicit major. Unpinned majors chosen: globals@17, eslint-plugin-react-hooks@5 (v7 adds the React-Compiler rule set), eslint-plugin-react-refresh@0.5, concurrently@9, cross-env@10, tsx@4, pino@10, pino-http@11, pino-pretty@13, helmet@8, swagger-ui-express@5, prom-client@15, supertest@7, ioredis@5 (spec; 6 exists), lucide-react@1, sonner@2, date-fns@4, tailwind-merge@3, @testing-library/react@16 with its peer @testing-library/dom@10, jest-dom@6, @playwright/test@1, react-is@19 (recharts peer). The Arbiter-only entries of the shared "Version pins" block (monaco, bullmq, socket.io and its Redis adapter/emitter, react-resizable-panels) are not installed: no CipherDrop feature uses them.
- 2026-11-07 (S-BACK, audit): zod 3.25 has a memory-DoS advisory for oversized constrained arrays (fixed only in zod 4.6.6, while the spec pins zod 3). It is mitigated in our schemas: `boundedArray()` in packages/shared (and an inline guard in ManifestSchema) never validates more than max+1 elements, and every request array must use it. The remaining advisories are in dev-only tooling pinned by the plan (vitest 3.2 / tinypool / @vitest/mocker, the esbuild 0.27 dev server, minimatch, deepmerge-ts under the prisma CLI) and are accepted.
- 2026-11-07 (S-BACK, compose): dev ports are published on loopback only, on both 127.0.0.1 and [::1], because on this Windows machine `localhost` resolves to ::1 only and Node clients do not fall back to IPv4. MinIO's healthcheck is `mc ready local` (the image ships mc and bash). Redis is ephemeral in dev.
- 2026-11-07 (S-BACK, Redis keys): the spec's key names get the KEY_PREFIX: `${KEY_PREFIX}:revoked:sid:<sid>`, `${KEY_PREFIX}:rl:<limiter>:<key>` and `${KEY_PREFIX}:lock:cleanup` (default prefix `cd`).
- 2026-11-07 (S-BACK, routing): every route goes through `createRouter(basePath)` -> `{router, route(def, ...handlers)}`, the counterpart of the sibling plan's R12. `route()` registers the Express route, the OpenAPI path (full path, `:param` -> `{param}`) and a `routeManifest` entry, de-duplicated per method+path. `def.auth` also applies the middleware: user -> requireAuth, admin -> requireAuth + requireRole('ADMIN'), optional/owner -> optionalAuth, token kinds -> documentation only. Module stubs answer 501 with code `INTERNAL`, so no new error code is added.
- 2026-11-07 (S-BACK, API behaviour): `requireRole` re-checks the role in the database, so a demotion takes effect at once. QUOTA_EXCEEDED is HTTP 413. `ipPrefix()` returns null for a missing or invalid address, and `ipKey()` (full IPv4, IPv6 /64) is the per-IP rate-limit key. A new limiter rule `loginMfa` (10 per 15 min) covers /auth/login/mfa. Request logs carry only {id, method, path without query, ipPrefix, status}. BigInt values are serialised as JSON numbers by an app-level json replacer.
- 2026-11-07 (S-BACK, API contracts): StorageDriver gains `init()` (local mkdir, s3 CreateBucket at startup), and `getChunkStream` returns a `Readable`. The cleanup stubs are `runCleanup(now, ctx?)` and `startCleanupScheduler(ctx) -> {stop()}`. `createApp(deps)` also accepts `logger` and `env` overrides. Secrets have no defaults in env.ts: local dev values live in the gitignored apps/api/.env, whose template is .env.example. Production refuses dev or test secrets and RATE_LIMITS_ENABLED=false. Relative STORAGE_DIR values resolve against apps/api.
- 2026-11-07 (S-BACK, crypto API): beyond section 7.7, packages/crypto adds `createRecoveryBundle(accountKey)`, used by recovery/complete and the R9 rotation. `createPasswordProtection`, `createAccountBundle` and `rewrapForNewPassword` take an optional trailing `params?: Argon2Params` (default KDF_DEFAULT; still bounded by assertKdfParams). The `Argon2Params`/`KdfParams` types live in constants.ts. The error classes carry a stable `code`. ManifestSchema is `.strict()` and checks that chunkCount equals max(1, ceil(size / chunkSize)) and that file ids are unique.
- 2026-11-07 (S-BACK, shared): packages/shared imports its constants from `@cipherdrop/crypto/constants`, the single source. Shared schemas accept only canonical base64url: 43 chars for 32 bytes, 22 chars for 16 bytes, exactly 80 chars for wrapped keys. CreateDropRequest checks that each file's ciphertextBytes is consistent with its chunkCount. `Me` = {id, email, role, totpEnabled, autoLockMinutes, storageQuotaBytes, storageUsedBytes, createdAt}. The report response is `{id}`. The 409 details of complete are `{missing, sizeMismatch?}`.
- 2026-11-07 (S-BACK, tooling): apps/api's tsconfig includes the DOM lib, because the API typechecks @cipherdrop/crypto's isomorphic source and @types/node does not declare CryptoKey or BufferSource. The Prisma seed stays in package.json#prisma (R26) despite Prisma 6's deprecation notice, because prisma.config.ts would stop .env auto-loading. S1 created minimal web placeholders (tsconfig.json, tsconfig.node.json, vite.config.ts, src/vite-env.d.ts, .env and .env.example) so the frozen typecheck script works; S5 owns and completes them.
- 2026-11-08 (C1, crypto behaviour): choices the spec leaves open, documented in packages/crypto/README.md. (1) `b64urlDecode` accepts only canonical unpadded base64url: it rejects `+`, `/`, `=`, whitespace, lengths of 4n+1 and non-zero trailing bits. `utf8Decode` is fatal and keeps a leading BOM. (2) Misuse throws TypeError/RangeError, never a crypto error; only a WebCrypto OperationError becomes IntegrityError or WrongPasswordError. `unwrapKey` maps an authentication failure to WrongPasswordError under the drop-password, account and recovery labels and to IntegrityError under the owner label; a malformed blob is an IntegrityError. (3) `wrapKey`/`unwrapKey` accept only the four AAD.WRAP_* labels and only 32-byte keys, so a wrapped key is always 80 chars. (4) `argon2id` rejects an empty password (TypeError: hash-wasm cannot hash one) and salts under 8 bytes (KdfParamsError). `deriveDropPasswordKeys`/`deriveAccountKeys` require `kdf.salt` to be the canonical b64url of exactly 16 bytes (KdfParamsError). (5) `createChunkDecryptor` validates its key up front, decrypts overlapping calls in call order, and refuses every chunk after the first failure, including data after the final chunk; `done()` is then false. `chunkCount`/`chunkNonce` refuse more than 2^32 chunks (the uint32 counter). (6) `encryptManifest` validates with ManifestSchema (ZodError) and throws RangeError above 64 KiB. `decryptManifest` rejects oversized blobs before decoding and treats a non-string blob as a TypeError. (7) `parseRecoveryKey` also applies NFKC and ignores any whitespace, Unicode dash and invisible format character; its errors never echo the key. `parseShareFragment` keeps the raw text when URL-decoding fails and strips trailing junk with a linear scan, avoiding regex backtracking on hostile links. (8) `buildShareLink` strips trailing `/` from the origin and requires a base64url dropId and a 32-byte DK, or null for password drops.
- 2026-11-08 (C1, tests and tooling): added `packages/crypto/vitest.config.ts` (node environment, 60 s timeout, at most 4 workers) and the internal module `src/internal.ts` (HKDF, AES-GCM and KDF helpers; not re-exported). The R20 regression vectors are the Argon2 reference implementation's published Argon2id KATs (m=65536 and m=262144, t=2, p=1, both inside the KDF bounds), checked against both hash-wasm and @node-rs/argon2 `hashRaw`, plus hash-wasm vs `hashRaw` cross-checks at KDF_MIN, p=2 and KDF_MAX. `conformance.test.ts` re-implements section 7 with node:crypto, with labels typed from the spec, and pins a STREAM golden vector.
- 2026-11-08 (C1, browser check): the unchanged `packages/crypto` source, bundled with esbuild, passed a smoke test (Argon2id KAT, STREAM golden vector, tamper detection, manifest, account and recovery, password drop, links) in headless Chromium, in a page and in a module Worker, under the exact section 12 CSP: `'wasm-unsafe-eval'` is enough for hash-wasm. Across the Worker boundary structured clone drops an error's class and `code`, so workers post `{code, message}` and the client maps it back.
- 2026-11-08 (S5, design tokens): the section 11.1 palette is used with its exact values (`--cd-*` variables mapped through Tailwind 4 `@theme inline`, dark mode via `@custom-variant dark` on `html.dark`). Some derived tokens are added for WCAG AA, measured against the spec colours. `muted-strong` (#5d6b80 light) exists because muted #64748b is 4.76:1 on the surface but only 4.44:1 on the page background, so small secondary text placed directly on the background uses muted-strong. `border-strong` (#868fa1 light / #56677a dark) gives form controls 3:1 non-text contrast; the spec border #e4e7ec is 1.24:1. The `*-ink` shades are for text on soft tinted fills, where the base status colours fall to about 4.1-4.4:1. `surface-2` is a subtle fill. Dark-mode success/warning/danger, the `*-foreground` colours and a dark primary-hover are not given by the spec, so S5 chose them (light text colours on dark backgrounds; dark text on light solid fills).
- 2026-11-08 (S5, theme): light-first. The preference `light | dark | system` (default light) is the only setting the SPA keeps in localStorage (`cd-theme`). The external `/theme-init.js` applies it before first paint, because the CSP forbids inline scripts.
- 2026-11-08 (S5, API client): paths are relative to `/api`. Options are `schema` (zod validation, INVALID_RESPONSE on mismatch), `raw`, `query`, `token` (capability bearer: never refreshed), `anonymous` and `skipRefresh`. ApiError adds two client codes, NETWORK_ERROR (status 0) and INVALID_RESPONSE; `retryAfter` is in seconds and parsed from delta-seconds or an HTTP date. The client refreshes 30 s before the access token expires, using the token's own iat/exp lifetime on the local clock so clock skew is harmless. Requests issued during the boot refresh wait for it. A refresh answered with any 4xx other than 429 ends the session as `session-expired` (with a toast); 429, 5xx and network failures are transient and never log the user out. A session epoch makes a refresh result arriving after a login or logout a no-op. `putBinary` lives in the worker-safe `lib/http.ts` as `putBinary(path, body, headers, {baseUrl, token, signal})`.
- 2026-11-08 (S5, vault, R7): `lockedSinceBoot` drives the boot-only redirect to `/unlock?next=`. It is true until the first unlock and becomes true again after a logout; an idle or manual lock keeps it false, so nothing navigates. `setAccountKey` rejects extractable and non-AES-GCM keys. Auto-lock samples activity events (at most once per 5 s) and checks the deadline every 15 s and when the tab becomes visible. Logout also clears the TanStack Query cache.
- 2026-11-08 (S5, routing): the guards are layout routes. A non-admin on /admin gets a 403 "Admins only" state rather than a redirect. `?next=` is pathname + search only: the `#fragment` (which may hold a drop key) is never copied into a query string, and `safeNextPath` rejects external, protocol-relative and control-character values and the login/unlock pages themselves. Titles come from route `handle.title`. The root `HydrateFallback` renders the shell with a loader while the first lazy page loads. The skip link focuses `<main>` without touching `location.hash`. `/admin` is AdminLayout plus an index page.
- 2026-11-08 (S5, components): the UI kit also provides Field, Checkbox, Alert, ErrorState, ConfirmDialog, DropdownMenu, CopyButton, SkeletonText, PageLoader and ButtonLink. Layout adds PageHeader, Logo and `useSignOut`. Dialog is a portal with `aria-modal`, a focus trap, an `inert` app root, a scroll lock with scrollbar compensation and focus restore; it does not use native `<dialog>`, because jsdom lacks `showModal`. A loading Button stays focusable (`aria-disabled` + `aria-busy`) and ignores activation.
- 2026-11-08 (S5, R8): only @zxcvbn-ts/core and language-common are installed, so PasswordStrength ships its own English feedback strings for the v3 translation keys. Its crack-time line uses zxcvbn's offline slow-hash estimate (1e4 guesses/s). "cipherdrop" and the given user inputs are penalised. QrCode renders `qrcode.create()` modules as an inline SVG path (merged runs, 4-module quiet zone, always dark on white), with no `innerHTML`.
- 2026-11-08 (S5, headers): the section 12 header set is centralised in `apps/web/securityHeaders.ts`; nginx must mirror it (R25). `vite preview` sends every section 12 header except HSTS, which is production-only (browsers ignore it over HTTP). The dev server sends all of them except the CSP, which Vite's inline React Refresh preamble cannot satisfy. `vite.config.ts` reads API_PROXY_TARGET through `loadEnv` (env var or apps/web/.env). `tsconfig.node.json` also includes `securityHeaders.ts` and has the DOM lib, for Playwright `page.evaluate` callbacks and @cipherdrop/crypto types.
- 2026-11-08 (S5, formatting): `formatBytes` uses 1024-based units labelled KB/MB/GB, so 104 857 600 bytes reads "100 MB". Rate-limit waits are rounded up ("Try again in 2 min" for 90 s). The main bundle is about 507 kB (156 kB gzip), including zod via @cipherdrop/shared. `chunkSizeWarningLimit` is 1600 for the lazy zxcvbn dictionary chunk.
- 2026-11-08 (B1): authKeys and recoveryAuthKeys are verified with modules/auth/authKeyHash.ts (hashRaw on raw bytes, constant-time compare) instead of lib/argon2 verifyAuthKey, because @node-rs/argon2 verify() rejects non-UTF-8 passwords. Stored PHC hashes are unchanged.
- 2026-11-08 (B1): Wrong MFA codes (TOTP or backup) count toward the same 10-failure, 15-minute account lockout as wrong authKeys.
- 2026-11-08 (B1): POST /auth/recovery/rotate (R9) is audited RECOVERY_KEY_ROTATED, revokes no sessions, requires the current authKey and, when TOTP is enabled, a TOTP or backup code.
- 2026-11-08 (B1): DELETE /me requires the authKey (and a TOTP code when enabled), deletes the blobs of every owned drop first, then the user row; all sessions die at once through the sid denylist.
- 2026-11-08 (B1): In tests the next TOTP code is generated with the timestamp set to now + 30000 ms instead of sleeping (R23).
- 2026-11-08 (B2): Quota at create counts `storageUsedBytes` plus the ciphertext bytes of the owner's own UPLOADING drops, so parallel uploads cannot overshoot the quota; `storageUsedBytes` itself is incremented only on complete (READY) and released exactly once when the blobs are purged (owner delete, admin disable, expiry, exhaustion cleanup).
- 2026-11-08 (B2): `purgeDropBlobs()` (modules/drops/lifecycle.ts) is the single blob-deletion path: storage first (idempotent), then a conditional `blobsDeletedAt` update that releases the quota, so racing cleanup, owner delete and admin disable never double-release. Cleanup also sweeps terminal drops whose earlier purge failed, and deletes grants expired for more than 24 h.
- 2026-11-08 (B2): Admin review grants are audited on the admin's own log as `DROP_OPENED` with `{adminReview: true}` (no dedicated enum value exists); they never consume a download.
- 2026-11-08 (B2): Reports are audited to the drop owner as `DROP_REPORTED` without the reporter's ipPrefix (the owner must not learn it); the reporter's ipPrefix is stored on the Report row, visible to admins only.
- 2026-11-08 (B2): Meta, unlock, open and report answer 404 for a drop still UPLOADING (recipients cannot tell it from an unknown id); gone drops answer 410 with the reason.
- 2026-11-08 (B2): Chunk PUT checks everything that does not need the body (upload token, status, file, index, X-Chunk-SHA256 format, declared Content-Length) before reading it, then express.raw buffers at most the chunk ciphertext size; rejected bodies of verified uploaders are drained so browsers receive the error status instead of a connection reset.
- 2026-11-08 (W1): kdf.worker has composite operations (unlockVault, changePassword, rotateRecoveryKey, completeRecovery) so the raw account key never leaves the worker: it is unwrapped, used and zeroed there, and only a non-extractable CryptoKey (R7) or wrapped material is returned. Errors cross as {code, message} (crypto codes plus TYPE_ERROR/RANGE_ERROR) and kdfClient maps them back to the crypto error classes.
- 2026-11-08 (W1): The wrong-password path on /unlock, password change and recovery-key rotation is decided locally (unwrap fails with WrongPasswordError) before any request is sent. /unlock loads GET /auth/vault on mount; submitting a password makes no network call.
- 2026-11-08 (W1): After login the vault is unlocked with the encKey derived during login (no second Argon2id run): GET /auth/vault then a local unwrap. If that fails the vault stays locked and the dashboard redirects to /unlock.
- 2026-11-08 (W1): Register and recover enforce a minimum password: 10 characters and zxcvbn score >= 2 (fallback 12 characters when the lazy estimator is unavailable), checked on submit rather than by disabling the button.
- 2026-11-08 (W1): Registration signs the user in immediately (session and vault key set) and shows the recovery-key step; Continue stays disabled until "I saved my recovery key" is checked, and a beforeunload warning guards the unsaved key. Recovery also rotates the recovery key and shows the new one on the same card.
- 2026-11-08 (W1): Recovery is two steps: POST /auth/recovery/start (email + recoveryAuthKey), then a new password (plus the 2FA code field only when the server says mfaRequired) and POST /auth/recovery/complete.
- 2026-11-08 (W1): Settings adds a Profile card (email, member since, storage meter) and an Appearance card (light/dark/system) to the Account tab, beyond the spec text. Settings tabs have no icons (they overflowed at 390 px).
- 2026-11-08 (W1): /how-it-works shows three SVG diagrams (key in the fragment, chunked STREAM encryption, account key hierarchy), the two-column "server stores / never sees" table (stacked lists below 640 px, hidden from assistive tech to avoid duplication) and the honest-limitations list. The plan's "4 diagrams" are delivered as 3 diagrams plus the table.
- 2026-11-08 (W1): Login failures are one generic message ("Incorrect email or password. Repeated failures temporarily lock the account."): the server's lockout is also a generic 401, so nothing distinguishes it. 429 uses the shared "try again in N min" text from Retry-After.
- 2026-11-08 (W2A): Anonymous drops are remembered in localStorage (stores/deviceDrops: dropId, ownerToken, createdAt, expiresAt only); the "Sent from this device" list prunes expired entries on load and removes an entry after a successful Delete.
- 2026-11-08 (W2A): The resume record lives in sessionStorage (R11) and carries no file names; the resume prompt asks the sender to re-select the same files, matched by size + lastModified, and verifyResume re-encrypts the last received chunk of every file and compares its SHA-256 with upload-status before continuing; any mismatch abandons the old drop (best-effort delete) and starts a fresh one.
- 2026-11-08 (W2A): Failure taxonomy (R14): network errors, 429 and 5xx are retried 3 times with backoff 0.5 s / 2 s / 8 s (Retry-After honoured, capped), then shown as a retryable error state; only a cryptographic IntegrityError shows the "modified in transit or storage" error and nothing is written.
- 2026-11-08 (W2A): Files of 256 MB or less are saved through a Blob and a[download]; larger files get a per-file "Save..." button that calls showSaveFilePicker first inside the click handler (R22). Saved names pass through sanitizeFilename (200 unit cap, R15) and the manifest name accepts up to 1024 units.
- 2026-11-08 (W2A): FileList lays each row out as a grid (icon, name, trailing actions, then a full-width detail row) so per-file progress bars align across rows and previews keep their width on a 390 px screen.
- 2026-11-08 (W2B): Dashboard rows and the admin reports and users lists are semantic lists with a responsive grid instead of tables, so every action stays reachable at 390 px without sideways scrolling; the admin uploads chart keeps a table view for screen readers.
- 2026-11-08 (W2B): Dashboard Copy link rebuilds /d/id#key from the owner wrap; password drops copy the keyless link (also while the vault is locked); it is disabled for non-live drops, for locked non-password drops, and for drops created without an owner wrap (their name shows "Name unavailable").
- 2026-11-08 (W2B): The decrypted drop keys live only in the dashboard component state and are zeroed and dropped the moment the vault locks (R7); a manifest or wrap that fails to decrypt shows a "Couldn't decrypt names" row, never a crash.
- 2026-11-08 (W2B): Admin uploads chart is a hand-built accessible HTML chart (no recharts): one series, one axis, a Drops/Bytes switch instead of a dual axis, 4 px rounded caps, hover/focus tooltips, roving arrow-key focus and a table view. Bars use the primary token (validated: single hue, no legend needed).
- 2026-11-08 (W2B): Storage meter severity: accent below 80 %, warning from 80 %, danger from 95 %, always with a text note; the track is a lighter step of the fill colour.
- 2026-11-08 (W2B): Admin quota edit takes GB (1 GB = 1024^3 bytes), a plain positive decimal with at most two decimals and at most 10 240 GB; below-usage quotas are allowed with a warning; only changed fields are PATCHed; an admin cannot change their own role in the UI.
- 2026-11-08 (W2B): In the reports queue, Disable is disabled for drops that are already DELETED or DISABLED, Review is disabled without a reporter key, and Disable and Dismiss ask for confirmation.
- 2026-11-08 (W2B): ExpiryBadge shows nothing for used-up or disabled drops that have not reached their expiry time (the status badge says it all).
- 2026-11-11 (I1, audit): admin review grants are audited as the dedicated action `ADMIN_REVIEW_GRANT` (enum value plus migration `add_admin_review_grant_audit`) on the admin's own log with `{adminReview: true}`; this supersedes the B2 line that used `DROP_OPENED`. The Activity tab shows it as "Reviewed a reported drop".
- 2026-11-11 (I1, argon2): the binary-safe authKey verification (hashRaw on raw bytes, constant-time compare) moved from `modules/auth/authKeyHash.ts` into `lib/argon2.ts` `verifyAuthKey`, so the seed, smoke script, drops and admin share one correct verifier; `authKeyHash.ts` keeps the B1 names as aliases. This supersedes the B1 line about working around `verifyAuthKey`.
- 2026-11-11 (review): create takes `SELECT ... FOR UPDATE` on the user row so the quota check and the insert are atomic (parallel creates cannot overshoot); a chunk write reads the drop row `FOR SHARE` and stores the blob and the `DropChunk` row in one transaction, so delete, disable, complete and account deletion wait for an in-flight chunk and their purge removes it (no orphans, no chunk changes after READY).
- 2026-11-11 (review): the S3 client uses 256 sockets, a 5 s connect timeout and a 60 s idle-socket timeout (R17), and chunk GET aborts after `CHUNK_IDLE_TIMEOUT_SEC` of silence, so slow readers cannot exhaust the pool.
- 2026-11-11 (review): audit writes after a committed change (create, open, complete, delete, report, admin disable) are best-effort: a failure is logged and never fails the request, so it cannot burn a burn-after-read download. The unlock-failure audit stays pre-commit.
- 2026-11-11 (review): the reporter's decryption key is kept only while the report is OPEN; DISMISS, DISABLE_DROP and blob purge null it, and the admin list returns it only for OPEN reports. A report on a gone drop answers 410.
- 2026-11-11 (round 2): reports are accepted while the ciphertext exists (READY, EXHAUSTED and EXPIRED until purged); DELETED, DISABLED and purged drops answer 410. Chunk blobs are `<dropId>/<fileId>/<index>.<version>`: each PUT writes a fresh version with no DB connection held, then a short `FOR SHARE` transaction points `DropChunk.blobVersion` at it (a refused write is deleted by the handler, the superseded version after commit); downloads read the version from the row; null means the legacy `<index>` key. Chunk PUT and GET answer 429 `RATE_LIMITED` + `Retry-After` when the in-flight caps per token/grant, per IP or per process are reached. Sign out during an upload asks first and cancels the upload (deleting the unfinished drop) before logging out.
- 2026-11-11 (review): the chunk PUT in-flight cap is per process; behind several instances use reverse-proxy connection limits. `storage_free_bytes` is a metric refreshed by `/readyz`, not a readiness check.
- 2026-11-11 (review, web): resume refuses drops whose files share size and `lastModified` (the match would be ambiguous), so a fresh drop is started and the old UPLOADING drop is deleted best-effort; drop passwords use the `validateNewPassword` floor (min length and zxcvbn); the Toaster is portalled outside `#root` so it is not inert under a dialog; the Receive page blocks Decrypt & download up front when a file over 256 MB cannot be saved (no `showSaveFilePicker`), so the download is not consumed first (§11.2).
- 2026-11-11 (I1, seed and smoke): the seed is idempotent: users are found by email and drops by a deterministic id (SHA-256 of a seed label), so a second run creates nothing and only reprints the credentials and links. Seeded drops expire relative to the first run; a rerun does not renew them. `npm run smoke` (`apps/api/scripts/smoke.ts`) logs in as the demo user with an authKey derived from the password and decrypts every seeded manifest. Prisma refuses `migrate reset` when run by an AI agent without the user's explicit consent, so automated runs use `npm run db:deploy` and the idempotent seed; `npm run db:reset` stays a manual command.
- 2026-11-11 (I1, live run): the SPA on the Vite dev server against the real API, driven by Playwright through register, login, reload and unlock, link and password sends, fresh-context downloads, dashboard, delete, demo login and admin review, found no contract mismatch. Measured on the dev server (load not recorded): Argon2id derive in the kdf worker, median 327 ms over 5 runs; 96 MB encrypt and upload 12.2 MB/s and download and decrypt including page load 27.8 MB/s (one run each; quoted in `docs/BENCHMARKS.md` section 6). Requests carrying a plaintext file name or its URL-encoded form during those flows (names with accents and a right-to-left override included): 0.
- 2026-11-11 (I2, e2e infrastructure): `apps/web/e2e/support/start-api.ts` creates, migrates and wipes `cipherdrop_e2e`; the e2e API runs on port 4101 with Redis DB 9, `KEY_PREFIX=cd-e2e` and `RATE_LIMITS_ENABLED=false`, and the SPA is `vite build` + `vite preview` with the production CSP. The leak guard (`e2e/support/fixtures.ts`) records every request of every watched context and fails a test on a file name (raw, URL-encoded, JSON-escaped, base64, base64url), plaintext bytes or key material in any URL, header or body, and on any CSP violation or uncaught page error; `leakguard.spec.ts` tests the guard itself.
- 2026-11-11 (I2, fixes found in e2e): Vite inlined the small woff2 fonts as `data:` URIs, which `font-src 'self'` blocks, so `build.assetsInlineLimit` is 0. A deliberate logout or account deletion sends the user to `/`, not to `/login?next=...` (the route guard was still mounted for one render). The dashboard drops query revalidates on every view (`staleTime: 0`), so a drop burned by a recipient leaves the Active tab.
- 2026-11-12 (round 4): The R11 resume record also holds ownerId, expiresInHours and hasNote (never the note, the password or a hash of it). A resume requires the form to show the drop's options; a note or password the page cannot vouch for (after a reload) counts as a change and starts a new drop. The record is offered only to its owner and is cleared, with its drop deleted best-effort, whenever the session ends or changes user.
- 2026-11-12 (polish, deployment and CI, section 14/16): the images are `apps/api/Dockerfile` and `apps/web/Dockerfile` (build context = repository root, `.dockerignore` excludes every `.env`), the nginx config is `deploy/nginx.conf` (baked into the web image) and the optional Caddy config `deploy/Caddyfile`. The api image runs `prisma migrate deploy` from a separately installed Prisma CLI pinned to the lockfile version (the CLI is a devDependency, so the production install omits it). Compose reads `.env.production` (template `.env.production.example`, deliberately failing the production guard until filled in); Postgres and Redis are not published, Redis persists with AOF because it holds the session denylist. nginx answers 404 for `/readyz` and `/metrics` and has its own `/healthz`; it caps in-flight `/api` requests at 400 (`limit_conn`, one API instance). Finding recorded in `docs/DEPLOYMENT.md`: the SPA only supports a same-origin API (relative `/api` URLs, `connect-src 'self'`, `SameSite=Strict` cookie on `/api/auth`), so a split deployment must route `/api` through the SPA's origin; an API on another hostname is not supported. CI (`.github/workflows/ci.yml`) maps its Postgres, Redis and MinIO services to the dev ports so the test and e2e configs run unchanged. `npm run smoke:prod -w @cipherdrop/web` (apps/web/deploy-checks) smoke-tests a running production stack; `apps/web/deploy-checks/nginx-headers.test.ts` keeps nginx and `securityHeaders.ts` in step (R25).
- 2026-11-12: `bench` (section 14) is split in three, all reported in `docs/BENCHMARKS.md`: `packages/crypto/src/bench.ts` (crypto in Node), `apps/api/scripts/bench-upload.ts` (upload and download against a running API, registers and deletes its own account) and, outside the root `npm run bench` because they need a running stack, `apps/web/bench/bench-browser.ts` (`npm run bench:browser -w @cipherdrop/web`: production build under `vite preview`, one headless Chromium) and `apps/web/bench/chromium-upload-ceiling.ts` (`npm run bench:ceiling`, control without CipherDrop code). The benches ran against a separate API with rate limits off on the disposable e2e database, so they never touch the seeded dev data. Screenshots now also include `hero.png` and were regenerated against the seeded dev stack.
- 2026-11-12 (polish, documentation): the documentation set is `README.md`, `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/SECURITY.md` (section 12's threat model), `docs/DEPLOYMENT.md`, `docs/BENCHMARKS.md`, `docs/DEMO.md` and the review record `docs/review/2026-11-11-review.md`. The build's working notes (`docs/lanes/`, `docs/NOTES-integration.md`, `docs/review/fx-*.md`, `docs/review/integrate.md`) were removed after their still-valid content moved into this log. There is no LICENSE file (deviation from section 5): the author chooses the license (since resolved, see 2026-11-20). `/how-it-works` links to `/SECURITY.md`, which serves `docs/SECURITY.md` as UTF-8 plain text: a Vite plugin in `apps/web/vite.config.ts` serves it from the dev and preview servers and copies it into the build, `deploy/nginx.conf` serves it with `text/plain`, and the web image copies that one file from `docs/`.
- 2026-11-14 (refresh grace window): a rotation whose response is lost left the browser presenting the used token, which revoked the session as reuse and signed the user out. `RefreshToken.rotatedFromId` (migration `refresh_token_rotated_from`) links each successor to the token it replaced. A used token presented less than `REFRESH_GRACE_MS` (30 s) after its `usedAt`, while its successor is unused, retires that successor and issues a new one in the same session (same sid, nothing denylisted, no `SESSION_REUSE_DETECTED`); the window counts from the original rotation, so re-issues do not extend it. Outside the window, or once any successor was used, it is reuse exactly as before. The successor's row lock plus the replaced-count check leave at most one live successor; the replay path's `FOR UPDATE` on the presented token queues concurrent replays, so each later one (a fresh READ COMMITTED snapshot) retires the successor the previous one issued instead of finding none and revoking the session. Trade-off accepted (`docs/SECURITY.md` section 7): a thief holding the old token during the same 30 s can hold a live token until the user's next refresh or logout, which presents the retired successor and ends the session; the window is short and only opens while the successor is unused.
- 2026-11-14 (refresh grace window, review follow-up): the replaced successor is retired by setting its `usedAt`, not deleted. Deleting it made the token the other party held unknown, so presenting it was a plain 401: a thief who replayed the old token inside the window kept the session with no reuse detection, and the user's logout with the deleted token revoked nothing. A retired successor was never delivered in a genuine lost response, so presenting it is reuse and revokes the family with `SESSION_REUSE_DETECTED`, and logout still finds its session. Any contested family therefore ends in revocation at the loser's next refresh.
- 2026-11-20 (documentation): `LICENSE` (MIT) was added in commit e554daa on 2026-11-13, which closes the 2026-11-12 deviation from section 5 ("There is no LICENSE file"). Also: the paragraph that split the section 6 table now follows the table; this log is in date order (two entries had been filed out of order, their text is unchanged); `packages/crypto/README.md` points to `docs/BENCHMARKS.md` section 3 instead of keeping a second set of bench numbers; `docs/SECURITY.md` section 5 states the consequence of requiring a second factor during recovery (losing the authenticator and every backup code locks the account, and there is no admin reset of 2FA); the navbar's vault tooltip says "in this tab", because Lock and the vault act per tab.
- 2026-11-20 (ops-1, nginx and slow clients): nginx streams chunk transfers and caps in-flight `/api` requests per client. Context: nginx buffered every request body and response, so it accepted a dripped 4 MiB chunk body on the API's behalf, and the API's answer-before-the-body rule, minimum body rate and download idle timeout acted on nginx instead of the client; and one client could hold all 400 `/api` slots. Decision: (1) the chunk routes get a location nested in `/api/` that matches the API's chunk route, with `proxy_request_buffering off`, `proxy_buffering off`, `client_max_body_size 5m` and a 60 s `client_body_timeout` as a backstop behind the API's 30 s idle window. It declares no headers, so it sends exactly the `/api/` ones; `set $api_upstream` moved to server level, because `set` in a location is not inherited by the locations nested in it. (2) JSON under `/api/`: `client_max_body_size 1m` (the API's JSON limit), `client_body_buffer_size 128k`, `client_body_timeout 15s` and `proxy_max_temp_file_size 0`; at server level `client_header_timeout 10s`, `keepalive_timeout 15s` and `reset_timedout_connection on`; Caddy's upstream keep-alive is 10 s, so it closes idle connections first. (3) `limit_conn api_ip 64` per client next to `api_total 400`, keyed through a `map` on `$binary_remote_addr` by IPv4 address or IPv6 /48 like `ipShareKey` (IPv4-mapped addresses count as IPv4); 64 is the API's 16 PUT + 32 GET per-IP shares + 16 ordinary requests, 48 x N + 16 for N instances. (4) A compose network `edge` (172.16.94.0/28, `ip_range` 172.16.94.8/29) with Caddy fixed at 172.16.94.2 and on no other network; nginx takes the client from `X-Forwarded-For` of that one address (`set_real_ip_from`), so `TRUST_PROXY=1` is right with or without Caddy. Measured: with `TRUST_PROXY=2` behind Caddy, a client that reached nginx directly could choose its own address. (5) Sized tmpfs mounts for the web container (64m, 1m, 1m). Rejected: keeping the buffering and enforcing limits in nginx, because open-source nginx has no request-body deadline; trusting Docker's private ranges in `set_real_ip_from`, because with the userland proxy direct clients appear from a bridge gateway address. Consequences: a JSON body dripped at a byte per 15 s is bounded only per client (about 7 addresses can still fill the 400); the fixed subnet must be free on the host; after the API's 401 to an unverified uploader nginx may discard the rest of its body for up to `lingering_time` (30 s); with chunks streamed, the API's 10 s forced exit on shutdown (ops-11) can cut transfers in flight. Covered by `apps/web/deploy-checks/nginx-headers.test.ts` (15 tests, also reading the API's settings and the compose file) and three raw-socket checks in `prod-smoke.spec.ts`; verified on a booted stack (`docs/DEPLOYMENT.md`, Verification record).
- 2026-11-20 (testing-1, ops-5, leak guard and server logs): the e2e leak guard inspects every request with `request.allHeaders()`. The I2 line above says it recorded every request; it in fact kept only URLs containing `/api/` and their provisional `headers()`, which leave out Cookie. It now records document navigations, assets, worker scripts and the requests workers make as well, strips the `#fragment` (never sent), ignores `data:` and `blob:` URLs (never sent), fails on any request to another origin, and keeps a request whose full headers cannot be read with its provisional ones and a note, never dropping it. `forbidKey()` forbids a key's bytes raw, as standard base64 (with and without padding, URL-encoded, with JSON's `\/` escape), base64url and hex, not only its link text; `forbidBytes()` adds base64url and hex; the text variants add `encodeURI` and HTML-form encoding. `leakguard.spec.ts` has 15 self-tests (was 4); the text variants also include the forms the browser's URL parser produces (`'` becomes `%27` in a query). Server-log coverage is in-memory pino tests per flow (`modules/auth/logs.test.ts`, new `modules/drops/logs.test.ts`), not a scan of the e2e API's log: the server can only log what it received, so the same needles add little there, and the real risk is secrets the server legitimately receives (tokens, wrapped keys, a reporter's key). The new test found a real leak: a `PrismaClientValidationError` while a report with its key was stored rendered the key into its message and stack, and Prisma's own stdout log printed it outside pino; `errorFormat: 'minimal'` still renders the arguments (checked against Prisma 6.19.3). So Prisma's warn and error logs are emitted as events into pino (an event from a call target such as `report.create` with only that target, never its message; an engine event, whose target contains `::`, keeps its message: a probe against Prisma 6.19.3 found query failures only under call targets), and `lib/logger.ts` `serializeError` reduces a Prisma error, or an error caused by one, to its class, its code (as `prismaCode`, because `*.code` is redacted), allow-listed `meta` names and the stack frames without the message; a `logMethod` hook keeps `log.error(prismaErr)` and `log.error({ err })` from copying the message into `msg`; an initialization error keeps its message (startup and connection reasons, no call arguments); the serializer is also pino-http's, and the audit and cleanup jobs log the error itself instead of `{ err: { message } }`; storage error codes are logged as `errCode`, because `*.code` is redacted. Not done: the leak guard does not run in the production smoke test.
- 2026-11-20 (testing-2, testing-9, CI supply chain): every `uses:` in both workflows is pinned to a commit SHA with its release in a comment (the newest release within the major already in use), and Dependabot (`.github/dependabot.yml`) proposes updates: npm weekly, minor and patch updates in groups, the zod and Prisma majors each as a pull request of its own, `@types/node` majors ignored (they follow the Node 22 runtime), and a 7-day cooldown on new npm releases; GitHub Actions weekly; Docker for both Dockerfiles, which finds nothing while their `FROM` lines take the image from an `ARG` default. Checkout uses `persist-credentials: false`. CI installs with `npm ci --ignore-scripts`, as the Dockerfiles do, then runs `npm run db:generate -w @cipherdrop/api`, which also fetches the Prisma engines, so Scarf's install telemetry never runs (the root `package.json` also sets `scarfSettings.enabled=false`); CI sets `CHECKPOINT_DISABLE=1`. A `workflows` job runs actionlint 1.7.12, pinned by image digest. The dependency audit gate is written in the repository (`scripts/audit-gate.mjs`, plain Node without an audit-ci dependency, 27 `node:test` tests): `npm audit --omit=dev` must report no high or critical advisory missing from the reviewed `scripts/audit-allowlist.json`, whose entries carry a reason and a `reviewBy` date, and stale or expired entries fail as well. Nothing it prints except its own `::error` annotations can act as a workflow command: every printed line has control and invisible characters replaced, `::` broken to `: :` and `##[` to `## [`, because the runner trims leading whitespace before it looks for `::` and finds `##[` anywhere in a line. It runs in its own workflow, `audit.yml` (pushes to main, pull requests, Mondays 05:23 UTC, on demand), so the weekly run does not start the test matrix. The gate found a third high advisory, `effect` GHSA-7589-6fvf-x4pw, which comes in only through `@prisma/config`; it is allowlisted with the other two until 2027-02-20 (`docs/SECURITY.md` section 7). Their first run on GitHub (2026-11-20, pull request #1) passed every job, so the committed API Dockerfile, which could not be built in the cloud container, and the S3 suite are verified there.
- 2026-11-21 (batch 1, ci: crypto-10, product-6, cross-engine e2e): cross-engine runs use their own config and script (`apps/web/playwright.cross.config.ts`, `npm run e2e:cross`, `npm run e2e:install:cross`), not an environment variable, so `playwright.config.ts` keeps its single desktop Chromium project and plain `npm run e2e` needs no other browser. The `@cross` subset is the receive side plus whatever differs between engines: tests 1-4 of `drops.spec`, the 4 `states.spec` tests, a focused vault-unlock test (the KDF worker posts a non-extractable `CryptoKey` to the page), `large-drop.spec` (C-03), `layout.spec` and the leak guard's own CSP test. Projects: `firefox` (Desktop Firefox), `webkit` (Desktop Safari), `mobile-chromium` (Pixel 7), `mobile-webkit` (iPhone 14). Results are labelled by engine: Playwright's WebKit is the Linux engine build, not Safari, and the phone projects only emulate a phone's viewport, user agent and touch. The C-03 test uses no 256 MiB of data: Node encrypts a drop with `@cipherdrop/crypto`, uploads one small chunk, and the manifest claims 300 MiB (the server never sees the manifest); in Chromium the test removes `showSaveFilePicker` first. It rests on the button being disabled, the refusal coming from the decrypted manifest, no `POST /open` or chunk GET being sent while the page loads (the leak guard records each request as it is sent), and an unchanged download count and READY status on the server. A forced click on the disabled button was removed in review: a disabled button gets no click event, so that assertion could not fail (waiting for network idle would not have made it able to fail either). The leak guard's CSP detection matches every engine's wording (`Content[- ]Security[- ]Policy`): Firefox hyphenates the name, so its violations were missed before. Skipped: the full `account.spec` tests 5 and 6 under `@cross` (long, and they use the desktop account menu; the vault-unlock part runs cross-engine as the focused test), and the early capability check in `apps/web/src/main.tsx` ("this browser is not supported"), which belongs to the product half of product-6. Consequence: in WebKit the leak guard cannot read the full headers of document navigations once the page or test ends, so those requests are checked with their provisional headers plus a note; Chromium remains the full-header check.
- 2026-11-21 (batch 1, ci: testing-4, testing-10, ops-10, the production stack in CI): a `prod-stack` job replaces the build-only images job of 2026-11-12. It builds with `docker compose build --pull`, the command an operator runs, so two third-party actions are gone (`docker/setup-buildx-action`, `docker/build-push-action`) and there is no build cache; it boots `docker-compose.prod.yml`, runs `smoke:prod`, and scans both images even when the boot or the smoke fails. Its `.env.production` is `.env.production.example` with only the REQUIRED values replaced (`openssl rand` secrets, masked with `::add-mask::`, plus `WEB_ORIGIN` and `WEB_PORT`): every other shipped value is kept (`COOKIE_SECURE=true`, `TRUST_PROXY=1`, local storage), so the template itself is what gets tested. Image scan policy (`scripts/image-scan.mjs`): a CRITICAL finding with a fixed version fails the job; HIGH findings, and CRITICAL ones with no fix yet, are listed and saved but never fail. Why: the api image had 14 HIGH findings, all fixable, 12 in the npm CLI bundled with `node:22-alpine`, which the server never runs, and 2 in `deepmerge-ts` and `effect` under `@prisma/config`, which `scripts/audit-allowlist.json` already accepts with a reason; a HIGH gate would be red on every upstream disclosure CI cannot act on, and the npm tree stays gated at HIGH by `audit:gate`. Exceptions go into `.trivyignore` with a reason and `exp:YYYY-MM-DD`; the file is mounted only when it exists. Trivy runs from `aquasec/trivy:0.76.2` pinned by its index digest, not from `aquasecurity/trivy-action` (a digest cannot be moved, an action's tags can), and scans a `docker save` tarball (`--input`), so it never gets the Docker socket; a failed scan or an unreadable report exits 2 (fail closed). The SBOM is CycloneDX 1.7 from Trivy, an inventory without vulnerability data, one per image, uploaded with the Trivy JSON reports as the `image-sbom-and-scan` artifact and kept 30 days; it is neither signed nor attested. Skipped: a second run with `--profile minio` and `STORAGE_DRIVER=s3` (cgr.dev was unreachable, so the MinIO image could not be pinned, and a new job on an unpinned image would break the pin-by-digest rule); booting the `tls` profile, pushing images to GHCR, cosign signing and build provenance (not in this task); a reproducible SPA build with an attested dist manifest (testing-10's stretch goal); the load and memory phase of testing-4 (k6 or autocannon, a `docker stats` ceiling), split into a follow-up as the brittle part. None of the new jobs had run on GitHub as of 2026-11-21; if branch protection requires the old `production images build` check, it must be replaced with `production stack (build, boot, smoke, scan)`.
- 2026-11-21 (batch 1, ci: testing-8, secrets, CodeQL, workflow audit, lint bans): gitleaks runs from the MIT-licensed CLI image (`zricethezav/gitleaks:v8.30.1`, pinned by digest), not `gitleaks-action`, which needs a licence key for organisations. It scans the full history (`fetch-depth: 0`) on a read-only mount with `--redact`, and `.gitleaks.toml` allows exact values with their reasons, never paths, so a real secret in the same file is still caught. CodeQL lives in its own workflow (`codeql.yml`), so only that job holds `security-events: write`; the workflow default is `permissions: {}`. It uses `security-extended` and `build-mode: none`, runs on pushes to main, pull requests, Tuesdays at 04:41 UTC and on demand, and keeps `actions: read`, which private repositories need; it needs a public repository or GitHub Code Security. zizmor runs in the `workflows` job with the pedantic persona and `--offline`: no token is handed to the tool, and the result depends only on the files. Instead, every pinned action SHA was checked against its version tag with `git ls-remote`. It is installed with `pip --require-hashes` from `.github/zizmor-requirements.txt`, which a new Dependabot pip entry (7-day cooldown) updates. ESLint bans `Math.random` in `packages/crypto` and the SPA's crypto and workers, `$queryRawUnsafe`, `$executeRawUnsafe` and `Prisma.raw` in the API, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` and `dangerouslySetInnerHTML` in the SPA, and requests to a literal absolute URL from the SPA; `eslint.config.test.mjs` (`npm run test:lint`) proves each ban fires. Skipped: Semgrep rules (the verifier called them optional on top of the ESLint bans) and GitHub secret-scanning push protection, which is a repository setting (recommended in `docs/SECURITY.md` section 7).
- 2026-11-21 (batch 1, ci: testing-10, testing-12, ops-10, pins and drift): the Dockerfiles use literal `FROM` lines with tag and index digest instead of `ARG` overrides, because Dependabot's parser ignores an `ARG`-based `FROM` and an override would let any build swap in an unpinned image without a diff; a registry mirror still works through the daemon's `registry-mirrors`. `docker-compose.prod.yml` pins postgres, redis and caddy, and CI's Postgres and Redis service containers use the same tag and digest, so tests run against the bytes production runs. The `prisma-cli` stage's lockfile is generated at build time from `package-lock.json` (`scripts/prisma-cli-lockfile.mjs`) and installed with `npm ci --ignore-scripts`; it is not committed, so it cannot drift from the root lockfile. `db:check` replays the migrations into a shadow database and fails when they do not build exactly `schema.prisma`; it refuses any `SHADOW_DATABASE_URL` whose database name does not end in `_shadow`, because Prisma wipes the shadow database (CI uses `cipherdrop_shadow`). Review follow-ups: (1) the Dockerfiles carry no `# syntax=` parser directive (removed, not pinned). Neither file needs a newer frontend (no `RUN --mount`, heredocs, `COPY --link` or `--chmod`), so the builder's built-in frontend is used: it is versioned with the Docker install the operator already trusts, nothing is pulled at build time, and it adds no pin to bump by hand. Trade-off: the frontend version follows the operator's BuildKit, acceptable because only core instructions are used; `docker build --check` is clean on both files. (2) CI's references to images that production uses must equal `docker-compose.prod.yml` byte for byte (the Postgres and Redis service containers and the MinIO `docker run`), and both Dockerfiles must share one node reference: `scripts/image-pins.test.mjs` enforces it in `npm run test:scripts`, which audit.yml runs on every push and pull request, so a Dependabot docker-compose pull request stays red until `ci.yml` moves in the same branch. References are compared by repository (`docker.io/library/` ignored), and any differing tag or digest fails; the dev stack (`docker-compose.yml`) is not covered and stays on tags. (3) The check is a small line reader on Node built-ins, not a YAML library, because the audit job installs nothing; it reads `image:` values and tagged references on non-comment lines, ignores mapping keys, `postgresql://` and `redis://` URLs and Dockerfile stage names, and asserts that it found the compose pins, `ci.yml`'s postgres and redis images and both node `FROM` lines, so it cannot pass on nothing found. Skipped: the MinIO digest (`cgr.dev/chainguard/minio:latest`, in `docker-compose.prod.yml`, `docker-compose.yml` and the CI integration job), because cgr.dev could not be reached and a guessed digest is not acceptable; the follow-up is `docker buildx imagetools inspect cgr.dev/chainguard/minio:latest` from a machine that reaches it, then the same `tag@sha256:<index digest>` in all three places. Also skipped: a pull-request-only check that existing migrations are append-only (an optional extra of testing-12). Dependabot does not see three pins (the Trivy image in `scripts/image-scan.mjs`, the gitleaks and actionlint images in `run:` steps); they are bumped by hand.
- 2026-11-21 (batch 1, websec: crypto-1, Swagger UI): context: the API mounted Swagger UI at `/api/docs` in every environment, and nginx proxies all of `/api/` on the origin that holds the vault key, drop keys and the refresh cookie, so a large third-party script bundle ran there. Decision: `API_DOCS_UI` defaults to false in every environment (the schema default); only the dev `.env.example` files turn it on, and `NODE_ENV=production` refuses true, the same way it refuses `RATE_LIMITS_ENABLED=false`. `/api/openapi.json` stays public in every environment. Second safeguard: nginx answers its own 404 for `/api/docs`, with no `add_header`, so the 404 keeps every server-level header. In review this became a case-insensitive top-level regex, `location ~* ^/api/docs(?:/|$)`, because Express mounts are case-insensitive and `/api/DOCS/` reached the API (checked with a real nginx and a real Express). It uses the same segment boundary as the Express mount, so `/api/docsx` is still proxied; it relies on `location /api/` staying a plain prefix (never `^~`), which the unit test enforces; `/API/docs` now also gets nginx's 404 (it used to fall through to the SPA). The footer's "API docs" link is shown only when `import.meta.env.DEV` is true. Consequence: an `apps/api/.env` copied before this change has Swagger UI off until `API_DOCS_UI=true` is added.
- 2026-11-21 (batch 1, websec: crypto-3, saved files and previews): a saved Blob keeps the sender's declared type only if it is on an allowlist of inert types (`text/plain`, `text/csv`, `image/png|jpeg|gif|webp|avif|bmp`, `audio/mpeg|ogg|wav|webm|flac|aac|mp4`, `video/mp4|webm|ogg|quicktime`); everything else becomes `application/octet-stream`. An allowlist rather than a denylist of active types, because an allowlist fails closed. PDF is deliberately left out, because PDF viewers run document JavaScript and forms. The saved file name keeps its extension, so the file opens normally from disk. Reason: some in-app browsers ignore `<a download>` and navigate to the same-origin `blob:` URL, which would render sender HTML or SVG on the key-holding origin. Previews: the sender's declared type only selects the renderer; an image preview URL is `blob.slice(0, size, <allowlisted raster type>)`, SVG is never previewed, and text types (HTML and XML included) are shown as source text in a `<pre>`. Skipped: click-to-show previews; the verifier rated them optional polish, because previews appear only after the user clicks **Decrypt & download**, and image-decoder bugs reach any page that shows images. Not tested: a real in-app browser that ignores `<a download>` (WebKit bug 216918); the rule is covered by unit tests and a Chromium e2e test that records object-URL Blob types.
- 2026-11-21 (batch 1, websec: crypto-4, the key leaves the address bar): the receive page reads the key once, then makes a React Router replace navigation (`preventScrollReset`) to the same path and query, keeping the fragment in that entry's `location.state.shareFragment` so a reload of the tab works. Any non-empty fragment is stripped, mangled and incomplete ones included. The state copy is cleared when `downloadsRemaining` reaches 0, or when the drop is 404, 410 or in a status other than READY and UPLOADING; it is kept while UPLOADING and in admin review mode. `readShareKey` takes the fragment as an argument, with no `window.location.hash` default, which after the strip would silently give null. What this does not do, and the docs must not claim: the browser's global and synced history keeps the full URL (Mozilla bug 753264), and `history.state` can reach session-restore files until it is cleared. Because copying the address bar no longer gives the key, the receive page has an explicit **Copy link**, as the verifier advised: the full key link for key drops, the bare link for password drops (never the unwrapped key), hidden in review mode and once no downloads are left. Review follow-up: when Copy link fails (no clipboard permission, some WebViews), the link is shown in a read-only, focused and selected "Link to this drop" field that replaces the button; it is never shown by default, so the key stays off screen for screen shares, and the hint says that a key link contains the key, or for password drops that the password goes separately.
- 2026-11-21 (batch 1, websec: crypto-7, worker-src and Trusted Types): `worker-src` is `'self'` only (`blob:` removed): both workers come from `new Worker(new URL('...worker.ts', import.meta.url))`, and a source-scan test fails if an inline or `blob:` worker is ever added. Trusted Types ship report-only: `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'; trusted-types default`. The `default` policy (`public/trusted-types.js`, loaded first by `index.html`) allows only same-origin `/assets/*.js` script URLs with no query or hash; `createHTML` and `createScript` always answer null and never throw, so report-only can never break the app. There is deliberately no report endpoint: a Trusted Types violation report carries a sample of the string that reached the sink (WebKit, for example, sends "sink|first 40 characters"), and that string could be decrypted plaintext. The e2e leak guard and the production smoke test are the reporter, failing on Trusted Types console messages; the Vite dev server sends neither CSP header. Review follow-up: WebKit (`ContentSecurityPolicyDirectiveList.cpp`) and Firefox (`nsCSPParser.cpp`) both log a notice for a report-only policy without `report-to` or `report-uri`, and Playwright's Juggler forwards Firefox's as a `warn` console message, so without an exemption every cross-browser test would fail (a correction to the review, which named WebKit only). The leak guard ignores that notice and only that: each exemption is the whole anchored message; WebKit's (`reportMissingReportToTokens`, or `reportMissingReportURI` in older builds) only for our exact policy text, Firefox's (`reportURINorReportToNotInReportOnlyHeader` behind "Content-Security-Policy: ") bare or wrapped as a "JavaScript Warning", never as an Error. Anything appended or prefixed, and any other policy, still counts as a violation (fail closed). The matcher took b1/ci's name and pattern (`isCspViolationMessage`, `/Content[- ]Security[- ]Policy/`), and `prod-smoke`'s `watchCsp` imports it instead of keeping its own regex. The exemption strings come from the engines' source; no real Firefox or WebKit run happened on this branch. Skipped: enforcing Trusted Types (it means moving the two directives into the enforced CSP after clean runs in other browsers), COEP (the verifier said to drop it or mark it optional: COOP, CORP and site isolation already cover the process-isolation argument), and removing `data:` from `img-src` or extending `Permissions-Policy` (not assigned; the verifier called the latter cosmetic).
- 2026-11-21 (batch 1, websec: crypto-5, what "Integrity verified" means): the badge label stays. Its precise meaning is in an always-visible line under **Decrypt & download** and in the badges' `title` ("A verified file is exactly what was encrypted with this link's key, unchanged in transit and storage. It does not tell you who sent it or whether it is safe to open: ..."). The explanation does not repeat the exact label, so the tamper e2e test can still assert that no badge is shown. The note card is titled "Note from the sender (not verified)" and described as "Text written by whoever created this link. CipherDrop cannot confirm who that is." The documentation half (sender identity, `docs/SECURITY.md` 2.6; a post-quantum statement in section 3; the key-commitment note in `packages/crypto/README.md`; the demo's questions) was left to the docs stage and is done with this entry. For the post-quantum statement, the pinned `caddy:2-alpine` image (Caddy 2.11.9) was checked on 2026-11-21 to negotiate X25519MLKEM768 by default with an OpenSSL 3.5 client; it is written as a property of the bundled Caddy, not of the system.
- 2026-11-21 (batch 1, websec: copy and a test): the receive page computes its in-memory limit text from `LIMITS.BLOB_SAVE_MAX_BYTES` and prints it in MiB (256 MiB, about 268 MB), and the unsupported-browser messages name the File System Access API. This corrects "256 MB" in the 2026-11-08 (W2A) entry and in section 11.2: the limit has always been 256 MiB. `verifyResume`: ascending order of `received` is not part of its contract (its only caller, `resumeDrop`, turns it into a skip list that is read back into a Set, and replays progress events that are only summed), so the test now compares a set and the code is unchanged; the order that does matter, checking the highest received index, is pinned by a test of its own.
- 2026-11-21 (batch 1, ops: ops-6, nginx access log and retention): `log_format privacy` = `$time_iso8601`, `$client_prefix` (IPv4 `a.b.c.0/24`, IPv6 /48, the same text as the API's `ipPrefix()`, from a `map` on the realip-restored `$remote_addr`), method, `$request_path`, status, body bytes, request time. No user agent, referer, `X-Forwarded-For`, `$request` or query. It is set at server level, so it replaces the image's http-level `main` format; `/assets/` and `/healthz` are not logged. `$request_path` comes from `$request_uri`, not `$uri`, which `try_files` turns into `/index.html` for every SPA route (found on the booted stack). Review follow-up: both nginx's `$request_path` and the API request log's `pathOnly()` cut the request target at the first `?`, `#` or `%23`, so neither a query string nor a fragment is logged. Why: a share link's fragment is its decryption key; a browser never sends it, but a client that requests the link verbatim does, as `#` straight to nginx and as `%23` through Caddy, which re-encodes a `#` in the path (checked with `caddy:2-alpine`). Other percent-escapes are kept, and a literal `%23` arrives as `%2523` and is unaffected. The nginx rule is `"~^(?<request_path_only>(?:[^?#%]|%(?!23))*)"`; the smoke test failed against `[^?]*` (fragment logged) and `[^?#]*` (`%23` form logged). nginx's error log stays in its fixed format at the image's default level: it records the full client address and request line for request-level errors (connection-cap 429s, 413s, upstream failures), and raising `error_log` to `crit` would hide upstream failures from operators, so it is a documented residual. Retention stays Docker's json-file rotation (3 x 10 MB per container): portable, but bounded by size, not time, about 200,000 nginx requests at 153 bytes per line on disk. Time-based retention (the journald driver with `MaxRetentionSec` in the host's `journald.conf`, or a log shipper with expiry) is documented, not configured, because journald is host-wide and not available on every Docker host.
- 2026-11-21 (batch 1, ops: docs-9, ops-8, disclosure and security.txt): the disclosure channel is GitHub private vulnerability reporting, in `.github/SECURITY.md`, which GitHub reads before `docs/`; the app keeps serving `docs/SECURITY.md` at `/SECURITY.md`. The commitments are worded as aims: acknowledgement within 7 days, a first assessment within 14, publication after the fix or after 90 days, credit unless declined, and a good-faith safe-harbour sentence. Only the latest commit on main is supported. `/.well-known/security.txt` (RFC 9116) is generated at build time (`apps/web/securityTxt.ts`), not committed: RFC 9116 requires `Expires`, so a committed file would carry a date in the repository that silently runs out. `Expires` is the build date plus 180 days, under the RFC's recommended year. Fields: `Contact` (one or more), `Expires`, `Policy`, `Preferred-Languages: en`; no `Canonical` (the build does not know the instance's origin) and no `Encryption` (there is no PGP key). The operator's contact comes from `SECURITY_TXT_CONTACT` (comma-separated `mailto:`, `tel:` or `https://` URIs, in order of preference) and `SECURITY_TXT_POLICY` (`https://` only), web build arguments that `docker-compose.prod.yml` passes from `.env.production` and `vite.config.ts` reads in dev, preview and build; unset means the project's own GitHub reporting form and the policy at `/security/policy`. Values must be printable ASCII without spaces, so a line break cannot add a field, and an invalid value fails the build. Every other `/.well-known/` path is a 404 (nginx `location ^~ /.well-known/ { return 404; }`, and the same in the Vite dev and preview middleware), never the SPA's HTML. Review follow-ups: `Expires` is renewed only by a build step that runs again, and an unchanged `up -d --build` is a BuildKit cache hit that keeps the old date (checked), so the documented renewal is `build --no-cache web` then `up -d web`; after a change of `SECURITY_TXT_CONTACT` or `SECURITY_TXT_POLICY`, `up -d --build web` is enough, because a changed build argument reruns the step. This documented instruction was chosen over a cache-busting build argument such as `SECURITY_TXT_BUILT_ON`, one less variable to remember; the production smoke test fails when `Expires` is less than 30 days away, so against a live instance it doubles as the renewal reminder. Without `SECURITY_TXT_CONTACT`, the file carries a comment that problems in the code go to the project and problems specific to the deployment go to its operator through the site; `.github/SECURITY.md` says the same about instances whose security.txt points back at the repository. Skipped: the rest of ops-8 (privacy, terms and abuse pages, `robots.txt`, HSTS preload), outside "security.txt only", and rewriting the relative links in `docs/SECURITY.md` (the verifier rated it cosmetic: the file is served as plain text, so no link is clickable). Open: the repository owner must enable private vulnerability reporting (Settings, Code security); until then the report link and the default `Contact` point at a form that does not accept reports.
- 2026-11-21 (batch 1, ops: critic-4, versioned S3 buckets): on a versioned bucket a delete without a `VersionId` only adds a delete marker, so expiry, burn after reading and Delete now would keep every ciphertext version. Start-up policy of the S3 driver: Object Lock is always refused; versioning `Enabled` or `Suspended` is refused unless `S3_DELETE_ALL_VERSIONS=true` (new, default false); versioning with MFA Delete is always refused; a setting the driver cannot read is fail-closed, so the key needs `s3:GetBucketObjectLockConfiguration` always and `s3:GetBucketVersioning` unless the flag is set. `NotImplemented` or HTTP 501 counts as "feature not present" (meant for R2, which is untested). With the flag, `deleteDrop` pages through `ListObjectVersions` with markers and deletes every version and delete marker by `VersionId` in `DeleteObjects` batches of 1,000, repeating passes until one finds nothing (at most 5, then it throws) to catch a chunk PUT racing the purge; `deleteChunk` deletes every version of exactly its key. Without the flag the delete paths are unchanged. This is an intended, fail-closed upgrade break for existing S3 deployments: a key without those read permissions now stops the API from starting (`docs/DEPLOYMENT.md` section 6). Verified against `bitnamilegacy/minio` from Docker Hub (53 tests), not the Chainguard image; R2 and AWS S3 untested. The backup and snapshot consequences are documented, not coded (`docs/DEPLOYMENT.md`, Operations).
- 2026-11-21 (batch 1, ops: ops-7, networks, Redis and limits): an internal `backend` network (`internal: true`) holds postgres, redis, minio and `migrate`; the api is on `backend` and `default`. `default` joins nginx to the API and is the API's way out to an external S3; `edge` (Caddy and nginx) is unchanged. Redis requires a password: `requirepass` is passed through the environment (`REDISCLI_AUTH`, from `REDIS_PASSWORD`) and an `sh -c 'exec docker-entrypoint.sh redis-server ...'` command, which keeps the literal password out of the container's `Cmd` while the image's entrypoint still drops to the `redis` user; Redis rewrites its process title, so `/proc/1/cmdline` shows only `redis-server *:6379`. The healthcheck requires the `PONG` reply, so a wrong password makes it unhealthy. `maxmemory 128mb` with `noeviction`: when full, writes fail (fail closed) rather than evicting a denylisted session. Resource limits (`mem_limit` / `pids_limit`): postgres 512m / 200 (`max_connections` 100 plus background workers), redis 256m / 32 (`maxmemory` plus room for the AOF fork's copy-on-write), migrate 512m / 64, api 1g / 256, web 256m / 64 (66 MiB of tmpfs counted in the cgroup, about 80 MiB of buffers for 400 connections, one worker per CPU), minio 1g / 256, caddy 256m / 64. The api's `pids_limit` was 128 and is 256 after review: measured 14 tasks with 1 CPU and 17 with 4, so about 13 plus one per host CPU (the Prisma query engine's runtime; no `cpus` limit is set), plus 7 while a healthcheck's node process runs, plus 4 with `UV_THREADPOOL_SIZE=8`; 256 covers hosts up to about 200 CPUs. Measured smoke-test peaks on 4 CPUs: api 44 MiB / 17, postgres 43 MiB / 8, redis 5 MiB / 6, web 7 MiB / 6, migrate 52 MiB / 8; the MinIO stand-in used 249 MiB / 57. No `cpus` limits, because CPU contention does not crash a host the way memory exhaustion does and a CPU quota on a small VM would slow Argon2id logins; no `NODE_OPTIONS` heap cap, because Node 22 sizes its heap to about half the cgroup limit (checked: a 524 MiB heap limit at `mem_limit: 1g`). Skipped: `*_FILE` or Docker secrets support in `env.ts` (not among the assigned parts; secrets still show in `docker inspect`), switching web to `nginx-unprivileged` with `cap_drop: [ALL]` and `cap_add` sets for postgres and redis (not assigned; it would also change the port mapping and healthcheck and touch Dockerfile lines that b1/ci changed), and image digest pinning (done on b1/ci).
- 2026-11-21 (batch 1, ops: ops-7, a DML-only role for the API): a one-shot `migrate` service (the API image with the command `migrate`, the same build section as `api`, so nothing is ever pulled under the name `cipherdrop-api`) runs `prisma migrate deploy` as the owner and then provisions the runtime role `cipherdrop_app`: `LOGIN` only, `USAGE` (never `CREATE`) on the schema, `SELECT`/`INSERT`/`UPDATE`/`DELETE` on every table, `USAGE` and `SELECT` on sequences, the same through `ALTER DEFAULT PRIVILEGES` for future tables, and nothing on `_prisma_migrations`. Re-running it is idempotent and rotates the password. The API runs with `MIGRATE_ON_START=false` and `POSTGRES_PASSWORD` blanked in its environment (`env_file` would otherwise hand it the owner's password), and waits for `migrate` with `service_completed_successfully`. The runtime password is sent as a SCRAM-SHA-256 verifier computed in Node, so the server never sees it; it must be 24 to 128 URL-safe characters and not a placeholder. An existing role with role-level powers has them removed when the owner is a superuser; a non-superuser owner refuses such a role (PostgreSQL lets only a superuser change `SUPERUSER`, `REPLICATION` or `BYPASSRLS`); a role that is a member of another role is always refused, because it could `SET ROLE`. The image's default entrypoint is unchanged for backward compatibility: `serve` runs the migrations first unless `MIGRATE_ON_START=false`, so single-container and split deployments keep working. The production guard now refuses a `dev-only`, `test-only` or `change-me` password inside `DATABASE_URL` or `REDIS_URL`, as it already did for the three secrets. A Redis password is not required in general, because a split deployment may use a private socket; the bundled compose enforces it with `${REDIS_PASSWORD:?}`. `POSTGRES_APP_PASSWORD` and `REDIS_PASSWORD` are new REQUIRED values in `.env.production.example`, and compose refuses to start without them with a message naming the variable. Review follow-up: `migrate` also refuses a placeholder password in the owner's `DATABASE_URL` (`POSTGRES_PASSWORD`), which nothing else checked because the API's guard never sees that URL; the error names `DATABASE_URL` and `POSTGRES_PASSWORD`, never the value, and it fails closed: it runs after `prisma migrate deploy` (harmless), exits 1, and the API never starts. At the merge, b1/ci's ESLint ban on `$executeRawUnsafe` met the role's DDL (`CREATE`/`ALTER ROLE`, `GRANT`, `REVOKE`), which PostgreSQL cannot take with bind parameters: the ban stays, and the twelve statements go through one helper, `ddl()`, which carries the only `eslint-disable-next-line` for that rule, with its reason and a comment on how each spliced value is checked.
- 2026-11-21 (batch 1, abuse: server-1, limits per /48 and the defaults): context: anonymous, end-to-end encrypted, auto-expiring drops are free file hosting for malware and phishing (Mozilla suspended Firefox Send in July 2020 for this), and the server cannot scan ciphertext, so the controls work on cost and volume (`docs/SECURITY.md` 2.7). Only `createDropAnon` and `register` moved from the /64 to the /48 key (`ipShareKey`), because a /48 holds 65,536 /64s. The guessing and volume limiters (`login`, `prelogin`, `loginMfa`, `open`, `unlock`, `report`, `chunkIp`, `global`) stay per /64, so one noisy neighbour cannot lock a whole /48 site out. Defaults: `ANON_TOTAL_PENDING_BYTES` 10 GiB (0 stays the explicit "no ceiling" opt-out, with the same meaning as before, when it was the default); `ANON_BYTES_PER_CLIENT` 1 GiB per `ANON_BYTES_WINDOW_HOURS` 24 (0 = off); `NEW_ACCOUNT_QUOTA_BYTES` 256 MiB for `NEW_ACCOUNT_PROBATION_DAYS` 7 (0 = no probation); `GLOBAL_STORAGE_CAP_BYTES` 0 (off, because only the operator knows the disk or bucket size); `STORAGE_MIN_FREE_BYTES` 1 GiB (0 = off, local storage only); `ALLOW_ANONYMOUS_UPLOADS` and `ALLOW_REGISTRATION` true. New code constants, not environment variables: `UPLOAD_ACTIVE_MS` = 10 min (`drops/service.ts`) and `EMPTY_UPLOAD_MS` = 1 h (`jobs/cleanup.ts`). The two migrations are named after the task date: `20261120000000_new_account_probation` and `20261120120000_chunk_stored_at`. Rejected: proof-of-work, which moves the cost onto honest (mobile) senders and is weak against botnets and GPUs (Laurie and Clayton 2004), and a CAPTCHA service, which would break the CSP `'self'` rule and the no-third-party anti-goal. Skipped: probation limits on downloads and expiry (the verifier suggested at most 10 downloads and 7 days for new accounts; a candidate follow-up), and a daily sign-up ceiling per IPv4 address or /48 (for example 10 a day, which would cut the single-address account path from about 120 accounts a day to 10; a policy choice, because CGNAT and campus networks share addresses).
- 2026-11-21 (batch 1, abuse: server-1, the anonymous byte budget): the budget meters the declared ciphertext bytes of each anonymous create per IPv4 address or IPv6 /48 in a rolling window, kept in Redis (so it holds across API processes, and one client can no longer fill the anonymous pool and lock every other anonymous sender out). It is reserved after the shape checks and given back only when the create fails afterwards (quota, pool or cap). Deleting a drop gives nothing back, so create-and-delete cycles cannot reset it. Retry-After is the time until enough old bytes leave the window. Signed-in senders are not affected, and it is independent of `RATE_LIMITS_ENABLED`, like the anonymous pool. As revised in review, the store is one Redis hash per client: each field is an hour (`floor(ms / 1 h)`) and holds the MiB taken that hour, every create rounded up to a whole MiB, and an hour counts for the `windowHours` full hours after it, so a create counts for at least the window and at most one hour more. Rounding up and the extra hour both make the budget stricter, never looser. A refund is a negative `HINCRBY` on the same hour, and the field is deleted at 0. `parseEnv` requires `ANON_BYTES_PER_CLIENT` to be 0 or at least `ANON_MAX_DROP_BYTES` rounded up to a MiB; the message names both variables but not their values, because environment errors never print values (some are secrets). Privacy, as corrected in review: for `ANON_BYTES_WINDOW_HOURS` plus up to one hour, Redis keeps the client key with the MiB total of its anonymous creates per hour, and no drop id, exact time or exact size. A Drop row's `createdAt` (the hour) and `totalCiphertextBytes` (the MiB range) can still be matched to a bucket, so on a quiet instance, with one anonymous create in an hour, whoever reads both Redis and Postgres can tie a full IPv4 address or /48 to that drop for the window; before this work, request logs held only IP prefixes. Rejected: one Redis member per create with the exact bytes and a millisecond score (the first round's design, an exact join with the Drop row), and a single fixed-window counter, whose reset lets a client spend twice the budget across the boundary. The copy: "Without an account you can send up to {limit} per {window}, and this drop would go over that. Try again in {wait}, or sign in to send more."
- 2026-11-21 (batch 1, abuse: server-1, new-account probation): stored as `User.quotaProbationEndsAt`, set at registration; existing accounts get null from the migration. The quota that applies is `min(storageQuotaBytes, NEW_ACCOUNT_QUOTA_BYTES)` while the date is in the future; `NEW_ACCOUNT_QUOTA_BYTES` is read at check time, but the end date is fixed at registration. An admin PATCH that includes `storageQuotaBytes`, higher or lower, clears the date at once; a role-only PATCH does not. The account moves to its stored quota on the date by itself, with no job. As revised in review: `AdminUser.storageQuotaBytes` is the stored quota, the value `PATCH storageQuotaBytes` sets, and the new `AdminUser.effectiveQuotaBytes` is the quota that applies now; `Me` keeps one `storageQuotaBytes`, the quota that applies to the user now, plus `quotaProbationEndsAt`. The admin dialog opens with the stored quota, shows the probation limit as a note, and counts the quota as changed only when the parsed field differs from the parsed starting text, so any stored value round-trips and only an explicit quota edit ends the probation. The probation `QUOTA_EXCEEDED` copy says "This drop does not fit in your storage" instead of "Your storage is full", and its details are `{quotaBytes, usedBytes, probationEndsAt?}`. Consequence: the benches register new accounts, so the bench API runs with `NEW_ACCOUNT_PROBATION_DAYS=0` (`docs/BENCHMARKS.md`).
- 2026-11-21 (batch 1, abuse: ops-3, operator switches): `ALLOW_ANONYMOUS_UPLOADS=false` and `ALLOW_REGISTRATION=false` answer 403 `FEATURE_DISABLED` with `details.feature`, checked after validation and before the limiter. They block new anonymous drops and new accounts only: drops already created finish their upload and stay downloadable, and existing accounts still sign in. `GET /api/config` exposes only the two switches (static environment), never how full the server is. The SPA loads the config once at boot in `main.tsx`, not in the pages, so page tests and their exact request lists are unchanged; unknown or failed config counts as on, and the server's 403 then marks the feature off in the store. As revised in review: an interrupted anonymous drop created before the switch can still be resumed, and the notice says so; if a resume fails with a mismatch while the switch is off, the page tries a new drop and explains the API's 403; the navbar's **Sign up** buttons and the login page's "Create an account" link are hidden while registration is off. Skipped: `REGISTRATION_MODE=invite` (invites need a new data model; the task asked for an on/off switch), and the hosting parts of ops-3 (a public demo, `DEMO_MODE`, an immutable demo account, a nightly reset job, deploy-on-tag, a README link), out of scope for in-app controls.
- 2026-11-21 (batch 1, abuse: ops-3, the global cap and the free-disk floor): both answer the same 507 `STORAGE_FULL` with no details, so a client learns neither which one fired nor how full the disk is; `drops_refused_total{reason=client_budget|anon_pool|global_cap|disk_floor}` tells the operator. The anonymous pool keeps its 413 `QUOTA_EXCEEDED`. The global cap's sum: anonymous drops not purged (the existing `ownerId`, `blobsDeletedAt` index), plus account drops counted as quotas count them, `SUM(User.storageUsedBytes)` in one pass over User, plus account drops still UPLOADING (status index). The uploads are read first, so a completion committed between the two reads is counted twice, never missed. A new `blobsDeletedAt` index was rejected: the planner then chose it for the anonymous-pool query and broke the existing C-R3-04 index test. Known gap: an account drop that never reached READY and has left UPLOADING (deleted, disabled, expired) is uncounted until its purge runs, within `CLEANUP_INTERVAL_SEC`. The free-disk floor, as revised in review: free space minus the declared bytes of every active upload in progress (created, or stored a chunk, in the last `UPLOAD_ACTIVE_MS` = 10 min) minus the new drop must stay at or above the floor. Activity comes from the new `DropChunk.storedAt`, set to `ctx.now()` by every chunk PUT in the upsert it already makes, with a `(dropId, storedAt)` index: one index probe per upload in progress, pinned by a plan test. The UPLOADING sum is read before `statfs`, under the lock. Only new drops are refused; chunk PUTs of accepted drops are not, so an accepted upload finishes. Drivers without free-space information (S3) skip it. Trade-off: an accepted upload that stalls for 10 minutes and then resumes can write below the floor. Rejected: counting every UPLOADING drop, the first round's rule, with which anyone could shut new drops off without uploading a byte; and a `Drop.lastChunkAt` column (parallel chunk PUTs hold the drop row `FOR SHARE`, so updating it in the same transaction would deadlock, and updating it after commit adds a Drop write per chunk). Cleanup now marks an UPLOADING drop that has stored no chunk one hour after its create DELETED and purges it (before: only after 24 hours or at expiry), which frees what a pure reservation holds: the owner's quota, the anonymous pool and the global cap. One hour rather than 10 minutes, so that a slow first chunk or a quick reload-and-resume still works (a chunk PUT times out after 300 s); resuming a deleted drop starts a new one, as after the 24-hour cleanup. The pool and the cap still count declared bytes until purge, because they bound what can be stored, not near-term disk writes. One capacity transaction: the user row lock is always taken first, then the capacity advisory lock (the same key as the old anonymous-pool lock); with the default floor on local storage, every create serialises on that lock, which is acceptable because creates are rate limited and the transaction is short. Residual, not closed: reservations kept refreshed (a small chunk every few minutes, or new drops within the rate limits) can still hold the floor, the pool and the cap; a stronger fix needs a cost per reserved byte (for example counting only bytes actually written, plus a hard floor on chunk PUTs) and is a separate design change.
- 2026-11-21 (batch 1, auth: critic-1, bounded Argon2id): server-side Argon2id of the authKey stays (the R3 defence in depth) but is bounded per process. `ARGON2_MAX_CONCURRENT=2` (1-64): the work is CPU-bound with p=1, 2 x 19 MiB = 38 MiB, about 65 to 180 hashes per second at 11 to 30 ms per hash. `ARGON2_MAX_QUEUE=32` (0-10000): a full queue drains in about 0.2 to 0.5 s. Past the queue: 429 `RATE_LIMITED` with `Retry-After: 1`, no failed-login count and no audit event, the same for known and unknown emails. The limit is per process like the chunk caps, so N instances do N times the work. The API image sets `UV_THREADPOOL_SIZE=8`, which leaves at least 6 libuv threads for fs, `dns.lookup` and crypto under a login flood; `env.ts` parses `UV_THREADPOOL_SIZE` (default 4, libuv's) only to refuse `ARGON2_MAX_CONCURRENT >= UV_THREADPOOL_SIZE`, in every environment. Review follow-up: a 429 from a full queue (`AppError.serverBusy`) is refunded by the per-client limiters in front of server-side Argon2id (`login`, `loginIp`, `register`, recovery complete and `reauth`): nothing was checked, so it is no attempt. Without the refund, an honest user who retried during a flood stayed locked out for up to 15 minutes (an hour for register) after it ended. The client gets the same 429 as before; a limiter's own 429 is never refunded, and the global 600 per minute still counts every request. Not chosen: remedy (a), replacing the account `authKeyHash` with HMAC or SHA-256, because it reverses the recorded R3 decision and needs a rehash migration. Not added: a test that floods `/auth/login` while a chunk GET completes, because on a 4-core host 40 parallel hashes clear in about 110 ms, so it would not reliably fail without the fix and would be flaky in CI; the limiter (unit and route tests), the env guard and the image setting are tested instead, and a 60-login flood was checked by hand against the running stack.
- 2026-11-21 (batch 1, auth: critic-1, per-client login limit and nginx): a new limiter, `loginIp`, allows 30 FAILED logins per 15 minutes per client, keyed by `ipShareKey` (an IPv4 address or an IPv6 /48), whatever the email. Successful logins are refunded (`skipSuccessfulRequests`), so a NAT of honest users never spends it; the prelogin and login limiters per IP and email are unchanged. Accepted trade-off: the budget is shared by everyone behind one IPv4 address (CGNAT, office NAT) or one /48, so anyone there can spend it and block even correct logins for everyone behind that address for 15 minutes (`ratelimit.test.ts` asserts this). Mitigations: successful logins and server-busy 429s are refunded, and 30 equals three users' worth of the per-email budget. Accepted, because without it one client could make the server hash for every email it invents. nginx adds `limit_req` zone `auth_ip`, keyed like `api_ip`, at 120 requests per minute (2 per second) with `burst=40 nodelay` and status 429, on the public credential routes only (`prelogin`, `login`, `login/mfa`, `register`, `recovery/start`, `recovery/complete`), matched case-insensitively with an optional trailing slash like the API's router. Refresh, logout and the signed-in routes are not limited, so users behind a NAT are not signed out. nginx's 429 is its HTML page without `Retry-After`, like `limit_conn`. Both numbers stay above the API's own budgets, so honest clients meet the API's JSON 429 first; the unit test checks this against `rateLimit.ts`. Out of scope: server-2 (lockout as a denial of service), read for context only; its 10-failure re-lock fits under the new 30-failure budget, so this work does not change that finding.
- 2026-11-21 (batch 1, auth: server-3, admins need two-step verification): admin routes require two-step verification on the account. `requireRole` re-reads `totpEnabledAt` with the role on every request. The refusal is 403 `FORBIDDEN` with `details.reason` `MFA_REQUIRED` (new `ForbiddenReasonSchema` and `ForbiddenDetailsSchema`, following the `GONE` `details.reason` pattern), so no new error code is needed for it; non-admins still get a bare 403. The check is per account, with no `amr` or `auth_time` claims. It holds for every session because enabling 2FA ends every other session and role ADMIN implies TOTP on (both from the review below). Review follow-ups: (1) enabling TOTP signs out every other session of the account, as a password change does: they are revoked and their sids denylisted, the session that re-authenticated and enrolled stays signed in, and `MFA_ENABLED` records `metadata.revokedSessions`. Without it, a session opened with the password alone before enrolment passed the gate afterwards and could keep refreshing until the absolute limit. Considered and not chosen: a `Session.mfaVerifiedAt` column, which adds nothing to the per-account check once enrolment ends every other session. (2) Role ADMIN implies TOTP on: `PATCH /admin/users/:id` refuses to promote an account without TOTP with 409 `CONFLICT` and writes nothing (the update succeeds only if `totpEnabledAt` is still set); `POST /auth/mfa/totp/disable` refuses admins with 409 ("Admins cannot turn off two-step verification. Ask another admin to change your role to User first."), checked before the password and the code, so no code is spent, and the update succeeds only if the role is still not ADMIN; `requireRole` keeps re-reading `totpEnabledAt` for accounts changed outside the app. Reason: an admin account without TOTP is open to anyone who knows its password, who can enrol their own authenticator, open the console and lock the real admin out. Considered and not chosen: demoting the account automatically when it turns 2FA off, as GitHub organisations do, a silent loss of role. Consequence: an admin who must replace their authenticator is demoted first by another admin (a sole admin uses SQL), re-enrols and is promoted again. No test covers the disable side against a concurrent promotion (it would need a request-level race); the promotion side is tested with a stale read. (3) Production bootstrap is enrol first, then promote: register, turn on 2FA in **Settings**, **Security**, then `UPDATE "User" SET role='ADMIN' WHERE email=... AND "totpEnabledAt" IS NOT NULL`, checking that psql prints `UPDATE 1`. No script, because the runtime image has no tsx. Seed and e2e: no seeded TOTP secret, because the console's 2FA gate is part of the demo, a shared secret would be one more credential in the repository, and enrolling takes one QR scan; the seed prints how to enrol, the e2e admin test enrols through the Settings UI so the gate and its notice are exercised, and the API test factory's `createAdminRecord` sets `totpEnabledAt` by default. The seeded dev admin stays without TOTP, to demo the gate (dev only). Dropped, as the verifier advised: point 4, a single-use `mfaToken` with a `jti` (a replay still needs a new valid code, because of `totpLastStep` and single-use backup codes). Still open: point 5, per-session recency (`amr`/`auth_time`) with a recent-auth step-up on `GET /admin/reports` and `POST /admin/drops/:id/grant`, so a 30-day admin session reads report keys without passing the second factor again (`docs/SECURITY.md` section 7). Also open: admins promoted before this rule, or by SQL without the condition, stay open to anyone who knows their password until they enrol; closing that in code would need an out-of-band channel, which the app does not have.
- 2026-11-21 (batch 1, auth: server-3, one re-authentication rule): one rule, `requireAccountProof`: the current authKey, plus a TOTP or backup code when TOTP is on. It covers password change (a new optional `code`, required with 2FA on), recovery-key rotation, TOTP disable, `DELETE /me`, backup-code regeneration (authKey and a TOTP code only), TOTP enable (authKey and the new authenticator's code) and session revocation (`DELETE /auth/sessions/:id` and `POST /auth/sessions/revoke-others`, both now under the reauth limiter). TOTP enable needs the password because otherwise a stolen access token could enrol the thief's authenticator and lock the owner out of sign-in and recovery for good. Session revocation needs it because ASVS 4.0.3 V3.3.4 asks for re-entered credentials before logging out other sessions, and revoking sessions one at a time must not bypass revoke-others. `PATCH /me/settings` (auto-lock) and logout stay without step-up. In the SPA, TOTP enable, backup-code regeneration and session revocation derive the authKey with `kdfClient.unlockVault`, which checks the password locally against the wrapped account key, so a wrong password fails with "Wrong password." and never reaches the server, as password change already did. Review follow-up: the budget (`reauth`, 10 per 15 minutes) is counted per session (user id and sid), not per user, and shared by every route that calls `requireAccountProof`. A new session needs the password (and the second factor), so a token thief still gets 10 guesses per window but cannot spend the owner's budget and stop them from signing the stolen session out. Successful proofs still count, because each runs a server-side Argon2id. From one session the owner can sign out up to 10 sessions one at a time per 15 minutes; "Sign out all other devices" ends any number in one request. Consequence: other clients of these routes break, because TOTP enable, backup-code regeneration and session revocation now require an authKey in the body (`docs/DEPLOYMENT.md` section 6).
- 2026-11-21 (batch 1, auth: server-3, absolute session lifetime): `SESSION_MAX_LIFETIME_DAYS`, default 30 (1-365), refused when below `REFRESH_TOKEN_TTL_DAYS` in every environment. The default follows NIST SP 800-63B's reauthentication period for AAL1 ("at least once per 30 days ... regardless of user activity"), since 2FA is optional. With both defaults at 30, a session is simply 30 days from sign-in, and the vault already asks for the password on every reload, so a monthly full sign-in costs users little. The absolute end is computed from `Session.createdAt` on every refresh, so sessions whose `expiresAt` slid before this change end too, and `GET /auth/sessions` no longer lists them. The refresh cookie's expiry, `Session.expiresAt` and the last access token's `exp` (its TTL is shortened near the end) all stop at the deadline.
- 2026-11-21 (batch 1, integration): the five branches were merged in the order b1/ci, b1/websec, b1/ops, b1/abuse, b1/auth, each merge commit listing its conflicts and their resolution. The ones that changed code: the leak guard's matcher (b1/websec's `isCspViolationMessage` block, a superset of b1/ci's pattern with the report-only exemptions); the redis service (b1/ci's digest-pinned image with b1/ops' password environment and command); CI's `prod-stack` job, which now also generates `POSTGRES_APP_PASSWORD` and `REDIS_PASSWORD` (without them compose refuses to start and `migrate` and the API refuse the template's placeholders) and sets `SMOKE_WEB_CONTAINER=cipherdrop-prod-web-1`, so the access-log check runs in CI; the runtime role's DDL behind one `ddl()` helper (entry above); `env.ts`, which keeps every new variable and dropped b1/auth's stale `ANON_TOTAL_PENDING_BYTES: int(0, 0)` line so the key is defined once, with b1/abuse's 10 GiB default; and `registerLimit`, keyed on `ipShareKey` (b1/abuse) with `refundServerBusy` (b1/auth), after the `ALLOW_REGISTRATION` check. The two new migrations come after `20261114000000` in timestamp order, and `db:check` reported no drift. Follow-up on the merged branch: the root `.env.example`, the documentation copy of every API variable, lacked 13 of `env.ts`'s keys (the batch-1 ones, and `ANON_TOTAL_PENDING_BYTES` from before); it now carries them, `env.ts` exports `ENV_KEYS`, and `env.test.ts` checks that the root `.env.example` sets each key (`UV_THREADPOOL_SIZE` commented out, because libuv reads it only from the process environment at start-up) and names nothing that neither the API nor `apps/web/.env.example` reads.
- 2026-11-21 (batch 1, documentation): the doc notes of the five branches were applied after checking each against the merged code, with these changes. `docs/DEPLOYMENT.md` gains section 6, Upgrading, which collects every change an operator of an existing install must act on, and a `CHANGELOG.md` (Keep a Changelog) is added to the documentation set of the 2026-11-12 entry. Test counts were re-run on the merged branch on 2026-11-21 (README, Running the tests). Not applied: the README's CodeQL badge (optional in the note, and `codeql.yml` has not run on GitHub yet); a change of "5 migrations applied" to 6 in the 2026-11-12 verification record, which was true on that date (the record already notes the sixth migration of 2026-11-14); and "Android Chrome has no `showSaveFilePicker`": `@mdn/browser-compat-data` 8.1.10 lists it in Chrome for Android from version 132, so the README says that the page detects the API, that MDN lists it there, and that no phone was tested with it. The minimum browser versions in the README come from the same data (module workers: Firefox 114, Safari 15; CSP `'wasm-unsafe-eval'`: Chrome and Edge 97, Firefox 102, Safari 16) and were not tested.
- 2026-11-21 (batch 1, docs-1, media run): `npm run media -w @cipherdrop/web` regenerates `docs/screenshots` and records `docs/screenshots/demo.gif` from the real app. It has its own config, `apps/web/playwright.media.config.ts`, and its specs end in `.media.ts`, which neither the e2e config nor the cross-engine one matches (both take `*.spec.ts`; `--list` shows no media test in either), and no workflow calls it, because it writes into the repository. docs-1 suggested a `MEDIA=1` gate inside the e2e run instead; a separate config keeps the specs out of that run whatever the environment holds. It starts the same servers as `npm run e2e` (the vite build under `vite preview` with the production CSP, and the real API on the wiped `cipherdrop_e2e` database), so it shares the e2e ports and cannot run next to an e2e run. The seeded demo and admin accounts get random passwords per run (`MEDIA_DEMO_PASSWORD` and `MEDIA_ADMIN_PASSWORD`, set in the runner before the workers and the web server start), never the `.env` ones, and that build gets the demo one as `VITE_DEMO_CREDENTIALS` for the recorded "Use demo account" sign-in. Every browser context's clock is frozen at the real current time (`clock.setFixedTime`), so countdowns read the same in every picture while fresh access tokens are not taken for expired ones. The e2e leak guard stays on, its CSP check included. The captions are a plain element built with DOM calls (`textContent` and CSSOM properties), not Playwright 1.65's `page.screencast.showOverlay`, which assigns its HTML string to `innerHTML`: the report-only Trusted Types `default` policy reports that assignment, and the guard rightly fails on the report. The chunk PUTs are held back on purpose: `send-progress-*` lets five through and parks the rest, and the clip delays each one by 600 ms so the ciphertext strip stays on screen, so the speeds shown are not measurements (DEMO.md and BENCHMARKS.md section 8 say so). Screenshots are 1440x900 (desktop) and 390x844 (phone) CSS pixels at device scale factor 2. The GIF is recorded at 1152x720, one browser context per scene, and ffmpeg joins the scenes at 8 frames per second and 960 px wide, drops unchanged frames (`mpdecimate`, frame delays kept) and uses one 96-colour palette for the clip; the run fails unless the GIF is under 6 MiB (as committed: 960x600, 186 frames, about 86 s, 4,636,528 bytes). Without ffmpeg the screenshots are still made and the scenes stay as WebM files. `hero.png` is now a composite, `send-progress-dark.png` and `receive-light.png` side by side at 1280x640 CSS pixels (2560x1280 px), not a copy of `receive-light.png`. The committed PNGs were recompressed losslessly with oxipng (level 4, safe chunk stripping, through `pyoxipng`) after the run, which writes Playwright's PNGs as they are and so needs no extra tool: the same pixels, 6.7 MB down to 4.8 MB. Two smaller deviations from docs-1: a GIF only, no MP4, and in `docs/screenshots` rather than a new `docs/media`. Not done: part (3) of docs-1, a profile for a public demo instance (small caps, a banner, a nightly wipe). An internet-facing anonymous upload endpoint is free encrypted hosting that the operator cannot inspect ([SECURITY.md](SECURITY.md) section 2.7), and a one-click demo account would need `VITE_DEMO_CREDENTIALS` in a production build, which DEPLOYMENT.md forbids and the production smoke test fails on.
- 2026-11-21 (batch 1, documentation review): corrections after a review of the batch-1 documentation. GitHub private vulnerability reporting, the channel that `.github/SECURITY.md`, docs/SECURITY.md section 8, the README and the default security.txt name, was off on this public repository (`gh api repos/exotic-Siddharth/cipherdrop/private-vulnerability-reporting` returned `{"enabled":false}`). Turning it on is a repository setting that only the owner can change, not a change in the code, so the documents now say that the form exists only while the setting is on and that it was off on this date (docs/SECURITY.md section 7); once the owner has turned it on, those notes go. In `CHANGELOG.md`: the first round of pull request #1 is dated 2026-11-20 (all 11 commits of `main..ccr-5c0c9ee9-ysizz2` are from that day), and the refresh-token change of 2026-11-14 and the LICENSE of 2026-11-13 are listed as already on `main`; the re-authentication bullet names the two exceptions (backup-code regeneration takes a TOTP code only, turning 2FA on a code from the new authenticator); the digest pins are scoped to the production stack, the Dockerfiles and CI (the dev compose file stays on tags, as DEPLOYMENT.md section 5 says; docs/SECURITY.md section 7 is scoped the same way); the removed build arguments and CI job are under Removed; the media run is listed; and `[Unreleased]` has its link definition. `hero.png` is described as 2560x1280 px (1280x640 CSS pixels at device scale factor 2) wherever its size is given.
