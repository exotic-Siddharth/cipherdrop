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
| Tests | Vitest 3, Supertest 7, @testing-library/react + jsdom, Playwright (chromium), `otpauth` in tests to compute TOTP codes |
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
| `REFRESH_TOKEN_TTL_DAYS` | 30 | |
| `COOKIE_SECURE` | false | |
| `TOTP_ENC_KEY` | dev value | 32 bytes base64; encrypts TOTP secrets at rest |
| `PRELOGIN_SECRET` | dev value | HMAC key for fake salts (no user enumeration) |
| `STORAGE_DRIVER` | local | `local` or `s3` |
| `STORAGE_DIR` | ./data/blobs | local driver root (gitignored) |
| `S3_ENDPOINT` `S3_REGION` `S3_BUCKET` `S3_ACCESS_KEY_ID` `S3_SECRET_ACCESS_KEY` `S3_FORCE_PATH_STYLE` | MinIO dev values (http://localhost:59000, us-east-1, cipherdrop, …, true) | |
| `ANON_MAX_DROP_BYTES` | 104857600 (100 MiB) | ciphertext bytes |
| `USER_MAX_DROP_BYTES` | 2147483648 (2 GiB) | |
| `USER_DEFAULT_QUOTA_BYTES` | 5368709120 (5 GiB) | |
| `ANON_MAX_EXPIRY_HOURS` | 72 | |
| `USER_MAX_EXPIRY_HOURS` | 720 | |
| `MAX_FILES_PER_DROP` | 20 | |
| `DOWNLOAD_GRANT_TTL_MIN` | 30 | |
| `CLEANUP_INTERVAL_SEC` | 60 | |
| `TRUST_PROXY` | false | true behind nginx |
| `SEED_ADMIN_PASSWORD` / `SEED_DEMO_PASSWORD` | dev values | |

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
  drop   Drop   @relation(fields: [dropId], references: [id], onDelete: Cascade)
  @@id([dropId, fileId, index])
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
- **Grants**: a successful open creates a `DownloadGrant`, an opaque token valid for `DOWNLOAD_GRANT_TTL_MIN`. Each chunk GET extends the expiry, up to 24 h after the grant was created. Chunk GETs need a valid grant for that drop, and the drop must not be DELETED or DISABLED. EXHAUSTED drops stay downloadable while a grant lives, so a burn-after-read download can still resume.
- **Upload validation**:
  - `index < chunkCount`;
  - non-final chunks are exactly `CHUNK_SIZE + 16` bytes, and the final chunk is between `16` and `CHUNK_SIZE + 16` bytes;
  - `X-Chunk-SHA256` must match the body;
  - re-PUT of the same index overwrites, so retries are idempotent.

  `complete` requires every chunk and requires each file's chunk sizes to sum to its declared `ciphertextBytes`. It moves the drop to READY, adds the bytes to the owner's `storageUsedBytes`, and writes an audit record.
- **Quotas**: on create, enforce the per-drop byte limit (anon vs user), `MAX_FILES_PER_DROP`, the expiry ceiling, `maxDownloads ∈ {1,2,3,5,10,20,50,100}` (anonymous ≤ 10), and the user quota (`storageUsedBytes + new ≤ storageQuotaBytes`). Bytes are released when the drop's blobs are deleted.
- **Cleanup** (`runCleanup(now)`, every `CLEANUP_INTERVAL_SEC`, under a Redis lock `lock:cleanup`):
  - READY drops past `expiresAt` → EXPIRED, delete blobs;
  - EXHAUSTED drops with no unexpired grant → delete blobs;
  - UPLOADING drops older than 24 h → DELETED, delete blobs;
  - release quota, write audit events (`DROP_EXPIRED` / `DROP_EXHAUSTED`) to the owner if there is one.

  `runCleanup` is pure-ish (takes `now`) and unit/integration tested.

---

## 10. REST API (prefix `/api`)

Conventions:
- Errors: `{error:{code, message, details?}}` with codes `VALIDATION_ERROR|UNAUTHORIZED|FORBIDDEN|NOT_FOUND|CONFLICT|GONE|RATE_LIMITED|PAYLOAD_TOO_LARGE|QUOTA_EXCEEDED|INTERNAL`.
- Paging: `?page&pageSize` → `{items,total,page,pageSize}`.
- `Cache-Control: no-store` on every `/api` response.
- All schemas are zod in `packages/shared` and appear in `/api/openapi.json` and `/api/docs`.

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
| POST /auth/password | user | `{currentAuthKey, newAuthKey, kdf, wrappedAccountKey}` → 204 (other sessions revoked) |
| POST /auth/recovery/start | – | `{email, recoveryAuthKey}` → `{recoveryToken, wrappedAccountKeyRecovery, mfaRequired}` (generic 401 on mismatch or unknown email) |
| POST /auth/recovery/complete | – | `{recoveryToken, code?, newAuthKey, kdf, wrappedAccountKey, wrappedAccountKeyRecovery, recoveryAuthHash}` → `AuthSuccess` + cookie |
| POST /auth/recovery/rotate | user | `{authKey, code?, wrappedAccountKeyRecovery, recoveryAuthHash}` → 204 (audited as `RECOVERY_KEY_ROTATED`; sessions stay signed in) |
| POST /auth/mfa/totp/setup | user | → `{secret, otpauthUrl}` (stored as pending, encrypted) |
| POST /auth/mfa/totp/enable | user | `{code}` → `{backupCodes: string[10]}` |
| POST /auth/mfa/totp/disable | user | `{authKey, code}` → 204 |
| POST /auth/mfa/backup-codes | user | `{code}` → `{backupCodes}` (regenerate) |
| GET /auth/sessions | user | → `SessionInfo[]` (`current` flag via sid) |
| DELETE /auth/sessions/:id | user | → 204 |
| POST /auth/sessions/revoke-others | user | → 204 |
| PATCH /me/settings | user | `{autoLockMinutes: 5|15|60}` → `{user: Me}` |
| DELETE /me | user | `{authKey, code?}` → 204 (deletes the user, their drops and blobs) |
| GET /me | user | → `{user: Me}` |
| GET /me/audit | user | `?action&page&pageSize` → Page<AuditEventDto> |
| GET /me/drops | user | `?status=active|expired|all&page&pageSize` → Page<OwnerDropSummary `{id, status, fileCount, totalBytes, maxDownloads, downloadCount, downloadsRemaining, expiresAt, createdAt, lastOpenedAt, passwordProtected, encryptedManifest, ownerWrappedKey}`>. active = UPLOADING/READY; expired = EXPIRED/EXHAUSTED/DISABLED; all = everything except DELETED |

TOTP uses `otpauth`: SHA1, 6 digits, a 30 s period, a ±1 step window, and replay protection via `totpLastStep`. Backup codes are 10 × 10 Crockford chars (`xxxxx-xxxxx`), stored as SHA-256 hashes and single-use.

### Drops
| Method & path | Auth | Request → Response |
|---|---|---|
| POST /drops | optional user | `CreateDropRequest {encryptedManifest, files:[{id, ciphertextBytes, chunkCount}], expiresInHours, maxDownloads, password?: {kdf, wrappedDropKey, authKeyHash}, ownerWrappedKey?}` → 201 `{dropId, ownerToken, uploadToken, expiresAt}` |
| PUT /drops/:id/files/:fileId/chunks/:index | `Bearer uploadToken` | body `application/octet-stream` (raw, limit CHUNK_SIZE + 16), header `X-Chunk-SHA256` (lowercase hex of the ciphertext) → 204 |
| GET /drops/:id/upload-status | `Bearer uploadToken` | → `{files:[{id, chunkCount, received:[{index, sha256}]}]}` |
| POST /drops/:id/complete | `Bearer uploadToken` | → `{status:"READY"}` (409 with the missing chunks if incomplete) |
| GET /drops/:id | – | → `DropMeta {id, status, fileCount, totalBytes, expiresAt, maxDownloads, downloadsRemaining, passwordProtected, encryptedManifest: string\|null /*null when password-protected*/, passwordKdf: KdfParams\|null, createdAt}`. 404 if unknown; **410** `GONE` with `details.reason` ∈ EXPIRED/EXHAUSTED/DELETED/DISABLED |
| POST /drops/:id/unlock | – | `{authKey}` → `{wrappedDropKey, encryptedManifest}`. 401 on mismatch (audited to the owner as `DROP_UNLOCK_FAILED`). Rate limits: 5/15 min per drop+IP, 20/h per drop |
| POST /drops/:id/open | – | `{authKey?}` (required for password drops) → `{downloadToken, expiresAt, downloadsRemaining}`. Atomic consumption (§9). Audited to the owner as `DROP_OPENED` (with ipPrefix + UA) |
| GET /drops/:id/files/:fileId/chunks/:index | `Bearer downloadToken` | → ciphertext stream (`application/octet-stream`) |
| DELETE /drops/:id | owner (`X-Owner-Token` or owner session) | → 204 (blobs deleted) |
| POST /drops/:id/report | – | `{reason, details?, decryptionKey?}` → 201. Rate limit 5/h per IP |

### Admin (`role=ADMIN`)
| Method & path | Purpose |
|---|---|
| GET /admin/stats | `{users, activeDrops, totalDrops, storageBytes, openReports, uploadsLast14d:[{date, drops, bytes}]}` |
| GET /admin/reports?status | Page<AdminReport `{id, reason, details, status, createdAt, hasKey, decryptionKey (only here), drop:{id, status, fileCount, totalBytes, ownerEmail, createdAt}}`> |
| POST /admin/reports/:id/resolve | `{action:"DISABLE_DROP"\|"DISMISS"}` → 204 |
| POST /admin/drops/:id/grant | non-consuming review grant → `{downloadToken, expiresAt, encryptedManifest}` (audited) |
| GET /admin/users?search · PATCH /admin/users/:id | `{role?, storageQuotaBytes?}` |

Health: `/healthz`, `/readyz` (DB + Redis + storage), `/metrics`.

**Rate limits** (Redis store, `Retry-After`):

| Endpoint | Limit |
|---|---|
| prelogin / login | 10 per 15 min per IP+email |
| register | 5/h per IP |
| recovery | 5/h per IP |
| create drop (anon) | 10/h per IP |
| create drop (user) | 60/h per user |
| chunk PUT / GET | 1200/min per upload/download token (exempt from the global limit) |
| open | 30/h per IP |
| unlock | as above |
| report | 5/h per IP |
| global | 600/min per IP |

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
| `/d/:id` (Receive) | States: loading · not found · gone (reason-specific copy: expired / downloads used up / deleted / disabled) · missing key · password prompt (wrong password → shake + message, rate-limit message) · ready: decrypted note, file list (name, size, type icon), "N of M downloads left · expires in …". **Decrypt & download** (a confirm dialog when it consumes the last download) → per-file progress → saved; files ≤ 256 MB go through a Blob + `<a download>`, larger ones through `showSaveFilePicker` when available (otherwise a clear message) → "Integrity verified" badge, image (png/jpg/gif/webp) and text (≤ 1 MB) previews from the decrypted Blob. An integrity failure shows a prominent red "This file was modified in transit or storage. Download blocked." Report link (dialog: reason, details, an opt-in checkbox "include the decryption key so moderators can review"). `?review=1` for admins uses the admin grant |
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
  - `Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'; worker-src 'self' blob:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`;
  - `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, and HSTS (prod).
- API: helmet; CORS restricted to `WEB_ORIGIN`; `no-store` caching; `trust proxy` from env.
- Constant-time comparisons for every token and hash (`crypto.timingSafeEqual` on equal-length buffers).
- pino redaction of `authorization`, `cookie`, `x-owner-token`, and request bodies on auth and drop routes. **Never log** request bodies, authKeys, tokens, manifests or wrapped keys.
- Generic auth errors. No user enumeration (prelogin fake salts, identical recovery errors). Account lockout. Rate limits (§10).
- Tokens are random 32 bytes and stored only as SHA-256 hashes. Upload tokens are useless once the drop is READY.
- Validation everywhere with zod. Body limits: 1 MB JSON, `CHUNK_SIZE + 16` raw on chunk PUT.
- Admin: RBAC on every route. Admin review grants are audited.
- **SECURITY.md**:
  - an asset and adversary table (network attacker, malicious or breached server, link interceptor, XSS);
  - what the server can see (drop count, ciphertext sizes ≈ plaintext sizes, timestamps, IP prefixes, account email) and can't see;
  - limitations: a malicious server could serve modified JavaScript (mitigations discussed: CSP, SRI, reproducible builds; out of scope: code-signing extensions); keys in links leak through chat logs and browser history (password mode mitigates this); size metadata leaks; losing the recovery key means data loss by design; the KDF parameter rationale;
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

The seed prints the demo credentials and the share links of the non-password drops.

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
- **E2E** (Playwright, chromium, preview build with CSP):
  1. Anonymous send of a 5 MB random file → open the link in a new context → download → the SHA-256 equals the original.
  2. Password drop: the wrong password shows an error; the right one downloads.
  3. Burn after reading: a second context gets the "downloads used up" page.
  4. **Tamper test**: `page.route` flips one byte of a chunk response → the UI shows the integrity error and no file is saved.
  5. Account: register (recovery key step) → send → the dashboard shows the decrypted filename → reload → unlock → filenames visible → enable TOTP (code computed from the secret shown) → logout → login requires TOTP.
  6. Recovery with the recovery key → new password works.

  Capture **screenshots** (light and dark: send, progress, success, receive, dashboard, settings) into `docs/screenshots/`.
- **CI**: lint + typecheck + unit; integration with postgres/redis services (+ MinIO started via `docker run` for `test:s3`); e2e with the Playwright report uploaded on failure.

A feature is done when it has: its endpoint(s) with zod validation, auth rules and rate limits; tests; its UI wired to the real API, with loading, empty and error states; OpenAPI registration; zero TS or ESLint errors; and **no plaintext metadata reaching the server** (reviewers check request payloads in the e2e traces).

---

## 15. Observability & operations
- pino JSON logs with requestId and the redaction rules (§12).
- Prometheus metrics:
  - `http_request_duration_seconds`;
  - `drops_created_total{anon}`, `drop_opens_total`;
  - `chunk_bytes_uploaded_total`, `chunk_bytes_downloaded_total`;
  - `cleanup_runs_total`, `cleanup_deleted_drops_total`;
  - `storage_bytes` gauge.
- Graceful shutdown (stop the server, the cleanup interval, Prisma and Redis).

## 16. Deployment (docs/DEPLOYMENT.md)
- `docker-compose.prod.yml` services:
  - `postgres` and `redis`;
  - `minio`, or external S3/R2 via env;
  - `api` (multi-stage image; `prisma migrate deploy` on start);
  - `web` (nginx: SPA + headers from §12 + `/api` proxy with `client_max_body_size 5m`);
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
