# Changelog

Notable changes to CipherDrop. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). There
are no releases yet: only the latest commit on `main` is supported, so everything after the v1 build is listed under
Unreleased. The reasons behind each change are in the Decisions log of [docs/DESIGN.md](docs/DESIGN.md).

## [Unreleased]

Since the v1 build: two changes already on `main` (2026-11-13 and 2026-11-14), the first round of pull request #1
(2026-11-20) and batch 1 (merged 2026-11-21).

### Upgrade notes

Several changes need action on an existing install **before** the next `up`, or the stack or the API refuses to
start: two new required passwords, new S3 permissions, and checks on `ANON_MAX_DROP_BYTES`,
`REFRESH_TOKEN_TTL_DAYS` and `TRUST_PROXY`. Others change behaviour on their own: admins need two-step verification,
sessions end 30 days after sign-in, and several API routes take new request bodies. Read
[docs/DEPLOYMENT.md, section 6 (Upgrading)](docs/DEPLOYMENT.md#6-upgrading) first.

### Security

- Admin step-up: reporters' decryption keys (`GET /admin/reports`) and review grants need a sign-in or
  `POST /auth/step-up` (password plus a 2FA code) within `ADMIN_STEP_UP_MINUTES` (default 15). Sessions record
  `authenticatedAt`, which refreshes never move; the console asks for the step-up.
- Lock vault and sign-out apply to every open tab of the browser (a `BroadcastChannel`, with a `storage`-event
  fallback; only the signal crosses tabs, never key material). Before, another unlocked tab kept the account key.
- Admin routes require two-step verification on the account (403 `MFA_REQUIRED` otherwise), because the console can
  return reporters' decryption keys. Only accounts with 2FA can be promoted, admins cannot turn 2FA off, and turning
  2FA on signs out every other session of the account.
- One re-authentication rule for every sensitive action: password change, recovery-key rotation, turning 2FA on or
  off, backup-code regeneration, signing one or all other sessions out, and account deletion need the current
  password, plus a TOTP or backup code when 2FA is on (backup-code regeneration takes a TOTP code only; turning 2FA
  on takes a code from the new authenticator), with a budget of 10 attempts per 15 minutes per session.
- Sessions have an absolute lifetime (`SESSION_MAX_LIFETIME_DAYS`, 30 days from sign-in) besides the idle one.
- Server-side Argon2id is bounded per API process (2 running, 32 waiting, then 429 with `Retry-After: 1`, which the
  login, registration, recovery and re-authentication limits do not count), and the API image sets `UV_THREADPOOL_SIZE=8` so a login flood cannot take the
  libuv threads that file I/O needs.
- Failed logins are limited to 30 per 15 minutes per IPv4 address or IPv6 /48, and the bundled nginx limits the
  credential routes to 2 requests per second per client (burst 40).
- Hosting-abuse controls: anonymous creates and sign-ups counted per IPv6 /48 instead of /64; a rolling byte budget
  per anonymous client (1 GiB per 24 hours); a 10 GiB ceiling on all anonymous drops by default (it was off); a
  256 MiB probation quota for new accounts' first 7 days; an optional global storage cap and a 1 GiB free-disk floor
  (507 `STORAGE_FULL`); operator switches for anonymous uploads and registration. Cleanup deletes an upload that has
  stored no chunk one hour after its create.
- Swagger UI, a large third-party bundle, is no longer served on the origin that holds the keys: the API mounts it
  only with `API_DOCS_UI=true`, which production refuses, and nginx answers 404 for `/api/docs` in any letter case.
- The receive page takes the key out of the address bar once it has read it (the browser's history still holds it),
  and offers an explicit Copy link.
- Received files keep their declared type only if it is inert (text, CSV, raster images, common audio and video);
  HTML, SVG, XML, scripts, PDF and every other type are saved as `application/octet-stream`. Image previews are
  typed from the same allowlist.
- `worker-src 'self'` (no `blob:`), and Trusted Types in report-only mode with a `default` policy; the e2e leak guard
  and the production smoke test fail on any violation.
- The S3 driver refuses to start on a bucket where a delete would not be final (Object Lock, or versioning without
  the new `S3_DELETE_ALL_VERSIONS=true`, which deletes every version).
- The production stack isolates Postgres, Redis and MinIO on an internal network, requires a Redis password, runs the
  migrations in a one-shot `migrate` service as the owner, and connects the API as `cipherdrop_app`, a role with
  rights on rows only. Placeholder passwords are refused in `DATABASE_URL` and `REDIS_URL` (by the API) and in the
  owner's URL (by `migrate`).
- nginx's access log records only the client's IP prefix and the path cut at the first `?`, `#` or `%23`, so a share
  link's key never reaches a log even when a client requests the link verbatim; the API's request log cuts its path
  the same way.
- Supply chain: every third-party image of the production stack, the Dockerfiles and CI is pinned by tag and digest
  (MinIO's excepted; the dev compose file, `docker-compose.yml`, stays on tags), the Dockerfiles have no
  floating `# syntax=` frontend, the image's Prisma CLI is installed from a lockfile cut out of `package-lock.json`,
  and CI's service images are checked equal to the production pins.
- First round: nginx streams chunk transfers and caps in-flight `/api` requests per client (64) and in total (400),
  so the API's slow-client defences act on the real client; behind the bundled Caddy, nginx trusts
  `X-Forwarded-For` only from Caddy's fixed address, and `TRUST_PROXY` is `1` with or without Caddy.
- First round: Prisma error text is kept out of every log path (a validation error had rendered a reporter's drop
  key into the API's log); the leak guard checks every request of every browser context with all its headers; the
  audit gate's output cannot act as a GitHub Actions workflow command.
- On `main` (2026-11-14): a refresh whose response was lost no longer signs the user out. A used refresh token
  presented within 30 seconds of its rotation, while its successor is unused, gets a new successor in the same
  session; the replaced successor is retired, not deleted, so presenting it later is detected as reuse.

### Added

- Admin console: Clear lock for a locked-out account (`POST /api/admin/users/:id/clear-lock`), audited as
  `ACCOUNT_LOCK_CLEARED` on the account and on the admin. SECURITY.md section 7 records the lockout trade-off.
- `/.well-known/security.txt` (RFC 9116), generated at build time from `SECURITY_TXT_CONTACT` and
  `SECURITY_TXT_POLICY`, and a vulnerability disclosure policy in `.github/SECURITY.md` (GitHub private
  vulnerability reporting, which works only once the repository setting is on; it was off on 2026-11-21, see
  docs/SECURITY.md section 7); every other `/.well-known/` path is a 404.
- `GET /api/config` (the two operator switches), the error codes `FEATURE_DISABLED` (403), `UPLOAD_BUDGET_EXCEEDED`
  (429) and `STORAGE_FULL` (507), and the fields `Me.quotaProbationEndsAt`, `AdminUser.effectiveQuotaBytes` and
  `AdminUser.quotaProbationEndsAt`.
- Environment variables: `SESSION_MAX_LIFETIME_DAYS`, `ARGON2_MAX_CONCURRENT`, `ARGON2_MAX_QUEUE`,
  `UV_THREADPOOL_SIZE`, `API_DOCS_UI`, `S3_DELETE_ALL_VERSIONS`, `ALLOW_ANONYMOUS_UPLOADS`, `ALLOW_REGISTRATION`,
  `ANON_BYTES_PER_CLIENT`, `ANON_BYTES_WINDOW_HOURS`, `NEW_ACCOUNT_QUOTA_BYTES`, `NEW_ACCOUNT_PROBATION_DAYS`,
  `GLOBAL_STORAGE_CAP_BYTES`, `STORAGE_MIN_FREE_BYTES`; for the compose stack `POSTGRES_APP_PASSWORD` and
  `REDIS_PASSWORD` (required), and for the API image `MIGRATE_ON_START`, `DB_RUNTIME_ROLE` and `DB_RUNTIME_PASSWORD`.
- Metrics: `drops_refused_total{reason}`, `argon2_active`, `argon2_queued` and `argon2_rejected_total`.
- Migrations `20261120000000_new_account_probation` and `20261120120000_chunk_stored_at`, and on `main` since
  2026-11-14 `20261114000000_refresh_token_rotated_from` (`RefreshToken.rotatedFromId`).
- Resource limits (`mem_limit`, `pids_limit`) on every service of the production stack.
- CI: a cross-engine e2e job (Firefox, WebKit and two emulated phones for the `@cross` subset), a `prod-stack` job
  that builds the images from the Dockerfiles, boots the stack, runs the smoke test and scans both images with Trivy
  (CycloneDX SBOMs as artifacts), a gitleaks scan of the full history, zizmor, CodeQL (`codeql.yml`), a migration
  drift check (`npm run db:check`), ESLint security bans with their own test (`npm run test:lint`), and a check that
  CI's images equal the production pins. All of them passed on their first GitHub run (2026-11-21, commit ee40e84).
- Production smoke tests for security.txt, Swagger UI, the access log and the credential-route rate limit (14 in
  all).
- Documentation: the sender-identity and hosting-abuse sections of the threat model, a post-quantum statement, the
  key-commitment limit in `packages/crypto/README.md`, an Upgrading section in `docs/DEPLOYMENT.md`, and this file.
- `npm run media -w @cipherdrop/web` (`apps/web/playwright.media.config.ts`; opt-in, never run by `npm run e2e` or
  CI) regenerates `docs/screenshots` at device scale factor 2 and records `docs/screenshots/demo.gif`, the DEMO.md
  flow. Six new screenshots (password prompt, used-up drop, recovery-key step, TOTP setup, second-factor sign-in, the
  blocked download on a phone), `hero.png` as a real composite instead of a copy of `receive-light.png`, and a README
  gallery.
- On `main` (2026-11-13): the MIT `LICENSE`.
- First round: Dependabot, every action pinned to a commit SHA, `npm ci --ignore-scripts` everywhere, actionlint,
  and a dependency audit gate (`npm run audit:gate`, `audit.yml`) with a reviewed allowlist.

### Changed

- `POST /auth/mfa/totp/enable`, `POST /auth/mfa/backup-codes`, `DELETE /auth/sessions/:id` and
  `POST /auth/sessions/revoke-others` require `authKey` (and a code) in the body; `POST /auth/password` takes a
  `code` when 2FA is on; `POST /auth/mfa/totp/disable` answers 409 for admins; `PATCH /admin/users/:id` answers 409
  when promoting an account without 2FA. `AdminUser.storageQuotaBytes` is the stored quota.
- `ANON_TOTAL_PENDING_BYTES` defaults to 10 GiB (was 0, off), and `ANON_BYTES_PER_CLIENT` must be at least
  `ANON_MAX_DROP_BYTES` (rounded up to a MiB), or 0.
- The API image no longer has to migrate on start in the compose stack (`MIGRATE_ON_START=false` there); its default
  `serve` command still migrates first, so other deployments keep working.
- The Dockerfiles use literal, digest-pinned `FROM` lines.
- The receive page's copy: "Integrity verified" is explained, the note is titled "Note from the sender (not
  verified)", and the in-memory limit is stated as 256 MiB.
- First round: `TRUST_PROXY` is `1` for the `tls` profile (it used to be told 2), and the production stack has a
  compose network `edge` on `172.16.94.0/28` between Caddy and nginx.

### Removed

- The `NODE_IMAGE` and `NGINX_IMAGE` build arguments of the Dockerfiles (use the Docker daemon's `registry-mirrors`
  for a mirror).
- CI's build-only images job, replaced by `prod-stack`; a branch protection rule that requires
  `production images build` must require `production stack (build, boot, smoke, scan)` instead.

[Unreleased]: https://github.com/exotic-Siddharth/cipherdrop/compare/main...ccr-5c0c9ee9-ysizz2
