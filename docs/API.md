# API

The REST API is served by `apps/api` (Express 5) under the `/api` prefix. Every request and response body is a
zod schema in `packages/shared`, and the same schemas generate the OpenAPI document, so the document cannot drift
from the validation. This page explains the conventions and the main endpoints; the OpenAPI document is the
complete reference.

The API only ever handles ciphertext, wrapped keys, hashes and derived auth keys. All byte strings in JSON are
unpadded base64url. See [SECURITY.md](SECURITY.md) for what this means for each field.

## OpenAPI document

| URL (dev API on port 4100) | Content |
|---|---|
| `http://localhost:4100/api/openapi.json` | OpenAPI 3.0.3 document, 42 operations (including the three operational routes) |
| `http://localhost:4100/api/docs` | Swagger UI for the same document |

Through the SPA's dev server or the production nginx the same paths work on the web origin
(`http://localhost:5174/api/docs`); the site footer links to it. A test (`apps/api/src/app.test.ts`) walks the
real Express router stack and fails if any route is missing from the document.

```bash
curl -s http://localhost:4100/api/openapi.json -o openapi.json
```

## Authentication

There are five kinds of credentials. All tokens are random 32-byte values that the server stores only as
SHA-256 hashes.

| Scheme (OpenAPI name) | Sent as | Obtained from | Used for |
|---|---|---|---|
| `bearerAuth` | `Authorization: Bearer <JWT>` | login, register, refresh | account endpoints, `/me`, `/admin`; HS256, 15 minutes, claims `sub`, `role`, `sid` |
| `refreshCookie` | cookie `cd_rt` (httpOnly, `SameSite=Strict`, `Path=/api/auth`) | login, register, refresh | `POST /auth/refresh` and `/auth/logout`; rotated on every use |
| `uploadToken` | `Authorization: Bearer <token>` | `POST /drops` | chunk PUTs, upload status, complete; useless once the drop is READY |
| `downloadToken` | `Authorization: Bearer <token>` | `POST /drops/:id/open` or an admin review grant | chunk GETs; valid for `DOWNLOAD_GRANT_TTL_MIN` (30), extended by each chunk GET up to 24 h after issue |
| `ownerToken` | header `X-Owner-Token` | `POST /drops` | deleting an anonymous drop (signed-in owners can use their session instead) |

Admin endpoints need `role=ADMIN`; the role is re-read from the database on every request, so a demotion takes
effect at once. A revoked session's access token is refused immediately through a Redis denylist of session ids.

## Errors

Every error has the same shape:

```json
{ "error": { "code": "NOT_FOUND", "message": "Unknown drop" } }
```

`details` is optional. Validation errors list the failing fields:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request",
    "details": {
      "issues": [
        { "path": "params.id", "message": "Expected base64url (no padding) of exactly 16 bytes", "code": "invalid_string" }
      ]
    }
  }
}
```

| HTTP | `code` | Typical cause |
|---|---|---|
| 400 | `VALIDATION_ERROR` | body, query or path fails its schema; malformed JSON |
| 401 | `UNAUTHORIZED` | missing or expired token; wrong authKey (always generic for login and recovery) |
| 403 | `FORBIDDEN` | not the owner, or not an admin |
| 404 | `NOT_FOUND` | unknown id; a drop still uploading is also reported as unknown to recipients |
| 409 | `CONFLICT` | email already registered; `complete` with missing chunks (`details.missing`) |
| 410 | `GONE` | drop expired, used up, deleted or disabled; `details.reason` is `EXPIRED`, `EXHAUSTED`, `DELETED` or `DISABLED` |
| 413 | `PAYLOAD_TOO_LARGE`, `QUOTA_EXCEEDED` | body over its limit; drop larger than the per-drop limit or the user's quota |
| 429 | `RATE_LIMITED` | a rate limit or an in-flight cap; the `Retry-After` header gives the wait in seconds |
| 500 | `INTERNAL` | unexpected error; the response carries no stack trace, the log has the request id |

Every response has an `X-Request-Id` header and `Cache-Control: no-store`. Paged lists take `?page&pageSize`
and return `{items, total, page, pageSize}`.

## Rate limits

Limits are counted in Redis (`apps/api/src/lib/rateLimit.ts`) and reported with the draft-7 `RateLimit` and
`RateLimit-Policy` headers. "Per IP" means the full IPv4 address or the IPv6 /64.

| Limiter | Limit | Key |
|---|---|---|
| global (all `/api` except chunk transfers) | 600 per minute | IP |
| prelogin, login | 10 per 15 minutes each | IP + email |
| login MFA step | 10 per 15 minutes | IP |
| register | 5 per hour | IP |
| recovery start, recovery complete | 5 per hour each | IP |
| create drop | 10 per hour anonymous (per IP), 60 per hour signed in (per user) | IP or user |
| chunk PUT / chunk GET | 1,200 per minute | upload or download token |
| chunk transfers, any token | 6,000 per minute, checked before the token limits | IP |
| open | 30 per hour | IP |
| unlock (failures only) | 5 per 15 minutes per drop + IP, and 20 per hour per drop; `/unlock` and `/open` of password drops share these counters | drop + IP, drop |
| report | 5 per hour | IP |

In-flight caps on chunk transfers (per API process, answered with 429 and `Retry-After`): 64 uploads in total,
8 per upload token and 16 per client; 192 downloads in total, 8 per download grant and 32 per client. "Client"
here is the IPv4 address or the IPv6 /48. The values are environment variables
([DESIGN.md section 6](DESIGN.md#6-configuration-zod-validated-env-fail-fast)).

The e2e suite and the benchmarks run their own API with `RATE_LIMITS_ENABLED=false`; production refuses to start
with that setting.

## Endpoints

Paths are relative to `/api`. Request and response fields are in the OpenAPI document.

### Accounts (`/auth`)

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /auth/prelogin` | none | KDF parameters for an email; unknown emails get a deterministic fake salt with the same shape |
| `POST /auth/register` | none | create an account from client-derived material (`authKey`, KDF params, wrapped account key, recovery wrap and hash); sets `cd_rt` |
| `POST /auth/login` | none | `{email, authKey}`; returns the access token, or `{mfaRequired: true, mfaToken}` |
| `POST /auth/login/mfa` | none | `{mfaToken, code}` with a TOTP or backup code |
| `POST /auth/refresh` | cookie | rotate the refresh cookie, new access token; a reused token revokes the session |
| `POST /auth/logout` | cookie | revoke the current session |
| `GET /auth/vault` | bearer | wrapped account key and KDF params, for unlocking the vault in the browser |
| `POST /auth/password` | bearer | change password: new authKey and the re-wrapped account key; other sessions are revoked |
| `POST /auth/recovery/start`, `/complete` | none | recovery with the recovery key; complete rotates the recovery key and revokes every session |
| `POST /auth/recovery/rotate` | bearer | replace the recovery key while signed in |
| `POST /auth/mfa/totp/setup`, `/enable`, `/disable`, `POST /auth/mfa/backup-codes` | bearer | TOTP enrolment, 10 backup codes, regeneration |
| `GET /auth/sessions`, `DELETE /auth/sessions/:id`, `POST /auth/sessions/revoke-others` | bearer | list and revoke sessions |

### The signed-in user (`/me`)

| Method and path | Purpose |
|---|---|
| `GET /me` | profile with storage quota and usage |
| `PATCH /me/settings` | vault auto-lock: 5, 15 or 60 minutes |
| `GET /me/drops?status=active\|expired\|all` | owned drops with their encrypted manifests and owner-wrapped keys, which the browser decrypts |
| `GET /me/audit?action` | the activity log |
| `DELETE /me` | delete the account, its drops and their blobs (requires the authKey, and a TOTP code when enabled) |

### Drops (`/drops`)

A send is `create`, then one PUT per chunk, then `complete`. A receive is `GET /drops/:id`, optionally
`unlock` (password drops), then `open` (consumes one download) and one GET per chunk.

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /drops` | none or bearer | create: encrypted manifest, per-file ciphertext sizes and chunk counts, expiry, download limit, optional password verifier and owner wrap; returns `dropId`, `uploadToken`, `ownerToken` |
| `PUT /drops/:id/files/:fileId/chunks/:index` | upload token | raw ciphertext chunk (`application/octet-stream`, at most 4 MiB + 16 bytes) with `X-Chunk-SHA256`; a re-PUT overwrites, so retries are safe |
| `GET /drops/:id/upload-status` | upload token | received chunks and their SHA-256, used to resume after a reload |
| `POST /drops/:id/complete` | upload token | checks every chunk and size, marks the drop READY; 409 lists what is missing |
| `GET /drops/:id` | none | metadata: status, file count, total size, expiry, downloads left, encrypted manifest (null for password drops) and the password KDF params |
| `POST /drops/:id/unlock` | none | `{authKey}` for a password drop; returns the wrapped drop key and the manifest; rate limited |
| `POST /drops/:id/open` | none | consumes one download atomically and returns a download token |
| `GET /drops/:id/files/:fileId/chunks/:index` | download token | streams one ciphertext chunk |
| `DELETE /drops/:id` | owner token or owner session | delete the drop and its blobs |
| `POST /drops/:id/report` | none | abuse report; the drop key is included only if the reporter opts in |

### Admin (`/admin`, `role=ADMIN`)

| Method and path | Purpose |
|---|---|
| `GET /admin/stats` | totals and uploads per day for 14 days |
| `GET /admin/reports?status` | abuse reports; the reporter's key is returned only for OPEN reports |
| `POST /admin/reports/:id/resolve` | `DISABLE_DROP` (blobs deleted) or `DISMISS` |
| `POST /admin/drops/:id/grant` | review grant that consumes no download; audited as `ADMIN_REVIEW_GRANT` |
| `GET /admin/users?search`, `PATCH /admin/users/:id` | list users; change role or storage quota |

### Operations (no `/api` prefix)

| Path | Purpose |
|---|---|
| `GET /healthz` | liveness |
| `GET /readyz` | readiness: database, Redis and blob storage |
| `GET /metrics` | Prometheus metrics: request durations, drops created and opened, chunk bytes up and down, cleanup runs, storage bytes |

The production nginx answers 404 for `/readyz` and `/metrics`, so they are reachable only inside the Docker
network ([DEPLOYMENT.md](DEPLOYMENT.md)).
