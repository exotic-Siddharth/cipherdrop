# Deployment

This guide covers running CipherDrop in production: the single-host Docker Compose stack that ships in this
repository, and a split deployment (static SPA host, API on a container host, managed Postgres and Redis, S3-compatible
storage). It follows `docs/DESIGN.md` section 16. Everything marked **verified** was run on the author's machine and is
recorded in [Verification record](#verification-record); everything else is described, not tested.

CipherDrop is zero-knowledge: the server only ever stores ciphertext, wrapped keys and hashes (DESIGN sections 7 and 12;
the threat model is [SECURITY.md](SECURITY.md)). Deployment therefore protects availability, metadata and the integrity of the
JavaScript that the browser runs; it cannot protect a file from a user who loses the link or the password.

## 1. Single-host stack (`docker-compose.prod.yml`)

```mermaid
flowchart LR
  B[Browser] -->|HTTPS| C["caddy (optional, profile tls)"]
  B -->|HTTP, loopback or your own TLS proxy| W
  C --> W["web: nginx<br/>SPA + security headers"]
  W -->|"/api/* (max body 5 MiB)"| A["api: Node 22, non-root<br/>prisma migrate deploy on start"]
  A --> P[(postgres 16)]
  A --> R[(redis 7, AOF)]
  A --> S[("blobs volume<br/>or S3 / R2 / minio")]
```

| Service    | Image                                              | Notes                                                                                                                                                                            |
| ---------- | -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `postgres` | `postgres:16-alpine`                               | Volume `postgres-data`. Not published.                                                                                                                                           |
| `redis`    | `redis:7-alpine`                                   | AOF persistence on volume `redis-data`: it holds the revoked-session denylist, so a restart must not forget it. Not published.                                                   |
| `api`      | built from `apps/api/Dockerfile`                   | Multi-stage (build, pinned Prisma CLI, runtime). Runs as uid 1000, read-only root filesystem, all capabilities dropped. Runs `prisma migrate deploy`, then the server.           |
| `web`      | built from `apps/web/Dockerfile` (nginx 1.31)      | The built SPA, `deploy/nginx.conf`, healthcheck on `/healthz`. The only service that publishes a port (`WEB_BIND:WEB_PORT`, default `127.0.0.1:8080`).                           |
| `minio`    | `cgr.dev/chainguard/minio` (profile `minio`)       | Optional S3-compatible storage inside the stack. `minio/minio` left Docker Hub, hence the Chainguard image (same choice as the dev compose file).                                |
| `caddy`    | `caddy:2-alpine` (profile `tls`)                   | Optional automatic HTTPS on 80/443 in front of nginx. Needs a public DNS name pointing at the host.                                                                              |

Every service has a healthcheck and `restart: unless-stopped`. `web` waits for `api` to be healthy (`/readyz`: database,
Redis and blob storage), and `api` waits for Postgres and Redis.

### Install

Requirements: Docker Engine with Compose v2, a host that can build the images (about 2 GB of free disk for the build
cache, images and layers), and for real use a DNS name and TLS.

```sh
cp .env.production.example .env.production       # .env.production is gitignored

# generate the secrets (each one separately) and paste them into .env.production
openssl rand -hex 24      # POSTGRES_PASSWORD  (URL-safe: compose embeds it in DATABASE_URL)
openssl rand -hex 32      # JWT_ACCESS_SECRET
openssl rand -hex 32      # PRELOGIN_SECRET
openssl rand -base64 32   # TOTP_ENC_KEY

# also set WEB_ORIGIN (the exact public origin) and TRUST_PROXY, see below
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
docker compose --env-file .env.production -f docker-compose.prod.yml ps
```

`--env-file` supplies the values compose interpolates (`POSTGRES_PASSWORD`, `WEB_PORT`, ...), and the same file is passed
to the `api` container as its environment (`env_file`, overridable with `ENV_FILE=...`). Compose then overrides what the
topology fixes: `NODE_ENV=production`, `DATABASE_URL` and `REDIS_URL` (pointing at the `postgres` and `redis`
services), `STORAGE_DIR`, `API_PORT`.

With TLS terminated by the bundled Caddy:

```sh
# in .env.production: SITE_ADDRESS=drop.example.com  WEB_ORIGIN=https://drop.example.com  TRUST_PROXY=2
docker compose --env-file .env.production -f docker-compose.prod.yml --profile tls up -d --build
```

With your own TLS terminator or load balancer in front, point it at `WEB_BIND:WEB_PORT` and set `TRUST_PROXY` to the
number of proxies between the internet and the API (nginx counts as one).

### The production configuration guard

`apps/api/src/config/env.ts` refuses to start under `NODE_ENV=production` unless:

- `DATABASE_URL`, `REDIS_URL`, `WEB_ORIGIN` and `TRUST_PROXY` are set explicitly;
- `COOKIE_SECURE=true` (the refresh cookie is `Secure`; browsers store it only from an `https://` page, with
  `http://localhost` and `http://127.0.0.1` as the exceptions);
- `WEB_ORIGIN` is a bare origin (no path, no trailing slash), because CORS compares it to the `Origin` header exactly;
- `RATE_LIMITS_ENABLED` is not `false`;
- `JWT_ACCESS_SECRET` and `PRELOGIN_SECRET` have at least 32 characters, `TOTP_ENC_KEY` decodes to exactly 32 bytes,
  and none of them contains `dev-only`, `test-only` or `change-me`.

`.env.production.example` is written to fail that guard until it is filled in: its three secrets are `change-me`
placeholders. `apps/api/src/config/env.production-example.test.ts` checks both directions: the file as shipped is
refused, and the same file with real random secrets is accepted.

`TRUST_PROXY` is the number of proxy hops whose `X-Forwarded-For` entry is trusted for `req.ip`, which feeds rate limits,
the per-IP in-flight caps and the IP prefix in audit events. nginx appends the address it sees to the header, so:

| Path to the API                                       | `TRUST_PROXY` |
| ----------------------------------------------------- | ------------- |
| client, nginx (this stack, no TLS proxy)              | `1`           |
| client, Caddy (profile `tls`) or your load balancer, nginx | `2`      |

Too low puts every client behind the proxy's address (one shared rate-limit bucket); too high lets a client choose its own
address by sending the header. Check it after deploying: two different clients must show different IP prefixes in the audit
log.

### nginx and the security headers

`deploy/nginx.conf` serves the SPA and sends the DESIGN section 12 headers (the strict CSP, `Referrer-Policy`,
`X-Content-Type-Options`, `Permissions-Policy`, COOP, CORP and HSTS) with `always`. The list mirrors
`apps/web/securityHeaders.ts`, the same constants `vite preview` serves during the Playwright e2e run, so the CSP the
browser tests exercise is the CSP production sends. `apps/web/deploy-checks/nginx-headers.test.ts` fails when the two
drift apart.

Other behaviour worth knowing:

- `/api/*` is proxied to `api:4100` with `client_max_body_size 5m` (a chunk PUT is 4 MiB + 16 bytes, JSON bodies are at
  most 1 MiB). API responses keep their own helmet headers; nginx adds HSTS (replacing the API's weaker one) and
  `Permissions-Policy`.
- `/assets/*` is cached for a year (content-hashed names), `index.html` and the unhashed root files are `no-cache`, unknown
  paths fall back to `index.html` (client-side routes such as `/d/<id>`), a missing `/assets/` file is a 404.
- `/healthz` is nginx's own liveness. `/readyz` and `/metrics` answer 404 from nginx; scrape the API's `/metrics` inside the
  Docker network (`api:4100`), see DESIGN section 15 for the metric list.
- `/SECURITY.md` serves the threat model (`docs/SECURITY.md`, copied into the build) as UTF-8 plain text; the
  `/how-it-works` page links to it. The web image's build stage copies that one file from `docs/`, which
  `.dockerignore` otherwise excludes.
- JSON is not gzip-compressed (BREACH), static types are.
- `limit_conn` allows at most 400 in-flight `/api` requests in total (429 beyond that); see [Per-process caps](#4-per-process-caps-and-multi-instance-deployments).
- The container runs with a read-only root filesystem (tmpfs for nginx's cache and pid file).
- nginx resolves `api` through Docker's resolver (`127.0.0.11`) and caches the answer for 10 s (`valid=10s`), so
  recreating the API container leaves nginx pointing at a dead address for at most about 10 s.

### Operations

- **Logs:** pino JSON on stdout (`docker compose ... logs api`), json-file driver rotated at 3 x 10 MB. Request bodies,
  tokens, cookies and keys are redacted (DESIGN section 12).
- **Upgrades:** `git pull`, then `up -d --build`. The API container applies pending Prisma migrations before it starts
  serving (`migrate deploy` takes a Postgres advisory lock, so replicas starting together are safe). Migrations are
  forward-only: take a database backup before upgrading, because there is no automatic down-migration.
- **Shutdown:** `docker stop` sends SIGTERM; the API stops accepting connections, stops the cleanup job and disconnects
  Prisma and Redis (`stop_grace_period: 15s`; the process forces exit after 10 s).
- **Cleanup:** the expiry and exhausted-drop cleanup runs inside the API every `CLEANUP_INTERVAL_SEC` (default 60) under a
  Redis lock.
- **Backups:** nothing automatic. Back up (a) Postgres (`pg_dump` of database `cipherdrop`), (b) the blob store (volume
  `blobs`, or the bucket) at a point close to the dump, and (c) `.env.production`, in particular `TOTP_ENC_KEY`: without it
  every stored TOTP secret is unreadable. A dump without its blobs gives drops whose files are gone (downloads fail), a
  blob store without the dump is unreadable ciphertext.
- **Secrets rotation:** changing `JWT_ACCESS_SECRET` invalidates all access tokens (15-minute lifetime, clients refresh).
  Changing `PRELOGIN_SECRET` changes the fake salts of unknown emails (an observable difference to an attacker who recorded
  them earlier). Changing `TOTP_ENC_KEY` breaks enrolled TOTP secrets, there is no re-encryption tool.
- **Seed data is for development.** Do not run `db:seed` in production and do not set `SEED_*` or `VITE_DEMO_CREDENTIALS`;
  the web image is built from a context that excludes every `.env` file, and the smoke test checks that the bundle contains no
  demo credentials.

### Smoke test of a running stack

`apps/web/deploy-checks/prod-smoke.spec.ts` drives a running stack through nginx with a real browser. Use the loopback
address, because WebCrypto needs a secure context and the refresh cookie is `Secure`:

```sh
# stack started with WEB_ORIGIN=http://127.0.0.1:8080
SMOKE_BASE_URL=http://127.0.0.1:8080 npm run smoke:prod -w @cipherdrop/web
```

It checks every header nginx sends on `/`, on a deep link and on `/api`, the asset cache headers, the 404 for a missing asset,
the 413 for a 6 MiB body, that `/readyz` and `/metrics` are not exposed, that the bundle has no demo credentials, and one
complete flow: register, upload 5 MiB (two chunks), reload and unlock (refresh cookie through the proxy), and a second
browser context decrypting identical bytes with no CSP violation or page error. It leaves the account it registered in the
database, so do not run it against a production database you care about.

## 2. S3-compatible storage

`STORAGE_DRIVER=local` keeps ciphertext on the `blobs` volume and only works with one API instance (every instance would
need the same filesystem). For anything else use `STORAGE_DRIVER=s3` with an S3-compatible store:

```sh
STORAGE_DRIVER=s3
S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com   # R2; omit for AWS S3
S3_REGION=auto                                              # R2: auto, AWS: the bucket's region
S3_BUCKET=cipherdrop
S3_ACCESS_KEY_ID=...
S3_SECRET_ACCESS_KEY=...
S3_FORCE_PATH_STYLE=true                                    # MinIO; R2 and AWS S3 also accept false
```

Create the bucket yourself and give the key read, write and delete rights on it; the driver only creates the bucket when it
is missing. The bucket must not be publicly readable: the API streams chunks to authorised clients, nothing links to the
store directly. With `--profile minio` the stack runs MinIO itself (`S3_ENDPOINT=http://minio:9000`,
`S3_FORCE_PATH_STYLE=true`, the access key and secret become MinIO's root credentials). The S3 driver is covered by the
contract tests against MinIO (`npm run test:s3`); R2 and AWS S3 were not tested.

## 3. Split deployment

Static SPA on a static host, API on a container host, managed Postgres and Redis, S3-compatible storage (for example R2).

```mermaid
flowchart LR
  B[Browser] -->|"https://drop.example.com/*"| H["static host / CDN<br/>serves dist/ + headers"]
  H -->|"/api/* rewritten or proxied<br/>(same origin)"| A["API container host<br/>2+ instances, TRUST_PROXY=hops"]
  A --> PG[(managed Postgres)]
  A --> RD[(managed Redis)]
  A --> S3[(R2 / S3)]
```

**The SPA and the API must be the same origin.** This is a property of the code, not a preference:

- the SPA calls relative `/api/...` URLs (`apps/web/src/lib/http.ts`), there is no configurable API base URL;
- the CSP says `connect-src 'self'`, so the browser would block a request to another host;
- requests use `credentials: 'same-origin'`, and the refresh token is an `httpOnly`, `Secure`, `SameSite=Strict` cookie
  scoped to `Path=/api/auth` with no `Domain`, so it is sent only to the exact host that set it.

Consequently:

1. Build the SPA (`npm run build -w @cipherdrop/web`, output `apps/web/dist`) and publish it on the static host, **with the
   section 12 headers** from `deploy/nginx.conf` (copy the values; they are plain strings) and the SPA fallback to
   `index.html`. Do not set `VITE_DEMO_CREDENTIALS` for the build.
2. Make `https://<spa-host>/api/*` reach the API: a rewrite or proxy rule of the static host or CDN, an edge function on the
   same hostname, or a small reverse proxy in front of both. The path must be forwarded unchanged (`/api/...`). Check the
   limits of that proxy: it must pass request bodies of at least 4 MiB + 16 bytes (nginx here allows 5 MiB), response
   bodies of the same size, and timeouts of at least 120 s. I have not tested any specific static host or CDN.
3. Set the API's `WEB_ORIGIN` to the SPA's exact origin, for example `https://drop.example.com` (scheme and host, no path, no
   trailing slash, default port omitted). With the proxy in place requests are same-origin and CORS never applies, but
   the production guard still requires a bare origin and the CORS allow-list is that string.
4. `COOKIE_SECURE=true` and HTTPS end to end for the browser-facing hop. Set `TRUST_PROXY` to the number of proxies between
   the client and the API container (the static host's proxy, plus your load balancer, ...). Verify it with the audit log as
   described above.
5. Postgres: `DATABASE_URL=postgresql://user:password@host:5432/db?schema=public&sslmode=require` (TLS if the provider
   offers it). The role that starts the API needs DDL rights, because `prisma migrate deploy` runs on every start; the
   database needs `max_connections` for instances times Prisma's pool (default `num_cpus * 2 + 1` per instance).
6. Redis: `REDIS_URL=rediss://...`. Use `noeviction` and persistence: it holds rate-limit counters, the revoked-session
   denylist and the cleanup lock, and evicting the denylist would let a revoked access token live until it expires
   (`ACCESS_TOKEN_TTL_SEC`, 15 minutes by default).
7. Storage: `STORAGE_DRIVER=s3` (section 2). More than one instance cannot use `local`.

An API on a different hostname (`api.example.com`) is **not supported by the current build**. It would need an API base URL
in the SPA, an extra `connect-src` entry in the CSP, `credentials: 'include'`, and a decision about the cookie (a sibling
subdomain is same-site, so `SameSite=Strict` would still work, but the cookie has no `Domain`). None of that exists or has
been tested.

## 4. Per-process caps and multi-instance deployments

Review point C-15 added ceilings on chunk transfers so one slow or hostile client cannot exhaust memory or storage
sockets. Which of them are shared between instances matters as soon as there is more than one API process:

| Control                                                                                                       | Scope                         | Effect with N instances                                                              |
| ------------------------------------------------------------------------------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------ |
| `MAX_CONCURRENT_CHUNK_UPLOADS` (64): in-flight chunk PUTs, each buffered up to 4 MiB + 16 B                    | **per process** (in memory)   | N x 64 uploads, up to N x 256 MiB of buffered bodies                                 |
| `MAX_CONCURRENT_CHUNK_DOWNLOADS` (192, max 224): streaming chunk GETs, kept below the 256-socket S3 pool       | **per process**               | N x 192 streams                                                                      |
| `MAX_CHUNK_UPLOADS_PER_TOKEN` / `_PER_IP` (8 / 16), `MAX_CHUNK_DOWNLOADS_PER_GRANT` / `_PER_IP` (8 / 32)       | **per process**               | A client spread over N instances gets up to N times the per-IP and per-token share   |
| Body idle timeout and minimum rate (`CHUNK_UPLOAD_IDLE_TIMEOUT_SEC`, `CHUNK_UPLOAD_MIN_BYTES_PER_SEC`), `CHUNK_IDLE_TIMEOUT_SEC` | per request                   | Unaffected                                                                           |
| HTTP rate limits (global 600 per minute per IP, auth, drops, chunk limiters)                                   | **shared** (Redis store)      | Unaffected                                                                           |
| `ANON_TOTAL_PENDING_BYTES`                                                                                     | **shared** (Postgres advisory lock) | Unaffected                                                                     |
| Session denylist, cleanup lock                                                                                 | **shared** (Redis)            | Unaffected                                                                           |
| `STORAGE_DRIVER=local`                                                                                         | one filesystem                | Not usable: use S3                                                                   |

The in-flight caps are a safety net for one process, so on a multi-instance deployment enforce the global limits at the
reverse proxy or load balancer in front of the API:

- **Connections per upstream:** cap what each instance can be handed, a little above its own caps (64 + 192 = 256 stream
  slots plus ordinary requests), for example nginx `server api1:4100 max_conns=300;` in an `upstream` block with
  `least_conn`. The bundled `deploy/nginx.conf` applies a total of 400 in-flight `/api` requests (`limit_conn api_total`);
  with N instances behind one nginx raise it to about 400 x N, or the proxy answers 429 first.
- **Connections per client IP:** the per-IP caps (16 PUT, 32 GET) are per process, so the effective allowance is N times
  that. Either route each client address to one instance (`hash $binary_remote_addr consistent;`, which keeps the caps exact
  per client) or add a per-IP `limit_conn` at the edge (about 48 in total, 16 + 32). Key it on the real client address: behind
  another proxy or a CDN nginx sees the proxy's address unless you restore the client's with the realip module and
  `set_real_ip_from` for exactly your proxies, otherwise every client shares one bucket.
- **The caps are only as good as `TRUST_PROXY`**, because they key on `req.ip`.
- Rate limiting, anonymous-quota and revocation state need no per-proxy work, they are in Redis and Postgres.

Not implemented, so not claimed: a cluster-wide in-flight counter, autoscaling guidance, or load testing of any multi-instance
setup. The bundled compose file runs one API instance.

## 5. Known limitations

- Images use floating tags (`node:22-alpine`, `nginx:1.31-alpine`, `postgres:16-alpine`, `redis:7-alpine`, `caddy:2-alpine`,
  `cgr.dev/chainguard/minio:latest`); pin digests for reproducible production builds. The npm install is lockfile-exact.
- The API image is large for a Node service (see the record below): the Prisma client ships engines for three targets, the
  Prisma CLI is installed next to the app to run migrations at start, and npm installs a few optional peers (TypeScript,
  Prisma) of `@prisma/client`. Trimming it was not attempted.
- A malicious server could serve modified JavaScript; the CSP and the absence of inline scripts narrow what such code can do,
  they do not make the client verifiable (DESIGN section 12 lists this as a stated limitation).
- No HA, backup automation, log shipping or alerting is provided. Postgres, Redis and nginx are single containers.
- The CI workflow (`.github/workflows/ci.yml`) has been validated with actionlint but has not run on GitHub.

## Verification record

Run on 2026-11-12 on a Windows 11 laptop with Docker Desktop (Linux containers), Node 22.12. Not run on a Linux server,
and not run with TLS or the `tls` / `minio` profiles booted (their configuration was rendered and the Caddyfile validated, see below).

| Check | Command (from the repo root, project name `cipherdrop-polish`, ports moved off the dev stack) | Result |
| ----- | ----- | ----- |
| Images build | `docker compose --env-file <file> -p cipherdrop-polish -f docker-compose.prod.yml build --no-cache` | Both images built, 81 s cold (base images already local, npm downloads included). `cipherdrop-api` 811 MB, `cipherdrop-web` 96.4 MB (`docker images`). |
| Boot on a fresh database | `up -d` with `WEB_PORT=18480`, `WEB_ORIGIN=http://127.0.0.1:18480`, random secrets | All four services healthy; the API log shows the 5 migrations applied, then `CipherDrop API listening`; the API runs as `uid=1000(node)` with a read-only root filesystem. Idle memory: api 55 MiB, postgres 39 MiB, web 8 MiB, redis 4 MiB (`docker stats`). |
| Smoke through nginx | `SMOKE_BASE_URL=http://127.0.0.1:18480 npm run smoke:prod -w @cipherdrop/web` | 7 of 7 passed in 5.4 s: headers, asset caching, 404 and 413 behaviour, `/readyz` and `/metrics` not exposed, no demo credentials in the bundle, and register, 5 MiB upload, reload and unlock, second-context download with identical SHA-256 and no CSP violation. |
| Headers | `curl -D - http://127.0.0.1:18480/` | All seven section 12 headers present once each, plus `Cache-Control: no-cache`; `/api/*` carries the API's helmet headers once and nginx's HSTS and `Permissions-Policy`. `/healthz` returns `200 ok`. |
| API readiness inside the stack | `docker compose exec api node -e "fetch('http://127.0.0.1:4100/readyz')..."` | `{"ok":true,"checks":{"db":"ok","redis":"ok","storage":"ok"}}` |
| Guard in the real image | `docker run --env-file .env.production.example -e NODE_ENV=production ... node dist/index.js` | The unfilled template is refused: `JWT_ACCESS_SECRET`, `PRELOGIN_SECRET` and `TOTP_ENC_KEY` listed as development/test secrets. |
| Optional profiles | `docker compose --profile tls --profile minio config`; `caddy validate` on `deploy/Caddyfile` | Rendered all six services; the Caddyfile is a valid configuration. Neither profile was booted. |
| Workflow | `docker run --rm -v <repo>:/repo -w /repo rhysd/actionlint:latest` | No findings. |
| Teardown | `down -v`, `docker rmi` of the two images | Stack, volumes and the two built images removed; the dev stack was not touched. |

Unit checks added with this change: `apps/web/deploy-checks/nginx-headers.test.ts` (5 tests) and
`apps/api/src/config/env.production-example.test.ts` (4 tests).
