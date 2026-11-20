# Deployment

This guide covers running CipherDrop in production: the single-host Docker Compose stack that ships in this
repository, and a split deployment (static SPA host, API on a container host, managed Postgres and Redis, S3-compatible
storage). It follows `docs/DESIGN.md` section 16. Everything marked **verified** was run, on the author's machine or in a
Linux cloud container, and is recorded in [Verification record](#verification-record); everything else is described, not
tested.

CipherDrop is zero-knowledge: the server only ever stores ciphertext, wrapped keys and hashes (DESIGN sections 7 and 12;
the threat model is [SECURITY.md](SECURITY.md)). Deployment therefore protects availability, metadata and the integrity of the
JavaScript that the browser runs; it cannot protect a file from a user who loses the link or the password.

## 1. Single-host stack (`docker-compose.prod.yml`)

```mermaid
flowchart LR
  B[Browser] -->|HTTPS| C["caddy (optional, profile tls)"]
  B -->|HTTP, loopback or your own TLS proxy| W
  C --> W["web: nginx<br/>SPA + security headers"]
  W -->|"/api/*: JSON max 1 MiB, buffered;<br/>chunks max 5 MiB, streamed"| A["api: Node 22, non-root<br/>prisma migrate deploy on start"]
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
# in .env.production: SITE_ADDRESS=drop.example.com  WEB_ORIGIN=https://drop.example.com  TRUST_PROXY=1
docker compose --env-file .env.production -f docker-compose.prod.yml --profile tls up -d --build
```

With your own TLS terminator or load balancer in front, point it at `WEB_BIND:WEB_PORT` and see the `TRUST_PROXY`
table below.

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
the per-IP in-flight caps and the IP prefix in audit events. nginx appends the client address it resolved to the header.
Behind the bundled Caddy that address is already the real client: nginx takes it from the `X-Forwarded-For` that Caddy
sets (the realip module, `set_real_ip_from 172.16.94.2`, Caddy's fixed address on the compose network `edge`), and Caddy
replaces whatever a client sent in that header. So:

| Path to the API                                                                          | `TRUST_PROXY`                                                  |
| ---------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| client, nginx (this stack, no TLS proxy)                                                 | `1`                                                            |
| client, Caddy (profile `tls`), nginx                                                     | `1`                                                            |
| client, your own proxy or load balancer, nginx, with the proxy in `set_real_ip_from`     | `1`                                                            |
| client, your own proxy or load balancer, nginx, with the proxy not in `set_real_ip_from` | `2`, and only if nothing but that proxy can reach nginx's port |

With `2`, any client that reaches nginx's port directly can choose its own address (measured below with Caddy), so
firewall that port so that only the proxy reaches it, or keep `WEB_BIND` on loopback with the proxy on the same host. A
load balancer on another host needs a non-loopback `WEB_BIND`, which makes the port reachable to others unless a
firewall stops them. `2` also makes nginx see every client as the proxy's address: its per-client connection cap
then counts them all as one client, so the whole site shares 64 in-flight `/api` requests.

So for your own proxy, prefer adding its address to `set_real_ip_from` in `deploy/nginx.conf`, rebuilding the web
image and keeping `1`. List exact addresses, never a private range, and only an address that stays the same:

- A proxy on another host, or in a container on `edge` with a fixed `ipv4_address` (as Caddy has): its own address.
- A proxy on this host that connects to `127.0.0.1:WEB_PORT` reaches nginx through Docker's userland proxy, from the
  gateway address of the compose project's `default` network, not of `edge` (checked on 2026-11-20 with Docker 29.10.0
  and a container on both networks, like `web`). Find it in nginx's access log (`docker compose ... logs web`, the first field of each
  request line) or with `docker network inspect cipherdrop-prod_default`. Docker picks that network's subnet when it
  creates the network, so the address can change after `down` and `up` (in the same check it went from `172.19.0.1` to
  `172.20.0.1` once another network held the old subnet). If it changes, the `set_real_ip_from` entry stops matching
  and every client silently shares one address again, in nginx's cap and in the API's rate limits. Trust it only after
  giving `default` a fixed subnet and gateway in `docker-compose.prod.yml`, as `edge` has (the subnet must not overlap
  another Docker network), and only while `WEB_BIND` is loopback: with a public `WEB_BIND`, other connections that go
  through the userland proxy (IPv6 ones, for example) come from the same address and could then set their own client
  address.

Too low puts every client behind the proxy's address (one shared rate-limit bucket); too high lets a client choose its own
address by sending the header. Verified on 2026-11-20 with the `tls` profile: with `TRUST_PROXY=2`, a client that reached
nginx's port directly, not through Caddy, could set its own address with `X-Forwarded-For`; with `1` it could not, and
clients through Caddy were still seen with their real addresses. Check it after deploying: two different clients must show
different IP prefixes in the audit log.

### nginx and the security headers

`deploy/nginx.conf` serves the SPA and sends the DESIGN section 12 headers (the strict CSP, `Referrer-Policy`,
`X-Content-Type-Options`, `Permissions-Policy`, COOP, CORP and HSTS) with `always`. The list mirrors
`apps/web/securityHeaders.ts`, the same constants `vite preview` serves during the Playwright e2e run, so the CSP the
browser tests exercise is the CSP production sends. `apps/web/deploy-checks/nginx-headers.test.ts` fails when the two
drift apart; it also checks the limits below against the API's own settings and the compose file.

Other behaviour worth knowing:

- `/api/*` is proxied to `api:4100`. API responses keep their own helmet headers; nginx adds HSTS (replacing the API's
  weaker one) and `Permissions-Policy`.
  - JSON requests: `client_max_body_size 1m` (the API's own JSON limit), bodies up to 128 KiB kept in memory (the
    largest body the SPA sends is a 64 KiB encrypted manifest plus its file list), `client_body_timeout 15s` between
    two reads, and responses never spooled to disk (`proxy_max_temp_file_size 0`). nginx reads a JSON body in full
    before the API sees it, so a JSON body of 1 to 5 MiB gets nginx's HTML 413, not the API's JSON one.
  - Chunk transfers (`PUT` and `GET /api/drops/:id/files/:fileId/chunks/:index`, a location nested in `/api/` that
    matches the API's chunk route): `client_max_body_size 5m` (a chunk PUT is 4 MiB + 16 bytes; the API checks the
    exact size), streamed both ways (`proxy_request_buffering off`, `proxy_buffering off`), and `client_body_timeout
    60s` as a backstop behind the API's 30 s idle window. Streaming lets the API's defences act on the real client:
    it answers an unverified uploader before the body arrives, and its minimum body rate and download idle timeout
    see the client's own pace. The location declares no headers of its own, so it sends exactly the `/api/` headers
    (the unit test checks this).
- `/assets/*` is cached for a year (content-hashed names), `index.html` and the unhashed root files are `no-cache`, unknown
  paths fall back to `index.html` (client-side routes such as `/d/<id>`), a missing `/assets/` file is a 404.
- `/healthz` is nginx's own liveness. `/readyz` and `/metrics` answer 404 from nginx; scrape the API's `/metrics` inside the
  Docker network (`api:4100`), see DESIGN section 15 for the metric list.
- `/SECURITY.md` serves the threat model (`docs/SECURITY.md`, copied into the build) as UTF-8 plain text; the
  `/how-it-works` page links to it. The web image's build stage copies that one file from `docs/`, which
  `.dockerignore` otherwise excludes.
- JSON is not gzip-compressed (BREACH), static types are.
- `limit_conn` allows at most 64 in-flight `/api` requests per client and 400 in total, and answers 429 beyond that
  (nginx's own HTML error page, without `Retry-After`). The per-client key is an IPv4 address or the /48 of an IPv6
  address, like the API's per-IP shares; 64 is the API's 16 chunk PUTs + 32 chunk GETs per client plus 16 for ordinary
  requests. See [Per-process caps](#4-per-process-caps-and-multi-instance-deployments).
- Slow clients: `client_header_timeout 10s`, `keepalive_timeout 15s` and `reset_timedout_connection on` at server level.
  Caddy closes its idle upstream connections after 10 s (`deploy/Caddyfile`), before nginx does.
- The client address: nginx trusts `X-Forwarded-For` only from Caddy's fixed address `172.16.94.2`
  (`set_real_ip_from`, `real_ip_header X-Forwarded-For`), so behind Caddy both nginx's per-client cap and the API see
  the real client.
- The container runs with a read-only root filesystem and sized tmpfs mounts: `/var/cache/nginx` 64 MiB (it holds only
  JSON bodies between 128 KiB and 1 MiB, which the SPA never sends; one client can fill at most 64 MiB with 64 requests),
  `/var/run` 1 MiB (the pid file) and `/tmp` 1 MiB (unused).
- The compose network `edge` (`172.16.94.0/28`) joins Caddy and nginx. Caddy has the fixed address `.2` and is on no other
  network; containers without a fixed address get theirs from `ip_range` `172.16.94.8/29`. The subnet must not overlap
  another Docker network on the host, or `up` fails. To move it (also for a second copy of the stack on one host), change
  the subnet, `ip_range`, gateway and Caddy's `ipv4_address` in `docker-compose.prod.yml` and the address in
  `set_real_ip_from` in `deploy/nginx.conf`; the unit test checks that Caddy's address is the same in both and lies in
  the subnet, outside `ip_range`. The network is created even without the `tls` profile.
- nginx resolves `api` through Docker's resolver (`127.0.0.11`) and caches the answer for 10 s (`valid=10s`), so
  recreating the API container leaves nginx pointing at a dead address for at most about 10 s.

### Operations

- **Logs:** pino JSON on stdout (`docker compose ... logs api`), json-file driver rotated at 3 x 10 MB. Request bodies,
  tokens, cookies and keys are redacted (DESIGN section 12), and Prisma errors are logged as safe fields only
  ([SECURITY.md](SECURITY.md) section 1).
- **Upgrades:** `git pull`, then `up -d --build`. The API container applies pending Prisma migrations before it starts
  serving (`migrate deploy` takes a Postgres advisory lock, so replicas starting together are safe). Migrations are
  forward-only: take a database backup before upgrading, because there is no automatic down-migration. From
  2026-11-20, a deployment with the `tls` profile must set `TRUST_PROXY=1` (it used to be told 2): `up -d --build`
  keeps the old `.env.production`, and with 2 a client that reaches nginx's port directly can choose its own address.
- **Shutdown:** `docker stop` sends SIGTERM; the API stops accepting connections, stops the cleanup job and disconnects
  Prisma and Redis (`stop_grace_period: 15s`; the process forces exit after 10 s). nginx streams chunk transfers, so a
  chunk request lasts as long as the client's own transfer, and the forced exit can cut chunk uploads and downloads in
  flight. The web client retries a chunk with backoff (0.5, 2 and 8 s for uploads; 0.5 and 2 s for downloads) and then
  shows a retryable error, so a restart that outlasts the backoff needs the user to retry.
- **Cleanup:** the expiry and exhausted-drop cleanup runs inside the API every `CLEANUP_INTERVAL_SEC` (default 60) under a
  Redis lock.
- **Backups:** nothing automatic. Back up (a) Postgres (`pg_dump` of database `cipherdrop`), (b) the blob store (volume
  `blobs`, or the bucket) at a point close to the dump, and (c) `.env.production`, in particular `TOTP_ENC_KEY`: without it
  every stored TOTP secret is unreadable. A dump without its blobs gives drops whose files are gone (downloads fail), a
  blob store without the dump is unreadable ciphertext.
- **Secrets rotation:** changing `JWT_ACCESS_SECRET` invalidates all access tokens (15-minute lifetime, clients refresh).
  Changing `PRELOGIN_SECRET` changes the fake salts of unknown emails (an observable difference to an attacker who recorded
  them earlier). Changing `TOTP_ENC_KEY` breaks enrolled TOTP secrets; there is no re-encryption tool and no admin
  reset of 2FA. Backup codes still work but each only once, and turning 2FA off asks for a code too: users with at least
  two unused codes (one to sign in, one to turn 2FA off), or one while still signed in, can turn 2FA off and enrol
  again; the others are locked out ([SECURITY.md](SECURITY.md) section 5).
- **Seed data is for development.** Do not run `db:seed` in production and do not set `SEED_*` or `VITE_DEMO_CREDENTIALS`;
  the web image is built from a context that excludes every `.env` file, and the smoke test checks that the bundle contains no
  demo credentials.

### Smoke test of a running stack

`apps/web/deploy-checks/prod-smoke.spec.ts` drives a running stack through nginx with a real browser and raw sockets. Use
the loopback address, because WebCrypto needs a secure context and the refresh cookie is `Secure`, and point it at
nginx's own port (`WEB_BIND:WEB_PORT`), not at Caddy:

```sh
# stack started with WEB_ORIGIN=http://127.0.0.1:8080
SMOKE_BASE_URL=http://127.0.0.1:8080 npm run smoke:prod -w @cipherdrop/web
```

Its 10 tests check every header nginx sends on `/`, on a deep link and on `/api`, the asset cache headers, the 404 for a
missing asset, the 413 for a 6 MiB chunk body, that `/readyz` and `/metrics` are not exposed, that the bundle has no demo
credentials, and one complete flow: register, upload 5 MiB (two chunks), reload and unlock (refresh cookie through the
proxy), and a second browser context decrypting identical bytes with no CSP violation or page error.

Three of them are slow-client checks over raw sockets, about 46 s together:

- one client holds at most the per-client cap of `/api` slots with stalled JSON bodies, its further requests (a chunk GET
  included) get nginx's 429, and nginx drops the stalled bodies after about 15 s;
- a chunk PUT dripped one byte at a time without a valid upload token gets the API's 401 at once, and the connection
  closes;
- a verified uploader that drips its chunk body is hung up by the API's minimum body rate after about 30 s (nginx then
  answers 502 or closes). This check assumes the default `CHUNK_UPLOAD_IDLE_TIMEOUT_SEC=30`.

They need nginx's own port because Caddy cannot relay an early answer to a request whose body is stalled: through
Caddy the per-client check sees no 429, although nginx sent one. The run leaves the account it registered in the
database and creates one anonymous drop, deleted again, which counts towards the 10 anonymous drops per hour of the
address. Do not run it against a production database you care about.

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
   limits of that proxy: it must pass request bodies of at least 4 MiB + 16 bytes (nginx here allows 5 MiB on the chunk
   routes, 1 MiB elsewhere), response bodies of the same size, and timeouts of at least 120 s. It should stream chunk
   bodies rather than buffer them, or the API's slow-client defences (minimum body rate, download idle timeout) act on
   the proxy instead of the client. I have not tested any specific static host or CDN.
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
- **Connections per client IP:** the API's per-IP caps (16 PUT, 32 GET) are per process, so the effective allowance is N
  times that. Either route each client address to one instance (`hash $binary_remote_addr consistent;`, which keeps the
  caps exact per client) or rely on a per-IP `limit_conn` at the edge. The bundled nginx has one: `limit_conn api_ip 64`,
  that is 16 + 32 for the API's shares plus 16 for ordinary requests, keyed by IPv4 address or IPv6 /48 like the API's
  `ipShareKey`; with N instances behind it use 48 x N + 16. It must see the real client address. For the bundled Caddy
  this is built in (`set_real_ip_from 172.16.94.2`). Behind another proxy or a CDN, add `set_real_ip_from` for exactly
  that proxy's addresses, never a private range: with Docker's userland proxy, clients that connect to the published port
  directly appear from a bridge gateway address, and their own `X-Forwarded-For` would then be believed. Without it,
  every client behind the proxy shares one bucket.
- **The caps are only as good as `TRUST_PROXY`**, because they key on `req.ip`.
- Rate limiting, anonymous-quota and revocation state need no per-proxy work, they are in Redis and Postgres.

Not implemented, so not claimed: a cluster-wide in-flight counter, autoscaling guidance, or load testing of any multi-instance
setup. The bundled compose file runs one API instance.

## 5. Known limitations

- Images use floating tags (`node:22-alpine`, `nginx:1.31-alpine`, `postgres:16-alpine`, `redis:7-alpine`, `caddy:2-alpine`,
  `cgr.dev/chainguard/minio:latest`); pin digests for reproducible production builds. Dependabot's `docker` entry
  (`.github/dependabot.yml`) cannot update the Dockerfiles while their `FROM` lines take the image from an `ARG` default
  (`ARG NODE_IMAGE=node:22-alpine`, `FROM ${NODE_IMAGE}`): it reads only `FROM` lines that name an image.
- The `npm ci` installs in both images are lockfile-exact. The `prisma-cli` stage of `apps/api/Dockerfile` is not: it
  installs `prisma` at the lockfile's version with `npm install` in an empty `/opt/prisma`, without a lockfile. Prisma
  pins its first two levels of dependencies exactly, but deeper ones (those of `c12`, for example) resolve from their
  semver ranges at build time, and `npm audit` of the repository does not cover that tree. That install also runs
  install scripts (the Prisma engines download), unlike the others, which use `--ignore-scripts`.
- The API image is large for a Node service (see the record below): the Prisma client ships engines for three targets, the
  Prisma CLI is installed next to the app to run migrations at start, and npm installs a few optional peers (TypeScript,
  Prisma) of `@prisma/client`. Trimming it was not attempted.
- A malicious server could serve modified JavaScript; the CSP and the absence of inline scripts narrow what such code can do,
  they do not make the client verifiable (DESIGN section 12 lists this as a stated limitation).
- No HA, backup automation, log shipping or alerting is provided. Postgres, Redis and nginx are single containers.
- CI (`.github/workflows/ci.yml`) and the audit workflow (`.github/workflows/audit.yml`) have been validated locally but
  have not run on GitHub. Every action is pinned to a commit SHA with a version comment, and Dependabot proposes
  updates; checkout uses `persist-credentials: false`; installs run `npm ci --ignore-scripts`, then
  `npm run db:generate -w @cipherdrop/api`, which generates the Prisma client and fetches the Prisma engines that the
  skipped install scripts would have fetched; a `workflows` job runs actionlint 1.7.12, pinned by image digest. The audit
  workflow runs the dependency audit gate ([SECURITY.md](SECURITY.md) section 7) on pushes to main, on pull requests,
  every Monday at 05:23 UTC and on demand. The CI service images (`postgres:16-alpine`, `redis:7-alpine`) and the MinIO
  image are still pinned by tag only.

## Verification record

### 2026-11-20: Linux, slow-client defences and the `tls` profile

Run on 2026-11-20 in a Linux cloud container: Docker 29.10.0, Compose v5.7.1, Node 22.23.5, no IPv6. Project name
`cipherdrop-nginxcheck`, `WEB_PORT=18580`, `WEB_ORIGIN=http://127.0.0.1:18580`, random secrets; the dev stack was not
touched. The container has no IPv6, so nginx refuses `listen [::]:80` (`socket() [::]:80 failed (97)`); the stack ran
with a compose override that mounted `deploy/nginx.conf` minus that one line. The `minio` profile was not booted (its
image registry was unreachable).

| Check | Command | Result |
| ----- | ----- | ----- |
| nginx configuration | `nginx -t` in `nginx:1.27-alpine` and `nginx:1.31-alpine` (1.31.9) | Passes on both once the `[::]:80` listen is removed. |
| Caddyfile | `caddy validate` and `caddy adapt` (Caddy 2.11.9, `SITE_ADDRESS=drop.example.com`) | Valid; upstream keep-alive idle timeout 10 s. |
| Compose file | `docker compose --env-file <file> -f docker-compose.prod.yml --profile tls config` | `caddy` only on `edge` at `172.16.94.2`; `web` on `default` and `edge`; the `edge` subnet, `ip_range` and gateway; the web tmpfs sizes. |
| Images build | `docker compose ... build` | The committed `apps/api/Dockerfile` did not build: `apk add --no-cache openssl` could not reach the Alpine mirrors, which the container's egress policy blocks. The web image built from `apps/web/Dockerfile` (the build stage's `NODE_IMAGE` given the container's proxy CA): 96.4 MB, 22 s. The API ran from a stand-in, a copy of `apps/api/Dockerfile` without its three `apk add openssl` lines (`node:22-alpine` already has libssl3 and libcrypto3), built from the working tree: 810 MB, 39 s. |
| Boot on a fresh database | `up -d --no-build` | All four services healthy; the API log shows the 6 migrations applied (the newest is `20261114000000_refresh_token_rotated_from`); the API runs as uid 1000. Idle memory: api 48 MiB, postgres 42 MiB, web 5.7 MiB, redis 3.9 MiB. `df` in `web` shows the tmpfs mounts at 64M, 1M and 1M; `web` got `172.16.94.8` from `ip_range`. |
| Headers on `/api` | `curl -D -` of `/api/does-not-exist` (404) and of a chunk GET without a token (401) | The same response header names on both; HSTS once, `Permissions-Policy` on both. |
| Smoke through nginx | `SMOKE_BASE_URL=http://127.0.0.1:18580 npm run smoke:prod -w @cipherdrop/web -- --trace off` | 10 of 10 passed in 50.7 s (and 52.1 s in the run before). A first run had 9 of 10: the per-client check counted a slot still held by the previous test's 413, and the check was rewritten. The nginx log shows the 64 stalled JSON POSTs answered 408 after 15 s and the 2 extra ones 429 (`limiting connections by zone "api_ip"`), the chunk GET 429 while they were held, the API's 401 to the token-less dripped PUT after 7 ms, and nginx's 502 after the API aborted the verified dripped PUT at 30,008 ms. Against the previous `deploy/nginx.conf` all three slow-client checks fail. |
| `tls` profile | `--profile tls up` with `SITE_ADDRESS=:80` (plain HTTP), Caddy's port 80 published on `127.0.0.1:18581` and on a second host address, `192.0.2.2:18582`; requests carry a forged `X-Forwarded-For: 203.0.113.7` | The profile's first boot. Caddy got `172.16.94.2`. Through Caddy from `192.0.2.2`: nginx logged `192.0.2.2` and the API the IP prefix `192.0.2.0/24`. Through Caddy on loopback: `172.16.94.1` (Docker's userland proxy). Direct to nginx: the bridge gateway, not trusted. From a container at `172.16.94.3` on `edge`: not trusted. The forged value was never used. |
| `TRUST_PROXY=2` with the `tls` profile | the same requests | Through Caddy still correct (`192.0.2.0/24`), but a client that reached nginx directly set its own address (the API logged `203.0.113.0/24`). Hence `TRUST_PROXY=1` for both profiles. |
| Per-client cap through Caddy | 66 stalled requests from one client, then probes | The holding client got 429, a second client through Caddy and a direct client got 404 (served). With `set_real_ip_from` removed, the second client through Caddy also got 429: every client then shares Caddy's address. |
| Smoke through Caddy | `SMOKE_BASE_URL=http://127.0.0.1:18581` (and `WEB_ORIGIN` to match) | 9 of 10, twice: through Caddy the per-client check sees no 429 ([Smoke test](#smoke-test-of-a-running-stack)). |
| Configuration guard | `TEST_SCHEMA=lane_nginxcheck TEST_REDIS_DB=13 npx vitest run src/config/env.production-example.test.ts src/config/env.test.ts` (in `apps/api`) | 13 passed. The guard was not re-run inside the stand-in image. |
| Workflows | `docker run --rm -v <repo>:/repo -w /repo rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667`; `zizmor --offline .github/` (1.32.0) | No findings from either; zizmor's pedantic mode flags only the tag-pinned `postgres` and `redis` service images. |
| Teardown | `--profile tls down -v --remove-orphans`, `docker rmi` of the built images | No containers, networks, volumes or images of the run left. |

Unit checks at this date: `apps/web/deploy-checks/nginx-headers.test.ts` has 15 tests (besides `deploy/nginx.conf` it
reads the API's `env.ts`, `app.ts` and drop `routes.ts`, `docker-compose.prod.yml` and `deploy/Caddyfile`, so the limits,
the chunk route and Caddy's address cannot drift apart), and `apps/api/src/config/env.production-example.test.ts` has 4.

### 2026-11-12: first run

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

The sixth migration, `20261114000000_refresh_token_rotated_from`, was added on 2026-11-14, after this run; the
2026-11-20 run above applied all six.
