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
  W -->|"/api/*: JSON max 1 MiB, buffered;<br/>chunks max 5 MiB, streamed"| A["api: Node 22, non-root<br/>connects as cipherdrop_app"]
  subgraph backend ["network backend (internal)"]
    M["migrate (one-shot)<br/>migrations as the owner,<br/>then the runtime role"]
    P[(postgres 16)]
    R[(redis 7, AOF, password)]
    S[("minio (profile minio)")]
  end
  M --> P
  A --> P
  A --> R
  A --> S
  A --> V[("blobs volume<br/>or an external S3 / R2")]
```

| Service    | Image                                         | Notes                                                                                                                                                                                                                                                                                                  |
| ---------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `postgres` | `postgres:16-alpine`                          | Volume `postgres-data`. Network `backend` only. Not published.                                                                                                                                                                                                                                       |
| `redis`    | `redis:7-alpine`                              | AOF persistence on volume `redis-data`: it holds the revoked-session denylist, so a restart must not forget it. Password-protected (`requirepass`, from `REDIS_PASSWORD`), `maxmemory 128mb` with `noeviction`. Network `backend` only. Not published.                                                 |
| `migrate`  | the API image, command `migrate`              | One-shot: applies pending migrations as the database owner (`POSTGRES_USER` `cipherdrop`, which the postgres image creates as a superuser), then creates or updates the runtime role `cipherdrop_app` with rights on rows only, and exits. Network `backend`. No healthcheck, `restart: 'no'`.             |
| `api`      | built from `apps/api/Dockerfile`              | Multi-stage (build, Prisma CLI from a lockfile, runtime). Runs as uid 1000, read-only root filesystem, all capabilities dropped. Starts after `migrate` has completed and connects as `cipherdrop_app`, with `MIGRATE_ON_START=false`. Networks `default` and `backend`.                             |
| `web`      | built from `apps/web/Dockerfile` (nginx 1.31) | The built SPA, `deploy/nginx.conf`, healthcheck on `/healthz`. The only service that publishes a port (`WEB_BIND:WEB_PORT`, default `127.0.0.1:8080`). Networks `default` and `edge`.                                                                                                                  |
| `minio`    | `cgr.dev/chainguard/minio` (profile `minio`)  | Optional S3-compatible storage inside the stack. `minio/minio` left Docker Hub, hence the Chainguard image (same choice as the dev compose file). Network `backend`.                                                                                                                                     |
| `caddy`    | `caddy:2-alpine` (profile `tls`)              | Optional automatic HTTPS on 80/443 in front of nginx. Needs a public DNS name pointing at the host. Network `edge` only, at a fixed address.                                                                                                                                                           |

Every third-party image is pinned by tag and index digest except MinIO's ([section 5](#5-known-limitations)). Every
long-running service has a healthcheck and `restart: unless-stopped`, and every service has a `mem_limit` and a
`pids_limit` ([Resource limits](#resource-limits)). `web` waits for `api` to be healthy (`/readyz`: database, Redis
and blob storage), and `api` waits for Postgres and Redis to be healthy and for `migrate` to have completed
successfully (`service_completed_successfully`), so a failed migration or a refused password leaves the API stopped.

The network `backend` is internal: it has no route out, and only `api` and `migrate` join Postgres, Redis and MinIO on
it, so nginx can neither resolve nor reach them. `default` joins nginx to the API and is the API's way out to an
external S3. `edge` joins Caddy to nginx.

### Install

Requirements: Docker Engine with Compose v2, a host that can build the images (about 2 GB of free disk for the build
cache, images and layers), and for real use a DNS name and TLS.

```sh
cp .env.production.example .env.production       # .env.production is gitignored

# generate the secrets (each one separately) and paste them into .env.production
openssl rand -hex 24      # POSTGRES_PASSWORD      (the owner role; URL-safe: compose embeds it in a DATABASE_URL)
openssl rand -hex 24      # POSTGRES_APP_PASSWORD  (a different value: the API's own role, cipherdrop_app)
openssl rand -hex 32      # REDIS_PASSWORD
openssl rand -hex 32      # JWT_ACCESS_SECRET
openssl rand -hex 32      # PRELOGIN_SECRET
openssl rand -base64 32   # TOTP_ENC_KEY

# also set WEB_ORIGIN (the exact public origin) and TRUST_PROXY, see below,
# and on a public instance SECURITY_TXT_CONTACT and GLOBAL_STORAGE_CAP_BYTES
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
docker compose --env-file .env.production -f docker-compose.prod.yml ps
```

`--env-file` supplies the values compose interpolates (`POSTGRES_PASSWORD`, `POSTGRES_APP_PASSWORD`, `REDIS_PASSWORD`,
`WEB_PORT`, ...), and the same file is passed to the `api` container as its environment (`env_file`, overridable with
`ENV_FILE=...`). Compose then overrides what the topology fixes: `NODE_ENV=production`, `DATABASE_URL` (the runtime
role `cipherdrop_app` with `POSTGRES_APP_PASSWORD`), `REDIS_URL` (`redis://:REDIS_PASSWORD@redis:6379/0`),
`MIGRATE_ON_START=false`, `POSTGRES_PASSWORD=''` (otherwise `env_file` would hand the owner's password to the API),
`STORAGE_DIR` and `API_PORT`. Compose refuses to start when `POSTGRES_PASSWORD`, `POSTGRES_APP_PASSWORD` or
`REDIS_PASSWORD` is empty, with a message naming the variable. `SECURITY_TXT_CONTACT` and `SECURITY_TXT_POLICY` are
build arguments of the web image ([nginx and the security headers](#nginx-and-the-security-headers)).

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
- `API_DOCS_UI` is not `true`: Swagger UI never runs on the SPA's origin, which holds the keys. nginx also answers
  its own 404 for `/api/docs` in any letter case, and the web image sends the Trusted Types report-only header;
- `JWT_ACCESS_SECRET` and `PRELOGIN_SECRET` have at least 32 characters, `TOTP_ENC_KEY` decodes to exactly 32 bytes,
  and none of them contains `dev-only`, `test-only` or `change-me`;
- the password inside `DATABASE_URL` and inside `REDIS_URL` contains none of those markers either.

Two cross-field checks apply in every environment, not only in production: `SESSION_MAX_LIFETIME_DAYS` must be at
least `REFRESH_TOKEN_TTL_DAYS`, and `ARGON2_MAX_CONCURRENT` must stay below `UV_THREADPOOL_SIZE` (the API image sets
`UV_THREADPOOL_SIZE=8`; raise both together on a larger host). A third: `ANON_BYTES_PER_CLIENT` must be 0 or at least
`ANON_MAX_DROP_BYTES` rounded up to a whole MiB; the error names both variables, never their values.

Which component refuses which placeholder: the API's guard checks its three secrets and the passwords in its own
`DATABASE_URL` (`POSTGRES_APP_PASSWORD` in this stack) and `REDIS_URL` (`REDIS_PASSWORD`). It never sees
`POSTGRES_PASSWORD`. The one-shot `migrate` refuses a `dev-only`, `test-only` or `change-me` password in the owner's
`DATABASE_URL` (`POSTGRES_PASSWORD`) and in `DB_RUNTIME_PASSWORD` (`POSTGRES_APP_PASSWORD`, which must also be 24 to
128 URL-safe characters). It exits 1 after the migrations, and the API, which waits for it, does not start. The
error names the variables, never the value.

`.env.production.example` is written to fail these checks until it is filled in: its three secrets and its three
passwords (`POSTGRES_PASSWORD`, `POSTGRES_APP_PASSWORD`, `REDIS_PASSWORD`) are `change-me` placeholders.
`apps/api/src/config/env.production-example.test.ts` checks both directions: the file as shipped is refused, and the
same file with real random values is accepted. It reads the `api` and the `migrate` service's `environment:` from
`docker-compose.prod.yml` and interpolates it as compose does, so it checks what each container really receives.

### Hosting-abuse controls (public instances)

The server cannot scan ciphertext, so what an open instance offers is free, anonymous, encrypted file hosting
([SECURITY.md](SECURITY.md) section 2.7). These variables bound it; the defaults are on in every environment:

| Variable                                                  | Default                            | Effect                                                                                                                                                                                                                                                      |
| --------------------------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ALLOW_ANONYMOUS_UPLOADS`                                 | `true`                             | `false`: an anonymous `POST /drops` answers 403 `FEATURE_DISABLED`. Drops created earlier still finish their upload and stay downloadable.                                                                                                                  |
| `ALLOW_REGISTRATION`                                      | `true`                             | `false`: `POST /auth/register` answers 403 `FEATURE_DISABLED`, and the SPA hides its sign-up links. Existing accounts still sign in.                                                                                                                         |
| `ANON_TOTAL_PENDING_BYTES`                                | `10737418240` (10 GiB)             | Ceiling on the bytes of all anonymous drops whose blobs are not purged; 0 = no ceiling. Beyond it: 413 `QUOTA_EXCEEDED`.                                                                                                                                    |
| `ANON_BYTES_PER_CLIENT` with `ANON_BYTES_WINDOW_HOURS`    | `1073741824` (1 GiB) per `24` h    | Rolling budget per anonymous client (IPv4 address or IPv6 /48), counted in whole MiB per hour; 0 = off. Must be at least `ANON_MAX_DROP_BYTES` rounded up to a MiB. The window is 1 to 720 hours. Beyond it: 429 `UPLOAD_BUDGET_EXCEEDED` with `Retry-After`. |
| `NEW_ACCOUNT_QUOTA_BYTES` with `NEW_ACCOUNT_PROBATION_DAYS` | `268435456` (256 MiB) for `7` days | The quota of a new account during its first days (0 to 365; 0 = no probation). The end date is fixed at registration; an admin's quota edit ends it at once.                                                                                                |
| `GLOBAL_STORAGE_CAP_BYTES`                                | `0` (off)                          | Ceiling on the bytes of all drops, anonymous and signed in, whose blobs are not purged. Beyond it: 507 `STORAGE_FULL`.                                                                                                                                       |
| `STORAGE_MIN_FREE_BYTES`                                  | `1073741824` (1 GiB)               | Local storage only (skipped for S3): a new drop is refused with 507 `STORAGE_FULL` when the blob volume's free space, minus the declared bytes of uploads active in the last 10 minutes and of the new drop, would fall below it; 0 = off.                     |

On a public instance:

- **Set `GLOBAL_STORAGE_CAP_BYTES`** below the space blobs may use (the disk, or the bucket budget). It is the only
  bound on the account path: one address can register 120 accounts a day, each with 5 GiB once its probation is
  over.
- Consider `ALLOW_REGISTRATION=false` and/or `ALLOW_ANONYMOUS_UPLOADS=false` for a demo.
- Alert on `drops_refused_total{reason}` (`client_budget`, `anon_pool`, `global_cap`, `disk_floor`) and
  `storage_free_bytes`. Clients get the same 507 for the cap and the floor, so only the metric says which fired.

The SPA reads the two switches from `GET /api/config` when it loads, and explains a closed door or a full server on
the send and register pages. Cleanup also deletes an upload that has stored no chunk one hour after its create, so
a pure reservation frees the quota, the pool and the cap it held.

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
  and a container on both networks, like `web`). Read it from `docker network inspect cipherdrop-prod_default` (the IPAM
  `Gateway`); nginx's access log no longer helps, because it records only the /24 prefix of each client and puts the
  time first. Docker picks that network's subnet when it
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

`deploy/nginx.conf` serves the SPA and sends the DESIGN section 12 headers (the strict CSP, the Trusted Types
report-only policy, `Referrer-Policy`, `X-Content-Type-Options`, `Permissions-Policy`, COOP, CORP and HSTS) with
`always`. The list mirrors
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
  paths fall back to `index.html` (client-side routes such as `/d/<id>`) except under `/.well-known/`, a missing
  `/assets/` file is a 404.
- `/healthz` is nginx's own liveness. `/readyz` and `/metrics` answer 404 from nginx; scrape the API's `/metrics` inside the
  Docker network (`api:4100`), see DESIGN section 15 for the metric list.
- `/api/docs` and everything under it answer nginx's own 404, in any letter case (`location ~* ^/api/docs(?:/|$)`),
  because Express mounts are case-insensitive. This is the second safeguard behind the API's refusal of
  `API_DOCS_UI=true` in production; `/api/openapi.json` is proxied as usual.
- `/.well-known/security.txt` (RFC 9116) is generated by the web build from `SECURITY_TXT_CONTACT` (one or more
  `mailto:`, `tel:` or `https://` URIs, comma-separated, in order of preference) and `SECURITY_TXT_POLICY` (an
  `https://` URL), which `docker-compose.prod.yml` passes as build arguments from `.env.production`. Unset, they
  point at this repository's GitHub private vulnerability reporting, and the file says in a comment that reports
  about the code go to the project and reports about the deployment to its operator through the site. Values must
  be printable ASCII without spaces; an invalid one fails the build. `Expires` is the build date plus 180 days, and
  an unchanged `up -d --build` reuses Docker's cached build step and keeps the old date. Renew it at least every 180
  days (the smoke test fails once fewer than 30 are left):

  ```sh
  docker compose --env-file .env.production -f docker-compose.prod.yml build --no-cache web
  docker compose --env-file .env.production -f docker-compose.prod.yml up -d web
  ```

  After changing `SECURITY_TXT_CONTACT` or `SECURITY_TXT_POLICY`, `up -d --build web` is enough, because a changed
  build argument reruns the step. Every other `/.well-known/` path is a 404, never the SPA's `index.html`.
- Access log: the `privacy` format, set at server level so that it replaces the image's `main` format. It records
  the ISO time, the client's prefix (IPv4 /24, IPv6 /48, the same text as the API's audit prefix, computed by a
  `map` on the realip-restored `$remote_addr`), the method, the path as requested cut at the first `?`, `#` or
  `%23`, the status, the bytes sent and the duration. So no query string and no fragment is logged: a browser never
  sends a share link's fragment (its key), but a client that requests the link verbatim does, as `#` straight to
  nginx and as `%23` through Caddy, which re-encodes a `#` in the path. The API's request log cuts its path the same
  way. There is no user agent, referer or `X-Forwarded-For`, and `/assets/` and `/healthz` are not logged. nginx's
  error log keeps its fixed format, which includes the full client address and request line of the request-level
  errors it records (connection-cap and rate-limit 429s, 413s, upstream failures).
- `limit_req` allows 2 requests per second per client (burst 40, answered at once) on the credential routes only:
  `prelogin`, `login`, `login/mfa`, `register`, `recovery/start` and `recovery/complete`, matched case-insensitively
  with an optional trailing slash like the API's router, and keyed like the per-client connection cap. Beyond it
  nginx answers 429 (its own HTML page, without `Retry-After`). Every other request maps to an empty key and is not
  counted, so refreshes and signed-in routes are unaffected. Both numbers stay above the API's own budgets, so an
  honest client meets the API's JSON 429 first; `nginx-headers.test.ts` checks that against
  `apps/api/src/lib/rateLimit.ts`.
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
  recreating the API container leaves nginx pointing at a dead address for at most about 10 s. It is not on the
  `backend` network, so it can neither resolve nor reach Postgres or Redis.

### Operations

- **Logs:** pino JSON on stdout (`docker compose ... logs api`); nginx's access log in the `privacy` format, IP
  prefixes only (`... logs web`). Request bodies, tokens, cookies and keys are redacted (DESIGN section 12), and
  Prisma errors are logged as safe fields only ([SECURITY.md](SECURITY.md) section 1). Retention: the json-file
  driver keeps 3 x 10 MB per container, which is bounded by size, not time. A privacy-format nginx line took about
  150 bytes on disk (153 measured, Docker's JSON wrapper included), so about 200,000 requests: days on a busy
  instance, months on a quiet one. For a time limit, use the `journald` logging driver with `MaxRetentionSec=` in the
  host's `journald.conf` (it applies host-wide), or a log shipper that expires entries. Caddy writes no access log by
  default.
- **Upgrades:** `git pull`, then `up -d --build`. The one-shot `migrate` service applies pending Prisma migrations as
  the owner (`migrate deploy` takes a Postgres advisory lock) and updates `cipherdrop_app`; then the API starts as
  that role. Migrations are forward-only: take a database backup before upgrading, because there is no automatic
  down-migration. Read [Upgrading](#6-upgrading) before upgrading an install from before 2026-11-21: some changes
  need action first.
- **Admins:** production is not seeded. To create the first admin, register normally, turn on two-step verification
  in **Settings**, **Security**, then run:

  ```sh
  docker compose --env-file .env.production -f docker-compose.prod.yml exec postgres \
    psql -U cipherdrop -d cipherdrop -c \
    "UPDATE \"User\" SET role='ADMIN' WHERE email='you@example.com' AND \"totpEnabledAt\" IS NOT NULL"
  ```

  Check that psql prints `UPDATE 1`; `UPDATE 0` means the email is wrong or 2FA is not on yet. The account gets the
  admin role in a fresh token at its next refresh (a reload). Further admins are promoted from the console, which
  refuses accounts without 2FA. Admins cannot turn 2FA off: to replace an authenticator, another admin changes their
  role to User first (a sole admin uses SQL), they re-enrol, and are promoted again. List admins without 2FA with
  `SELECT email FROM "User" WHERE role='ADMIN' AND "totpEnabledAt" IS NULL`.
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
  blob store without the dump is unreadable ciphertext. Backups keep deleted data: a `pg_dump`, a bucket or blob
  backup and a filesystem snapshot of the `blobs` volume keep the rows and ciphertext of drops deleted, burned or
  expired after they were taken. Restoring one brings those back, and a key that leaks later decrypts them, so keep
  backup retention short and stated. Bucket lifecycle rules such as noncurrent-version expiry only delay deletion;
  they are no substitute for an unversioned bucket ([section 2](#2-s3-compatible-storage)).
- **security.txt:** every few months, rebuild the web image without the cache to renew its `Expires`
  ([nginx and the security headers](#nginx-and-the-security-headers)).
- **Secrets rotation:** `POSTGRES_APP_PASSWORD`: change it and run `up -d` (`migrate` sets the new password, and the
  API is recreated). `REDIS_PASSWORD`: change it and run `up -d` (Redis and the API are recreated; the denylist
  survives in the AOF). `POSTGRES_PASSWORD` takes effect only when a new volume is initialised, so change it with
  `ALTER ROLE` inside Postgres first, then in the file.
  Changing `JWT_ACCESS_SECRET` invalidates all access tokens (15-minute lifetime, clients refresh).
  Changing `PRELOGIN_SECRET` changes the fake salts of unknown emails (an observable difference to an attacker who recorded
  them earlier). Changing `TOTP_ENC_KEY` breaks enrolled TOTP secrets; there is no re-encryption tool and no admin
  reset of 2FA. Backup codes still work but each only once, and turning 2FA off asks for a code too: users with at least
  two unused codes (one to sign in, one to turn 2FA off), or one while still signed in, can turn 2FA off and enrol
  again; the others are locked out ([SECURITY.md](SECURITY.md) section 5).
- **Seed data is for development.** Do not run `db:seed` in production and do not set `SEED_*` or `VITE_DEMO_CREDENTIALS`;
  the web image is built from a context that excludes every `.env` file, and the smoke test checks that the bundle contains no
  demo credentials.

### Resource limits

Every service has a `mem_limit` and a `pids_limit` (`docker-compose.prod.yml` gives the reasoning for each). A
process past its memory limit is killed by the kernel and restarted by Docker, instead of pushing the whole host into
swap or its OOM killer; a pids limit stops a runaway fork or thread loop. The peaks are from the production smoke
test on a 4-CPU host (2026-11-21, before `UV_THREADPOOL_SIZE=8` added 4 threads to the API):

| Service    | `mem_limit` / `pids_limit` | Sized for                                                                                                                                                                           | Peak measured           |
| ---------- | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `api`      | 1g / 256                   | 64 chunk bodies of 4 MiB in flight outside the heap, an Argon2id hash of 19 MiB per libuv thread, the Prisma query engine and the heap; about 13 tasks plus one per host CPU, plus 7 while a healthcheck runs | 44 MiB / 17 tasks       |
| `postgres` | 512m / 200                 | `shared_buffers` (128 MB) plus a few MB per connection; one process per connection, `max_connections` 100 plus about 15 background workers                                         | 43 MiB / 8              |
| `redis`    | 256m / 32                  | `maxmemory 128mb` plus room for the copy-on-write of the AOF rewrite's fork                                                                                                          | 5 MiB / 6               |
| `web`      | 256m / 64                  | 66 MiB of tmpfs counted in the cgroup, about 80 MiB of buffers for 400 connections, one worker per CPU                                                                                | 7 MiB / 6               |
| `migrate`  | 512m / 64                  | Node and the Prisma CLI, then its schema engine                                                                                                                                      | 52 MiB / 8 (sampled)    |
| `minio`    | 1g / 256                   | a single-drive server for one API                                                                                                                                                    | 249 MiB / 57, a Docker Hub stand-in after the S3 suite |
| `caddy`    | 256m / 64                  | certificates, TLS state and a goroutine per connection                                                                                                                              | not measured            |

Node sizes its heap to about half of the limit by itself (a 524 MiB heap limit at `mem_limit: 1g`), so no
`NODE_OPTIONS` cap is set. Raise the api's `mem_limit` by about 4 MiB per extra `MAX_CONCURRENT_CHUNK_UPLOADS`, its
`pids_limit` on hosts with more than about 200 CPUs, and web's `pids_limit` on hosts with more than about 60 CPUs (one
nginx worker per CPU; nginx logs the failed fork and starts fewer workers). No CPU limits (`cpus`) are set: CPU
contention does not crash a host the way memory exhaustion does, and a CPU quota on a small host would slow Argon2id
logins.

### Smoke test of a running stack

`apps/web/deploy-checks/prod-smoke.spec.ts` drives a running stack through nginx with a real browser and raw sockets. Use
the loopback address, because WebCrypto needs a secure context and the refresh cookie is `Secure`, and point it at
nginx's own port (`WEB_BIND:WEB_PORT`), not at Caddy:

```sh
# stack started with WEB_ORIGIN=http://127.0.0.1:8080
SMOKE_BASE_URL=http://127.0.0.1:8080 SMOKE_WEB_CONTAINER=cipherdrop-prod-web-1 npm run smoke:prod -w @cipherdrop/web
```

CI runs this smoke test on every push and pull request in its `prod-stack` job, against the stack built from the
committed Dockerfiles and booted with generated secrets.

Its 14 tests check every header nginx sends on `/`, on a deep link and on `/api`, the asset cache headers, the 404 for a
missing asset, the 413 for a 6 MiB chunk body, that `/readyz` and `/metrics` are not exposed, that the bundle has no demo
credentials, and one complete flow: register, upload 5 MiB (two chunks), reload and unlock (refresh cookie through the
proxy), and a second browser context decrypting identical bytes with no CSP violation or page error. Further checks:

- `/.well-known/security.txt`: 200, `text/plain; charset=utf-8`, every header, a `Contact` and an `Expires` within a
  year that is at least 30 days away (run against a live instance, this is the renewal reminder); other
  `/.well-known/` paths are 404s, not the SPA;
- Swagger UI: `/api/docs` in several letter cases and with trailing slashes gets nginx's 404, while
  `/api/openapi.json` is served;
- the access log, only with `SMOKE_WEB_CONTAINER` set to the web container's name and the `docker` CLI at hand
  (otherwise it is skipped): it reads `docker logs` and asserts the format, no query string, no user agent or
  referer and no full IPv4 address. It also sends a share link verbatim, as `/d/<id>#<marker>` and
  `/d/<id>%23<marker>`, over a raw socket (TLS when `SMOKE_BASE_URL` is `https`), and asserts that the marker is not
  in nginx's log;
- the credential-route rate limit: 60 concurrent prelogins get nginx's own 429 beyond the burst, while other `/api`
  routes are unaffected. It runs last, because it spends the client's credential-route budget (which refills at 2
  per second).

Three of them are slow-client checks over raw sockets, about 46 s together:

- one client holds at most the per-client cap of `/api` slots with stalled JSON bodies, its further requests (a chunk GET
  included) get nginx's 429, and nginx drops the stalled bodies after about 15 s;
- a chunk PUT dripped one byte at a time without a valid upload token gets the API's 401 at once, and the connection
  closes;
- a verified uploader that drips its chunk body is hung up by the API's minimum body rate after about 30 s (nginx then
  answers 502 or closes). This check assumes the default `CHUNK_UPLOAD_IDLE_TIMEOUT_SEC=30`.

They need nginx's own port because Caddy cannot relay an early answer to a request whose body is stalled: through
Caddy the per-client check sees no 429, although nginx sent one. The run leaves the account it registered in the
database and creates one anonymous drop, deleted again, which counts towards the 10 anonymous drops per hour and
the anonymous byte budget of the address; its last test spends the address's credential-route budget at nginx. Do
not run it against a production database you care about.

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

Create the bucket yourself and give the key read, write and delete rights on it, plus
`s3:GetBucketObjectLockConfiguration` and, unless `S3_DELETE_ALL_VERSIONS=true`, `s3:GetBucketVersioning` (below);
the driver only creates the bucket when it is missing. The bucket must not be publicly readable: the API streams
chunks to authorised clients, nothing links to the store directly. With `--profile minio` the stack runs MinIO itself
(`S3_ENDPOINT=http://minio:9000`, `S3_FORCE_PATH_STYLE=true`, the access key and secret become MinIO's root
credentials). The S3 driver is covered by the contract tests against MinIO (`npm run test:s3`); R2 and AWS S3 were not
tested.

**Versioning and Object Lock.** On a versioned bucket, a delete without a `VersionId` only adds a delete marker and
keeps every ciphertext version, so expiry, burn after reading and Delete now would not delete anything. The API
therefore refuses to start on:

- a bucket with Object Lock, always;
- a bucket with versioning `Enabled` or `Suspended`, unless `S3_DELETE_ALL_VERSIONS=true`;
- versioning with MFA Delete, always;
- a bucket whose settings it cannot read (fail closed).

With `S3_DELETE_ALL_VERSIONS=true`, every delete lists the versions and delete markers (`s3:ListBucketVersions`) and
deletes each by its `VersionId` (`s3:DeleteObjectVersion`), in batches of 1,000, and repeats until a pass finds
nothing (at most 5 passes), to catch a chunk PUT racing the purge. It also works on an unversioned bucket. A server
that answers `NotImplemented` (meant for R2, untested) counts as having neither feature. Prefer an unversioned
bucket. `npm run test:s3` also covers versioned and Object Lock buckets (`<S3_TEST_BUCKET>-versioned` and `-locked`,
created by the tests); on 2026-11-21 it passed 53 tests against a MinIO stand-in from Docker Hub
(`bitnamilegacy/minio`), not the Chainguard image CI uses.

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
   offers it). The database needs `max_connections` for instances times Prisma's pool (default `num_cpus * 2 + 1` per
   instance). Two ways to run the migrations:
   - Option A, the image's default: one role with DDL rights, and the API image runs `prisma migrate deploy` on every
     start (`MIGRATE_ON_START` defaults to `true`).
   - Option B, recommended: run the API image with the command `migrate` as a release step, with the owner's
     `DATABASE_URL` plus `DB_RUNTIME_ROLE` and `DB_RUNTIME_PASSWORD` (24 to 128 URL-safe characters). It applies the
     migrations, then creates or updates that role with rights on rows only. Then start the API with
     `MIGRATE_ON_START=false` and the runtime role's `DATABASE_URL`. The owner needs `CREATEROLE` and must own the
     tables. A non-superuser owner cannot remove `SUPERUSER`, `REPLICATION` or `BYPASSRLS`, so provisioning refuses a
     pre-existing role that has them, and it always refuses a role that is a member of another role.
6. Redis: `REDIS_URL=rediss://:password@host:port/0`. Use a password: the API refuses a placeholder one in production.
   Use `noeviction` and persistence: it holds rate-limit counters, the revoked-session denylist, the anonymous byte
   budget and the cleanup lock, and evicting the denylist would let a revoked access token live until it expires
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
| HTTP rate limits (global 600 per minute per IP, auth including `loginIp`, drops, chunk limiters)               | **shared** (Redis store)      | Unaffected                                                                           |
| `ARGON2_MAX_CONCURRENT` (2) / `ARGON2_MAX_QUEUE` (32): server-side Argon2id hashes running and waiting          | **per process** (in memory)   | N x 2 hashes run at once                                                             |
| `ANON_BYTES_PER_CLIENT` budget                                                                                 | **shared** (a Redis hash per client, one Lua script) | Unaffected                                                    |
| `ANON_TOTAL_PENDING_BYTES`, `GLOBAL_STORAGE_CAP_BYTES`                                                         | **shared** (Postgres advisory lock) | Unaffected                                                                     |
| `STORAGE_MIN_FREE_BYTES`                                                                                       | local storage only            | One filesystem, so one instance; skipped for S3                                      |
| `ALLOW_ANONYMOUS_UPLOADS`, `ALLOW_REGISTRATION`                                                                | per-process environment       | Set them the same on every instance                                                  |
| New-account probation                                                                                          | an end date stored per account at registration | Unaffected                                                          |
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

- Every third-party image is pinned by tag plus multi-platform index digest, except MinIO's. Both Dockerfiles use
  literal `FROM` lines (`node:22-alpine` in both, `nginx:1.31-alpine`), because Dependabot ignores an `ARG`-based
  `FROM`; the `ARG NODE_IMAGE` / `NGINX_IMAGE` overrides are gone (for a registry mirror, use the Docker daemon's
  `registry-mirrors`). The Dockerfiles carry no `# syntax=` directive: the build uses the builder's built-in
  Dockerfile frontend and pulls no frontend image (removed on 2026-11-21; `docker/dockerfile:1` used to be fetched by
  a floating tag on every build). `docker-compose.prod.yml` pins postgres, redis and caddy. CI's Postgres and Redis
  service images and its MinIO `docker run` use exactly the references in `docker-compose.prod.yml`, and both
  Dockerfiles use the same node reference: `scripts/image-pins.test.mjs` (in `npm run test:scripts`, which audit.yml
  runs) fails otherwise, so a Dependabot docker-compose pull request stays red until `ci.yml` is updated in the same
  branch. Dependabot's `docker` and `docker-compose` entries propose digest bumps, grouped, ignoring Node, Postgres and
  Redis majors. The exception: `cgr.dev/chainguard/minio:latest` (the `minio` profile, `docker-compose.yml` and the CI
  integration job) stays tag-only, because cgr.dev could not be reached to resolve a digest. Bumped by hand, because
  Dependabot does not see them: the actionlint and gitleaks images (`run:` steps in `ci.yml`) and the Trivy image
  (`scripts/image-scan.mjs`). The dev stack, `docker-compose.yml`, stays on tags.
- All three npm installs in the images are lockfile-exact and use `--ignore-scripts`. The `prisma-cli` stage installs
  with `npm ci` from a lockfile that `scripts/prisma-cli-lockfile.mjs` cuts out of `package-lock.json` at build time:
  `prisma` and its whole tree, with the root lockfile's versions and integrity hashes, the same tree `npm audit`
  checks. `prisma version` then fetches the engines (checksummed), and the build checks that the schema engine is
  present.
- The API image is large for a Node service (see the record below): the Prisma client ships engines for three targets, the
  Prisma CLI is installed next to the app to run migrations (in the `migrate` service, or at start), and npm installs a
  few optional peers (TypeScript, Prisma) of `@prisma/client`. Trimming it was not attempted.
- A malicious server could serve modified JavaScript; the CSP and the absence of inline scripts narrow what such code can do,
  they do not make the client verifiable (DESIGN section 12 lists this as a stated limitation).
- No HA, backup automation, log shipping or alerting is provided. Postgres, Redis and nginx are single containers.
- Secrets are passed only as environment variables (no `*_FILE` or Docker secrets), so they show in `docker inspect`
  and in `/proc/1/environ` of their containers. The `api` container no longer holds the database owner's password,
  but `migrate` and `postgres` do.
- The web container runs stock nginx with its default capabilities and a root master process (`nginx-unprivileged`
  with `cap_drop: [ALL]` was not adopted). nginx's error log can hold full client addresses
  ([nginx and the security headers](#nginx-and-the-security-headers)). No CPU limits are set.
- CI. `.github/workflows/ci.yml` has these jobs:
  - `static`: lint, `test:lint` (the ESLint security bans fire), format check, typecheck, unit tests;
  - `integration`: the API tests on Postgres and Redis service containers, then `db:check` (the migrations replayed
    into `cipherdrop_shadow` must build exactly `schema.prisma`), then `test:s3` against MinIO started with
    `docker run`;
  - `e2e`: every spec in desktop Chromium, the report uploaded on failure;
  - `e2e-cross`: the `@cross` subset, one runner per project (`firefox`, `webkit`, `mobile-chromium`,
    `mobile-webkit`), each browser installed with `--with-deps`;
  - `secrets`: gitleaks 8.30.1 over the full history, with the exact-value allowlist in `.gitleaks.toml`;
  - `workflows`: actionlint 1.7.12 and zizmor 1.32.0 (pedantic persona, offline);
  - `prod-stack`, which replaced the build-only images job: both images built with `docker compose build` from the
    Dockerfiles, `docker-compose.prod.yml` booted with `openssl rand` secrets and `WEB_ORIGIN=http://127.0.0.1:8080`,
    `npm run smoke:prod` with `SMOKE_WEB_CONTAINER` set, then `scripts/image-scan.mjs`: Trivy 0.76.2 by digest, a
    CycloneDX SBOM and the Trivy JSON per image in the `image-sbom-and-scan` artifact. The stack's logs are uploaded
    on failure.

  `codeql.yml` runs CodeQL (`javascript-typescript`, `security-extended`) on pushes to main, pull requests, Tuesdays
  at 04:41 UTC and on demand; it is free on public repositories, and private ones need GitHub Code Security.
  `audit.yml` runs `npm run test:scripts` (the image-pin check included) and the dependency audit gate
  ([SECURITY.md](SECURITY.md) section 7) on pushes to main, on pull requests, every Monday at 05:23 UTC and on demand.
  Every action is pinned to a commit SHA with a version comment, and Dependabot proposes updates; checkout uses
  `persist-credentials: false`; installs run `npm ci --ignore-scripts`, then `npm run db:generate -w @cipherdrop/api`,
  which generates the Prisma client and fetches the Prisma engines that the skipped install scripts would have fetched.
  CI ran on GitHub for the first time on 2026-11-20 (pull request #1) and passed every job it then had. The jobs added
  on 2026-11-21 (`e2e-cross`, `prod-stack`, `secrets`, zizmor in `workflows`, and `codeql.yml`) had not run on GitHub
  as of 2026-11-21. If branch protection requires the old `production images build` check, replace it with
  `production stack (build, boot, smoke, scan)`.
- Not covered by CI: the `minio` (S3) and `tls` profiles of the production stack, any memory or load ceiling (the
  `mem_limit` values above are sized by reasoning and smoke-test peaks, not by a load test), and image publication:
  images are built per run, not pushed to a registry, signed or given provenance attestations. The SBOM is an
  inventory artifact, not an attestation.

## 6. Upgrading

`git pull` and `up -d --build` keep the old `.env.production`, so an install of an earlier commit needs the steps
below. Items 7 and 8 came with the first round of pull request #1 (2026-11-20); everything else came with batch 1
(2026-11-21), so an install of the pull request's first round needs all but those two. Take a database backup
first: migrations are forward-only. The full list of changes is in
[CHANGELOG.md](../CHANGELOG.md).

### Before the next `up`

Until items 1 to 6 are done, compose, `migrate` or the API refuses to start. Items 7 to 10 otherwise leave a client
able to choose its address, or break `up`, a build or a sidecar.

1. **Add `POSTGRES_APP_PASSWORD` and `REDIS_PASSWORD` to `.env.production`** (`openssl rand -hex 24` and
   `openssl rand -hex 32`; `POSTGRES_APP_PASSWORD` different from `POSTGRES_PASSWORD`). Compose refuses to start
   without them, with a message naming the variable. On the next `up`, the one-shot `migrate` service applies the
   migrations as the owner and creates the role `cipherdrop_app`, and the API then connects as that role instead of
   the owner. The `redis-data` volume keeps its data under the new password.
2. **`POSTGRES_PASSWORD` must not be the template's placeholder** (`migrate` refuses a `dev-only`, `test-only` or
   `change-me` owner password, after the migrations, and the API then does not start). Nothing checked it before. If
   yours still is one, change it with `ALTER ROLE cipherdrop PASSWORD '...'` inside Postgres first, then in the file:
   the variable only takes effect when a new volume is initialised ([Operations](#operations), Secrets rotation).
3. **With `STORAGE_DRIVER=s3`**, grant the API's key `s3:GetBucketObjectLockConfiguration` and
   `s3:GetBucketVersioning`, or set `S3_DELETE_ALL_VERSIONS=true` and grant `s3:GetBucketObjectLockConfiguration`,
   `s3:ListBucketVersions` and `s3:DeleteObjectVersion`. The API reads the bucket's settings at start-up and refuses
   to start without these permissions, on a bucket with Object Lock, and on a versioned bucket unless
   `S3_DELETE_ALL_VERSIONS=true` ([section 2](#2-s3-compatible-storage)). This is deliberate: on a versioned bucket a
   plain delete removes nothing.
4. **With `ANON_MAX_DROP_BYTES` above 1 GiB**, raise `ANON_BYTES_PER_CLIENT` to at least that value rounded up to a
   whole MiB, or set it to 0 (off). The API refuses to start otherwise; the error names both variables.
5. **With `REFRESH_TOKEN_TTL_DAYS` above 30**, set `SESSION_MAX_LIFETIME_DAYS` to at least that value. The API
   refuses to start otherwise.
6. **`ARGON2_MAX_CONCURRENT` must stay below `UV_THREADPOOL_SIZE`**: 8 in the API image, libuv's default 4 when the
   API runs outside it. The default (2) passes; a value raised to that level makes the API refuse to start, so raise
   `UV_THREADPOOL_SIZE` with it.
7. **With the `tls` profile**, set `TRUST_PROXY=1` (since 2026-11-20; it used to be told 2). With 2, a client that
   reaches nginx's port directly can choose its own address.
8. **The compose network `edge` (`172.16.94.0/28`, since 2026-11-20)** must not overlap another Docker network on
   the host, or `up` fails; see [nginx and the security headers](#nginx-and-the-security-headers) to move it.
9. **A build that overrode `NODE_IMAGE` or `NGINX_IMAGE`** with `--build-arg` (for a registry mirror) must use the
   Docker daemon's `registry-mirrors` instead: the Dockerfiles have literal, digest-pinned `FROM` lines.
10. **Anything that reached Postgres or Redis over the compose network** (a backup sidecar, a monitoring
    exporter) must join the internal `backend` network: `default` no longer reaches them. Redis now needs the
    password, and the database's application role is `cipherdrop_app`.

### What changes on its own

- **Sessions have an absolute lifetime** of `SESSION_MAX_LIFETIME_DAYS` (30) from sign-in. It is computed from each
  session's creation time, so sessions older than 30 days end at their next refresh after the upgrade, and their
  users sign in again (with the 2FA code when it is on).
- **Admins need two-step verification.** An admin without it gets 403 `MFA_REQUIRED` on every admin route, and the
  console asks them to turn it on in **Settings**, **Security**. Do it at once: until the owner enrols, anyone who
  knows the password can enrol their own authenticator and open the console. Find such accounts with
  `SELECT email FROM "User" WHERE role='ADMIN' AND "totpEnabledAt" IS NULL`. Admins can no longer turn 2FA off, and
  only accounts with 2FA can be promoted ([Admins](#operations)).
- **Turning on 2FA signs out the account's other sessions**, as a password change does.
- **Re-authentication is required** for TOTP enable (password plus a code from the new authenticator), backup-code
  regeneration (password plus a TOTP code), and signing one session or all other sessions out (password, plus a code
  when 2FA is on). A password change also needs a code when 2FA is on. The SPA is updated; any other client of these
  routes breaks, because they now require `authKey` (and `code`) in the body. `POST /auth/mfa/totp/disable` answers
  409 for admins, and `PATCH /admin/users/:id` answers 409 when it would promote an account without 2FA.
- **Swagger UI is off unless `API_DOCS_UI=true`**, which only development may set: production refuses it, and nginx
  answers 404 for `/api/docs`. A local `apps/api/.env` copied from the template before this change needs the line
  `API_DOCS_UI=true` for Swagger UI. `/api/openapi.json` is always served.
- **New hosting-abuse defaults** ([Hosting-abuse controls](#hosting-abuse-controls-public-instances)): a 10 GiB
  ceiling on all anonymous drops (`ANON_TOTAL_PENDING_BYTES` was 0, off), 1 GiB per 24 hours per anonymous client,
  and, with local storage, a 1 GiB free-disk floor: if the blob volume has less than 1 GiB free (minus active
  uploads), every new drop gets 507 `STORAGE_FULL` (`STORAGE_MIN_FREE_BYTES=0` turns it off). Accounts registered
  after the upgrade start on the 256 MiB probation quota for 7 days; existing accounts get no probation.
  `GLOBAL_STORAGE_CAP_BYTES` stays off until you set it, which a public instance should.
- **Anonymous drop creates and sign-ups are counted per IPv6 /48**, not /64 (IPv4 is unchanged), so clients in one
  /48 share 10 anonymous drops and 5 sign-ups per hour. Failed logins are also limited to 30 per 15 minutes per IPv4
  address or IPv6 /48, and nginx limits the credential routes to 2 requests per second per client (burst 40).
- **Two migrations** run on the next start: `20261120000000_new_account_probation` (`User.quotaProbationEndsAt`)
  and `20261120120000_chunk_stored_at` (`DropChunk.storedAt` with a default, and an index on `(dropId, storedAt)`).
  The index build blocks writes to `DropChunk` while it runs, which is before the API serves.
- **Cleanup** also deletes an upload that has stored no chunk one hour after its create.
- **nginx's access log** has a new format (time first, client IP prefix only, no query string, user agent or
  referer), so anything that parsed the old `main` format must change. The address of a proxy on this host is now
  read from `docker network inspect` (see `TRUST_PROXY` above).
- **Resource limits** apply to every service. On hosts with more than about 60 CPUs, raise web's `pids_limit`; on
  hosts with more than about 200, the api's ([Resource limits](#resource-limits)). Redis now has `maxmemory 128mb`
  with `noeviction`: when it is full, writes fail rather than evict a denylisted session.
- **Admin API fields:** `AdminUser.storageQuotaBytes` is the stored quota, and the new `effectiveQuotaBytes` is the
  one that applies now; `Me` and `AdminUser` gain `quotaProbationEndsAt`. A `PATCH /admin/users/:id` with
  `storageQuotaBytes` ends an account's probation.

### Recommended

- Set `SECURITY_TXT_CONTACT` (and `SECURITY_TXT_POLICY`) to your own contact, then `up -d --build web`; without it,
  `/.well-known/security.txt` points at this repository. Rebuild the web image with `--no-cache` at least every 180
  days. If the contact is a fork's GitHub reporting form (`https://github.com/OWNER/REPO/security/advisories/new`),
  turn on private vulnerability reporting in that repository's settings first: the form exists only while the
  setting is on ([SECURITY.md](SECURITY.md) section 7).
- On a public instance, set `GLOBAL_STORAGE_CAP_BYTES`, and alert on `drops_refused_total` and `storage_free_bytes`.
- For local development: the bench API needs `NEW_ACCOUNT_PROBATION_DAYS=0` ([BENCHMARKS.md](BENCHMARKS.md)), and
  the seeded admin must enrol 2FA before it can open the console.
- For a fork with branch protection: replace the required `production images build` check with
  `production stack (build, boot, smoke, scan)`.

## Verification record

### 2026-11-21: the merged batch-1 branch

Run on 2026-11-21 in a Linux cloud container (Docker 29.10.0, Compose v5.7.1, Node 22.23.5, no IPv6) on the branch
that merges the five batch-1 branches. Project `cd-int`, `WEB_PORT=18660`, `WEB_ORIGIN=http://127.0.0.1:18660`,
secrets generated by CI's own env-generation script (`openssl rand`, the template's other values kept). The images
were built from stand-in Dockerfiles that differ from the committed ones only in dropping `apk add --no-cache
openssl` (the Alpine mirrors are blocked there) and trusting the sandbox's proxy CA during the build; nginx ran with
`deploy/nginx.conf` minus `listen [::]:80` (no IPv6).

| Check | Command | Result |
| ----- | ----- | ----- |
| Boot on a fresh database | `docker compose -p cd-int ... up -d --no-build --wait` | Every service healthy; `migrate` exited 0 after applying the 8 migrations (the newest is `20261120120000_chunk_stored_at`) and logged that the runtime role is up to date (DML only). |
| Smoke through nginx | `SMOKE_BASE_URL=http://127.0.0.1:18660 SMOKE_WEB_CONTAINER=cd-int-web-1 npm run smoke:prod -w @cipherdrop/web -- --trace off` | 14 of 14 passed in 49.9 s, the access-log check included. |
| Secrets in logs | `grep -F` of each of the six generated secrets in `docker compose logs` and the smoke output | No hit. |
| Teardown | `down -v --remove-orphans`, `docker rmi` of both images | No container, volume, network or image of the run left. |

Unit checks at this date: `apps/web/deploy-checks/nginx-headers.test.ts` has 31 tests (it also checks the access-log
format and its prefix map against `ipPrefix()`, `/.well-known/`, the credential-route rate limit against the API's
limits, and the compose file's networks, limits, Redis settings and `migrate` ordering),
`apps/web/deploy-checks/security-txt.test.ts` 17, `apps/api/src/config/env.production-example.test.ts` 7 and
`apps/api/src/db/runtimeRole.test.ts` 24 (against Postgres).

### 2026-11-21: CI's `prod-stack` job, run locally

The job's own env-generation script and compose environment (project `cd-ci`, `WEB_PORT=18630`), images from the same
kind of stand-in Dockerfiles, and nginx without `listen [::]:80`, on the `b1/ci` branch. First run, on images built
while the `# syntax=docker/dockerfile:1` directive was still there: healthy in 30 s, 6 migrations applied, smoke 10 of
10 in 51.4 s, the generated secrets in neither log file, and the image scan passed (api: CRITICAL 0, HIGH 14, all
fixable, 12 of them in the npm CLI bundled with Node and 2 already allowlisted under `@prisma/config`, 450 SBOM
components; web: CRITICAL 0, HIGH 0, MEDIUM 11, 73 components). Re-run after removing the directive (the built-in
frontend, no frontend image pulled): healthy in 23 s, 6 migrations, smoke 10 of 10 in 51.6 s, the secrets in no log;
the scan was not re-run.

### 2026-11-21: ops hardening (networks, Redis password, limits, runtime role, access log)

Linux cloud container, Docker 29.10.0, Compose v5.7.1, no IPv6, on the `b1/ops` branch. Project `cd-ops`,
`WEB_PORT=18650`, a stand-in API image (no `apk` step) and the nginx configuration minus `listen [::]:80`.

| Check | Result |
| ----- | ----- |
| Compose configuration | Fails fast, naming the variable, when `POSTGRES_APP_PASSWORD` or `REDIS_PASSWORD` is missing. |
| Boot | `migrate` exited 0 (6 migrations, role provisioned), every service healthy, `up --wait` fine with the one-shot. The API connects as `cipherdrop_app` (not a superuser), and the owner's password is absent from its `docker inspect`. |
| Networks | `web` has no DNS for `postgres` or `redis`, and TCP to their addresses is blocked; `api` reaches both; `postgres` has no route out; `api` has. |
| Redis | `NOAUTH` without the password; runs as the `redis` user; `/proc/1/cmdline` is `redis-server *:6379`, and the container's `Cmd` shows the literal `$REDISCLI_AUTH`, not the password; `noeviction`. |
| Limits | Applied (`docker inspect`), with the peaks listed under [Resource limits](#resource-limits). |
| Rotation | `POSTGRES_APP_PASSWORD` changed, then `up -d`: worked. |
| Smoke | 12 of 12 in 51.9 s with `SMOKE_WEB_CONTAINER` (the first run found that `$uri` logged `/index.html` for every SPA route; fixed). |
| Access log | 117 lines, none with a full IPv4 address, 153 bytes per line on disk. The prefix map agreed with a real nginx 1.31 on 20,021 addresses. |
| security.txt | The build arguments reach the image; an invalid contact fails the build. |
| S3 | `npm run test:s3`: 53 passed against a MinIO stand-in (`bitnamilegacy/minio`). |
| Review round | With `POSTGRES_PASSWORD` left at the template's placeholder, `migrate` applied the migrations, then refused ("DATABASE_URL: the owner password is still a placeholder") and exited 1; `api` and `web` did not start. A fresh stack: smoke 12 of 12 in 52.1 s; api `PidsLimit` 256. The access-log check failed against the earlier `[^?]*` rule (fragment logged) and against `[^?#]*` (the `%23` form logged), and passed with the shipped rule; raw `/api/drops/<id>#m` and `%23m` requests left neither marker in the API's log or nginx's. An unchanged rebuild of the web image was `CACHED` at the build step and kept `Expires` 2027-05-20T09:44:55Z; `--no-cache` gave 2027-05-20T09:45:30Z. `caddy:2-alpine` forwarded `GET /d/X#k` to nginx as `/d/X%23k` (a plain-HTTP probe). |
| Teardown | Nothing left. Not booted: the `tls` profile (fixed host ports 80 and 443). |

### 2026-11-20: auth hardening

Stack `cd-auth` with stand-in images (no `apk` lines, the proxy CA as a build-only argument), on the `b1/auth` branch:
11 of 11 smoke tests passed; the API container has `UV_THREADPOOL_SIZE=8`; 60 concurrent logins from 60 client
addresses straight to the API gave 34 x 401 and 26 x 429 (`Retry-After: 1`) in 528 ms, and `argon2_rejected_total`
was 26; through nginx, one client got its burst and then nginx's 429. `nginx-headers.test.ts` had 19 tests on that
branch.

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
