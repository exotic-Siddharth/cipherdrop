# CipherDrop API image (spec section 16). Build context = repository root:
#   docker build -f apps/api/Dockerfile -t cipherdrop-api .
# Stages: base (the pinned Node image plus OpenSSL) -> build (full install, prisma generate, tsup bundle) ->
# prisma-cli (the migrate CLI, installed from a lockfile) -> runtime (production dependencies only, non-root,
# `prisma migrate deploy` then the server).

# The base image, pinned by its multi-platform index digest: the tag says which line it follows, the digest fixes the
# bytes. A literal FROM, not an ARG default, so Dependabot (.github/dependabot.yml) can propose the digest bumps: its
# Dockerfile parser reads only FROM lines that name an image. To build from a registry mirror, configure the mirror in
# the Docker daemon (registry-mirrors) or edit this line: the digest still has to match.
# There is no `syntax` parser directive on purpose: the build uses the Dockerfile frontend built into the builder
# (BuildKit, versioned with the Docker install), so no frontend image is pulled by a floating tag and run on every
# build. Nothing in either Dockerfile needs a newer frontend (no RUN --mount, no heredocs, no COPY --link or --chmod).
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS base
# Prisma's engines need OpenSSL (binaryTargets in schema.prisma: linux-musl-openssl-3.0.x): the build's
# `prisma generate`, the migrate CLI and the runtime's query engine.
RUN apk add --no-cache openssl

FROM base AS build
WORKDIR /repo
# Manifests first so the dependency layer is cached until a package.json or the lockfile changes.
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
# Installs apps/api and its workspace dependencies only (not the SPA). Scripts are skipped: the Prisma client
# is generated explicitly below.
RUN npm ci -w @cipherdrop/api --ignore-scripts
COPY packages packages
COPY apps/api apps/api
RUN npm run db:generate -w @cipherdrop/api && npm run build -w @cipherdrop/api

# The Prisma CLI is a devDependency of the API, so the production install below omits it. It is installed on
# its own so `migrate deploy` can run when the container starts, from a lockfile cut out of package-lock.json
# (scripts/prisma-cli-lockfile.mjs): prisma and its whole tree at the root lockfile's versions and integrity hashes,
# the same tree the dependency audit gate checks. Scripts are skipped as in the other installs; `prisma version`
# then fetches the engines that @prisma/engines' postinstall would have (the schema engine `migrate deploy` runs, and
# the query engine), checksum-verified by @prisma/fetch-engine, and proves the CLI starts.
FROM base AS prisma-cli
COPY package-lock.json scripts/prisma-cli-lockfile.mjs /tmp/prisma-cli/
RUN set -eu; \
    node /tmp/prisma-cli/prisma-cli-lockfile.mjs /tmp/prisma-cli/package-lock.json /opt/prisma && \
    cd /opt/prisma && \
    npm ci --ignore-scripts --no-audit --no-fund --loglevel=error && \
    CHECKPOINT_DISABLE=1 node_modules/.bin/prisma version && \
    test -x node_modules/@prisma/engines/schema-engine-linux-musl-openssl-3.0.x && \
    npm cache clean --force && rm -rf /tmp/prisma-cli

FROM base AS runtime
ENV NODE_ENV=production \
    PRISMA_HIDE_UPDATE_MESSAGE=1 \
    CHECKPOINT_DISABLE=1
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/
# Production dependencies of the API only (apps/web is not copied, so the SPA tree is not installed). The workspace packages (@cipherdrop/crypto, shared) are bundled into
# dist by tsup, so no source is copied for them.
RUN npm ci --omit=dev -w @cipherdrop/api --ignore-scripts && npm cache clean --force
COPY --from=build /repo/node_modules/.prisma /app/node_modules/.prisma
COPY --from=prisma-cli /opt/prisma /opt/prisma
COPY --from=build /repo/apps/api/dist /app/apps/api/dist
COPY apps/api/prisma/schema.prisma /app/apps/api/prisma/schema.prisma
COPY apps/api/prisma/migrations /app/apps/api/prisma/migrations
COPY deploy/api-entrypoint.sh /usr/local/bin/api-entrypoint.sh
# Local blob storage lives in /data/blobs (a named volume in docker-compose.prod.yml).
RUN chmod 0755 /usr/local/bin/api-entrypoint.sh && mkdir -p /data/blobs && chown -R node:node /data
USER node
# libuv threadpool (Node's default is 4). Argon2id (@node-rs/argon2) runs on it next to fs (local blob reads and
# writes), dns.lookup and async crypto. The API runs at most ARGON2_MAX_CONCURRENT (default 2) hashes at once, so
# 8 threads leave at least 8 - 2 = 6 for that I/O under a login flood, more than the 4 it shared with every hash
# before. Idle threads cost little (their stacks are reserved, not committed). Raise it together with
# ARGON2_MAX_CONCURRENT, which must stay below it (config/env.ts refuses otherwise).
ENV API_PORT=4100 \
    STORAGE_DIR=/data/blobs \
    UV_THREADPOOL_SIZE=8
EXPOSE 4100
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:4100/healthz').then((r)=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["/usr/local/bin/api-entrypoint.sh"]
