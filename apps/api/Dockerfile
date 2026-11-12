# syntax=docker/dockerfile:1
# CipherDrop API image (spec section 16). Build context = repository root:
#   docker build -f apps/api/Dockerfile -t cipherdrop-api .
# Stages: build (full install, prisma generate, tsup bundle) -> prisma-cli (pinned migrate CLI) -> runtime
# (production dependencies only, non-root, `prisma migrate deploy` then the server).
ARG NODE_IMAGE=node:22-alpine

FROM ${NODE_IMAGE} AS build
# Prisma's query engine needs OpenSSL (binaryTargets in schema.prisma: linux-musl-openssl-3.0.x).
RUN apk add --no-cache openssl
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
# its own, at exactly the version in package-lock.json, so `migrate deploy` can run when the container starts.
FROM ${NODE_IMAGE} AS prisma-cli
RUN apk add --no-cache openssl
COPY package-lock.json /tmp/package-lock.json
RUN set -eu; \
    version="$(node -p "require('/tmp/package-lock.json').packages['node_modules/prisma'].version")"; \
    mkdir /opt/prisma && cd /opt/prisma && npm init -y >/dev/null && \
    npm install --no-audit --no-fund --loglevel=error "prisma@${version}" && \
    npm cache clean --force

FROM ${NODE_IMAGE} AS runtime
RUN apk add --no-cache openssl
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
ENV API_PORT=4100 \
    STORAGE_DIR=/data/blobs
EXPOSE 4100
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:4100/healthz').then((r)=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["/usr/local/bin/api-entrypoint.sh"]
