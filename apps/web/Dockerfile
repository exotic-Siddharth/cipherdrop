# CipherDrop web image (spec section 16): the built SPA served by nginx with the section 12 security headers and an
# /api reverse proxy (deploy/nginx.conf). Build context = repository root:
#   docker build -f apps/web/Dockerfile -t cipherdrop-web .
# Both base images are pinned by their multi-platform index digest, in literal FROM lines so Dependabot can propose
# the bumps (see apps/api/Dockerfile; the node reference must be the same in both files, scripts/image-pins.test.mjs
# checks it). No `syntax` parser directive, as in apps/api/Dockerfile: the build uses the builder's own Dockerfile
# frontend.

FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build
WORKDIR /repo
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
# The SPA and the workspace packages it bundles; no scripts needed (the API's Prisma client is not part of it).
RUN npm ci -w @cipherdrop/web --ignore-scripts
COPY packages packages
# .dockerignore keeps apps/web/.env out: no VITE_DEMO_CREDENTIALS is ever baked into a production bundle.
COPY apps/web apps/web
# Served at /SECURITY.md (linked from /how-it-works); the build copies it into dist.
COPY docs/SECURITY.md docs/SECURITY.md
RUN npm run build -w @cipherdrop/web

FROM nginx:1.31-alpine@sha256:fb4658584bd9a916ffb6f6e365f97c25cfdb2923801f551ea08356e695f14ff7 AS runtime
RUN rm -f /etc/nginx/conf.d/default.conf
COPY deploy/nginx.conf /etc/nginx/conf.d/cipherdrop.conf
COPY --from=build /repo/apps/web/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1/healthz"]
