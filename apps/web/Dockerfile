# syntax=docker/dockerfile:1
# CipherDrop web image (spec section 16): the built SPA served by nginx with the section 12 security headers and an
# /api reverse proxy (deploy/nginx.conf). Build context = repository root:
#   docker build -f apps/web/Dockerfile -t cipherdrop-web .
ARG NODE_IMAGE=node:22-alpine
ARG NGINX_IMAGE=nginx:1.31-alpine

FROM ${NODE_IMAGE} AS build
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

FROM ${NGINX_IMAGE} AS runtime
RUN rm -f /etc/nginx/conf.d/default.conf
COPY deploy/nginx.conf /etc/nginx/conf.d/cipherdrop.conf
COPY --from=build /repo/apps/web/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1/healthz"]
