#!/bin/sh
# Entrypoint of the API image.
#   api-entrypoint.sh            The server: apply pending migrations first (unless MIGRATE_ON_START=false), then
#                                replace this shell with the server (exec: SIGTERM reaches node, which shuts down
#                                gracefully). The default, for a database role that owns the schema.
#   api-entrypoint.sh migrate    Apply pending migrations; then, when DB_RUNTIME_ROLE is set, create or update that
#                                role with rights on rows only (apps/api/src/db/runtimeRole.ts) and exit.
#                                docker-compose.prod.yml runs this as its one-shot `migrate` service, as the owner,
#                                and starts the API as the runtime role with MIGRATE_ON_START=false.
# Several instances starting together are safe: `migrate deploy` serialises on a Postgres advisory lock.
set -eu

migrate() {
  node /opt/prisma/node_modules/prisma/build/index.js migrate deploy --schema /app/apps/api/prisma/schema.prisma
}

case "${1:-serve}" in
  serve)
    if [ "${MIGRATE_ON_START:-true}" != false ]; then migrate; fi
    exec node /app/apps/api/dist/index.js
    ;;
  migrate)
    migrate
    if [ -n "${DB_RUNTIME_ROLE:-}" ]; then exec node /app/apps/api/dist/provision-runtime-role.js; fi
    ;;
  *)
    echo "usage: api-entrypoint.sh [serve|migrate]" >&2
    exit 64
    ;;
esac
