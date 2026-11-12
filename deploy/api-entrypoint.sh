#!/bin/sh
# Apply pending migrations, then replace this shell with the server (exec: SIGTERM reaches node, which shuts down
# gracefully). Several instances starting together are safe: `migrate deploy` serialises on a Postgres advisory lock.
set -eu
node /opt/prisma/node_modules/prisma/build/index.js migrate deploy --schema /app/apps/api/prisma/schema.prisma
exec node /app/apps/api/dist/index.js
