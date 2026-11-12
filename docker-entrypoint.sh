#!/bin/sh
# Platform volumes (Render disks, Fly volumes, Railway volumes) are often mounted root-owned. Fix ownership, then drop privileges.
set -e
mkdir -p "$(dirname "${PHOENIX_DB:-/data/phoenix.db}")" "${PHOENIX_BACKUP_DIR:-/data/backups}"
if [ "$(id -u)" = "0" ]; then
  chown -R node:node "$(dirname "${PHOENIX_DB:-/data/phoenix.db}")" "${PHOENIX_BACKUP_DIR:-/data/backups}" 2>/dev/null || true
  exec su-exec node "$@"
fi
exec "$@"
