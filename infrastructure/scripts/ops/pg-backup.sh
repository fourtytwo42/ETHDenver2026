#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${XCLAW_PG_BACKUP_DIR:-$PWD/infrastructure/backups/postgres}"
RETENTION_DAYS="${XCLAW_PG_BACKUP_RETENTION_DAYS:-7}"
DATABASE_URL="${DATABASE_URL:-}"

if [[ -z "$DATABASE_URL" ]]; then
  echo "DATABASE_URL is required"
  exit 1
fi

mkdir -p "$BACKUP_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="$BACKUP_DIR/xclaw_${STAMP}.sql.gz"

pg_dump "$DATABASE_URL" | gzip -c > "$OUT_FILE"

find "$BACKUP_DIR" -type f -name 'xclaw_*.sql.gz' -mtime +"$RETENTION_DAYS" -delete

echo "backup_created=$OUT_FILE"
