#!/usr/bin/env bash
set -euo pipefail

BACKUP_FILE="${1:-}"
TARGET_DATABASE_URL="${TARGET_DATABASE_URL:-${DATABASE_URL:-}}"
CONFIRM="${XCLAW_PG_RESTORE_CONFIRM:-}"
ALLOW_NONEMPTY="${XCLAW_PG_RESTORE_ALLOW_NONEMPTY:-}"

if [[ -z "$BACKUP_FILE" ]]; then
  echo "Usage: $0 <backup_file.sql.gz>"
  exit 1
fi

if [[ ! -f "$BACKUP_FILE" ]]; then
  echo "Backup file not found: $BACKUP_FILE"
  exit 1
fi

if [[ -z "$TARGET_DATABASE_URL" ]]; then
  echo "TARGET_DATABASE_URL or DATABASE_URL is required"
  exit 1
fi

if [[ "$CONFIRM" != "YES_RESTORE" ]]; then
  echo "Set XCLAW_PG_RESTORE_CONFIRM=YES_RESTORE to proceed"
  exit 1
fi

TABLE_COUNT="$(psql "$TARGET_DATABASE_URL" -tA -c "select count(*) from information_schema.tables where table_schema='public';")"
TABLE_COUNT="${TABLE_COUNT//[[:space:]]/}"
if [[ "$TABLE_COUNT" != "0" && "$ALLOW_NONEMPTY" != "YES_NONEMPTY" ]]; then
  echo "Target database is not empty (public tables=$TABLE_COUNT). Use a clean target, or set XCLAW_PG_RESTORE_ALLOW_NONEMPTY=YES_NONEMPTY to override."
  exit 1
fi

gzip -dc "$BACKUP_FILE" | psql --set ON_ERROR_STOP=1 "$TARGET_DATABASE_URL"

echo "restore_completed_from=$BACKUP_FILE"
