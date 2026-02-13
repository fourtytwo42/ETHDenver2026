# X-Claw Ops Backup/Restore Runbook

## Scope
This runbook defines Slice 14 MVP backup and restore operations for VM-native Postgres.

## Prerequisites
- `pg_dump` and `psql` installed on VM.
- `DATABASE_URL` set for backup source.
- `TARGET_DATABASE_URL` set for restore target (optional; falls back to `DATABASE_URL`).

## Nightly backup command
```bash
infrastructure/scripts/ops/pg-backup.sh
```

### Defaults
- Backup directory: `infrastructure/backups/postgres`
- File pattern: `xclaw_<UTC timestamp>.sql.gz`
- Retention: 7 days

### Optional overrides
- `XCLAW_PG_BACKUP_DIR`
- `XCLAW_PG_BACKUP_RETENTION_DAYS`

## Cron installation (nightly at 02:15 UTC)
```bash
crontab -l > /tmp/xclaw.cron || true
echo "15 2 * * * cd /home/hendo420/ETHDenver2026 && /usr/bin/env DATABASE_URL='$DATABASE_URL' ./infrastructure/scripts/ops/pg-backup.sh >> /home/hendo420/ETHDenver2026/infrastructure/backups/postgres/backup.log 2>&1" >> /tmp/xclaw.cron
crontab /tmp/xclaw.cron
```

## Pre-deploy backup (required before schema changes)
```bash
DATABASE_URL="$DATABASE_URL" infrastructure/scripts/ops/pg-backup.sh
```

## Restore drill command
```bash
XCLAW_PG_RESTORE_CONFIRM=YES_RESTORE \
TARGET_DATABASE_URL="$TARGET_DATABASE_URL" \
infrastructure/scripts/ops/pg-restore.sh infrastructure/backups/postgres/<backup-file>.sql.gz
```

Restore safety defaults:
- target DB must be empty (no tables in `public` schema)
- SQL restore runs with `ON_ERROR_STOP=1`
- non-empty target override (not recommended): `XCLAW_PG_RESTORE_ALLOW_NONEMPTY=YES_NONEMPTY`

## Restore drill validation
Run after restore:
```bash
npm run db:parity
npm run seed:verify
```

Expected:
- `db:parity` returns `"ok": true`
- `seed:verify` returns `"ok": true`

## Safety notes
- Restore is destructive to target DB state.
- Never run restore against production DB without explicit change window approval.
- Keep backup artifacts outside public web paths.
