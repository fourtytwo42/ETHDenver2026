#!/usr/bin/env bash
set -euo pipefail

FAUCET_HOME="${XCLAW_FAUCET_HOME:-$HOME/.xclaw-faucet}"
BACKUP_DIR="${XCLAW_FAUCET_BACKUP_DIR:-$HOME/.xclaw-faucet-backups}"
KEY_FILE="${XCLAW_FAUCET_BACKUP_KEY_FILE:-$HOME/.xclaw-faucet-backup-key.txt}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"

if [ ! -d "$FAUCET_HOME" ]; then
  echo "[xclaw-faucet-backup] faucet home not found: $FAUCET_HOME" >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

if [ ! -f "$KEY_FILE" ]; then
  python3 -c 'import secrets; print(secrets.token_urlsafe(64))' >"$KEY_FILE"
  chmod 600 "$KEY_FILE"
fi

KEY="$(cat "$KEY_FILE")"
ARCHIVE_BASENAME="xclaw-faucet-${TS}.tar.gz"
ARCHIVE_PATH="$BACKUP_DIR/$ARCHIVE_BASENAME"
ENCRYPTED_PATH="${ARCHIVE_PATH}.enc"
SHA_PATH="${ENCRYPTED_PATH}.sha256"
LATEST_LINK="$BACKUP_DIR/latest.enc"

tar -C "$HOME" -czf "$ARCHIVE_PATH" ".xclaw-faucet"
openssl enc -aes-256-cbc -pbkdf2 -salt -in "$ARCHIVE_PATH" -out "$ENCRYPTED_PATH" -pass "pass:$KEY"
rm -f "$ARCHIVE_PATH"

sha256sum "$ENCRYPTED_PATH" >"$SHA_PATH"
chmod 600 "$ENCRYPTED_PATH" "$SHA_PATH"
ln -sfn "$ENCRYPTED_PATH" "$LATEST_LINK"

cat <<EOF
[xclaw-faucet-backup] backup complete
encrypted_backup=$ENCRYPTED_PATH
checksum_file=$SHA_PATH
latest_symlink=$LATEST_LINK
key_file=$KEY_FILE
EOF
