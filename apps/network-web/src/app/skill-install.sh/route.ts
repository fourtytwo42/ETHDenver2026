import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

export const runtime = 'nodejs';

function resolvePublicBaseUrl(req: NextRequest): string {
  const configured = process.env.XCLAW_PUBLIC_BASE_URL?.trim();
  if (configured) {
    return configured;
  }

  const host = req.nextUrl.hostname;
  if (host === '0.0.0.0' || host === '::' || host === '[::]') {
    return 'https://xclaw.trade';
  }
  return req.nextUrl.origin;
}

function buildInstallerScript(origin: string): string {
  return `#!/usr/bin/env bash
set -euo pipefail

echo "[xclaw] bootstrap start"

export XCLAW_WORKDIR="\${XCLAW_WORKDIR:-$HOME/xclaw}"
export XCLAW_REPO_REF="\${XCLAW_REPO_REF:-main}"
export XCLAW_REPO_URL="\${XCLAW_REPO_URL:-https://github.com/fourtytwo42/ETHDenver2026}"
export XCLAW_API_BASE_URL="\${XCLAW_API_BASE_URL:-${origin}}"
export XCLAW_DEFAULT_CHAIN="\${XCLAW_DEFAULT_CHAIN:-base_sepolia}"

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT

if [ -d "$XCLAW_WORKDIR/.git" ]; then
  echo "[xclaw] existing git workspace found: $XCLAW_WORKDIR"
  cd "$XCLAW_WORKDIR"
  git fetch --all --prune
  git checkout "$XCLAW_REPO_REF"
  git pull --ff-only
elif [ ! -e "$XCLAW_WORKDIR" ]; then
  archive_base="$(echo "$XCLAW_REPO_URL" | sed -E 's#https?://github.com/##' | sed -E 's#\\.git$##')"
  archive_url="https://codeload.github.com/$archive_base/tar.gz/refs/heads/$XCLAW_REPO_REF"
  echo "[xclaw] downloading source archive: $archive_url"
  curl -fsSL "$archive_url" -o "$tmp_dir/repo.tar.gz"
  tar -xzf "$tmp_dir/repo.tar.gz" -C "$tmp_dir"

  src_dir="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d -name 'ETHDenver2026-*' | head -n1)"
  if [ -z "$src_dir" ]; then
    echo "[xclaw] unable to find extracted repository directory"
    exit 1
  fi

  mkdir -p "$(dirname "$XCLAW_WORKDIR")"
  mv "$src_dir" "$XCLAW_WORKDIR"
else
  echo "[xclaw] existing non-git directory at $XCLAW_WORKDIR"
  echo "[xclaw] set XCLAW_WORKDIR to an empty path or convert it into a git clone, then retry"
  exit 1
fi

cd "$XCLAW_WORKDIR"
echo "[xclaw] running setup_agent_skill.py"
python3 skills/xclaw-agent/scripts/setup_agent_skill.py

if [ -n "\${XCLAW_WALLET_PASSPHRASE:-}" ]; then
  echo "[xclaw] creating wallet (non-interactive using XCLAW_WALLET_PASSPHRASE)"
  python3 skills/xclaw-agent/scripts/xclaw_agent_skill.py wallet-create || true
else
  echo "[xclaw] XCLAW_WALLET_PASSPHRASE not set; wallet-create may require interactive passphrase entry"
fi

echo "[xclaw] wallet address"
python3 skills/xclaw-agent/scripts/xclaw_agent_skill.py wallet-address || true

cat <<'NEXT_STEPS'
[xclaw] install complete

Next steps:
1) Fetch full instructions:
   curl -fsSL ${origin}/skill.md
2) Verify skill availability in OpenClaw:
   openclaw skills info xclaw-agent
3) Register + heartbeat:
   follow section "Register agent" in /skill.md
4) Start runtime checks:
   python3 skills/xclaw-agent/scripts/xclaw_agent_skill.py status
NEXT_STEPS
`;
}

export async function GET(req: NextRequest) {
  const publicBaseUrl = resolvePublicBaseUrl(req);
  const body = buildInstallerScript(publicBaseUrl);
  return new NextResponse(body, {
    status: 200,
    headers: {
      'content-type': 'text/x-shellscript; charset=utf-8',
      'cache-control': 'public, max-age=300'
    }
  });
}
