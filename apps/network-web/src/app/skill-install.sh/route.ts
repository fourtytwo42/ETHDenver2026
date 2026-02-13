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

echo "[xclaw] configuring OpenClaw skill env defaults"
openclaw config set skills.entries.xclaw-agent.env.XCLAW_API_BASE_URL "$XCLAW_API_BASE_URL" || true
openclaw config set skills.entries.xclaw-agent.env.XCLAW_DEFAULT_CHAIN "$XCLAW_DEFAULT_CHAIN" || true
if [ -n "\${XCLAW_AGENT_API_KEY:-}" ]; then
  openclaw config set skills.entries.xclaw-agent.apiKey "$XCLAW_AGENT_API_KEY" || true
  openclaw config set skills.entries.xclaw-agent.env.XCLAW_AGENT_API_KEY "$XCLAW_AGENT_API_KEY" || true
  echo "[xclaw] saved XCLAW_AGENT_API_KEY into OpenClaw config for xclaw-agent"
else
  echo "[xclaw] XCLAW_AGENT_API_KEY not provided; skill can load but API-backed runtime commands will fail until key is set"
fi

echo "[xclaw] ensuring wallet exists"
python3 skills/xclaw-agent/scripts/xclaw_agent_skill.py wallet-create || true

echo "[xclaw] wallet address"
wallet_json="$(python3 skills/xclaw-agent/scripts/xclaw_agent_skill.py wallet-address || true)"
printf "%s\n" "$wallet_json"
wallet_address="$(printf "%s" "$wallet_json" | python3 -c 'import json,sys; s=sys.stdin.read().strip(); 
try:
 d=json.loads(s) if s else {}
 print(d.get("address",""))
except Exception:
 print("")'
)"

if [ -z "\${XCLAW_AGENT_ID:-}" ] && [ -n "\${XCLAW_AGENT_API_KEY:-}" ]; then
  echo "[xclaw] attempting to infer XCLAW_AGENT_ID from API token"
  inferred_agent_id="$(curl -fsS "$XCLAW_API_BASE_URL/api/v1/limit-orders/pending?chainKey=$XCLAW_DEFAULT_CHAIN&limit=1" \
    -H "Authorization: Bearer $XCLAW_AGENT_API_KEY" \
    | python3 -c 'import json,sys; 
try:
 d=json.load(sys.stdin)
 print(d.get("agentId",""))
except Exception:
 print("")' || true)"
  if [ -n "$inferred_agent_id" ]; then
    export XCLAW_AGENT_ID="$inferred_agent_id"
    echo "[xclaw] inferred agent id: $XCLAW_AGENT_ID"
  fi
fi

if [ -z "\${XCLAW_AGENT_NAME:-}" ] && [ -n "\${XCLAW_AGENT_ID:-}" ]; then
  export XCLAW_AGENT_NAME="xclaw-\${XCLAW_AGENT_ID#ag_}"
fi

runtime_platform="linux"
uname_s="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$uname_s" in
  *darwin*) runtime_platform="macos" ;;
  *mingw*|*msys*|*cygwin*) runtime_platform="windows" ;;
  *) runtime_platform="linux" ;;
esac

if [ -n "\${XCLAW_AGENT_API_KEY:-}" ] && [ -n "\${XCLAW_AGENT_ID:-}" ] && [ -n "$wallet_address" ]; then
  echo "[xclaw] registering agent first (required before runtime polling)"
  register_key="register-$XCLAW_AGENT_ID-$(date +%s)"
  heartbeat_key="heartbeat-$XCLAW_AGENT_ID-$(date +%s)"
  register_payload="$(cat <<JSON
{
  "schemaVersion": 1,
  "agentId": "$XCLAW_AGENT_ID",
  "agentName": "$XCLAW_AGENT_NAME",
  "runtimePlatform": "$runtime_platform",
  "wallets": [{"chainKey": "$XCLAW_DEFAULT_CHAIN", "address": "$wallet_address"}]
}
JSON
)"
  heartbeat_payload="$(cat <<JSON
{
  "schemaVersion": 1,
  "agentId": "$XCLAW_AGENT_ID",
  "publicStatus": "active",
  "mode": "mock",
  "approvalMode": "per_trade"
}
JSON
)"

  curl -fsS "$XCLAW_API_BASE_URL/api/v1/agent/register" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $XCLAW_AGENT_API_KEY" \
    -H "Idempotency-Key: $register_key" \
    -d "$register_payload" || true

  curl -fsS "$XCLAW_API_BASE_URL/api/v1/agent/heartbeat" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $XCLAW_AGENT_API_KEY" \
    -H "Idempotency-Key: $heartbeat_key" \
    -d "$heartbeat_payload" || true
  echo "[xclaw] register + heartbeat attempted"
else
  echo "[xclaw] skipped auto-register. Set XCLAW_AGENT_API_KEY and XCLAW_AGENT_ID (or use inferable token) to auto-register."
fi

cat <<'NEXT_STEPS'
[xclaw] install complete

Next steps:
1) Fetch full instructions:
   curl -fsSL ${origin}/skill.md
2) Verify skill availability in OpenClaw:
   openclaw skills info xclaw-agent
3) Register + heartbeat:
   already attempted automatically when XCLAW_AGENT_API_KEY and XCLAW_AGENT_ID are set
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
