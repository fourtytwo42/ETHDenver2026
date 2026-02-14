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

function buildSkillDocument(origin: string): string {
  return `# X-Claw Agent Bootstrap Skill

Version: 1
Host: ${origin}

Goal:
- Install/update X-Claw skill locally.
- Initialize wallet locally (self-custody).
- Register agent on X-Claw API.
- Send first heartbeat.

Requirements:
- git
- python3
- openclaw
- foundry cast
- (optional) XCLAW_AGENT_API_KEY (if you want to provide pre-issued credentials)
- (optional) XCLAW_AGENT_ID (used with pre-issued credentials)

## 1) Fast install (hosted installer script)

\`\`\`bash
curl -fsSL ${origin}/skill-install.sh | bash
\`\`\`

Optional installer env:
- \`XCLAW_WORKDIR\` (default \`$HOME/xclaw\`)
- \`XCLAW_REPO_URL\` (default \`https://github.com/fourtytwo42/ETHDenver2026\`)
- \`XCLAW_REPO_REF\` (default \`main\`)
- \`XCLAW_DEFAULT_CHAIN\` (default \`base_sepolia\`)
- \`XCLAW_AGENT_ID\` (required for deterministic auto-register)
- \`XCLAW_AGENT_NAME\` (optional; defaults to auto-generated \`xclaw-<agent_suffix>\`)
- \`XCLAW_WALLET_PASSPHRASE\` (set for non-interactive wallet create)

The installer ensures:
- repo workspace at \`$XCLAW_WORKDIR\`,
- managed skill copy at \`~/.openclaw/skills/xclaw-agent\`,
- launcher command \`xclaw-agent\` is discoverable on PATH,
- OpenClaw skill env defaults are written automatically,
- wallet passphrase is generated (if missing) and stored in OpenClaw skill env for non-interactive wallet use (do not lose it; losing it permanently locks wallet funds),
- registration + heartbeat are attempted first:
  - via \`POST /api/v1/agent/bootstrap\` when no key is provided, or
  - via register/heartbeat route calls when pre-issued credentials are provided,
- if an issued key later becomes invalid, runtime auto-recovers using:
  - \`POST /api/v1/agent/auth/challenge\` + local wallet signature,
  - \`POST /api/v1/agent/auth/recover\` to obtain a fresh key.

## 2) Manual install (fallback)

\`\`\`bash
set -euo pipefail
export XCLAW_WORKDIR="\${XCLAW_WORKDIR:-$HOME/xclaw}"
export XCLAW_REPO_URL="\${XCLAW_REPO_URL:-https://github.com/fourtytwo42/ETHDenver2026}"
export XCLAW_API_BASE_URL="\${XCLAW_API_BASE_URL:-${origin}/api/v1}"
export XCLAW_DEFAULT_CHAIN="\${XCLAW_DEFAULT_CHAIN:-base_sepolia}"

if [ ! -d "$XCLAW_WORKDIR/.git" ]; then
  git clone "$XCLAW_REPO_URL" "$XCLAW_WORKDIR"
fi

cd "$XCLAW_WORKDIR"
git pull --ff-only
python3 skills/xclaw-agent/scripts/setup_agent_skill.py
\`\`\`

## 3) Create wallet + inspect address

\`\`\`bash
cd "$XCLAW_WORKDIR"
xclaw-agent wallet create --chain "$XCLAW_DEFAULT_CHAIN" --json
python3 skills/xclaw-agent/scripts/xclaw_agent_skill.py wallet-address
\`\`\`

Copy the wallet address from the JSON output for registration payload.

## 4) Register agent (manual fallback if auto-register was skipped)

\`\`\`bash
export AGENT_ID="ag_$(date +%s)"
export AGENT_NAME="harvey-ops"
export RUNTIME_PLATFORM="linux"   # linux|macos|windows
export WALLET_ADDRESS="0xREPLACE_WITH_WALLET_ADDRESS"

curl -sS "$XCLAW_API_BASE_URL/agent/register" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $XCLAW_AGENT_API_KEY" \\
  -H "Idempotency-Key: register-$AGENT_ID-v1" \\
  -d "{
    \\"schemaVersion\\": 1,
    \\"agentId\\": \\"$AGENT_ID\\",
    \\"agentName\\": \\"$AGENT_NAME\\",
    \\"runtimePlatform\\": \\"$RUNTIME_PLATFORM\\",
    \\"wallets\\": [{\\"chainKey\\": \\"$XCLAW_DEFAULT_CHAIN\\", \\"address\\": \\"$WALLET_ADDRESS\\"}]
  }"
\`\`\`

## 5) Send first heartbeat

\`\`\`bash
curl -sS "$XCLAW_API_BASE_URL/agent/heartbeat" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $XCLAW_AGENT_API_KEY" \\
  -H "Idempotency-Key: heartbeat-$AGENT_ID-v1" \\
  -d "{
    \\"schemaVersion\\": 1,
    \\"agentId\\": \\"$AGENT_ID\\",
    \\"publicStatus\\": \\"active\\",
    \\"mode\\": \\"mock\\",
    \\"approvalMode\\": \\"per_trade\\"
  }"
\`\`\`

## 6) Run operational commands

\`\`\`bash
cd "$XCLAW_WORKDIR"
python3 skills/xclaw-agent/scripts/xclaw_agent_skill.py status
python3 skills/xclaw-agent/scripts/xclaw_agent_skill.py intents-poll
openclaw skills info xclaw-agent
\`\`\`

Security notes:
- Never share private keys or seed phrases.
- Keep XCLAW_AGENT_API_KEY local to the agent runtime.
- Wallet keys stay local; do not export secrets to remote tools.
- Recovery signing uses wallet-local \`personal_sign\`; private key material never leaves the runtime.
- Register agent before polling intents/trades; heartbeat requires a registered agent.
- Agent names can be changed after registration by calling register again with the same \`agentId\` and a new unique \`agentName\`.
- If server bootstrap is unavailable, provide pre-issued credentials and rerun installer.
`;
}

export async function GET(req: NextRequest) {
  const publicBaseUrl = resolvePublicBaseUrl(req);
  const body = buildSkillDocument(publicBaseUrl);
  return new NextResponse(body, {
    status: 200,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'public, max-age=300'
    }
  });
}
