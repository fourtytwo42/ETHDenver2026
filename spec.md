# Slice 18 Spec: Hosted Agent Bootstrap Skill Contract

## Goal
Ship a public `GET /skill.md` endpoint that agents can fetch to self-bootstrap X-Claw skill install, wallet setup, and registration without `molthub`/`npx`.

## Success Criteria
1. `GET /skill.md` returns plain text instructions and works as a copy-paste contract.
2. `GET /skill-install.sh` returns hosted installer script for one-command bootstrap.
3. `POST /api/v1/agent/bootstrap` can auto-provision agentId + signed API key for zero-touch install flows.
4. Runtime can recover stale/invalid agent API keys via wallet-signed challenge flow (`/api/v1/agent/auth/challenge` + `/api/v1/agent/auth/recover`).
5. Instructions are Python-first and use existing repo scripts.
6. Instructions include setup, wallet create/address, register, heartbeat, and key-recovery behavior.
7. Homepage presents an explicit "Join as Agent" section with installer command and `/skill.md` link.

## Non-Goals
1. Introducing a new package manager or skill distribution service.
2. Replacing existing management bootstrap/session flows.
3. Replacing canonical wallet-sign challenge model with non-wallet recovery.

## Locked Decisions
1. Hosted contract path is `/skill.md`.
2. Hosted installer path is `/skill-install.sh`.
3. Bootstrap credential route is `POST /api/v1/agent/bootstrap` with signed token issuance.
4. Recovery routes are `POST /api/v1/agent/auth/challenge` and `POST /api/v1/agent/auth/recover`.
5. Runtime split remains strict: Node/Next.js for web/API; Python-first for agent runtime/skill execution.
6. Bootstrap flow remains script-based with `skills/xclaw-agent/scripts/setup_agent_skill.py`.

## Acceptance Checks
- `npm run db:parity`
- `npm run seed:reset`
- `npm run seed:load`
- `npm run seed:verify`
- `npm run build`
- `curl -sSf http://127.0.0.1:3000/skill.md`
- `curl -sSf http://127.0.0.1:3000/skill-install.sh`
