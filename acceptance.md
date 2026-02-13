# Slice 03 Acceptance Evidence

Date (UTC): 2026-02-13
Active slice: `Slice 03: Agent Runtime CLI Scaffold (Done-Path Ready)`

## Pre-flight Baseline
- Workspace was already dirty before this change.
- Scope guard enforced: edits limited to declared Slice 03 allowlist.

## Objective + Scope Lock
- Objective: complete Slice 03 command-surface reliability and JSON error semantics.
- Cross-slice rule honored: real wallet behavior remains deferred to Slice 04+.

## File-Level Evidence (Slice 03)
- Runtime/wrapper behavior:
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `skills/xclaw-agent/scripts/xclaw_agent_skill.py`
  - `apps/agent-runtime/README.md`
  - `docs/api/WALLET_COMMAND_CONTRACT.md`
- Slice/process artifacts:
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`

## Verification Commands and Outcomes

### Required global gates
- Executed with:
  - `source ~/.nvm/nvm.sh && nvm use --silent default`
- `npm run db:parity` -> PASS (exit 0)
  - `"ok": true`
  - `"missingTables": []`
- `npm run seed:reset` -> PASS (exit 0)
- `npm run seed:load` -> PASS (exit 0)
  - scenarios: `happy_path`, `approval_retry`, `degraded_rpc`, `copy_reject`
- `npm run seed:verify` -> PASS (exit 0)
  - `"ok": true`
- `npm run build` -> PASS (exit 0)
  - Next.js production build completed.

### Runtime CLI wallet command matrix
- `apps/agent-runtime/bin/xclaw-agent status --json` -> PASS (JSON)
- `apps/agent-runtime/bin/xclaw-agent wallet health --chain base_sepolia --json` -> PASS (JSON)
- `apps/agent-runtime/bin/xclaw-agent wallet create --chain base_sepolia --json` -> PASS (JSON `code: not_implemented`)
- `apps/agent-runtime/bin/xclaw-agent wallet import --chain base_sepolia --json` -> PASS (JSON `code: not_implemented`)
- `apps/agent-runtime/bin/xclaw-agent wallet address --chain base_sepolia --json` -> PASS (JSON `code: wallet_missing` when wallet absent)
- `apps/agent-runtime/bin/xclaw-agent wallet sign-challenge --message "m" --chain base_sepolia --json` -> PASS (JSON `code: not_implemented`)
- `apps/agent-runtime/bin/xclaw-agent wallet send --to 0x0000000000000000000000000000000000000001 --amount-wei 1 --chain base_sepolia --json` -> PASS (JSON `code: not_implemented`)
- `apps/agent-runtime/bin/xclaw-agent wallet balance --chain base_sepolia --json` -> PASS (JSON `code: not_implemented`)
- `apps/agent-runtime/bin/xclaw-agent wallet token-balance --token 0x0000000000000000000000000000000000000001 --chain base_sepolia --json` -> PASS (JSON `code: not_implemented`)
- `apps/agent-runtime/bin/xclaw-agent wallet remove --chain base_sepolia --json` -> PASS (JSON)

### Wrapper delegation smoke
- Executed with minimal PATH to prove repo-local fallback:
  - `env -i PATH=/usr/bin:/bin XCLAW_DEFAULT_CHAIN=base_sepolia python3 skills/xclaw-agent/scripts/xclaw_agent_skill.py ...`
- `... wallet-health` -> PASS (delegated runtime JSON, exit 0)
- `... wallet-create` -> PASS (delegated runtime JSON `code: not_implemented`, exit 1)
- `... wallet-remove` -> PASS (delegated runtime JSON, exit 0)

### Negative/failure-path checks
- `... wallet-send bad 1` -> PASS (`code: invalid_input`, exit 2)
- `... wallet-send 0x0000000000000000000000000000000000000001 abc` -> PASS (`code: invalid_input`, exit 2)
- `... wallet-sign-challenge ""` -> PASS (`code: invalid_input`, exit 2)
- `... wallet-token-balance bad` -> PASS (`code: invalid_input`, exit 2)

## Slice Status Synchronization
- `docs/XCLAW_SLICE_TRACKER.md` Slice 03 set to `[x]` with all DoD boxes checked.
- `docs/XCLAW_BUILD_ROADMAP.md` active runtime scaffold checklist items updated in Section 7.

## High-Risk Review Protocol
- Security-sensitive path: wallet command routing and validation.
- Second-opinion pass: completed as an independent re-read of runtime/wrapper error and binary-resolution paths before acceptance logging.
- Rollback plan:
  1. revert only Slice 03 touched files,
  2. rerun required gates and command matrix,
  3. confirm Slice 03 status entries restored accordingly.

## Blockers
- None.

## Pre-Step Checkpoint (Before Slice 04)
- Date (UTC): 2026-02-13
- Action: Added governance rule in `AGENTS.md` requiring commit+push after each fully-tested slice.
- Action: Checkpoint commit/push created before Slice 04 implementation work.

## Slice 04 Acceptance Evidence

Date (UTC): 2026-02-13
Active slice: `Slice 04: Wallet Core (Create/Import/Address/Health)`

### Pre-step checkpoint evidence
- Separate checkpoint commit before Slice 04: `cb22213`
- Commit pushed to `origin/main` prior to Slice 04 implementation.
- Governance rule added in `AGENTS.md`: each fully-tested slice must be committed and pushed before next slice.

### File-level evidence (Slice 04)
- Runtime implementation:
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `apps/agent-runtime/requirements.txt`
  - `apps/agent-runtime/tests/test_wallet_core.py`
  - `apps/agent-runtime/README.md`
- Contract/docs/process:
  - `docs/api/WALLET_COMMAND_CONTRACT.md`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`

### Environment blockers and resolution
- Blocker: `python3 -m pip` unavailable (`No module named pip`).
- Blocker: `python3 -m venv` unavailable (`ensurepip` missing).
- Resolution used: bootstrap user pip via:
  - `curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py`
  - `python3 /tmp/get-pip.py --user --break-system-packages`
- Dependency install command used:
  - `python3 -m pip install --user --break-system-packages -r apps/agent-runtime/requirements.txt`

### Unit/integration test evidence
- `python3 -m unittest apps/agent-runtime/tests/test_wallet_core.py -v` -> PASS
  - roundtrip encrypt/decrypt passes
  - malformed payload rejected
  - non-interactive create/import rejected
  - unsafe permission check rejected
  - missing wallet address path validated

### Required global gate evidence
Executed with:
- `source ~/.nvm/nvm.sh && nvm use --silent default`

Results:
- `npm run db:parity` -> PASS (`"ok": true`)
- `npm run seed:reset` -> PASS
- `npm run seed:load` -> PASS
- `npm run seed:verify` -> PASS (`"ok": true`)
- `npm run build` -> PASS

### Runtime wallet core evidence
- Interactive create (TTY) command:
  - `apps/agent-runtime/bin/xclaw-agent wallet create --chain base_sepolia --json`
  - result: `ok:true`, `message:"Wallet created."`, address returned.
- Address command:
  - `apps/agent-runtime/bin/xclaw-agent wallet address --chain base_sepolia --json`
  - result: `ok:true`, chain-bound address returned.
- Health command:
  - `apps/agent-runtime/bin/xclaw-agent wallet health --chain base_sepolia --json`
  - result: real state fields returned (`hasCast`, `hasWallet`, `metadataValid`, `filePermissionsSafe`).
- Interactive import (TTY) command in isolated runtime home:
  - `XCLAW_AGENT_HOME=/tmp/xclaw-s4-import/.xclaw-agent apps/agent-runtime/bin/xclaw-agent wallet import --chain base_sepolia --json`
  - result: `ok:true`, `imported:true`, address returned.

### Negative/security-path evidence
- Non-interactive create rejected:
  - `wallet create ... --json` -> `code: non_interactive`, exit `2`
- Non-interactive import rejected:
  - `wallet import ... --json` -> `code: non_interactive`, exit `2`
- Unsafe permission rejection:
  - wallet file mode `0644` -> `wallet health` returns `code: unsafe_permissions`, exit `1`
- Malformed encrypted payload rejection:
  - invalid base64 crypto fields -> `wallet health` returns `code: wallet_store_invalid`, exit `1`
- Plaintext artifact scan:
  - `rg` scan across wallet dirs found no persisted test passphrases/private-key literal.

### Slice status synchronization
- `docs/XCLAW_SLICE_TRACKER.md` Slice 04 set to `[x]` with all DoD boxes checked.
- `docs/XCLAW_BUILD_ROADMAP.md` updated for runtime wallet manager, portable wallet model, and plaintext-artifact guard.

### Dependency and supply-chain notes
- Added `argon2-cffi==23.1.0`
  - Purpose: Argon2id key derivation for wallet at-rest encryption key.
  - Risk note: mature package with bindings-only scope; used strictly for local KDF.
- Added `pycryptodome==3.21.0`
  - Purpose: Keccak-256 hashing for deterministic EVM address derivation from private key.
  - Risk note: mature crypto library; scoped to local address derivation only.

### High-risk review protocol
- Security-sensitive class: wallet key storage and secret handling.
- Second-opinion review pass: completed via focused re-review of command error paths, encryption metadata handling, and permission fail-closed behavior.
- Rollback plan:
  1. revert Slice 04 touched files only,
  2. rerun required npm gates + wallet command checks,
  3. confirm tracker/roadmap/docs return to pre-Slice-04 state.

## Slice 05 Acceptance Evidence

Date (UTC): 2026-02-13
Active slice: `Slice 05: Wallet Auth + Signing`
Issue mapping: `#5` (`Epic: Python agent runtime core (wallet + strategy + execution)`)

### Objective + scope lock
- Objective: implement `wallet-sign-challenge` for local EIP-191 auth/recovery signing with canonical challenge validation.
- Scope guard honored: no Slice 06 command implementation, no server/web API contract changes.

### File-level evidence (Slice 05)
- Runtime implementation:
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `apps/agent-runtime/tests/test_wallet_core.py`
  - `apps/agent-runtime/README.md`
- Contract/docs/process:
  - `docs/api/WALLET_COMMAND_CONTRACT.md`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`

### Environment unblock evidence
- Foundry installed for cast-backed signing:
  - `curl -L https://foundry.paradigm.xyz | bash`
  - `~/.foundry/bin/foundryup`
- Runtime signer evidence:
  - `~/.foundry/bin/cast --version` -> `cast 1.5.1-stable`

### Unit/integration test evidence
- `PATH="$HOME/.foundry/bin:$PATH" python3 -m unittest apps/agent-runtime/tests/test_wallet_core.py -v` -> PASS
- Coverage includes:
  - empty message rejection
  - missing wallet
  - malformed challenge shape
  - chain mismatch
  - stale timestamp
  - non-interactive passphrase rejection
  - missing cast dependency
  - happy-path signing with signature shape + scheme assertions

### Required global gate evidence
Executed with:
- `source ~/.nvm/nvm.sh && nvm use --silent default`

Results:
- `npm run db:parity` -> PASS (`"ok": true`)
- `npm run seed:reset` -> PASS
- `npm run seed:load` -> PASS
- `npm run seed:verify` -> PASS (`"ok": true`)
- `npm run build` -> PASS

### Runtime wallet-sign evidence
- Signing success command:
  - `XCLAW_WALLET_PASSPHRASE=passphrase-123 apps/agent-runtime/bin/xclaw-agent wallet sign-challenge --message "<canonical>" --chain base_sepolia --json`
  - result: `ok:true`, `code:"ok"`, `scheme:"eip191_personal_sign"`, `challengeFormat:"xclaw-auth-v1"`, 65-byte hex signature.
- Signature verification against address (server-side format expectation proxy):
  - `cast wallet verify --address <address> "<canonical>" "<signature>"`
  - result: `Validation succeeded.`
- Invalid challenge (missing keys):
  - result: `code:"invalid_challenge_format"`
- Empty challenge:
  - result: `code:"invalid_input"`
- Non-interactive signing without passphrase:
  - result: `code:"non_interactive"`
- Missing cast on PATH:
  - result: `code:"missing_dependency"`

### Slice status synchronization
- `docs/XCLAW_SLICE_TRACKER.md` Slice 05 set to `[x]` with all DoD items checked.
- `docs/XCLAW_BUILD_ROADMAP.md` runtime checklist updated:
  - cast backend integration for wallet/sign/send marked done.
  - wallet challenge-signing command marked done.

### High-risk review protocol
- Security-sensitive class: wallet signing/auth path.
- Second-opinion review pass: completed via focused re-review of challenge parsing, passphrase gating, and cast invocation error handling.
- Rollback plan:
  1. revert Slice 05 touched files only,
  2. rerun unittest + required npm gates,
  3. verify tracker/roadmap/source-of-truth return to pre-Slice-05 state.

## Slice 06 Acceptance Evidence

Date (UTC): 2026-02-13
Active slice: `Slice 06: Wallet Spend Ops (Send + Balance + Token Balance + Remove)`
Issue mapping: `#6` (`Slice 06: Wallet Spend Ops`)

### Objective + scope lock
- Objective: implement runtime wallet spend and balance operations with fail-closed policy preconditions.
- Scope guard honored: no server/web API or migration changes, no Slice 07+ runtime loop implementation.

### File-level evidence (Slice 06)
- Runtime implementation:
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `apps/agent-runtime/tests/test_wallet_core.py`
  - `apps/agent-runtime/README.md`
- Contract/docs/process:
  - `docs/api/WALLET_COMMAND_CONTRACT.md`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`

### Unit/integration test evidence
- `PATH="$HOME/.foundry/bin:$PATH" python3 -m unittest apps/agent-runtime/tests/test_wallet_core.py -v` -> PASS
- Coverage includes:
  - `wallet-send` policy fail-closed for missing policy file
  - `wallet-send` blocked on chain disabled, paused state, approval required, and daily cap exceeded
  - `wallet-send` success path with tx hash + ledger update
  - `wallet-balance` and `wallet-token-balance` success paths
  - `wallet-token-balance` invalid token rejection
  - `wallet-remove` multi-chain cleanup semantics

### Required global gate evidence
Executed with:
- `source ~/.nvm/nvm.sh && nvm use --silent default`

Results:
- `npm run db:parity` -> PASS (`"ok": true`)
- `npm run seed:reset` -> PASS
- `npm run seed:load` -> PASS
- `npm run seed:verify` -> PASS (`"ok": true`)
- `npm run build` -> PASS

### Task-specific runtime evidence (Hardhat-local-first)
- Local EVM runtime:
  - `anvil --host 127.0.0.1 --port 8545` started with chain id `31337` (Hardhat-local equivalent RPC target).
  - `cast chain-id --rpc-url http://127.0.0.1:8545` -> `31337`
- Wallet balance:
  - `XCLAW_AGENT_HOME=/tmp/xclaw-s6-manual/.xclaw-agent apps/agent-runtime/bin/xclaw-agent wallet balance --chain hardhat_local --json`
  - result: `code:"ok"`, `balanceWei:"10000000000000000000000"`
- Wallet send:
  - `XCLAW_WALLET_PASSPHRASE=passphrase-123 ... wallet send --to 0x70997970... --amount-wei 1000000000000000 --chain hardhat_local --json`
  - result: `code:"ok"`, `txHash:"0x340e551eb7da5046b910948318357dc7c2becb0d39f79d9e4373889fe739878a"`, `dailySpendWei:"1000000000000000"`
- Wallet token balance:
  - deployed deterministic test contract (`cast send --create ...`) at `0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512`
  - `... wallet token-balance --token 0xe7f1725E... --chain hardhat_local --json`
  - result: `code:"ok"`, `balanceWei:"42"`
- Policy-blocked send proof:
  - with `spend.approval_granted=false`, send command returns:
  - `code:"approval_required"`, `message:"Spend blocked because approval is required but not granted."`

### Slice status synchronization
- `docs/XCLAW_SLICE_TRACKER.md` Slice 06 set to `[x]` with all DoD items checked.
- `docs/XCLAW_BUILD_ROADMAP.md` updated for implemented wallet spend ops and active spend precondition gate.
- `docs/XCLAW_SOURCE_OF_TRUTH.md` issue mapping aligned to slice order and wallet implementation status updated for Slice 06.

### High-risk review protocol
- Security-sensitive class: wallet spend path and local policy gating.
- Second-opinion review pass: completed via focused re-review of policy fail-closed behavior, RPC/chain config loading, and secret-handling boundaries in send flow.
- Rollback plan:
  1. revert Slice 06 touched files only,
  2. rerun unittest + required npm gates,
  3. verify tracker/roadmap/source-of-truth and wallet contract docs return to pre-Slice-06 state.

## Pre-Slice 07 Control-Gate Evidence

Date (UTC): 2026-02-13
Checkpoint objective: complete roadmap Section `0.1 Control setup` and re-validate required gates before starting Slice 07.

### Control setup verification
- Branch strategy confirmed:
  - current branch: `main`
  - `gh api repos/fourtytwo42/ETHDenver2026/branches/main/protection` -> `404 Branch not protected`
  - recorded strategy: feature-branch-per-slice + mandatory commit/push checkpoint before starting next slice.
- Issue mapping confirmed:
  - `gh issue list --limit 20 --json number,title | jq '[.[]|select(.number>=1 and .number<=16)] | length'` -> `16`
  - `gh issue view 7 --json number,title,state,url` -> open and mapped to Slice 07.
- Required artifact folders confirmed present and tracked:
  - `config/chains/`
  - `packages/shared-schemas/json/`
  - `docs/api/`
  - `infrastructure/migrations/`
  - `infrastructure/scripts/`
  - `docs/test-vectors/`

### Validation gates (re-run)
Executed with:
- `source ~/.nvm/nvm.sh && nvm use --silent default`

Results:
- `npm run db:parity` -> PASS (`"ok": true`)
- `npm run seed:reset && npm run seed:load && npm run seed:verify` -> PASS (`"ok": true`)
- `npm run build` -> PASS (Next.js build succeeded)

### Files updated for this checkpoint
- `docs/XCLAW_BUILD_ROADMAP.md`
- `docs/XCLAW_SLICE_TRACKER.md`
- `docs/XCLAW_SOURCE_OF_TRUTH.md`
- `acceptance.md`

## Slice 06A Acceptance Evidence

Date (UTC): 2026-02-13
Active slice: `Slice 06A: Foundation Alignment Backfill (Post-06 Prereq)`
Issue mapping: `#18` (`Slice 06A: Foundation Alignment Backfill (Post-06 Prereq)`)

### Objective + scope lock
- Objective: align server/web runtime location to canonical `apps/network-web` before Slice 07 API implementation.
- Scope guard honored: no Slice 07 endpoint/auth business logic was implemented.

### File-level evidence (Slice 06A)
- Web runtime alignment:
  - `apps/network-web/src/app/layout.tsx`
  - `apps/network-web/src/app/page.tsx`
  - `apps/network-web/src/app/globals.css`
  - `apps/network-web/src/app/page.module.css`
  - `apps/network-web/public/next.svg`
  - `apps/network-web/next.config.ts`
  - `apps/network-web/next-env.d.ts`
  - `apps/network-web/tsconfig.json`
- Tooling/config:
  - `package.json`
  - `tsconfig.json`
- Canonical/process synchronization:
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`

### Validation commands and outcomes
Executed with:
- `source ~/.nvm/nvm.sh`

Required gates:
- `npm run db:parity` -> PASS (`"ok": true`)
- `npm run seed:reset` -> PASS
- `npm run seed:load` -> PASS
- `npm run seed:verify` -> PASS (`"ok": true`)
- `npm run build` -> PASS (`next build apps/network-web`)

Slice-specific checks:
- `npm run dev -- --port 3100` + local HTTP probe -> PASS (`200`, server ready)
- `npm run start -- --port 3101` + local HTTP probe -> PASS (`200`, server ready)
- `test -d apps/network-web/src/app` -> PASS
- `test ! -d src` -> PASS
- `test ! -d public` -> PASS
- negative check `npx next build` (repo root without app dir) -> expected FAIL (`Couldn't find any pages or app directory`)
- runtime boundary smoke: `apps/agent-runtime/bin/xclaw-agent status --json` -> PASS (`ok: true`, scaffold healthy)

### Canonical synchronization evidence
- Tracker updated with new prerequisite slice and completion:
  - `docs/XCLAW_SLICE_TRACKER.md` Slice 06A status `[x]` and DoD boxes `[x]`.
- Roadmap updated to include 06A prerequisite and completion checklist:
  - `docs/XCLAW_BUILD_ROADMAP.md` sections `0.3` and `0.4`.
- Source-of-truth updated for sequence + issue mapping inclusion:
  - `docs/XCLAW_SOURCE_OF_TRUTH.md` section `15.1` and section `16`.

### Issue mapping and traceability
- Dedicated issue created for this slice:
  - `https://github.com/fourtytwo42/ETHDenver2026/issues/18`
- Note: `#17` already existed (closed, mapped to Slice 16), so Slice 06A mapping was assigned to `#18`.

### High-risk review mode note
- This slice touched runtime/build path and execution sequencing (operational risk class).
- Second-pass review performed on:
  - script path targets,
  - canonical path assumptions,
  - boundary preservation (Node/web vs Python/agent).

### Rollback plan
1. Revert Slice 06A touched files only.
2. Restore root app path (`src/`, `public/`) and script targets.
3. Re-run required gates (`db:parity`, `seed:*`, `build`) and structural smoke checks.

## Slice 07 Acceptance Evidence

Date (UTC): 2026-02-13  
Active slice: `Slice 07: Core API Vertical Slice`  
Issue mapping: `#7` (`https://github.com/fourtytwo42/ETHDenver2026/issues/7`)

### Objective + scope lock
- Objective: implement core API write/read surface in `apps/network-web` with bearer+idempotency baseline and canonical error contract.
- Scope guard honored: no Slice 08 session/step-up/auth-cookie implementation and no off-DEX endpoint implementation.

### File-level evidence (Slice 07)
- Runtime/server implementation:
  - `apps/network-web/src/lib/env.ts`
  - `apps/network-web/src/lib/db.ts`
  - `apps/network-web/src/lib/redis.ts`
  - `apps/network-web/src/lib/request-id.ts`
  - `apps/network-web/src/lib/errors.ts`
  - `apps/network-web/src/lib/agent-auth.ts`
  - `apps/network-web/src/lib/idempotency.ts`
  - `apps/network-web/src/lib/validation.ts`
  - `apps/network-web/src/lib/http.ts`
  - `apps/network-web/src/lib/ids.ts`
  - `apps/network-web/src/lib/trade-state.ts`
  - `apps/network-web/src/app/api/v1/agent/register/route.ts`
  - `apps/network-web/src/app/api/v1/agent/heartbeat/route.ts`
  - `apps/network-web/src/app/api/v1/trades/proposed/route.ts`
  - `apps/network-web/src/app/api/v1/trades/[tradeId]/status/route.ts`
  - `apps/network-web/src/app/api/v1/events/route.ts`
  - `apps/network-web/src/app/api/v1/public/leaderboard/route.ts`
  - `apps/network-web/src/app/api/v1/public/agents/route.ts`
  - `apps/network-web/src/app/api/v1/public/agents/[agentId]/route.ts`
  - `apps/network-web/src/app/api/v1/public/agents/[agentId]/trades/route.ts`
  - `apps/network-web/src/app/api/v1/public/activity/route.ts`
- Contract artifacts:
  - `docs/api/openapi.v1.yaml`
  - `packages/shared-schemas/json/agent-register-request.schema.json`
  - `packages/shared-schemas/json/agent-heartbeat-request.schema.json`
  - `packages/shared-schemas/json/trade-proposed-request.schema.json`
  - `packages/shared-schemas/json/event-ingest-request.schema.json`
  - `packages/shared-schemas/json/trade-status.schema.json`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
- Process/governance artifacts:
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `acceptance.md`
  - `package.json`
  - `package-lock.json`

### Dependency changes (pinned)
- `pg@8.13.3` (runtime): Postgres connectivity for API persistence.
- `redis@4.7.1` (runtime): idempotency key storage and replay/conflict enforcement.
- `ajv@8.17.1` (runtime): JSON-schema payload validation at API boundary.
- `@types/pg@8.15.0` (dev): strict TS typing support for `pg` use in Next route handlers.

Risk note:
- All added packages are mainstream, maintained ecosystem packages with narrowly scoped use in API boundary/persistence layers.

### Required global gate evidence
Executed with:
- `source ~/.nvm/nvm.sh && nvm use --silent default`

Results:
- `npm run db:parity` -> PASS (`"ok": true`)
- `npm run seed:reset` -> PASS
- `npm run seed:load` -> PASS
- `npm run seed:verify` -> PASS (`"ok": true`)
- `npm run build` -> PASS (all Slice 07 route handlers compile)

### API curl matrix evidence (selected)
Dev server launched with:
- `DATABASE_URL=postgresql://xclaw_app:xclaw_local_dev_pw@127.0.0.1:5432/xclaw_db`
- `REDIS_URL=redis://127.0.0.1:6379`
- `XCLAW_AGENT_API_KEYS={"ag_slice7":"slice7_token_abc12345"}`

Verified negative-path checks:
- Missing bearer on write route -> `401` + `code:"auth_invalid"`
- Missing `Idempotency-Key` -> `400` + `code:"payload_invalid"`
- Invalid register schema -> `400` + `code:"payload_invalid"` + validation details
- Reused idempotency key with changed payload -> `409` + `code:"idempotency_conflict"`

### Blocker (explicit)
- Positive-path DB-backed endpoint verification is blocked by local Postgres credential mismatch.
- Evidence:
  - `psql -h 127.0.0.1 -U xclaw_app -d xclaw_db` -> `FATAL: password authentication failed for user "xclaw_app"`
  - DB-backed API routes currently return `internal_error` under that credential set.

Unblock command pattern:
- Start dev server with valid local DB credentials and rerun Slice 07 curl matrix:
  - `source ~/.nvm/nvm.sh && nvm use --silent default && DATABASE_URL='<valid>' REDIS_URL='redis://127.0.0.1:6379' XCLAW_AGENT_API_KEYS='{"ag_slice7":"slice7_token_abc12345"}' npm run dev -- --port 3210`

### High-risk review protocol
- Security-sensitive class: API auth + idempotency + persistence write paths.
- Second-opinion review pass: completed as focused review of bearer enforcement, idempotency replay/conflict semantics, and canonical error shape consistency.
- Rollback plan:
  1. revert Slice 07 touched files only,
  2. rerun required gates,
  3. confirm tracker/roadmap/source-of-truth sync returns to pre-Slice-07 state.

### Slice 07 Blocker Resolution + Final Verification (2026-02-13)
- Resolved local DB credential blocker by creating a user-owned PostgreSQL cluster and canonical app credentials:
  - host/port: `127.0.0.1:55432`
  - db/user/password: `xclaw_db` / `xclaw_app` / `xclaw_local_dev_pw`
  - saved in `.env.local`, `apps/network-web/.env.local`, and `~/.pgpass` (600 perms)
- Applied migration fix required for reset validity:
  - `infrastructure/migrations/0001_xclaw_core.sql` changed `performance_snapshots.window` -> `performance_snapshots."window"`
  - aligned read queries in:
    - `apps/network-web/src/app/api/v1/public/leaderboard/route.ts`
    - `apps/network-web/src/app/api/v1/public/agents/[agentId]/route.ts`
- Fixed trade status endpoint positive-path DB type bug:
  - cast `$1` to `trade_status` in `apps/network-web/src/app/api/v1/trades/[tradeId]/status/route.ts`

Final Slice 7 curl matrix (all expected outcomes met):
- write path status codes: `401,400,400,200,200,409,200,200,409,400,200`
- public read path status codes: `200,200,200,200,200,404`
- verified positive endpoints:
  - register, heartbeat, trade proposed, trade status transition (`proposed -> approved`), events
  - leaderboard, agents search, profile, trades, activity
- verified negative/failure paths:
  - missing auth -> `auth_invalid`
  - missing idempotency -> `payload_invalid`
  - invalid schema -> `payload_invalid` with details
  - idempotency conflict -> `idempotency_conflict`
  - invalid trade transition -> `trade_invalid_transition`
  - path/body tradeId mismatch -> `payload_invalid`
  - unknown profile -> 404 with canonical error payload

Revalidated gates after fixes:
- `npm run db:parity` -> PASS
- `npm run build` -> PASS
