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
