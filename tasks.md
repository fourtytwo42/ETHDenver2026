# Slice 10 Tasks

Active slice: `Slice 10: Management UI Vertical Slice`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice guardrails.
- [x] Reconcile issue `#10` scope with canonical Slice 10 DoD (include off-DEX queue/controls + audit panel).
- [x] Add management API routes for agent-state, approvals decision/scope, policy update, pause/resume, withdraw destination/withdraw, audit list, off-DEX decision, session helpers, and logout.
- [x] Add/extend management service + auth helpers for Slice 10 write/read enforcement and audit recording.
- [x] Add JSON schemas for Slice 10 request payloads and wire route validation.
- [x] Update `/agents/[agentId]` to render authorized management panels with loading/empty/error/degraded/unauthorized states.
- [x] Add header managed-agent dropdown + logout behavior and route auto-switch.
- [x] Update OpenAPI and auth wire examples for Slice 10 endpoint additions.
- [x] Run required global validation gates.
- [x] Run Slice-10 functional + negative-path verification matrix and capture evidence.
- [x] Update tracker/roadmap Slice 10 status after all validations pass.
- [x] Commit/push Slice 10 and post verification evidence + commit hash to issue `#10`.
