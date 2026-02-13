# Slice 08 Tasks

Active slice: `Slice 08: Auth + Management Vertical Slice`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice guardrails.
- [x] Add management cookie/session/CSRF primitives in `apps/network-web/src/lib`.
- [x] Add management service flows (bootstrap, challenge, verify, revoke-all rotation).
- [x] Implement management auth validation helpers for session and CSRF enforcement.
- [x] Implement management API routes for bootstrap/challenge/verify/revoke-all.
- [x] Add minimal `/agents/[agentId]` bootstrap surface with `?token=` handling and URL stripping.
- [x] Add shared schema artifacts for management request payload validation.
- [x] Update OpenAPI and auth wire examples for Slice 08 behavior.
- [x] Run required global validation gates.
- [x] Run Slice 08 curl/browser matrix including negative-path checks.
- [x] Update process artifacts and acceptance evidence.
- [x] Mark Slice 08 complete in tracker/roadmap only after all validations pass.
- [ ] Post final verification evidence + commit hash to issue `#8`.
