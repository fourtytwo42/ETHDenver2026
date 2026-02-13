# Slice 18 Tasks

Active slice: `Slice 18: Hosted Agent Bootstrap Skill Contract`

## Checklist
- [x] Add Slice 18 entries to tracker and roadmap.
- [x] Sync source-of-truth with hosted `/skill.md` contract requirements.
- [x] Implement `GET /skill.md` plain-text route in `apps/network-web`.
- [x] Implement `GET /skill-install.sh` installer script route in `apps/network-web`.
- [x] Implement `POST /api/v1/agent/bootstrap` for signed credential auto-provision.
- [x] Implement wallet-sign recovery API: `POST /api/v1/agent/auth/challenge` + `POST /api/v1/agent/auth/recover`.
- [x] Include setup + wallet + register + heartbeat command guidance in hosted content.
- [x] Add runtime auto-recovery for stale/invalid agent API keys (wallet signature challenge flow).
- [x] Add homepage join panel with direct command and link to `/skill.md`.
- [x] Run required global gates and hosted route checks in acceptance evidence.
