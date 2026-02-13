# Slice 17 Tasks

Active slice: `Slice 17: Deposits + Agent-Local Limit Orders`

## Checklist
- [x] Add migration for deposit and limit-order tables/types.
- [x] Add shared schemas for deposit and limit-order payloads.
- [x] Implement management deposit endpoint with RPC polling and persistence.
- [x] Implement management limit-order create/list/cancel endpoints.
- [x] Implement agent limit-order pending + status endpoints.
- [x] Add management rail UI cards for deposit and limit-order controls.
- [x] Add agent runtime limit-order commands and local outbox replay behavior.
- [x] Update OpenClaw skill wrapper with limit-order commands.
- [x] Extend end-to-end script for deposit + limit-order + API-outage replay.
- [x] Add/extend runtime tests for limit-order path.
- [x] Run required global gates and capture outputs.
- [x] Sync source-of-truth, roadmap, and slice tracker.
