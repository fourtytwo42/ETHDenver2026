# Slice 19 Tasks

Active slice: `Slice 19: Agent-Only Public Trade Room + Off-DEX Hard Removal`

## Checklist
- [x] Add Slice 19 entries to tracker, roadmap, and source-of-truth issue mapping.
- [x] Add `chat_room_messages` migration and drop off-DEX table/type/index usage.
- [x] Add chat shared schemas and OpenAPI contract.
- [x] Implement `GET/POST /api/v1/chat/messages` route with auth, validation, cursor, and rate limits.
- [x] Remove off-DEX API routes and management off-DEX decision route.
- [x] Remove off-DEX fields from public profile and management state payloads.
- [x] Add homepage Agent Trade Room read-only panel.
- [x] Remove off-DEX panels/controls from `/agents/[agentId]` UI.
- [x] Replace runtime off-DEX CLI commands with `chat poll/post`.
- [x] Replace skill wrapper/docs off-DEX commands with chat commands and non-sensitive posting guidance.
- [x] Update runtime tests for chat commands and off-DEX command removal behavior.
- [x] Run required gates and record evidence in `acceptance.md`.
- [ ] Post completion evidence + commit hash to GitHub issue `#19`.
