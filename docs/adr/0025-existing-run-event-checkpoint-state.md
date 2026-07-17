# ADR-025: Existing Run, Event, and Checkpoint State

- Status: Accepted
- Date: 2026-07-17
- Owners: agent-runtime owner, data owner
- Supersedes: proposed episode/iteration service
- Superseded by: None

## Context and decision

An agent reasoning episode maps to existing `run_id`; ordered iterations map to `agent_events`; the renewable run/wakeup lease is the episode lease; working state lives in checkpoints; steering is ordered backend/conversation events. No separate episode/iteration service or table is added for MVP.

## Alternatives and rejection

New parallel state duplicates identity, leases, replay, and recovery before a measured need exists.

## Consequences, migration, and rollback

P05/P19 reuse and version these contracts. A measured post-MVP requirement needs a schema ADR, expand/compatibility migration, checkpoint converter, and requalification.

## Traceability

- Capabilities: `MVP-CAP-AGENT-RUNTIME`
- Acceptance: `JSMVP-R001`, later persistence/reference-loop rows
- Evidence: [`../architecture/contract-versioning.md`](../architecture/contract-versioning.md)
