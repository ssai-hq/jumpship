# ADR-014: Agent Runtime Freeze and Later Bakeoff

- Status: Accepted
- Date: 2026-07-17
- Owners: agent-runtime owner, architecture owner
- Supersedes: premature framework selection
- Superseded by: None

## Context and decision

The MVP freezes a custom Go reference loop through J19. A later isolated bakeoff may evaluate frameworks against the real Jumpship trajectory corpus, but may emit only a next-release proposal. It cannot alter the current image, AgentBundle, canonical state, provider, memory, or trust boundaries.

## Alternatives and rejection

Selecting a framework before the durable loop contract is implemented surrenders architecture to unmeasured defaults. Prohibiting evaluation forever would discard future evidence.

## Consequences, migration, and rollback

The reference loop must expose framework-neutral checkpoint/resume, wait, streaming, typed state, tool, and trace ports. Adoption later requires an approved ADR, checkpoint migration, compatibility proof, and full requalification.

## Traceability

- Capabilities: `MVP-CAP-AGENT-RUNTIME`
- Acceptance: `JSMVP-R001`, later agent conformance/quality rows
- Evidence: [`../architecture/contract-versioning.md`](../architecture/contract-versioning.md)
