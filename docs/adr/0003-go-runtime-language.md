# ADR-003: Go Runtime Language

- Status: Accepted
- Date: 2026-07-17
- Owners: architecture owner, engine owner
- Supersedes: None
- Superseded by: None

## Context and decision

Control API, coordinator, Mothership, reference harness loop, supervisor, and deterministic engine use Go 1.26.5. Go provides one deployable toolchain, bounded concurrency, static analysis, and mature PostgreSQL, MongoDB, AWS, protocol, and observability libraries. Python is not a record-path runtime.

## Alternatives and rejection

Multiple service languages increase recovery, supply-chain, and operating cost. A framework-selected harness language is premature before the frozen reference loop is measured.

## Consequences, migration, and rollback

P01 pins the toolchain; later engine/runtime packets own libraries and tests. A future isolated bakeoff may propose another harness runtime only if it materially improves outcomes without weakening boundaries or checkpoint migration.

## Traceability

- Capabilities: `MVP-CAP-ENGINE-STACK`, `MVP-CAP-AGENT-RUNTIME`
- Acceptance: `JSMVP-R001`, later build/runtime rows
- Evidence: [`../architecture/contract-versioning.md`](../architecture/contract-versioning.md)
