# ADR-004: PostgreSQL Storage Baseline

- Status: Accepted
- Date: 2026-07-17
- Owners: data owner, architecture owner
- Supersedes: local alternate-dialect guidance
- Superseded by: None

## Context and decision

PostgreSQL 17.10 is the storage dialect across shared control and cell runtime state. Local development uses PostgreSQL semantics rather than a second database dialect. Shared and cell databases remain separate authorities with distinct schemas, roles, retention, and data classes.

## Alternatives and rejection

A second local dialect hides RLS, locking, transaction, JSON, extension, and migration incompatibilities. A single shared database for cell raw state violates custody and tenant boundaries.

## Consequences, migration, and rollback

P01/P03 provide pinned local PostgreSQL; P04/P05 own separate schemas and isolation tests. There is no MVP rollback to another dialect.

## Traceability

- Capabilities: `MVP-CAP-ARCH-TRUST-DOMAINS`, `MVP-CAP-AGENT-RUNTIME`
- Acceptance: `JSMVP-R001`, later persistence/isolation rows
- Evidence: [`../architecture/system-boundaries.md`](../architecture/system-boundaries.md)
