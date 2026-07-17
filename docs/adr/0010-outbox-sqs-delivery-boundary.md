# ADR-010: Outbox and SQS Delivery Boundary

- Status: Accepted
- Date: 2026-07-17
- Owners: control-plane owner, data owner
- Supersedes: queue-as-workflow assumptions
- Superseded by: None

## Context and decision

PostgreSQL state machines and transactional outbox/inbox records own workflow authority. SQS and Scheduler carry only typed shared-plane delivery/wakeup identities and hashes. Cells do not use SQS as their workflow or durable checkpoint substrate.

## Alternatives and rejection

Queue authority makes replay, audit, and transaction boundaries ambiguous. Adding a cell broker service duplicates Cell PostgreSQL and complicates isolated recovery.

## Consequences, migration, and rollback

Consumers reconcile idempotently against database truth; delivery loss or duplication cannot advance state by itself. There is no MVP reopening condition.

## Traceability

- Capabilities: `MVP-CAP-ARCH-TRUST-DOMAINS`, `MVP-CAP-AGENT-RUNTIME`
- Acceptance: `JSMVP-R001`, later async/recovery rows
- Evidence: [`../security/data-classification-and-flows.md`](../security/data-classification-and-flows.md)
