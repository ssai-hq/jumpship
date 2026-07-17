# ADR-024: Durable Outer Loop and Bounded Inner Loop

- Status: Accepted
- Date: 2026-07-17
- Owners: agent-runtime owner, control-plane owner
- Supersedes: one-call-per-workflow and unbounded-think-loop models
- Superseded by: None

## Context and decision

The conductor uses a durable outer workflow with one renewable active-run lease and a bounded sequence of model/inline-observation iterations. Each model invocation ends in exactly one typed outcome and has a ContextManifest. Safe observations may continue inline; effects, blocking waits/decisions, and terminal outcomes require atomic durable transitions and receipts.

## Alternatives and rejection

Persisting after every harmless observation adds needless latency; keeping effects inside an ephemeral model turn loses crash/replay authority. Continuous reasoning wastes cost and weakens boundedness.

## Consequences, migration, and rollback

Every iteration advances append-only events/checkpoints and steering/budget checks. Inner operations are idempotent and recoverable. A qualified replacement must preserve the same leases, authority, receipt, and recovery contract.

## Traceability

- Capabilities: `MVP-CAP-AGENT-RUNTIME`, `MVP-CAP-PRIME-DIRECTIVE`
- Acceptance: `JSMVP-R001`, later reference-loop/recovery rows
- Evidence: [`../architecture/contract-versioning.md`](../architecture/contract-versioning.md)
