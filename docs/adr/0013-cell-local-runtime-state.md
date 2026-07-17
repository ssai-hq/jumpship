# ADR-013: Cell-Local Runtime State

- Status: Accepted
- Date: 2026-07-17
- Owners: cell owner, data owner
- Supersedes: None
- Superseded by: None

## Context and decision

Agent execution state, memory, context manifests, tool journals, engine checkpoints, and raw evidence live in Cell PostgreSQL/EBS/S3. Shared RDS remains canonical product authority and stores only approved durable outcomes and safe projections.

## Alternatives and rejection

Putting raw runtime state in shared RDS violates the diode and couples cell recovery to shared tenancy. Treating agent memory as canonical truth permits stale reasoning to override approved state.

## Consequences, migration, and rollback

Mothership restores runtime; the backend supplies the signed canonical checkpoint projection. Teardown consolidates approved outcomes and discards raw working memory. Enterprise recovery SLOs may justify per-cell RDS through a superseding ADR.

## Traceability

- Capabilities: `MVP-CAP-AGENT-RUNTIME`, `MVP-CAP-ARCH-TRUST-DOMAINS`, `MVP-CAP-AWS-CELL`
- Acceptance: `JSMVP-R007`, later cell-state/recovery rows
- Evidence: [`../architecture/system-boundaries.md`](../architecture/system-boundaries.md)
