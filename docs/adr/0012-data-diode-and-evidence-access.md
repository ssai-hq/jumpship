# ADR-012: Data Diode and Evidence Access

- Status: Accepted
- Date: 2026-07-17
- Owners: security/data owner, API owner
- Supersedes: None
- Superseded by: None

## Context and decision

Raw customer evidence never transits Vercel, shared RDS, SQS, Mothership, central telemetry, or cross-migration quality. Cells export only typed, classified, bounded projections. A browser accesses one restricted artifact through a one-use, short-lived, no-store capability issued by the backend.

## Alternatives and rejection

Shared proxies, generic JSON exports, presigned prefixes, and hashing of low-entropy values create uncontrolled or reversible data paths.

## Consequences, migration, and rollback

Every boundary contract declares maximum data class/size and fails closed. Later packets own contract linting and runtime export checks. There is no MVP exception path; a new flow requires coordinated ADR, threat, contract, IAM/network, and test changes.

## Traceability

- Capabilities: `MVP-CAP-ARCH-TRUST-DOMAINS`, `MVP-CAP-CREDENTIAL-CUSTODY`, `MVP-CAP-CROSS-MIGRATION-LEARNING`
- Acceptance: `JSMVP-R007`, later evidence-boundary rows
- Evidence: [`../security/data-classification-and-flows.md`](../security/data-classification-and-flows.md)
