# ADR-005: Public and Cell Protocols

- Status: Accepted
- Date: 2026-07-17
- Owners: API owner, cell-control owner
- Supersedes: None
- Superseded by: None

## Context and decision

Browser/public APIs are OpenAPI-first REST plus cursor-resumable SSE. Cell control uses versioned protobuf/ConnectRPC over outbound mTLS. These protocols separate browser product semantics from long-lived cell control and allow generated clients and breaking-change checks.

## Alternatives and rejection

A shared ad-hoc JSON protocol weakens compatibility and classification enforcement. Browser-to-cell access or inbound cell listeners widen the trust boundary.

## Consequences, migration, and rollback

P02 owns schemas/code generation; P01 owns freshness hooks. Breaking public behavior requires a versioned path, and protobuf field numbers are never reused. A proven protocol limitation requires a superseding ADR.

## Traceability

- Capabilities: `MVP-CAP-AUTOMATION-SURFACE`, `MVP-CAP-ARCH-TRUST-DOMAINS`
- Acceptance: `JSMVP-R001`, later contract/protocol rows
- Evidence: [`../architecture/contract-versioning.md`](../architecture/contract-versioning.md)
