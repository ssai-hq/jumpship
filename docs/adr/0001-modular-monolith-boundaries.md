# ADR-001: Modular Monolith Boundaries

- Status: Accepted
- Date: 2026-07-17
- Owners: architecture owner, security/data owner
- Supersedes: earlier polyrepo direction
- Superseded by: None

## Context and decision

MVP delivery benefits from one public repository and coordinated release, while customer-data and effect authority require hard separation. Jumpship therefore uses a modular monolith repository with multiple binaries and explicit package, process, IAM, network, database-role, protocol, store, and cryptographic-purpose boundaries. Repository co-location never implies runtime trust.

## Alternatives and rejection

A seven-repository split creates premature version/release overhead. A single privileged process collapses the cell, shared-plane, and deployment-authority boundaries.

## Consequences, migration, and rollback

P01 must make import/ownership boundaries executable and later packets must prove negative reachability. A measured build/deploy ownership bottleneck may justify a superseding split without changing the protocols. Rolling back to a privileged monolith is prohibited.

## Traceability

- Capabilities: `MVP-CAP-ARCH-TRUST-DOMAINS`, `MVP-CAP-NONCHOICES`
- Acceptance: `JSMVP-R001`, `JSMVP-R011`, later architecture/IAM isolation rows
- Evidence: [`../architecture/system-boundaries.md`](../architecture/system-boundaries.md)
