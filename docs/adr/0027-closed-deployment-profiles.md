# ADR-027: Closed Deployment Profiles

- Status: Accepted
- Date: 2026-07-17
- Owners: infrastructure owner, release owner, product owner
- Supersedes: open-ended environment composition
- Superseded by: None

## Context and decision

Deployment has exactly four profiles: `local`, `ephemeral-nonprod`, `persistent-nonprod`, and `paid-production`. `ephemeral-nonprod` is the implementation default. Only `paid-production` may hold customer data or a paid cutover. Qualification binds exact profile/version/hash and materialized inventory.

## Alternatives and rejection

Arbitrary environment flags create unreviewed security/cost combinations. Always-on nonproduction raises fixed cost without a measured need; a weaker profile cannot stand in for staging or production qualification.

## Consequences, migration, and rollback

P10 owns closed schemas, cost/readiness evidence, and refusal of mixed profiles. A new profile requires a measured need and a superseding ADR preserving security, recovery, support, evidence, and customer-data targets.

## Traceability

- Capabilities: `MVP-CAP-AWS-CELL`, `MVP-CAP-ARCH-TRUST-DOMAINS`
- Acceptance: `JSMVP-R001`, later deployment/cost/readiness rows
- Evidence: [`../architecture/contract-versioning.md`](../architecture/contract-versioning.md)
