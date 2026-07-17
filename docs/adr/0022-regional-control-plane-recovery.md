# ADR-022: Regional Control-Plane Recovery

- Status: Accepted
- Date: 2026-07-17
- Owners: infrastructure owner, recovery owner
- Supersedes: active-active shared-plane assumptions
- Superseded by: None

## Context and decision

The shared plane uses a prepositioned cold/warm standby region and reconstructs delivery from canonical database authority after a separately approved failover. Migration cells remain independently regional and can continue safe local work/waits under their signed bindings.

## Alternatives and rejection

Active-active authority adds conflict resolution and signer/routing complexity before an MVP SLO requires it. Rebuilding state from queues or traces violates canonical authority.

## Consequences, migration, and rollback

Recovery binds two approvals, primary fence, restore point/root, reconciled provider journal, infrastructure readiness, release unit, expiry, and new control epoch. A simpler design must prove the same targets before superseding this ADR.

## Traceability

- Capabilities: `MVP-CAP-ARCH-TRUST-DOMAINS`, `MVP-CAP-AWS-CELL`
- Acceptance: `JSMVP-R001`, later recovery/failover rows
- Evidence: [`../architecture/system-boundaries.md`](../architecture/system-boundaries.md)
