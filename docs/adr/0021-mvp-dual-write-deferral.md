# ADR-021: MVP Automatic Dual-Write Deferral

- Status: Accepted
- Date: 2026-07-17
- Owners: product owner, engine owner, security/data owner
- Supersedes: living-source optional-tier implication for MVP
- Superseded by: None

## Context and decision

Automatic no-freeze dual write is explicitly outside the MVP sellable guarantee. The accepted capability record is `explicitly-deferred` with `result=not_applicable`, `reason=not_implemented_in_mvp`, and `public_selectable=false`. MVP uses a measured freeze/drain plus mandatory reverse-sync rollback window.

## Alternatives and rejection

Claiming the tier without implementation, threat model, 100% comparison, application writer fencing, and qualification would create split authority and a false guarantee.

## Consequences, migration, and rollback

API, UI, automation, and sales/catalog surfaces cannot select or advertise the tier. Reopening requires a separately contracted tier, owned implementation packet, threat-model delta, applicability contract, and full proof/release qualification.

## Traceability

- Capabilities: `MVP-CAP-DUAL-WRITE`, `MVP-CAP-WRITER-AUTHORITY-FENCING`
- Acceptance: `JSMVP-R001`, `JSMVP-R002`, later applicability/authority rows
- Evidence: [`../../contracts/capabilities/mvp.yaml`](../../contracts/capabilities/mvp.yaml)
