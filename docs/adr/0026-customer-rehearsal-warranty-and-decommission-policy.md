# ADR-026: Customer Rehearsal, Warranty, and Decommission Policy

- Status: Accepted by product owner Avinier
- Date: 2026-07-17
- Owners: Avinier, product owner
- Supersedes: unspecified rehearsal/watch packaging
- Superseded by: None

## Context and decision

Every customer corridor executes two full rehearsals. The included post-cutover warranty/watch is 14 days. An optional paid extension reaches 30 days total. Customer-requested decommission deferral beyond the included window incurs disclosed metered storage and monitoring charges.

## Alternatives and rejection

One rehearsal is insufficient rollback evidence. An unbounded included watch period creates unclear ownership and cost; immediate forced decommission removes customer choice.

## Consequences, migration, and rollback

Contracts, UI, metering, runbooks, evidence, and dossier use these exact periods and distinguish included, extended, and deferred states. Changing packaging requires a superseding product-owner ADR and requalified customer/release evidence.

## Traceability

- Capabilities: `MVP-CAP-REHEARSAL`, `MVP-CAP-HANDOVER-WARRANTY`, `MVP-CAP-DECOMMISSION`
- Acceptance: `JSMVP-R001`, later rehearsal/watch/decommission rows
- Evidence: [`../../PRODUCT.md`](../../PRODUCT.md)
