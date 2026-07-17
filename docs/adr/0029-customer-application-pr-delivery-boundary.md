# ADR-029: Customer Application PR Delivery Boundary

- Status: Accepted
- Date: 2026-07-17
- Owners: product owner, application-delivery owner, security owner
- Supersedes: report-only application guidance
- Superseded by: None

## Context and decision

Jumpship discovers the complete selected application estate, authors migration-scoped sealed changes, and automatically/idempotently opens namespaced customer-owned draft PRs after one standing exact-repository grant. The customer alone validates, merges, and deploys. Cutover requires exact merge-equivalence and source-SHA-to-artifact-to-rollout-to-runtime proof.

## Alternatives and rejection

Advice without patches leaves the hardest migration work outside the product. Granting Jumpship merge/deploy/workflow authority violates customer control and expands compromise impact.

## Consequences, migration, and rollback

Head drift invalidates review/validation; changed revisions republish through provenance-bound identities. Jumpship exposes no merge or deploy operation. A new product contract may change delivery authority only with explicit owner approval and equal provenance/control.

## Traceability

- Capabilities: `MVP-CAP-APPLICATION-PR-DELIVERY`, `MVP-CAP-CONNECT-GITHUB`, `MVP-CAP-SEMANTIC-TRANSLATION`
- Acceptance: `JSMVP-R002`, later application-delivery rows
- Evidence: [`../../PRODUCT.md`](../../PRODUCT.md), [`../security/data-classification-and-flows.md`](../security/data-classification-and-flows.md)
