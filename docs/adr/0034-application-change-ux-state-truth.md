# ADR-034: Application-Change UX State Truth

- Status: Accepted
- Date: 2026-07-17
- Owners: product owner, web owner, application-delivery owner
- Supersedes: undifferentiated application-change progress UI
- Superseded by: None

## Context and decision

Application-change UX is owned by the product/frontend plan and objective comprehension/accessibility gates. The UI visibly distinguishes proposed change, sealed revision, draft PR publication, optional AI review, customer validation, merge, deployment, runtime proof, writer authority, blockers, and exact next actor/action. No visual state collapses these authorities into a generic success indicator.

## Alternatives and rejection

A single progress badge or agent narration lets users infer that review equals validation or that PR publication equals deployed compatibility.

## Consequences, migration, and rollback

P22/P24/P25 own exhaustive state fixtures, responsive/accessibility evidence, reconnect/staleness behavior, and customer comprehension tests. A tested replacement may supersede the layout only if state truth remains equally explicit.

## Traceability

- Capabilities: `MVP-CAP-SESSION-SHELL`, `MVP-CAP-APPLICATION-PR-DELIVERY`, `MVP-CAP-EXTERNAL-PR-REVIEW`, `MVP-CAP-WRITER-AUTHORITY-FENCING`
- Acceptance: `JSMVP-R001`, `JSMVP-R044`, later frontend/application rows
- Evidence: [`../../DESIGN.md`](../../DESIGN.md), [`../../PRODUCT.md`](../../PRODUCT.md)
