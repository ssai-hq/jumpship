# ADR-002: Source Precedence and Product Scope

- Status: Accepted
- Date: 2026-07-17
- Owners: product owner, architecture owner
- Supersedes: incompatible repository-era product claims
- Superseded by: None

## Context and decision

The frozen MVP baseline supersedes older repository, sprint, and research claims where they conflict. Jumpship is a production chat-first multi-tenant migration SaaS with exactly two consent kinds and a closed MongoDB-to-managed-PostgreSQL corridor; it is not defined by an earlier local engine surface.

## Alternatives and rejection

Treating all historical documents as equal authority makes scope and safety contradictory. Rewriting history would remove useful lineage.

## Consequences, migration, and rollback

Public truth documents and the capability registry name the accepted scope while history remains readable as lineage. A newer accepted product master may supersede this ADR through baseline change control.

## Traceability

- Capabilities: `MVP-CAP-ACCESS-MANIFEST`, `MVP-CAP-PRIME-DIRECTIVE`, `MVP-CAP-NONCHOICES`
- Acceptance: `JSMVP-R001`, `JSMVP-R011`
- Evidence: [`../../PRODUCT.md`](../../PRODUCT.md), [`../architecture/README.md`](../architecture/README.md)
