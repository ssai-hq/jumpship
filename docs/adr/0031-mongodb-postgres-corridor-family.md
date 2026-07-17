# ADR-031: Closed MongoDB/PostgreSQL Corridor Family

- Status: Accepted
- Date: 2026-07-17
- Owners: product owner, corridor owner, architecture owner
- Supersedes: generic any-source/any-target implication
- Superseded by: None

## Context and decision

The MVP corridor family is `mongodb_postgres`: MongoDB Atlas or a supported self-managed MongoDB topology to either Supabase Postgres or PlanetScale Postgres. Immutable composed profiles declare snapshot/change-feed/load/rehearsal/verification physics and typed fallback/refusal. Framework-neutral ports do not constitute a generic any-to-any product promise.

## Alternatives and rejection

One hard-coded Atlas/Supabase path misses accepted target/source profiles. A generic engine claim cannot be qualified without per-pair canonical form, reverse transform, provider physics, and evidence.

## Consequences, migration, and rollback

P02 owns profile contracts; P07/P14 adapters/probes; engine packets consume exact profiles. Another corridor family requires separate contracts, packets, threat model, and qualification.

## Traceability

- Capabilities: `MVP-CAP-CORRIDOR-CONTRACT`, `MVP-CAP-CONNECT-MONGODB`, `MVP-CAP-CONNECT-POSTGRES-TARGET`, `MVP-CAP-TARGET-PROBE`
- Acceptance: `JSMVP-R001`, `JSMVP-R002`, later corridor rows
- Evidence: [`../../PRODUCT.md`](../../PRODUCT.md)
