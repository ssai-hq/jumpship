# ADR-006: Canonical RDS PostgreSQL

- Status: Accepted
- Date: 2026-07-17
- Owners: data owner, infrastructure owner
- Supersedes: None
- Superseded by: None

## Context and decision

Private Multi-AZ RDS PostgreSQL is canonical production authority for shared identity and migration product state. Outbox/inbox, schedules, decisions, consent, release bindings, and audit derive from database transactions rather than queues or telemetry.

## Alternatives and rejection

Aurora adds cost/complexity before an RTO or read-scale need. Queue or trace authority cannot provide canonical transactional state.

## Consequences, migration, and rollback

P04 owns RLS, guarded transitions, migrations, backup/recovery, and failover evidence. Aurora/Multi-AZ cluster requires measured SLO pressure and a compatible migration ADR.

## Traceability

- Capabilities: `MVP-CAP-ARCH-TRUST-DOMAINS`
- Acceptance: `JSMVP-R001`, later data/recovery rows
- Evidence: [`../architecture/system-boundaries.md`](../architecture/system-boundaries.md)
