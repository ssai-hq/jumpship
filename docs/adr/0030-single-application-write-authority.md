# ADR-030: Single Application Write Authority

- Status: Accepted, safety-critical
- Date: 2026-07-17
- Owners: application-delivery owner, engine owner, security/data owner
- Supersedes: informal freeze/flip sequencing
- Superseded by: None

## Context and decision

Non-atomic service deployments use a fenced rolling protocol. One global application-authority epoch is distinct from the cell write epoch and each cohort grant generation. Every writer is inventoried and bound to exact build/config/runtime evidence. Source is fenced and drained before target cohorts activate; target is fenced and reverse-drained before a proven source-resume stream and fresh source grants. Source and target application writes are never simultaneously enabled.

## Alternatives and rejection

DNS/config flips, manual writer checklists, or dual-store fallback cannot prove one authority across workers, queues, cron, mobile/offline clients, scripts, and direct users.

## Consequences, migration, and rollback

Unknown/offline/unfenceable writers and unattributed writes enter safe refusal or `authority_conflict_frozen`. Partial activation remains one-sided. Only a separately qualified ADR-021 tier may change this invariant.

## Traceability

- Capabilities: `MVP-CAP-WRITER-CENSUS`, `MVP-CAP-WRITER-AUTHORITY-FENCING`, `MVP-CAP-CUTOVER-CHOREOGRAPHY`, `MVP-CAP-REVERSE-ROLLBACK`
- Acceptance: `JSMVP-R002`, later writer/cutover/rollback rows
- Evidence: [`../architecture/system-boundaries.md`](../architecture/system-boundaries.md)
