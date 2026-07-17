# Jumpship Product Contract

Jumpship is a chat-first, multi-tenant migration SaaS for a closed MVP corridor: MongoDB Atlas or a supported self-managed MongoDB source to either Supabase Postgres or PlanetScale Postgres. It reconstructs the selected application estate, data shape, workload behavior, and human decisions; proposes a durable PostgreSQL design; authors sealed application patches and customer-owned draft pull requests; and supervises migration execution and evidence.

## Customer outcome

The customer receives a defensible target model, versioned application changes, repeatable rehearsals, continuously reconciled CDC, a signed integrity result, a proven rollback path, a bounded watch period, and a deletion attestation. Every customer-visible assertion links to deterministic evidence rather than model confidence.

The customer remains the authority for validating, merging, and deploying application changes. Optional Codex or Claude Code review is separately authorized, advisory, and bound to an exact draft-PR head. It never acquires merge, deployment, consent, or traffic-authority power.

## Product interaction

One migration is one dominant workspace thread. Custody setup, the three mandatory connections, discovery, decisions, attempts, verification, cutover choreography, and watch state appear in that thread or in explicitly opened detail surfaces. The composer unlocks only after MongoDB, the selected PostgreSQL target, and GitHub are backend-proven connected; the first prompt atomically begins discovery.

Only cutover and decommission are product consent kinds. Foundation confirmation, design/spec approval, quarantine rulings, rubric confirmation, rehearsal start, and rollback are authenticated decisions or operations, but they do not enter the consent state machine.

## Closed scope

- One immutable compiled transform plan drives batch and change-event paths.
- Every selected repository, service, worker, queue, cron job, ORM, direct driver, and database writer is accounted for before cutover.
- Unknown or unfenceable writers, unresolved quarantine, stale application evidence, unhealthy reverse sync, or failed verification block progression.
- Automatic no-freeze dual write is explicitly deferred by ADR-021. The MVP exposes measured freeze and mandatory reverse sync; no product, API, automation, or sales surface may select the deferred tier.
- Jumpship is not a generic any-to-any data mover, application-modernization service, general APM product, DBA service, or customer operations team.

## Authority split

The conductor investigates, synthesizes, explains, and requests typed operations. The backend owns canonical product state and authorizes effects. Deterministic tools own record-path mechanics. Mothership owns only signed cell lifecycle reconciliation. Customer systems remain customer-owned, while raw evidence and temporary working copies stay inside one isolated migration cell.

The stable capability registry in [`contracts/capabilities/mvp.yaml`](./contracts/capabilities/mvp.yaml) is the public mechanical index for this contract. A record marked `planned` is a promise routed to future implementation, not evidence that it has shipped.
