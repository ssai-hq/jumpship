# Jumpship

**Evidence-grounded MongoDB-to-managed-PostgreSQL migrations with a verifiable guarantee.**

Jumpship reconstructs how a company works from its code, MongoDB data, workloads, and human knowledge; designs a defensible PostgreSQL model for the customer's declared planning horizon; and supervises a safe, reversible migration into that model.

The conductor investigates, explains, and proposes. A deterministic Go engine performs every record transform, load, CDC apply, verification, reverse-sync effect, and safety gate. No model call sits in the record path.

## Product flow

```text
connect a MongoDB source, a managed-PostgreSQL target, and every migration-relevant repository
  -> isolated discovery and custody proof
  -> snapshot, census, multi-repository archaeology, and readiness
  -> target-model decisions and versioned mapping spec
  -> sealed application patches and customer-owned draft pull requests
  -> rehearsal, staged load, and quarantine resolution
  -> CDC, reconciliation, and signed verification
  -> customer validation, merge, deployment, and exact-runtime proof
  -> human-authorized cutover
  -> mandatory rollback window and post-cutover watch
  -> human-authorized decommission and deletion attestation
```

There are exactly two high-friction consent kinds: cutover and decommission. Design approval, quarantine rulings, verification-rubric confirmation, and rollback are authenticated decisions or operations, not additional consent kinds.

## Data and ownership boundaries

Jumpship deliberately separates permanent product state, temporary migration custody, and customer-owned databases:

| Boundary | Ownership and purpose |
|---|---|
| Shared control RDS | Permanent Jumpship application database: users, workspaces, auth, migrations, decisions, approved specs, consents, verdicts, safe evidence metadata, audit, and async coordination |
| Migration cell | Temporary Jumpship custody for one migration: Cell PostgreSQL, encrypted EBS, S3 Object Lock, agent execution state, checkpoints, CDC/quarantine state, and raw evidence |
| Customer source | Customer-owned MongoDB Atlas or supported self-managed MongoDB; baseline access is read-only/change-stream access |
| Customer target | Customer-owned Supabase Postgres or PlanetScale Postgres; Jumpship loads, verifies, and temporarily installs a private helper schema for fencing and idempotency |
| Customer repositories | Customer-owned selected repositories; Jumpship reads the migration-relevant estate, generates sealed patches, and opens draft PRs, while the customer alone validates, merges, and deploys |
| Telemetry backend | Redacted operational spans, metrics, and logs; useful for operations but never authoritative migration state |

Raw customer records, unredacted prompts, CDC payloads, quarantine bodies, and agent working memory never enter shared RDS. Shared services receive only allowlisted metadata, hashes, decisions, summaries, and scores. The migration cell is destroyed after rollback/watch closure and decommission; immutable objects or key deletion may complete later according to their disclosed retention windows.

## Runtime boundaries

- **Web:** Next.js on Vercel. Presentation and ephemeral UI state only.
- **Control API and coordinator:** Go services on ECS Fargate. Auth, workspaces, canonical migration state, gates, ledger, API, realtime, and operation authorization.
- **Mothership:** a narrow ECS infrastructure reconciler. It provisions, bootstraps, observes, restarts, revokes, and destroys cells from signed backend commands. It has no shared-RDS route and owns no migration semantics, evidence, prompts, approvals, or agent quality.
- **Migration cell:** one active isolated cell generation at a time for a migration. Discovery and final migration generations are replaced rather than privilege-upgraded in place. A cell hosts the conductor harness, deterministic engine, Cell PostgreSQL, encrypted working storage, and evidence.
- **Customer systems:** external source and target databases remain customer-owned. Jumpship does not host the permanent target.

## Non-negotiables

- One immutable compiled transform plan serves both batch and CDC drivers.
- Shared backend PostgreSQL alone owns canonical phase, approved spec, consent, traffic authority, and verification verdict.
- Customer data and agent execution state remain cell-local; a data diode permits only typed safe projections into the shared plane.
- Every ambiguity becomes a human answer or a ledgered reversible assumption. Foundation decisions cannot use the assumption escape hatch.
- Source writes, unresolved-quarantine progression, unverified cutover, consent bypass, premature deletion, agent self-lifecycle, and IAM widening are structurally denied.
- Every consequential effect is backend-authorized, idempotent, receipt-backed, and recoverable.
- Evidence, not model confidence, supports every customer-visible claim.
- Jumpship accounts for every selected repository, service, worker, queue, cron job, ORM, direct driver, and database writer before cutover; unknown or unfenceable writers block progression.
- Optional Codex or Claude Code review is advisory and bound to the exact draft-PR head. It never grants merge, deployment, consent, or traffic-authority power.

## Technology baseline

- Go 1.26.5 modular monolith with hard package, process, IAM, database, and trust boundaries.
- PostgreSQL 17.10 with `pgx/v5`, `sqlc`, and handwritten `goose` migrations.
- Next.js 16.2, React 19, strict TypeScript, Tailwind CSS v4, Radix, and TanStack Query.
- OpenAPI 3.1 REST, SSE with durable cursors, and protobuf/ConnectRPC cell control.
- AWS ECS Fargate, private Multi-AZ RDS, SQS/outbox, EC2 migration cells, EBS, S3 Object Lock, KMS, Secrets Manager, and Bedrock.
- OpenTofu infrastructure with GitHub OIDC; no long-lived AWS deployment keys.
- OpenTelemetry to AWS-supported observability paths. A specialized trace/search backend is added only after measured volume or query evidence justifies it.

## Status

Early and pre-first-migration. The repository currently contains guidance files only; the production scaffold and contracts have not yet been implemented.

The first implementation sequence is:

1. Reconcile repository truth, stable capability IDs, ADR index, and the accepted Apache-2.0 license decision.
2. Add the monorepo scaffold, version locks, local dependencies, and CI spine.
3. Add versioned contract schemas and generated-code drift checks.
4. Add control-plane and cell database baselines with RLS, grants, and isolation tests.
5. Prove a mock web -> API/outbox -> fake cell -> typed event -> web vertical slice.

## Source of truth

For internal development, the controlled implementation source of truth is:

```text
../mdhq/*MIGRATIONPIVOT/jumpship-docs/mvp-implementation/
```

Start with its `README.md` and `plan.md`, then use the focused plan and agent task packet for the work being implemented. Repository-wide implementation instructions live in [`AGENTS.md`](./AGENTS.md). Earlier Jumpship research, case-study flows, and repository history provide lineage only where they do not conflict with the current packet.

This repository is public. Never commit customer names, records, source code, credentials, connection strings, migration transcripts, prompts, traces containing customer material, or raw evidence.

Jumpship source code is licensed under the [Apache License 2.0](./LICENSE).
