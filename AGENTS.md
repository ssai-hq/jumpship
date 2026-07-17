# Jumpship Repository Instructions

Jumpship is the current SSAI product: a production SaaS and isolated migration system for the closed MongoDB-to-managed-PostgreSQL MVP corridor, supporting MongoDB Atlas or compatible self-managed MongoDB sources and Supabase Postgres or PlanetScale Postgres targets. It is not limited to a command-line migration engine, and the public repository is not the architecture authority.

## Source precedence

For internal work, use sources in this order:

1. The current user or product-owner instruction.
2. `../mdhq/*MIGRATIONPIVOT/jumpship-docs/mvp-implementation/`.
3. Other current Jumpship documents under `../mdhq/*MIGRATIONPIVOT/jumpship-docs/`.
4. Earlier research, case-study flows, `fable-scaffold.md`, and repository history only where compatible.

Read the implementation packet's `README.md`, `plan.md`, architecture contracts, threat model, relevant focused plan, and assigned task packet before changing production code. Implement one packet at a time and terminate against the acceptance rubric rather than subjective feature completeness.

## Product and execution model

- The product is a chat-first multi-tenant SaaS with auth, workspaces, shared APIs, evidence-linked decisions, live migration state, and exactly two consent kinds: cutover and decommission.
- The conductor preserves one evidence-grounded understanding across discovery, target-model design, migration operations, verification, and handoff.
- Jumpship discovers the complete selected application estate, generates sealed migration patches, and opens customer-owned draft pull requests. The customer alone validates, merges, and deploys; optional Codex/Claude Code review is advisory and exact-head-bound.
- The model authors judgments, questions, explanations, and versioned proposals. The deterministic Go engine owns record transforms, loads, CDC apply, reconciliation, verification, reverse sync, and gates.
- Batch and CDC must consume the same immutable compiled transform plan; two-driver parity is a merge gate.
- Every consequential effect requires backend authorization, a scoped grant, idempotency identity, and durable receipt reconciliation.
- Every application writer must be inventoried, source-fenced, and activated against one monotonic application-authority epoch; an unknown or unfenceable writer blocks cutover.

## Storage and custody boundaries

- **Shared control RDS is permanent Jumpship product authority.** It stores identity/workspace/auth state, canonical migration state, decisions, approved specs/rubrics, consent, safe evidence metadata, audit, outbox/inbox, schedules, and sanitized quality/release metadata.
- **Cell PostgreSQL is temporary per-migration execution state.** It stores agent checkpoints/events/waits/memory, context manifests, model invocation metadata, tool requests/receipts, and engine/CDC/load/quarantine/verification checkpoints.
- **Cell EBS and S3 hold raw customer evidence and working data.** Raw BSON, repo samples, CDC bodies, quarantine rows, manifests, and unredacted prompts never enter shared RDS, Vercel, SQS payloads, shared logs, or shared traces.
- **Customer source and target remain customer-owned external systems.** Jumpship keeps a temporary encrypted golden snapshot and working copies inside the cell, but it never hosts the permanent target.
- **Telemetry is non-authoritative.** OpenTelemetry/CloudWatch stores redacted operational signals. Shared RDS may keep safe semantic timeline projections, but traces never decide product state.
- Credentials and token values live only in Secrets Manager under scoped KMS. Databases and IaC state contain handles and lifecycle metadata only.

Before cell teardown, deterministically consolidate the durable customer-facing outcome into shared decisions, approved artifacts, evidence roots, verdicts, ledger entries, and the dossier. Do not preserve raw agent working memory merely for product continuity.

## Runtime authority

- The control API/coordinator owns product truth and compiles authorized desired state.
- Mothership only reconciles signed cell infrastructure lifecycle commands. It has no shared-RDS network path or database role and cannot read migration phase, prompts, evidence, secrets, or agent memory.
- The cell supervisor verifies the signed manifest and runtime identity but cannot author agent memory or engine effects.
- The cell harness may manage agent execution state and read safe engine summaries but cannot perform deterministic migration effects.
- The cell engine may perform only operations present in an exact signed grant and cannot mutate agent memory or canonical shared state.
- A cell agent, prompt, tool result, or engine cannot provision, restart, widen, or destroy its own infrastructure.

## Implementation constraints

- Use Go 1.26.5, PostgreSQL 17.10, `pgx/v5`, `sqlc`, and handwritten `goose` migrations.
- Use OpenTofu 1.11-compatible HCL. Do not add Terraform-specific workflow assumptions or long-lived AWS keys.
- Public REST is OpenAPI-first; browser events, cell protocols, mappings, manifests, tools, checkpoints, context, and proofs are versioned contracts with freshness checks.
- Shared workspace tables force RLS, use composite tenant foreign keys, and fail closed without transaction-local workspace/principal context.
- Safety-critical state changes occur through guarded functions or append-only transitions, not unrestricted CRUD.
- Schema changes use expand -> compatible code -> resumable backfill -> validate -> switch -> later cleanup. Never remove a shape while a live cell or rollback target references it.
- No EKS, Kafka, Step Functions, Redis durability, service mesh, standalone vector database, general shell/SQL/MCP, ambient AWS/IAM access, agent self-spawn, or LLM-driven CDC/watch loop in the MVP.
- Do not add a datastore, service, workflow framework, model provider, or permission because it is convenient. Binding architecture changes require an ADR and explicit approval.

## Repository discipline

- This repository is public. Fixtures must be synthetic; never commit customer data, code, credentials, prompts, transcripts, raw evidence, or identifying traces.
- Generated artifacts must ship with their drift/freshness check.
- Cloud deployment changes use GitHub OIDC and digest-pinned artifacts.
- Keep `MEMORY.md` to dated durable build state and decisions; do not duplicate the architecture packet in it.
- Report exact files changed, commands and results, generated artifacts, acceptance IDs, skipped tests, security/data-boundary implications, and unresolved dependencies.

## Current status

The repository is pre-scaffold and pre-first-migration. P00's repository truth, ADR register, security boundary, stable capability registry, and exact source-anchor manifest are present and mechanically checked. A `planned` registry record is not shipped behavior. The next authorized implementation is P01's monorepo, contract, local-development, and CI spine; do not infer that later planned directories or capabilities exist.
