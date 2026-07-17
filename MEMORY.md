# Jumpship Memory

Running log of durable decisions and build state. Newest first. Keep entries dated; prune when superseded.

## 2026-07-17 — P00 architecture and capability baseline implemented

- The public repository now carries all 34 frozen ADRs, public architecture/security summaries, and the accepted Apache-2.0 license record.
- `contracts/capabilities/mvp.yaml` contains the closed 69-record MVP capability namespace plus stable customer-visible incapability IDs and the explicit automatic-dual-write deferral.
- `contracts/capabilities/mvp-source-anchors.yaml` binds logical source `jumpship-mvp-source-v1-2026-07-17`, the frozen source SHA-256, and every numbered occurrence and binding addendum content hash.
- The direct public checker has zero uncovered, orphaned, untestable, or ambiguous-anchor findings. The separate private-source checker compares a mounted source and can emit only a review candidate.
- P01 remains the next implementation packet. It owns the root dispatcher/toolchain scaffold and must delegate capability checking to P00's accepted entrypoint without changing normalized behavior.

## 2026-07-17 — P00 seed and license decision frozen

- The existing root-document edits are the official P00 seed and must be continued rather than discarded or independently recreated.
- The closed MVP corridor is MongoDB Atlas or supported self-managed MongoDB to Supabase Postgres or PlanetScale Postgres.
- Jumpship owns application-estate discovery, sealed patch generation, and draft-PR publication. Customers alone validate, merge, and deploy; Codex/Claude Code review remains advisory.
- Apache License 2.0 is the accepted public-source license for ADR-019. The canonical `LICENSE` file is present at the repository root.
- Avinier is the initial technical lead, security/data owner, product owner, and release owner for planning-baseline decisions. Independent approvals required by release contracts remain separate and cannot be self-approved merely because one founder holds several planning roles.
- The repository remains pre-scaffold. P00 completes capability/ADR truth; P01 owns runtime scaffold replacement and must preserve this seed's durable decisions.

## 2026-07-15 — Public repository reconciled to the production MVP packet

- The canonical internal source of truth is now `mdhq/*MIGRATIONPIVOT/jumpship-docs/mvp-implementation/`, which supersedes incompatible command-line-only and six-day-sprint guidance.
- Jumpship's MVP is a chat-first multi-tenant SaaS for the closed MongoDB-to-managed-PostgreSQL corridor, with exactly two high-friction consent kinds: cutover and decommission.
- The runtime is a modular monolith with hard trust boundaries: Vercel web, ECS control API/coordinator, narrow Mothership, and one isolated temporary AWS migration cell per migration.
- Shared control-plane RDS is permanent product authority. Agent/engine execution state and raw customer material remain cell-local. Customer source and target databases remain externally owned; only temporary encrypted migration copies enter Jumpship custody.
- Agent execution journals and working memory remain in Cell PostgreSQL. Shared RDS retains safe conversations, decisions, approved specifications, semantic timeline projections, evidence roots, verdicts, audit, and final handoff records. Redacted operational traces flow through OpenTelemetry rather than becoming product authority.
- Mothership has no shared-RDS route or migration semantics. It reconciles signed provision/bootstrap/heartbeat/restart/revoke/destroy commands and returns signed lifecycle receipts.
- The repository remains pre-scaffold and pre-first-migration. Next work is M0 source/capability/ADR reconciliation, then the M1 monorepo, contracts, local dependencies, and CI spine.

## 2026-07-08 — Repo initialized

- Monorepo created under `ssai-hq/jumpship` (public). Engine (Go), web, deploy, docs all in one repo — deliberate reversal of the earlier 7-repo polyrepo plan for MVP speed.
- Central brain: `mdhq/*MIGRATIONPIVOT/jumpship-docs/` in the ssai workspace — all planning/design docs for this repo go there (repo is public; docs stay private).
- At initialization, `fable-scaffold.md` was treated as the canonical build plan. It remains useful lineage for failure-mode invariants but is superseded by the 2026-07-15 production MVP implementation packet where they conflict.
- Nothing was built at initialization.

## Open threads

- Go module path: `github.com/ssai-hq/jumpship` — init when engine code starts.
