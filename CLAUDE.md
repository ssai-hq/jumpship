# Jumpship

MongoDB → Postgres migration engine with a verifiable guarantee. This is the SSAI Mission 3 MVP monorepo — everything (engine, web, deploy, docs) lives here.

## What we're building

The whole migration gets built, but the **guarantee is the product**: integrity verification, human-gated cutover/rollback, and an auditable reversibility ledger. The transform layer (profiling, schema synthesis, data movement) is built to be *good enough and verifiable*; the verification/cutover surface is built to be best in the world. General coding agents commoditize the transform — they structurally can't own the guarantee.

## The central brain

**`../mdhq/*MIGRATIONPIVOT/jumpship-docs/`** (in the parent ssai workspace, not this repo) is the central brain for this repo — planning docs, design notes, and session outputs for jumpship live there, never in the public repo. Check it first when picking up work.

The research foundation sits alongside it in `../mdhq/*MIGRATIONPIVOT/mission3-mongo-to-pg-research/`: `fable-scaffold.md` is the canonical design doc, and the 97-failure-mode catalog + mitigations are the spec for the guarantee surface. FM/M numbers referenced in code comments and commits point there.

## Load-bearing architectural constraints (decided; do not relitigate)

1. **LLM designs, deterministic engine executes.** Claude emits a declarative mapping spec; the Go engine executes it mechanically. Never put LLM calls in the data path — determinism is what makes checksum verification, reproducible rehearsals, and crash-resume possible.
2. **One transform library, two drivers.** Batch load and CDC apply share the same transform code (FM40 is fatal otherwise). CI gates on two-driver parity.
3. **Autonomy via reversibility, one consent gate.** Every cheap-to-undo decision is taken autonomously on disposable branches; the single human moment is business consent at cutover, given against the integrity proof.
4. **Customer data never lands in the control plane.** Hashes, counts, specs, decisions only. Bulk checksum manifests go to S3 as sorted Parquet.
5. **Scope: MongoDB → Postgres (Supabase/Neon family) only.** Firebase is corridor #2, unbuilt. No SaaS shell, no dashboard, no multi-tenancy until after migration #3.
6. **Engine you operate, not a SaaS you launch.** CLI + orchestrator, driven concierge-style.

## Repo layout

```
engine/          Go — the ssai-engine binary and all pipeline internals
  cmd/engine/    CLI entrypoint: profile|interrogate|synthesize|load|verify|tail|cutover|watch|inject
  internal/      profile, spec, transform, load, verify, cdc, cutover, ledger, controlplane, cognitive
  testdata/golden/  nasty-doc corpus → expected rows (CI gate on transform changes)
  tools/inject/  corruption injector (test-only, built day 1)
web/             frontend (readiness/integrity report rendering; later — no SaaS surface in MVP)
deploy/box/      dev: compose, golden-snapshot script
deploy/aws/      prod: Terraform — AMI, VPC-per-migration, KMS, S3 object-lock, CloudTrail
docs/            readiness-report + integrity-report templates, cutover runbook template
```

## Conventions

- Go for the engine; control plane is SQLite in dev, Postgres in prod (same schema).
- Reference failure modes as `FM<n>` and mechanisms as `M<n>` in comments/commits when a design choice exists because of one.
- MVP acceptance criteria live in fable-scaffold.md §8 (dirty-data gauntlet, crash-resume, two-driver parity, verification honesty, rollback rehearsal, security posture, no silent guesses). Features that don't serve one of these are out of scope.
- This repo is **public**. No customer names, connection strings, or migration transcripts ever get committed.

## Memory

`MEMORY.md` is the running project log — decisions made, state of the build, open threads. Update it when something durable changes; keep entries dated.
