# Jumpship

**MongoDB → Postgres migrations with a verifiable guarantee.**

Jumpship migrates production MongoDB databases to Postgres (Supabase / Neon / RDS) — and proves the result is correct. The transform is deterministic and reversible; every row is checksum-verified against the source; cutover is rehearsed, human-gated, and rollback-able. No silent drops, no silent guesses.

## How it works

```
prod Mongo ──dump──▶ immutable golden copy ──▶ worker replica
                                                  │
                       profiler (schema census, dirty-data scan)
                                                  │
                       interrogation (tacit knowledge → recorded answers)
                                                  │
                       schema synthesis → mapping-spec.yaml + DDL
                                                  │
                       deterministic transform ──▶ rehearsal branch
                                                  │
                       verification pyramid (counts → invariants → block hashes → shadow reads)
                                                  │
                       CDC tail (live change streams, same transform)
                                                  │
                       cutover (freeze → delta → verify → flip, with rollback)
                                                  │
                       post-cutover parity watch
```

The LLM designs the mapping; a deterministic Go engine executes it. That's what makes 100% verification possible.

## Status

Early. Pre-first-migration. Repo layout in `CLAUDE.md`.

## Layout

- `engine/` — the `ssai-engine` Go binary: profile, interrogate, synthesize, load, verify, tail, cutover, watch
- `web/` — report rendering (later)
- `deploy/` — dev box compose + AWS Terraform
- `docs/` — readiness report, integrity report, cutover runbook templates
