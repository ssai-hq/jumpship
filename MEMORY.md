# Jumpship Memory

Running log of durable decisions and build state. Newest first. Keep entries dated; prune when superseded.

## 2026-07-08 — Repo initialized

- Monorepo created under `ssai-hq/jumpship` (public). Engine (Go), web, deploy, docs all in one repo — deliberate reversal of the earlier 7-repo polyrepo plan for MVP speed.
- Canonical build plan: `fable-scaffold.md` in the ssai workspace (`mdhq/*MIGRATIONPIVOT/mission3-mongo-to-pg-research/`). Component specs, mapping-spec format, verification pyramid, and acceptance criteria all live there.
- Nothing built yet. First milestone per the scaffold's 6-day sprint: profiler + corruption injector + golden test corpus.

## Open threads

- License not chosen yet (repo is public; currently all-rights-reserved by default).
- Go module path: `github.com/ssai-hq/jumpship` — init when engine code starts.
