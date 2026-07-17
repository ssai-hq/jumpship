# P03 bootstrap needs from P01

P03 is not dispatch-ready until P02 also has a complete accepted receipt. When it becomes ready, it should consume these P01 contracts without redefining them.

## Required inputs

- Run the P01 root `doctor` and `bootstrap`; use only commands from `build/tools/bin` for pinned Go, Node, pnpm, OpenTofu, lint, and scanner behavior.
- Add P03 direct targets `dev-up`, `dev-down`, `dev-reset`, `web-dev`, and `api-dev` in `mk/packets/P03.mk`.
- Register the contract-declared P03 `SUITE=local-stack` hooks for unit and security dispatch; do not edit root dispatcher recipes or another packet fragment.
- Preserve the one-package `web` pnpm workspace and Go module. Any root-lock change begins as `dependency/requests/P03.yaml` and remains unapplied until the real P01 root-lock-steward approval is supplied.
- Materialize the PostgreSQL 17.10 local baseline and the rest of P03's packet-owned representative services through P03's own local-stack files; P01 intentionally supplies no service, schema, migration, fixture, or production infrastructure.
- P03 owns workflow files that invoke these repository scripts. Workflow existence must not be simulated in P01.
- Keep `sqlc` and DuckDB inactive unless a later accepted dependency request supplies checksum-bound artifacts for all four supported platforms and the root-lock workflow succeeds.

## Required behavior

- Local destructive reset remains an explicit, narrow, confirmed command.
- Generated files are produced through accepted generators and remain drift-clean.
- Local-stack hooks must stay `planned` until substantive P03 recipes exist; empty/no-op recipes are rejected.
- `planctl` remains the only readiness and handoff authority. The public runtime inventory cannot unlock P03.
