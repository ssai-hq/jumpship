# P01 ownership and generated-path handoff

## Ownership

- P01 owns the root dispatcher, public packet/command contracts, repository checker/toolchain scripts, root locks/configuration, CODEOWNERS bootstrap, and P01 evidence.
- P00 retains exclusive ownership of `mk/packets/P00.mk` and accepted capability/ADR truth.
- Later packets own their declared `mk/packets/Pxx.mk`, hidden hooks, domain implementations, and packet evidence.
- Only the P01 root-lock steward applies accepted `dependency/requests/Pxx.yaml` changes to root Go/pnpm/tool locks. The workflow validates but never invents the approval record.
- P03 alone owns CI workflows that invoke the P01 scripts.

## Generated paths

| Output | Accepted source | Generator/check |
|---|---|---|
| `docs/generated/packet-execution-manifest.json` | public packet graph and command contract | `make gen`; `make gen-check` |
| P01 architecture graph/report JSON | current repository source/import graph | `scripts/architecture/check --graph-output ... --report-output ...` |
| P01 documentation report JSON | current public repository documents/policy | `scripts/docs/check --report-output ...` |
| P01 runtime inventory JSON | public graph/command contracts plus local fragments and untrusted receipt markers | `python3 scripts/packets/check inventory --output ...` |
| P01 clean-clone JSON | a clean committed source snapshot | `scripts/dev/clean-clone --output ...` |
| later dependency-update receipt | one accepted committed dependency request and exact root-lock candidate | `scripts/dependency-locks/apply-request ...` |

Generated files must not be hand-edited. Writers reject out-of-repository destinations, symlinked parents/outputs, and output identity races; regular outputs are atomically replaced and directory-synced. Dependency receipts are exclusive and cannot be overwritten or replayed.

Ignored `build/`, tool caches, node_modules, coverage, and temporary validation homes are never generated-path deliverables.
