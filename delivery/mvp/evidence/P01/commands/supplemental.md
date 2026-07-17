# P01 supplemental verification

All results are from 2026-07-17. Absolute worktree paths and network locations are intentionally omitted.

## Repository verification

| Command | Result |
|---|---|
| `make verify` | exit `0`; all P01 static checks and repository unit hook passed; planned downstream hooks remained explicitly planned |
| `make test-unit SUITE=repository` | exit `0`; P01 repository suite passed |
| direct P00 capability command versus `make --no-print-directory capability-check` | both exit `0`; normalized output byte-identical; 3 lines |
| `make test-unit SUITE=local-stack` | expected exit `2`; selected P03 hook denied because lifecycle is `planned` |
| `make REQUIRE_COMPLETE=1 test-unit` | expected exit `2`; five planned hooks listed; message states local coverage is not acceptance/readiness |
| `scripts/dependency-locks/check` | exit `0`; manifest, runtime pins, workspace, root locks, and request lifecycle valid |
| `git diff --check` | exit `0` |

## Supply-chain verification

The first sandboxed network attempts failed only because DNS is disabled. The same official-source checks were then rerun with approved network access.

| Check | Result |
|---|---|
| Deferred provenance | exit `0`; all 9 deferred records verified; `sqlc` and DuckDB remained activation-blocked |
| pnpm audit | critical `0`, high `0`, moderate `1`, low `0`; output SHA-256 `d7aa1813b7083360d634643c43492542d62fe9fb556cb5f2794ab99db4e7528f` |
| Trivy filesystem/lock scan | high/critical findings `0`; output SHA-256 `c6475295cb2fadc0857813e5266e57cea6b3fc0cec3fc04d24d1fc962aeecbff` |
| Trivy database | metadata SHA-256 `323c651cfce53ea2ce31c82bc73199e9d950499b5fb1c55d063683462540fa51`; database SHA-256 `30b2bb67ee3ffc3c91a6e171a052fab80710683d496ac7050d1fc5f6d7c2351f` |
| Supported-platform pnpm licenses | 32 of 32 lock packages covered: 22 host-inventoried and 10 official tarballs verified against lock SRI |

Host pnpm inventory license counts were: MIT 11, Apache-2.0 5, ISC 2, 0BSD 1, BSD-3-Clause 1, CC-BY-4.0 1, and LGPL-3.0-or-later 1. Its redacted output SHA-256 was `d51744651d0c23772b01adecbeba8fa39362f29c9257c4482e4ab311e7019adc`.

The dependency-apply regression covers committed candidate binding, exact immediate-parent/non-merge history, unrelated-path denial, immutable repair before evidence collection, exclusive writer/shared readers, lock/path symlink denial, license and source-integrity binding, vulnerability checks, dual final CAS, receipt-before-status crash handling, replay denial, and historical receipt validation after a later manifest change.
