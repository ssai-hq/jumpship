# P01 supply-chain review

Date: 2026-07-17.

An independent latest-state review examined archive extraction, network provenance, tool/write containment, reader/writer locking, dependency request lifecycle, candidate Git binding, license coverage, vulnerability evidence, crash/replay behavior, receipt history, clean-clone isolation, and redaction.

Resolved findings included:

1. Bootstrap/apply now hold exclusive tool-operation locks while doctor/check/format/lint/test/provenance readers use shared locks.
2. Every mutable tool/cache/journal path and dynamic dependency-receipt parent rejects symlink escape; private writes use no-follow regular-file checks and fsync.
3. Apply repairs tools from checksum-verified archives before collecting license, audit, or scanner evidence.
4. Historical applied receipts validate against their candidate commit's manifest, not the current worktree manifest.
5. Go code and deferred Go-tool changes require the module ZIP sum; a metadata-only `go.mod` sum cannot authorize source bytes.
6. pnpm license review covers every package reachable on the four supported platform targets, fetching only lock-SRI-bound missing package manifests.
7. Clean-clone tails redact source/temp paths, forwarded network values, and credential/query-bearing URLs.
8. `sqlc` and DuckDB activation is fail-closed until four-platform integrity is complete.

Final reviewer result: clean, with no remaining actionable supply-chain or security finding. The focused toolchain suite passed all 34 tests; dependency validation, exact toolchain check, doctor, format, lint, and all nine live deferred provenance checks passed.

The blocked `sqlc`/DuckDB activation state is an explicit future input requirement, not a skipped P01 acceptance check or an approval.
