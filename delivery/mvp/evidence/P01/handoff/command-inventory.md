# P01 command inventory handoff

The static generated catalog contains 31 packet/join nodes, 214 public targets, 46 selectors, and 45 internal hooks/adapters. Its bytes derive only from `delivery/mvp/packet-graph.yaml` and `delivery/mvp/command-contract.yaml`; receipts and local fragments cannot drift the checked-in catalog.

The live runtime inventory is informational. It reports fragment presence and local hook coverage, labels committed complete-receipt markers as untrusted hints, and states that neither `active` nor `REQUIRE_COMPLETE=1` establishes packet acceptance or dispatch readiness.

P01 owns these public front doors:

- repository: `help`, `doctor`, `bootstrap`, `docs-check`, `capability-check`, `command-check`, `packet-graph-check`, `architecture-check`, `gen`, `gen-check`, `fmt`, `lint`, `verify`;
- generic dispatch: `test-unit`, `test-integration`, `test-security`, `test-chaos`, `test-kill`, `test-e2e`, `db-migration-compat`;
- composite dispatch: `api-callback-log-canary`, `cell-crl-publication-test`, `activation-receipt-crash-test`.

P01 supplies `_p01_test-unit_SUITE-repository` and delegates `capability-check` to P00's accepted `_p00_capability-check`. Later packets add only contract-declared hidden hooks or direct targets in their own `mk/packets/Pxx.mk`; one owner is enforced for every public target and dispatcher-selector tuple.

`make help` is the human index, `make command-check` validates current ownership/lifecycle, `make packet-graph-check` validates the dependency graph, and `make gen-check` validates the static generated catalog.
