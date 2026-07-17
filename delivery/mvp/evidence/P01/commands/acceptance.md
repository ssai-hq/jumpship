# P01 acceptance command

Required command:

```text
make doctor bootstrap docs-check capability-check command-check packet-graph-check gen-check fmt lint test-unit architecture-check
```

Observed result on the stable implementation worktree: exit `0`.

Key normalized results:

```text
doctor: supported darwin-arm64; host prerequisites present; repository-local toolchain exact
bootstrap: six pinned tools re-extracted and verified; frozen pnpm install completed with lifecycle scripts disabled
docs-check: PASS; 0 findings
capability-check: PASS; capabilities=69 anchors=253 uncovered=0 orphaned=0 untestable=0 bare-duplicates=0
command-check: PASS; commands, selectors, hooks, ownership, and live local lifecycle valid
packet-graph-check: PASS; 31 nodes, exact dependency expansion, joins, and acyclicity valid
gen-check: PASS; static generated catalog current
fmt: PASS; UTF-8, LF, final-newline, text, and gofmt policy clean
lint: PASS; dependency contracts valid; golangci-lint findings=0
test-unit: PASS; 118 Python tests, all Go packages, and present pnpm tests
architecture-check: PASS; modules=1 nodes=70 edges=0 forbidden=0 symlinks=0
```

The Python count comprises 29 architecture, 8 accepted P00 truth, 34 toolchain/dependency, 11 documentation, and 36 packet-contract tests. Planned hooks not yet implemented by downstream packets were reported as planned and skipped by the local dispatcher; P01's `SUITE=repository` hook ran. This local lifecycle inventory is not scheduling or receipt authority.

No required acceptance check was skipped.

The same acceptance vector passed in the isolated clean-clone rehearsal recorded at `commands/clean-clone.json`: exit `0`, duration 64 seconds, output SHA-256 `1e45e7c3bf21d5c57bd56795888172b9cf04c8be978c005b01a3abad9618a73f`, source snapshot `47ce31097878966d55a5a6d7bd7a0895498b5e43`.
