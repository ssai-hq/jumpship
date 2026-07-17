# Static truth, hygiene, and ambiguity scans

## Stale truth

```text
rg -n 'no SaaS|one consent|SQLite in dev|latest' README.md PRODUCT.md AGENTS.md CLAUDE.md MEMORY.md docs
exit: 1
matches: 0
result: PASS (ripgrep no-match exit is expected)
```

## Public-repository secret/connection-string pattern scan

```text
rg -n 'customer[ ]name|mongodb[+]srv://|postgres(ql)?://' . --glob '!test/**' --glob '!.git/**'
exit: 1
matches: 0
result: PASS (ripgrep no-match exit is expected)
```

## Stale narrow-product wording

```text
rg -n 'CLI-only|no-SaaS' README.md PRODUCT.md AGENTS.md CLAUDE.md MEMORY.md DESIGN.md SECURITY.md docs
exit: 1
matches: 0
result: PASS (ripgrep no-match exit is expected)
```

## Reused-display references

The public checker scans repository documentation, contracts, code, and tests for bare hash-style references to reused displays 124, 125, and 126. Result: 0 violations. The source manifest contains only full semantic `numbered-list:<display>:<slug>` identities.

## License

```text
shasum -a 256 LICENSE
ec754bc72c6efa41f19c252c7839c22ad2f5f714daba62a015db5a62ec1da431  LICENSE
exit: 0
```
