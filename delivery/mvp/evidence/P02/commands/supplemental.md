# P02 supplemental validation

The following repository checks were run after packet acceptance:

```text
make command-check architecture-check fmt lint
```

Normalized results:

- Command contract: pass; commands, selectors, hooks, ownership, and live lifecycle are valid.
- Architecture: pass; `modules=1`, `nodes=76`, `edges=6`, `forbidden=0`, `symlinks=0`.
- Formatting: pass; UTF-8, LF, final-newline, text policy, and `gofmt` are clean.
- Lint: final pass; dependency manifests, Python, shell, Go, and workspace checks passed with `0` findings.

The first supplemental lint pass found one Go variable-shadowing finding in the new content-identity verifier. The identifier was renamed without behavioral change, generation was rerun, and the final lint and packet acceptance runs passed.

Focused pinned runtime commands also passed independently before the exact acceptance run:

```text
GOMODCACHE=/tmp/jumpship-p02-go-mod GOCACHE=/tmp/jumpship-p02-go-build GOFLAGS=-mod=readonly ./build/tools/bin/go test ./internal/contracts/...
./build/tools/bin/node --experimental-strip-types --test ./web/src/lib/api/generated/canonical.test.ts
```
