# P03 cache and artifact-retention handoff

The composite setup action pins `actions/cache` to commit `5a3ec84eff668545956fd18022155c47e93e2684`. Its cache key is:

```text
<runner-os>-<runner-arch>-<gate-namespace>-<hash(tools/manifest.yaml,go.sum,pnpm-lock.yaml)>
```

Only repository-local tool downloads, unpacked toolchains, Go build/module caches, golangci-lint cache, pnpm store, and Trivy cache are restored. The action then runs checksum-verifying `make bootstrap`. Checkout disables persisted credentials.

Artifact policy:

| Workflow artifact | Retention |
| --- | ---: |
| PR fast gate | `7` days |
| Merge/nightly verification | `14` days |
| Clean-clone rehearsal | `14` days |
| Infrastructure plan | `1` day |
| Image and supply-chain evidence | `30` days |
| Browser evidence | `7` days |
| Chaos evidence | `14` days |
| Evaluation evidence | `14` days |
| Release qualification evidence | `30` days |

Every upload pins `actions/upload-artifact` to commit `ea165f8d65b6e75b540449e92b4886f43607fa02`, sets `include-hidden-files: true` for `.ci-artifacts`, fails when files are absent, and uses compression level `6`. Workflow policy rejects drift in those controls.

Retained gate output contains a concise job summary plus redacted structured artifacts. `run_gate.py` closes its environment, rejects credential-bearing values and unsafe selectors, redacts URLs/tokens/paths, bounds retained tails, and stores hashes of the redacted stdout rather than raw provider or customer material.
