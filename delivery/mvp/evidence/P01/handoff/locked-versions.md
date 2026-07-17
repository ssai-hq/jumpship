# P01 locked-version handoff

## Bootstrap/runtime pins

| Component | Version | Mode | License |
|---|---:|---|---|
| Go | 1.26.5 | repository-local bootstrap | BSD-3-Clause |
| Node.js | 24.18.0 | repository-local bootstrap | MIT |
| pnpm | 11.4.0 | repository-local bootstrap | MIT |
| OpenTofu | 1.11.0 | repository-local bootstrap | MPL-2.0 |
| golangci-lint | 2.12.2 | repository-local bootstrap | GPL-3.0-only |
| Trivy | 0.72.0 | repository-local bootstrap | Apache-2.0 |
| PostgreSQL | 17.10 | external/local-stack provisioner owns materialization | PostgreSQL |

All bootstrap artifacts have immutable checksums for Darwin/Linux on amd64/arm64, except pnpm's single platform-independent package artifact. Bootstrap re-hashes cached archives and re-extracts every tool on each run.

## Deferred tool pins

| Component | Version | Status |
|---|---:|---|
| goose | 3.27.2 | provenance verified; deferred |
| sqlc | 1.31.1 | provenance verified; activation blocked pending four-platform artifacts |
| oapi-codegen | 2.8.0 | Go module/source sum verified; deferred |
| buf | 1.71.0 | provenance verified; deferred |
| openapi-typescript | 7.13.0 | registry integrity verified; deferred |
| Syft | 1.48.0 | provenance verified; deferred |
| Cosign | 3.1.2 | provenance verified; deferred |
| Semgrep | 1.170.0 | provenance verified; deferred |
| DuckDB | 1.5.4 | provenance verified; activation blocked pending four-platform artifacts |

Deferred means P01 records immutable provenance but does not install the tool. A later activation request must use the serialized dependency workflow and pass license, vulnerability, provenance, and clean-clone validation.

## Application workspace pins

- Root module: `github.com/ssai-hq/jumpship`, Go `1.26.5`.
- Sole pnpm package: `web`.
- Next.js `16.2.10`, React `19.2.7`, React DOM `19.2.7`.
- Root pnpm lock format: `9.0`; lifecycle-script allowlist: empty.
