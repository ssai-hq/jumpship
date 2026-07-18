# P03 supplemental validation

The binding clean-clone rehearsal ran from clean committed `main` at `415a5ec3912afa501aaa5d7b6de37f7773ed3b00`:

```text
python3 scripts/ci/clean_clone_rehearsal.py --output delivery/mvp/evidence/P03/commands/clean-clone.json
```

Result: exit `0` in `164` seconds. The isolated clone ran `make doctor bootstrap gen-check fmt lint test-unit verify` with an isolated home, cache, config, and Docker config; no cloud credential, Docker credential, Docker context, Docker host, or TLS selector was forwarded. The only Docker material copied into the isolated config was the executable Compose v2 plugin, integrity-checked and recorded by exact version and SHA-256 in the generated report. The redacted stdout digest is `99eb70c429bebdea0277a7e9988b93525e01f6fb6e56189b5121ef62b20fc1ef`.

Additional successful checks included:

```text
make doctor bootstrap gen-check fmt lint test-unit verify
make fmt lint docs-check test-unit test-security SUITE=local-stack
infra/local/bin/stack up --profile network --profile agent --profile observability --wait-timeout 180
infra/local/bin/stack down
```

Normalized results:

- Repository-local Go `1.26.5`, Node `24.18.0`, pnpm `11.4.0`, OpenTofu `1.11.0`, golangci-lint `2.12.2`, and Trivy `0.72.0` were checksum-verified. The optional pnpm metadata update probe reported a non-fatal network warning; pinned bootstrap and lock installation still completed successfully.
- Generation, formatting, lint, documentation, architecture, command-contract, unit, contract, and security checks passed.
- Final focused validation reported `15/15` local-stack tests, `18/18` security-policy tests, workflow policy clean, documentation check clean across `128` Markdown files, and pinned Trivy scanning `485` repository source files with `0` findings. The redacted raw-report digest was `c00ca54d5a3a082ac47250ce7ad3c80536df61fb436c42979e9eff7ed65bddb9`.
- The complete P03 optional-profile topology reached controller readiness, then tore down without deleting volumes.
- A protected Mongo fixture's attempt to open `/dev/tcp/1.1.1.1/80` failed with `Network is unreachable`, proving the hard-internal fixture network denies direct internet egress.
- A `tcp://` Docker endpoint override was rejected before Compose execution with exit `2`.
- An incorrect reset confirmation was rejected with exit `2` after enumerating only the fixed project, `<local-docker-endpoint>`, and six exact volumes.

The pre-close diff and staged diff both passed `git diff --check`. No required generated file was edited by hand.
