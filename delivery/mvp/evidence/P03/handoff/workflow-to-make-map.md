# P03 workflow-to-Make handoff

`scripts/ci/run_gate.py` resolves targets against the live checked-in command inventory, validates closed selector variables, records redacted per-target evidence, and distinguishes active success from `planned-not-evaluated` future ownership.

| Workflow | Trigger / authority | Active or handed-off Make targets |
| --- | --- | --- |
| `ci-pr.yml` | pull request or manual; `contents: read` | P03 fast gate: `doctor`, `docs-check`, `capability-check`, `command-check`, `packet-graph-check`, `gen-check`, `fmt`, `lint`, `architecture-check`, `test-unit`, `test-contracts`, `test-security`. P09 handoff: `tofu-fmt-check`, `tofu-validate`, `tofu-policy-test`. |
| `ci-merge.yml` | main push, nightly, or manual; `contents: read` | Merge job: `verify`. Clean-clone job: `make doctor bootstrap gen-check fmt lint test-unit verify` through the P03 rehearsal. |
| `ci-infra.yml` | manual main-branch dispatch; closed non-production profile | P09/P10 handoff: `deployment-profile-validate`, `tofu-fmt-check`, `tofu-validate`, `tofu-policy-test`, `tofu-plan` with exact `ENV=nonprod`, `ROOT=control-plane`, and guard-produced `PROFILE`. Only the plan job has `id-token: write`; it never applies. |
| `ci-images.yml` | every pull request, main push, or manual dispatch | P10 handoff: `build-images`, `image-scan`, `sbom`, `image-verify-signature`, `supply-chain-verify`. No path filter can omit a dependency change. |
| `test-browser.yml` | relevant application paths or manual dispatch | P22 handoff: `web-test-e2e`, `web-test-a11y`, `web-test-visual`. |
| `test-chaos.yml` | weekly or manual closed phase | P17/P26 handoff: `test-chaos` with exact `PHASE=cdc` or `PHASE=cutover`; local profile guard runs first. |
| `quality-evals.yml` | relevant quality paths, weekdays, or manual dispatch | P21 handoff: `eval-validate`, `eval-unit`, `eval-sanitize`, `eval-run` with exact `SUITE=mvp`. |
| `release-qualify.yml` | manual main-branch exact profile plus immutable digest | P28 handoff: `release-qualify` with `ENV=production`, guard-produced `PROFILE=paid-production`, and validated immutable `RELEASE_DIGEST`. This job has no OIDC permission and never deploys. |

Future-owner targets are intentionally accepted only with `--allow-planned`; a missing planned target is recorded as not evaluated, never as a pass. Unknown targets, unknown selectors, unsafe make variables, static cloud credentials, non-main protected handoffs, mutable release references, and ad-hoc profiles fail before authority output.
