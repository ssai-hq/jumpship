# P03 rubric contribution map

All statuses below mean the P03-owned local contribution passed. Shared rubric completion and staging/production qualification remain with the producers and joins named by the frozen plan.

| Rubric | Status | P03 evidence |
| --- | --- | --- |
| `JSMVP-R012` | `passed_local` | Workflow actions use immutable commit SHAs; all eight local third-party images use exact versions and OCI digests; the profile guard binds the P02 contract and deployment-profile registry hashes; workflow policy rejects mutable actions/images, unsafe permissions, unredacted artifacts, and unclosed selectors. |
| `JSMVP-R013` | `passed_local` | The generated clean-clone report proves doctor, checksum-verifying bootstrap, generation, format, lint, unit tests, and full `verify` under isolated home/config/cache state. The exact P03 lifecycle acceptance also passes with deterministic fixtures and safe teardown. |
| `JSMVP-R062` | `passed_local` | P03 supplies the pinned image/supply-chain workflow spine, detailed redacted artifact handling, and exact future P10 target handoff for image build, scan, SBOM, signature, provenance, and supply-chain verification. Those P10 targets remain visibly `planned-not-evaluated`; P03 does not represent later image, staging, or production evidence as complete. |

Primary evidence: `commands/acceptance.md`, `commands/clean-clone.json`, `commands/runtime-profiles.md`, `handoff/workflow-to-make-map.md`, `handoff/cache-artifact-retention.md`, and `reviews/pre-close-review.md` in this evidence namespace.
