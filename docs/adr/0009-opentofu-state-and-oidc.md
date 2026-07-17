# ADR-009: OpenTofu State and GitHub OIDC

- Status: Accepted
- Date: 2026-07-17
- Owners: infrastructure owner, security owner
- Supersedes: Terraform-specific and long-lived-key assumptions
- Superseded by: None

## Context and decision

Infrastructure uses OpenTofu 1.11-compatible HCL, separate S3 state per authority/environment boundary, locked and encrypted state, and GitHub OIDC for deployment identity. No long-lived AWS deployment keys are permitted.

## Alternatives and rejection

One global state increases blast radius and ownership conflicts. Static CI keys are durable credentials with poor rotation/provenance. Terraform-only workflow assumptions weaken tool portability without an MVP benefit.

## Consequences, migration, and rollback

P01 selects the compatible patch; P09/P10/P11 own roots, policies, locks, plan/apply evidence, and recovery. A tool security/support regression requires a superseding ADR and state-migration proof.

## Traceability

- Capabilities: `MVP-CAP-AWS-CELL`, `MVP-CAP-ARCH-TRUST-DOMAINS`
- Acceptance: `JSMVP-R001`, later IaC/supply-chain rows
- Evidence: [`../architecture/contract-versioning.md`](../architecture/contract-versioning.md)
