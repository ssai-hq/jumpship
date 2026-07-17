# Architecture Decision Records

The numeric filename is the canonical ADR ID from the frozen architecture register. Titles may become clearer; IDs never change. A superseding decision links both directions and preserves history.

| ADR | Decision | Status |
|---|---|---|
| [ADR-001](./0001-modular-monolith-boundaries.md) | Public modular monolith with hard runtime boundaries | Accepted |
| [ADR-002](./0002-source-precedence-and-product-scope.md) | Source precedence and production SaaS scope | Accepted |
| [ADR-003](./0003-go-runtime-language.md) | Go runtime language | Accepted |
| [ADR-004](./0004-postgresql-storage-baseline.md) | PostgreSQL storage baseline | Accepted |
| [ADR-005](./0005-public-and-cell-protocols.md) | Public and cell protocols | Accepted |
| [ADR-006](./0006-canonical-rds-postgresql.md) | Canonical production RDS PostgreSQL | Accepted |
| [ADR-007](./0007-shared-and-cell-compute.md) | Shared and cell compute split | Accepted |
| [ADR-008](./0008-vercel-presentation-boundary.md) | Vercel presentation boundary | Accepted |
| [ADR-009](./0009-opentofu-state-and-oidc.md) | OpenTofu state and GitHub OIDC | Accepted |
| [ADR-010](./0010-outbox-sqs-delivery-boundary.md) | Outbox/SQS delivery boundary | Accepted |
| [ADR-011](./0011-region-placement-solver.md) | Region placement solver | Accepted |
| [ADR-012](./0012-data-diode-and-evidence-access.md) | Data diode and evidence access | Accepted |
| [ADR-013](./0013-cell-local-runtime-state.md) | Cell-local runtime state | Accepted |
| [ADR-014](./0014-agent-runtime-bakeoff.md) | Agent runtime freeze and later bakeoff | Accepted |
| [ADR-015](./0015-auth-and-webauthn-step-up.md) | Authentication and WebAuthn step-up | Accepted |
| [ADR-016](./0016-retention-and-deletion-attestation.md) | Retention and deletion attestation | Accepted |
| [ADR-017](./0017-encryption-and-proof-key-separation.md) | Encryption/proof key separation | Accepted |
| [ADR-018](./0018-editorial-font-license-policy.md) | Editorial font license policy | Accepted; provenance gate open |
| [ADR-019](./0019-public-license.md) | Apache License 2.0 public license | Accepted |
| [ADR-020](./0020-sealed-analysis-runner-boundary.md) | Sealed analysis runner boundary | Accepted |
| [ADR-021](./0021-mvp-dual-write-deferral.md) | MVP automatic dual-write deferral | Accepted |
| [ADR-022](./0022-regional-control-plane-recovery.md) | Regional control-plane recovery | Accepted |
| [ADR-023](./0023-bedrock-route-and-provider-data-use.md) | Bedrock route and provider-data-use policy | Accepted; release review gate open |
| [ADR-024](./0024-durable-outer-loop-and-bounded-inner-loop.md) | Durable outer loop and bounded inner loop | Accepted |
| [ADR-025](./0025-existing-run-event-checkpoint-state.md) | Existing run/event/checkpoint mapping | Accepted |
| [ADR-026](./0026-customer-rehearsal-warranty-and-decommission-policy.md) | Rehearsal, warranty, and decommission policy | Accepted |
| [ADR-027](./0027-closed-deployment-profiles.md) | Four closed deployment profiles | Accepted |
| [ADR-028](./0028-migration-thread-inline-setup-and-start.md) | Migration thread, inline setup, and start | Accepted |
| [ADR-029](./0029-customer-application-pr-delivery-boundary.md) | Customer application PR delivery boundary | Accepted |
| [ADR-030](./0030-single-application-write-authority.md) | Single application write authority | Accepted |
| [ADR-031](./0031-mongodb-postgres-corridor-family.md) | Closed MongoDB/PostgreSQL corridor family | Accepted |
| [ADR-032](./0032-advisory-coding-agent-review-boundary.md) | Advisory coding-agent review boundary | Accepted |
| [ADR-033](./0033-semantic-agent-artifact-release-gate.md) | Semantic agent artifact release gate | Accepted |
| [ADR-034](./0034-application-change-ux-state-truth.md) | Application-change UX state truth | Accepted |

The accepted status transcribes the frozen planning baseline approved on 2026-07-17; it does not close separate external, provider, design-asset, staging, or production gates. Those remain open until their own evidence and named approval exist.

Use [`0000-template.md`](./0000-template.md) for a proposed or superseding ADR. An implementation agent may draft a proposal but cannot mark a new material product/security decision accepted without its named owner and baseline change control.
