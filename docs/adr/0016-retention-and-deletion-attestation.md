# ADR-016: Retention and Deletion Attestation

- Status: Accepted
- Date: 2026-07-17
- Owners: security/data owner, product owner
- Supersedes: immediate-deletion wording incompatible with provider semantics
- Superseded by: None

## Context and decision

Retention/deletion is a multi-state, two-stage process. Decommission immediately revokes access and initiates teardown while recording immutable/object/key retention states and `retain_until`. A preliminary attestation describes initiation. A final independently signed attestation requires complete provider/component receipts proving expiry or cryptographic deletion.

## Alternatives and rejection

Claiming immediate physical deletion conflicts with S3 Object Lock and scheduled KMS deletion. Letting the coordinator sign its own completion collapses evidence independence.

## Consequences, migration, and rollback

Deletion inventories are append-only and customer-visible. Once access/key destruction advances, rollback may be impossible; the consent screen must disclose that door. Provider semantic changes require a superseding ADR.

## Traceability

- Capabilities: `MVP-CAP-DECOMMISSION`, `MVP-CAP-CREDENTIAL-CUSTODY`, `MVP-CAP-DOSSIER`
- Acceptance: `JSMVP-R001`, later deletion/attestation rows
- Evidence: [`../architecture/system-boundaries.md`](../architecture/system-boundaries.md)
