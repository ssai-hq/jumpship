# ADR-017: Encryption and Proof Key Separation

- Status: Accepted
- Date: 2026-07-17
- Owners: security owner, proof owner
- Supersedes: None
- Superseded by: None

## Context and decision

Each cell uses a purpose-scoped symmetric customer-data encryption key. Integrity proof uses a separate asymmetric signing key/purpose whose verification survives cell teardown. Encryption keys are not described or used as signing keys; proof, deletion, audit, promotion, and emergency signatures also remain purpose-separated.

## Alternatives and rejection

One key for encryption and signing confuses purpose, lifecycle, and verifier trust. A cell-local signing key deleted with custody cannot support durable verification.

## Consequences, migration, and rollback

Contracts bind purpose, environment, key ID/fingerprint, algorithm, validity/revocation, payload hash, and detached signature. Cross-purpose replay is a negative release gate. There is no MVP merger of these keys.

## Traceability

- Capabilities: `MVP-CAP-SIGNED-INTEGRITY`, `MVP-CAP-CREDENTIAL-CUSTODY`, `MVP-CAP-DECOMMISSION`
- Acceptance: `JSMVP-R001`, later crypto/proof rows
- Evidence: [`../security/threat-model.md`](../security/threat-model.md)
