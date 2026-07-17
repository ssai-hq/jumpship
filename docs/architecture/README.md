# Jumpship Architecture Baseline

This directory is the public projection of the frozen MVP architecture. It is intentionally sufficient for repository implementation and review without exposing private planning material or customer evidence.

## Precedence

1. A current product-owner or user instruction that is within an accepted packet.
2. The frozen private MVP implementation baseline and its machine lock.
3. These public ADRs and architecture/security documents.
4. Earlier research and repository history where compatible.

A public document cannot widen a packet, override a machine gate, or claim that planned behavior is implemented. Material changes require an accepted ADR, corresponding threat/contract updates, and a re-frozen planning baseline before implementation.

## Index

- [`system-boundaries.md`](./system-boundaries.md): modular-monolith topology, authority, stores, trust domains, custody, placement, and deletion.
- [`contract-versioning.md`](./contract-versioning.md): contract ownership and compatibility policy.
- [`../security/data-classification-and-flows.md`](../security/data-classification-and-flows.md): enforced data classes and complete P00 flow allowlist.
- [`../security/threat-model.md`](../security/threat-model.md): security invariants and denial boundaries.
- [`../adr/README.md`](../adr/README.md): complete ADR register.
- [`../../contracts/capabilities/mvp.yaml`](../../contracts/capabilities/mvp.yaml): stable capability, applicability, test, evidence, and incapability routing.

The architecture is one public modular monolith with multiple binaries and hard package, process, IAM, database-role, network, protocol, and cryptographic boundaries. Repository unity is not runtime trust.
