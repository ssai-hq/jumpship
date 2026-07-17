# Explicit P02 inputs from P00

P02 consumes these immutable public inputs through P00's validated receipt:

1. `contracts/capabilities/mvp.schema.json` and `mvp.yaml`: exact 69-ID capability namespace, requirement/applicability/status vocabulary, ownership/test/evidence routing, and 10 public incapability source records.
2. `contracts/capabilities/mvp-source-anchors.schema.json` and `mvp-source-anchors.yaml`: logical source version, raw source hash, source-plan hash, anchor algorithm, and all 253 anchor/content hashes.
3. Seven contract data-class identifiers: `public`, `internal_operational`, `identity_tenant`, `shared_migration`, `restricted_customer`, `credential_secret`, and `security_material`.
4. F01-F28 flow allowlist semantics. Boundary-crossing P02 schemas must declare maximum data class and size and cannot use unbounded generic payloads.
5. Customer-incapability catalog source fields: stable incapability ID, public effect/reason/remediation, `remediation_source`, linked capability IDs, source anchors, negative-test references, and exact source-registry/source-plan hashes. P02 owns the client projection schema; it must not mint replacement source identities.
6. Dual-write applicability identity: `explicitly_deferred`, `not_applicable`, `not_implemented_in_mvp`, `public_selectable=false`, bound to ADR-021.
7. Contract/version policy: explicit schema/profile/compiler versions, immutable hashes, additive public compatibility windows, versioned breaking paths, protobuf field preservation, typed refusal, detached signature purpose, and generated-output freshness.
8. Customer application authority from ADR-029/030/032: draft PR publication is Jumpship-owned, validation/merge/deploy remain customer-owned, external review is advisory, and one application-authority epoch/fenced cohort generations prevent split writes.

P02 may add its authorized contract schemas and generated types, but a missing concept is a planning/contract change request—not permission to create a divergent ID, data class, DTO, consent kind, or authority path.
