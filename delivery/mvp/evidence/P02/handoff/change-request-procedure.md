# Frozen-contract change procedure

P02 freezes contract schema version `1.0.0` and the exact hashes in `contracts/contract-manifest.json`.

1. Identify every affected schema, OpenAPI operation, protobuf field/RPC, generated DTO/client, fixture, and downstream consumer.
2. Classify the change before editing. Additive optional changes may remain in v1. Removing or renaming fields, tightening accepted values, changing protobuf field numbers, changing an existing operation/RPC, or altering canonical identity is breaking and requires a versioned path plus fixture migration.
3. Change only codegen sources or canonical library sources. Never edit generated artifacts directly.
4. Add valid, invalid, tamper, replay, transition, or compatibility fixtures appropriate to the change. Preserve prior fixtures for replay unless the versioned migration explicitly supersedes them.
5. Regenerate with `make gen`; then run `make gen-check test-contracts` and the affected downstream packet suites.
6. Attach a compatibility report, generated diff, and replay-fixture update. Obtain review from the contract owner, every affected consumer owner, and the security owner.
7. Publish a new immutable manifest hash and update downstream pins in their owning packets. Do not overwrite or reinterpret the P02 receipt.

The generator rejects unsupported schema keywords, invalid synthesized fixtures, stale generated files, duplicate protobuf identifiers/numbers, missing policy metadata, and changes that violate the frozen v1 compatibility baseline.
