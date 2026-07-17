# P02 acceptance

Required packet command:

```text
make gen gen-check test-contracts
```

Observed result on `2026-07-18`: exit `0`.

Normalized results:

- Generator materialized `159` P02 artifacts and the generated-diff check reported the catalog current.
- The generator's strict fail-fast corpus check accepted all `93` schemas and rejected every generated negative witness.
- Python contract conformance: `20` tests passed.
- Go contract packages: passed, including canonicalization, typed digest, content identity, ECDSA P-256, RSA-PSS, registry-chain, replay, tamper, catalog-order, strict ProtoJSON, and in-memory Connect transport tests.
- TypeScript runtime conformance: `6` tests passed, `0` failed.

No required acceptance check was skipped. Node emitted a non-failing module-type performance warning because the existing `web/package.json` does not declare ESM; the pinned test runner reparsed the generated TypeScript module and all assertions passed. Changing that package declaration is outside P02's authorized scope.
