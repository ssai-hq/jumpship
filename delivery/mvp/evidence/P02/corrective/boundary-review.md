# P02 Corrective Boundary Review

Date: 2026-07-19

## Compatibility

- The defective flat catalog `1.0.0` is an explicitly authorized major-version replacement at the same frozen contract path. The generator permits only this named `P02-CATALOG-RU-HASH-CYCLE` replacement and the two OpenAPI response-component changes.
- Binding and response schemas are new additive `1.0.0` object types. OpenAPI now returns the response envelope.
- The refreshed compatibility baseline and current surface hashes are identical: `07a5b948ccb122a2526e8f36284ba0cca9e7f1f31d69d8f2caffa1def26799d8`.

## Content addressing and signature

- Catalog domain separator is `jumpship:customer_incapability_catalog:2.0.0\\0`.
- Catalog ID/hash changes only for schema version, source-registry or disclosure content changes. Selection, migration, ReleaseUnit and evidence metadata cannot enter the catalog object.
- Binding has its own typed identity over the ReleaseUnit ID/hash, catalog ID/hash and source-registry hash. It is not a ReleaseUnit member and cannot alter either upstream identity.
- Catalog and binding have no independent release signature. The existing detached `release_evidence` signature covers ReleaseUnit, which contains the exact catalog/source hashes. Association verification occurs after ReleaseUnit identity/signature verification.

## Downgrade and substitution

- JSON Schema, Go and TypeScript tests reject flat `1.0.0`, metadata smuggling and response-as-catalog inputs.
- Go and TypeScript association verifiers reject ReleaseUnit, catalog and source-registry substitutions even when the substituted binding has a coherent independent content identity.
- There is no newest-release fallback or tolerant v1 reader.
