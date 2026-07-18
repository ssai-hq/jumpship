# P02 Corrective Contract Evidence

Date: 2026-07-19
Defect: `P02-CATALOG-RU-HASH-CYCLE`
Starting integration commit: `35d530535bfb9c438a827962024fe04e6df09d14`
Superseded receipt: `delivery/mvp/handoffs/P02/fac74609221cb1045ac79a605d2577e7a905af36.json`

The immutable customer-incapability catalog is now schema/object `2.0.0` and its logical identity contains only `schema_version`, `source_registry_hash`, and strictly sorted disclosure items. ReleaseUnit, deployment, migration, selection, evidence-chain, response and signature metadata are absent from the object, not merely excluded from hashing.

ReleaseUnit still binds the exact catalog and source-registry hashes. A separate content-addressed `CustomerIncapabilityCatalogBinding` validates the exact ReleaseUnit/catalog/source tuple after ReleaseUnit identity and release-evidence signature validation. `CustomerIncapabilityCatalogResponse` is a non-content-addressed API envelope that nests the immutable catalog and binding with selection, migration, evidence-chain and response-time metadata.

The generator emitted 164 artifacts: 163 entries bound by `contracts/contract-manifest.json` plus the manifest itself. The P03 profile guard's exact P02-manifest pin was advanced under the corrective scope so repository-wide verification consumes the corrected contract surface. P03 and P04 were not completed, receipted or published by this work.
