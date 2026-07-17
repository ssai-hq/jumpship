# P02 pre-close review

Review date: `2026-07-18`.

Scope and generation:

- All packet changes are under `contracts/**` (excluding `contracts/capabilities/**`), `internal/contracts/**`, `web/src/lib/api/generated/**`, `mk/packets/P02.mk`, or this P02 evidence namespace.
- No endpoint handler, persistence implementation, domain policy, infrastructure resource, visual component, P00 capability fragment, or planning input was changed.
- Generated artifacts were produced only by `internal/contracts/codegen/generate.py`; `make gen-check` is clean.

Correctness and failure behavior:

- Schemas are closed, bounded, versioned, uniquely identified, data-classified, and fail closed on unsupported keywords.
- State-machine and conditional partitions include valid and invalid witnesses; the corpus generator validates its own output before writing.
- OpenAPI mutations declare explicit audience, limits, media type, authorization surface, idempotency/concurrency, audit, and problem responses. OAuth form handoffs use manual redirect handling; browser CSRF and coding-agent exclusions remain distinct.
- Cell recovery is unary and authority-free; supervisor streaming uses explicit Connect framing, cancellation, trailers, bounded messages, and no generic authority tunnel.
- Canonical JSON rejects duplicate keys, trailing values, non-finite numbers, and lone surrogates. Typed digests include the object type and schema version.
- Signature verification binds schema/type/purpose/environment/tenant/migration/registry identity, exact key algorithm, validity, revocation, supersession, replay time, and payload digest. Both ECDSA P-256 and RSA-PSS use shared cross-runtime vectors.
- TypeScript ECDSA verification rejects non-minimal, negative, zero, overlong, truncated, and trailing-content DER encodings through 11 shared malformed vectors.
- Content-addressed catalog verifiers pin the exact top-level schema, projection constants, 1 MiB canonical-byte ceiling, item fields, bounds, hashes, identifiers, and ordering; attacker-selected projections, oversized catalogs, unknown fields, missing fields, duplicates, and non-ascending keys fail closed in both runtimes.
- Provider-use leases declare and test the invariant `expires_at - issued_at == ttl_seconds <= 60`; signed interval mismatches and overlong intervals fail conformance even when scalar fields are individually schema-valid.
- Generated Connect clients use standard lowerCamel ProtoJSON, accept only the standard compatibility spelling, reject duplicate/unknown/missing/multiple oneof fields, and pass real unary/bidirectional framing, metadata, trailer, and EOF tests through an in-memory HTTP transport.
- No secret, credential, raw customer evidence, external URI, or provider response is present in evidence.

Findings fixed before close:

- Nested schema-condition sampling, sibling `contains` witness preservation, provider-transition sampling, and the OpenAPI generated-surface assertion were corrected.
- The operation-ID schema was widened compatibly to bind the exact camelCase OpenAPI operation ID used by external-exposure reversibility.
- Go response-buffer redeclaration, registry validation compile hygiene, TypeScript canonical PEM terminal-newline handling, and one Go vet shadowing finding were corrected.
- Generator-side strict validation now prevents an invalid synthesized corpus from being emitted.
- Final security audit findings for ProtoJSON interoperability, canonical ECDSA DER, provider-lease duration, and catalog projection trust were all fixed and regression-tested before close.

Final local result: required acceptance, command contract, architecture, format, and lint checks pass. P02 has no unresolved manual or external completion gate and no scope exception.
