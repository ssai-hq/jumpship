# P02 application and profile inventory

The complete hash inventory is `contracts/contract-manifest.json`. This handoff calls out the application-adaptation and deployment-composition surfaces that downstream packets must pin.

Application contracts (`contracts/application/**`):

- `application-adaptation-spec`, `application-adapter-manifest`, `application-estate`, and browser-safe estate projection.
- `application-change-set`, browser-safe change-set projection, merge equivalence, reverse-apply attribution, and pull-request binding.
- `application-writer-grant` and `writer-control` for backend-owned writer authority.
- deployment attestation, runtime proof, evidence-provider binding, and external-review handoff.

The directory contains 15 closed JSON Schemas. They account for selected repositories, services, workers, queues, cron jobs, ORM/direct writers, versioned patches, exact PR heads, customer validation, deployment evidence, and reverse-apply attribution without granting Jumpship merge or deploy authority.

Provider/profile contracts:

- `contracts/corridors/mongodb-postgres-profile.schema.json` freezes MongoDB Atlas/self-managed source rungs and Supabase/PlanetScale PostgreSQL endpoint compositions, including direct/Supavisor/PgBouncer constraints and explicit fallback/refusal.
- `contracts/release/deployment-profile.schema.json` plus `contracts/release/deployment-profiles.yaml` freezes the four deployment profiles and their stage/promotion limits.
- `contracts/release/cost-baseline.schema.json`, `fixed-cost-inputs.schema.json`, and `test-run-manifest.schema.json` bind provider/version/source roots, materialized inventory, expiry, assumptions, currency, variance policy, and exact deployment profile identity.
- `contracts/auth/deployed-auth-config.schema.json` freezes the closed browser, CLI-human, coding-agent, OAuth callback, cell, and application-writer trust topology.
- `contracts/agent/provider*.schema.json` freezes provider selection, evidence review, use leases, route holds, status, and journal transitions without embedding provider credentials.

All listed surfaces use schema version `1.0.0`; downstream consumers must use the exact artifact hash from `contracts/contract-manifest.json`, not a filename or semantic version alone.
