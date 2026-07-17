# Contract and Version Policy

Every boundary-crossing shape is a versioned contract with a named authority, consumers, compatibility rule, fixtures, and drift check. Generic maps, arbitrary JSON, protobuf `Any`, unbounded log fields, or provider-native envelopes cannot cross a trust boundary until a contract declares type, size, maximum data class, and failure behavior.

## Compatibility rules

- Public REST begins at `/v1`; OpenAPI changes are additive for one deployment window. Breaking behavior requires a versioned path and explicit consumer migration.
- Browser session events carry `schema_version`; an unknown event becomes a visible unsupported state, never a silent drop.
- Cell protobuf contracts use the `jumpship.cell.v1` package, pass breaking-change checks, and never reuse field numbers.
- Mapping, rubric, placement, corridor, runtime, checkpoint, tool, grant, receipt, evidence, and release contracts carry explicit schema/compiler/profile versions and immutable input hashes.
- Corridor profiles use semantic versions plus exact immutable profile/probe hashes. Unsupported provider physics yields a typed fallback or refusal.
- Mutable resources expose a strong version/ETag; safety changes bind `If-Match` or an explicit expected version.
- Durable effects are idempotent by stable request identity and request hash. Changed replay input is rejected.
- Detached signatures bind canonical bytes and an explicit purpose, environment, key identity, and hash. A signature for one purpose is never valid for another.
- Generated Go/TypeScript clients and schemas are committed with provenance. Generation plus a clean diff is the freshness gate once P01/P02 add those toolchains.

## Deployment compatibility

Database and contract changes follow expand, compatible code, resumable backfill, validate, switch, and later cleanup. A shape remains supported while any active cell or rollback target references it.

A new shared deployment proves compatibility against the frozen inventory of all active cell release bindings before activation. Existing cells keep their immutable binding until a controlled upgrade seals a compatible checkpoint, provisions a new generation, verifies restore, and fences the predecessor. No process selects a newer bundle merely because it exists.

## Toolchain ownership

P01 owns root dependency locks and selects the still-open Node, pnpm, and OpenTofu patch versions within the frozen major/minor policy. P00 does not choose them. Fixed baseline versions are Go 1.26.5 and PostgreSQL 17.10; MongoDB/worker versions are corridor-profile inputs. Images, actions, external tools, and providers are pinned by immutable version/digest with SBOM, scan, signature, and provenance gates where they enter a release.

## Change control

A contract change includes the schema, compatibility report, affected consumers, replay/negative fixtures, capability linkage, and acceptance evidence. Material product or trust changes also require a superseding ADR and threat-model delta. Private planning changes do not silently flow into a public clone: the source/plan hashes and source-anchor manifest must be regenerated, reviewed, and reaccepted.
