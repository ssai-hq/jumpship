# 2026-07-17 — P00 architecture baseline

P00 replaced repository-only narrative with a public, mechanically checkable architecture truth layer.

- The frozen living source is bound by logical version, source SHA-256, and 253 stable content-hashed anchors: 213 numbered occurrences and 40 binding addendum headings.
- The closed registry contains 69 authorized `MVP-CAP-*` records and 10 stable public `MVP-INCAP-*` disclosures.
- Reused legacy displays 124, 125, and 126 resolve to separate semantic anchors; new code and documentation may not use a bare hash-style reference to those displays.
- Automatic no-freeze dual write remains outside the MVP under ADR-021 and resolves to the explicit `not_applicable`/`not_implemented_in_mvp` record.
- Public architecture and security documents record modular-monolith trust boundaries, custody, placement, deletion, exactly two consent kinds, data classifications, and the 28-flow allowlist.
- All 34 frozen architecture decisions are transcribed under `docs/adr/`. Apache License 2.0 remains unchanged at the repository root.

P00 adds no runtime, database, or cloud implementation. P01 is responsible for the monorepo/toolchain/dispatcher scaffold and must delegate capability checking to P00's direct script without behavioral drift.
