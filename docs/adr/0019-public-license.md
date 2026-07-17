# ADR-019: Public License

- Status: Accepted by owner Avinier
- Date: 2026-07-17
- Owners: Avinier
- Supersedes: repository license ambiguity
- Superseded by: None

## Context and decision

The public Jumpship repository uses the standard Apache License 2.0. Frozen seed commit `399e4f55f91c3f43e3dd7153700a77f345a0932b` contains the canonical root `LICENSE`; P00 preserves it byte-for-byte. Its accepted SHA-256 is `ec754bc72c6efa41f19c252c7839c22ad2f5f714daba62a015db5a62ec1da431`.

## Alternatives and rejection

Leaving the distribution unlicensed is incompatible with a public repository. A custom exception was not approved or required.

## Consequences, migration, and rollback

Source contributions follow Apache-2.0. A materially different distribution or licensing model requires a superseding owner-approved ADR; an implementation agent cannot make that decision.

## Traceability

- Capabilities: `MVP-CAP-NONCHOICES`
- Acceptance: `JSMVP-R001`, `JSMVP-R011`
- Evidence: [`../../LICENSE`](../../LICENSE), frozen seed commit and license hash above
