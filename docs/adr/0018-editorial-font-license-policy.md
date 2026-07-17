# ADR-018: Editorial Font License Policy

- Status: Accepted; production asset-provenance gate unresolved
- Date: 2026-07-17
- Owners: product/design owner, legal/provenance owner
- Supersedes: None
- Superseded by: None

## Context and decision

Tiempos Text is the selected SSAI editorial face, paired with Geist Sans and Geist Mono. Production self-hosting of Tiempos is prohibited until a recorded webfont license and exact asset-provenance evidence are accepted. Visual qualification fails closed while that preflight gate remains pending.

## Alternatives and rejection

Using an unverified font file creates licensing and supply-chain risk. Silently substituting a different editorial face would invalidate brand and visual baselines.

## Consequences, migration, and rollback

P22 may develop with an honest fallback but cannot claim production typography or close its visual gate. A newer accepted brand decision may choose a replacement and requalify typography/accessibility/visual fixtures.

## Traceability

- Capabilities: `MVP-CAP-SESSION-SHELL`
- Acceptance: `JSMVP-R001`, later visual/provenance rows
- Evidence: [`../../DESIGN.md`](../../DESIGN.md); unresolved preflight is intentionally not represented as approved
