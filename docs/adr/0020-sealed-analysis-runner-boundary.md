# ADR-020: Sealed Analysis Runner Boundary

- Status: Accepted
- Date: 2026-07-17
- Owners: agent-runtime owner, security owner
- Supersedes: arbitrary agent-authored execution
- Superseded by: None

## Context and decision

Agent-authored exploratory diagnostics run only through the typed `analysis.run.v1` capability in a release-pinned container with declared read-only mounts, no network/secrets, strict resource/output limits, quarantine, schema/leak scanning, and a receipt. It is never part of transform, load, CDC, reverse, verification, gate, traffic, or signing paths.

## Alternatives and rejection

General shell, SQL, MCP, cloud, or database access makes prompt injection an effect-authority path. Banning diagnostics entirely would remove useful bounded exploration.

## Consequences, migration, and rollback

P02 owns the contract; P20 owns runner/broker/sanitizer; P21 qualifies adversarial behavior. A replacement must preserve equal containment and evidence.

## Traceability

- Capabilities: `MVP-CAP-SEALED-ANALYSIS-RUNNER`, `MVP-CAP-AGENT-INCAPABILITY-DISCLOSURE`
- Acceptance: `JSMVP-R039`, `JSMVP-R042`, `JSMVP-R062`
- Evidence: [`../security/threat-model.md`](../security/threat-model.md)
