# ADR-011: Region Placement Solver

- Status: Accepted
- Date: 2026-07-17
- Owners: infrastructure owner, product owner
- Supersedes: source-region-only placement wording
- Superseded by: None

## Context and decision

Placement is a foundation decision computed from source, application, target options, residency, private connectivity, Bedrock route, transfer volume, latency, and cost. The target normally follows the long-lived application; worker and golden bucket minimize repeated heavy transfers. Inputs, recommendation, alternatives, and pricing/profile versions are immutable evidence.

## Alternatives and rejection

Always co-locating with the source optimizes a temporary leg while potentially imposing permanent application latency. A hidden default violates one-way-door and cost-honesty rules.

## Consequences, migration, and rollback

Discovery produces TTL-bound evidence before target resources exist. Final placement is confirmed as a foundation decision and moving later requires a new target/rehearsal path. A measured solver result may select a different triple without superseding the algorithm.

## Traceability

- Capabilities: `MVP-CAP-PLACEMENT-SOLVER`, `MVP-CAP-FOUNDATION-DECISIONS`, `MVP-CAP-FANOUT-COST`
- Acceptance: `JSMVP-R002`, later placement/foundation rows
- Evidence: [`../architecture/system-boundaries.md`](../architecture/system-boundaries.md)
