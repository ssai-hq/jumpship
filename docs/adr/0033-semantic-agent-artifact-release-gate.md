# ADR-033: Semantic Agent Artifact Release Gate

- Status: Accepted
- Date: 2026-07-17
- Owners: agent-runtime owner, quality owner, release owner
- Supersedes: prompt prose as unversioned implementation detail
- Superseded by: None

## Context and decision

P20 implements prompt/skill prose, but release requires a non-placeholder semantic artifact inventory. Each artifact binds path/hash, compatible phases/provider profile, input/output schemas, evidence/citation requirements, allowed tools, authority/stop/refusal rules, forbidden claims, examples/adversarial fixtures, AgentBundle identity, and independent P21 eval IDs.

## Alternatives and rejection

Shipping unversioned prompts or self-evaluated examples makes runtime behavior irreproducible and permits silent authority drift.

## Consequences, migration, and rollback

Any semantic component change creates a new AgentBundle and affected qualification evidence. Independent quality can evaluate but cannot sign/activate its own unit. A new runtime must preserve equal semantic completeness and release gates.

## Traceability

- Capabilities: `MVP-CAP-AGENT-RUNTIME`, `MVP-CAP-CROSS-MIGRATION-LEARNING`, `MVP-CAP-PRIME-DIRECTIVE`
- Acceptance: `JSMVP-R001`, later agent-quality/release rows
- Evidence: [`../architecture/contract-versioning.md`](../architecture/contract-versioning.md)
