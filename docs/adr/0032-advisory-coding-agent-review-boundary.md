# ADR-032: Advisory Coding-Agent Review Boundary

- Status: Accepted, safety-critical
- Date: 2026-07-17
- Owners: product owner, application-delivery owner, security owner
- Supersedes: coding-agent review as implicit approval
- Superseded by: None

## Context and decision

Codex and Claude Code PR review integrations are optional, separately customer-authorized, exact-head-bound, and advisory. Dispatch binds exact repository/PR/base/head, command, nonce, and expected actor; review polling verifies the same head. Review can report findings but cannot customer-validate, patch, merge, deploy, consent, approve a migration decision, or alter traffic authority.

## Alternatives and rejection

Using the Jumpship App token for model review, accepting arbitrary comments, or treating reviewer success as approval creates injection, scope, and authority confusion.

## Consequences, migration, and rollback

Unavailable providers produce an honest manual handoff. Stale or disagreeing review remains visible and cannot advance gates. A reviewer may become policy authority only through a separately accepted contract and requalification.

## Traceability

- Capabilities: `MVP-CAP-EXTERNAL-PR-REVIEW`, `MVP-CAP-AGENT-INCAPABILITY-DISCLOSURE`
- Acceptance: `JSMVP-R002`, `JSMVP-R044`, later review/application rows
- Evidence: [`../../PRODUCT.md`](../../PRODUCT.md), [`../../contracts/capabilities/mvp.yaml`](../../contracts/capabilities/mvp.yaml)
