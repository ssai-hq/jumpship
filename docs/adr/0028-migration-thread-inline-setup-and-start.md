# ADR-028: Migration Thread, Inline Setup, and Start

- Status: Accepted
- Date: 2026-07-17
- Owners: product owner, web owner, API owner
- Supersedes: separate connect wizard and phase-rail assumptions
- Superseded by: None

## Context and decision

One migration is one Codex-like workspace-sidebar thread. Custody, mandatory connections, optional recommendations, and discovery readiness render inside it. The composer remains locked until MongoDB, the selected PostgreSQL target, and GitHub are backend-proven connected. Its first prompt atomically records one message, advances `connect -> discovery`, and emits one wakeup effect.

## Alternatives and rejection

A detached onboarding wizard fragments the engagement's evidence/history. Client-only readiness or multiple start routes creates duplicate or premature migrations.

## Consequences, migration, and rollback

P08 owns the atomic command; P23/P24 own exhaustive state rendering and reconnect races. A newer accepted product master may replace the interaction model only while preserving backend readiness/start authority.

## Traceability

- Capabilities: `MVP-CAP-CONNECT-STAGED`, `MVP-CAP-SESSION-SHELL`
- Acceptance: `JSMVP-R044`, `JSMVP-R045`
- Evidence: [`../../PRODUCT.md`](../../PRODUCT.md), [`../../DESIGN.md`](../../DESIGN.md)
