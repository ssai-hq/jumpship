# ADR-015: Authentication and WebAuthn Step-Up

- Status: Accepted
- Date: 2026-07-17
- Owners: identity owner, security owner
- Supersedes: generic session-only consent
- Superseded by: None

## Context and decision

OIDC login requests identity-only scopes and remains separate from connector grants. WebAuthn/passkeys are the MFA and fresh step-up factor for bound named approvers at cutover and decommission. Consent also binds the exact evidence/state/version and typed phrase; silence or timeout denies.

## Alternatives and rejection

Session-cookie-only authorization cannot establish fresh intent. Connector scopes at login create a permissions wall and mix identity with integration authority.

## Consequences, migration, and rollback

P06/P23 own enrollment, readiness, recovery, ceremony, and accessibility tests. An accepted equivalent factor may be added only for demonstrated accessibility/customer constraints without weakening fresh named-approver binding.

## Traceability

- Capabilities: `MVP-CAP-IDENTITY-LOGIN`, `MVP-CAP-CONSENT-STEPUP`, `MVP-CAP-WORKSPACE-RBAC`
- Acceptance: `JSMVP-R044`, later auth/consent rows
- Evidence: [`../../PRODUCT.md`](../../PRODUCT.md), [`../security/threat-model.md`](../security/threat-model.md)
