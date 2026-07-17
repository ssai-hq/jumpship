# ADR-008: Vercel Presentation Boundary

- Status: Accepted
- Date: 2026-07-17
- Owners: web owner, security/data owner
- Supersedes: None
- Superseded by: None

## Context and decision

Vercel Pro hosts only the Next.js presentation and navigation layer. Browsers call the public AWS API directly using the API-host session boundary. AWS owns authentication, canonical business state, SSE, evidence capability issuance, and effects.

## Alternatives and rejection

Proxying auth, raw evidence, or business mutations through Vercel creates a second authority/data path and weakens custody claims. All-AWS frontend hosting is unnecessary without a contractual requirement.

## Consequences, migration, and rollback

Frontend code contains no production secret or raw-evidence server path. CORS, cookies, origins, preview protection, CSP, and generated-client behavior are release evidence. A customer contract may require an all-AWS superseding deployment.

## Traceability

- Capabilities: `MVP-CAP-SESSION-SHELL`, `MVP-CAP-ARCH-TRUST-DOMAINS`
- Acceptance: `JSMVP-R001`, `JSMVP-R044`, later browser/network rows
- Evidence: [`../security/data-classification-and-flows.md`](../security/data-classification-and-flows.md)
