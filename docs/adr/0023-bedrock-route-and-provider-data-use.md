# ADR-023: Bedrock Route and Provider Data Use

- Status: Accepted architecture; release-bound provider review unresolved
- Date: 2026-07-17
- Owners: security/data owner, agent-runtime owner, release owner
- Supersedes: public-provider fallback assumptions
- Superseded by: None

## Context and decision

Customer-data inference uses an exact regional `anthropic.claude*` model ARN through standard Amazon Bedrock Runtime from the cell, with a VPC endpoint, cell IAM, and invocation-body logging disabled. A current release-bound provider-data-use record/review/transition must prove route and policy eligibility. Public, cross-region inference-profile, or data-sharing routes are ineligible and have no customer-data fallback.

## Alternatives and rejection

Public/provider fallback and unbound model aliases weaken residency, identity, audit, and data-use claims. AgentCore is not the MVP runtime substrate under ADR-014.

## Consequences, migration, and rollback

Provider evidence expiry or invalidation stops lease renewal and visibly blocks new calls. The architecture decision is accepted, but the separate provider approval gate remains open until actual evidence is supplied; P00 does not claim it.

## Traceability

- Capabilities: `MVP-CAP-AGENT-RUNTIME`, `MVP-CAP-CREDENTIAL-CUSTODY`
- Acceptance: `JSMVP-R001`, later provider/data-use rows
- Evidence: [`../security/data-classification-and-flows.md`](../security/data-classification-and-flows.md); unresolved provider gate remains external to P00
