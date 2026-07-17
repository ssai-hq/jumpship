# Jumpship Security Policy and Architecture

Jumpship handles customer database contents, source code, credentials, and migration authority. Security is therefore enforced through distinct identities, stores, networks, protocols, grants, state machines, and cryptographic purposes—not through an assumption that components sharing a cloud provider trust each other.

## Reporting vulnerabilities

Do not open a public issue containing a vulnerability, credential, customer identifier, or exploit detail. Use the private security contact published by the repository owner. If no private contact is available, report only that a private channel is required and withhold sensitive details until one is established.

## Non-negotiable boundaries

- Raw customer records, repository bodies, query/log parameters, CDC images, quarantine rows, prompts, and unrestricted tool output stay in one migration cell and the approved regional Bedrock path.
- Credentials live only in purpose-scoped Secrets Manager/KMS custody and an ephemeral consuming process. They do not enter product databases, IaC state, browser storage, events, logs, or model context.
- Shared RDS is canonical product authority; Cell PostgreSQL/EBS/S3 are temporary execution and raw-evidence stores; telemetry is redacted and non-authoritative.
- Mothership has no shared-RDS path, customer-data decrypt capability, migration semantics, prompt access, or agent-quality authority.
- The agent has no ambient cloud discovery, IAM mutation, source-write credential, arbitrary shell/SQL/MCP, direct traffic flip, proof-signing key, or self-lifecycle authority.
- Every consequential effect requires a backend-owned durable operation, an exact scoped grant, idempotency identity, receipt reconciliation, and current phase/epoch/consent checks.
- Baseline source access is read-only. Reverse sync uses a separate, time-bounded credential only after its gate.
- Cutover and decommission require a fresh bound named approver and WebAuthn step-up. Timeout and uncertainty fail closed.

The enforced classifications and complete P00 flow allowlist are in [`docs/security/data-classification-and-flows.md`](./docs/security/data-classification-and-flows.md). Trust boundaries and the public threat summary are in [`docs/security/threat-model.md`](./docs/security/threat-model.md). Security-relevant architecture decisions are indexed in [`docs/adr/README.md`](./docs/adr/README.md).

## Public repository hygiene

Only synthetic fixtures may be committed. Do not commit customer data or code, credentials, connection strings, tokens, prompts, transcripts, private provider evidence, raw traces, or identifying screenshots. Redacted packet evidence belongs only under its declared `delivery/mvp/evidence/<node>/` namespace and must be safe for this public repository.
