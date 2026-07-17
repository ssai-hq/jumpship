# System Boundaries

## Product topology

Jumpship is built from one versioned repository and release unit, deployed into distinct trust roles:

| Domain | Runtime purpose | Authority | Explicit denial |
|---|---|---|---|
| Vercel web | Next.js presentation, navigation, client rendering | Ephemeral UI state only | Product auth/business authority, credentials, raw evidence |
| Shared control | Go API, coordinator, canonical RDS, outbox/scheduling | Identity, workspace, migration state, decisions, approved artifacts, consent, grants, audit | Raw cell evidence and ambient cell access |
| Mothership | Signed cell provision/bootstrap/liveness/restart/revoke/destroy reconciliation | Narrow infrastructure lifecycle role | Shared-RDS route, migration semantics, evidence decrypt, agent quality |
| Migration cell | Conductor harness, deterministic engine, Cell PostgreSQL, EBS/S3 working evidence | One migration generation's authorized execution | Other cells, deployment authority, canonical shared-state mutation |
| Customer/provider systems | MongoDB source, selected PostgreSQL target, GitHub, optional connectors | Customer-owned data/application systems | Unscoped Jumpship access or authority transfer |

The control API compiles desired state and authorizes operations. Mothership provisions only a signed cell envelope. The conductor chooses and explains work, but invokes named capabilities. Deterministic tools execute exact grants. No cell component provisions, widens, restarts, or destroys itself.

## Store authority

- Shared RDS permanently stores identity, tenancy, canonical migration state, decisions, approved specs/rubrics, consent, safe evidence metadata, audit, outbox/inbox, schedules, release bindings, and final durable outcomes.
- Cell PostgreSQL temporarily stores run/checkpoint/wait state, agent events and memory, context manifests, model metadata, tool requests/receipts, and engine checkpoints.
- Cell EBS and S3 temporarily store raw BSON, dumps, source code evidence, query/CDC bodies, quarantine rows, prompts, manifests, and other restricted artifacts.
- Secrets Manager/KMS store credentials and private key material by exact purpose; application databases and IaC state store only handles and lifecycle metadata.
- Telemetry holds redacted operational signals and never determines product state.
- Customer source and target remain external and customer-owned. Jumpship's golden snapshot and working replicas are temporary custody, not a hosted permanent target.

Before cell teardown, the backend deterministically consolidates approved customer-facing outcomes and evidence roots into shared authority. Raw working memory is not retained merely for continuity.

## Migration and application authority

The deterministic Go engine owns snapshot, census, mapping compilation, load, CDC apply, reconciliation, verification, reverse sync, and effect gates. One immutable transform plan serves batch and change-event drivers.

Jumpship inventories the complete selected application estate and automatically publishes authorized draft PRs from sealed changes. The customer alone validates, merges, and deploys. Cutover waits for exact source-revision-to-artifact-to-rollout-to-running-digest proof and for every writer cohort to be known, fenced, drained, and operating under one application-authority epoch. Source and target application writes are never enabled together in the MVP.

## Custody and placement

Placement is a deterministic foundation decision over source region, application regions, target availability, residency, private-connectivity rung, Bedrock availability, transfer volume, latency, and cost. The long-lived application/target relationship takes priority; worker and golden-bucket placement minimizes repeated heavy movement. Chosen and rejected alternatives are ledgered.

Discovery uses a restricted custody capsule before final placement. Secret intake requires a signed regional custody manifest. Moving from discovery to the final cell uses version-bound service-side replication or reissue with old-copy deletion receipts; plaintext relocation is prohibited.

## Retention and deletion

Deletion is a multi-state process. Decommission immediately revokes access, stops operations, initiates teardown, and records `retain_until` for immutable/object/key semantics. A preliminary attestation cannot claim physical deletion. The final attestation is emitted only after the complete inventory proves provider retention and cryptographic deletion states have finished under a separate surviving signer.

## Consent and decisions

Cutover and decommission are the only consent kinds. Both bind a named approver, fresh WebAuthn step-up, current evidence, typed phrase, exact state/version, and timeout-to-deny. Foundation confirmation, design/spec approval, quarantine rulings, rubric confirmation, rehearsal start, and rollback are versioned decisions or operations, not consent aliases.
