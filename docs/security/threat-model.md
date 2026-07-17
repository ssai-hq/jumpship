# Public Threat Model

## Security outcome

Compromise, adversarial customer material, provider failure, stale state, or a model mistake must not grant cross-tenant access, source mutation, consent bypass, split application write authority, evidence forgery, secret disclosure, self-provisioning, or premature deletion claims.

## Protected assets and adversaries

Protected assets include customer records/code/query evidence, credentials, tenant identity, canonical migration state, approved specs/rubrics, traffic authority, immutable snapshots/manifests, proof/deletion signing keys, release authority, and audit continuity.

Threat sources include malicious or compromised users, browser extensions and pasted content, repository/data prompt injection, compromised dependencies/images/actions, provider callbacks/errors, stolen credentials, stale cells or grants, crash/retry races, insider misuse, misconfiguration, regional failure, and a reasoning model that follows hostile instructions or makes a confident mistake.

## Required denials

- Workspace and database roles fail closed without transaction-local workspace/principal context; composite tenant foreign keys prevent cross-workspace references.
- Every cell has a distinct generation, VPC, workload/runtime/tool roles, KMS scope, secrets namespace, storage prefix, database roles, and signed manifest. Account-wide discovery is absent.
- Agent and deterministic tool identities are separate. Tool execution requires an exact input/schema/hash/phase/epoch/consent grant and emits a terminal receipt.
- Model output, memory, analysis output, telemetry, and provider status are advisory/non-authoritative until a deterministic contract and gate consume them.
- Raw evidence crosses to the browser only through a one-artifact short-lived capability and never through Vercel or a shared proxy/cache.
- Source writes require the reverse-only credential. Customer workload writes require current store/authority/cohort grants; unknown or unfenceable writers freeze progression.
- Signers are purpose-, environment-, and caller-separated. Proof, deletion, audit, bundle promotion, and emergency-stop signatures cannot substitute for one another.
- Decommission uses inventory states and independent attestation. Object retention and scheduled key deletion are disclosed until final provider proof exists.
- Release activation is a reviewed, readiness-bound compare-and-swap against the current pointer and active-binding inventory; quality evaluation cannot sign or activate its own result.

## Prompt and tool containment

Every customer artifact is untrusted instruction-wise. The context compiler supplies an immutable constitution, typed task/acceptance condition, current canonical projection, provenance-bearing memories, and the smallest evidence excerpts. The agent receives no ambient credential or generic cloud/database/shell capability.

Exploratory code is allowed only through `analysis.run.v1`: a release-pinned, no-network/no-secret container with declared read-only mounts, CPU/memory/time/output limits, quarantine, leak/schema scanning, and a typed sanitized result. It cannot run in transform, load, CDC, reverse, verification, traffic-gate, or proof-signing paths.

## Stop rules

Implementation or release stops on an unresolved critical boundary ambiguity, cross-tenant or source-write path, unredacted restricted evidence in a shared surface, signature-purpose confusion, unknown writer, source/target dual-authority interval, unverifiable evidence, unaccepted external gate, open critical defect, or a test that passes only by weakening the contract.

The complete public data-flow allowlist is in [`data-classification-and-flows.md`](./data-classification-and-flows.md). Later packets own executable IAM, RLS, protocol, fuzz, chaos, kill, security, and release qualification evidence.
