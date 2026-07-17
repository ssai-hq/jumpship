# Data Classification and Allowed Flows

These identifiers are future code/schema values, not informal labels. A derivative inherits the highest input class unless a deterministic, versioned sanitizer proves a lower class. Hashing a low-entropy customer value does not declassify it.

## Classes

| Code | Meaning | Allowed authority/store | Never allowed |
|---|---|---|---|
| `public` | Public docs, public keys, non-customer product names | Public repository, web, CDN | Secrets or customer-specific material |
| `internal_operational` | Image digests, safe health/reason codes, template versions | Scoped shared control, Mothership, central operations | Customer values, credentials, raw prompts |
| `identity_tenant` | Verified identity, membership, invites, WebAuthn public metadata | Shared RDS/API and workspace-authorized UI | Cell/Mothership exports or public telemetry |
| `shared_migration` | Contract-permitted counts, hashes, safe paths, specs, decisions, states, verdicts, bounded summaries | Shared RDS/API and authorized browser | Raw values/code/query bodies/credentials |
| `restricted_customer` | BSON, dumps, repository bodies, query/log parameters, CDC images, quarantine rows, manifests, prompts/completions | One cell's PostgreSQL/EBS/S3, approved regional Bedrock, exact direct-browser capability | Shared RDS/SQS, Vercel server, Mothership, central logs, cross-migration learning |
| `credential_secret` | Mongo URI, target/provider tokens or credentials, GitHub installation token, reverse-write credential | Exact Secrets Manager/KMS location and ephemeral consumer | Product database, IaC state, browser storage, events, logs, model context |
| `security_material` | Token/challenge hashes, private signing/CA material | Purpose-specific RDS hash, KMS/Secrets store, exact signer/runtime | Cell agent, public response, telemetry, generic configuration |

Field paths and schema names may be `shared_migration` only when the product contract permits them; examples and values remain `restricted_customer`. Generated patches, PR/review bodies, CI output, and customer edits remain restricted even after publication to a private customer repository. Provider/tool errors are classified from their unredacted bodies; only stable mapped reason codes cross the diode.

## Flow allowlist

Anything not listed is denied until its contract, classification, IAM/network policy, threat model, and tests change together.

| ID | From → to | Permitted content | Required controls and explicit denial |
|---|---|---|---|
| F01 | Browser → Vercel shell | `public`, presentation state | TLS/CSP; no credential or raw-evidence body in server action/log |
| F02 | Browser ↔ control API | `identity_tenant`, `shared_migration`; dedicated secret intake only | Cookie, CSRF/origin, OpenAPI, size limits; no restricted response/body |
| F03 | Control API ↔ shared RDS | Canonical product state, hashes, handles, safe summaries | TLS, forced RLS, scoped role, transactions; no raw artifact/credential/tool blob |
| F04 | Control → per-cell Secrets Manager | Exact credential version lifecycle and service-side relocation/reissue | Signed custody manifest, put-only writer, receipts; no intake before placement or get/decrypt/list |
| F05 | Control/coordinator → SQS/Scheduler | Typed wakeup IDs/hashes | Signed envelope, encryption, dedupe/DLQ; no raw data, prompt, credential, or workflow authority |
| F06 | Backend ↔ cell | Signed projection, spec/rubric, grant, safe summary/receipt | Outbound mTLS typed protocol and data-class check; no record/code/query/CDC/quarantine/prompt dump |
| F07 | Mothership ↔ cell | Deployment/custody manifest, bootstrap identity, infrastructure liveness | Signed template/generation; no phase, evidence, secret value, semantics, or in-place privilege widening |
| F08 | Cell ↔ source | Snapshot/read/change stream | Read-only credential, TLS/private rung, egress allowlist; no baseline source mutation |
| F09 | Reverse tool → source | Approved reverse-state effect | Separate time-bounded write credential and exact grant/epoch; no agent/general-engine use |
| F10 | Cell ↔ target | Probe, rehearsal, load, CDC, verify, reverse feed | Direct endpoint, typed tool, target epoch/receipts; no agent SQL or stale-generation effect |
| F11 | Dedicated cell adapter ↔ GitHub | Selected repo read, sealed patch, namespaced draft PR, exact review trigger/poll | Staged tokens and compiled method/path/repo/ref/tree/body allowlist; no generic HTTP, unselected repo, merge, deploy, workflow/settings/admin write, or shared code webhook |
| F12 | Cell → Bedrock | Smallest required restricted context | Exact approved same-region model route/VPC/IAM, body logging disabled; no public/cross-region fallback |
| F13 | Cell → cell stores | Raw evidence, checkpoints, prompts, tool output, manifests | Cell KMS/IAM and scoped database/prefix; no cross-cell resource |
| F14 | Browser ↔ cell evidence store | One exact upload/download artifact | One-use nonce, short bearer lifetime, no-store/no-referrer; no list or prefix capability |
| F15 | Cell → shared quality | Sanitized scores, reason codes, bundle/corpus hashes | Explicit export schema; no identity, prompt, completion, memory, or raw trajectory |
| F16 | Backend → Slack/SES/on-call | Minimal summons, digest, status, deep link | Least scope and delivery receipt; channel cannot mutate consent or carry credentials/raw evidence |
| F17 | Runtime → telemetry/audit | IDs, safe codes, timings, hashes, consequential spans | Source redaction and bounded labels; no bodies, values, tokens, query/prompt text |
| F18 | Cell broker → inline observation/sealed analysis | Pre-authorized read-only scope and declared restricted mounts/profile | Pinned descriptor, cumulative limits, no network/secrets/effect authority; output quarantined and sanitized |
| F19 | Provider → callback ingress | One-use OAuth/OIDC/App callback | Dedicated callback listener, state/PKCE/nonce, whole-query/cookie/auth redaction; no logged main listener or arbitrary path |
| F20 | Coordinator ↔ deletion attestor | Canonical deletion root and safe component receipt inventory | Independent cross-account verifier/signer; no raw object/secret, cell decrypt, RDS access, or coordinator self-signing |
| F21 | Protected release/incident workflow → bundle activator | Kind-specific digest-bound promotion or emergency-stop envelope | Separate keys/purposes, exact identities/reviewers, one-off narrow function; no cross-kind replay, quality self-activation, or fabricated recovery |
| F22 | Browser/API → provider callback → API completion | One-use prepare/completion secret and safe handle/pending secret version | Redacted POST, separate host cookie, exact browser/origin/intent, atomic consume; callback cannot create session/active grant |
| F23 | Human automation → local broker → public API/browser ceremony | Typed safe request/handle/receipt and exact human ceremony metadata | OS store, peer-checked protected socket, method allowlist; no bearer IPC/stdout/env/log or coding-agent ceremony |
| F24 | Jumpship → GitHub → customer reviewer | Exact repo/PR/base/head plus pinned command nonce/actor | Separate review token and exact polling/manual fallback; no Jumpship model-body export, arbitrary comment, approval/effect promotion, patch/merge/deploy |
| F25 | Source-fence adapter → MongoDB/provider/network control | Exact inventoried principal/role/network revoke, terminate, denial proof, authorized restore | No-data credential and compiled allowlist; no record access, unlisted principal, agent/engine use, or silent/manual success |
| F26 | Customer workload → control/coordinator/cell grant broker | Released workload attestation, ephemeral public key, safe claims, encrypted envelope | Dedicated audience, build/config/env binding, short TTL, reserve/sign/complete; no plaintext shared-plane credential or stale/cross-workload grant |
| F27 | Customer workload → source or target | Writes for exactly one store under current grant generation | Role/gate checks, expiry/revocation/session termination; no dual-store fallback, stale/wrong-build grant, old role/session, or target bypass |
| F28 | Evidence adapter ↔ deployment controller/workload/CI trust endpoint | Versioned trust proof, artifact digest, read-only rollout identity, nonce, signed runtime heartbeat | Exact scope and pinned trust/rotation/revocation/freshness; no deployment/config mutation, self-registered trust, replay, or CI claim without runtime proof |

This matrix is P00's classification/flow contribution. Runtime contract fields and enforcement tests remain owned by later packets; the registry's `planned` status makes that distinction explicit.
