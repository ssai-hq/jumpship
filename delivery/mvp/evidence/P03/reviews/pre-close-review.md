# P03 pre-close review

Review date: `2026-07-18`.

Scope and architecture:

- All P03 product changes are under `infra/local/**`, `.github/actions/**`, the eight authorized workflow patterns, `scripts/ci/**`, `test/support/ci/**`, `mk/packets/P03.mk`, or this P03 evidence namespace.
- No product handler, persistence implementation, domain behavior, infrastructure resource, provider credential, cloud apply/deploy path, P00 capability fragment, P02 contract, root dependency lock, or frozen planning input was changed.
- The local architecture is a fixed two-network trust boundary: protected fixtures occupy only a hard-internal network; four immutable, read-only HAProxy relays are the only dual-homed services and port publishers.

Correctness and failure behavior:

- The safe lifecycle controller fixes the Compose project and env file, allowlists inherited environment, rejects remote/simultaneous Docker selectors, validates profiles and rendered Compose before startup, waits for service readiness, and pins the validated local Unix endpoint across reset confirmation and deletion.
- `down` preserves state. `reset` accepts one exact confirmation token and can remove only six exact named volumes; no prune or caller-selected project/path exists.
- MongoDB is an authenticated single-node replica set. Startup requires initializer exit `0`, writable-primary proof, and an authenticated host-ingress change-stream proof using direct connection semantics.
- Optional `network`, `agent`, and `observability` fixtures are deterministic and additive. Later-owned `web` and `full` application boundaries fail closed instead of inventing product services.
- Workflow guards bind the closed P02 deployment registry, reject static credentials and unauthorized refs before OIDC or output, require immutable release digests, and never invoke apply or deploy.
- Gate dispatch uses the live command inventory and records future owners as `planned-not-evaluated`; it cannot turn an absent future target into a passing result.
- All third-party images and actions are immutable. The pinned offline Trivy secret scan emits only a bounded safe summary and raw-report digest.

Security and data boundaries:

- No service mounts the Docker socket, uses host networking, runs privileged, or accepts an arbitrary upstream. Protected fixtures have no direct host publication or internet route.
- Fixture credentials and payloads are synthetic. No real secret, credentialed URI, raw customer evidence, provider response, or external evidence reference is present in P03 evidence.
- The OpenTelemetry configuration drops payload-bearing URL/query/provider fields and replaces log bodies before the local debug exporter.
- Detailed CI artifacts include hidden `.ci-artifacts` content deliberately, have bounded retention, fail if absent, and are redacted before upload.

Findings fixed before close:

- Artifact uploads were hardened to include hidden evidence directories, and workflow policy now rejects any future omission.
- Mongo host-consumer documentation and runtime proof were strengthened with exact direct-connection options and an unprivileged ingress-only change-stream client.
- The first isolated rehearsal exposed a macOS Docker Desktop packaging dependency: Compose lived in the source user's plugin directory and disappeared with isolated `HOME`. P03 now copies only the resolved Compose v2 executable into an empty isolated Docker config, verifies its SHA-256 after copying, records its version/hash, and forwards no source Docker configuration or authority. The binding rehearsal then passed.
- Independent re-review reproduced the change-stream server path, the isolated Compose discovery, workflow policy, local tests, and staged diff. No P0-P3 finding remains.

Final local result: required acceptance, clean-clone R013 rehearsal, complete optional-profile runtime proof, workflow policy, secret scan, format, lint, documentation, and supplemental repository verification pass. P03 has no unresolved manual/external gate, scope exception, skipped required check, or known defect.
