# P03 runtime-profile proof

The following local-only profile set was exercised together on `2026-07-18`:

```text
infra/local/bin/stack up --profile network --profile agent --profile observability --wait-timeout 180
```

Result: exit `0`. Sixteen long-running services were ready and `mongo-init` exited `0`. The controller reported the profile set `local, network, agent, observability` healthy after its service and host-side probes.

Boundary observations:

- The three PostgreSQL roles, MongoDB, MinIO, Mailpit, Toxiproxy, all four WireMock fixtures, and the OpenTelemetry collector attached only to the hard-internal `fixtures` network.
- Only `local-ingress`, `network-ingress`, `agent-ingress`, and `observability-ingress` were dual-homed to `fixtures` and `host-ingress`; only those four immutable HAProxy relays published ports, all on `127.0.0.1`.
- The authenticated Mongo host-consumer proof used `replicaSet=rs0`, `directConnection=true`, and `authSource=admin`, entered through `local-ingress`, and opened a change stream from an unprivileged, read-only, capability-free one-shot client attached only to `host-ingress`.
- Mongo direct internet egress was denied with `Network is unreachable`.
- The OpenTelemetry collector accepted local trace, metric, and log endpoints only after its configuration had removed payload-bearing URL/query/provider attributes and replaced log bodies with a redaction marker.

Teardown command `infra/local/bin/stack down` exited `0`; a subsequent project-label container query returned no containers. Named volumes were preserved.
