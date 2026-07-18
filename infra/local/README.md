# Local fixture stack

P03 provides a reproducible, local-only integration surface. It creates no cloud resources, invokes no cloud CLI, mounts no container socket, and accepts no production credentials. Every published port is fixed to `127.0.0.1`; every checked-in credential is conspicuously synthetic.

## Lifecycle

The root Make targets call the checked-in controller, which can also be used directly:

```text
infra/local/bin/stack config --quiet
infra/local/bin/stack up
infra/local/bin/stack up --profile network --profile agent --profile observability
infra/local/bin/stack down
infra/local/bin/stack reset --confirm destroy:jumpship-local:volumes
```

`down` preserves every named volume. `reset` resolves and prints the exact local Docker context, Unix-socket endpoint, fixed `jumpship-local` project, and its six exact volume names before it accepts the confirmation token. The validated socket is then pinned explicitly through every inspection and destructive Compose call. It never calls a broad `docker volume prune`, accepts simultaneous/remote Docker selectors, or accepts a caller-supplied project name.

The controller always uses [`.env.example`](.env.example), removes host `COMPOSE_FILE`, `COMPOSE_PROFILES`, and `COMPOSE_PROJECT_NAME` overrides, and validates the rendered configuration before starting or resetting anything. Port values can be overridden in the invoking environment, but bind addresses cannot.

## Services and profiles

The default `local` topology contains PostgreSQL 17.10 control, cell, and target roles; an authenticated single-node MongoDB source replica set; MinIO; and Mailpit. `dev-up` proves the Mongo initializer exited successfully and then performs an authenticated `hello` assertion that `rs0` elected a writable primary. Empty fixture databases are deliberate: schema, migration, and product fixtures belong to later packets.

Host-side MongoDB clients connect to loopback on the configured Mongo port with the synthetic user/password from [`.env.example`](.env.example), database `admin`, and URI options `replicaSet=rs0&directConnection=true&authSource=admin`. The direct-connection flag is required because the single replica-set member intentionally advertises its internal-only `mongo:27017` identity. `dev-up` exercises this fixed ingress corridor with an authenticated client and opens a change stream before reporting healthy.

Optional profiles are additive:

- `network` adds Toxiproxy and a deterministic allowed-egress HTTP fixture. It does not proxy arbitrary internet traffic.
- `agent` adds deterministic Bedrock-shaped, chat, and tool-broker HTTP fixtures. They have no production fallback.
- `observability` adds an OpenTelemetry collector that exports only to its local debug stream after dropping query/URL/provider attributes and replacing every log body with a redaction marker.
- `web` and `full` are explicit fail-closed ownership boundaries. P03 does not invent application services owned by later packets. `infra/local/bin/dev web|api` likewise refuses cleanly until the corresponding packet supplies its real entrypoint.

The `full` profile activates all P03-owned optional fixtures and then exits with a clear unavailable message. Later application packets may replace that boundary only through their authorized scope.

## Security and reproducibility

All eight third-party images are immutable multi-architecture digest references. Local persisted state lives only in the six explicitly named `jumpship-local-*` volumes. Every data/provider/telemetry fixture lives only on the hard-internal `fixtures` network. Four fixed-config HAProxy relays are the sole dual-homed services and sole port publishers; their host publications bind to `127.0.0.1`, their configuration is read-only, and they expose no HAProxy statistics, runtime API, or caller-selected upstream. This is the local enforcement contribution to `MVP-CAP-ARCH-TRUST-DOMAINS`; adopting a fixed relay instead of a remotely configurable general proxy is an explicit `MVP-CAP-NONCHOICES` boundary. Optional HTTP fixtures mount read-only mappings and run without Linux capabilities or writable root filesystems.

Never copy a real token, credential, customer payload, or provider response into this directory. For a private local port override, export only the relevant `JUMPSHIP_*_PORT` variable in your shell; do not add a committed environment file.
