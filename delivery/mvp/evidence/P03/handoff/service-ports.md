# P03 local service-port handoff

Every publication is fixed to loopback. The environment may override only the numeric `JUMPSHIP_*_PORT`; it cannot override the bind address, Compose project, networks, or upstream service.

| Profile | Host corridor | Default loopback port | Internal destination |
| --- | --- | ---: | --- |
| `local` | control PostgreSQL | `15432` | `control-postgres:5432` |
| `local` | cell PostgreSQL | `15433` | `cell-postgres:5432` |
| `local` | target PostgreSQL | `15435` | `target-postgres:5432` |
| `local` | MongoDB source | `27017` | `mongo:27017` |
| `local` | MinIO API | `19000` | `minio:9000` |
| `local` | MinIO console | `19001` | `minio:9001` |
| `local` | Mailpit SMTP | `11025` | `mailpit:1025` |
| `local` | Mailpit UI | `18025` | `mailpit:8025` |
| `network` | Toxiproxy API | `18474` | `toxiproxy:8474` |
| `network` | Toxiproxy data | `18666` | `toxiproxy:8666` |
| `network` | deterministic allowed-egress fixture | `18083` | `allowed-egress-fixture:8080` |
| `agent` | deterministic Bedrock-shaped fixture | `18080` | `fake-bedrock:8080` |
| `agent` | deterministic chat fixture | `18081` | `fake-chat:8080` |
| `agent` | deterministic tool-broker fixture | `18082` | `fake-tool-broker:8080` |
| `observability` | OTLP gRPC | `14317` | `otel-collector:4317` |
| `observability` | OTLP HTTP | `14318` | `otel-collector:4318` |
| `observability` | collector health | `13133` | `otel-collector:13133` |

Host-side Mongo clients must use database `admin` and URI options `replicaSet=rs0&directConnection=true&authSource=admin`. The checked-in synthetic username and password remain in `infra/local/.env.example`; they are intentionally not duplicated into evidence.

No protected fixture publishes a port directly. Four read-only, fixed-config HAProxy services are the sole publishers and the sole members of both `fixtures` and `host-ingress`.
