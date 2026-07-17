# Composition roots

Each child directory is one deployable or installed command boundary. Command packages may parse configuration, compose dependencies, expose health, and coordinate graceful startup or shutdown; product rules remain under `internal/`. A shared repository does not merge process, IAM, network, database-role, or signing authority.

P01 creates documentation-only package roots. The packet named in the public packet graph owns each later executable implementation and colocated container build.
