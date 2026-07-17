# Harness subtree instructions

Read and follow the repository-wide [`AGENTS.md`](../../AGENTS.md). This file adds only harness-specific constraints.

- Model output, memory, traces, provider state, and tool exit codes are untrusted and never canonical authority.
- Expose only closed, typed, release-pinned tool descriptors with explicit data class, budgets, and failure behavior.
- Do not import Mothership provisioning or direct source/target drivers; use typed broker and engine ports.
- Keep credentials, ambient shell/SQL/AWS access, IMDS, Docker sockets, and undeclared network or filesystem access unavailable.
