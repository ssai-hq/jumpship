# Infrastructure subtree instructions

Read and follow the repository-wide [`AGENTS.md`](../AGENTS.md). This file adds only infrastructure-specific constraints.

- Pin provider and module versions and commit the accepted dependency locks.
- Preserve separate IAM purposes, database roles, signer roles, state boundaries, and per-cell resources; co-location is not permission inheritance.
- Never commit state, plans containing secret values, credentials, customer/account identifiers, or copied console output.
- Destructive operations require the repository command's exact scope preview and confirmation contract. Do not bypass that contract with a direct provider command.
