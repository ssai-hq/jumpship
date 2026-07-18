# P03 fixture-credential policy

The local stack accepts only conspicuously synthetic, checked-in fixture values from `infra/local/.env.example`.

Policy:

- The Compose controller starts from an environment allowlist and always supplies the checked-in environment file. Caller values cannot introduce arbitrary customer, provider, registry, or cloud variables into Compose interpolation.
- PostgreSQL, MongoDB replica-set, and MinIO fixture values are local test material only. They must never be reused in a shared environment, cloud account, provider tenant, customer system, or production-like qualification.
- Real tokens, customer payloads, provider responses, private keys, Docker credentials, and cloud credentials are forbidden from `infra/local/**` and this evidence namespace.
- Optional provider-shaped services are deterministic WireMock fixtures with read-only mappings, read-only root filesystems, no Linux capabilities, no production fallback, and no direct internet path.
- The MongoDB fixture requires authentication and a replica-set key, but both are synthetic. The host proof uses the same checked-in fixture values without printing or persisting a credentialed URI.
- Private local customization is limited to exporting a documented numeric `JUMPSHIP_*_PORT` override in the invoking shell. No additional committed environment file is permitted.
- Local lifecycle commands invoke no cloud CLI and create no cloud resource. Cloud and release workflow guards reject static credential environment variables before producing a validated selector or reaching OIDC-capable jobs.

P03 takes no custody of a real credential, provider token, customer record, signing key, or deployment authority.
