# P03 acceptance

Required packet command:

```text
make dev-up test-unit test-contracts test-security dev-down
```

Observed result on `2026-07-18` against implementation commit `415a5ec3912afa501aaa5d7b6de37f7773ed3b00`: exit `0`.

Normalized results:

- `dev-up` rendered the fixed `jumpship-local` Compose project, started the default local fixtures, waited for service health, proved the Mongo initializer exited `0`, asserted an authenticated writable `rs0` primary, and opened an authenticated change stream through the host-ingress corridor.
- Repository unit dispatch passed, including `15/15` P03 local-stack contract tests and the existing P01/P02 unit contributions.
- Contract conformance passed, including `20/20` Python contract tests and the existing pinned Go and TypeScript checks.
- Security dispatch passed, including `18/18` P03 policy tests, workflow-policy validation for eight workflows and one local action, and a zero-finding repository secret scan with pinned Trivy `0.72.0`.
- `dev-down` removed the project containers and both project networks while preserving the six exact named volumes.

No required acceptance check was skipped. The command created no cloud resource, forwarded no cloud credential, and invoked no provider or cloud control plane.
