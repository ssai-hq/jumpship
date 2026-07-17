# P01 architecture and security review

Date: 2026-07-17.

## Enforced boundaries

- Mothership cannot reach harness, engine, decision, or evidence implementations.
- Harness cannot reach Mothership/infra provisioning or direct source/target drivers, including guarded external AWS provisioning and database-driver modules.
- Engine cannot reach model providers, provisioning implementations, or direct database drivers; typed harness ports remain allowed.
- Internal quality code may import only the standard library, its own subtree, and the exact generated sanitized-trajectory contract package.
- Contract packages cannot import implementation packages.
- Web code cannot import backend domains, escape the web root through relative/bare/configured aliases, or hide dynamic imports through escaped identifiers, computed hooks, or nonliteral `require`/`import` calls.
- Generated/source paths and report writers reject symlink aliases and out-of-repository output.

The analyzer parses all Go files regardless of tests, generation markers, build tags, or nested modules; preserves guarded third-party module identities; and checks forbidden paths transitively. The current graph contains one module, 70 nodes, zero implementation edges, zero forbidden edges, and zero source symlinks.

## Security/custody impact

P01 introduces no customer data, credential, database, cloud-account, runtime signer, deployment, or production evidence custody. Networked bootstrap and provenance operations are limited to checksum/integrity-bound public tool and registry sources. Repository evidence stores hashes, counts, versions, and redacted tails only.

Dependency validation clears ambient registry/scanner controls, uses an isolated validation home, re-establishes tools from immutable archives before trusting results, denies lifecycle scripts, and binds a clean committed candidate through the final receipt/status CAS. Tool writes and evidence writers use no-follow, regular-file, directory-identity, and atomic-publication checks.

Result: no unresolved P01-owned architecture, import, symlink, output-write, secret, customer-identifier, or custody finding remains.
