# Contributing to Jumpship

Jumpship is a public, security-sensitive migration system. Small changes are
welcome, but a passing happy path is not enough: preserve the repository's
process, data-custody, and authority boundaries and include the negative tests
that prove a change fails closed.

## Start here

Repository scripts require POSIX `sh`, Git, Make, and Python 3.10 or newer on
the host. No host Go, Node.js, pnpm, OpenTofu, linter, or scanner installation
is required; bootstrap provisions their exact reviewed versions locally.

1. Read [`AGENTS.md`](./AGENTS.md) and the nearest nested `AGENTS.md` for the
   subtree you will change.
2. Run `make doctor bootstrap` from a clean clone. Bootstrap installs only
   checksum-verified tools below `build/tools/`; it never modifies a system or user
   toolchain.
3. Select one accepted implementation packet and stay within its machine
   write scope.
4. Run the packet's exact acceptance command and `make verify` where its
   dependencies are ready.

Never commit credentials, customer data or code, connection strings, prompts,
raw evidence, or identifying traces. Fixtures must be synthetic.

## Generated files

Do not hand-edit generated files. Change their accepted source, run the
repository generator, and commit source and generated output together. A
change is incomplete when `make gen-check` reports drift.

## Dependency changes

P01 is the sole steward of `go.mod`, `go.sum`, the root `package.json`,
`pnpm-lock.yaml`, and `tools/manifest.yaml`. A later packet requests a change
in `dependency/requests/Pxx.yaml`, conforming to
[`dependency/requests/schema.yaml`](./dependency/requests/schema.yaml). The
request must pin an exact version, SPDX license, purpose, source provenance,
checksum or registry integrity, affected builds, and security impact.

The root-lock steward validates and applies one accepted request at a time:

```sh
scripts/dependency-locks/validate-request dependency/requests/Pxx.yaml
# Commit only the accepted request and its declared root-lock update, then use
# the exact commit immediately before that candidate as <base-commit>.
scripts/dependency-locks/apply-request \
  --request dependency/requests/Pxx.yaml \
  --base-commit <40-hex-base-commit> \
  --expected-request-sha256 <sha256> \
  --confirm <request-id>
```

The apply step requires a clean `main` worktree at the committed, non-merge
candidate and proves the supplied base is its one immediate parent. It rejects
any candidate path outside the one accepted request plus its declared root
locks. It directly runs the pinned toolchain and deferred-provenance checks,
installs the exact frozen candidate pnpm lock without lifecycle scripts in a
credential-isolated official-registry environment, inventories requested
Go/pnpm/tool licenses, runs pnpm audit, runs Trivy against the explicit official
database source while recording database metadata, and performs exact
clean-clone acceptance; caller-authored pass reports are not trusted. On
success it writes exactly
`delivery/mvp/evidence/Pxx/dependency-locks/<request-id>.json`, binding both the
accepted and applied request hashes, and atomically changes the request status
to `applied`. The canonical receipt makes replay fail closed. An interrupted
receipt-before-status transition blocks automatic re-entry and requires the
root-lock steward to inspect and explicitly resolve the journal; caller bytes
can never cause an automatic status transition.
The script validates the supplied approval record but never creates or implies
an approval. It does not grant the requester ownership of root locks.

Deferred binary declarations are provenance records, not an install-ready
promise. `tools/manifest.yaml` marks a declaration activation-blocked while its
checksum-bound artifacts do not cover all four supported platforms. Dependency
apply rejects requests that try to activate a declaration while that gate
remains. Once a steward-reviewed manifest supplies the complete platform set,
the same serialized request may activate an explicitly supported optional
repository-local tool. This is a supply-chain gate, not an implied approval.

## Review expectations

- Explain affected trust and data boundaries.
- Add deterministic tests for success, denial, replay, and recovery paths as
  applicable.
- Keep generated and machine-readable contracts in sync.
- Report commands, exact results, skipped checks, and unresolved external
  gates honestly.
- Never weaken a check to make a change pass.

Production publication and deployment require the separate release and
environment approvals defined by the implementation plan. A local green test
does not imply either approval.
