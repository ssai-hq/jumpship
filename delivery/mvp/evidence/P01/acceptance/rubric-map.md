# P01 acceptance and rubric map

| Rubric | P01 result | Evidence | Downstream remainder |
|---|---|---|---|
| `JSMVP-R004` | `passed_local` | Static direct/transitive Go and web import graph; external provider/driver edges; forbidden-edge and symlink reports; 29 positive/negative analyzer tests | P27/P28 qualify the integrated staging/production compositions |
| `JSMVP-R012` | `passed_local` | Exact runtime/tool manifest, Go/pnpm locks, generated catalog drift check, provenance, cross-platform license coverage, pnpm audit, Trivy scan, and serialized dependency-update receipt workflow | Listed later producers pin actions, modules, images, AMIs, generated clients, and release artifacts; P27/P28 qualify them |
| `JSMVP-R013` | `passed_local` | Doctor/bootstrap/format/lint/unit checks, repository-local tool isolation, hidden-state denials, and isolated clean-clone rehearsal contract | P03 owns the local-stack/build contribution and the row's sole-write closure; P27/P28 qualify the release |

Every status is limited to P01's machine-declared contribution. No row is represented as staging- or production-qualified.
