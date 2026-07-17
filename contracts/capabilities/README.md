# MVP Capability Contracts

The `.yaml` files in this directory use JSON-compatible YAML so P00's direct checker can parse them with the Python standard library and no repository dependency lock.

- `mvp.schema.json` closes the 69 authorized MVP capability IDs and the registry/incapability record shapes.
- `mvp.yaml` is the accepted stable registry. `planned` records establish identity, source/authority routing, future owners, applicability, test metadata, and archive-relative evidence locations; they do not claim shipped behavior.
- `mvp-source-anchors.schema.json` defines the accepted living-source manifest.
- `mvp-source-anchors.yaml` binds the exact logical source version, raw source SHA-256, P00 planning-input hashes, canonical source-plan hash, and 253 stable anchor/content hashes.

## Hash and anchor rules

`source_plan_sha256` is SHA-256 over compact canonical JSON containing `logical_source_version`, the raw living-source SHA-256, and the ordered `planning_inputs` array. `source_manifest_sha256` in the registry is SHA-256 over the exact checked-in manifest bytes.

The repository-owned `jumpship-capability-anchors-v1` parser assigns:

- one semantic slugged `numbered-list:` anchor to every top-level product-list occurrence, including distinct occurrences of reused display numbers;
- one heading-path `addendum:` anchor to every binding heading from the first addendum through the end of the living source;
- a SHA-256 to the exact canonical line or heading-scoped section content.

Public checking needs only these accepted files. The separate private-source command compares a mounted source byte/anchor set and may write a candidate only outside the repository or under `build/capability-candidates/`; it cannot overwrite accepted contract bytes.

Every planned record carries the P00 metadata test. Moving a record to `implemented` or `qualified` additionally requires capability-specific executable test metadata and the later packet/release evidence dictated by the registry.
