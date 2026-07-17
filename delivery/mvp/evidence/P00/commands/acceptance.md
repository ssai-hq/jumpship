# P00 direct acceptance command

Required command:

```text
./scripts/capabilities/check --registry --source-manifest contracts/capabilities/mvp-source-anchors.yaml
```

Observed result:

```text
capability registry check: PASS capabilities=69 anchors=253 uncovered=0 orphaned=0 untestable=0 bare-duplicates=0
coverage-json=<target-repo>/build/capability-coverage.json
coverage-markdown=<target-repo>/build/capability-coverage.md
exit: 0
```

The generated reports are committed in this evidence namespace as `generated/capability-coverage.json` and `generated/capability-coverage.md`; `build/` is not committed.
