# P00 owns the accepted direct capability checker. P01's dispatcher includes this
# fragment and delegates without changing arguments or normalized output.
.PHONY: _p00_capability-check
_p00_capability-check:
	@./scripts/capabilities/check --registry --source-manifest contracts/capabilities/mvp-source-anchors.yaml
