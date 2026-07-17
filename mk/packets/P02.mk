# P02 owns the public contract conformance commands.
.PHONY: test-contracts api-gen-check api-contract-test

test-contracts:
	@PYTHONDONTWRITEBYTECODE=1 python3 ./internal/contracts/codegen/generate.py --check
	@PYTHONDONTWRITEBYTECODE=1 python3 ./internal/contracts/tests/run_contract_tests.py
	@GOMODCACHE=/tmp/jumpship-p02-go-mod GOCACHE=/tmp/jumpship-p02-go-build GOFLAGS=-mod=readonly ./build/tools/bin/go test ./internal/contracts/...
	@./build/tools/bin/node --experimental-strip-types --test ./web/src/lib/api/generated/canonical.test.ts

api-gen-check:
	@PYTHONDONTWRITEBYTECODE=1 python3 ./internal/contracts/codegen/generate.py --check

api-contract-test:
	@PYTHONDONTWRITEBYTECODE=1 python3 ./internal/contracts/tests/run_contract_tests.py
