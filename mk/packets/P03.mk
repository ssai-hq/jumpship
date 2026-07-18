# P03 owns the reproducible local stack and CI policy hooks.
.PHONY: dev-up dev-down dev-reset web-dev api-dev _p03_test-unit_SUITE-local-stack _p03_test-security_SUITE-local-stack

dev-up:
	@./infra/local/bin/stack up

dev-down:
	@./infra/local/bin/stack down

dev-reset:
	@./infra/local/bin/stack reset --confirm "$${CONFIRM:-}"

web-dev:
	@./infra/local/bin/dev web

api-dev:
	@./infra/local/bin/dev api

_p03_test-unit_SUITE-local-stack:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ./test/support/ci -p 'test_local_stack.py' -v
	@PYTHONDONTWRITEBYTECODE=1 python3 ./scripts/ci/workflow_policy.py check

_p03_test-security_SUITE-local-stack:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ./test/support/ci -p 'test_security_policy.py' -v
	@PYTHONDONTWRITEBYTECODE=1 python3 ./scripts/ci/workflow_policy.py check
	@PYTHONDONTWRITEBYTECODE=1 python3 ./scripts/ci/secret_scan.py
