# P01 owns the stable repository dispatcher and its repository-only test hook.
.PHONY: help doctor bootstrap docs-check capability-check command-check packet-graph-check architecture-check gen gen-check fmt lint verify test-unit test-integration test-security test-chaos test-kill test-e2e db-migration-compat api-callback-log-canary cell-crl-publication-test activation-receipt-crash-test _p01_test-unit_SUITE-repository

help:
	@python3 ./scripts/packets/check help

doctor:
	@./scripts/dev/doctor

bootstrap:
	@./scripts/dev/bootstrap

docs-check:
	@./scripts/docs/check

capability-check:
	@$(MAKE) --no-print-directory _p00_capability-check

command-check:
	@python3 ./scripts/packets/check commands

packet-graph-check:
	@python3 ./scripts/packets/check graph

architecture-check:
	@./scripts/architecture/check

gen:
	@python3 ./scripts/packets/check generate

gen-check:
	@python3 ./scripts/packets/check generated

fmt:
	@./scripts/dev/fmt

lint:
	@./scripts/dev/lint

verify:
	@$(MAKE) --no-print-directory doctor docs-check capability-check command-check packet-graph-check gen-check fmt lint architecture-check test-unit test-integration test-security test-chaos test-kill test-e2e db-migration-compat api-callback-log-canary cell-crl-publication-test activation-receipt-crash-test

test-unit:
	@python3 ./scripts/packets/check dispatch test-unit

test-integration:
	@python3 ./scripts/packets/check dispatch test-integration

test-security:
	@python3 ./scripts/packets/check dispatch test-security

test-chaos:
	@python3 ./scripts/packets/check dispatch test-chaos

test-kill:
	@python3 ./scripts/packets/check dispatch test-kill

test-e2e:
	@python3 ./scripts/packets/check dispatch test-e2e

db-migration-compat:
	@python3 ./scripts/packets/check dispatch db-migration-compat

api-callback-log-canary:
	@python3 ./scripts/packets/check dispatch api-callback-log-canary

cell-crl-publication-test:
	@python3 ./scripts/packets/check dispatch cell-crl-publication-test

activation-receipt-crash-test:
	@python3 ./scripts/packets/check dispatch activation-receipt-crash-test

_p01_test-unit_SUITE-repository:
	@./scripts/dev/test-unit
