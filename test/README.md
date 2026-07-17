# Cross-package tests

Golden, fixture, integration, corridor, chaos, and end-to-end suites live here when they span package ownership. Fixtures are synthetic, deterministic where possible, provenance-recorded, and must not weaken the same trust boundaries enforced in production code.

Tests may use explicit fakes only inside test support. A skipped check or mock never counts as release evidence without the packet's declared exception and expiry.
