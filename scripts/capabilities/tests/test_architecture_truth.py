#!/usr/bin/env python3
"""P00 architecture, security, license, and root-truth invariants."""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
ADR_FILES = [
    "0001-modular-monolith-boundaries.md",
    "0002-source-precedence-and-product-scope.md",
    "0003-go-runtime-language.md",
    "0004-postgresql-storage-baseline.md",
    "0005-public-and-cell-protocols.md",
    "0006-canonical-rds-postgresql.md",
    "0007-shared-and-cell-compute.md",
    "0008-vercel-presentation-boundary.md",
    "0009-opentofu-state-and-oidc.md",
    "0010-outbox-sqs-delivery-boundary.md",
    "0011-region-placement-solver.md",
    "0012-data-diode-and-evidence-access.md",
    "0013-cell-local-runtime-state.md",
    "0014-agent-runtime-bakeoff.md",
    "0015-auth-and-webauthn-step-up.md",
    "0016-retention-and-deletion-attestation.md",
    "0017-encryption-and-proof-key-separation.md",
    "0018-editorial-font-license-policy.md",
    "0019-public-license.md",
    "0020-sealed-analysis-runner-boundary.md",
    "0021-mvp-dual-write-deferral.md",
    "0022-regional-control-plane-recovery.md",
    "0023-bedrock-route-and-provider-data-use.md",
    "0024-durable-outer-loop-and-bounded-inner-loop.md",
    "0025-existing-run-event-checkpoint-state.md",
    "0026-customer-rehearsal-warranty-and-decommission-policy.md",
    "0027-closed-deployment-profiles.md",
    "0028-migration-thread-inline-setup-and-start.md",
    "0029-customer-application-pr-delivery-boundary.md",
    "0030-single-application-write-authority.md",
    "0031-mongodb-postgres-corridor-family.md",
    "0032-advisory-coding-agent-review-boundary.md",
    "0033-semantic-agent-artifact-release-gate.md",
    "0034-application-change-ux-state-truth.md",
]
DATA_CLASSES = {
    "public",
    "internal_operational",
    "identity_tenant",
    "shared_migration",
    "restricted_customer",
    "credential_secret",
    "security_material",
}


class ArchitectureTruthTests(unittest.TestCase):
    def test_complete_accepted_adr_register(self) -> None:
        adr_root = ROOT / "docs/adr"
        actual = sorted(path.name for path in adr_root.glob("[0-9][0-9][0-9][1-9]-*.md"))
        actual.extend(sorted(path.name for path in adr_root.glob("[0-9][0-9][1-9]0-*.md")))
        self.assertEqual(sorted(ADR_FILES), sorted(actual))
        for filename in ADR_FILES:
            body = (adr_root / filename).read_text(encoding="utf-8")
            self.assertRegex(body, r"(?m)^- Status: Accepted")

    def test_license_is_the_accepted_apache_bytes(self) -> None:
        observed = hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
        self.assertEqual("ec754bc72c6efa41f19c252c7839c22ad2f5f714daba62a015db5a62ec1da431", observed)

    def test_security_classes_and_flow_allowlist_are_complete(self) -> None:
        body = (ROOT / "docs/security/data-classification-and-flows.md").read_text(encoding="utf-8")
        observed_classes = {item for item in DATA_CLASSES if f"`{item}`" in body}
        self.assertEqual(DATA_CLASSES, observed_classes)
        observed_flows = set(re.findall(r"(?m)^\| (F[0-9]{2}) \|", body))
        self.assertEqual({f"F{number:02d}" for number in range(1, 29)}, observed_flows)

    def test_root_truth_names_two_and_only_two_consent_kinds(self) -> None:
        product = (ROOT / "PRODUCT.md").read_text(encoding="utf-8")
        self.assertIn("Only cutover and decommission are product consent kinds.", product)
        self.assertIn("Automatic no-freeze dual write is explicitly deferred", product)

    def test_stale_binding_claims_are_absent(self) -> None:
        paths = [ROOT / name for name in ("README.md", "PRODUCT.md", "AGENTS.md", "CLAUDE.md", "MEMORY.md")]
        paths.extend((ROOT / "docs").rglob("*.md"))
        stale = re.compile(r"no SaaS|one consent|SQLite in dev|latest")
        findings = []
        for path in paths:
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if stale.search(line):
                    findings.append(f"{path.relative_to(ROOT)}:{line_number}")
        self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
