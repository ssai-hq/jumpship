#!/usr/bin/env python3
"""P00 closed-registry metadata and clean-clone coverage tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CAPABILITY_IDS = ['MVP-CAP-ACCESS-MANIFEST', 'MVP-CAP-AGENT-INCAPABILITY-DISCLOSURE', 'MVP-CAP-AGENT-RUNTIME', 'MVP-CAP-APPLICATION-PR-DELIVERY', 'MVP-CAP-ARCH-TRUST-DOMAINS', 'MVP-CAP-ARCHAEOLOGY', 'MVP-CAP-ATTEMPT-TIMELINE', 'MVP-CAP-AUTOMATION-SURFACE', 'MVP-CAP-AWS-CELL', 'MVP-CAP-BILLING-RATCHET', 'MVP-CAP-CDC-APPLY', 'MVP-CAP-CENSUS', 'MVP-CAP-CONNECT-CHANNELS', 'MVP-CAP-CONNECT-DETECTION', 'MVP-CAP-CONNECT-GITHUB', 'MVP-CAP-CONNECT-MONGODB', 'MVP-CAP-CONNECT-POSTGRES-TARGET', 'MVP-CAP-CONNECT-STAGED', 'MVP-CAP-CONSENT-STEPUP', 'MVP-CAP-CORRIDOR-CONTRACT', 'MVP-CAP-CREDENTIAL-CUSTODY', 'MVP-CAP-CROSS-MIGRATION-LEARNING', 'MVP-CAP-CUTOVER-CHOREOGRAPHY', 'MVP-CAP-CUTOVER-RUNBOOK', 'MVP-CAP-DECISION-PROVENANCE', 'MVP-CAP-DECOMMISSION', 'MVP-CAP-DESIGN-BRIEF', 'MVP-CAP-DOSSIER', 'MVP-CAP-DRIFT-SENTINEL', 'MVP-CAP-DUAL-WRITE', 'MVP-CAP-ENGINE-STACK', 'MVP-CAP-EXTERNAL-PR-REVIEW', 'MVP-CAP-FANOUT-COST', 'MVP-CAP-FOUNDATION-DECISIONS', 'MVP-CAP-GATED-APPROVAL', 'MVP-CAP-GOLDEN-PROOF', 'MVP-CAP-HANDOVER-WARRANTY', 'MVP-CAP-IDENTITY-LOGIN', 'MVP-CAP-IDMAP-RESUME', 'MVP-CAP-INCIDENT-BRIEF', 'MVP-CAP-INTERROGATION', 'MVP-CAP-MAPPING-TOTALITY', 'MVP-CAP-NONCHOICES', 'MVP-CAP-NORMALIZATION', 'MVP-CAP-PLACEMENT-SOLVER', 'MVP-CAP-POSTCUTOVER-WATCH', 'MVP-CAP-PRIME-DIRECTIVE', 'MVP-CAP-QUARANTINE', 'MVP-CAP-READINESS', 'MVP-CAP-RECOMMENDED-DEFAULT', 'MVP-CAP-RECONCILIATION', 'MVP-CAP-REHEARSAL', 'MVP-CAP-REVERSE-ROLLBACK', 'MVP-CAP-REVERSIBILITY', 'MVP-CAP-SEALED-ANALYSIS-RUNNER', 'MVP-CAP-SEMANTIC-TRANSLATION', 'MVP-CAP-SESSION-SHELL', 'MVP-CAP-SIGNED-INTEGRITY', 'MVP-CAP-SNAPSHOT-LADDER', 'MVP-CAP-STAGED-LOAD', 'MVP-CAP-SYNC-HEALTH', 'MVP-CAP-TARGET-PROBE', 'MVP-CAP-TOKEN-LOSS', 'MVP-CAP-TRANSFORM-PARITY', 'MVP-CAP-VERIFICATION-RUBRIC', 'MVP-CAP-VERIFY-LAYERS', 'MVP-CAP-WORKSPACE-RBAC', 'MVP-CAP-WRITER-AUTHORITY-FENCING', 'MVP-CAP-WRITER-CENSUS']
INCAPABILITY_IDS = ['MVP-INCAP-SOURCE-WRITE', 'MVP-INCAP-PER-RECORD-IMPROVISATION', 'MVP-INCAP-GATE-BYPASS', 'MVP-INCAP-CUSTOMER-VALIDATE-MERGE-DEPLOY', 'MVP-INCAP-REVIEWER-AUTHORITY', 'MVP-INCAP-SELF-INFRASTRUCTURE-LIFECYCLE', 'MVP-INCAP-CROSS-CELL-OR-SHARED-AUTHORITY', 'MVP-INCAP-ARBITRARY-SHELL-SQL-MCP', 'MVP-INCAP-RAW-EVIDENCE-EXPORT', 'MVP-INCAP-AUTOMATIC-DUAL-WRITE']


class RegistryMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = json.loads((ROOT / "contracts/capabilities/mvp.yaml").read_text(encoding="utf-8"))
        self.manifest = json.loads((ROOT / "contracts/capabilities/mvp-source-anchors.yaml").read_text(encoding="utf-8"))

    def test_closed_capability_and_incapability_ids(self) -> None:
        self.assertEqual(set(CAPABILITY_IDS), {entry["id"] for entry in self.registry["capabilities"]})
        self.assertEqual(set(INCAPABILITY_IDS), {entry["id"] for entry in self.registry["incapabilities"]})

    def test_every_source_anchor_is_covered(self) -> None:
        expected = {entry["anchor_id"] for entry in self.manifest["anchors"]}
        observed = {anchor for entry in self.registry["capabilities"] for anchor in entry["source_anchors"]}
        self.assertEqual(expected, observed)

    def test_source_occurrence_and_addendum_counts_are_frozen(self) -> None:
        numbered = [entry for entry in self.manifest["anchors"] if entry["kind"] == "numbered-list"]
        addenda = [entry for entry in self.manifest["anchors"] if entry["kind"] == "addendum"]
        self.assertEqual(213, len(numbered))
        self.assertEqual(40, len(addenda))


if __name__ == "__main__":
    unittest.main()
