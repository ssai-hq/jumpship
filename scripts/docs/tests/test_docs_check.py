#!/usr/bin/env python3
"""Tests for public documentation freshness and safety checks."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from docs_check import check, main as docs_main


class DocsCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.write("AGENTS.md", "# Instructions\n")
        self.write("CLAUDE.md", "# Compatibility\n\nRead [`AGENTS.md`](./AGENTS.md).\n")
        self.write(
            "MEMORY.md",
            "# Memory\n\n## 2026-07-17 — Current\n\n- Durable state.\n\n"
            "## 2026-07-16 — Prior\n\n- Prior state.\n",
        )
        self.write("README.md", "# Project\n\nSee [the decision](docs/adr/0001-test.md#decision).\n")
        self.write(
            "docs/adr/0001-test.md",
            "# ADR-001: Test\n\n- Status: Accepted\n\n## Decision\n\nAccepted.\n",
        )
        self.write("Makefile", "doctor:\n\t@true\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def findings(self, check_name: str) -> list[dict[str, object]]:
        return [item for item in check(self.root)["findings"] if item["check"] == check_name]

    def test_clean_document_set_passes_deterministically(self) -> None:
        first = json.dumps(check(self.root), sort_keys=True)
        second = json.dumps(check(self.root), sort_keys=True)

        self.assertEqual(first, second)
        self.assertEqual("pass", json.loads(first)["status"])

    def test_reports_missing_relative_target_and_anchor(self) -> None:
        self.write(
            "README.md",
            "# Project\n\n[missing](docs/missing.md) [anchor](docs/adr/0001-test.md#absent)\n",
        )

        findings = self.findings("relative-links")

        self.assertEqual(2, len(findings))

    def test_rejects_duplicate_accepted_adr_id(self) -> None:
        self.write(
            "docs/adr/0002-duplicate.md",
            "# ADR-001: Duplicate\n\n- Status: Accepted\n",
        )

        findings = self.findings("adr-ids")

        self.assertTrue(any("does not match filename" in item["message"] for item in findings))
        self.assertTrue(any("duplicate accepted" in item["message"] for item in findings))

    def test_enforces_pointer_memory_and_generated_markers(self) -> None:
        self.write("CLAUDE.md", "# Rules\n\n## Independent\n\nDo something else.\n")
        self.write(
            "MEMORY.md",
            "# Memory\n\n## 2026-01-01 — Old\n\n## 2026-02-01 — New\n",
        )
        self.write("docs/generated/index.json", '{"schema_version":"1"}\n')

        report = check(self.root)

        self.assertEqual("fail", report["checks"]["claude_pointer"])
        self.assertEqual("fail", report["checks"]["memory"])
        self.assertEqual("fail", report["checks"]["generated_markers"])

    @unittest.skipIf(not hasattr(os, "symlink"), "platform does not support symlinks")
    def test_rejects_symlinked_generated_file_even_when_target_is_in_repository(self) -> None:
        target = self.write("handwritten.json", '{"schema_version":"1"}\n')
        generated = self.root / "docs/generated"
        generated.mkdir(parents=True)
        (generated / "index.json").symlink_to(target)

        report = check(self.root)

        self.assertEqual("fail", report["checks"]["generated_markers"])
        self.assertTrue(
            any(item["check"] == "generated-symlinks" for item in report["findings"])
        )

    @unittest.skipIf(not hasattr(os, "symlink"), "platform does not support symlinks")
    def test_rejects_symlinked_generated_directory(self) -> None:
        alias = self.root / "aliased-generated"
        alias.mkdir()
        (self.root / "docs/generated").symlink_to(alias, target_is_directory=True)

        report = check(self.root)

        self.assertEqual("fail", report["checks"]["generated_markers"])
        self.assertTrue(
            any(item["path"] == "docs/generated" for item in report["findings"])
        )

    @unittest.skipIf(not hasattr(os, "symlink"), "platform does not support symlinks")
    def test_report_writer_refuses_symlink_and_preserves_victim(self) -> None:
        victim = self.write("report-victim.json", '{"authority":"preserve"}\n')
        output = self.root / "evidence/docs-report.json"
        output.parent.mkdir(parents=True)
        output.symlink_to(victim)
        errors = io.StringIO()

        with contextlib.redirect_stderr(errors):
            result = docs_main(
                ["--root", str(self.root), "--report-output", "evidence/docs-report.json"]
            )

        self.assertEqual(1, result)
        self.assertEqual('{"authority":"preserve"}\n', victim.read_text(encoding="utf-8"))
        self.assertTrue(output.is_symlink())
        self.assertIn("non-regular output", errors.getvalue())

    def test_report_writer_regenerates_existing_regular_file(self) -> None:
        output = self.write("evidence/docs-report.json", "stale\n")

        result = docs_main(
            ["--root", str(self.root), "--report-output", "evidence/docs-report.json"]
        )

        self.assertEqual(0, result)
        self.assertEqual("pass", json.loads(output.read_text(encoding="utf-8"))["status"])

    def test_rejects_private_paths_credentials_and_customer_literals(self) -> None:
        self.write(
            "notes.md",
            "Workspace: /Users/alice/private\n"
            "Source: postgresql://admin:not-a-secret@example.invalid/db\n"
            "customer_id = acme-production\n",
        )

        report = check(self.root)
        checks = {item["check"] for item in report["findings"]}

        self.assertTrue({"private-paths", "secrets", "customer-identifiers"} <= checks)

    def test_documented_make_target_must_exist(self) -> None:
        self.write("AGENTS.md", "# Instructions\n\nRun `make doctor absent MODE=test`.\n")

        findings = self.findings("public-commands")

        self.assertEqual(1, len(findings))
        self.assertIn("absent", findings[0]["message"])

    def test_repository_local_toolchain_documents_are_excluded(self) -> None:
        self.write(
            ".tools/toolchains/node/24.18.0/README.md",
            "private checkout /Users/upstream/build and make absent\n",
        )

        report = check(self.root)

        self.assertEqual("pass", report["status"])
        self.assertEqual([], report["findings"])


if __name__ == "__main__":
    unittest.main()
