from __future__ import annotations

import copy
import json
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PACKET_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PACKET_DIR))

from packet_contract import (  # noqa: E402
    COMMAND_PATH,
    GRAPH_PATH,
    MANIFEST_PATH,
    ContractError,
    build_catalog,
    build_runtime_inventory,
    canonical_json,
    expand_dependencies,
    load_json_yaml,
    committed_receipt_markers_untrusted,
    scan_make_definitions,
    validate_public_references,
    validate_commands,
    validate_graph,
    verify_catalog,
    write_exclusive_output,
)


class PacketGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.graph, _ = load_json_yaml(REPO_ROOT / GRAPH_PATH)
        cls.commands, _ = load_json_yaml(REPO_ROOT / COMMAND_PATH)

    def test_production_graph_is_complete_and_acyclic(self) -> None:
        nodes, order = validate_graph(copy.deepcopy(self.graph))
        self.assertEqual(31, len(nodes))
        self.assertEqual({"J13", "J19"}, {node.id for node in nodes if node.kind == "join"})
        self.assertLess(order.index("P20"), order.index("J19"))
        self.assertLess(order.index("P26"), order.index("J13"))

    def test_range_expansion_is_inclusive(self) -> None:
        known = {f"P{number:02d}" for number in range(29)} | {"J13", "J19"}
        self.assertEqual(
            ["P13", "P14", "P15", "P16", "P17", "P18"],
            expand_dependencies(["P13..P18"], "test", known),
        )

    def test_reversed_range_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "reversed range"):
            expand_dependencies(["P18..P13"], "test", {f"P{number:02d}" for number in range(29)})

    def test_join_range_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "join IDs cannot appear in ranges"):
            expand_dependencies(["J13..J19"], "test", {"J13", "J19"})

    def test_unknown_dependency_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "invalid dependency expression"):
            expand_dependencies(["P29"], "test", {"P00"})

    def test_duplicate_node_is_rejected(self) -> None:
        graph = copy.deepcopy(self.graph)
        graph["nodes"].append(copy.deepcopy(graph["nodes"][0]))
        with self.assertRaisesRegex(ContractError, "duplicate graph nodes"):
            validate_graph(graph)

    def test_cycle_is_rejected(self) -> None:
        graph = copy.deepcopy(self.graph)
        graph["nodes"][0]["start_requires"] = ["P28"]
        with self.assertRaisesRegex(ContractError, "contains a cycle"):
            validate_graph(graph)

    def test_join_owner_is_fixed(self) -> None:
        graph = copy.deepcopy(self.graph)
        join = next(node for node in graph["nodes"] if node["id"] == "J19")
        join["owner"] = "P20"
        with self.assertRaisesRegex(ContractError, "must be P19"):
            validate_graph(graph)

    def test_duplicate_public_target_is_rejected(self) -> None:
        commands = copy.deepcopy(self.commands)
        commands["target_groups"][1]["targets"]["help"] = "Duplicate help."
        nodes, _ = validate_graph(copy.deepcopy(self.graph))
        with self.assertRaisesRegex(ContractError, "duplicate public targets"):
            validate_commands(commands, nodes)

    def test_duplicate_selector_registration_is_rejected(self) -> None:
        commands = copy.deepcopy(self.commands)
        commands["selectors"].append(copy.deepcopy(commands["selectors"][0]))
        nodes, _ = validate_graph(copy.deepcopy(self.graph))
        with self.assertRaisesRegex(ContractError, "duplicate selector registration"):
            validate_commands(commands, nodes)

    def test_duplicate_hook_ownership_is_rejected(self) -> None:
        commands = copy.deepcopy(self.commands)
        duplicate = copy.deepcopy(commands["hooks"][0])
        duplicate["target"] = "_p01_test-unit_SUITE-repository-copy"
        commands["hooks"].append(duplicate)
        nodes, _ = validate_graph(copy.deepcopy(self.graph))
        with self.assertRaisesRegex(ContractError, "duplicate hook ownership"):
            validate_commands(commands, nodes)

    def test_unsafe_selector_is_rejected(self) -> None:
        commands = copy.deepcopy(self.commands)
        commands["selectors"][0]["value"] = "repository;touch-pwned"
        nodes, _ = validate_graph(copy.deepcopy(self.graph))
        with self.assertRaisesRegex(ContractError, "unsafe"):
            validate_commands(commands, nodes)

    def test_hidden_hook_name_is_canonical(self) -> None:
        commands = copy.deepcopy(self.commands)
        commands["hooks"][0]["target"] = "_p01_test-unit_SUITE-wrong"
        nodes, _ = validate_graph(copy.deepcopy(self.graph))
        with self.assertRaisesRegex(ContractError, "must be _p01_test-unit_SUITE-repository"):
            validate_commands(commands, nodes)


class RepositoryIntegrationTests(unittest.TestCase):
    def make_repository(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / GRAPH_PATH).parent.mkdir(parents=True)
        (root / COMMAND_PATH).parent.mkdir(parents=True, exist_ok=True)
        (root / GRAPH_PATH).write_bytes((REPO_ROOT / GRAPH_PATH).read_bytes())
        (root / COMMAND_PATH).write_bytes((REPO_ROOT / COMMAND_PATH).read_bytes())
        for relative in (
            Path("contracts/capabilities/mvp.yaml"),
            Path("contracts/capabilities/mvp.schema.json"),
        ):
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_bytes((REPO_ROOT / relative).read_bytes())
        (root / "mk/packets").mkdir(parents=True)
        return temporary, root

    def write_safe_root_makefile(self, root: Path, extra: str = "") -> None:
        (root / "Makefile").write_text(
            "SHELL := /bin/sh\n"
            "ifneq ($(shell python3 ./scripts/packets/check make-safety),JUMPSHIP_PACKET_MAKE_SAFETY_OK)\n"
            "$(error packet Make safety check failed)\n"
            "endif\n"
            "include $(sort $(wildcard mk/packets/P??.mk))\n"
            f"{extra}",
            encoding="utf-8",
        )

    def install_packet_checker(self, root: Path) -> None:
        destination = root / "scripts/packets"
        destination.mkdir(parents=True)
        for name in ("check", "packet_contract.py"):
            shutil.copy2(PACKET_DIR / name, destination / name)
        (destination / "check").chmod(0o755)

    def git(self, root: Path, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments], cwd=root, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True,
        )
        return completed.stdout.strip()

    def initialize_repository(self, root: Path) -> str:
        self.git(root, "init", "-q")
        self.git(root, "config", "user.name", "Packet Contract Test")
        self.git(root, "config", "user.email", "packet-contract@example.invalid")
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "initial fixture")
        return self.git(root, "rev-parse", "HEAD")

    def write_rule(self, root: Path, packet_id: str, target: str, recipe: str = "@echo covered") -> None:
        path = root / f"mk/packets/{packet_id}.mk"
        prior = path.read_text(encoding="utf-8") if path.exists() else ""
        path.write_text(
            prior + f".PHONY: {target}\n{target}:\n\t{recipe}\n", encoding="utf-8"
        )

    def commit_marker(self, root: Path, node_id: str, mutate=None) -> dict:
        ending_commit = self.git(root, "rev-parse", "HEAD")
        document = {
            "schema_version": "1.0.0", "packet_id": node_id,
            "outcome": "complete", "ending_commit": ending_commit,
        }
        if mutate:
            mutate(document)
        receipt_path = f"delivery/mvp/handoffs/{node_id}/{ending_commit}.json"
        path = root / receipt_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", f"{node_id} marker")
        return document

    def nodes(self, root: Path):
        return validate_graph(json.loads((root / GRAPH_PATH).read_text(encoding="utf-8")))[0]

    def test_static_catalog_ignores_fragments_and_receipts_while_runtime_updates(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.write_rule(root, "P01", "_p01_test-unit_SUITE-repository")
        self.initialize_repository(root)
        catalog = build_catalog(root)
        catalog_bytes = canonical_json(catalog)
        (root / MANIFEST_PATH).parent.mkdir(parents=True)
        (root / MANIFEST_PATH).write_bytes(catalog_bytes)
        before = build_runtime_inventory(root)
        self.assertEqual(canonical_json(before), canonical_json(build_runtime_inventory(root)))
        hook_before = next(
            item for item in before["commands"]["internal_targets"]
            if item["target"] == "_p01_test-unit_SUITE-repository"
        )
        self.assertEqual("present", hook_before["lifecycle"])

        self.commit_marker(root, "P00")
        self.assertEqual(catalog_bytes, canonical_json(build_catalog(root)))
        verify_catalog(root, build_catalog(root))
        after_receipt = build_runtime_inventory(root)
        hook_after = next(
            item for item in after_receipt["commands"]["internal_targets"]
            if item["target"] == "_p01_test-unit_SUITE-repository"
        )
        self.assertEqual("active", hook_after["lifecycle"])

        self.write_rule(root, "P03", "dev-up")
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "later packet fragment")
        self.assertEqual(catalog_bytes, canonical_json(build_catalog(root)))
        verify_catalog(root, build_catalog(root))
        after_fragment = build_runtime_inventory(root)
        dev_up = next(item for item in after_fragment["commands"]["targets"] if item["name"] == "dev-up")
        self.assertEqual("present", dev_up["lifecycle"])

    def test_committed_receipt_marker_is_explicitly_untrusted(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.initialize_repository(root)
        self.commit_marker(root, "P00")
        self.assertIn("P00", committed_receipt_markers_untrusted(root, self.nodes(root)))
        inventory = build_runtime_inventory(root)
        self.assertIn("P00", inventory["committed_complete_receipt_markers_untrusted_not_acceptance"])
        self.assertIn("do not establish packet acceptance", inventory["runtime_semantics"])

    def test_malformed_or_uncommitted_receipt_marker_is_ignored(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        ending = self.initialize_repository(root)
        path = root / f"delivery/mvp/handoffs/P00/{ending}.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"schema_version": "1.0.0", "packet_id": "P00", "outcome": "complete", "ending_commit": ending}))
        self.assertNotIn("P00", committed_receipt_markers_untrusted(root, self.nodes(root)))
        path.write_text(json.dumps({"schema_version": "9.9.9", "packet_id": "P00", "outcome": "complete", "ending_commit": ending}))
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "malformed marker")
        self.assertNotIn("P00", committed_receipt_markers_untrusted(root, self.nodes(root)))

    def test_require_complete_is_local_hook_coverage_only(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        inventory = build_runtime_inventory(root)
        namespace = runpy.run_path(str(PACKET_DIR / "check"))
        with mock.patch.dict(os.environ, {"REQUIRE_COMPLETE": "1"}, clear=False):
            with self.assertRaisesRegex(ContractError, "does not establish packet acceptance or readiness"):
                namespace["dispatch"](root, inventory, "test-unit")

    def test_phony_and_rule_must_both_exist_with_substantive_recipe(self) -> None:
        cases = {
            "orphan-phony": ".PHONY: help\n",
            "non-phony-rule": "help:\n\t@echo help\n",
            "empty-rule": ".PHONY: help\nhelp:\n",
            "true-noop": ".PHONY: help\nhelp:\n\t@true\n",
            "colon-noop": ".PHONY: help\nhelp:\n\t@:\n",
        }
        for name, contents in cases.items():
            with self.subTest(name=name):
                temporary, root = self.make_repository()
                try:
                    (root / "mk/packets/P01.mk").write_text(contents, encoding="utf-8")
                    with self.assertRaises(ContractError):
                        scan_make_definitions(root)
                finally:
                    temporary.cleanup()

    def test_undocumented_make_target_is_rejected(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.write_rule(root, "P01", "surprise-target")
        with self.assertRaisesRegex(ContractError, "undocumented Make targets"):
            build_runtime_inventory(root)

    def test_wrong_fragment_owner_is_rejected(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.write_rule(root, "P01", "web-build")
        with self.assertRaisesRegex(ContractError, "owned by P22 but defined by P01"):
            build_runtime_inventory(root)

    def test_duplicate_make_target_is_rejected(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.write_safe_root_makefile(root, ".PHONY: help\nhelp:\n\t@echo root\n")
        self.write_rule(root, "P01", "help")
        with self.assertRaises(ContractError):
            scan_make_definitions(root)

    def test_unapproved_fragment_name_is_rejected(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        (root / "mk/packets/J13.mk").write_text("# joins have no fragments\n", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "unapproved packet Make fragment"):
            scan_make_definitions(root)

    def test_pkg_passthrough_is_rejected(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.write_safe_root_makefile(root, "PKG ?= ./...\n")
        with self.assertRaisesRegex(ContractError, "PKG passthrough is forbidden"):
            scan_make_definitions(root)

    def test_make_parse_time_and_ownership_bypasses_are_rejected(self) -> None:
        cases = {
            "shell": "X := $(shell touch bad)\n", "eval": "$(eval help:; @echo bad)\n",
            "shell-assignment": "X != touch bad\n", "nested-include": "include attacker.mk\n",
            "silent-include": "sinclude attacker.mk\n", "global-shell": "SHELL := /tmp/attacker\n",
            "ignore-errors": ".IGNORE:\n",
            "default": ".DEFAULT:\n\t@echo bad\n", "pattern": "%: %.in\n\t@echo bad\n",
            "selector-interpolation": ".PHONY: help\nhelp:\n\t@echo $(SUITE)\n",
            "command-substitution": ".PHONY: help\nhelp:\n\t@echo $$(id)\n",
        }
        for name, contents in cases.items():
            with self.subTest(name=name):
                temporary, root = self.make_repository()
                try:
                    (root / "mk/packets/P02.mk").write_text(contents, encoding="utf-8")
                    with self.assertRaises(ContractError):
                        scan_make_definitions(root)
                finally:
                    temporary.cleanup()

    def test_make_safety_preflight_blocks_override_and_fragment_side_effect(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.install_packet_checker(root)
        self.write_safe_root_makefile(root)
        self.write_rule(root, "P01", "help")
        safe = subprocess.run(
            ["make", "PACKET_MAKE_SAFETY=JUMPSHIP_PACKET_MAKE_SAFETY_OK", "help"],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(0, safe.returncode, safe.stderr)

        side_effect = root / "side-effect"
        (root / "mk/packets/P02.mk").write_text(
            f"EVIL := $(shell touch {side_effect})\n", encoding="utf-8"
        )
        blocked = subprocess.run(
            ["make", "PACKET_MAKE_SAFETY=JUMPSHIP_PACKET_MAKE_SAFETY_OK", "help"],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertNotEqual(0, blocked.returncode)
        self.assertFalse(side_effect.exists())

    def test_make_safety_preflight_blocks_parse_safe_cross_packet_override(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.install_packet_checker(root)
        self.write_safe_root_makefile(root)
        self.write_rule(root, "P01", "help", "@echo P01_HELP")
        self.write_rule(root, "P02", "help", "@echo P02_OVERRIDE_EXECUTED")

        blocked = subprocess.run(
            ["make", "help"], cwd=root, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

        self.assertNotEqual(0, blocked.returncode)
        self.assertNotIn("P02_OVERRIDE_EXECUTED", blocked.stdout)
        self.assertIn("packet Make safety check failed", blocked.stderr)

    def test_make_safety_rejects_p99_before_include_and_emits_exact_token_for_allowed_set(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.install_packet_checker(root)
        self.write_safe_root_makefile(root)
        self.write_rule(root, "P01", "help")
        safety = subprocess.run(
            [sys.executable, str(root / "scripts/packets/check"), "make-safety", "--repo-root", str(root)],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(0, safety.returncode, safety.stderr)
        self.assertEqual("JUMPSHIP_PACKET_MAKE_SAFETY_OK\n", safety.stdout)

        side_effect = root / "p99-side-effect"
        (root / "mk/packets/P99.mk").write_text(
            f"EVIL := $(shell touch {side_effect})\n", encoding="utf-8"
        )
        blocked = subprocess.run(
            ["make", "help"], cwd=root, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertNotEqual(0, blocked.returncode)
        self.assertFalse(side_effect.exists())

    def test_root_include_is_exactly_allowlisted(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.write_safe_root_makefile(root)
        self.write_rule(root, "P01", "help")
        self.assertIn("help", scan_make_definitions(root))
        (root / "Makefile").write_text(
            (root / "Makefile").read_text(encoding="utf-8").replace(
                "include $(sort $(wildcard mk/packets/P??.mk))", "include mk/packets/*.mk"
            ),
            encoding="utf-8",
        )
        with self.assertRaises(ContractError):
            scan_make_definitions(root)

    def test_public_metadata_references_resolve(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        graph = json.loads((root / GRAPH_PATH).read_text(encoding="utf-8"))
        commands = json.loads((root / COMMAND_PATH).read_text(encoding="utf-8"))
        commands["target_groups"][0]["targets"]["help"] += (
            " JSMVP-R082 MVP-CAP-ACCESS-MANIFEST contracts/capabilities/mvp.yaml "
            "https://jumpship.dev/schemas/capabilities/mvp.schema.json"
        )
        validate_public_references(root, graph, commands)

    def test_public_metadata_references_reject_unknown_values(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        graph = json.loads((root / GRAPH_PATH).read_text(encoding="utf-8"))
        base = json.loads((root / COMMAND_PATH).read_text(encoding="utf-8"))
        invalid = (
            "JSMVP-R083",
            "MVP-CAP-DOES-NOT-EXIST",
            "contracts/capabilities/missing.schema.json",
            "https://jumpship.dev/schemas/missing.schema.json",
        )
        for reference in invalid:
            with self.subTest(reference=reference):
                commands = copy.deepcopy(base)
                commands["target_groups"][0]["targets"]["help"] += f" {reference}"
                with self.assertRaises(ContractError):
                    validate_public_references(root, graph, commands)

    def test_generated_catalog_drift_is_rejected(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        catalog = build_catalog(root)
        (root / MANIFEST_PATH).parent.mkdir(parents=True)
        (root / MANIFEST_PATH).write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "generated catalog drift"):
            verify_catalog(root, catalog)

    def test_generate_refuses_symlink_output_and_preserves_victim(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.install_packet_checker(root)
        victim = root / "victim.json"
        original = b'{"authority":"must-survive"}\n'
        victim.write_bytes(original)
        output = root / MANIFEST_PATH
        output.parent.mkdir(parents=True)
        output.symlink_to(Path("../../victim.json"))

        blocked = subprocess.run(
            [sys.executable, str(root / "scripts/packets/check"), "generate", "--repo-root", str(root)],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

        self.assertNotEqual(0, blocked.returncode)
        self.assertEqual(original, victim.read_bytes())
        self.assertTrue(output.is_symlink())
        self.assertIn("refusing to replace non-regular output", blocked.stderr)

    def test_generate_refuses_symlinked_parent(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        self.install_packet_checker(root)
        real_docs = root / "real-docs"
        real_docs.mkdir()
        (root / "docs").symlink_to(real_docs, target_is_directory=True)

        blocked = subprocess.run(
            [sys.executable, str(root / "scripts/packets/check"), "generate", "--repo-root", str(root)],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

        self.assertNotEqual(0, blocked.returncode)
        self.assertFalse((real_docs / "generated/packet-execution-manifest.json").exists())
        self.assertIn("not a real directory", blocked.stderr)

    def test_runtime_inventory_output_is_exclusive_and_repo_contained(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        payload = canonical_json({"runtime": "inventory"})
        output = write_exclusive_output(root, Path("delivery/mvp/evidence/P01/runtime.json"), payload)
        self.assertEqual(payload, output.read_bytes())
        with self.assertRaisesRegex(ContractError, "refusing to overwrite"):
            write_exclusive_output(root, Path("delivery/mvp/evidence/P01/runtime.json"), payload)
        with self.assertRaisesRegex(ContractError, "inside repository root"):
            write_exclusive_output(root, Path(temporary.name).parent / "outside.json", payload)

    def test_runtime_inventory_output_refuses_symlinked_parent(self) -> None:
        temporary, root = self.make_repository()
        self.addCleanup(temporary.cleanup)
        outside = Path(temporary.name).parent / f"{Path(temporary.name).name}-outside"
        outside.mkdir()
        self.addCleanup(outside.rmdir)
        (root / "linked").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ContractError, "not a real directory"):
            write_exclusive_output(root, Path("linked/runtime.json"), b"{}\n")

    def test_runtime_checker_has_no_private_plan_dependency(self) -> None:
        for path in (PACKET_DIR / "packet_contract.py", PACKET_DIR / "check"):
            self.assertNotIn("mdhq", path.read_text(encoding="utf-8").lower())


if __name__ == "__main__":
    unittest.main()
