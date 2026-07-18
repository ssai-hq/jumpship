#!/usr/bin/env python3
"""Unit tests for P01's bootstrap and root-lock policy."""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


toolchain = _load("jumpship_toolchain", ROOT / "scripts" / "dev" / "toolchain.py")
dependency_locks = _load(
    "jumpship_dependency_locks", ROOT / "scripts" / "dependency-locks" / "dependency_locks.py"
)
quality = _load("jumpship_quality", ROOT / "scripts" / "dev" / "quality.py")
clean_clone = _load("jumpship_clean_clone", ROOT / "scripts" / "dev" / "clean_clone.py")
tool_lock = sys.modules[toolchain.tool_operation_lock.__module__]


def _valid_request(status: str = "proposed") -> dict:
    request = {
        "schema_version": 1,
        "request_id": "P02-dep-example",
        "packet_id": "P02",
        "status": status,
        "created_at": "2026-07-17T00:00:00Z",
        "requested_by": "packet-owner",
        "dependencies": [
            {
                "ecosystem": "go",
                "name": "example.invalid/module",
                "version": "1.0.0",
                "license": "MIT",
                "purpose": "exercise dependency validation",
                "source_url": "https://example.invalid/module/v1.0.0",
                "integrity": {
                    "algorithm": "go-sum",
                    "value": "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "source_url": "https://sum.golang.org/lookup/example.invalid/module@v1.0.0",
                },
                "direct_runtime_dependency": False,
            }
        ],
        "affected_lockfiles": ["go.mod"],
        "affected_builds": ["contracts"],
        "risk": {
            "security_sensitive": False,
            "data_boundary_impact": "none",
            "justification": "reviewed test request",
        },
        "validation_requirements": ["license", "vulnerability", "clean-clone"],
    }
    if status in {"accepted", "applied"}:
        request["approval"] = {
            "decision_id": "decision-test",
            "approved_by": "root-lock-steward",
            "approver_role": "p01-root-lock-steward",
            "approved_at": "2026-07-17T00:01:00Z",
        }
    if status == "rejected":
        request["rejection_reason"] = "not accepted for this candidate"
    return request


class ToolchainPolicyTests(unittest.TestCase):
    def test_manifest_and_workspace_are_closed_and_consistent(self) -> None:
        manifest = json.loads((ROOT / "tools" / "manifest.yaml").read_text(encoding="utf-8"))
        self.assertEqual([], dependency_locks._manifest_errors(manifest))
        started = time.monotonic()
        self.assertEqual([], dependency_locks._workspace_errors(manifest))
        self.assertLess(time.monotonic() - started, 5.0, "workspace scan traversed ignored tool trees")

    def test_manifest_rejects_unsafe_archive_root(self) -> None:
        manifest = json.loads((ROOT / "tools" / "manifest.yaml").read_text(encoding="utf-8"))
        manifest["runtimes"][0]["artifacts"]["darwin-arm64"]["root"] = "../escape"
        errors = dependency_locks._manifest_errors(manifest)
        self.assertTrue(any("archive root must be safe" in error for error in errors))

    def test_manifest_rejects_deferred_version_without_provenance_binding(self) -> None:
        manifest = json.loads((ROOT / "tools" / "manifest.yaml").read_text(encoding="utf-8"))
        deferred = next(record for record in manifest["tools"] if record["name"] == "sqlc")
        deferred["version"] = "1.31.2"
        errors = dependency_locks._manifest_errors(manifest)
        self.assertTrue(any("source does not bind" in error for error in errors))
        self.assertTrue(any("provenance URL does not bind" in error for error in errors))

    def test_platform_incomplete_deferred_binaries_cannot_be_activated(self) -> None:
        manifest = json.loads((ROOT / "tools" / "manifest.yaml").read_text(encoding="utf-8"))
        for name in ("sqlc", "duckdb"):
            record = next(item for item in manifest["tools"] if item["name"] == name)
            self.assertEqual("blocked", record["activation"]["status"])
            self.assertEqual(["darwin-arm64"], record["activation"]["pinned_platforms"])
            dependency = {
                "integrity": {
                    "algorithm": "sha256",
                    "value": record["integrity"]["sha256"],
                    "source_url": record["integrity"]["url"],
                }
            }
            self.assertIsNone(dependency_locks._tool_integrity_binding(record, dependency))
        sqlc = next(item for item in manifest["tools"] if item["name"] == "sqlc")
        sqlc["activation"]["status"] = "ready"
        errors = dependency_locks._manifest_errors(manifest)
        self.assertTrue(any("activation must remain blocked" in error for error in errors))

    def test_complete_sqlc_artifacts_enable_optional_repository_bootstrap(self) -> None:
        manifest = json.loads((ROOT / "tools" / "manifest.yaml").read_text(encoding="utf-8"))
        sqlc = next(item for item in manifest["tools"] if item["name"] == "sqlc")
        sqlc["bootstrap"] = True
        sqlc.pop("activation")
        sqlc.pop("integrity")
        sqlc["artifacts"] = {
            platform_name: {
                "url": f"https://github.com/sqlc-dev/sqlc/releases/download/v1.31.1/sqlc-{platform_name}.zip",
                "archive": "zip",
                "root": ".",
                "sha256": str(index) * 64,
            }
            for index, platform_name in enumerate(sorted(dependency_locks.SUPPORTED_PLATFORMS), 1)
        }
        self.assertEqual([], dependency_locks._manifest_errors(manifest))
        records = toolchain._records(manifest)
        current_manifest = json.loads(
            (ROOT / "tools" / "manifest.yaml").read_text(encoding="utf-8")
        )
        self.assertNotIn(
            "sqlc", toolchain._enabled_bootstrap_names(toolchain._records(current_manifest))
        )
        self.assertIn("sqlc", toolchain._enabled_bootstrap_names(records))

    def test_toolchain_rejects_unsafe_version_path_atom(self) -> None:
        manifest = json.loads((ROOT / "tools" / "manifest.yaml").read_text(encoding="utf-8"))
        manifest["runtimes"][0]["version"] = "../../escape"
        with self.assertRaises(toolchain.ToolchainError):
            toolchain._records(manifest)

    def test_unlocked_bootstrap_repairs_every_pinned_tool_before_dependency_install(self) -> None:
        manifest = json.loads((ROOT / "tools" / "manifest.yaml").read_text(encoding="utf-8"))
        events: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            test_root = Path(temporary).resolve()
            state_path = test_root / "build" / "tools" / "state.json"
            state_path.parent.mkdir(parents=True)
            state_path.write_text('{"tampered":true}\n', encoding="utf-8")

            def install(record, _platform, *, offline, repair):
                self.assertFalse(offline)
                self.assertTrue(repair)
                events.append(f"repair:{record['name']}")
                return Path(temporary) / record["name"]

            def run(_command, label, *, command_env=None):
                self.assertEqual({"CLOSED": "1"}, command_env)
                events.append(label)

            with mock.patch.multiple(
                toolchain,
                ROOT=test_root,
                TOOLS_ROOT=test_root / "build" / "tools",
                STATE_PATH=state_path,
                _preflight_mutable_paths=mock.DEFAULT,
                _load_manifest=mock.DEFAULT,
                _install_record=mock.DEFAULT,
                _write_wrappers=mock.DEFAULT,
                verify_repo_toolchain=mock.DEFAULT,
                _run_bootstrap_command=mock.DEFAULT,
                _check_unlocked=mock.DEFAULT,
            ) as patched:
                patched["_preflight_mutable_paths"].return_value = None
                patched["_load_manifest"].return_value = manifest
                patched["_install_record"].side_effect = install
                patched["_write_wrappers"].side_effect = lambda _records: events.append("wrappers")
                patched["verify_repo_toolchain"].return_value = []
                patched["_run_bootstrap_command"].side_effect = run
                patched["_check_unlocked"].side_effect = lambda: events.append("final-check")
                toolchain._bootstrap_unlocked(
                    offline=False,
                    repair=True,
                    command_env={"CLOSED": "1"},
                )
        self.assertEqual("dependency lock check", events[0])
        repaired = [event.removeprefix("repair:") for event in events if event.startswith("repair:")]
        self.assertEqual(list(toolchain.BOOTSTRAP_NAMES), repaired)
        self.assertLess(events.index("wrappers"), events.index("frozen pnpm install"))
        self.assertLess(events.index("frozen pnpm install"), events.index("final-check"))

    def test_supply_validation_stops_before_scans_when_verified_repair_fails(self) -> None:
        with mock.patch.object(
            dependency_locks, "_preflight_dependency_mutable_paths"
        ), mock.patch.object(
            dependency_locks, "_validation_env", return_value={}
        ), mock.patch.object(
            dependency_locks.repository_toolchain,
            "_bootstrap_unlocked",
            side_effect=dependency_locks.repository_toolchain.ToolchainError("tampered archive"),
        ), mock.patch.object(dependency_locks, "_capture") as capture:
            with self.assertRaisesRegex(dependency_locks.LockError, "verified toolchain repair"):
                dependency_locks._run_dependency_validations("0" * 40, _valid_request("accepted"))
            capture.assert_not_called()

    def test_download_source_rejects_http_and_credentials(self) -> None:
        for value in (
            "http://go.dev/dl/tool.tar.gz",
            "https://user:password@go.dev/dl/tool.tar.gz",
            "https://example.invalid/tool.tar.gz",
            "https://go.dev/dl/tool.tar.gz?token=forbidden",
        ):
            with self.subTest(value=value), self.assertRaises(toolchain.ToolchainError):
                toolchain._safe_url(value)

    def test_persisted_dependency_urls_reject_queries_and_fragments(self) -> None:
        for value in (
            "https://registry.npmjs.org/example?token=forbidden",
            "https://registry.npmjs.org/example#fragment",
            "https://user@example.invalid/module",
        ):
            with self.subTest(value=value):
                self.assertFalse(dependency_locks._is_https(value))

    def test_closed_validation_environment_drops_inherited_scanner_and_registry_controls(self) -> None:
        hostile = {
            "TRIVY_IGNOREFILE": "/tmp/attacker-ignore",
            "trivy_skip_db_update": "true",
            "NPM_TOKEN": "not-a-real-token",
            "npm_config_registry": "https://attacker.invalid/",
            "PnPm_CoNfIg_UserConfig": "/tmp/attacker-npmrc",
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            env = dependency_locks._validation_env()
        self.assertFalse(any(name.lower().startswith("trivy_") for name in env))
        self.assertNotIn("NPM_TOKEN", env)
        self.assertNotIn("npm_config_registry", env)
        self.assertNotIn("PnPm_CoNfIg_UserConfig", env)
        self.assertEqual(dependency_locks.OFFICIAL_NPM_REGISTRY, env["NPM_CONFIG_REGISTRY"])
        self.assertEqual(os.devnull, env["NPM_CONFIG_USERCONFIG"])

    def test_requested_pnpm_dependency_must_bind_candidate_lock_integrity_and_directness(self) -> None:
        version = "16.2.10"
        integrity = dependency_locks._pnpm_lock_integrity("next", version)
        self.assertIsNotNone(integrity)
        source = f"{dependency_locks.OFFICIAL_NPM_REGISTRY}next/{version}"
        dependency = {
            "ecosystem": "pnpm",
            "name": "next",
            "version": version,
            "license": "MIT",
            "purpose": "web application framework",
            "source_url": source,
            "integrity": {
                "algorithm": "npm-sri",
                "value": integrity,
                "source_url": source,
            },
            "direct_runtime_dependency": True,
        }
        manifest = json.loads((ROOT / "tools" / "manifest.yaml").read_text(encoding="utf-8"))
        licenses = {
            "MIT": [{"name": "next", "versions": [version], "license": "MIT"}]
        }
        review = dependency_locks._requested_dependency_review(
            {"dependencies": [dependency]},
            manifest,
            [],
            {"name": "next", "version": version},
            licenses,
        )
        self.assertEqual("pnpm-lock.yaml:resolution.integrity", review[0]["integrity_binding"])
        forged = json.loads(json.dumps(dependency))
        forged["integrity"]["value"] = "sha512-" + "A" * 86 + "=="
        with self.assertRaises(dependency_locks.LockError):
            dependency_locks._requested_dependency_review(
                {"dependencies": [forged]},
                manifest,
                [],
                {"name": "next", "version": version},
                licenses,
            )

    def test_go_dependency_rejects_metadata_only_go_mod_sum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "web").mkdir()
            (root / "package.json").write_text('{"private":true}\n', encoding="utf-8")
            (root / "web" / "package.json").write_text('{"private":true}\n', encoding="utf-8")
            module = "example.invalid/dependency"
            version = "v1.2.3"
            module_sum = "h1:" + "A" * 43 + "="
            go_mod_sum = "h1:" + "B" * 43 + "="
            (root / "go.sum").write_text(
                f"{module} {version} {module_sum}\n{module} {version}/go.mod {go_mod_sum}\n",
                encoding="utf-8",
            )
            escaped = dependency_locks._go_proxy_escape(module)
            dependency = {
                "ecosystem": "go",
                "name": module,
                "version": "1.2.3",
                "license": "MIT",
                "purpose": "runtime dependency fixture",
                "source_url": f"https://proxy.golang.org/{escaped}/@v/{version}.info",
                "integrity": {
                    "algorithm": "go-sum",
                    "value": go_mod_sum,
                    "source_url": f"https://sum.golang.org/lookup/{escaped}@{version}",
                },
                "direct_runtime_dependency": True,
            }
            manifest = {"runtimes": [], "tools": []}
            go_modules = [{"Path": module, "Version": version}]
            with mock.patch.object(dependency_locks, "ROOT", root):
                with self.assertRaisesRegex(dependency_locks.LockError, "does not match go.sum"):
                    dependency_locks._requested_dependency_review(
                        {"dependencies": [dependency]}, manifest, go_modules, [], {}
                    )
                dependency["integrity"]["value"] = module_sum
                review = dependency_locks._requested_dependency_review(
                    {"dependencies": [dependency]}, manifest, go_modules, [], {}
                )
            self.assertEqual("go.sum:module", review[0]["integrity_binding"])
            self.assertEqual("steward-reviewed-request", review[0]["license_basis"])

    def test_tool_ecosystem_go_tool_requires_module_zip_sum(self) -> None:
        manifest = json.loads((ROOT / "tools" / "manifest.yaml").read_text(encoding="utf-8"))
        record = next(item for item in manifest["tools"] if item["name"] == "oapi-codegen")
        dependency = {
            "ecosystem": "tool",
            "name": record["name"],
            "version": record["version"],
            "license": record["license"],
            "purpose": "generate accepted API consumers",
            "source_url": record["source"],
            "integrity": {
                "algorithm": "go-sum",
                "value": record["integrity"]["go_mod_sum"],
                "source_url": record["integrity"]["url"],
            },
            "direct_runtime_dependency": False,
        }
        with self.assertRaisesRegex(dependency_locks.LockError, "integrity does not match"):
            dependency_locks._requested_dependency_review(
                {"dependencies": [dependency]}, manifest, [], {}, {}
            )
        dependency["integrity"]["value"] = record["integrity"]["sum"]
        review = dependency_locks._requested_dependency_review(
            {"dependencies": [dependency]}, manifest, [], {}, {}
        )
        self.assertEqual("go-module-sum", review[0]["integrity_binding"])
        self.assertEqual("steward-reviewed-manifest", review[0]["license_basis"])

    def test_pnpm_license_coverage_includes_all_supported_platform_optionals(self) -> None:
        required = dependency_locks._pnpm_supported_lock_packages()
        darwin = ("@img/sharp-darwin-arm64", "0.34.5")
        linux = ("@img/sharp-linux-x64", "0.34.5")
        self.assertIn(darwin, required)
        self.assertIn(linux, required)
        entries = [
            {"name": name, "versions": [version], "license": "MIT"}
            for name, version in sorted(required)
            if (name, version) != linux
        ]
        with self.assertRaisesRegex(dependency_locks.LockError, "supported-platform"):
            dependency_locks._pnpm_license_coverage({"MIT": entries})
        derived_evidence = {
            "name": linux[0],
            "version": linux[1],
            "license": "MIT",
            "source_url": (
                "https://registry.npmjs.org/@img/sharp-linux-x64/-/"
                "sharp-linux-x64-0.34.5.tgz"
            ),
            "integrity": dependency_locks._pnpm_supported_lock_records()[linux],
        }
        with mock.patch.object(
            dependency_locks, "_fetch_pnpm_tarball_license", return_value=derived_evidence
        ) as fetch:
            derived_coverage = dependency_locks._pnpm_license_coverage(
                {"MIT": entries}, fetch_missing=True
            )
        fetch.assert_called_once()
        self.assertEqual([derived_evidence], derived_coverage["tarball_derived_packages"])
        entries.append({"name": linux[0], "versions": [linux[1]], "license": "MIT"})
        coverage = dependency_locks._pnpm_license_coverage({"MIT": entries})
        self.assertEqual(coverage["supported_lock_packages"], coverage["covered_lock_packages"])

    def test_tool_root_symlink_chain_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            (root / "build").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(toolchain.ToolchainError):
                toolchain._assert_no_symlink_chain(root, root / "build" / "tools" / "state.json")

    def test_dependency_apply_and_mutable_preflight_reject_symlinked_ignored_parents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            outside = root / "outside"
            outside.mkdir()
            (root / "build").symlink_to(outside, target_is_directory=True)
            with mock.patch.multiple(
                dependency_locks,
                ROOT=root,
                TOOLS_ROOT=root / "build" / "tools",
            ):
                with self.assertRaises(dependency_locks.LockError):
                    with dependency_locks._apply_lock():
                        self.fail("symlinked apply lock unexpectedly acquired")
            self.assertFalse((outside / "tools" / "dependency-apply.lock").exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "build" / "tools").mkdir(parents=True)
            outside = root / "outside"
            outside.mkdir()
            (root / "build" / "tools" / "trivy-cache").symlink_to(
                outside, target_is_directory=True
            )
            with mock.patch.multiple(
                tool_lock,
                ROOT=root,
                TOOLS_ROOT=root / "build" / "tools",
                LOCK_PATH=root / "build" / "tools" / ".operation.lock",
            ):
                with self.assertRaises(tool_lock.ToolLockError):
                    tool_lock.assert_safe_mutable_paths(
                        (root / "build" / "tools" / "trivy-cache" / "db",)
                    )

    def test_toolchain_private_writes_preserve_preplanted_symlink_victims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            tools_root = root / "build" / "tools"
            bin_root = tools_root / "bin"
            bin_root.mkdir(parents=True)
            victim = root / "victim.txt"
            victim.write_text("do-not-touch\n", encoding="utf-8")
            wrapper_temporary = bin_root / f"go.tmp-{os.getpid()}"
            wrapper_temporary.symlink_to(victim)
            with mock.patch.multiple(
                toolchain,
                ROOT=root,
                TOOLS_ROOT=tools_root,
                BIN_ROOT=bin_root,
            ):
                with self.assertRaises(toolchain.ToolchainError):
                    toolchain._write_wrapper("go", 'exec /bin/false "$@"\n')
                for relative in (
                    "state.json",
                    "_toolchains/example/1.0.0/.jumpship-tool.json",
                ):
                    target = tools_root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(victim)
                    with self.assertRaises(toolchain.ToolchainError):
                        toolchain._write_exclusive_file(target, b"forbidden\n", mode=0o644)
            self.assertEqual("do-not-touch\n", victim.read_text(encoding="utf-8"))
            self.assertTrue(wrapper_temporary.is_symlink())

    def test_archive_paths_reject_traversal(self) -> None:
        for value in ("../escape", "/absolute", "safe/../../escape"):
            with self.subTest(value=value), self.assertRaises(toolchain.ToolchainError):
                toolchain._safe_archive_name(value)

    def test_request_rejects_floating_version_and_secret_fields(self) -> None:
        request = {
            "schema_version": 1,
            "request_id": "P02-dep-example",
            "packet_id": "P02",
            "status": "proposed",
            "created_at": "not-a-timestamp",
            "requested_by": "",
            "dependencies": [
                {
                    "ecosystem": "go",
                    "name": "example.invalid/module",
                    "version": "latest",
                    "license": "not-an-spdx-license",
                    "purpose": "exercise negative validation",
                    "source_url": "https://example.invalid/module",
                    "integrity": {
                        "algorithm": "go-sum",
                        "value": "weak",
                        "source_url": "https://sum.golang.org/lookup/example.invalid/module@v1.0.0"
                    },
                    "direct_runtime_dependency": False
                }
            ],
            "affected_lockfiles": ["go.mod", "go.sum"],
            "affected_builds": ["", ""],
            "risk": {
                "security_sensitive": "false",
                "data_boundary_impact": "none",
                "justification": "bad"
            },
            "validation_requirements": ["license", "vulnerability", "clean-clone"],
            "api_token": "not-a-real-value"
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "P02.yaml"
            path.write_text(json.dumps(request), encoding="utf-8")
            errors = dependency_locks.request_errors(path)
        self.assertTrue(any("version must be exact" in error for error in errors))
        self.assertTrue(any("created_at must be a real UTC" in error for error in errors))
        self.assertTrue(any("reviewed SPDX" in error for error in errors))
        self.assertTrue(any("does not match its algorithm" in error for error in errors))
        self.assertTrue(any("requested_by must be" in error for error in errors))
        self.assertTrue(any("affected_builds must contain" in error for error in errors))
        self.assertTrue(any("security_sensitive must be boolean" in error for error in errors))
        self.assertTrue(any("risk justification" in error for error in errors))
        self.assertTrue(any("unexpected property 'api_token'" in error for error in errors))
        self.assertTrue(any("secret-bearing fields" in error for error in errors))

    def test_rejected_request_requires_string_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "P02.yaml"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "request_id": "P02-dep-example",
                        "packet_id": "P02",
                        "status": "rejected",
                        "created_at": "2026-07-17T00:00:00Z",
                        "requested_by": "packet-owner",
                        "dependencies": [],
                        "affected_lockfiles": ["go.mod"],
                        "affected_builds": ["contracts"],
                        "risk": {
                            "security_sensitive": False,
                            "data_boundary_impact": "none",
                            "justification": "reviewed rejection"
                        },
                        "validation_requirements": ["license", "vulnerability", "clean-clone"],
                        "rejection_reason": 7
                    }
                ),
                encoding="utf-8",
            )
            errors = dependency_locks.request_errors(path)
        self.assertTrue(any("string rejection_reason" in error for error in errors))

    def test_request_schema_uses_ecma_urls_status_conditionals_and_integrity_patterns(self) -> None:
        schema = json.loads((ROOT / "dependency" / "requests" / "schema.yaml").read_text())
        dependency = schema["properties"]["dependencies"]["items"]
        self.assertEqual(r"^https://\S+$", dependency["properties"]["source_url"]["pattern"])
        self.assertEqual(
            r"^https://\S+$",
            dependency["properties"]["integrity"]["properties"]["source_url"]["pattern"],
        )
        self.assertEqual(3, len(schema["allOf"]))
        integrity_patterns = {
            item["if"]["properties"]["algorithm"]["const"]: item["then"]["properties"][
                "value"
            ]["pattern"]
            for item in dependency["properties"]["integrity"]["allOf"]
        }
        self.assertEqual(
            {"sha256", "sha512", "npm-sri", "go-sum", "oci-digest"},
            set(integrity_patterns),
        )

    def test_applied_and_interrupted_request_states_fail_closed_without_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request_dir = root / "dependency" / "requests"
            request_dir.mkdir(parents=True)
            request_path = request_dir / "P02.yaml"

            applied = _valid_request("applied")
            request_path.write_bytes(dependency_locks._canonical_bytes(applied))
            missing_errors = dependency_locks._request_lifecycle_errors(
                request_path, applied, root=root
            )
            self.assertTrue(any("requires its canonical complete receipt" in error for error in missing_errors))

            accepted = _valid_request("accepted")
            request_path.write_bytes(dependency_locks._canonical_bytes(accepted))
            receipt_path = dependency_locks._canonical_receipt_path(accepted, root=root)
            receipt_path.parent.mkdir(parents=True)
            receipt_path.write_text('{"status":"complete"}\n', encoding="utf-8")
            interrupted_errors = dependency_locks._request_lifecycle_errors(
                request_path, accepted, root=root
            )
            self.assertTrue(any("transition is incomplete" in error for error in interrupted_errors))

            request_path.write_bytes(dependency_locks._canonical_bytes(applied))
            forged_errors = dependency_locks._request_lifecycle_errors(
                request_path, applied, root=root
            )
            self.assertTrue(any("missing or extra top-level" in error for error in forged_errors))

    def test_zero_python_test_discovery_is_a_failure(self) -> None:
        with self.assertRaises(quality.QualityError):
            quality._test_directories([])

    def test_python_test_discovery_finds_this_suite(self) -> None:
        directories = quality._test_directories(quality._repo_files())
        self.assertIn(ROOT / "scripts" / "dev" / "tests", directories)

    def test_public_readers_wait_while_exclusive_tool_writer_replaces_wrappers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary).resolve()
            isolated_tools = temporary_root / "build" / "tools"
            isolated_bin = isolated_tools / "bin"
            isolated_bin.mkdir(parents=True)
            (temporary_root / "tools").mkdir()
            manifest_path = temporary_root / "tools" / "manifest.yaml"
            manifest_path.write_bytes((ROOT / "tools" / "manifest.yaml").read_bytes())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            records = toolchain._records(manifest)
            state = {
                "manifest_id": manifest["manifest_id"],
                "manifest_sha256": dependency_locks._digest_file(manifest_path),
                "platform": toolchain._platform_key(),
                "tools": {name: records[name]["version"] for name in toolchain.BOOTSTRAP_NAMES},
            }
            (isolated_tools / "state.json").write_bytes(toolchain._canonical_bytes(state))
            outputs = {
                "go": "go version go1.26.5 test/arch",
                "node": "v24.18.0",
                "pnpm": "11.4.0",
                "tofu": "OpenTofu v1.11.0",
                "golangci-lint": "golangci-lint has version 2.12.2",
                "trivy": "Version: 0.72.0",
            }
            for name, output in outputs.items():
                wrapper = isolated_bin / name
                wrapper.write_text(f"#!/bin/sh\nprintf '%s\\n' {output!r}\n", encoding="utf-8")
                wrapper.chmod(0o755)
            (temporary_root / ".gitignore").write_text("build/\n", encoding="utf-8")
            (temporary_root / "README.md").write_text("# isolated lock test\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(temporary_root), "init", "-b", "main"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            ready = temporary_root / "ready"
            patch_prelude = textwrap.dedent(
                f"""
                import sys
                from pathlib import Path
                sys.path.insert(0, {str(ROOT / 'scripts' / 'dev')!r})
                import tool_lock
                isolated_root = Path({str(temporary_root)!r})
                isolated_tools = isolated_root / 'build' / 'tools'
                tool_lock.ROOT = isolated_root
                tool_lock.TOOLS_ROOT = isolated_tools
                tool_lock.LOCK_PATH = isolated_tools / '.operation.lock'
                """
            )
            holder_code = textwrap.dedent(
                f"""
                import os
                {textwrap.indent(patch_prelude, '                ').lstrip()}
                ready = Path({str(ready)!r})
                original = isolated_tools / 'bin'
                replacement = isolated_tools / 'bin.writer'
                with tool_lock.tool_operation_lock(exclusive=True):
                    try:
                        os.replace(original, replacement)
                        ready.write_text('ready', encoding='utf-8')
                        if sys.stdin.read(1) != 'x':
                            raise RuntimeError('exclusive-holder release pipe closed unexpectedly')
                    finally:
                        if replacement.exists():
                            os.replace(replacement, original)
                """
            )
            check_code = patch_prelude + textwrap.dedent(
                f"""
                import toolchain
                toolchain.ROOT = isolated_root
                toolchain.MANIFEST_PATH = isolated_root / 'tools' / 'manifest.yaml'
                toolchain.TOOLS_ROOT = isolated_tools
                toolchain.BIN_ROOT = isolated_tools / 'bin'
                toolchain.TOOLCHAINS_ROOT = isolated_tools / '_toolchains'
                toolchain.CACHE_ROOT = isolated_tools / 'cache'
                toolchain.STATE_PATH = isolated_tools / 'state.json'
                toolchain.check()
                """
            )
            format_code = patch_prelude + textwrap.dedent(
                """
                import quality
                quality.ROOT = isolated_root
                quality.TOOLS_ROOT = isolated_tools
                quality.TOOLS_BIN = isolated_tools / 'bin'
                quality.format_check(write=False)
                """
            )
            provenance_code = patch_prelude + textwrap.dedent(
                f"""
                sys.path.insert(0, {str(ROOT / 'scripts' / 'dependency-locks')!r})
                import dependency_locks
                dependency_locks._preflight_dependency_mutable_paths = lambda: None
                def verify(*, command_env=None):
                    if not (isolated_tools / 'bin' / 'go').is_file():
                        raise RuntimeError('provenance reader observed missing tool root')
                    print('dependency-provenance-check: isolated verified')
                dependency_locks._verify_deferred_provenance_unlocked = verify
                dependency_locks.verify_deferred_provenance()
                """
            )
            holder = subprocess.Popen(
                [sys.executable, "-c", holder_code],
                cwd=temporary_root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            readers: list[subprocess.Popen[str]] = []
            try:
                deadline = time.monotonic() + 30
                while not ready.exists() and holder.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not ready.exists():
                    if holder.stdin is not None and not holder.stdin.closed:
                        holder.stdin.close()
                        holder.stdin = None
                    try:
                        holder_output, _ = holder.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        holder.kill()
                        holder_output, _ = holder.communicate()
                    self.fail(f"exclusive holder did not become ready: {holder_output}")
                readers = [
                    subprocess.Popen(
                        [sys.executable, "-c", check_code],
                        cwd=temporary_root,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    ),
                    subprocess.Popen(
                        [sys.executable, "-c", format_code],
                        cwd=temporary_root,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    ),
                    subprocess.Popen(
                        [sys.executable, "-c", provenance_code],
                        cwd=temporary_root,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    ),
                ]
                time.sleep(0.25)
                self.assertTrue(all(reader.poll() is None for reader in readers))
                self.assertIsNotNone(holder.stdin)
                holder.stdin.write("x")
                holder.stdin.flush()
                holder.stdin.close()
                holder.stdin = None
                holder_output, _ = holder.communicate(timeout=15)
                self.assertEqual(0, holder.returncode, holder_output)
                outputs = [reader.communicate(timeout=30)[0] for reader in readers]
                self.assertEqual([0, 0, 0], [reader.returncode for reader in readers], outputs)
                self.assertIn("toolchain-check", outputs[0])
                self.assertIn("fmt:", outputs[1])
                self.assertIn("dependency-provenance-check", outputs[2])
            finally:
                if holder.poll() is None:
                    if holder.stdin is not None and not holder.stdin.closed:
                        try:
                            holder.stdin.write("x")
                            holder.stdin.flush()
                            holder.stdin.close()
                        except (BrokenPipeError, OSError):
                            pass
                        holder.stdin = None
                    try:
                        holder.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        holder.kill()
                        holder.communicate()
                for reader in readers:
                    if reader.poll() is None:
                        reader.kill()
                    reader.communicate()

    def test_serialized_apply_fails_closed_on_rename_or_copy(self) -> None:
        for status in ("R ", " R", "C ", " C"):
            payload = f"{status}allowed-path\0unauthorized-destination\0"
            with self.subTest(status=status), self.assertRaises(dependency_locks.LockError):
                dependency_locks._parse_status_z(payload)

    def test_candidate_diff_fails_closed_on_rename_or_copy(self) -> None:
        with self.assertRaises(dependency_locks.LockError):
            dependency_locks._parse_diff_name_status_z("R100\0go.mod\0other/go.mod\0")

    def test_serialized_apply_temp_git_journal_failure_replay_and_race_paths(self) -> None:
        digest = "a" * 64

        def git(root: Path, *arguments: str) -> str:
            result = subprocess.run(
                ["git", "-C", str(root), *arguments],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return result.stdout.strip()

        def make_fixture(
            root: Path, *, unrelated: bool = False, receipt_parent_symlink: bool = False
        ):
            root = root.resolve()
            git(root, "init", "-b", "main")
            git(root, "config", "user.email", "test@example.invalid")
            git(root, "config", "user.name", "P01 test")
            (root / "tools").mkdir()
            (root / "dependency" / "requests").mkdir(parents=True)
            (root / ".gitignore").write_text("build/\n", encoding="utf-8")
            (root / "go.mod").write_text("module example.invalid/test\n\ngo 1.26.5\n", encoding="utf-8")
            manifest = {
                "runtimes": [],
                "tools": [
                    {
                        "name": "example-tool",
                        "version": "1.0.0",
                        "license": "MIT",
                        "source": "https://example.invalid/example-tool/v1.0.0",
                        "bootstrap": False,
                        "integrity": {
                            "kind": "release-asset",
                            "url": "https://example.invalid/example-tool/v1.0.0/tool.tar.gz",
                            "sha256": digest,
                        },
                    }
                ],
            }
            manifest_path = root / "tools" / "manifest.yaml"
            manifest_path.write_bytes(dependency_locks._canonical_bytes(manifest))
            if receipt_parent_symlink:
                outside_receipts = root / "outside-receipts"
                outside_receipts.mkdir()
                packet_evidence = root / "delivery" / "mvp" / "evidence" / "P02"
                packet_evidence.mkdir(parents=True)
                (packet_evidence / "dependency-locks").symlink_to(
                    os.path.relpath(outside_receipts, packet_evidence),
                    target_is_directory=True,
                )
            git(root, "add", ".")
            git(root, "commit", "-m", "base")
            base = git(root, "rev-parse", "HEAD")

            request = _valid_request("accepted")
            request["dependencies"] = [
                {
                    "ecosystem": "tool",
                    "name": "example-tool",
                    "version": "1.0.0",
                    "license": "MIT",
                    "purpose": "exercise serialized apply",
                    "source_url": "https://example.invalid/example-tool/v1.0.0",
                    "integrity": {
                        "algorithm": "sha256",
                        "value": digest,
                        "source_url": "https://example.invalid/example-tool/v1.0.0/tool.tar.gz",
                    },
                    "direct_runtime_dependency": False,
                }
            ]
            request_path = root / "dependency" / "requests" / "P02.yaml"
            request_path.write_bytes(dependency_locks._canonical_bytes(request))
            (root / "go.mod").write_text(
                "module example.invalid/test\n\ngo 1.26.5\n\n// candidate lock update\n",
                encoding="utf-8",
            )
            if unrelated:
                (root / "UNRELATED.txt").write_text("forbidden\n", encoding="utf-8")
            git(root, "add", ".")
            git(root, "commit", "-m", "candidate")
            candidate = git(root, "rev-parse", "HEAD")
            accepted_sha = dependency_locks._digest_file(request_path)
            return manifest_path, request, request_path, base, candidate, accepted_sha

        def validations(request: dict, candidate: str) -> dict:
            dependency = request["dependencies"][0]
            return {
                "toolchain": {
                    "command": ["internal:toolchain._bootstrap_unlocked(repair=True)"],
                    "stdout_sha256": digest,
                },
                "deferred_provenance": {
                    "command": ["internal:_verify_deferred_provenance_unlocked"],
                    "stdout_sha256": digest,
                },
                "license": {
                    "candidate_install_stdout_sha256": digest,
                    "command": ["pnpm", "licenses", "list", "--json"],
                    "stdout_sha256": digest,
                    "license_counts": {},
                    "pnpm_supported_platform_coverage": {
                        "supported_lock_packages": 1,
                        "covered_lock_packages": 1,
                        "host_inventory_packages": 1,
                        "tarball_derived_packages": [],
                    },
                    "go_module_inventory_sha256": digest,
                    "pnpm_inventory_sha256": digest,
                    "requested_dependencies": [
                        {
                            "ecosystem": dependency["ecosystem"],
                            "name": dependency["name"],
                            "version": dependency["version"],
                            "license": dependency["license"],
                            "integrity": dependency["integrity"],
                            "source_url": dependency["source_url"],
                            "direct_runtime_dependency": dependency[
                                "direct_runtime_dependency"
                            ],
                            "integrity_binding": "deferred-provenance",
                            "license_basis": "steward-reviewed-manifest",
                        }
                    ],
                    "tool_manifest_licenses": {"example-tool": "MIT"},
                },
                "vulnerability": {
                    "pnpm_audit_stdout_sha256": digest,
                    "pnpm_counts": {"high": 0, "critical": 0},
                    "trivy_stdout_sha256": digest,
                    "trivy_high_critical_findings": 0,
                    "trivy_database": {
                        "repository": dependency_locks.TRIVY_DB_REPOSITORY,
                        "metadata": {"Version": 2},
                        "metadata_sha256": digest,
                        "database_sha256": digest,
                    },
                },
                "clean_clone": {
                    "report_sha256": digest,
                    "source_commit": candidate,
                    "command": ["make", "doctor", "bootstrap", "fmt", "lint", "test-unit"],
                    "stdout_sha256": digest,
                    "environment": {
                        "isolated_home": True,
                        "local_clone_no_hardlinks": True,
                        "source_worktree_clean": True,
                        "cloud_credentials_forwarded": False,
                    },
                },
            }

        @contextlib.contextmanager
        def patched_repo(root: Path, manifest_path: Path):
            root = root.resolve()
            manifest_path = manifest_path.resolve()

            @contextlib.contextmanager
            def neutral_tool_lock(*, exclusive: bool):
                self.assertTrue(exclusive)
                yield

            with mock.patch.multiple(
                dependency_locks,
                ROOT=root,
                MANIFEST_PATH=manifest_path,
                SCHEMA_PATH=root / "dependency" / "requests" / "schema.yaml",
                TOOLS_ROOT=root / "build" / "tools",
            ), mock.patch.object(
                dependency_locks, "tool_operation_lock", side_effect=neutral_tool_lock
            ), mock.patch.multiple(
                tool_lock,
                ROOT=root,
                TOOLS_ROOT=root / "build" / "tools",
                LOCK_PATH=root / "build" / "tools" / ".operation.lock",
            ):
                yield

        def arguments(request_path: Path, base: str, request_sha: str):
            return types.SimpleNamespace(
                request=request_path,
                base_commit=base,
                expected_request_sha256=request_sha,
                confirm="P02-dep-example",
            )

        # Stale caller input and an unrelated candidate both fail before any journal mutation.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, _, request_path, base, _, accepted_sha = make_fixture(root)
            accepted_bytes = request_path.read_bytes()
            with patched_repo(root, manifest_path):
                with self.assertRaises(dependency_locks.LockError):
                    dependency_locks.apply_request(arguments(request_path, base, "0" * 64))
            self.assertEqual(accepted_bytes, request_path.read_bytes())
            self.assertFalse((root / "delivery").exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, _, request_path, base, _, accepted_sha = make_fixture(
                root, receipt_parent_symlink=True
            )
            outside_receipts = root / "outside-receipts"
            with patched_repo(root, manifest_path), mock.patch.object(
                dependency_locks, "_run_dependency_validations"
            ) as validation_mock:
                with self.assertRaisesRegex(dependency_locks.LockError, "containment"):
                    dependency_locks.apply_request(arguments(request_path, base, accepted_sha))
                validation_mock.assert_not_called()
            self.assertEqual([], list(outside_receipts.iterdir()))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, _, request_path, base, _, accepted_sha = make_fixture(
                root, unrelated=True
            )
            accepted_bytes = request_path.read_bytes()
            with patched_repo(root, manifest_path), mock.patch.object(
                dependency_locks, "_run_dependency_validations"
            ) as validation_mock:
                with self.assertRaises(dependency_locks.LockError):
                    dependency_locks.apply_request(arguments(request_path, base, accepted_sha))
                validation_mock.assert_not_called()
            self.assertEqual(accepted_bytes, request_path.read_bytes())
            self.assertFalse((root / "delivery").exists())

        # Validation failure has no journal mutation; a concurrent lock edit is caught by final CAS.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, request, request_path, base, candidate, accepted_sha = make_fixture(root)
            accepted_bytes = request_path.read_bytes()
            with patched_repo(root, manifest_path), mock.patch.object(
                dependency_locks,
                "_run_dependency_validations",
                side_effect=dependency_locks.LockError("synthetic validation failure"),
            ):
                with self.assertRaisesRegex(dependency_locks.LockError, "synthetic validation"):
                    dependency_locks.apply_request(arguments(request_path, base, accepted_sha))
            self.assertEqual(accepted_bytes, request_path.read_bytes())
            self.assertFalse((root / "delivery").exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, request, request_path, base, candidate, accepted_sha = make_fixture(root)
            accepted_bytes = request_path.read_bytes()

            def racing_validation(_candidate: str, _request: dict):
                (root / "go.mod").write_text("raced\n", encoding="utf-8")
                return validations(request, candidate)

            with patched_repo(root, manifest_path), mock.patch.object(
                dependency_locks, "_run_dependency_validations", side_effect=racing_validation
            ):
                with self.assertRaisesRegex(dependency_locks.LockError, "worktree changed"):
                    dependency_locks.apply_request(arguments(request_path, base, accepted_sha))
            self.assertEqual(accepted_bytes, request_path.read_bytes())
            self.assertFalse((root / "delivery").exists())

        # A receipt-before-status crash is a distinct blocked journal and cannot replay.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, request, request_path, base, candidate, accepted_sha = make_fixture(root)
            with patched_repo(root, manifest_path), mock.patch.object(
                dependency_locks,
                "_run_dependency_validations",
                return_value=validations(request, candidate),
            ), mock.patch.object(
                dependency_locks,
                "_atomic_replace",
                side_effect=dependency_locks.LockError("synthetic receipt/status crash"),
            ):
                with self.assertRaisesRegex(dependency_locks.LockError, "receipt/status crash"):
                    dependency_locks.apply_request(arguments(request_path, base, accepted_sha))
                self.assertEqual("accepted", json.loads(request_path.read_text())["status"])
                receipt = dependency_locks._canonical_receipt_path(request)
                self.assertTrue(receipt.is_file())
                lifecycle = dependency_locks._request_lifecycle_errors(request_path, request)
                self.assertTrue(any("transition is incomplete" in error for error in lifecycle))
                with self.assertRaisesRegex(dependency_locks.LockError, "transition is incomplete"):
                    dependency_locks.apply_request(arguments(request_path, base, accepted_sha))

        # Success holds the exclusive tool lock through both CAS checks, validates applied state,
        # and makes replay fail without changing either journal file.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, request, request_path, base, candidate, accepted_sha = make_fixture(root)
            lock_state = {"held": False}
            cas_calls: list[bool] = []
            original_cas = dependency_locks._final_apply_cas

            @contextlib.contextmanager
            def exclusive_lock(*, exclusive: bool):
                self.assertTrue(exclusive)
                self.assertFalse(lock_state["held"])
                lock_state["held"] = True
                try:
                    yield
                finally:
                    lock_state["held"] = False

            def tracked_validation(_candidate: str, _request: dict):
                self.assertTrue(lock_state["held"])
                return validations(request, candidate)

            def tracked_cas(**kwargs):
                cas_calls.append(lock_state["held"])
                return original_cas(**kwargs)

            with patched_repo(root, manifest_path), mock.patch.object(
                dependency_locks, "tool_operation_lock", side_effect=exclusive_lock
            ), mock.patch.object(
                dependency_locks,
                "_run_dependency_validations",
                side_effect=tracked_validation,
            ), mock.patch.object(
                dependency_locks, "_final_apply_cas", side_effect=tracked_cas
            ):
                dependency_locks.apply_request(arguments(request_path, base, accepted_sha))
                applied = json.loads(request_path.read_text())
                receipt_path = dependency_locks._canonical_receipt_path(applied)
                self.assertEqual("applied", applied["status"])
                self.assertEqual([], dependency_locks._request_lifecycle_errors(request_path, applied))
                self.assertEqual([True, True], cas_calls)
                git(root, "add", ".")
                git(root, "commit", "-m", "commit applied dependency journal")
                later_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                later_manifest["tools"].append(
                    {
                        "name": "later-tool",
                        "version": "2.0.0",
                        "license": "Apache-2.0",
                        "source": "https://example.invalid/later-tool/v2.0.0",
                        "bootstrap": False,
                        "integrity": {
                            "kind": "release-asset",
                            "url": "https://example.invalid/later-tool/v2.0.0/tool.tar.gz",
                            "sha256": "b" * 64,
                        },
                    }
                )
                manifest_path.write_bytes(dependency_locks._canonical_bytes(later_manifest))
                git(root, "add", "tools/manifest.yaml")
                git(root, "commit", "-m", "later sequential tool update")
                self.assertEqual(
                    [], dependency_locks._request_lifecycle_errors(request_path, applied)
                )
                request_after = request_path.read_bytes()
                receipt_after = receipt_path.read_bytes()
                with self.assertRaises(dependency_locks.LockError):
                    dependency_locks.apply_request(
                        arguments(request_path, base, dependency_locks._digest_file(request_path))
                    )
                self.assertEqual(request_after, request_path.read_bytes())
                self.assertEqual(receipt_after, receipt_path.read_bytes())

    def test_applied_request_cannot_transition_again(self) -> None:
        applied = dependency_locks._applied_request({"status": "accepted"})
        self.assertEqual("applied", applied["status"])
        with self.assertRaises(dependency_locks.LockError):
            dependency_locks._applied_request(applied)

    def test_dependency_receipt_path_is_canonical(self) -> None:
        path = dependency_locks._canonical_receipt_path(
            {"packet_id": "P02", "request_id": "P02-dep-example"}
        )
        self.assertEqual(
            ROOT / "delivery/mvp/evidence/P02/dependency-locks/P02-dep-example.json",
            path,
        )

    def test_forged_minimal_receipt_cannot_trigger_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "P02-dep-example.json"
            receipt.write_text('{"status":"complete"}\n', encoding="utf-8")
            with self.assertRaises(dependency_locks.LockError):
                dependency_locks._ensure_receipt_absent(receipt)

    def test_clean_clone_relative_output_is_root_relative_and_contained(self) -> None:
        relative = Path("delivery/mvp/evidence/P01/clean-clone.json")
        self.assertEqual(ROOT / relative, clean_clone._resolve_output(relative))
        with self.assertRaises(clean_clone.CleanCloneError):
            clean_clone._resolve_output(Path("../escape.json"))

    def test_clean_clone_tail_redacts_temporary_absolute_paths(self) -> None:
        temporary_root = Path("/private/tmp/jumpship-clean-123")
        clone = temporary_root / "jumpship"
        home = temporary_root / "home"
        tail = clean_clone._redacted_tail(
            f"failed in {clone}/cmd\nhome={home}/.cache\nroot={temporary_root}/other\n",
            clone,
            home,
            temporary_root,
        )
        rendered = "\n".join(tail)
        self.assertNotIn(str(temporary_root), rendered)
        self.assertIn("<clean-clone>/cmd", rendered)
        self.assertIn("<isolated-home>/.cache", rendered)

    def test_clean_clone_tail_redacts_forwarded_network_values_and_credentialed_urls(self) -> None:
        temporary_root = Path("/private/tmp/jumpship-clean-456")
        clone = temporary_root / "jumpship"
        isolated_home = temporary_root / "home"
        proxy = "https://alice:super-secret@proxy.example:8443/?token=private"
        certificate = "/private/company/certs/internal.pem"
        rendered = "\n".join(
            clean_clone._redacted_tail(
                f"proxy={proxy}\ncert={certificate}\nsource={ROOT}\n"
                "url=https://example.invalid/file?credential=private\n",
                clone,
                isolated_home,
                temporary_root,
                (proxy, certificate),
            )
        )
        for forbidden in ("alice", "super-secret", "token=", certificate, str(ROOT), "credential="):
            self.assertNotIn(forbidden, rendered)
        self.assertIn("<forwarded-network-value>", rendered)
        self.assertIn("<redacted-url>", rendered)


if __name__ == "__main__":
    unittest.main()
