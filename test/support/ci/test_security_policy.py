"""P03 fail-closed profile, workflow, and local-security tests."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
PROFILE_GUARD = ROOT / "scripts" / "ci" / "profile_guard.py"
WORKFLOW_POLICY = ROOT / "scripts" / "ci" / "workflow_policy.py"
RUN_GATE = ROOT / "scripts" / "ci" / "run_gate.py"
SECRET_SCAN = ROOT / "scripts" / "ci" / "secret_scan.py"


def run(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    for name in tuple(environment):
        if name.startswith(("AWS_", "GOOGLE_", "AZURE_")) or name.endswith(
            ("_TOKEN", "_API_KEY", "_SECRET")
        ):
            environment.pop(name, None)
    return subprocess.run(
        [*arguments],
        cwd=ROOT,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
    )


class ProfileGuardTests(unittest.TestCase):
    @staticmethod
    def load_guard_module():
        spec = importlib.util.spec_from_file_location("p03_profile_guard", PROFILE_GUARD)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def assert_profile(self, mode: str, profile: str, accepted: bool) -> None:
        arguments = [
            sys.executable,
            str(PROFILE_GUARD),
            "--mode",
            mode,
            "--profile",
            profile,
        ]
        if mode == "release":
            arguments.extend(("--release-digest", "sha256:" + "a" * 64))
        result = run(*arguments)
        if accepted:
            self.assertEqual(result.returncode, 0, result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_closed_profile_matrix(self) -> None:
        allowed = {
            "local": {"local"},
            "cloud": {"ephemeral-nonprod", "persistent-nonprod"},
            "release": {"paid-production"},
        }
        profiles = {
            "local",
            "ephemeral-nonprod",
            "persistent-nonprod",
            "paid-production",
            "dev",
            "staging",
            "production",
            "ephemeral-nonprod-extra",
        }
        for mode, accepted in allowed.items():
            for profile in profiles:
                with self.subTest(mode=mode, profile=profile):
                    self.assert_profile(mode, profile, profile in accepted)

    def test_rejection_does_not_emit_authority_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="jumpship-p03-guard-") as directory:
            output = Path(directory) / "github-output"
            result = run(
                sys.executable,
                str(PROFILE_GUARD),
                "--mode",
                "cloud",
                "--profile",
                "ad-hoc",
                "--github-output",
                str(output),
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertFalse(output.exists(), "denied profile emitted a downstream authority handle")

    def test_static_credentials_deny_before_profile_output(self) -> None:
        module = self.load_guard_module()
        with self.assertRaises(module.ProfileGuardError):
            module.validate_profile(
                "ephemeral-nonprod",
                "cloud",
                environment={"AWS_ACCESS_KEY_ID": "synthetic-but-forbidden"},
            )

    def test_protected_handoffs_deny_non_main_before_profile_output(self) -> None:
        module = self.load_guard_module()
        digest = "sha256:" + "a" * 64
        with self.assertRaises(module.ProfileGuardError):
            module.validate_profile(
                "ephemeral-nonprod",
                "cloud",
                environment={"GITHUB_REF": "refs/heads/feature"},
                require_main_ref=True,
            )
        with self.assertRaises(module.ProfileGuardError):
            module.validate_profile(
                "paid-production",
                "release",
                environment={"GITHUB_REF": "refs/tags/v1.0.0"},
                release_digest=digest,
                require_main_ref=True,
            )
        accepted = module.validate_profile(
            "ephemeral-nonprod",
            "cloud",
            environment={"GITHUB_REF": "refs/heads/main"},
            require_main_ref=True,
        )
        self.assertEqual(accepted["profile"], "ephemeral-nonprod")

    def test_profile_registry_bytes_are_bound_to_the_p02_manifest(self) -> None:
        module = self.load_guard_module()
        with tempfile.TemporaryDirectory(prefix="jumpship-p03-profile-contract-") as directory:
            isolated_root = Path(directory)
            for relative in (
                module.P02_CONTRACT_MANIFEST,
                module.PROFILE_REGISTRY,
            ):
                destination = isolated_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            registry = isolated_root / module.PROFILE_REGISTRY
            registry.write_bytes(registry.read_bytes() + b" ")
            with self.assertRaises(module.ProfileGuardError):
                module.validate_profile(
                    "ephemeral-nonprod",
                    "cloud",
                    environment={},
                    root=isolated_root,
                )

    def test_profile_registry_default_and_enum_are_semantically_closed(self) -> None:
        module = self.load_guard_module()
        registry = json.loads(
            (ROOT / module.PROFILE_REGISTRY).read_text(encoding="utf-8")
        )
        wrong_default = copy.deepcopy(registry)
        wrong_default["default_profile_id"] = "persistent-nonprod"
        with self.assertRaises(module.ProfileGuardError):
            module.validate_registry_semantics(wrong_default)

        widened = copy.deepcopy(registry)
        widened_profile = widened["profiles"][-1]
        widened_profile["profile_id"] = "ad-hoc-production"
        widened_profile["profile_hash"] = module._canonical_profile_hash(widened_profile)
        with self.assertRaises(module.ProfileGuardError):
            module.validate_registry_semantics(widened)

    def test_release_requires_an_immutable_digest(self) -> None:
        missing = run(
            sys.executable,
            str(PROFILE_GUARD),
            "--mode",
            "release",
            "--profile",
            "paid-production",
        )
        mutable = run(
            sys.executable,
            str(PROFILE_GUARD),
            "--mode",
            "release",
            "--profile",
            "paid-production",
            "--release-digest",
            "latest",
        )
        self.assertNotEqual(missing.returncode, 0, missing.stdout)
        self.assertNotEqual(mutable.returncode, 0, mutable.stdout)


class WorkflowAndLocalSecurityTests(unittest.TestCase):
    @staticmethod
    def load_run_gate_module():
        spec = importlib.util.spec_from_file_location("p03_run_gate", RUN_GATE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def load_secret_scan_module():
        spec = importlib.util.spec_from_file_location("p03_secret_scan", SECRET_SCAN)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_workflow_policy_passes(self) -> None:
        result = run(sys.executable, str(WORKFLOW_POLICY), "check")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_workflows_and_actions_are_json_compatible_yaml(self) -> None:
        paths = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        paths.extend(sorted((ROOT / ".github" / "actions").glob("*/action.yml")))
        self.assertGreaterEqual(len(paths), 9)
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                json.loads(path.read_text(encoding="utf-8"))

    def test_cloud_and_release_input_guards_explicitly_require_main(self) -> None:
        guarded_jobs = {
            "ci-infra.yml": "profile-gate",
            "release-qualify.yml": "release-input-gate",
        }
        for workflow, job_name in guarded_jobs.items():
            document = json.loads(
                (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
            )
            runs = [
                str(step.get("run", ""))
                for step in document["jobs"][job_name]["steps"]
                if isinstance(step, dict)
            ]
            with self.subTest(workflow=workflow):
                self.assertTrue(any("--require-main-ref" in run for run in runs))

    def test_local_entrypoints_cannot_invoke_cloud_control_planes(self) -> None:
        paths = sorted((ROOT / "infra" / "local" / "bin").glob("*"))
        paths.extend(
            [ROOT / "scripts" / "ci" / "clean_clone_rehearsal.py"]
        )
        invocation = re.compile(
            r"(?m)^\s*(?:exec\s+)?(?:[\"']?[^\s\"']*/)?(?:aws|tofu|terraform|gcloud|kubectl)(?:[\"']|\s|$)"
        )
        for path in paths:
            if not path.is_file():
                continue
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertIsNone(invocation.search(path.read_text(encoding="utf-8")))

    def test_local_telemetry_drops_payload_bearing_fields(self) -> None:
        config = (ROOT / "infra" / "local" / "config" / "otel-collector.yaml").read_text(
            encoding="utf-8"
        )
        for required in (
            "error_mode: propagate",
            'set(log.body, "[redacted-local-log-body]")',
            'delete_key(span.attributes, "db.query.text")',
            'delete_key(span.attributes, "url.full")',
            'delete_key(span.attributes, "gen_ai.prompt")',
            'delete_key(log.attributes, "gen_ai.completion")',
            'delete_key(log.attributes, "http.request.header.authorization")',
            'delete_key(log.attributes, "http.request.header.cookie")',
            'keep_keys(datapoint.attributes, ["jumpship.local.metric.dimension"])',
        ):
            self.assertIn(required, config)
        metrics_pipeline = re.search(
            r"(?ms)^    metrics:\n"
            r"(?:^      .+\n)*?"
            r"^      processors: \[([^\]]+)\]$",
            config,
        )
        self.assertIsNotNone(metrics_pipeline)
        assert metrics_pipeline is not None
        self.assertIn("transform/redact", metrics_pipeline.group(1).split(", "))

    def test_no_long_lived_cloud_key_material_is_declared(self) -> None:
        forbidden = re.compile(
            r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS|"
            r"AZURE_CLIENT_SECRET|AKIA[0-9A-Z]{16}"
        )
        paths = [ROOT / "infra" / "local", ROOT / ".github" / "workflows"]
        for base in paths:
            for path in sorted(base.rglob("*")):
                if path.is_file():
                    with self.subTest(path=path.relative_to(ROOT)):
                        self.assertIsNone(forbidden.search(path.read_text(encoding="utf-8")))

    def test_retained_gate_logs_are_redacted(self) -> None:
        module = self.load_run_gate_module()
        jwt = "eyJsynthetic12345.eyJsynthetic67890.syntheticSignature12345"
        access_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        github_token = "ghp_" + "a" * 36
        raw = (
            f"{ROOT} https://provider.invalid/path?token=value\n"
            "arn:aws:iam::123456789012:role/example\n"
            "Authorization: Bearer opaque-value\n"
            f"AWS_ACCESS_KEY_ID={access_key}\n"
            "DATABASE_PASSWORD=database-plaintext\n"
            "CLIENT_SECRET=client-plaintext\n"
            "NPM_TOKEN=npm-plaintext\n"
            f"GITHUB_TOKEN={github_token}\n"
            "RDS_HOST=db.cluster-abc.us-east-1.rds.amazonaws.com\n"
            "connected to queue.us-east-1.amazonaws.com\n"
            "PRIVATE_ENDPOINT=service.internal.example\n"
            "peer=10.24.3.8\n"
            f"password:plaintext {jwt}\n"
        )
        redacted = module.redact_line(raw, ROOT)
        for forbidden in (
            str(ROOT),
            "provider.invalid",
            "123456789012",
            "Bearer-value",
            "opaque-value",
            access_key,
            "database-plaintext",
            "client-plaintext",
            "npm-plaintext",
            github_token,
            "db.cluster-abc.us-east-1.rds.amazonaws.com",
            "service.internal.example",
            "10.24.3.8",
            "plaintext",
            jwt,
        ):
            self.assertNotIn(forbidden, redacted)
        self.assertIn("<redacted-url>", redacted)
        self.assertIn("<redacted-cloud-resource>", redacted)
        self.assertIn("<redacted-cloud-endpoint>", redacted)
        self.assertIn("<redacted-endpoint>", redacted)
        self.assertIn("<redacted-ip-address>", redacted)

    def test_gate_make_variables_are_closed_non_secret_selectors(self) -> None:
        module = self.load_run_gate_module()
        for allowed in (
            "SUITE=mvp",
            "PHASE=cdc",
            "PROFILE=ephemeral-nonprod",
            "ENV=nonprod",
            "ENV=production",
            "ROOT=control-plane",
            "RELEASE_DIGEST=sha256:" + "a" * 64,
        ):
            with self.subTest(allowed=allowed):
                self.assertTrue(module.make_variable_is_allowed(allowed))
        for denied in (
            "TOKEN=opaque",
            "FOO=bar",
            "ROOT=cell",
            "PROFILE=production",
            "PHASE=arbitrary",
            "RELEASE_DIGEST=latest",
        ):
            with self.subTest(denied=denied):
                self.assertFalse(module.make_variable_is_allowed(denied))

    def test_planned_gate_classification_uses_canonical_runtime_transitions(self) -> None:
        module = self.load_run_gate_module()
        inventory = module.load_runtime_inventory(ROOT)
        active = module.expected_inactive_coverage(
            inventory, "test-unit", ["SUITE=local-stack"]
        )
        self.assertEqual(active, frozenset())

        planned = module.expected_inactive_coverage(
            inventory, "test-unit", ["SUITE=identity"]
        )
        self.assertEqual(planned, frozenset({"_p06_test-unit_SUITE-identity=planned"}))

        transitioned = copy.deepcopy(inventory)
        for item in transitioned["commands"]["internal_targets"]:
            if item.get("target") == "_p06_test-unit_SUITE-identity":
                item["lifecycle"] = "active"
        self.assertEqual(
            module.expected_inactive_coverage(
                transitioned, "test-unit", ["SUITE=identity"]
            ),
            frozenset(),
        )
        with self.assertRaises(module.GateRunnerError):
            module.expected_inactive_coverage(inventory, "valid-but-unknown", [])

    def test_pinned_secret_scan_has_closed_offline_reporting(self) -> None:
        module = self.load_secret_scan_module()
        report = {
            "Results": [
                {"Secrets": [{"Match": "must-not-render"}]},
                {"Secrets": [{"Match": "also-must-not-render"}]},
            ]
        }
        self.assertEqual(module.count_secret_findings(report), 2)
        source = SECRET_SCAN.read_text(encoding="utf-8")
        for required in (
            '"--scanners"',
            '"secret"',
            '"--offline-scan"',
            '"--skip-db-update"',
            '"--disable-telemetry"',
            "raw scanner output suppressed",
            "raw matches suppressed",
        ):
            self.assertIn(required, source)
        make_fragment = (ROOT / "mk" / "packets" / "P03.mk").read_text(
            encoding="utf-8"
        )
        self.assertIn("python3 ./scripts/ci/secret_scan.py", make_fragment)

    def test_p03_policy_reserves_later_owner_workflow_names(self) -> None:
        spec = importlib.util.spec_from_file_location("p03_workflow_policy", WORKFLOW_POLICY)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for allowed in (
            "platform-plan.yml",
            "signer-qualify.yml",
            "deploy-production.yml",
            "recovery-drill.yml",
            "cell-build.yml",
            "mothership-release.yml",
        ):
            with self.subTest(allowed=allowed):
                self.assertIsNotNone(module.FUTURE_OWNER_WORKFLOW_RE.fullmatch(allowed))
        self.assertIsNone(module.FUTURE_OWNER_WORKFLOW_RE.fullmatch("unknown.yml"))


if __name__ == "__main__":
    unittest.main()
