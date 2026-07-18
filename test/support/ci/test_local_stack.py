"""P03 local-stack and reproducibility contract tests."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from unittest import mock


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "infra" / "local" / "compose.yml"
STACK = ROOT / "infra" / "local" / "bin" / "stack"
DEV = ROOT / "infra" / "local" / "bin" / "dev"
TRUST_DOMAIN_CAPABILITY = "MVP-CAP-ARCH-TRUST-DOMAINS"
NONCHOICES_CAPABILITY = "MVP-CAP-NONCHOICES"
HAPROXY_IMAGE = (
    "haproxy:3.2.11-alpine3.23@"
    "sha256:17cd651239b99d2481580814103d56f55307ddc1170300702efa0c1baf106fa4"
)
INGRESS_SERVICES = frozenset(
    {"local-ingress", "network-ingress", "agent-ingress", "observability-ingress"}
)
PROTECTED_FIXTURES = frozenset(
    {
        "control-postgres",
        "cell-postgres",
        "target-postgres",
        "mongo",
        "mongo-init",
        "minio",
        "mailpit",
        "toxiproxy",
        "allowed-egress-fixture",
        "fake-bedrock",
        "fake-chat",
        "fake-tool-broker",
        "otel-collector",
    }
)


def run(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
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


class LocalStackContractTests(unittest.TestCase):
    @staticmethod
    def load_stack_module():
        loader = importlib.machinery.SourceFileLoader("p03_local_stack", str(STACK))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def test_compose_configuration_is_valid_without_runtime_state(self) -> None:
        result = run(str(STACK), "config")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_compose_images_are_versioned_and_digest_pinned(self) -> None:
        result = run(
            "docker",
            "compose",
            "--env-file",
            str(ROOT / "infra" / "local" / ".env.example"),
            "-f",
            str(COMPOSE),
            "--profile",
            "*",
            "config",
            "--format",
            "json",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        model = json.loads(result.stdout)
        images = [service["image"] for service in model["services"].values()]
        self.assertGreaterEqual(len(images), 8, images)
        for image in images:
            self.assertRegex(image, r":(?!latest(?:@|$))[^@]+@sha256:[0-9a-f]{64}$")

    def test_representative_services_and_profiles_are_declared(self) -> None:
        text = COMPOSE.read_text(encoding="utf-8").lower()
        for required in (
            "control-postgres",
            "cell-postgres",
            "target-postgres",
            "mongo",
            "minio",
            "mailpit",
            "toxiproxy",
            "wiremock",
            "otel",
        ):
            self.assertIn(required, text)
        self.assertNotIn("source-postgres", text)
        profile_result = run(
            "docker",
            "compose",
            "--env-file",
            str(ROOT / "infra" / "local" / ".env.example"),
            "-f",
            str(COMPOSE),
            "config",
            "--profiles",
        )
        self.assertEqual(profile_result.returncode, 0, profile_result.stdout)
        self.assertEqual(
            set(profile_result.stdout.split()),
            {"network", "agent", "observability", "web", "full"},
        )

    def test_only_fixed_ingress_relays_cross_the_internal_trust_boundary(self) -> None:
        text = COMPOSE.read_text(encoding="utf-8")
        lowered = text.lower()
        self.assertNotIn("privileged:", lowered)
        self.assertNotIn("docker.sock", lowered)
        self.assertNotIn("network_mode: host", lowered)
        rendered = run(
            "docker",
            "compose",
            "--env-file",
            str(ROOT / "infra" / "local" / ".env.example"),
            "-f",
            str(COMPOSE),
            "--profile",
            "*",
            "config",
            "--format",
            "json",
        )
        self.assertEqual(rendered.returncode, 0, rendered.stdout)
        model = json.loads(rendered.stdout)
        self.assertEqual(
            set(model["volumes"]),
            {
                "control-postgres-data",
                "cell-postgres-data",
                "target-postgres-data",
                "mongo-data",
                "mongo-config",
                "minio-data",
            },
        )
        self.assertTrue(model["networks"]["fixtures"]["internal"])
        self.assertFalse(model["networks"]["host-ingress"].get("internal", False))
        module = self.load_stack_module()
        self.assertEqual(module.MVP_CAP_ARCH_TRUST_DOMAINS, TRUST_DOMAIN_CAPABILITY)
        self.assertEqual(module.MVP_CAP_NONCHOICES, NONCHOICES_CAPABILITY)
        for network in model["networks"].values():
            self.assertEqual(
                network["labels"]["com.jumpship.capability.trust-domains"],
                TRUST_DOMAIN_CAPABILITY,
            )
            self.assertEqual(
                network["labels"]["com.jumpship.capability.nonchoices"],
                NONCHOICES_CAPABILITY,
            )

        published_services = {
            name for name, service in model["services"].items() if service.get("ports")
        }
        self.assertEqual(published_services, INGRESS_SERVICES)
        for name, service in model["services"].items():
            networks = set(service.get("networks", {}))
            if name in INGRESS_SERVICES:
                self.assertEqual(networks, {"fixtures", "host-ingress"}, name)
                self.assertEqual(service["image"], HAPROXY_IMAGE)
                self.assertEqual(
                    service["labels"]["com.jumpship.capability.trust-domains"],
                    TRUST_DOMAIN_CAPABILITY,
                )
                self.assertEqual(
                    service["labels"]["com.jumpship.capability.nonchoices"],
                    NONCHOICES_CAPABILITY,
                )
                for publication in service["ports"]:
                    self.assertEqual(publication["host_ip"], "127.0.0.1", name)
                config_mounts = [
                    mount
                    for mount in service.get("volumes", [])
                    if mount.get("target") == "/usr/local/etc/haproxy/haproxy.cfg"
                ]
                self.assertEqual(len(config_mounts), 1, name)
                self.assertTrue(config_mounts[0]["read_only"], name)
            elif name in PROTECTED_FIXTURES:
                self.assertEqual(networks, {"fixtures"}, name)
                self.assertFalse(service.get("ports"), name)
            else:
                self.assertFalse(service.get("ports"), name)
                self.assertNotIn("host-ingress", networks, name)

        ingress_configs = sorted(
            (ROOT / "infra" / "local" / "config" / "haproxy").glob("*.cfg")
        )
        self.assertEqual(len(ingress_configs), len(INGRESS_SERVICES))
        for config in ingress_configs:
            source = config.read_text(encoding="utf-8").lower()
            for forbidden in (
                "stats enable",
                "stats socket",
                "server-template",
                "http-request set-dst",
                "http-request set-uri",
            ):
                self.assertNotIn(forbidden, source, config)

    def test_stack_entrypoints_are_executable_and_repo_relative(self) -> None:
        for path in (STACK, DEV):
            mode = path.stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR, f"{path} is not executable")
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("/Users/", source)
            self.assertNotIn("/home/", source)

    def test_reset_fails_closed_and_discloses_exact_confirmation(self) -> None:
        result = run(str(STACK), "reset", "--confirm", "wrong-token")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("destroy:jumpship-local:volumes", result.stdout)
        self.assertIn("Docker context:", result.stdout)
        self.assertIn("Docker endpoint: 'unix://", result.stdout)

    def test_remote_docker_endpoints_and_contexts_are_denied(self) -> None:
        module = self.load_stack_module()
        with mock.patch.dict(
            os.environ,
            {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "DOCKER_HOST": "tcp://production.example.invalid:2376",
            },
            clear=True,
        ):
            with self.assertRaises(module.LocalStackError):
                module._local_docker_endpoint()

        with mock.patch.dict(
            os.environ,
            {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "DOCKER_HOST": "unix:///tmp/synthetic-local-docker.sock",
                "DOCKER_CONTEXT": "production",
            },
            clear=True,
        ), mock.patch.object(module, "_run") as docker_run:
            with self.assertRaises(module.LocalStackError):
                module._local_docker_endpoint()
            docker_run.assert_not_called()

        remote_context = subprocess.CompletedProcess(
            args=["docker", "context", "inspect"],
            returncode=0,
            stdout="ssh://production.example.invalid\n",
            stderr="",
        )
        with mock.patch.dict(
            os.environ,
            {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "DOCKER_CONTEXT": "production",
            },
            clear=True,
        ), mock.patch.object(module, "_run", return_value=remote_context):
            with self.assertRaises(module.LocalStackError):
                module._local_docker_endpoint()

    def test_unknown_and_later_owned_profiles_fail_before_docker(self) -> None:
        unknown = run(str(STACK), "up", "--profile", "ad-hoc")
        web = run(str(STACK), "up", "--profile", "web")
        full = run(str(STACK), "up", "--profile", "full")
        self.assertNotEqual(unknown.returncode, 0, unknown.stdout)
        self.assertIn("unknown local profile", unknown.stdout)
        for result in (web, full):
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("fail-closed ownership boundary", result.stdout)

    def test_compose_environment_is_allowlisted_and_credential_free(self) -> None:
        module = self.load_stack_module()
        hostile = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": "/tmp/synthetic-home",
            "AWS_ACCESS_KEY_ID": "synthetic-but-forbidden",
            "VERCEL_TOKEN": "synthetic-but-forbidden",
            "CUSTOMER_DATABASE_URL": "postgres://forbidden.invalid/customer",
            "JUMPSHIP_FIXTURE_POSTGRES_PASSWORD": "forbidden-override",
            "COMPOSE_FILE": "/tmp/forbidden-compose.yml",
            "COMPOSE_PROFILES": "full",
            "DOCKER_HOST": "unix:///tmp/synthetic-docker.sock",
            "DOCKER_CONTEXT": "synthetic-context",
            "DOCKER_TLS_VERIFY": "1",
            "DOCKER_CERT_PATH": "/tmp/synthetic-certs",
            "JUMPSHIP_CONTROL_POSTGRES_PORT": "25432",
        }
        with mock.patch.dict(os.environ, hostile, clear=True):
            environment = module._environment()
            pinned_environment = module._environment(
                sanitize_docker_selectors=True
            )
        self.assertEqual(environment["JUMPSHIP_CONTROL_POSTGRES_PORT"], "25432")
        self.assertEqual(environment["COMPOSE_PROJECT_NAME"], "jumpship-local")
        for forbidden in (
            "AWS_ACCESS_KEY_ID",
            "VERCEL_TOKEN",
            "CUSTOMER_DATABASE_URL",
            "JUMPSHIP_FIXTURE_POSTGRES_PASSWORD",
            "COMPOSE_FILE",
            "COMPOSE_PROFILES",
        ):
            self.assertNotIn(forbidden, environment)
        for selector in module.DOCKER_SELECTOR_ENVIRONMENT:
            self.assertNotIn(selector, pinned_environment)

    def test_down_preserves_volumes_and_reset_is_narrow(self) -> None:
        source = STACK.read_text(encoding="utf-8")
        down = source.split("def _down()", 1)[1].split("def _reset", 1)[0]
        reset = source.split("def _reset", 1)[1].split("def _config", 1)[0]
        self.assertNotIn("--volumes", down)
        self.assertIn('"--volumes"', reset)
        self.assertNotIn("volume prune", source)
        self.assertIn("validated Docker endpoint:", reset)

    def test_reset_pins_the_preconfirmation_endpoint_through_deletion(self) -> None:
        module = self.load_stack_module()
        selection = ("desktop-linux", "unix:///tmp/synthetic-docker.sock")
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with mock.patch.object(
            module, "_local_docker_endpoint", return_value=selection
        ), mock.patch.object(
            module, "_require_compose", return_value=selection
        ) as require_compose, mock.patch.object(
            module, "_validate_config"
        ) as validate_config, mock.patch.object(
            module, "_run", return_value=success
        ) as docker_run, contextlib.redirect_stdout(io.StringIO()):
            module._reset(module.RESET_CONFIRMATION)

        require_compose.assert_called_once_with(daemon=True, selection=selection)
        validate_config.assert_called_once_with(docker_host=selection[1])
        command = docker_run.call_args.args[0]
        self.assertEqual(command[:3], ["docker", "--host", selection[1]])
        self.assertEqual(command[-3:], ["down", "--volumes", "--remove-orphans"])
        self.assertTrue(docker_run.call_args.kwargs["sanitize_docker_selectors"])

    def test_mongo_primary_assertion_is_pinned_and_authenticated(self) -> None:
        module = self.load_stack_module()
        endpoint = "unix:///tmp/synthetic-docker.sock"
        results = (
            subprocess.CompletedProcess(args=[], returncode=0, stdout="container-id\n", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="exited 0\n", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="mongo-id\n", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="sha256:synthetic\n", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
        )
        with mock.patch.object(module, "_run", side_effect=results) as docker_run:
            module._assert_mongo_primary(endpoint)

        calls = docker_run.call_args_list
        self.assertEqual(len(calls), 6)
        for call in calls:
            self.assertEqual(call.args[0][:3], ["docker", "--host", endpoint])
            self.assertTrue(call.kwargs["sanitize_docker_selectors"])
        self.assertIn("mongo-init", calls[0].args[0])
        self.assertIn("{{.State.Status}} {{.State.ExitCode}}", calls[1].args[0])
        self.assertIn("db.hello().isWritablePrimary", calls[2].args[0][-1])
        self.assertIn("$MONGO_INITDB_ROOT_USERNAME", calls[2].args[0][-1])
        self.assertIn("mongo", calls[3].args[0])
        self.assertIn("{{.Image}}", calls[4].args[0])
        self.assertIn("jumpship-local-host-ingress", calls[5].args[0])
        self.assertTrue(
            any(
                "replicaSet=rs0&directConnection=true" in argument
                for argument in calls[5].args[0]
            )
        )
        self.assertIn(".watch(", calls[5].args[0][-1])
        self.assertIn("--read-only", calls[5].args[0])
        self.assertIn("--user", calls[5].args[0])
        self.assertIn("--cap-drop", calls[5].args[0])
        self.assertIn("--entrypoint", calls[5].args[0])

        readme = (ROOT / "infra" / "local" / "README.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("replicaSet=rs0&directConnection=true", readme)
        self.assertIn("change stream", readme)

        rendered = run(
            "docker",
            "compose",
            "--env-file",
            str(ROOT / "infra" / "local" / ".env.example"),
            "-f",
            str(COMPOSE),
            "config",
            "--format",
            "json",
        )
        self.assertEqual(rendered.returncode, 0, rendered.stdout)
        model = json.loads(rendered.stdout)
        self.assertEqual(
            model["services"]["local-ingress"]["depends_on"]["mongo-init"][
                "condition"
            ],
            "service_completed_successfully",
        )

    def test_every_runnable_profile_has_host_side_readiness_probes(self) -> None:
        module = self.load_stack_module()
        probes = module._readiness_probes(("network", "agent", "observability"))
        labels = {probe.label for probe in probes}
        self.assertEqual(len(labels), len(probes))
        for required in (
            "control PostgreSQL",
            "cell PostgreSQL",
            "target PostgreSQL",
            "MongoDB",
            "MinIO API",
            "Mailpit SMTP",
            "Mailpit UI",
            "Toxiproxy API",
            "allowed-egress fixture",
            "fake Bedrock",
            "fake chat",
            "fake tool broker",
            "OpenTelemetry gRPC",
            "OpenTelemetry HTTP",
            "OpenTelemetry health",
        ):
            self.assertIn(required, labels)

    def test_clean_clone_vector_is_the_binding_r013_vector(self) -> None:
        path = ROOT / "scripts" / "ci" / "clean_clone_rehearsal.py"
        spec = importlib.util.spec_from_file_location("p03_clean_clone", path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec else None)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        self.assertEqual(
            module.P03_VECTOR,
            ["make", "doctor", "bootstrap", "gen-check", "fmt", "lint", "test-unit", "verify"],
        )

    def test_clean_clone_environment_excludes_credentials_and_docker_authority(self) -> None:
        path = ROOT / "scripts" / "ci" / "clean_clone_rehearsal.py"
        spec = importlib.util.spec_from_file_location("p03_clean_clone_environment", path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec else None)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        with mock.patch.dict(
            os.environ,
            {
                "AWS_ACCESS_KEY_ID": "must-not-cross",
                "AWS_SECRET_ACCESS_KEY": "must-not-cross",
                "DOCKER_AUTH_CONFIG": "must-not-cross",
                "DOCKER_CERT_PATH": "must-not-cross",
                "DOCKER_CONTEXT": "must-not-cross",
                "DOCKER_HOST": "tcp://must-not-cross.example:2376",
                "DOCKER_TLS_VERIFY": "1",
            },
            clear=False,
        ):
            environment = module._isolated_environment(
                Path("/isolated-home"),
                Path("/isolated-root"),
                Path("/isolated-home/.docker"),
            )
        self.assertEqual(environment["HOME"], "/isolated-home")
        self.assertEqual(environment["DOCKER_CONFIG"], "/isolated-home/.docker")
        for forbidden in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "DOCKER_AUTH_CONFIG",
            "DOCKER_CERT_PATH",
            "DOCKER_CONTEXT",
            "DOCKER_HOST",
            "DOCKER_TLS_VERIFY",
        ):
            self.assertNotIn(forbidden, environment)


if __name__ == "__main__":
    unittest.main()
