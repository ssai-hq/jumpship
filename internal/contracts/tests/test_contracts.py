from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

from schema_validator import Registry, ValidationError, validate


ROOT = Path(__file__).resolve().parents[3]
CODEGEN = ROOT / "internal/contracts/codegen"
sys.path.insert(0, str(CODEGEN))
from model import DATA_CLASSES, GENERATOR, SCHEMA_DIALECT  # noqa: E402


class ContractSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema_paths = sorted(
            path
            for path in (ROOT / "contracts").rglob("*.schema.json")
            if "capabilities" not in path.relative_to(ROOT / "contracts").parts
        )
        cls.schemas = [json.loads(path.read_text()) for path in cls.schema_paths]
        cls.registry = Registry({document["$id"]: document for document in cls.schemas})

    def test_schema_registry_is_strict_unique_and_bounded(self) -> None:
        self.assertGreaterEqual(len(self.schemas), 70)
        ids = [schema["$id"] for schema in self.schemas]
        titles = [schema["title"] for schema in self.schemas]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(titles), len(set(titles)))
        versioned_schema_exceptions = {
            "contracts/client/customer-incapability-catalog.schema.json": "2.0.0",
        }
        for path, schema in zip(self.schema_paths, self.schemas, strict=True):
            relative = path.relative_to(ROOT).as_posix()
            self.assertEqual(schema["$schema"], SCHEMA_DIALECT, relative)
            self.assertEqual(schema["type"], "object", relative)
            self.assertIs(schema["additionalProperties"], False, relative)
            self.assertIn("schema_version", schema["required"], relative)
            self.assertEqual(
                schema["properties"]["schema_version"]["const"],
                versioned_schema_exceptions.get(relative, "1.0.0"),
                relative,
            )
            self.assertEqual(schema["x-generated-by"], GENERATOR, relative)
            self.assertIn(schema["x-jumpship-data-class"], DATA_CLASSES, relative)
            self.assertGreater(schema["x-jumpship-max-bytes"], 0, relative)
            self.assertTrue(schema["x-jumpship-flow-ids"], relative)
            self.assertTrue(all(re.fullmatch(r"F(?:0[1-9]|1[0-9]|2[0-8])", item) for item in schema["x-jumpship-flow-ids"]), relative)
            self._assert_bounded_objects(schema, relative)

    def _assert_bounded_objects(self, value: object, location: str) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object":
                self.assertIn("additionalProperties", value, location)
                additional = value["additionalProperties"]
                self.assertTrue(additional is False or isinstance(additional, dict), location)
            if value.get("type") == "array":
                self.assertIn("maxItems", value, location)
            for child in value.values():
                self._assert_bounded_objects(child, location)
        elif isinstance(value, list):
            for child in value:
                self._assert_bounded_objects(child, location)

    def test_schema_validator_fails_closed_and_uses_json_equality(self) -> None:
        with self.assertRaisesRegex(ValidationError, "unsupported schema keywords"):
            validate({}, {"type": "object", "unevaluatedMagic": False}, Registry({}))
        with self.assertRaises(ValidationError):
            validate(True, {"const": 1}, Registry({}))
        with self.assertRaises(ValidationError):
            validate([True], {"type": "array", "uniqueItems": True, "items": {}, "minItems": 1, "maxItems": 2, "contains": {"const": 1}}, Registry({}))
        with self.assertRaisesRegex(ValidationError, "unique JSON values"):
            validate("value", {"enum": ["value", "value"]}, Registry({}))

    def test_every_schema_has_valid_and_invalid_fixture(self) -> None:
        corpus = json.loads((ROOT / "contracts/fixtures/schema-corpus.json").read_text())
        records = corpus["records"]
        self.assertEqual(len(records), len(self.schemas))
        for record in records:
            schema = self.registry.by_id[record["schema_id"]]
            try:
                validate(record["valid"], schema, self.registry)
            except ValidationError as error:
                self.fail(f"valid fixture failed for {record['schema_path']}: {error}")
            with self.assertRaises(ValidationError, msg=record["schema_path"]):
                validate(record["invalid"], schema, self.registry)

    def test_declared_domain_fixtures_match_schema_expectations(self) -> None:
        checked = 0
        for path in sorted((ROOT / "contracts").rglob("*fixtures/*.json")) + sorted(
            (ROOT / "contracts/fixtures").rglob("*.json")
        ):
            if path.name == "schema-corpus.json":
                continue
            document = json.loads(path.read_text())
            default_schema = document.get("schema_path")
            for case in document.get("cases", []):
                payload = case.get("payload", case.get("document"))
                schema_path = case.get("schema_path", default_schema)
                expectation = case.get("expectation", case.get("expected"))
                if payload is None or schema_path is None or expectation not in {"valid", "invalid"}:
                    continue
                schema = json.loads((ROOT / schema_path).read_text())
                if expectation == "valid":
                    validate(payload, schema, self.registry)
                else:
                    with self.assertRaises(ValidationError, msg=f"{path}:{case.get('reason', case.get('name'))}"):
                        validate(payload, schema, self.registry)
                checked += 1

            expected_valid = document.get("expected_valid")
            if not isinstance(expected_valid, bool) or not isinstance(default_schema, str):
                continue
            instance = document.get("instance")
            if instance is None and isinstance(document.get("instance_patch"), dict):
                source_path = document.get("instance_patch_from")
                if isinstance(source_path, str):
                    base_path = ROOT / source_path
                else:
                    base_path = path.with_name(path.name.replace("invalid-", "valid-", 1))
                base_document = json.loads(base_path.read_text())
                instance = {**base_document["instance"], **document["instance_patch"]}
            if instance is None:
                self.fail(f"fixture declares expected_valid without an instance: {path}")
            schema = json.loads((ROOT / default_schema).read_text())
            if expected_valid:
                validate(instance, schema, self.registry)
            else:
                with self.assertRaises(ValidationError, msg=str(path)):
                    validate(instance, schema, self.registry)
            checked += 1

        self.assertGreaterEqual(checked, 40)

    def test_state_transition_fixtures_are_exhaustive_partitions(self) -> None:
        for path in sorted((ROOT / "contracts/fixtures/state-machines").glob("*.json")):
            fixture = json.loads(path.read_text())
            states = fixture["states"]
            valid = {(edge["from_state"], edge["to_state"]) for edge in fixture["valid_transitions"]}
            invalid = {(edge["from_state"], edge["to_state"]) for edge in fixture["invalid_transitions"]}
            known_invalid = {
                edge for edge in invalid if edge[0] in states and edge[1] in states
            }
            unknown_invalid = invalid - known_invalid
            self.assertFalse(valid & known_invalid, path.name)
            self.assertEqual(
                valid | known_invalid,
                {(source, target) for source in states for target in states},
                path.name,
            )
            self.assertTrue(
                any(source not in states for source, _ in unknown_invalid), path.name
            )
            self.assertTrue(
                any(target not in states for _, target in unknown_invalid), path.name
            )
            schema = json.loads((ROOT / fixture["schema_path"]).read_text())
            edge_branches = next(item["oneOf"] for item in schema["allOf"] if "oneOf" in item)
            self.assertEqual(len(edge_branches), len(valid), path.name)

    def test_monotonic_transition_and_failover_arithmetic_is_semantic(self) -> None:
        corpus = json.loads((ROOT / "contracts/fixtures/schema-corpus.json").read_text())
        by_id = {record["schema_id"]: record for record in corpus["records"]}

        transition_id = (
            "https://jumpship.dev/contracts/workflow/"
            "traffic-authority-state-machine.schema.json"
        )
        transition = by_id[transition_id]["valid"]
        transition_schema = self.registry.by_id[transition_id]
        validate(transition, transition_schema, self.registry)

        def valid_transition_arithmetic(value: dict[str, object]) -> bool:
            return (
                value["resulting_version"]
                == value["expected_version"] + value["version_increment"]
                and value["resulting_application_authority_epoch"]
                == value["expected_application_authority_epoch"]
                + value["application_authority_epoch_increment"]
                and value["resulting_cell_write_epoch"]
                == value["expected_cell_write_epoch"]
                + value["cell_write_epoch_increment"]
                and value["cell_write_epoch_increment"]
                == (1 if value["cell_generation_changed"] else 0)
            )

        self.assertTrue(valid_transition_arithmetic(transition))
        for field in (
            "resulting_version",
            "resulting_application_authority_epoch",
            "resulting_cell_write_epoch",
        ):
            tampered = {**transition, field: transition[field] + 1}
            validate(tampered, transition_schema, self.registry)
            self.assertFalse(valid_transition_arithmetic(tampered), field)

        for schema_id in (
            "https://jumpship.dev/contracts/recovery/control-region-failover-manifest.schema.json",
            "https://jumpship.dev/contracts/cell/certificate-recovery-renewal.schema.json",
        ):
            value = by_id[schema_id]["valid"]
            schema = self.registry.by_id[schema_id]
            validate(value, schema, self.registry)
            self.assertEqual(
                value["current_control_region_epoch"],
                value["prior_control_region_epoch"] + 1,
            )
            tampered = {
                **value,
                "current_control_region_epoch": value["current_control_region_epoch"] + 1,
            }
            validate(tampered, schema, self.registry)
            self.assertNotEqual(
                tampered["current_control_region_epoch"],
                tampered["prior_control_region_epoch"] + 1,
            )

    def test_application_and_bundle_lifecycles_are_closed_partitions(self) -> None:
        application = json.loads(
            (ROOT / "contracts/fixtures/application/state-transitions.json").read_text()
        )
        self.assertEqual(
            set(application["machines"]),
            {"patch_set", "pull_request", "external_review", "writer_grant", "writer_control"},
        )
        for name, machine in application["machines"].items():
            states = set(machine["states"])
            valid = {(edge["from_state"], edge["to_state"]) for edge in machine["valid_transitions"]}
            invalid = {(edge["from_state"], edge["to_state"]) for edge in machine["invalid_transitions"]}
            known_invalid = {(source, target) for source, target in invalid if source in states and target in states}
            self.assertFalse(valid & known_invalid, name)
            self.assertEqual(valid | known_invalid, {(source, target) for source in states for target in states}, name)
            self.assertTrue(any(source not in states for source, _ in invalid), name)
            self.assertTrue(any(target not in states for _, target in invalid), name)

        writer = application["machines"]["writer_control"]
        self.assertEqual(
            writer["authority_by_state"],
            {
                "source_enabled": "source",
                "freezing": "none",
                "fenced": "none",
                "target_pending": "none",
                "target_enabled": "target",
                "revoking": "none",
                "target_fenced": "none",
                "source_pending": "none",
                "source_resumed": "source",
                "tombstoned": "none",
                "blocked": "none",
            },
        )

        bundle = self.registry.by_id[
            "https://jumpship.dev/contracts/quality/bundle-lifecycle-transition.schema.json"
        ]
        states = set(bundle["properties"]["from_state"]["enum"])
        branches = bundle["oneOf"]
        edges = {
            (
                branch["properties"]["from_state"]["const"],
                branch["properties"]["to_state"]["const"],
            )
            for branch in branches
        }
        self.assertEqual(len(edges), len(branches))
        self.assertTrue(all(source in states and target in states for source, target in edges))
        for terminal in ("blocked", "superseded", "boundary_rolled_back"):
            self.assertFalse(any(source == terminal for source, _ in edges), terminal)
        self.assertNotIn(("boundary_canary", "production_authorized"), edges)

    def test_manifest_hashes_and_generated_inventory(self) -> None:
        manifest = json.loads((ROOT / "contracts/contract-manifest.json").read_text())
        self.assertEqual(manifest["canonicalization"], "RFC8785-JCS")
        self.assertEqual(len(manifest["artifacts"]), len({item["path"] for item in manifest["artifacts"]}))
        for record in manifest["artifacts"]:
            payload = (ROOT / record["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), record["sha256"], record["path"])
        expected_library_sources = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "internal/contracts/canonical").glob("*.go")
            if not path.name.endswith(("_test.go", ".gen.go"))
        }
        self.assertEqual(
            {record["path"] for record in manifest["library_sources"]},
            expected_library_sources,
        )
        for record in manifest["library_sources"]:
            payload = (ROOT / record["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), record["sha256"], record["path"])

        baseline = json.loads((ROOT / "contracts/compatibility-baseline.json").read_text())
        report = json.loads((ROOT / "contracts/compatibility-report.json").read_text())
        self.assertTrue(report["compatible"])
        self.assertIn(report["status"], {"compatible_unchanged", "compatible_additive"})
        baseline_hash = hashlib.sha256(
            (json.dumps(baseline["surface"], indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
        ).hexdigest()
        self.assertEqual(report["baseline_surface_sha256"], baseline_hash)

    def test_openapi_mutation_policy_and_audience_boundary(self) -> None:
        api = json.loads((ROOT / "contracts/openapi/openapi.yaml").read_text())
        self.assertTrue(str(api["openapi"]).startswith("3.1."))
        self.assertTrue(
            api["servers"][0]["url"].rstrip("/").endswith("/v1")
            or all(path.startswith("/v1/") for path in api["paths"]),
            "OpenAPI must expose only the /v1 base path",
        )
        sensitive_markers = {"consent", "approver", "secret", "evidence", "foundation", "billing", "traffic", "rollback"}
        mutation_count = 0
        operation_ids: set[str] = set()
        request_components: set[str] = set()
        for path, item in api["paths"].items():
            for method, operation in item.items():
                operation_id = operation["operationId"]
                self.assertNotIn(operation_id, operation_ids)
                operation_ids.add(operation_id)
                path_parameters = {
                    parameter["name"]
                    for parameter in operation.get("parameters", [])
                    if parameter["in"] == "path"
                }
                self.assertEqual(path_parameters, set(re.findall(r"\{([^}]+)\}", path)))
                if method not in {"post", "put", "patch", "delete"}:
                    continue
                mutation_count += 1
                policy = operation.get("x-jumpship-policy")
                self.assertIsInstance(policy, dict, f"{method.upper()} {path}")
                for field in (
                    "authorization",
                    "idempotency",
                    "audit",
                    "concurrency",
                    "stable_errors",
                    "allowed_audiences",
                    "data_class",
                    "max_request_bytes",
                    "csrf",
                ):
                    self.assertIn(field, policy, f"{method.upper()} {path}")
                self.assertTrue(
                    {"session_expired", "step_up_required", "stale_version", "capability_expired", "rate_limited"}.issubset(
                        policy["stable_errors"]
                    ),
                    f"stable error taxonomy drift for {method.upper()} {path}",
                )
                self.assertTrue(policy["audit"]["required"], operation_id)
                self.assertFalse(policy["audit"]["body_logged"], operation_id)
                self.assertTrue(policy["authorization"]["roles"], operation_id)
                self.assertEqual(
                    policy["coding_agent_denied"],
                    "jumpship-coding-agent" not in policy["allowed_audiences"] or policy["browser_only"],
                    operation_id,
                )
                if policy["idempotency"]["identity"] == "protocol_one_time_transaction":
                    self.assertFalse(policy["idempotency"]["required"], operation_id)
                else:
                    self.assertTrue(policy["idempotency"]["required"], operation_id)
                request_body = operation["requestBody"]
                self.assertEqual(request_body["x-jumpship-max-bytes"], policy["max_request_bytes"])
                self.assertEqual(request_body["x-jumpship-data-class"], policy["data_class"])
                self.assertEqual(len(request_body["content"]), 1, operation_id)
                media_type, media = next(iter(request_body["content"].items()))
                form_operations = {
                    "prepareIdentityOAuthCallback",
                    "completeIdentityOAuth",
                    "prepareConnectorOAuthCallback",
                    "completeConnectorOAuth",
                }
                self.assertEqual(
                    media_type,
                    "application/x-www-form-urlencoded" if operation_id in form_operations else "application/json",
                    operation_id,
                )
                request_ref = media["schema"]["$ref"]
                component_name = request_ref.removeprefix("#/components/schemas/")
                self.assertNotIn(component_name, request_components, operation_id)
                request_components.add(component_name)
                request_schema = api["components"]["schemas"][component_name]
                self.assertIs(request_schema["additionalProperties"], False, operation_id)
                self.assertTrue({"schema_version", "request_id"}.issubset(request_schema["required"]), operation_id)
                if method != "delete":
                    self.assertGreaterEqual(len(request_schema["required"]), 3, operation_id)
                if sensitive_markers.intersection(re.split(r"[/{}_-]+", path)):
                    self.assertNotIn("jumpship-coding-agent", policy["allowed_audiences"], path)
                exact_csrf_exempt = {
                    "startIdentityOAuth",
                    "prepareIdentityOAuthCallback",
                    "completeIdentityOAuth",
                    "prepareConnectorOAuthCallback",
                    "completeConnectorOAuth",
                }
                self.assertEqual(policy["csrf"]["exempt"], operation_id in exact_csrf_exempt, operation_id)
                header_names = {
                    parameter["name"]
                    for parameter in operation.get("parameters", [])
                    if parameter["in"] == "header"
                }
                if "jumpship-browser" in policy["allowed_audiences"] and operation_id not in exact_csrf_exempt:
                    self.assertIn("X-CSRF-Token", header_names, operation_id)
        self.assertGreaterEqual(mutation_count, 50)
        self.assertEqual(len(request_components), mutation_count)
        consent = api["components"]["schemas"]["ConsentKind"]
        self.assertEqual(consent["enum"], ["cutover", "decommission"])
        self.assertTrue(
            set(api["x-jumpship-sensitive-coding-agent-denylist"]).issubset(operation_ids)
        )
        forbidden = {
            "mergePullRequest",
            "deployApplication",
            "setTrafficAuthority",
            "activateRelease",
            "rollbackRelease",
            "emergencyStopRelease",
        }
        self.assertFalse(operation_ids & forbidden)

    def test_openapi_protocol_hosts_and_critical_shapes(self) -> None:
        api = json.loads((ROOT / "contracts/openapi/openapi.yaml").read_text())

        def operation(path: str, method: str) -> dict[str, object]:
            return api["paths"][path][method]

        oauth_start = operation("/v1/auth/oauth/{provider}/start", "post")
        self.assertEqual(oauth_start["security"], [{}, {"CookieSession": []}])
        callback = operation("/v1/auth/oauth/{provider}/callback", "get")
        self.assertEqual(callback["security"], [])
        self.assertEqual(callback["x-jumpship-query-one-of"], [["code"], ["error"]])
        self.assertEqual(callback["servers"][0]["url"], "https://auth-callback.{domain}")
        self.assertEqual(
            {parameter["name"] for parameter in callback["parameters"] if parameter["in"] == "query"},
            {"state", "code", "error", "error_description"},
        )
        self.assertIn("text/html", callback["responses"]["200"]["content"])
        self.assertEqual(callback["responses"]["200"]["headers"]["Cache-Control"]["schema"]["const"], "no-store")
        prepare = operation("/v1/auth/oauth/{provider}/prepare", "post")
        self.assertIn("303", prepare["responses"])
        self.assertNotIn("200", prepare["responses"])
        self.assertEqual(set(prepare["requestBody"]["content"]), {"application/x-www-form-urlencoded"})
        self.assertIn(
            "Origin",
            {parameter["name"] for parameter in prepare["parameters"] if parameter["in"] == "header"},
        )
        complete = operation("/v1/auth/oauth/complete", "post")
        self.assertIn("303", complete["responses"])
        self.assertEqual(set(complete["requestBody"]["content"]), {"application/x-www-form-urlencoded"})
        connector_begin = operation(
            "/v1/workspaces/{workspace_id}/migrations/{migration_id}/connectors/{kind}/begin",
            "post",
        )
        self.assertIn(
            "X-CSRF-Token",
            {parameter["name"] for parameter in connector_begin["parameters"] if parameter["in"] == "header"},
        )

        start = api["components"]["schemas"]["StartMigrationFromPromptRequest"]
        self.assertTrue(
            {
                "first_prompt",
                "expected_migration_version",
                "expected_start_readiness_version",
                "mandatory_connector_proof_roots",
            }.issubset(start["required"])
        )
        self.assertEqual(start["properties"]["mandatory_connector_proof_roots"]["minItems"], 3)
        writer = operation("/v1/application-writer/grants", "post")
        self.assertEqual(writer["security"], [{"ApplicationWriterBearer": []}])
        bootstrap = operation("/v1/internal/cell-certificates/bootstrap/request", "post")
        self.assertEqual(bootstrap["security"], [{"CellBootstrapSecret": []}])

    def test_auth_topology_is_closed_and_negative_witnesses_deny(self) -> None:
        fixture = json.loads(
            (ROOT / "contracts/fixtures/auth/valid-deployed-config.json").read_text()
        )
        schema = json.loads((ROOT / fixture["schema_path"]).read_text())
        instance = fixture["instance"]
        validate(instance, schema, self.registry)
        self.assertEqual(
            [provider["provider"] for provider in instance["providers"]],
            ["google", "github"],
        )
        self.assertEqual(
            {cookie["name"] for cookie in instance["cookies"]},
            {
                "__Host-js_session",
                "__Host-js_oauth_start",
                "__Host-js_oauth_callback",
                "__Secure-js_present",
            },
        )
        for cookie in instance["cookies"]:
            self.assertTrue(cookie["secure"])
            self.assertTrue(cookie["http_only"])
            self.assertEqual(cookie["same_site"], "Lax")
        self.assertEqual(len(instance["route_tuples"]), 9)
        self.assertEqual(len(instance["sensitive_body_routes"]), 14)
        self.assertEqual(instance["presentation_jwks_url"], "https://api.example.com/v1/auth/jwks.json")
        self.assertLessEqual(instance["presentation_jwks_cache_max_seconds"], 300)
        self.assertEqual(instance["presentation_rotation_cadence"], "monthly")
        self.assertTrue(instance["cors_allow_credentials"])
        self.assertEqual(
            set(instance["csrf_exempt_operation_ids"]),
            {
                "startIdentityOAuth",
                "prepareIdentityOAuthCallback",
                "consumeIdentityOAuthCallback",
                "completeIdentityOAuth",
                "prepareConnectorOAuthCallback",
                "consumeConnectorOAuthCallback",
                "completeConnectorOAuth",
            },
        )

        duplicate_provider = json.loads(json.dumps(instance))
        duplicate_provider["providers"][1]["provider"] = "google"
        with self.assertRaises(ValidationError):
            validate(duplicate_provider, schema, self.registry)
        insecure_cookie = json.loads(json.dumps(instance))
        insecure_cookie["cookies"][0]["secure"] = False
        with self.assertRaises(ValidationError):
            validate(insecure_cookie, schema, self.registry)
        wrong_session_ttl = json.loads(json.dumps(instance))
        wrong_session_ttl["cookies"][0]["max_age_seconds"] = 60
        with self.assertRaises(ValidationError):
            validate(wrong_session_ttl, schema, self.registry)
        inherited_csrf_exemption = json.loads(json.dumps(instance))
        invitation_route = next(
            route
            for route in inherited_csrf_exemption["sensitive_body_routes"]
            if route["path_template"] == "/v1/invitations/accept"
        )
        invitation_route["csrf_exempt"] = True
        with self.assertRaises(ValidationError):
            validate(inherited_csrf_exemption, schema, self.registry)
        incomplete_sensitive_routes = json.loads(json.dumps(instance))
        incomplete_sensitive_routes["sensitive_body_routes"].pop()
        with self.assertRaises(ValidationError):
            validate(incomplete_sensitive_routes, schema, self.registry)

        denials = json.loads(
            (ROOT / "contracts/fixtures/auth/deployed-config-denials.json").read_text()
        )
        for case in denials["cases"]:
            witness = json.loads(json.dumps(instance))
            if "extra_property" in case:
                witness[case["extra_property"]] = "forbidden"
            if "remove" in case:
                witness.pop(case["remove"])
            witness.update(case.get("patch", {}))
            with self.assertRaises(ValidationError, msg=case["case_id"]):
                validate(witness, schema, self.registry)

        internal_routes = [
            route for route in instance["route_tuples"] if route["host_role"] == "cell_control"
        ]
        self.assertEqual(len(internal_routes), 2)
        self.assertTrue(all(route["csrf_exempt"] for route in internal_routes))
        invitation = next(
            route
            for route in instance["sensitive_body_routes"]
            if route["path_template"] == "/v1/invitations/accept"
        )
        self.assertFalse(invitation["csrf_exempt"])

    def test_proto_recovery_is_unary_and_authority_free(self) -> None:
        proto = (ROOT / "contracts/proto/jumpship/cell/v1/cell.proto").read_text()
        self.assertIn("service CellCertificateRecovery", proto)
        self.assertRegex(
            proto,
            r"rpc\s+Connect\s*\(\s*stream\s+SupervisorFrame\s*\)\s+returns\s*\(\s*stream\s+SupervisorFrame\s*\)",
        )
        renew = re.search(r"rpc\s+Renew\s*\(\s*(\w+)\s*\)\s+returns\s*\(\s*(\w+)\s*\)", proto)
        self.assertIsNotNone(renew)
        self.assertNotRegex(proto, r"rpc\s+Renew\s*\(\s*stream")
        self.assertNotIn("google.protobuf.Any", proto)
        request = re.search(rf"message\s+{re.escape(renew.group(1))}\s*\{{(.*?)\n\}}", proto, re.S)
        self.assertIsNotNone(request)
        self.assertFalse(re.search(r"grant|write_authority|stream_authority|tool_authority", request.group(1), re.I))
        response = re.search(rf"message\s+{re.escape(renew.group(2))}\s*\{{(.*?)\n\}}", proto, re.S)
        self.assertIsNotNone(response)
        response_fields = set(
            re.findall(r"^\s*(?:[A-Za-z0-9_.]+)\s+([a-z][a-z0-9_]*)\s*=", response.group(1), re.M)
        )
        self.assertEqual(
            response_fields,
            {"context", "request_id", "poll_secret", "poll_secret_hash", "expires_at", "recovery_receipt_root"},
        )
        self.assertFalse(
            response_fields
            & {"command", "operation_grant", "credential_lease", "stream_token", "traffic_authority"}
        )
        supervisor = re.search(r"message\s+SupervisorFrame\s*\{(.*?)\n\}", proto, re.S)
        self.assertIsNotNone(supervisor)
        self.assertIn("oneof frame", supervisor.group(1))
        self.assertEqual(len(re.findall(r"=\s*(?:[2-9]|1[0-9])\s*;", supervisor.group(1))), 18)
        self.assertIn("ProviderEvidenceTransitionDelivery provider_evidence_transition", supervisor.group(1))
        self.assertIn("ProviderUseLeaseFrame provider_use_lease", supervisor.group(1))
        hello = re.search(r"message\s+CellHello\s*\{(.*?)\n\}", proto, re.S)
        self.assertIsNotNone(hello)
        self.assertIn("repeated ProviderControlHead provider_control_heads", hello.group(1))
        lease = re.search(r"message\s+ProviderUseLeaseFrame\s*\{(.*?)\n\}", proto, re.S)
        self.assertIsNotNone(lease)
        for required_claim in (
            "reservation_id",
            "cell_id",
            "cell_generation",
            "provider_data_use_record_hash",
            "accepted_transition_sequence",
            "accepted_status_hash",
            "agent_bundle_hash",
            "release_unit_hash",
            "control_epoch",
            "ttl_seconds",
            "nonce_hash",
            "signature_envelope_hash",
        ):
            self.assertRegex(lease.group(1), rf"\b{required_claim}\s*=", required_claim)
        nested_stream_messages = {
            "CellHello",
            "Heartbeat",
            "CommandLease",
            "CommandAck",
            "ProjectionSnapshot",
            "OperationGrant",
            "ToolReceipt",
            "CellEventBatch",
            "EventAck",
            "EvidenceAccessRequest",
            "EvidenceAccessReceipt",
            "CredentialLeaseRequest",
            "CredentialLeaseReceipt",
            "RecoveryPointer",
            "ProviderEvidenceTransitionDelivery",
            "ProviderRouteHoldFrame",
            "ProviderUseLeaseFrame",
            "ProviderControlAck",
        }
        for message in re.finditer(r"message\s+(\w+)\s*\{(.*?)\n\}", proto, re.S):
            numbers = re.findall(r"=\s*(\d+)\s*;", message.group(2))
            self.assertEqual(len(numbers), len(set(numbers)), message.group(1))
            if message.group(1) in nested_stream_messages:
                self.assertNotRegex(message.group(2), r"\bEnvelopeContext\s+context\s*=", message.group(1))

    def test_crypto_corridor_reversibility_and_certificate_profiles_are_closed(self) -> None:
        signature = self.registry.by_id[
            "https://jumpship.dev/contracts/crypto/signature-envelope.schema.json"
        ]
        registry = self.registry.by_id[
            "https://jumpship.dev/contracts/crypto/public-key-registry.schema.json"
        ]
        algorithms = ["ECDSA_P256_SHA256", "RSA_PSS_SHA256"]
        self.assertEqual(signature["properties"]["algorithm"]["enum"], algorithms)
        self.assertEqual(
            registry["properties"]["keys"]["items"]["properties"]["algorithm"]["enum"],
            algorithms,
        )

        reversibility = self.registry.by_id[
            "https://jumpship.dev/contracts/decisions/reversibility.schema.json"
        ]
        expected_classes = {
            "free_until_cutover",
            "expensive_after_cutover",
            "closes_on_first_external_exposure",
            "closes_on_a_clock",
            "never_reversible",
        }
        branches = next(item["oneOf"] for item in reversibility["allOf"] if "oneOf" in item)
        self.assertEqual(
            {branch["properties"]["reversibility_class"]["const"] for branch in branches},
            expected_classes,
        )
        for branch in branches:
            properties = branch["properties"]
            self.assertIs(properties["warning_required"]["const"], True)
            self.assertEqual(properties["warning_threshold_seconds"]["minItems"], 1)
            self.assertIn("const", properties["closure_predicate"])

        corridor = self.registry.by_id[
            "https://jumpship.dev/contracts/corridors/mongodb-postgres-profile.schema.json"
        ]
        serialized = json.dumps(corridor, sort_keys=True)
        for invariant in (
            "change_stream_pre_post_images",
            "change_stream_lookup",
            "freeze_only",
            "target_endpoint_unsuitable",
            "transaction_pooler",
        ):
            self.assertIn(invariant, serialized)

        certificate = (ROOT / "contracts/cell/certificate-profile.yaml").read_text()
        self.assertIn("maximum_seconds: 86400", certificate)
        self.assertIn("private_key_export_allowed: false", certificate)
        self.assertIn("required_uri_pattern: '^spiffe://jumpship/cells/", certificate)
        self.assertRegex(certificate, r"extended_key_usage:\n  critical: true\n  required:\n    - clientAuth")
        self.assertIsNotNone(
            re.search(r"extended_key_usage:.*?forbidden:\n    - serverAuth", certificate, re.S)
        )
        crl = (ROOT / "contracts/cell/crl-profile.yaml").read_text()
        self.assertIn("monotonic_increment: 1", crl)
        self.assertIn("content_addressed: true", crl)
        self.assertIn("versioned_object_required: true", crl)
        self.assertIn("direct_overwrite_forbidden: true", crl)

    def test_tool_and_boundary_contracts(self) -> None:
        tool = self.registry.by_id["https://jumpship.dev/contracts/agent/tool.schema.json"]
        required = set(tool["required"])
        self.assertTrue(
            {
                "execution_mode",
                "consequence_class",
                "input_schema_hash",
                "output_schema_hash",
                "capability_requirements",
                "timeout_ms",
                "retry_policy",
                "limits",
                "receipt_schema_id",
                "receipt_schema_hash",
                "allowed_phases",
                "gate_requirements",
                "consent_requirement",
                "idempotency_scope",
                "input_data_class",
                "output_data_class",
                "run_brief_authorization",
                "reversibility_class",
                "warning_rule",
                "safe_failure",
            }.issubset(required)
        )
        self.assertEqual(tool["properties"]["execution_mode"]["enum"], ["inline", "durable"])
        inline = next(
            branch
            for branch in tool["oneOf"]
            if branch["properties"]["execution_mode"].get("const") == "inline"
        )
        self.assertEqual(inline["properties"]["consequence_class"]["const"], "observation")
        self.assertEqual(inline["properties"]["reversibility_class"]["const"], "not_applicable")
        self.assertEqual(inline["properties"]["warning_rule"]["const"], "none")
        self.assertEqual(inline["properties"]["consent_requirement"]["const"], "none")
        self.assertEqual(inline["properties"]["limits"]["properties"]["network_mode"]["const"], "none")
        self.assertFalse(
            inline["properties"]["run_brief_authorization"]["properties"]["may_widen_to_durable"]["const"]
        )
        self.assertNotIn(
            "credential_secret",
            inline["properties"]["input_data_class"]["enum"],
        )
        run_brief = tool["properties"]["run_brief_authorization"]["properties"]
        self.assertLessEqual(run_brief["max_cumulative_wall_clock_ms"]["maximum"], 3_600_000)
        self.assertLessEqual(run_brief["max_cumulative_output_bytes"]["maximum"], 104_857_600)

        analysis = self.registry.by_id[
            "https://jumpship.dev/contracts/agent/analysis-run.schema.json"
        ]
        for field in ("network_enabled", "credentials_mounted", "undeclared_artifacts_allowed"):
            self.assertIs(analysis["properties"][field]["const"], False)
        sandbox = analysis["properties"]["sandbox"]["properties"]
        for field in (
            "rootless",
            "read_only_root_filesystem",
            "no_new_privileges",
            "user_namespace_enabled",
        ):
            self.assertIs(sandbox[field]["const"], True)
        for field in (
            "imds_access",
            "broker_socket_mounted",
            "container_socket_mounted",
            "provider_material_mounted",
            "iam_material_mounted",
            "secret_material_mounted",
            "socket_syscalls_allowed",
        ):
            self.assertIs(sandbox[field]["const"], False)
        authority = analysis["properties"]["authority"]["properties"]
        self.assertIs(authority["advisory_only"]["const"], True)
        self.assertTrue(
            all(spec.get("const") is False for name, spec in authority.items() if name != "advisory_only")
        )
        analysis_limits = analysis["properties"]["resource_limits"]["properties"]
        self.assertEqual(analysis_limits["execution_count"]["const"], 1)
        self.assertLessEqual(analysis_limits["wall_seconds"]["maximum"], 60)
        self.assertLessEqual(analysis_limits["memory_bytes"]["maximum"], 4_294_967_296)
        self.assertLessEqual(analysis_limits["max_output_bytes"]["maximum"], 104_857_600)

        provider = self.registry.by_id[
            "https://jumpship.dev/contracts/agent/provider-data-use.schema.json"
        ]
        self.assertEqual(provider["properties"]["provider"]["const"], "amazon_bedrock")
        self.assertIn("foundation-model/anthropic\\.claude", provider["properties"]["model_id"]["pattern"])
        self.assertIs(provider["properties"]["cross_region_allowed"]["const"], False)
        self.assertIs(provider["properties"]["public_endpoint_allowed"]["const"], False)
        self.assertEqual(provider["properties"]["api_surface"]["const"], "bedrock-runtime")
        self.assertRegex("123456789012", provider["properties"]["aws_account_id"]["pattern"])
        self.assertEqual(provider["properties"]["provider_sharing_mode"]["const"], "disabled")
        self.assertEqual(provider["properties"]["training_use"]["const"], "prohibited")
        incapability = self.registry.by_id["https://jumpship.dev/contracts/client/customer-incapability-catalog.schema.json"]
        self.assertFalse(
            any("signature" in property_name for property_name in incapability["properties"]),
            "the ReleaseUnit release-evidence signature binds the catalog; the catalog has no independent signature field",
        )
        self.assertIs(
            incapability["properties"]["items"]["items"]["properties"]["coding_agent_denied"]["const"],
            True,
        )
        self.assertEqual(incapability["properties"]["schema_version"]["const"], "2.0.0")
        self.assertFalse(
            {
                "selection_mode",
                "release_unit_id",
                "release_unit_hash",
                "migration_id",
                "release_evidence_chain",
                "issued_at",
                "served_at",
            }
            & set(incapability["properties"]),
            "immutable catalog identity must contain no release, migration, selection, evidence, or response metadata",
        )
        binding = self.registry.by_id[
            "https://jumpship.dev/contracts/client/customer-incapability-catalog-binding.schema.json"
        ]
        response = self.registry.by_id[
            "https://jumpship.dev/contracts/client/customer-incapability-catalog-response.schema.json"
        ]
        self.assertTrue({"release_unit_id", "catalog_hash", "source_registry_hash"}.issubset(binding["properties"]))
        self.assertTrue({"selection_mode", "migration_id", "release_evidence_chain", "catalog_binding", "catalog"}.issubset(response["properties"]))
        forbidden_paths = [path for path in (ROOT / "contracts").rglob("*") if "episode" in path.name or "iteration" in path.name]
        self.assertEqual(forbidden_paths, [])

    def test_provider_use_lease_duration_is_semantically_exact(self) -> None:
        schema = self.registry.by_id[
            "https://jumpship.dev/contracts/agent/provider-use-lease.schema.json"
        ]
        self.assertEqual(
            schema["x-jumpship-semantic-invariants"],
            [
                "expires_at_minus_issued_at_equals_ttl_seconds",
                "ttl_seconds_at_most_60",
            ],
        )

        def timestamp_nanos(value: object) -> int | None:
            if not isinstance(value, str):
                return None
            match = re.fullmatch(
                r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z",
                value,
            )
            if match is None:
                return None
            *parts, fraction = match.groups()
            try:
                instant = datetime(*(int(part) for part in parts), tzinfo=timezone.utc)
            except ValueError:
                return None
            seconds = int(instant.timestamp())
            return seconds * 1_000_000_000 + int((fraction or "").ljust(9, "0") or "0")

        def lease_is_valid(payload: dict[str, object]) -> bool:
            issued = timestamp_nanos(payload.get("issued_at"))
            expires = timestamp_nanos(payload.get("expires_at"))
            ttl = payload.get("ttl_seconds")
            return (
                issued is not None
                and expires is not None
                and isinstance(ttl, int)
                and not isinstance(ttl, bool)
                and 1 <= ttl <= 60
                and expires - issued == ttl * 1_000_000_000
            )

        valid_document = json.loads(
            (ROOT / "contracts/agent/fixtures/provider-control-valid.json").read_text()
        )
        lease_case = next(
            case
            for case in valid_document["cases"]
            if case["schema_path"] == "contracts/agent/provider-use-lease.schema.json"
        )
        self.assertTrue(lease_is_valid(lease_case["payload"]))

        invalid_document = json.loads(
            (ROOT / "contracts/agent/fixtures/provider-control-invalid.json").read_text()
        )
        semantic_cases = invalid_document["semantic_cases"]
        self.assertGreaterEqual(len(semantic_cases), 2)
        for case in semantic_cases:
            validate(case["payload"], schema, self.registry)
            self.assertFalse(lease_is_valid(case["payload"]), case["reason"])

    def test_customer_incapability_catalog_identity_and_order_are_executable(self) -> None:
        fixture = json.loads(
            (
                ROOT
                / "contracts/fixtures/client/valid-customer-incapability-catalog.json"
            ).read_text()
        )
        catalog = fixture["instance"]
        schema = self.registry.by_id[
            "https://jumpship.dev/contracts/client/customer-incapability-catalog.schema.json"
        ]
        validate(catalog, schema, self.registry)
        binding_fixture = json.loads(
            (
                ROOT
                / "contracts/fixtures/client/valid-customer-incapability-catalog-binding.json"
            ).read_text()
        )
        response_fixture = json.loads(
            (
                ROOT
                / "contracts/fixtures/client/valid-customer-incapability-catalog-response.json"
            ).read_text()
        )
        binding = binding_fixture["instance"]
        response = response_fixture["instance"]
        binding_schema = self.registry.by_id[
            "https://jumpship.dev/contracts/client/customer-incapability-catalog-binding.schema.json"
        ]
        response_schema = self.registry.by_id[
            "https://jumpship.dev/contracts/client/customer-incapability-catalog-response.schema.json"
        ]
        validate(binding, binding_schema, self.registry)
        validate(response, response_schema, self.registry)

        def semantic_check(instance: dict[str, object]) -> bool:
            projection = instance.get("logical_payload_projection")
            if not isinstance(projection, dict):
                return False
            excluded = projection.get("excluded_fields")
            if not isinstance(excluded, list) or not all(
                isinstance(field, str) for field in excluded
            ):
                return False
            logical = {
                key: value for key, value in instance.items() if key not in excluded
            }
            canonical = json.dumps(
                logical,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            domain = (
                f"jumpship:{projection.get('object_type')}:"
                f"{projection.get('object_schema_version')}\0"
            ).encode("utf-8")
            digest = hashlib.sha256(domain + canonical).hexdigest()
            id_field = projection.get("id_field")
            equivalent = projection.get("equivalent_digest_fields", [])
            if (
                not isinstance(id_field, str)
                or not isinstance(equivalent, list)
                or instance.get("logical_payload_sha256") != digest
                or instance.get(id_field) != digest
                or any(instance.get(field) != digest for field in equivalent)
            ):
                return False
            items = instance.get("items")
            if not isinstance(items, list):
                return False
            pairs = [
                (item.get("capability_id"), item.get("incapability_id"))
                for item in items
                if isinstance(item, dict)
            ]
            return len(pairs) == len(items) and pairs == sorted(pairs) and len(pairs) == len(set(pairs))

        self.assertTrue(semantic_check(catalog))
        self.assertEqual(response["catalog"], catalog)
        self.assertEqual(response["catalog_binding"], binding)
        response_metadata_changed = json.loads(json.dumps(response))
        response_metadata_changed["selection_mode"] = "pinned_cell_release_binding"
        response_metadata_changed["migration_id"] = "018f0f7e-7b8a-7abc-8def-0123456789ab"
        response_metadata_changed["release_evidence_chain"] = ["7" * 64]
        response_metadata_changed["served_at"] = "2026-07-19T00:00:00Z"
        validate(response_metadata_changed, response_schema, self.registry)
        self.assertEqual(response_metadata_changed["catalog"], catalog)
        self.assertTrue(semantic_check(response_metadata_changed["catalog"]))

        old_flat = json.loads(json.dumps(catalog))
        old_flat.update(
            {
                "schema_version": "1.0.0",
                "selection_mode": "new_admission_release",
                "release_unit_id": "2" * 64,
                "release_unit_hash": "2" * 64,
            }
        )
        with self.assertRaises(ValidationError):
            validate(old_flat, schema, self.registry)
        with self.assertRaises(ValidationError):
            validate(response, schema, self.registry)

        self.assertEqual(binding["release_unit_id"], binding["release_unit_hash"])
        self.assertEqual(binding["catalog_id"], catalog["catalog_id"])
        self.assertEqual(binding["catalog_hash"], catalog["catalog_hash"])
        self.assertEqual(binding["source_registry_hash"], catalog["source_registry_hash"])
        substituted_binding = json.loads(json.dumps(binding))
        substituted_binding["source_registry_hash"] = "8" * 64
        validate(substituted_binding, binding_schema, self.registry)
        self.assertNotEqual(
            substituted_binding["source_registry_hash"],
            catalog["source_registry_hash"],
            "cross-object equality is a registrar/verifier rule in addition to JSON Schema",
        )

        tampered = json.loads(json.dumps(catalog))
        tampered["items"][0]["safe_explanation"] = "Tampered while retaining the prior ID."
        validate(tampered, schema, self.registry)
        self.assertFalse(semantic_check(tampered), "held-ID content tamper must be denied")

        unsorted = json.loads(json.dumps(catalog))
        unsorted["items"].reverse()
        validate(unsorted, schema, self.registry)
        self.assertFalse(semantic_check(unsorted), "declared sort order must be enforced")

        duplicate_pair = json.loads(json.dumps(catalog))
        duplicate = json.loads(json.dumps(duplicate_pair["items"][0]))
        duplicate["safe_remediation"] = "A distinct explanation cannot disguise a duplicate key."
        duplicate_pair["items"].insert(1, duplicate)
        validate(duplicate_pair, schema, self.registry)
        self.assertFalse(semantic_check(duplicate_pair), "catalog keys must be unique")

    def test_data_classes_and_promotion_mode_witnesses_are_complete(self) -> None:
        observed_classes = {schema["x-jumpship-data-class"] for schema in self.schemas}
        self.assertEqual(observed_classes, set(DATA_CLASSES) - {"credential_secret"})
        api = json.loads((ROOT / "contracts/openapi/openapi.yaml").read_text())
        self.assertTrue(
            any(
                operation["x-jumpship-policy"]["data_class"] == "credential_secret"
                for path_item in api["paths"].values()
                for operation in path_item.values()
            )
        )
        for schema in self.schemas:
            self.assertTrue(schema["x-jumpship-flow-ids"], schema["$id"])
            self.assertNotIn("raw_payload", schema["properties"], schema["$id"])
            if schema["x-jumpship-data-class"] in {"public", "internal_operational"}:
                self.assertNotIn("credential_value", schema["properties"], schema["$id"])
                self.assertNotIn("private_key", schema["properties"], schema["$id"])

        event = self.registry.by_id["https://jumpship.dev/contracts/events/session-event.schema.json"]
        self.assertIs(event["properties"]["payload"]["additionalProperties"], False)
        estate = self.registry.by_id[
            "https://jumpship.dev/contracts/application/application-estate.schema.json"
        ]
        self.assertEqual(estate["x-jumpship-data-class"], "restricted_customer")
        safe_estate = self.registry.by_id[
            "https://jumpship.dev/contracts/application/application-estate-safe-projection.schema.json"
        ]
        self.assertEqual(safe_estate["x-jumpship-data-class"], "shared_migration")
        self.assertFalse(
            {"repositories", "data_access_sites", "writers", "path_hash", "content_hash"}
            & set(safe_estate["properties"])
        )
        self.assertFalse(
            {"source_code", "credential", "raw_provider_observation"} & set(estate["properties"])
        )
        estate_operation = api["paths"][
            "/v1/workspaces/{workspace_id}/migrations/{migration_id}/application-estate"
        ]["get"]
        estate_response_ref = estate_operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        component = api["components"]["schemas"][estate_response_ref.removeprefix("#/components/schemas/")]
        self.assertEqual(
            component["$ref"],
            "https://jumpship.dev/contracts/application/application-estate-safe-projection.schema.json",
        )

        valid = json.loads(
            (ROOT / "contracts/quality/fixtures/promotion-modes-valid.json").read_text()
        )
        shapes = {
            (case["payload"]["kind"], case["payload"]["mode"], case["payload"]["evidence_class"])
            for case in valid["cases"]
        }
        self.assertTrue(
            {
                ("activate", "ordinary", "release"),
                ("rollback", "ordinary", "release"),
                ("rollback", "ordinary_rollback_takeover", "release"),
                ("activate", "genesis", "release"),
                ("activate", "bootstrap_recovery", "release"),
                ("activate", "emergency_recovery", "release"),
                ("emergency_stop", "emergency_stop_current_active_not_serving", "release"),
                ("emergency_stop", "emergency_stop_supported", "release"),
                ("activate", "ordinary", "boundary_fixture"),
            }.issubset(shapes)
        )
        invalid = json.loads(
            (ROOT / "contracts/quality/fixtures/promotion-modes-invalid.json").read_text()
        )
        self.assertGreaterEqual(len(invalid["cases"]), 10)

    def test_closed_deployment_profiles(self) -> None:
        profiles = json.loads((ROOT / "contracts/release/deployment-profiles.yaml").read_text())
        self.assertEqual(
            [profile["profile_id"] for profile in profiles["profiles"]],
            ["local", "ephemeral-nonprod", "persistent-nonprod", "paid-production"],
        )
        self.assertEqual(profiles["default_profile_id"], "ephemeral-nonprod")
        self.assertEqual(
            [profile["profile_id"] for profile in profiles["profiles"] if profile["implementation_default"]],
            ["ephemeral-nonprod"],
        )
        privileged = [
            profile["profile_id"]
            for profile in profiles["profiles"]
            if profile["allows_customer_cells"] or profile["allows_cutover"]
        ]
        self.assertEqual(privileged, ["paid-production"])
        paid = profiles["profiles"][-1]
        self.assertEqual(paid["data_eligibility"], "customer_data")
        self.assertTrue(paid["requires_ha_recovery_support"])

        profile_schema = self.registry.by_id[
            "https://jumpship.dev/contracts/release/deployment-profile.schema.json"
        ]
        branches = profile_schema["oneOf"]
        self.assertEqual(
            [branch["properties"]["profile_id"]["const"] for branch in branches],
            ["local", "ephemeral-nonprod", "persistent-nonprod", "paid-production"],
        )

        corpus = json.loads((ROOT / "contracts/fixtures/schema-corpus.json").read_text())
        by_path = {record["schema_path"]: record for record in corpus["records"]}
        for path in (
            "contracts/release/deployment-readiness-receipt.schema.json",
            "contracts/release/cost-baseline.schema.json",
        ):
            record = by_path[path]
            schema = json.loads((ROOT / path).read_text())
            witness = {**record["valid"], "environment": "production", "stage": "production", "deployment_profile_id": "local"}
            with self.assertRaises(ValidationError, msg=path):
                validate(witness, schema, self.registry)

    def test_rubric_ownership_is_exact_and_provider_chain_is_complete(self) -> None:
        ownership = json.loads((ROOT / "contracts/release/mvp-rubric-ownership.yaml").read_text())
        identifiers = [record["rubric_id"] for record in ownership["records"]]
        self.assertEqual(identifiers, [f"JSMVP-R{number:03d}" for number in range(1, 83)])
        self.assertEqual(len(identifiers), len(set(identifiers)))
        required_provider = {
            "provider-data-use.schema.json",
            "provider-data-use-review.schema.json",
            "provider-data-use-status.schema.json",
            "provider-evidence-transition.schema.json",
            "provider-evidence-journal-checkpoint.schema.json",
            "provider-route-hold.schema.json",
            "provider-use-lease.schema.json",
            "provider-review-delivery.schema.json",
        }
        actual = {path.name for path in (ROOT / "contracts/agent").glob("provider*.schema.json")}
        self.assertTrue(required_provider.issubset(actual))

        bundle = self.registry.by_id[
            "https://jumpship.dev/contracts/agent/agent-bundle.schema.json"
        ]
        components = bundle["properties"]["components"]
        component_kinds = set(components["items"]["properties"]["kind"]["enum"])
        required_component_kinds = {
            branch["properties"]["components"]["contains"]["properties"]["kind"]["const"]
            for branch in bundle["allOf"]
        }
        self.assertEqual(required_component_kinds, component_kinds)
        self.assertEqual(components["minItems"], len(component_kinds))
        self.assertEqual(components["maxItems"], len(component_kinds))

        release_unit = self.registry.by_id[
            "https://jumpship.dev/contracts/release/release-unit.schema.json"
        ]
        release_branch = next(
            branch
            for branch in release_unit["oneOf"]
            if branch["properties"]["evidence_class"]["const"] == "release"
        )
        boundary_branch = next(
            branch
            for branch in release_unit["oneOf"]
            if branch["properties"]["evidence_class"]["const"] == "boundary_fixture"
        )
        self.assertEqual(release_branch["properties"]["environment_scope"]["const"], ["staging", "production"])
        self.assertIs(release_branch["properties"]["synthetic"]["const"], False)
        self.assertEqual(boundary_branch["properties"]["environment_scope"]["const"], ["isolated-quality"])
        self.assertIs(boundary_branch["properties"]["synthetic"]["const"], True)
        release_kinds = {
            rule["contains"]["properties"]["kind"]["const"]
            for rule in release_branch["properties"]["members"]["allOf"]
        }
        self.assertTrue(
            {
                "source",
                "source_plan",
                "capability_registry",
                "contract",
                "generated_client",
                "runtime_image",
                "ami",
                "web_deployment",
                "auth_config",
                "composition_gate",
                "agent_bundle",
                "provider_data_use_record",
                "qualification_record",
                "cli",
                "skill",
                "proof_verifier",
                "infrastructure_module",
                "infrastructure_provider_lock",
                "signer_policy",
                "trust_anchor",
                "crl_profile",
                "customer_incapability_catalog",
                "rubric_ownership",
            }.issubset(release_kinds)
        )

    def test_generated_client_surfaces_exist(self) -> None:
        required = [
            "internal/contracts/api/openapi.gen.go",
            "internal/contracts/cell/v1/cell.types.gen.go",
            "internal/contracts/cell/v1/cell.connect.gen.go",
            "internal/contracts/cell/v1/cell.connect.gen_test.go",
            "internal/contracts/generated/types.gen.go",
            "internal/contracts/quality/sanitizedtrajectory/types.gen.go",
            "web/src/lib/api/generated/openapi.gen.ts",
            "web/src/lib/api/generated/contracts.gen.ts",
            "web/src/lib/api/generated/canonical.gen.ts",
        ]
        for relative in required:
            self.assertTrue((ROOT / relative).is_file(), relative)

        inventory = json.loads((ROOT / "contracts/generated-type-inventory.json").read_text())
        generated_names = {record["type"] for record in inventory["types"]}
        handwritten_go_names: set[str] = set()
        for path in (ROOT / "internal/contracts").rglob("*.go"):
            if path.name.endswith(".gen.go"):
                continue
            handwritten_go_names.update(
                re.findall(r"(?m)^type\s+([A-Za-z][A-Za-z0-9]*)\s+struct\s*\{", path.read_text())
            )
        self.assertFalse(generated_names & handwritten_go_names)

        generated_go = (ROOT / "internal/contracts/generated/types.gen.go").read_text()
        generated_ts = (ROOT / "web/src/lib/api/generated/contracts.gen.ts").read_text()
        self.assertNotIn("map[string]any", generated_go)
        self.assertNotIn("Readonly<Record<string, unknown>>", generated_ts)
        cell_types = (ROOT / "internal/contracts/cell/v1/cell.types.gen.go").read_text()
        self.assertIn("protobuf:\"", cell_types)
        self.assertIn("HasValidFrame", cell_types)
        self.assertIn('json:"workspaceId,omitempty"', cell_types)
        self.assertNotIn('json:"workspace_id,omitempty"', cell_types)
        self.assertIn("contains unknown field", cell_types)
        self.assertIn("requires exactly one non-null variant", cell_types)
        cell_client = (ROOT / "internal/contracts/cell/v1/cell.connect.gen.go").read_text()
        self.assertIn("type SupervisorControlClient interface", cell_client)
        self.assertIn("type CellCertificateRecoveryClient interface", cell_client)
        self.assertIn("NewSupervisorControlClient", cell_client)
        self.assertIn("NewCellCertificateRecoveryClient", cell_client)
        self.assertIn(
            '"/jumpship.cell.v1.SupervisorControl/Connect"', cell_client
        )
        self.assertIn(
            '"/jumpship.cell.v1.CellCertificateRecovery/Renew"', cell_client
        )
        self.assertIn('connectStreamContentType = "application/connect+json"', cell_client)
        self.assertIn("binary.BigEndian.PutUint32", cell_client)
        self.assertIn("connectFlagEndStream", cell_client)
        self.assertIn("Connect-Protocol-Version", cell_client)
        self.assertIn("func (message SupervisorFrame) MarshalJSON", cell_types)
        self.assertIn("func (message *SupervisorFrame) UnmarshalJSON", cell_types)
        cell_transport_tests = (
            ROOT / "internal/contracts/cell/v1/cell.connect.gen_test.go"
        ).read_text()
        self.assertIn("httptest.NewRequest", cell_transport_tests)
        self.assertIn("handlerRoundTripper", cell_transport_tests)
        self.assertNotIn("httptest.NewServer", cell_transport_tests)
        self.assertIn("TestCellCertificateRecoveryConnectUnaryTransport", cell_transport_tests)
        self.assertIn("TestSupervisorControlConnectBidiTransport", cell_transport_tests)

        openapi_go = (ROOT / "internal/contracts/api/openapi.gen.go").read_text()
        self.assertRegex(openapi_go, r"\bRequestMediaType\s+string\b")
        self.assertRegex(openapi_go, r"\bForm\s+url\.Values\b")
        self.assertIn('case "application/x-www-form-urlencoded":', openapi_go)
        self.assertIn("http.ErrUseLastResponse", openapi_go)
        form_operation_constants = {
            "completeIdentityOAuth": "CompleteIdentityOAuth",
            "prepareIdentityOAuthCallback": "PrepareIdentityOAuthCallback",
            "completeConnectorOAuth": "CompleteConnectorOAuth",
            "prepareConnectorOAuthCallback": "PrepareConnectorOAuthCallback",
        }
        for operation_id, constant_name in form_operation_constants.items():
            operation_line = next(
                (
                    line
                    for line in openapi_go.splitlines()
                    if line.lstrip().startswith(f"Operation{constant_name}:")
                ),
                "",
            )
            self.assertIn(
                'RequestMediaType: "application/x-www-form-urlencoded"',
                operation_line,
                operation_id,
            )

        openapi_ts = (ROOT / "web/src/lib/api/generated/openapi.gen.ts").read_text()
        for operation_id in form_operation_constants:
            self.assertNotIn(f'"{operation_id}"', openapi_ts)


if __name__ == "__main__":
    unittest.main()
