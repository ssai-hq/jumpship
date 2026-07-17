"""P02 core, cryptographic, workflow, cell, and engine contracts.

The declarations in this module are deliberately transport-only.  They freeze
the shared representation, bounds, and legal state edges without importing or
embedding domain policy.  Every object is closed and bounded so none of these
contracts can become an untyped data tunnel across the cell diode.
"""

from __future__ import annotations

from typing import Any

from model import (
    Artifact,
    DATA_CLASSES,
    HASH_PATTERN,
    SCHEMA_VERSION,
    SEMVER_PATTERN,
    UUID_PATTERN,
    common_identity_properties,
    hash_field,
    json_artifact,
    nullable,
    s_array,
    s_boolean,
    s_integer,
    s_number,
    s_object,
    s_string,
    schema,
    text_artifact,
    timestamp_field,
)


_BASE64_PATTERN = (
    r"^(?:[A-Za-z0-9+/]{4})*"
    r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)
_SAFE_NAME_PATTERN = r"^[a-z][a-z0-9_.-]{0,127}$"
_OPERATION_ID_PATTERN = r"^[a-z][A-Za-z0-9_.-]{0,127}$"
_SAFE_REASON_PATTERN = r"^[a-z][a-z0-9_.-]{0,95}$"
_AWS_REGION_PATTERN = r"^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$"
_SERIAL_PATTERN = r"^(?:0[1-9a-f]|[1-9a-f])[0-9a-f]{0,39}$"
_SPIFFE_CELL_PATTERN = (
    r"^spiffe://jumpship/cells/[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}/generations/[1-9][0-9]*$"
)


def _id() -> dict[str, Any]:
    return s_string(pattern=UUID_PATTERN)


def _hashes(*, min_items: int = 0, max_items: int = 64) -> dict[str, Any]:
    return s_array(hash_field(), min_items=min_items, max_items=max_items, unique=True)


def _safe_names(*, min_items: int = 0, max_items: int = 64) -> dict[str, Any]:
    return s_array(
        s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
        min_items=min_items,
        max_items=max_items,
        unique=True,
    )


def _nullable_id() -> dict[str, Any]:
    return nullable(_id())


def _nullable_hash() -> dict[str, Any]:
    return nullable(hash_field())


def _nullable_timestamp() -> dict[str, Any]:
    return nullable(timestamp_field())


def _identity_required(*, include_operation: bool = False) -> list[str]:
    result = [
        "workspace_id",
        "migration_id",
        "cell_id",
        "cell_generation",
        "causation_id",
        "correlation_id",
    ]
    if include_operation:
        result.append("operation_id")
    return result


def _signature_envelope_schema() -> dict[str, Any]:
    return schema(
        "crypto/signature-envelope.schema.json",
        "Signature Envelope",
        {
            "envelope_id": hash_field(),
            "object_type": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "object_schema_id": s_string(
                pattern=r"^https://jumpship\.dev/contracts/[A-Za-z0-9_./-]+\.schema\.json$",
                max_length=512,
            ),
            "object_schema_version": s_string(pattern=SEMVER_PATTERN, max_length=64),
            "payload_digest": hash_field(),
            "purpose": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "environment": s_string(
                enum=(
                    "local",
                    "ephemeral-nonprod",
                    "persistent-nonprod",
                    "isolated-quality",
                    "staging",
                    "production",
                )
            ),
            "tenant_scope": nullable(_id()),
            "migration_scope": nullable(_id()),
            "kid": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "algorithm": s_string(
                enum=("ECDSA_P256_SHA256", "RSA_PSS_SHA256")
            ),
            "signer_id": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "signer_role": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "issued_at": timestamp_field(),
            "expires_at": _nullable_timestamp(),
            "key_registry_id": hash_field(),
            "key_registry_hash": hash_field(),
            "signature_base64": s_string(
                pattern=_BASE64_PATTERN,
                min_length=8,
                max_length=8192,
                description="Detached signature bytes; excluded from the signed claims.",
            ),
        },
        (
            "envelope_id",
            "object_type",
            "object_schema_id",
            "object_schema_version",
            "payload_digest",
            "purpose",
            "environment",
            "tenant_scope",
            "migration_scope",
            "kid",
            "algorithm",
            "signer_id",
            "signer_role",
            "issued_at",
            "expires_at",
            "key_registry_id",
            "key_registry_hash",
            "signature_base64",
        ),
        data_class="public",
        max_bytes=16384,
        flow_ids=("F06", "F17", "F20", "F21"),
        description=(
            "Purpose-scoped detached signature over typed canonical claims. The logical "
            "payload, derived object identity, and this envelope are separate objects."
        ),
    )


def _public_key_registry_schema() -> dict[str, Any]:
    key_entry = s_object(
        {
            "kid": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "algorithm": s_string(enum=("ECDSA_P256_SHA256", "RSA_PSS_SHA256")),
            "public_key_pem": s_string(
                pattern=r"^-----BEGIN PUBLIC KEY-----[A-Za-z0-9+/=\r\n-]+-----END PUBLIC KEY-----$",
                min_length=128,
                max_length=8192,
            ),
            "purposes": _safe_names(min_items=1, max_items=32),
            "environments": s_array(
                s_string(
                    enum=(
                        "local",
                        "ephemeral-nonprod",
                        "persistent-nonprod",
                        "isolated-quality",
                        "staging",
                        "production",
                    )
                ),
                min_items=1,
                max_items=6,
                unique=True,
            ),
            "tenant_scope": nullable(_id()),
            "valid_from": timestamp_field(),
            "valid_until": timestamp_field(),
            "status": s_string(enum=("active", "superseded", "revoked")),
            "supersedes_kid": nullable(s_string(pattern=_SAFE_NAME_PATTERN, max_length=128)),
            "revoked_at": _nullable_timestamp(),
            "revocation_reason": nullable(
                s_string(pattern=_SAFE_REASON_PATTERN, max_length=96)
            ),
        },
        (
            "kid",
            "algorithm",
            "public_key_pem",
            "purposes",
            "environments",
            "tenant_scope",
            "valid_from",
            "valid_until",
            "status",
            "supersedes_kid",
            "revoked_at",
            "revocation_reason",
        ),
    )
    key_entry["allOf"] = [
        {
            "if": {
                "required": ["status"],
                "properties": {"status": {"const": "revoked"}},
            },
            "then": {
                "properties": {
                    "revoked_at": timestamp_field(),
                    "revocation_reason": s_string(
                        pattern=_SAFE_REASON_PATTERN, max_length=96
                    ),
                }
            },
            "else": {
                "properties": {
                    "revoked_at": {"type": "null"},
                    "revocation_reason": {"type": "null"},
                }
            },
        }
    ]
    return schema(
        "crypto/public-key-registry.schema.json",
        "Public Key Registry",
        {
            "registry_id": hash_field(),
            "registry_version": s_integer(minimum=1),
            "previous_registry_hash": _nullable_hash(),
            "root_fingerprint": hash_field(),
            "purpose_policy_hash": hash_field(),
            "issued_at": timestamp_field(),
            "keys": s_array(key_entry, min_items=1, max_items=256),
        },
        (
            "registry_id",
            "registry_version",
            "previous_registry_hash",
            "root_fingerprint",
            "purpose_policy_hash",
            "issued_at",
            "keys",
        ),
        data_class="public",
        max_bytes=1_048_576,
        flow_ids=("F06", "F17"),
        description=(
            "Monotonic purpose/environment/tenant-scoped public-key registry. It contains "
            "no private material and is the sole Jumpship trust-bundle input to offline verification."
        ),
        all_of=[
            {
                "if": {
                    "required": ["registry_version"],
                    "properties": {"registry_version": {"const": 1}},
                },
                "then": {
                    "properties": {"previous_registry_hash": {"type": "null"}}
                },
                "else": {
                    "properties": {
                        "previous_registry_hash": hash_field()
                    }
                },
            }
        ],
    )


def _audit_checkpoint_schema() -> dict[str, Any]:
    return schema(
        "audit/checkpoint.schema.json",
        "Audit Checkpoint",
        {
            "checkpoint_id": hash_field(),
            "previous_checkpoint_hash": _nullable_hash(),
            "export_request_id": _id(),
            "interval_started_at": timestamp_field(),
            "interval_ended_at": timestamp_field(),
            "event_count": s_integer(minimum=0, maximum=10_000_000),
            "redacted_export_root": hash_field(),
            "export_schema_hash": hash_field(),
            "source_high_watermark": s_string(min_length=1, max_length=256),
            "created_at": timestamp_field(),
        },
        (
            "checkpoint_id",
            "previous_checkpoint_hash",
            "export_request_id",
            "interval_started_at",
            "interval_ended_at",
            "event_count",
            "redacted_export_root",
            "export_schema_hash",
            "source_high_watermark",
            "created_at",
        ),
        data_class="internal_operational",
        max_bytes=16384,
        flow_ids=("F03", "F17"),
        description=(
            "Canonical unsigned audit-checkpoint candidate. Only the offline audit root may "
            "attach a detached purpose=audit_checkpoint SignatureEnvelope."
        ),
    )


def _mapping_spec_schema() -> dict[str, Any]:
    mapping_rule = s_object(
        {
            "source_path": s_string(min_length=1, max_length=512),
            "target_relation": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "target_column": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "transform_id": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "nullable": s_boolean(),
            "on_missing": s_string(enum=("reject", "quarantine", "typed_default")),
            "evidence_root": hash_field(),
        },
        (
            "source_path",
            "target_relation",
            "target_column",
            "transform_id",
            "nullable",
            "on_missing",
            "evidence_root",
        ),
    )
    return schema(
        "mapping/mapping-spec.schema.json",
        "Mapping Specification",
        {
            "mapping_spec_id": hash_field(),
            "parent_mapping_spec_hash": _nullable_hash(),
            "status": s_string(enum=("draft", "confirmed", "superseded")),
            "corridor_profile_id": hash_field(),
            "corridor_profile_hash": hash_field(),
            "planning_horizon_months": s_integer(minimum=1, maximum=120),
            "target_model_version": s_integer(minimum=1),
            "target_model_hash": hash_field(),
            "decision_ledger_version": s_integer(minimum=1),
            "decision_ledger_hash": hash_field(),
            "compiler_version": s_string(pattern=SEMVER_PATTERN, max_length=64),
            "domain_ownership_refs": _hashes(min_items=1),
            "business_invariant_refs": _hashes(min_items=1),
            "lifecycle_history_refs": _hashes(),
            "tenancy_security_retention_refs": _hashes(min_items=1),
            "workload_index_rationale_refs": _hashes(min_items=1),
            "assumption_refs": _hashes(),
            "unknown_refs": _hashes(),
            "rejected_alternative_refs": _hashes(),
            "intentional_debt_refs": _hashes(),
            "evolution_trigger_refs": _hashes(),
            "source_evidence_roots": _hashes(min_items=1),
            "field_mappings": s_array(mapping_rule, min_items=1, max_items=4096),
            "created_at": timestamp_field(),
        },
        (
            "mapping_spec_id",
            "parent_mapping_spec_hash",
            "status",
            "corridor_profile_id",
            "corridor_profile_hash",
            "planning_horizon_months",
            "target_model_version",
            "target_model_hash",
            "decision_ledger_version",
            "decision_ledger_hash",
            "compiler_version",
            "domain_ownership_refs",
            "business_invariant_refs",
            "lifecycle_history_refs",
            "tenancy_security_retention_refs",
            "workload_index_rationale_refs",
            "assumption_refs",
            "unknown_refs",
            "rejected_alternative_refs",
            "intentional_debt_refs",
            "evolution_trigger_refs",
            "source_evidence_roots",
            "field_mappings",
            "created_at",
        ),
        data_class="shared_migration",
        max_bytes=2_097_152,
        flow_ids=("F02", "F03", "F06", "F10"),
        description=(
            "Immutable, evidence-linked MongoDB-to-PostgreSQL semantic mapping. Field paths "
            "are shared-safe; examples and customer values are prohibited."
        ),
    )


def _verification_rubric_schema() -> dict[str, Any]:
    check = s_object(
        {
            "check_id": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "layer": s_string(
                enum=(
                    "counts",
                    "business_invariants",
                    "canonical_hash",
                    "reverse_difference",
                    "query_semantics",
                )
            ),
            "expectation_kind": s_string(
                enum=("exact_hash", "exact_count", "boolean", "bounded_numeric", "zero_unexplained")
            ),
            "expected_hash": _nullable_hash(),
            "expected_count": nullable(s_integer(minimum=0)),
            "minimum": nullable(s_number()),
            "maximum": nullable(s_number()),
            "blocking": s_boolean(),
            "evidence_roots": _hashes(min_items=1, max_items=16),
        },
        (
            "check_id",
            "layer",
            "expectation_kind",
            "expected_hash",
            "expected_count",
            "minimum",
            "maximum",
            "blocking",
            "evidence_roots",
        ),
    )
    return schema(
        "verification/verification-rubric.schema.json",
        "Verification Rubric",
        {
            "verification_rubric_id": hash_field(),
            "version": s_integer(minimum=1),
            "status": s_string(enum=("draft", "confirmed", "superseded")),
            "mapping_spec_id": hash_field(),
            "mapping_spec_hash": hash_field(),
            "confirmed_by": nullable(_id()),
            "confirmed_at": _nullable_timestamp(),
            "checks": s_array(check, min_items=1, max_items=1024),
        },
        (
            "verification_rubric_id",
            "version",
            "status",
            "mapping_spec_id",
            "mapping_spec_hash",
            "confirmed_by",
            "confirmed_at",
            "checks",
        ),
        data_class="shared_migration",
        max_bytes=1_048_576,
        flow_ids=("F02", "F03", "F06"),
        description="Immutable pre-registered verification expectations; customer values are forbidden.",
    )


def _attempt_schema() -> dict[str, Any]:
    metric = s_object(
        {
            "name": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "unit": s_string(pattern=_SAFE_NAME_PATTERN, max_length=64),
            "value": s_number(),
        },
        ("name", "unit", "value"),
    )
    return schema(
        "workflow/attempt.schema.json",
        "Attempt",
        {
            **common_identity_properties(include_operation=True),
            "attempt_id": _id(),
            "attempt_kind": s_string(
                enum=(
                    "snapshot",
                    "snapshot_restore",
                    "golden_self_proof",
                    "rehearsal",
                    "bulk_load",
                    "verification",
                    "rollback_rehearsal",
                    "cutover",
                )
            ),
            "ordinal": s_integer(minimum=1),
            "parent_attempt_id": _nullable_id(),
            "retry_of_attempt_id": _nullable_id(),
            "state": s_string(
                enum=(
                    "declared",
                    "queued",
                    "running",
                    "waiting",
                    "succeeded",
                    "failed_recoverable",
                    "failed_terminal",
                    "canceled",
                )
            ),
            "concurrency_class": s_string(enum=("read_only", "resource_mutating")),
            "spec_version": s_integer(minimum=1),
            "spec_hash": hash_field(),
            "rubric_version": s_integer(minimum=1),
            "rubric_hash": hash_field(),
            "build_hash": hash_field(),
            "agent_bundle_id": hash_field(),
            "cell_write_epoch": s_integer(minimum=0),
            "started_at": _nullable_timestamp(),
            "finished_at": _nullable_timestamp(),
            "wait_kind": nullable(
                s_string(enum=("human", "provider", "timer", "resource", "none"))
            ),
            "wait_deadline": _nullable_timestamp(),
            "final_reason_code": nullable(
                s_string(pattern=_SAFE_REASON_PATTERN, max_length=96)
            ),
            "final_safe_summary": nullable(s_string(max_length=2048)),
            "final_artifact_roots": _hashes(max_items=64),
            "final_metrics": s_array(metric, max_items=128),
        },
        (
            *_identity_required(include_operation=True),
            "attempt_id",
            "attempt_kind",
            "ordinal",
            "parent_attempt_id",
            "retry_of_attempt_id",
            "state",
            "concurrency_class",
            "spec_version",
            "spec_hash",
            "rubric_version",
            "rubric_hash",
            "build_hash",
            "agent_bundle_id",
            "cell_write_epoch",
            "started_at",
            "finished_at",
            "wait_kind",
            "wait_deadline",
            "final_reason_code",
            "final_safe_summary",
            "final_artifact_roots",
            "final_metrics",
        ),
        data_class="shared_migration",
        max_bytes=131072,
        flow_ids=("F02", "F03", "F06", "F17"),
        description=(
            "Append-only attempt record. Retry always creates a new attempt identity; "
            "active, waiting, and terminal states have structurally distinct timing and result fields."
        ),
        all_of=[
            {
                "if": {
                    "properties": {"state": {"enum": ["declared", "queued"]}}
                },
                "then": {
                    "properties": {
                        "started_at": {"type": "null"},
                        "finished_at": {"type": "null"},
                        "wait_kind": {"anyOf": [{"type": "null"}, {"const": "none"}]},
                        "wait_deadline": {"type": "null"},
                        "final_reason_code": {"type": "null"},
                        "final_safe_summary": {"type": "null"},
                        "final_artifact_roots": {"maxItems": 0},
                        "final_metrics": {"maxItems": 0},
                    }
                },
            },
            {
                "if": {"properties": {"state": {"const": "running"}}},
                "then": {
                    "properties": {
                        "started_at": timestamp_field(),
                        "finished_at": {"type": "null"},
                        "wait_kind": {"anyOf": [{"type": "null"}, {"const": "none"}]},
                        "wait_deadline": {"type": "null"},
                        "final_reason_code": {"type": "null"},
                        "final_safe_summary": {"type": "null"},
                    }
                },
            },
            {
                "if": {"properties": {"state": {"const": "waiting"}}},
                "then": {
                    "properties": {
                        "started_at": timestamp_field(),
                        "finished_at": {"type": "null"},
                        "wait_kind": {
                            "type": "string",
                            "enum": ["human", "provider", "timer", "resource"],
                        },
                        "wait_deadline": timestamp_field(),
                        "final_reason_code": {"type": "null"},
                        "final_safe_summary": {"type": "null"},
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "state": {
                            "enum": [
                                "succeeded",
                                "failed_recoverable",
                                "failed_terminal",
                                "canceled",
                            ]
                        }
                    }
                },
                "then": {
                    "properties": {
                        "started_at": timestamp_field(),
                        "finished_at": timestamp_field(),
                        "wait_kind": {"anyOf": [{"type": "null"}, {"const": "none"}]},
                        "wait_deadline": {"type": "null"},
                        "final_reason_code": s_string(
                            pattern=_SAFE_REASON_PATTERN, max_length=96
                        ),
                        "final_safe_summary": s_string(min_length=1, max_length=2048),
                    }
                },
            },
            {
                "if": {"not": {"properties": {"retry_of_attempt_id": {"type": "null"}}}},
                "then": {"properties": {"ordinal": {"minimum": 2}}},
            },
        ],
    )


def _reversibility_schema() -> dict[str, Any]:
    classes = (
        "free_until_cutover",
        "expensive_after_cutover",
        "closes_on_first_external_exposure",
        "closes_on_a_clock",
        "never_reversible",
    )
    return schema(
        "decisions/reversibility.schema.json",
        "Reversibility Record",
        {
            "reversibility_id": hash_field(),
            "decision_key": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "decision_version": s_integer(minimum=1),
            "reversibility_class": s_string(enum=classes),
            "state": s_string(enum=("proposed", "open", "warning", "closed", "superseded")),
            "closure_predicate": s_string(
                enum=(
                    "successful_traffic_flip",
                    "priced_rehearsed_operation",
                    "first_external_exposure",
                    "backend_deadline",
                    "first_effect",
                )
            ),
            "closes_at": _nullable_timestamp(),
            "clock_source": s_string(enum=("backend_utc", "provider_receipt", "not_applicable")),
            "warning_required": s_boolean(),
            "warning_threshold_seconds": s_array(
                s_integer(minimum=1, maximum=31_536_000),
                max_items=16,
                unique=True,
            ),
            "safe_failure": s_string(
                enum=("block_effect", "retain_current_authority", "escalate_human", "refuse_unknown")
            ),
            "required_operation_id": nullable(
                s_string(pattern=_OPERATION_ID_PATTERN, max_length=128)
            ),
            "cost_estimate_minor_units": nullable(s_integer(minimum=0)),
            "cost_currency": nullable(s_string(pattern=r"^[A-Z]{3}$", max_length=3)),
            "viability_evidence_roots": _hashes(max_items=32),
            "exposure_subject_hash": _nullable_hash(),
            "closed_by_receipt_hash": _nullable_hash(),
            "superseded_by": _nullable_hash(),
        },
        (
            "reversibility_id",
            "decision_key",
            "decision_version",
            "reversibility_class",
            "state",
            "closure_predicate",
            "closes_at",
            "clock_source",
            "warning_required",
            "warning_threshold_seconds",
            "safe_failure",
            "required_operation_id",
            "cost_estimate_minor_units",
            "cost_currency",
            "viability_evidence_roots",
            "exposure_subject_hash",
            "closed_by_receipt_hash",
            "superseded_by",
        ),
        data_class="shared_migration",
        max_bytes=32768,
        flow_ids=("F02", "F03", "F06", "F16", "F17"),
        description=(
            "Five-class reversibility taxonomy with authoritative closure, warning, evidence, "
            "cost, and safe-failure fields. Closed records never reopen."
        ),
        all_of=[
            {
                "oneOf": [
                    {
                        "properties": {
                            "reversibility_class": {"const": "free_until_cutover"},
                            "closure_predicate": {"const": "successful_traffic_flip"},
                            "closes_at": {"type": "null"},
                            "clock_source": {"const": "provider_receipt"},
                            "warning_required": {"const": True},
                            "warning_threshold_seconds": {"minItems": 1},
                            "required_operation_id": s_string(
                                pattern=_OPERATION_ID_PATTERN, max_length=128
                            ),
                            "cost_estimate_minor_units": {"type": "null"},
                            "cost_currency": {"type": "null"},
                            "exposure_subject_hash": {"type": "null"},
                        }
                    },
                    {
                        "properties": {
                            "reversibility_class": {"const": "expensive_after_cutover"},
                            "closure_predicate": {"const": "priced_rehearsed_operation"},
                            "closes_at": {"type": "null"},
                            "clock_source": {"const": "not_applicable"},
                            "warning_required": {"const": True},
                            "warning_threshold_seconds": {"minItems": 1},
                            "required_operation_id": s_string(
                                pattern=_OPERATION_ID_PATTERN, max_length=128
                            ),
                            "cost_estimate_minor_units": s_integer(minimum=0),
                            "cost_currency": s_string(pattern=r"^[A-Z]{3}$", max_length=3),
                            "viability_evidence_roots": {"minItems": 1},
                            "exposure_subject_hash": {"type": "null"},
                        }
                    },
                    {
                        "properties": {
                            "reversibility_class": {
                                "const": "closes_on_first_external_exposure"
                            },
                            "closure_predicate": {"const": "first_external_exposure"},
                            "closes_at": {"type": "null"},
                            "clock_source": {"const": "provider_receipt"},
                            "warning_required": {"const": True},
                            "warning_threshold_seconds": {"minItems": 1},
                            "required_operation_id": s_string(
                                pattern=_OPERATION_ID_PATTERN, max_length=128
                            ),
                            "cost_estimate_minor_units": {"type": "null"},
                            "cost_currency": {"type": "null"},
                            "exposure_subject_hash": hash_field(),
                        }
                    },
                    {
                        "properties": {
                            "reversibility_class": {"const": "closes_on_a_clock"},
                            "closure_predicate": {"const": "backend_deadline"},
                            "closes_at": timestamp_field(),
                            "clock_source": {"const": "backend_utc"},
                            "warning_required": {"const": True},
                            "warning_threshold_seconds": {"minItems": 1},
                            "required_operation_id": s_string(
                                pattern=_OPERATION_ID_PATTERN, max_length=128
                            ),
                            "cost_estimate_minor_units": {"type": "null"},
                            "cost_currency": {"type": "null"},
                            "exposure_subject_hash": {"type": "null"},
                        }
                    },
                    {
                        "properties": {
                            "reversibility_class": {"const": "never_reversible"},
                            "closure_predicate": {"const": "first_effect"},
                            "closes_at": {"type": "null"},
                            "clock_source": {"const": "provider_receipt"},
                            "warning_required": {"const": True},
                            "warning_threshold_seconds": {"minItems": 1},
                            "safe_failure": {
                                "enum": ["block_effect", "refuse_unknown"]
                            },
                            "required_operation_id": s_string(
                                pattern=_OPERATION_ID_PATTERN, max_length=128
                            ),
                            "cost_estimate_minor_units": {"type": "null"},
                            "cost_currency": {"type": "null"},
                            "exposure_subject_hash": {"type": "null"},
                        }
                    },
                ]
            },
            {
                "if": {"properties": {"state": {"const": "closed"}}},
                "then": {
                    "properties": {
                        "closed_by_receipt_hash": hash_field(),
                        "superseded_by": {"type": "null"},
                    }
                },
                "else": {
                    "if": {"properties": {"state": {"const": "superseded"}}},
                    "then": {"properties": {"superseded_by": hash_field()}},
                    "else": {
                        "properties": {
                            "closed_by_receipt_hash": {"type": "null"},
                            "superseded_by": {"type": "null"},
                        }
                    },
                },
            },
            {
                "if": {"properties": {"state": {"const": "warning"}}},
                "then": {"properties": {"warning_required": {"const": True}}},
            },
        ],
    )


def _corridor_profile_schema() -> dict[str, Any]:
    source_profile = s_object(
        {
            "provider": s_string(enum=("mongodb_atlas", "self_managed_mongodb")),
            "topology": s_string(enum=("replica_set", "sharded_cluster", "standalone")),
            "server_version": s_string(pattern=r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$", max_length=32),
            "region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "network_rung": s_string(enum=("private_endpoint", "peering", "public_tls")),
            "snapshot_rung": s_string(
                enum=("provider_export", "secondary_dump_oplog", "freeze_only")
            ),
            "cdc_mode": s_string(
                enum=("change_stream_pre_post_images", "change_stream_lookup", "freeze_only")
            ),
            "cdc_supported": s_boolean(),
            "pre_post_images_supported": s_boolean(),
            "read_only_privilege_proof_hash": hash_field(),
            "probe_hash": hash_field(),
        },
        (
            "provider",
            "topology",
            "server_version",
            "region",
            "network_rung",
            "snapshot_rung",
            "cdc_mode",
            "cdc_supported",
            "pre_post_images_supported",
            "read_only_privilege_proof_hash",
            "probe_hash",
        ),
    )
    target_profile = s_object(
        {
            "provider": s_string(enum=("supabase_postgres", "planetscale_postgres")),
            "postgres_version": s_string(pattern=r"^[0-9]+(?:\.[0-9]+)?$", max_length=16),
            "region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "engine_endpoint_mode": s_string(
                const="direct",
                description=(
                    "Migration-engine DDL, COPY, replication, and administrative traffic. "
                    "This endpoint is never a pooler."
                ),
            ),
            "application_endpoint_mode": s_string(
                enum=("direct", "session_pooler", "transaction_pooler"),
                description=(
                    "Application traffic mode selected independently from the engine endpoint."
                ),
            ),
            "application_endpoint_service": s_string(
                enum=("direct", "supavisor", "pgbouncer"),
                description=(
                    "Provider-specific implementation of the selected application endpoint."
                ),
            ),
            "application_endpoint_branch_specific": {
                **s_boolean(),
                "description": (
                    "Whether the application connection endpoint is scoped to a target branch."
                ),
            },
            "application_endpoint_selection_basis": s_string(
                enum=(
                    "workload_semantics_and_plan_network_probes",
                    "transaction_semantics_and_branch_probe",
                    "direct_endpoint_required",
                ),
                description=(
                    "Released basis for choosing the application endpoint; never authorizes "
                    "engine or administrative traffic through that endpoint."
                ),
            ),
            "application_endpoint_selection_proof_hash": hash_field(),
            "branching_supported": s_boolean(),
            "logical_replication_supported": s_boolean(),
            "required_extensions": _safe_names(max_items=64),
            "privilege_profile_hash": hash_field(),
            "probe_hash": hash_field(),
        },
        (
            "provider",
            "postgres_version",
            "region",
            "engine_endpoint_mode",
            "application_endpoint_mode",
            "application_endpoint_service",
            "application_endpoint_branch_specific",
            "application_endpoint_selection_basis",
            "application_endpoint_selection_proof_hash",
            "branching_supported",
            "logical_replication_supported",
            "required_extensions",
            "privilege_profile_hash",
            "probe_hash",
        ),
    )
    return schema(
        "corridors/mongodb-postgres-profile.schema.json",
        "MongoDB PostgreSQL Corridor Profile",
        {
            "corridor_profile_id": hash_field(),
            "corridor_family": s_string(const="mongodb_postgres"),
            "profile_version": s_string(pattern=SEMVER_PATTERN, max_length=64),
            "profile_hash": hash_field(),
            "source": source_profile,
            "target": target_profile,
            "composition_outcome": s_string(enum=("supported", "fallback", "refused")),
            "fallback_or_refusal_reason": nullable(
                s_string(
                    enum=(
                        "standalone_requires_freeze",
                        "oplog_window_insufficient",
                        "target_privilege_insufficient",
                        "target_extension_unavailable",
                        "target_endpoint_unsuitable",
                        "region_or_residency_conflict",
                        "unsupported_version",
                    )
                )
            ),
            "pricing_version": s_string(pattern=SEMVER_PATTERN, max_length=64),
            "pricing_hash": hash_field(),
            "created_at": timestamp_field(),
        },
        (
            "corridor_profile_id",
            "corridor_family",
            "profile_version",
            "profile_hash",
            "source",
            "target",
            "composition_outcome",
            "fallback_or_refusal_reason",
            "pricing_version",
            "pricing_hash",
            "created_at",
        ),
        data_class="shared_migration",
        max_bytes=65536,
        flow_ids=("F03", "F06", "F08", "F10"),
        description=(
            "Immutable composition of an Atlas or self-managed MongoDB source with exactly one "
            "Supabase or PlanetScale Postgres target. Unsupported physics produces a typed fallback or refusal."
        ),
        all_of=[
            {
                "if": {
                    "properties": {
                        "source": {
                            "properties": {
                                "cdc_mode": {"const": "change_stream_pre_post_images"}
                            }
                        }
                    }
                },
                "then": {
                    "properties": {
                        "source": {
                            "properties": {
                                "cdc_supported": {"const": True},
                                "pre_post_images_supported": {"const": True},
                            }
                        }
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "source": {
                            "properties": {"cdc_mode": {"const": "change_stream_lookup"}}
                        }
                    }
                },
                "then": {
                    "properties": {
                        "source": {
                            "properties": {
                                "cdc_supported": {"const": True},
                                "pre_post_images_supported": {"const": False},
                            }
                        }
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "source": {"properties": {"cdc_mode": {"const": "freeze_only"}}}
                    }
                },
                "then": {
                    "properties": {
                        "source": {
                            "properties": {
                                "cdc_supported": {"const": False},
                                "pre_post_images_supported": {"const": False},
                            }
                        }
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "source": {"properties": {"topology": {"const": "standalone"}}}
                    }
                },
                "then": {
                    "properties": {
                        "source": {
                            "properties": {
                                "snapshot_rung": {"const": "freeze_only"},
                                "cdc_mode": {"const": "freeze_only"},
                                "cdc_supported": {"const": False},
                                "pre_post_images_supported": {"const": False},
                            }
                        },
                        "composition_outcome": {"enum": ["fallback", "refused"]},
                        "fallback_or_refusal_reason": {
                            "const": "standalone_requires_freeze"
                        },
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "target": {
                            "properties": {
                                "application_endpoint_mode": {"const": "direct"}
                            }
                        }
                    }
                },
                "then": {
                    "properties": {
                        "target": {
                            "properties": {
                                "application_endpoint_service": {"const": "direct"}
                            }
                        }
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "target": {
                            "properties": {
                                "application_endpoint_mode": {"const": "session_pooler"}
                            }
                        }
                    }
                },
                "then": {
                    "properties": {
                        "target": {
                            "properties": {
                                "provider": {"const": "supabase_postgres"},
                                "application_endpoint_service": {"const": "supavisor"},
                            }
                        }
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "target": {
                            "properties": {
                                "provider": {"const": "supabase_postgres"}
                            }
                        }
                    }
                },
                "then": {
                    "properties": {
                        "target": {
                            "properties": {
                                "application_endpoint_service": {
                                    "enum": ["direct", "supavisor"]
                                },
                                "application_endpoint_selection_basis": {
                                    "const": "workload_semantics_and_plan_network_probes"
                                },
                            }
                        }
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "target": {
                            "properties": {
                                "provider": {"const": "supabase_postgres"},
                                "application_endpoint_mode": {
                                    "const": "transaction_pooler"
                                },
                            }
                        }
                    }
                },
                "then": {
                    "properties": {
                        "target": {
                            "properties": {
                                "application_endpoint_service": {"const": "supavisor"}
                            }
                        }
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "target": {
                            "properties": {
                                "provider": {"const": "planetscale_postgres"}
                            }
                        }
                    }
                },
                "then": {
                    "properties": {
                        "target": {
                            "properties": {
                                "application_endpoint_mode": {
                                    "enum": ["direct", "transaction_pooler"]
                                },
                                "application_endpoint_service": {
                                    "enum": ["direct", "pgbouncer"]
                                },
                            }
                        }
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "target": {
                            "properties": {
                                "provider": {"const": "planetscale_postgres"},
                                "application_endpoint_mode": {
                                    "const": "transaction_pooler"
                                },
                            }
                        }
                    }
                },
                "then": {
                    "properties": {
                        "target": {
                            "properties": {
                                "application_endpoint_service": {"const": "pgbouncer"},
                                "application_endpoint_branch_specific": {"const": True},
                                "application_endpoint_selection_basis": {
                                    "const": "transaction_semantics_and_branch_probe"
                                },
                            }
                        }
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "target": {
                            "properties": {
                                "provider": {"const": "planetscale_postgres"},
                                "application_endpoint_mode": {"const": "direct"},
                            }
                        }
                    }
                },
                "then": {
                    "properties": {
                        "target": {
                            "properties": {
                                "application_endpoint_selection_basis": {
                                    "const": "direct_endpoint_required"
                                }
                            }
                        }
                    }
                },
            },
            {
                "if": {"properties": {"composition_outcome": {"const": "supported"}}},
                "then": {
                    "properties": {
                        "source": {"properties": {"cdc_supported": {"const": True}}},
                        "target": {
                            "properties": {
                                "engine_endpoint_mode": {"const": "direct"},
                                "branching_supported": {"const": True},
                            }
                        },
                        "fallback_or_refusal_reason": {"type": "null"},
                    }
                },
                "else": {
                    "properties": {
                        "fallback_or_refusal_reason": {
                            "type": "string",
                            "enum": [
                                "standalone_requires_freeze",
                                "oplog_window_insufficient",
                                "target_privilege_insufficient",
                                "target_extension_unavailable",
                                "target_endpoint_unsuitable",
                                "region_or_residency_conflict",
                                "unsupported_version",
                            ],
                        }
                    }
                },
            },
        ],
    )


def _placement_decision_schema() -> dict[str, Any]:
    alternative = s_object(
        {
            "target_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "worker_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "golden_bucket_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "network_rung": s_string(enum=("private_endpoint", "peering", "public_tls")),
            "one_time_transfer_cost_minor_units": s_integer(minimum=0),
            "repeated_transfer_cost_minor_units": s_integer(minimum=0),
            "estimated_latency_milliseconds": s_integer(minimum=0, maximum=600_000),
            "rejection_reason": s_string(pattern=_SAFE_REASON_PATTERN, max_length=96),
        },
        (
            "target_region",
            "worker_region",
            "golden_bucket_region",
            "network_rung",
            "one_time_transfer_cost_minor_units",
            "repeated_transfer_cost_minor_units",
            "estimated_latency_milliseconds",
            "rejection_reason",
        ),
    )
    return schema(
        "placement/placement-decision.schema.json",
        "Placement Decision",
        {
            **common_identity_properties(),
            "placement_decision_id": hash_field(),
            "input_evidence_root": hash_field(),
            "corridor_profile_id": hash_field(),
            "corridor_profile_hash": hash_field(),
            "pricing_version": s_string(pattern=SEMVER_PATTERN, max_length=64),
            "pricing_hash": hash_field(),
            "target_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "worker_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "golden_bucket_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "source_network_rung": s_string(enum=("private_endpoint", "peering", "public_tls")),
            "target_network_rung": s_string(enum=("private_endpoint", "peering", "public_tls")),
            "one_time_transfer_cost_minor_units": s_integer(minimum=0),
            "repeated_transfer_cost_minor_units": s_integer(minimum=0),
            "currency": s_string(pattern=r"^[A-Z]{3}$", max_length=3),
            "estimated_freeze_drain_seconds": s_integer(minimum=0, maximum=2_592_000),
            "model_availability": s_string(enum=("eligible", "degraded_wait", "ineligible")),
            "recommendation_basis_roots": _hashes(min_items=1, max_items=32),
            "rejected_alternatives": s_array(alternative, max_items=32),
            "decided_at": timestamp_field(),
        },
        (
            *_identity_required(),
            "placement_decision_id",
            "input_evidence_root",
            "corridor_profile_id",
            "corridor_profile_hash",
            "pricing_version",
            "pricing_hash",
            "target_region",
            "worker_region",
            "golden_bucket_region",
            "source_network_rung",
            "target_network_rung",
            "one_time_transfer_cost_minor_units",
            "repeated_transfer_cost_minor_units",
            "currency",
            "estimated_freeze_drain_seconds",
            "model_availability",
            "recommendation_basis_roots",
            "rejected_alternatives",
            "decided_at",
        ),
        data_class="shared_migration",
        max_bytes=131072,
        flow_ids=("F02", "F03", "F06", "F07"),
        description="Immutable selected placement plus priced and reasoned rejected alternatives.",
    )


def _custody_bootstrap_manifest_schema() -> dict[str, Any]:
    return schema(
        "cell/custody-bootstrap-manifest.schema.json",
        "Custody Bootstrap Manifest",
        {
            **common_identity_properties(),
            "custody_manifest_id": hash_field(),
            "custody_manifest_hash": hash_field(),
            "cell_mode": s_string(const="discovery"),
            "preliminary_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "allowed_residency_regions": s_array(
                s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
                min_items=1,
                max_items=16,
                unique=True,
            ),
            "allowed_secret_purposes": s_array(
                s_string(
                    enum=(
                        "mongodb_read",
                        "postgres_target",
                        "github_repo_scan",
                        "github_pr_author",
                        "github_review_dispatch",
                        "github_review_ingest",
                    )
                ),
                min_items=1,
                max_items=6,
                unique=True,
            ),
            "kms_boundary_hash": hash_field(),
            "secrets_namespace_hash": hash_field(),
            "s3_boundary_hash": hash_field(),
            "egress_policy_hash": hash_field(),
            "discovery_tool_catalog_hash": hash_field(),
            "release_unit_id": hash_field(),
            "release_unit_hash": hash_field(),
            "issued_at": timestamp_field(),
            "expires_at": timestamp_field(),
            "ttl_seconds": s_integer(minimum=60, maximum=259200),
        },
        (
            *_identity_required(),
            "custody_manifest_id",
            "custody_manifest_hash",
            "cell_mode",
            "preliminary_region",
            "allowed_residency_regions",
            "allowed_secret_purposes",
            "kms_boundary_hash",
            "secrets_namespace_hash",
            "s3_boundary_hash",
            "egress_policy_hash",
            "discovery_tool_catalog_hash",
            "release_unit_id",
            "release_unit_hash",
            "issued_at",
            "expires_at",
            "ttl_seconds",
        ),
        data_class="shared_migration",
        max_bytes=32768,
        flow_ids=("F04", "F06", "F07"),
        description=(
            "Signed-payload fields for the TTL-bound discovery custody envelope. It contains "
            "secret purpose names and boundary hashes, never secret values."
        ),
    )


def _deployment_manifest_schema() -> dict[str, Any]:
    image = s_object(
        {
            "component": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "digest": s_string(pattern=r"^sha256:[0-9a-f]{64}$", max_length=71),
        },
        ("component", "digest"),
    )
    properties: dict[str, Any] = {
        **common_identity_properties(),
        "deployment_manifest_id": hash_field(),
        "deployment_manifest_hash": hash_field(),
        "cell_mode": s_string(enum=("discovery", "migration")),
        "region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
        "template_version": s_string(pattern=SEMVER_PATTERN, max_length=64),
        "template_hash": hash_field(),
        "ami_digest": s_string(pattern=r"^sha256:[0-9a-f]{64}$", max_length=71),
        "container_images": s_array(image, min_items=1, max_items=32),
        "environment": s_string(
            enum=("ephemeral-nonprod", "persistent-nonprod", "staging", "production")
        ),
        "lifecycle_stage": s_string(enum=("candidate", "ready", "active", "recovery")),
        "release_unit_id": hash_field(),
        "release_unit_hash": hash_field(),
        "release_deployment_id": hash_field(),
        "release_deployment_generation": s_integer(minimum=1),
        "agent_bundle_id": hash_field(),
        "qualification_record_id": hash_field(),
        "activation_transaction_id": _id(),
        "activation_receipt_hash": hash_field(),
        "cell_release_binding_id": hash_field(),
        "cell_release_binding_version": s_integer(minimum=1),
        "cell_release_binding_state": s_string(enum=("active", "paused", "stopped")),
        "runtime_role_ids": _safe_names(min_items=1, max_items=32),
        "tool_role_ids": _safe_names(max_items=64),
        "vpc_policy_hash": hash_field(),
        "subnet_policy_hash": hash_field(),
        "endpoint_policy_hash": hash_field(),
        "egress_policy_hash": hash_field(),
        "data_encryption_key_ref_hash": hash_field(),
        "manifest_signer_fingerprint": hash_field(),
        "proof_signing_key_ref_hash": _nullable_hash(),
        "secrets_namespace_hash": hash_field(),
        "s3_boundary_hash": hash_field(),
        "storage_generation": s_integer(minimum=1),
        "checkpoint_pointer_hash": _nullable_hash(),
        "corridor_profile_id": hash_field(),
        "corridor_profile_hash": hash_field(),
        "tool_catalog_hash": hash_field(),
        "target_write_epoch": nullable(s_integer(minimum=1)),
        "custody_manifest_id": _nullable_hash(),
        "custody_manifest_hash": _nullable_hash(),
        "parent_discovery_generation": nullable(s_integer(minimum=1)),
        "placement_decision_hash": _nullable_hash(),
        "foundation_decision_root": _nullable_hash(),
        "discovery_root_parity_hash": _nullable_hash(),
        "resource_plan_hash": _nullable_hash(),
        "issued_at": timestamp_field(),
        "expires_at": timestamp_field(),
        "budget_minor_units": s_integer(minimum=0),
        "budget_currency": s_string(pattern=r"^[A-Z]{3}$", max_length=3),
        "retain_until": timestamp_field(),
    }
    required = [
        *_identity_required(),
        *[name for name in properties if name not in common_identity_properties()],
    ]
    required = list(dict.fromkeys(required))
    return schema(
        "cell/deployment-manifest.schema.json",
        "Cell Deployment Manifest",
        properties,
        required,
        data_class="shared_migration",
        max_bytes=262144,
        flow_ids=("F06", "F07", "F13"),
        description=(
            "Immutable digest-pinned discovery or migration cell deployment payload. Mode "
            "conditions prevent discovery generations from acquiring target/proof authority."
        ),
        all_of=[
            {
                "oneOf": [
                    {
                        "properties": {
                            "cell_mode": {"const": "discovery"},
                            "target_write_epoch": {"type": "null"},
                            "proof_signing_key_ref_hash": {"type": "null"},
                            "parent_discovery_generation": {"type": "null"},
                            "placement_decision_hash": {"type": "null"},
                            "foundation_decision_root": {"type": "null"},
                            "discovery_root_parity_hash": {"type": "null"},
                            "resource_plan_hash": {"type": "null"},
                            "custody_manifest_id": hash_field(),
                            "custody_manifest_hash": hash_field(),
                        }
                    },
                    {
                        "properties": {
                            "cell_mode": {"const": "migration"},
                            "target_write_epoch": s_integer(minimum=1),
                            "proof_signing_key_ref_hash": hash_field(),
                            "parent_discovery_generation": s_integer(minimum=1),
                            "placement_decision_hash": hash_field(),
                            "foundation_decision_root": hash_field(),
                            "discovery_root_parity_hash": hash_field(),
                            "resource_plan_hash": hash_field(),
                            "custody_manifest_id": {"type": "null"},
                            "custody_manifest_hash": {"type": "null"},
                        }
                    },
                ]
            }
        ],
    )


def _cell_bootstrap_schema() -> dict[str, Any]:
    return schema(
        "cell/bootstrap.schema.json",
        "Cell Bootstrap Exchange",
        {
            **common_identity_properties(),
            "bootstrap_exchange_id": hash_field(),
            "action": s_string(enum=("request", "poll", "complete")),
            "deployment_manifest_id": hash_field(),
            "deployment_manifest_hash": hash_field(),
            "cell_release_binding_id": hash_field(),
            "control_region_epoch": s_integer(minimum=1),
            "instance_identity_hash": hash_field(),
            "csr_der_hash": hash_field(),
            "bootstrap_secret_hash": _nullable_hash(),
            "poll_secret_hash": _nullable_hash(),
            "certificate_request_id": _nullable_id(),
            "certificate_receipt_id": _nullable_hash(),
            "status": s_string(enum=("pending", "issued", "delivered", "denied")),
            "issued_at": timestamp_field(),
            "expires_at": timestamp_field(),
            "response_replay_until": timestamp_field(),
        },
        (
            *_identity_required(),
            "bootstrap_exchange_id",
            "action",
            "deployment_manifest_id",
            "deployment_manifest_hash",
            "cell_release_binding_id",
            "control_region_epoch",
            "instance_identity_hash",
            "csr_der_hash",
            "bootstrap_secret_hash",
            "poll_secret_hash",
            "certificate_request_id",
            "certificate_receipt_id",
            "status",
            "issued_at",
            "expires_at",
            "response_replay_until",
        ),
        data_class="security_material",
        max_bytes=32768,
        flow_ids=("F06", "F07"),
        description=(
            "One-use bootstrap/request/poll/complete exchange. Only keyed hashes of bootstrap "
            "and poll secrets are contract fields; private key material is forbidden."
        ),
    )


def _certificate_request_schema() -> dict[str, Any]:
    return schema(
        "cell/certificate-request.schema.json",
        "Cell Certificate Request",
        {
            **common_identity_properties(),
            "certificate_request_id": _id(),
            "request_kind": s_string(enum=("bootstrap", "renewal", "recovery")),
            "request_status": s_string(enum=("pending", "claimed", "issued", "denied", "quarantined")),
            "deployment_manifest_id": hash_field(),
            "deployment_manifest_hash": hash_field(),
            "cell_release_binding_id": hash_field(),
            "control_region_epoch": s_integer(minimum=1),
            "instance_identity_hash": hash_field(),
            "csr_der_base64": s_string(
                pattern=_BASE64_PATTERN, min_length=128, max_length=16384
            ),
            "csr_der_hash": hash_field(),
            "requested_spiffe_uri": s_string(pattern=_SPIFFE_CELL_PATTERN, max_length=256),
            "issuer_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "ca_generation": s_integer(minimum=1),
            "certificate_profile_hash": hash_field(),
            "predecessor_serial_hex": nullable(
                s_string(pattern=_SERIAL_PATTERN, max_length=40)
            ),
            "failover_manifest_id": _nullable_hash(),
            "prior_control_region_epoch": nullable(s_integer(minimum=1)),
            "control_region_epoch_increment": s_integer(minimum=0, maximum=1),
            "requested_at": timestamp_field(),
            "expires_at": timestamp_field(),
        },
        (
            *_identity_required(),
            "certificate_request_id",
            "request_kind",
            "request_status",
            "deployment_manifest_id",
            "deployment_manifest_hash",
            "cell_release_binding_id",
            "control_region_epoch",
            "instance_identity_hash",
            "csr_der_base64",
            "csr_der_hash",
            "requested_spiffe_uri",
            "issuer_region",
            "ca_generation",
            "certificate_profile_hash",
            "predecessor_serial_hex",
            "failover_manifest_id",
            "prior_control_region_epoch",
            "control_region_epoch_increment",
            "requested_at",
            "expires_at",
        ),
        data_class="security_material",
        max_bytes=32768,
        flow_ids=("F06",),
        description=(
            "Typed, claimed X.509 workload-certificate request. The CSR contains a public key; "
            "the corresponding private key never leaves the cell's protected store."
        ),
        all_of=[
            {
                "oneOf": [
                    {
                        "properties": {
                            "request_kind": {"const": "bootstrap"},
                            "predecessor_serial_hex": {"type": "null"},
                            "failover_manifest_id": {"type": "null"},
                            "prior_control_region_epoch": {"type": "null"},
                            "control_region_epoch_increment": {"const": 0},
                        }
                    },
                    {
                        "properties": {
                            "request_kind": {"const": "renewal"},
                            "predecessor_serial_hex": s_string(pattern=_SERIAL_PATTERN, max_length=40),
                            "failover_manifest_id": {"type": "null"},
                            "prior_control_region_epoch": {"type": "null"},
                            "control_region_epoch_increment": {"const": 0},
                        }
                    },
                    {
                        "properties": {
                            "request_kind": {"const": "recovery"},
                            "predecessor_serial_hex": s_string(pattern=_SERIAL_PATTERN, max_length=40),
                            "failover_manifest_id": hash_field(),
                            "prior_control_region_epoch": s_integer(minimum=1),
                            "control_region_epoch_increment": {"const": 1},
                        }
                    },
                ]
            },
        ],
    )


def _certificate_receipt_schema() -> dict[str, Any]:
    return schema(
        "cell/certificate-receipt.schema.json",
        "Cell Certificate Receipt",
        {
            **common_identity_properties(),
            "certificate_receipt_id": hash_field(),
            "certificate_request_id": _id(),
            "request_kind": s_string(enum=("bootstrap", "renewal", "recovery")),
            "deployment_manifest_id": hash_field(),
            "deployment_manifest_hash": hash_field(),
            "cell_release_binding_id": hash_field(),
            "control_region_epoch": s_integer(minimum=1),
            "issuer_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "ca_generation": s_integer(minimum=1),
            "issuer_kid": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "serial_hex": s_string(pattern=_SERIAL_PATTERN, min_length=1, max_length=40),
            "spiffe_uri": s_string(pattern=_SPIFFE_CELL_PATTERN, max_length=256),
            "not_before": timestamp_field(),
            "not_after": timestamp_field(),
            "certificate_der_hash": hash_field(),
            "certificate_chain_hash": hash_field(),
            "certificate_profile_hash": hash_field(),
            "trust_store_version": s_integer(minimum=1),
            "trust_store_hash": hash_field(),
            "crl_number": s_integer(minimum=0),
            "crl_root_hash": hash_field(),
            "delivery_status": s_string(enum=("issued", "delivered", "revoked")),
            "issued_at": timestamp_field(),
            "delivered_at": _nullable_timestamp(),
            "revoked_at": _nullable_timestamp(),
        },
        (
            *_identity_required(),
            "certificate_receipt_id",
            "certificate_request_id",
            "request_kind",
            "deployment_manifest_id",
            "deployment_manifest_hash",
            "cell_release_binding_id",
            "control_region_epoch",
            "issuer_region",
            "ca_generation",
            "issuer_kid",
            "serial_hex",
            "spiffe_uri",
            "not_before",
            "not_after",
            "certificate_der_hash",
            "certificate_chain_hash",
            "certificate_profile_hash",
            "trust_store_version",
            "trust_store_hash",
            "crl_number",
            "crl_root_hash",
            "delivery_status",
            "issued_at",
            "delivered_at",
            "revoked_at",
        ),
        data_class="security_material",
        max_bytes=32768,
        flow_ids=("F06", "F17"),
        description=(
            "Public issuance/delivery receipt for one cell workload certificate; no private "
            "key or reusable bootstrap material is present."
        ),
        all_of=[
            {
                "oneOf": [
                    {"properties": {"delivery_status": {"const": "issued"}, "delivered_at": {"type": "null"}, "revoked_at": {"type": "null"}}},
                    {"properties": {"delivery_status": {"const": "delivered"}, "delivered_at": timestamp_field(), "revoked_at": {"type": "null"}}},
                    {"properties": {"delivery_status": {"const": "revoked"}, "delivered_at": timestamp_field(), "revoked_at": timestamp_field()}},
                ]
            }
        ],
    )


def _certificate_recovery_renewal_schema() -> dict[str, Any]:
    return schema(
        "cell/certificate-recovery-renewal.schema.json",
        "Cell Certificate Recovery Renewal",
        {
            **common_identity_properties(),
            "recovery_renewal_id": hash_field(),
            "failover_manifest_id": hash_field(),
            "failover_manifest_hash": hash_field(),
            "deployment_manifest_id": hash_field(),
            "deployment_manifest_hash": hash_field(),
            "old_serial_hex": s_string(pattern=_SERIAL_PATTERN, max_length=40),
            "prior_control_region_epoch": s_integer(minimum=1),
            "current_control_region_epoch": s_integer(minimum=2),
            "csr_der_base64": s_string(
                pattern=_BASE64_PATTERN, min_length=128, max_length=16384
            ),
            "csr_der_hash": hash_field(),
            "certificate_request_id": _id(),
            "poll_secret_hash": hash_field(),
            "request_nonce_hash": hash_field(),
            "requested_at": timestamp_field(),
            "expires_at": timestamp_field(),
            "status": s_string(enum=("reserved", "issued", "delivered", "denied")),
        },
        (
            *_identity_required(),
            "recovery_renewal_id",
            "failover_manifest_id",
            "failover_manifest_hash",
            "deployment_manifest_id",
            "deployment_manifest_hash",
            "old_serial_hex",
            "prior_control_region_epoch",
            "current_control_region_epoch",
            "csr_der_base64",
            "csr_der_hash",
            "certificate_request_id",
            "poll_secret_hash",
            "request_nonce_hash",
            "requested_at",
            "expires_at",
            "status",
        ),
        data_class="security_material",
        max_bytes=32768,
        flow_ids=("F06",),
        description=(
            "One-use prior-epoch unary renewal request. It grants no stream, command, or tool authority."
        ),
    )


def _crl_publication_schema() -> dict[str, Any]:
    revoked_serial = s_object(
        {
            "serial_hex": s_string(pattern=_SERIAL_PATTERN, max_length=40),
            "reason": s_string(
                enum=(
                    "key_compromise",
                    "ca_compromise",
                    "affiliation_changed",
                    "superseded",
                    "cessation_of_operation",
                    "privilege_withdrawn",
                )
            ),
            "revoked_at": timestamp_field(),
            "certificate_expires_at": timestamp_field(),
            "revocation_intent_hash": hash_field(),
        },
        (
            "serial_hex",
            "reason",
            "revoked_at",
            "certificate_expires_at",
            "revocation_intent_hash",
        ),
    )
    return schema(
        "cell/crl-publication.schema.json",
        "Cell CRL Publication",
        {
            "crl_publication_id": hash_field(),
            "issuer_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "ca_generation": s_integer(minimum=1),
            "issuer_kid": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "crl_number": s_integer(minimum=1),
            "previous_crl_root_hash": hash_field(),
            "revoked_serials": s_array(
                revoked_serial, min_items=0, max_items=100000, unique=True
            ),
            "revoked_serial_set_hash": hash_field(),
            "tbs_cert_list_hash": hash_field(),
            "crl_profile_hash": hash_field(),
            "this_update": timestamp_field(),
            "next_update": timestamp_field(),
            "status": s_string(enum=("reserved", "claimed", "published", "quarantined")),
            "crl_der_hash": _nullable_hash(),
            "object_key": nullable(
                s_string(
                    pattern=r"^cell-ca/crl/[a-z0-9-]+/[1-9][0-9]*/[0-9a-f]{64}\.crl$",
                    max_length=256,
                )
            ),
            "object_version_id": nullable(s_string(min_length=1, max_length=1024)),
            "new_crl_root_hash": _nullable_hash(),
            "terminal_receipt_hash": _nullable_hash(),
            "quarantine_evidence_hash": _nullable_hash(),
            "requested_at": timestamp_field(),
            "published_at": _nullable_timestamp(),
        },
        (
            "crl_publication_id",
            "issuer_region",
            "ca_generation",
            "issuer_kid",
            "crl_number",
            "previous_crl_root_hash",
            "revoked_serials",
            "revoked_serial_set_hash",
            "tbs_cert_list_hash",
            "crl_profile_hash",
            "this_update",
            "next_update",
            "status",
            "crl_der_hash",
            "object_key",
            "object_version_id",
            "new_crl_root_hash",
            "terminal_receipt_hash",
            "quarantine_evidence_hash",
            "requested_at",
            "published_at",
        ),
        data_class="security_material",
        max_bytes=8_388_608,
        flow_ids=("F06", "F17"),
        description=(
            "Monotonic RFC 5280 CRL request/publication record over the complete set of still-"
            "unexpired revoked serials. Object locations are exact and content addressed."
        ),
        all_of=[
            {
                "oneOf": [
                    {
                        "properties": {
                            "status": {"enum": ["reserved", "claimed"]},
                            "crl_der_hash": {"type": "null"},
                            "object_key": {"type": "null"},
                            "object_version_id": {"type": "null"},
                            "new_crl_root_hash": {"type": "null"},
                            "terminal_receipt_hash": {"type": "null"},
                            "quarantine_evidence_hash": {"type": "null"},
                            "published_at": {"type": "null"},
                        }
                    },
                    {
                        "properties": {
                            "status": {"const": "published"},
                            "crl_der_hash": hash_field(),
                            "object_key": s_string(pattern=r"^cell-ca/crl/[a-z0-9-]+/[1-9][0-9]*/[0-9a-f]{64}\.crl$", max_length=256),
                            "object_version_id": s_string(min_length=1, max_length=1024),
                            "new_crl_root_hash": hash_field(),
                            "terminal_receipt_hash": hash_field(),
                            "quarantine_evidence_hash": {"type": "null"},
                            "published_at": timestamp_field(),
                        }
                    },
                    {
                        "properties": {
                            "status": {"const": "quarantined"},
                            "crl_der_hash": {"type": "null"},
                            "object_key": {"type": "null"},
                            "object_version_id": {"type": "null"},
                            "new_crl_root_hash": {"type": "null"},
                            "terminal_receipt_hash": hash_field(),
                            "quarantine_evidence_hash": hash_field(),
                            "published_at": {"type": "null"},
                        }
                    },
                ]
            }
        ],
    )


def _release_binding_schema() -> dict[str, Any]:
    return schema(
        "cell/release-binding.schema.json",
        "Cell Release Binding",
        {
            **common_identity_properties(),
            "cell_release_binding_id": hash_field(),
            "binding_version": s_integer(minimum=1),
            "state": s_string(enum=("active", "paused", "stopped", "superseded")),
            "release_unit_id": hash_field(),
            "release_unit_hash": hash_field(),
            "release_deployment_id": hash_field(),
            "release_deployment_generation": s_integer(minimum=1),
            "agent_bundle_id": hash_field(),
            "qualification_record_id": hash_field(),
            "activation_transaction_id": _id(),
            "activation_receipt_hash": hash_field(),
            "support_policy_version": s_integer(minimum=1),
            "support_policy_hash": hash_field(),
            "supported": s_boolean(),
            "predecessor_binding_id": _nullable_hash(),
            "bound_at": timestamp_field(),
            "paused_at": _nullable_timestamp(),
            "stopped_at": _nullable_timestamp(),
            "superseded_at": _nullable_timestamp(),
        },
        (
            *_identity_required(),
            "cell_release_binding_id",
            "binding_version",
            "state",
            "release_unit_id",
            "release_unit_hash",
            "release_deployment_id",
            "release_deployment_generation",
            "agent_bundle_id",
            "qualification_record_id",
            "activation_transaction_id",
            "activation_receipt_hash",
            "support_policy_version",
            "support_policy_hash",
            "supported",
            "predecessor_binding_id",
            "bound_at",
            "paused_at",
            "stopped_at",
            "superseded_at",
        ),
        data_class="internal_operational",
        max_bytes=32768,
        flow_ids=("F03", "F06", "F07"),
        description=(
            "Immutable activated/supported release tuple for one exact cell generation. The "
            "mutable environment new-admission pointer is never cell authority."
        ),
    )


def _release_upgrade_schema() -> dict[str, Any]:
    return schema(
        "cell/release-upgrade.schema.json",
        "Cell Release Upgrade",
        {
            **common_identity_properties(),
            "release_upgrade_id": hash_field(),
            "state": s_string(
                enum=(
                    "requested",
                    "authorized",
                    "provisioning",
                    "restored",
                    "verified",
                    "superseded",
                    "failed",
                )
            ),
            "from_binding_id": hash_field(),
            "from_binding_hash": hash_field(),
            "to_binding_id": hash_field(),
            "to_binding_hash": hash_field(),
            "old_cell_generation": s_integer(minimum=1),
            "new_cell_generation": s_integer(minimum=2),
            "old_cell_write_epoch": s_integer(minimum=1),
            "new_cell_write_epoch": s_integer(minimum=2),
            "safe_checkpoint_hash": hash_field(),
            "checkpoint_schema_version": s_string(pattern=SEMVER_PATTERN, max_length=64),
            "compatibility_proof_hash": hash_field(),
            "authorization_receipt_hash": hash_field(),
            "restore_receipt_hash": _nullable_hash(),
            "verification_receipt_hash": _nullable_hash(),
            "old_generation_fence_receipt_hash": _nullable_hash(),
            "binding_supersession_receipt_hash": _nullable_hash(),
            "requested_at": timestamp_field(),
            "completed_at": _nullable_timestamp(),
        },
        (
            *_identity_required(),
            "release_upgrade_id",
            "state",
            "from_binding_id",
            "from_binding_hash",
            "to_binding_id",
            "to_binding_hash",
            "old_cell_generation",
            "new_cell_generation",
            "old_cell_write_epoch",
            "new_cell_write_epoch",
            "safe_checkpoint_hash",
            "checkpoint_schema_version",
            "compatibility_proof_hash",
            "authorization_receipt_hash",
            "restore_receipt_hash",
            "verification_receipt_hash",
            "old_generation_fence_receipt_hash",
            "binding_supersession_receipt_hash",
            "requested_at",
            "completed_at",
        ),
        data_class="internal_operational",
        max_bytes=32768,
        flow_ids=("F03", "F06", "F07", "F13"),
        description=(
            "Operator-authorized safe-checkpoint successor-generation upgrade. It cannot "
            "silently repin an existing generation to the current environment pointer."
        ),
    )


def _control_region_failover_manifest_schema() -> dict[str, Any]:
    approval = s_object(
        {
            "operator_id": _id(),
            "operator_role": s_string(enum=("recovery_operator", "security_operator")),
            "approved_at": timestamp_field(),
            "approval_evidence_hash": hash_field(),
        },
        ("operator_id", "operator_role", "approved_at", "approval_evidence_hash"),
    )
    return schema(
        "recovery/control-region-failover-manifest.schema.json",
        "Control Region Failover Manifest",
        {
            "failover_manifest_id": hash_field(),
            "purpose": s_string(const="control_region_failover"),
            "environment": s_string(enum=("staging", "production")),
            "source_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "target_region": s_string(pattern=_AWS_REGION_PATTERN, max_length=32),
            "prior_control_region_epoch": s_integer(minimum=1),
            "current_control_region_epoch": s_integer(minimum=2),
            "primary_fence_receipt_hash": hash_field(),
            "restore_point_id": s_string(min_length=1, max_length=256),
            "restore_root_hash": hash_field(),
            "provider_journal_reconciliation_root": hash_field(),
            "infrastructure_readiness_root": hash_field(),
            "release_unit_id": hash_field(),
            "release_unit_hash": hash_field(),
            "nonce_hash": hash_field(),
            "approvals": s_array(approval, min_items=2, max_items=2, unique=True),
            "issued_at": timestamp_field(),
            "expires_at": timestamp_field(),
        },
        (
            "failover_manifest_id",
            "purpose",
            "environment",
            "source_region",
            "target_region",
            "prior_control_region_epoch",
            "current_control_region_epoch",
            "primary_fence_receipt_hash",
            "restore_point_id",
            "restore_root_hash",
            "provider_journal_reconciliation_root",
            "infrastructure_readiness_root",
            "release_unit_id",
            "release_unit_hash",
            "nonce_hash",
            "approvals",
            "issued_at",
            "expires_at",
        ),
        data_class="internal_operational",
        max_bytes=32768,
        flow_ids=("F03", "F06", "F17"),
        description=(
            "Two-operator, no-RDS signed-payload authorization for one exact regional failover "
            "epoch transition. The signer cannot activate and the activator cannot sign."
        ),
    )


def _certificate_profile() -> Artifact:
    return text_artifact(
        """# Generated by internal/contracts/codegen/generate.py; DO NOT EDIT.
schema_version: 1.0.0
profile_id: jumpship-cell-workload-leaf-v1
standard: RFC5280
canonical_encoding: DER
signature_algorithm: ECDSA_P256_SHA256
public_key_algorithm: ECDSA_P256
serial:
  positive: true
  unique_per_issuer: true
  minimum_octets: 1
  maximum_octets: 20
validity:
  maximum_seconds: 86400
  renew_after_seconds: 43200
  maximum_clock_skew_seconds: 300
subject:
  encoding: empty_sequence
subject_alternative_name:
  critical: true
  required_uri_pattern: '^spiffe://jumpship/cells/[0-9a-f-]+/generations/[1-9][0-9]*$'
  dns_names_allowed: false
  ip_addresses_allowed: false
  email_addresses_allowed: false
basic_constraints:
  critical: true
  ca: false
key_usage:
  critical: true
  required:
    - digitalSignature
  forbidden:
    - keyCertSign
    - cRLSign
extended_key_usage:
  critical: true
  required:
    - clientAuth
  forbidden:
    - serverAuth
    - anyExtendedKeyUsage
forbidden_extensions:
  - subjectDirectoryAttributes
  - policyMappings
  - nameConstraints
  - policyConstraints
  - inhibitAnyPolicy
binding_requirements:
  - issuer_region
  - ca_generation
  - cell_id
  - cell_generation
  - deployment_manifest_hash
  - cell_release_binding_id
  - control_region_epoch
private_key_export_allowed: false
""",
        "application/yaml",
    )


def _crl_profile() -> Artifact:
    return text_artifact(
        """# Generated by internal/contracts/codegen/generate.py; DO NOT EDIT.
schema_version: 1.0.0
profile_id: jumpship-cell-crl-v1
standard: RFC5280
canonical_encoding: DER
version: 2
signature_algorithm: ECDSA_P256_SHA256
issuer_binding:
  require_exact_region: true
  require_exact_ca_generation: true
crl_number:
  required: true
  positive: true
  monotonic_increment: 1
authority_key_identifier:
  required: true
this_update:
  maximum_clock_skew_seconds: 300
next_update:
  minimum_seconds_after_this_update: 900
  maximum_seconds_after_this_update: 172800
distribution:
  content_addressed: true
  versioned_object_required: true
  direct_overwrite_forbidden: true
revoked_serials:
  complete_unexpired_set_required: true
  maximum_serial_octets: 20
  require_reason_code: true
  deterministic_sort: unsigned_big_endian_serial
chain:
  require_previous_root: true
  forbid_skipped_or_reused_number: true
signer:
  workload: cell-ca-signer
  database_role: cell_ca_signer
  may_create_or_approve_request: false
""",
        "application/yaml",
    )


def _cell_command_schema() -> dict[str, Any]:
    variable = s_object(
        {
            "name": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "value_hash": hash_field(),
            "maximum_data_class": s_string(enum=DATA_CLASSES),
        },
        ("name", "value_hash", "maximum_data_class"),
    )
    return schema(
        "lifecycle/cell-command.schema.json",
        "Cell Lifecycle Command",
        {
            **common_identity_properties(),
            "cell_command_id": hash_field(),
            "purpose": s_string(const="cell_lifecycle_command"),
            "desired_state": s_string(
                enum=("provision", "bootstrap", "start", "restart", "revoke", "destroy", "recover")
            ),
            "deployment_manifest_id": hash_field(),
            "deployment_manifest_hash": hash_field(),
            "cell_release_binding_id": hash_field(),
            "control_region_epoch": s_integer(minimum=1),
            "template_hash": hash_field(),
            "variables": s_array(variable, max_items=64),
            "idempotency_key_hash": hash_field(),
            "previous_receipt_hash": _nullable_hash(),
            "issued_at": timestamp_field(),
            "expires_at": timestamp_field(),
        },
        (
            *_identity_required(),
            "cell_command_id",
            "purpose",
            "desired_state",
            "deployment_manifest_id",
            "deployment_manifest_hash",
            "cell_release_binding_id",
            "control_region_epoch",
            "template_hash",
            "variables",
            "idempotency_key_hash",
            "previous_receipt_hash",
            "issued_at",
            "expires_at",
        ),
        data_class="internal_operational",
        max_bytes=65536,
        flow_ids=("F05", "F07"),
        description=(
            "Expiring backend-authorized lifecycle payload with exact manifest/template inputs. "
            "It is signed by a detached purpose-specific SignatureEnvelope."
        ),
    )


def _cell_receipt_schema() -> dict[str, Any]:
    effect = s_object(
        {
            "effect_kind": s_string(
                enum=("created", "updated", "started", "stopped", "revoked", "destroyed", "no_op")
            ),
            "resource_type": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "resource_id_hash": hash_field(),
            "before_hash": _nullable_hash(),
            "after_hash": _nullable_hash(),
        },
        ("effect_kind", "resource_type", "resource_id_hash", "before_hash", "after_hash"),
    )
    return schema(
        "lifecycle/cell-receipt.schema.json",
        "Cell Lifecycle Receipt",
        {
            **common_identity_properties(),
            "cell_receipt_id": hash_field(),
            "cell_command_id": hash_field(),
            "previous_receipt_hash": _nullable_hash(),
            "observed_state": s_string(
                enum=(
                    "planned",
                    "provisioning",
                    "bootstrapping",
                    "ready",
                    "active",
                    "degraded",
                    "restarting",
                    "failed",
                    "revoking",
                    "destroying",
                    "destroyed",
                )
            ),
            "inventory_root_hash": hash_field(),
            "tofu_state_version_id": s_string(min_length=1, max_length=1024),
            "plan_hash": hash_field(),
            "effects": s_array(effect, max_items=1024),
            "outcome": s_string(enum=("converged", "retryable", "failed_terminal", "quarantined")),
            "safe_reason_code": nullable(
                s_string(pattern=_SAFE_REASON_PATTERN, max_length=96)
            ),
            "observed_at": timestamp_field(),
        },
        (
            *_identity_required(),
            "cell_receipt_id",
            "cell_command_id",
            "previous_receipt_hash",
            "observed_state",
            "inventory_root_hash",
            "tofu_state_version_id",
            "plan_hash",
            "effects",
            "outcome",
            "safe_reason_code",
            "observed_at",
        ),
        data_class="internal_operational",
        max_bytes=262144,
        flow_ids=("F05", "F07", "F17"),
        description=(
            "Append-only infrastructure reconciliation receipt. It carries inventory/effect "
            "hashes and liveness only, never migration semantics or customer data."
        ),
    )


def _engine_operation_envelope_schema() -> dict[str, Any]:
    return schema(
        "engine/operation-envelope.schema.json",
        "Engine Operation Envelope",
        {
            **common_identity_properties(include_operation=True),
            "attempt_id": _nullable_id(),
            "corridor_profile_id": hash_field(),
            "corridor_profile_hash": hash_field(),
            "migration_phase": s_string(
                enum=(
                    "snapshot",
                    "census",
                    "design",
                    "rehearsal",
                    "bulk_load",
                    "sync",
                    "verify",
                    "cutover",
                    "watch",
                    "decommission",
                )
            ),
            "mapping_spec_id": hash_field(),
            "mapping_spec_hash": hash_field(),
            "verification_rubric_id": hash_field(),
            "verification_rubric_hash": hash_field(),
            "tool_name": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "tool_version": s_string(pattern=SEMVER_PATTERN, max_length=64),
            "tool_descriptor_hash": hash_field(),
            "execution_mode": s_string(const="durable"),
            "consequence_class": s_string(
                enum=(
                    "observation",
                    "advisory_analysis",
                    "proposal",
                    "deterministic_effect",
                    "irreversible_boundary",
                )
            ),
            "input_hash": hash_field(),
            "input_artifact_roots": _hashes(max_items=64),
            "maximum_input_data_class": s_string(enum=DATA_CLASSES),
            "maximum_output_data_class": s_string(enum=DATA_CLASSES),
            "maximum_input_bytes": s_integer(minimum=0, maximum=1_073_741_824),
            "maximum_output_bytes": s_integer(minimum=0, maximum=268_435_456),
            "application_authority_epoch": s_integer(minimum=1),
            "cell_write_epoch": s_integer(minimum=0),
            "idempotency_key_hash": hash_field(),
            "authorized_at": timestamp_field(),
            "expires_at": timestamp_field(),
        },
        (
            *_identity_required(include_operation=True),
            "attempt_id",
            "corridor_profile_id",
            "corridor_profile_hash",
            "migration_phase",
            "mapping_spec_id",
            "mapping_spec_hash",
            "verification_rubric_id",
            "verification_rubric_hash",
            "tool_name",
            "tool_version",
            "tool_descriptor_hash",
            "execution_mode",
            "consequence_class",
            "input_hash",
            "input_artifact_roots",
            "maximum_input_data_class",
            "maximum_output_data_class",
            "maximum_input_bytes",
            "maximum_output_bytes",
            "application_authority_epoch",
            "cell_write_epoch",
            "idempotency_key_hash",
            "authorized_at",
            "expires_at",
        ),
        data_class="shared_migration",
        max_bytes=65536,
        flow_ids=("F06", "F10", "F13", "F17"),
        description=(
            "Backend-authorized deterministic engine operation with immutable scope, versions, "
            "epochs, data bounds, durable-only execution mode, and idempotency identity."
        ),
    )


def _engine_checkpoint_schema() -> dict[str, Any]:
    cursor = s_object(
        {
            "name": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "position_hash": hash_field(),
            "sequence": s_integer(minimum=0),
        },
        ("name", "position_hash", "sequence"),
    )
    return schema(
        "engine/checkpoint.schema.json",
        "Engine Checkpoint",
        {
            **common_identity_properties(include_operation=True),
            "engine_checkpoint_id": hash_field(),
            "previous_checkpoint_hash": _nullable_hash(),
            "attempt_id": _nullable_id(),
            "checkpoint_schema_version": s_string(pattern=SEMVER_PATTERN, max_length=64),
            "engine_version": s_string(pattern=SEMVER_PATTERN, max_length=64),
            "plan_hash": hash_field(),
            "cell_write_epoch": s_integer(minimum=0),
            "checkpoint_sequence": s_integer(minimum=1),
            "status": s_string(enum=("active", "waiting", "terminal")),
            "cursors": s_array(cursor, max_items=64),
            "artifact_roots": _hashes(max_items=128),
            "created_at": timestamp_field(),
        },
        (
            *_identity_required(include_operation=True),
            "engine_checkpoint_id",
            "previous_checkpoint_hash",
            "attempt_id",
            "checkpoint_schema_version",
            "engine_version",
            "plan_hash",
            "cell_write_epoch",
            "checkpoint_sequence",
            "status",
            "cursors",
            "artifact_roots",
            "created_at",
        ),
        data_class="restricted_customer",
        max_bytes=262144,
        flow_ids=("F13",),
        description=(
            "Cell-local deterministic engine checkpoint. Only hashes and separately sanitized "
            "safe summaries may cross to the shared plane."
        ),
    )


def _engine_receipt_schema() -> dict[str, Any]:
    return schema(
        "engine/receipt.schema.json",
        "Engine Receipt",
        {
            **common_identity_properties(include_operation=True),
            "engine_receipt_id": hash_field(),
            "attempt_id": _nullable_id(),
            "checkpoint_id": _nullable_hash(),
            "tool_descriptor_hash": hash_field(),
            "consequence_class": s_string(
                enum=("observation", "deterministic_effect", "irreversible_boundary")
            ),
            "outcome": s_string(enum=("succeeded", "failed_retryable", "failed_terminal", "denied")),
            "before_root_hash": _nullable_hash(),
            "after_root_hash": _nullable_hash(),
            "provider_receipt_roots": _hashes(max_items=64),
            "idempotency_key_hash": hash_field(),
            "safe_reason_code": nullable(
                s_string(pattern=_SAFE_REASON_PATTERN, max_length=96)
            ),
            "safe_summary": s_string(max_length=2048),
            "started_at": timestamp_field(),
            "finished_at": timestamp_field(),
        },
        (
            *_identity_required(include_operation=True),
            "engine_receipt_id",
            "attempt_id",
            "checkpoint_id",
            "tool_descriptor_hash",
            "consequence_class",
            "outcome",
            "before_root_hash",
            "after_root_hash",
            "provider_receipt_roots",
            "idempotency_key_hash",
            "safe_reason_code",
            "safe_summary",
            "started_at",
            "finished_at",
        ),
        data_class="shared_migration",
        max_bytes=65536,
        flow_ids=("F03", "F06", "F10", "F17"),
        description=(
            "Append-only terminal engine receipt with safe reason/summary and content roots; "
            "raw tool/provider output remains cell-local."
        ),
    )


def _edge_constraints(
    edges: tuple[tuple[str, str], ...],
    *,
    domains: dict[tuple[str, str], str] | None = None,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for from_state, to_state in edges:
        properties: dict[str, Any] = {
            "from_state": {"const": from_state},
            "to_state": {"const": to_state},
        }
        if domains is not None:
            properties["state_dimension"] = {"const": domains[(from_state, to_state)]}
        result.append(
            {
                "properties": properties,
                "required": list(properties),
            }
        )
    return result


def _state_machine_schema(
    path: str,
    title: str,
    machine: str,
    states: tuple[str, ...],
    edges: tuple[tuple[str, str], ...],
    *,
    data_class: str = "shared_migration",
    flow_ids: tuple[str, ...] = ("F03", "F06"),
    extra_properties: dict[str, Any] | None = None,
    extra_required: tuple[str, ...] = (),
    extra_all_of: list[dict[str, Any]] | None = None,
    domains: dict[tuple[str, str], str] | None = None,
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        **common_identity_properties(),
        "transition_id": _id(),
        "machine": s_string(const=machine),
        "from_state": s_string(enum=states),
        "to_state": s_string(enum=states),
        "expected_version": s_integer(minimum=0),
        "resulting_version": s_integer(minimum=1),
        "version_increment": s_integer(minimum=1, maximum=1),
        "idempotency_key_hash": hash_field(),
        "authorization_root_hash": hash_field(),
        "evidence_roots": _hashes(max_items=64),
        "actor_type": s_string(enum=("human", "service", "provider", "system")),
        "reason_code": s_string(pattern=_SAFE_REASON_PATTERN, max_length=96),
        "occurred_at": timestamp_field(),
    }
    if domains is not None:
        properties["state_dimension"] = s_string(
            enum=tuple(sorted(set(domains.values())))
        )
    if extra_properties:
        properties.update(extra_properties)
    required = [
        *_identity_required(),
        "transition_id",
        "machine",
        "from_state",
        "to_state",
        "expected_version",
        "resulting_version",
        "version_increment",
        "idempotency_key_hash",
        "authorization_root_hash",
        "evidence_roots",
        "actor_type",
        "reason_code",
        "occurred_at",
    ]
    if domains is not None:
        required.append("state_dimension")
    required.extend(extra_required)
    all_of = [{"oneOf": _edge_constraints(edges, domains=domains)}]
    if extra_all_of:
        all_of.extend(extra_all_of)
    return schema(
        path,
        title,
        properties,
        required,
        data_class=data_class,
        max_bytes=131072,
        flow_ids=flow_ids,
        description=(
            f"Closed {machine} transition envelope. The schema enumerates every legal edge; "
            "unknown states, same-state rewrites, and unlisted edges are rejected."
        ),
        all_of=all_of,
    )


_MIGRATION_PHASE_STATES = (
    "connect",
    "discovery",
    "foundation",
    "provision",
    "snapshot",
    "census",
    "design",
    "rehearsal",
    "bulk_load",
    "sync",
    "verify",
    "cutover",
    "watch",
    "decommission",
    "complete",
)
_MIGRATION_PHASE_EDGES = tuple(zip(_MIGRATION_PHASE_STATES, _MIGRATION_PHASE_STATES[1:]))
_MIGRATION_EXECUTION_STATES = (
    "pending",
    "running",
    "waiting_human",
    "blocked",
    "failed_recoverable",
    "failed_terminal",
    "succeeded",
    "aborting",
    "aborted",
    "rolling_back",
    "rolled_back",
)
_MIGRATION_EXECUTION_EDGES = (
    ("pending", "running"),
    ("running", "waiting_human"),
    ("running", "blocked"),
    ("running", "failed_recoverable"),
    ("running", "failed_terminal"),
    ("running", "succeeded"),
    ("running", "aborting"),
    ("running", "rolling_back"),
    ("waiting_human", "running"),
    ("waiting_human", "blocked"),
    ("waiting_human", "aborting"),
    ("blocked", "running"),
    ("blocked", "failed_terminal"),
    ("blocked", "aborting"),
    ("failed_recoverable", "pending"),
    ("failed_recoverable", "aborting"),
    ("aborting", "aborted"),
    ("rolling_back", "rolled_back"),
)
_MIGRATION_EDGES = _MIGRATION_PHASE_EDGES + _MIGRATION_EXECUTION_EDGES
_MIGRATION_DOMAINS = {
    **{edge: "primary_phase" for edge in _MIGRATION_PHASE_EDGES},
    **{edge: "execution_status" for edge in _MIGRATION_EXECUTION_EDGES},
}


def _migration_state_machine_schema() -> dict[str, Any]:
    return _state_machine_schema(
        "workflow/migration-state-machine.schema.json",
        "Migration State Machine Transition",
        "migration",
        _MIGRATION_PHASE_STATES + _MIGRATION_EXECUTION_STATES,
        _MIGRATION_EDGES,
        domains=_MIGRATION_DOMAINS,
        extra_properties={
            "start_readiness_version": nullable(s_integer(minimum=1)),
            "all_mandatory_connectors_proven": s_boolean(),
            "start_transaction_id": nullable(_id()),
            "first_prompt_message_id": nullable(_id()),
            "start_conversation_id": nullable(_id()),
            "start_wakeup_id": nullable(_id()),
            "start_receipt_hash": _nullable_hash(),
            "application_authority_epoch": s_integer(minimum=1),
            "cell_write_epoch": s_integer(minimum=0),
            "rehearsed_rollback_reference_hash": _nullable_hash(),
        },
        extra_required=(
            "start_readiness_version",
            "all_mandatory_connectors_proven",
            "start_transaction_id",
            "first_prompt_message_id",
            "start_conversation_id",
            "start_wakeup_id",
            "start_receipt_hash",
            "application_authority_epoch",
            "cell_write_epoch",
            "rehearsed_rollback_reference_hash",
        ),
        extra_all_of=[
            {
                "if": {
                    "properties": {
                        "state_dimension": {"const": "primary_phase"},
                        "from_state": {"const": "connect"},
                        "to_state": {"const": "discovery"},
                    }
                },
                "then": {
                    "properties": {
                        "start_readiness_version": s_integer(minimum=1),
                        "all_mandatory_connectors_proven": {"const": True},
                        "start_transaction_id": _id(),
                        "first_prompt_message_id": _id(),
                        "start_conversation_id": _id(),
                        "start_wakeup_id": _id(),
                        "start_receipt_hash": hash_field(),
                        "actor_type": {"const": "human"},
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "to_state": {"enum": ["rolling_back", "rolled_back"]}
                    }
                },
                "then": {
                    "properties": {"rehearsed_rollback_reference_hash": hash_field()}
                },
            },
        ],
    )


_TRAFFIC_STATES = (
    "source_primary",
    "source_compatibility_deployed",
    "freezing_source",
    "source_fenced_and_drained",
    "target_primary_reverse_armed",
    "target_cohorts_activating",
    "watching_target",
    "rollback_draining",
    "target_fenced_and_reverse_drained",
    "source_restore_arming",
    "source_resume_stream_armed",
    "source_cohorts_activating",
    "source_primary_resynced",
    "reverify_for_cutover",
    "target_primary_irreversible",
    "source_retired",
    "authority_conflict_frozen",
    "incident_recovery_decision",
    "rebaseline_required",
)
_TRAFFIC_EDGES = (
    ("source_primary", "source_compatibility_deployed"),
    ("source_compatibility_deployed", "freezing_source"),
    ("freezing_source", "source_restore_arming"),
    ("freezing_source", "source_fenced_and_drained"),
    ("source_restore_arming", "source_resume_stream_armed"),
    ("source_resume_stream_armed", "source_cohorts_activating"),
    ("source_cohorts_activating", "source_primary_resynced"),
    ("source_fenced_and_drained", "source_restore_arming"),
    ("source_fenced_and_drained", "target_primary_reverse_armed"),
    ("target_primary_reverse_armed", "target_cohorts_activating"),
    ("target_primary_reverse_armed", "rollback_draining"),
    ("target_cohorts_activating", "watching_target"),
    ("target_cohorts_activating", "rollback_draining"),
    ("watching_target", "rollback_draining"),
    ("watching_target", "target_primary_irreversible"),
    ("rollback_draining", "target_fenced_and_reverse_drained"),
    ("target_fenced_and_reverse_drained", "source_resume_stream_armed"),
    ("target_primary_irreversible", "source_retired"),
    ("source_primary_resynced", "reverify_for_cutover"),
    ("reverify_for_cutover", "freezing_source"),
    *((state, "authority_conflict_frozen") for state in (
        "source_fenced_and_drained",
        "target_primary_reverse_armed",
        "target_cohorts_activating",
        "watching_target",
        "rollback_draining",
        "target_fenced_and_reverse_drained",
        "source_restore_arming",
        "source_resume_stream_armed",
        "source_cohorts_activating",
        "target_primary_irreversible",
    )),
    ("authority_conflict_frozen", "incident_recovery_decision"),
    ("incident_recovery_decision", "rollback_draining"),
    ("incident_recovery_decision", "rebaseline_required"),
)


_TRAFFIC_AUTHORITY_BY_STATE = {
    "source_primary": "source",
    "source_compatibility_deployed": "source",
    "freezing_source": "none",
    "source_fenced_and_drained": "none",
    "target_primary_reverse_armed": "target",
    "target_cohorts_activating": "target",
    "watching_target": "target",
    "rollback_draining": "none",
    "target_fenced_and_reverse_drained": "none",
    "source_restore_arming": "none",
    "source_resume_stream_armed": "none",
    "source_cohorts_activating": "source",
    "source_primary_resynced": "source",
    "reverify_for_cutover": "source",
    "target_primary_irreversible": "target",
    "source_retired": "target",
    "authority_conflict_frozen": "none",
    "incident_recovery_decision": "none",
    "rebaseline_required": "none",
}


def _traffic_edge_constraints() -> list[dict[str, Any]]:
    """Bind every legal edge to its exact authority, epoch, and receipt shape.

    JSON Schema cannot perform integer addition across sibling fields. The
    explicit 0/1 increment fields are therefore part of the wire contract;
    contract tests additionally prove ``resulting = expected + increment``.
    """

    result: list[dict[str, Any]] = []
    for from_state, to_state in _TRAFFIC_EDGES:
        from_authority = _TRAFFIC_AUTHORITY_BY_STATE[from_state]
        to_authority = _TRAFFIC_AUTHORITY_BY_STATE[to_state]
        authority_changed = from_authority != to_authority
        properties: dict[str, Any] = {
            "from_state": {"const": from_state},
            "to_state": {"const": to_state},
            "from_application_authority": {"const": from_authority},
            "to_application_authority": {"const": to_authority},
            "application_authority_epoch_increment": {"const": 1 if authority_changed else 0},
            "authority_epoch_transition": {"const": "advanced_once" if authority_changed else "unchanged"},
            "source_application_writes_enabled": {"const": to_authority == "source"},
            "target_application_writes_enabled": {"const": to_authority == "target"},
            "attribution_status": {"const": "clear"},
            "cohort_activation_receipt_root_hash": {"type": "null"},
            "reverse_health_root_hash": {"type": "null"},
            "source_fence_receipt_hash": {"type": "null"},
            "target_fence_receipt_hash": {"type": "null"},
            "source_denial_canary_root_hash": {"type": "null"},
            "target_denial_canary_root_hash": {"type": "null"},
            "source_resume_stream_receipt_hash": {"type": "null"},
            "source_parity_receipt_hash": {"type": "null"},
            "target_no_effect_receipt_hash": {"type": "null"},
            "smoke_root_hash": {"type": "null"},
            "rollback_window_closure_root_hash": {"type": "null"},
            "conflict_evidence_root_hash": {"type": "null"},
        }

        if to_state in {"freezing_source", "source_fenced_and_drained", "target_primary_reverse_armed"}:
            properties["source_fence_receipt_hash"] = hash_field()
            properties["source_denial_canary_root_hash"] = hash_field()
        if to_state in {"target_primary_reverse_armed", "target_cohorts_activating", "watching_target", "rollback_draining", "target_fenced_and_reverse_drained"}:
            properties["reverse_health_root_hash"] = hash_field()
        if to_state in {"target_cohorts_activating", "watching_target"}:
            properties["cohort_activation_receipt_root_hash"] = hash_field()
            properties["smoke_root_hash"] = hash_field()
        if to_state in {"rollback_draining", "target_fenced_and_reverse_drained", "source_resume_stream_armed", "source_cohorts_activating", "source_primary_resynced"}:
            properties["target_fence_receipt_hash"] = hash_field()
            properties["target_denial_canary_root_hash"] = hash_field()
        if to_state == "source_restore_arming":
            properties["target_no_effect_receipt_hash"] = hash_field()
        if to_state in {"source_resume_stream_armed", "source_cohorts_activating", "source_primary_resynced"}:
            properties["source_resume_stream_receipt_hash"] = hash_field()
            properties["source_parity_receipt_hash"] = hash_field()
        if to_state in {"source_cohorts_activating", "source_primary_resynced"}:
            properties["cohort_activation_receipt_root_hash"] = hash_field()
            properties["smoke_root_hash"] = hash_field()
        if to_state in {"target_primary_irreversible", "source_retired"}:
            properties["rollback_window_closure_root_hash"] = hash_field()
        if to_state in {"authority_conflict_frozen", "incident_recovery_decision", "rebaseline_required"} or from_state == "incident_recovery_decision":
            properties["conflict_evidence_root_hash"] = hash_field()
        if to_state == "authority_conflict_frozen":
            properties.update(
                {
                    "attribution_status": {"const": "authority_conflict"},
                    "source_fence_receipt_hash": hash_field(),
                    "target_fence_receipt_hash": hash_field(),
                    "source_denial_canary_root_hash": hash_field(),
                    "target_denial_canary_root_hash": hash_field(),
                }
            )
        result.append({"properties": properties, "required": list(properties)})
    return result


def _traffic_authority_state_machine_schema() -> dict[str, Any]:
    return _state_machine_schema(
        "workflow/traffic-authority-state-machine.schema.json",
        "Traffic Authority State Machine Transition",
        "traffic_authority",
        _TRAFFIC_STATES,
        _TRAFFIC_EDGES,
        extra_properties={
            "from_application_authority": s_string(enum=("source", "none", "target")),
            "to_application_authority": s_string(enum=("source", "none", "target")),
            "expected_application_authority_epoch": s_integer(minimum=1),
            "resulting_application_authority_epoch": s_integer(minimum=1),
            "application_authority_epoch_increment": s_integer(minimum=0, maximum=1),
            "authority_epoch_transition": s_string(enum=("unchanged", "advanced_once")),
            "expected_cell_write_epoch": s_integer(minimum=1),
            "resulting_cell_write_epoch": s_integer(minimum=1),
            "cell_write_epoch_increment": s_integer(minimum=0, maximum=1),
            "cell_generation_changed": s_boolean(),
            "cohort_grant_root_hash": hash_field(),
            "cohort_activation_receipt_root_hash": _nullable_hash(),
            "source_application_writes_enabled": s_boolean(),
            "target_application_writes_enabled": s_boolean(),
            "reverse_health_root_hash": _nullable_hash(),
            "source_fence_receipt_hash": _nullable_hash(),
            "target_fence_receipt_hash": _nullable_hash(),
            "source_denial_canary_root_hash": _nullable_hash(),
            "target_denial_canary_root_hash": _nullable_hash(),
            "source_resume_stream_receipt_hash": _nullable_hash(),
            "source_parity_receipt_hash": _nullable_hash(),
            "target_no_effect_receipt_hash": _nullable_hash(),
            "smoke_root_hash": _nullable_hash(),
            "rollback_window_closure_root_hash": _nullable_hash(),
            "conflict_evidence_root_hash": _nullable_hash(),
            "attribution_status": s_string(
                enum=("clear", "reverse_attribution_pending", "authority_conflict")
            ),
        },
        extra_required=(
            "from_application_authority",
            "to_application_authority",
            "expected_application_authority_epoch",
            "resulting_application_authority_epoch",
            "application_authority_epoch_increment",
            "authority_epoch_transition",
            "expected_cell_write_epoch",
            "resulting_cell_write_epoch",
            "cell_write_epoch_increment",
            "cell_generation_changed",
            "cohort_grant_root_hash",
            "cohort_activation_receipt_root_hash",
            "source_application_writes_enabled",
            "target_application_writes_enabled",
            "reverse_health_root_hash",
            "source_fence_receipt_hash",
            "target_fence_receipt_hash",
            "source_denial_canary_root_hash",
            "target_denial_canary_root_hash",
            "source_resume_stream_receipt_hash",
            "source_parity_receipt_hash",
            "target_no_effect_receipt_hash",
            "smoke_root_hash",
            "rollback_window_closure_root_hash",
            "conflict_evidence_root_hash",
            "attribution_status",
        ),
        extra_all_of=[
            {
                "if": {
                    "properties": {"cell_generation_changed": {"const": False}}
                },
                "then": {
                    "properties": {"cell_write_epoch_increment": {"const": 0}}
                },
            },
            {
                "if": {"properties": {"cell_generation_changed": {"const": True}}},
                "then": {"properties": {"cell_write_epoch_increment": {"const": 1}}},
            },
            {"oneOf": _traffic_edge_constraints()},
        ],
    )


_DECISION_STATES = (
    "draft",
    "computing",
    "awaiting_human",
    "discussing",
    "delegated",
    "resolved",
    "superseded",
)
_DECISION_EDGES = (
    ("draft", "computing"),
    ("computing", "awaiting_human"),
    ("awaiting_human", "discussing"),
    ("discussing", "awaiting_human"),
    ("awaiting_human", "delegated"),
    ("discussing", "delegated"),
    ("awaiting_human", "resolved"),
    ("discussing", "resolved"),
    ("delegated", "resolved"),
    ("resolved", "superseded"),
)


def _decision_state_machine_schema() -> dict[str, Any]:
    return _state_machine_schema(
        "workflow/decision-state-machine.schema.json",
        "Decision State Machine Transition",
        "decision",
        _DECISION_STATES,
        _DECISION_EDGES,
        extra_properties={
            "decision_key": s_string(pattern=_SAFE_NAME_PATTERN, max_length=128),
            "expected_card_version": s_integer(minimum=1),
            "resulting_card_version": s_integer(minimum=2),
            "resolution_kind": nullable(
                s_string(enum=("approve", "override", "reject", "postpone", "delegate"))
            ),
            "computation_current": s_boolean(),
            "unresolved_user_message_count": s_integer(minimum=0, maximum=10000),
            "foundation_decision": s_boolean(),
            "unknown_assumption": s_boolean(),
        },
        extra_required=(
            "decision_key",
            "expected_card_version",
            "resulting_card_version",
            "resolution_kind",
            "computation_current",
            "unresolved_user_message_count",
            "foundation_decision",
            "unknown_assumption",
        ),
        extra_all_of=[
            {
                "if": {"properties": {"to_state": {"const": "resolved"}}},
                "then": {
                    "properties": {
                        "computation_current": {"const": False},
                        "unresolved_user_message_count": {"const": 0},
                        "resolution_kind": {
                            "type": "string",
                            "enum": ["approve", "override", "reject", "postpone"],
                        },
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "foundation_decision": {"const": True},
                        "to_state": {"const": "resolved"},
                    }
                },
                "then": {"properties": {"unknown_assumption": {"const": False}}},
            },
        ],
    )


_CONSENT_STATES = (
    "closed",
    "ready",
    "challenge_issued",
    "pending_typed_consent",
    "consented",
    "executing",
    "executed",
    "declined",
    "expired",
    "invalidated",
)
_CONSENT_EDGES = (
    ("closed", "ready"),
    ("ready", "challenge_issued"),
    ("ready", "invalidated"),
    ("challenge_issued", "pending_typed_consent"),
    ("challenge_issued", "declined"),
    ("challenge_issued", "expired"),
    ("challenge_issued", "invalidated"),
    ("pending_typed_consent", "consented"),
    ("pending_typed_consent", "declined"),
    ("pending_typed_consent", "expired"),
    ("pending_typed_consent", "invalidated"),
    ("consented", "executing"),
    ("consented", "invalidated"),
    ("executing", "executed"),
)


def _consent_state_machine_schema() -> dict[str, Any]:
    return _state_machine_schema(
        "workflow/consent-state-machine.schema.json",
        "Consent State Machine Transition",
        "consent",
        _CONSENT_STATES,
        _CONSENT_EDGES,
        data_class="identity_tenant",
        flow_ids=("F02", "F03", "F16", "F17"),
        extra_properties={
            "consent_request_id": _id(),
            "consent_kind": s_string(enum=("cutover", "decommission")),
            "named_approver_id": _id(),
            "evidence_root_hash": hash_field(),
            "application_authority_epoch": s_integer(minimum=1),
            "cell_write_epoch": s_integer(minimum=1),
            "cohort_grant_root_hash": hash_field(),
            "challenge_hash": _nullable_hash(),
            "webauthn_assertion_hash": _nullable_hash(),
            "typed_phrase_hash": _nullable_hash(),
            "challenge_expires_at": _nullable_timestamp(),
        },
        extra_required=(
            "consent_request_id",
            "consent_kind",
            "named_approver_id",
            "evidence_root_hash",
            "application_authority_epoch",
            "cell_write_epoch",
            "cohort_grant_root_hash",
            "challenge_hash",
            "webauthn_assertion_hash",
            "typed_phrase_hash",
            "challenge_expires_at",
        ),
        extra_all_of=[
            {
                "if": {
                    "properties": {
                        "to_state": {"enum": ["consented", "executing", "executed"]}
                    }
                },
                "then": {
                    "properties": {
                        "challenge_hash": hash_field(),
                        "webauthn_assertion_hash": hash_field(),
                        "typed_phrase_hash": hash_field(),
                        "challenge_expires_at": timestamp_field(),
                    }
                },
            }
        ],
    )


_ARTIFACT_STATES = (
    "declared",
    "writing",
    "sealed",
    "verified",
    "retained",
    "deletion_pending",
    "deleted",
    "corrupt",
)
_ARTIFACT_EDGES = (
    ("declared", "writing"),
    ("writing", "sealed"),
    ("writing", "corrupt"),
    ("sealed", "verified"),
    ("sealed", "corrupt"),
    ("verified", "retained"),
    ("retained", "deletion_pending"),
    ("deletion_pending", "deleted"),
)


def _artifact_state_machine_schema() -> dict[str, Any]:
    return _state_machine_schema(
        "workflow/artifact-state-machine.schema.json",
        "Artifact State Machine Transition",
        "artifact",
        _ARTIFACT_STATES,
        _ARTIFACT_EDGES,
        extra_properties={
            "artifact_id": _id(),
            "artifact_version": s_integer(minimum=1),
            "artifact_data_class": s_string(enum=DATA_CLASSES),
            "artifact_hash": hash_field(),
            "opaque_handle": s_string(pattern=r"^art_[A-Za-z0-9_-]{16,128}$", max_length=132),
            "retain_until": _nullable_timestamp(),
            "encryption_access_state": s_string(
                enum=("readable", "access_disabled", "key_deletion_scheduled", "unreadable")
            ),
            "lifecycle_receipt_hash": _nullable_hash(),
        },
        extra_required=(
            "artifact_id",
            "artifact_version",
            "artifact_data_class",
            "artifact_hash",
            "opaque_handle",
            "retain_until",
            "encryption_access_state",
            "lifecycle_receipt_hash",
        ),
        extra_all_of=[
            {
                "if": {
                    "properties": {
                        "to_state": {"enum": ["retained", "deletion_pending"]}
                    }
                },
                "then": {"properties": {"retain_until": timestamp_field()}},
            },
            {
                "if": {"properties": {"to_state": {"const": "deleted"}}},
                "then": {
                    "properties": {
                        "lifecycle_receipt_hash": hash_field(),
                        "encryption_access_state": {"const": "unreadable"},
                    }
                },
            },
        ],
    )


_CELL_STATES = (
    "planned",
    "provisioning",
    "bootstrapping",
    "ready",
    "active",
    "degraded",
    "restarting",
    "failed",
    "revoking",
    "destroying",
    "destroyed",
)
_CELL_EDGES = (
    ("planned", "provisioning"),
    ("provisioning", "bootstrapping"),
    ("provisioning", "failed"),
    ("bootstrapping", "ready"),
    ("bootstrapping", "failed"),
    ("ready", "active"),
    ("ready", "failed"),
    ("active", "degraded"),
    ("degraded", "restarting"),
    ("restarting", "ready"),
    ("restarting", "failed"),
    ("ready", "revoking"),
    ("active", "revoking"),
    ("degraded", "revoking"),
    ("revoking", "destroying"),
    ("destroying", "destroyed"),
)


def _cell_state_machine_schema() -> dict[str, Any]:
    return _state_machine_schema(
        "workflow/cell-state-machine.schema.json",
        "Cell State Machine Transition",
        "cell",
        _CELL_STATES,
        _CELL_EDGES,
        data_class="internal_operational",
        flow_ids=("F05", "F06", "F07", "F17"),
        extra_properties={
            "deployment_manifest_id": hash_field(),
            "deployment_manifest_hash": hash_field(),
            "cell_release_binding_id": hash_field(),
            "control_region_epoch": s_integer(minimum=1),
            "target_write_epoch": nullable(s_integer(minimum=1)),
            "inventory_root_hash": hash_field(),
            "cell_receipt_hash": hash_field(),
        },
        extra_required=(
            "deployment_manifest_id",
            "deployment_manifest_hash",
            "cell_release_binding_id",
            "control_region_epoch",
            "target_write_epoch",
            "inventory_root_hash",
            "cell_receipt_hash",
        ),
    )


_OPERATION_STATES = (
    "requested",
    "authorized",
    "leased",
    "running",
    "succeeded",
    "failed_retryable",
    "failed_terminal",
    "lease_expired",
    "denied",
    "canceled",
)
_OPERATION_EDGES = (
    ("requested", "authorized"),
    ("requested", "denied"),
    ("requested", "canceled"),
    ("authorized", "leased"),
    ("authorized", "denied"),
    ("authorized", "canceled"),
    ("leased", "running"),
    ("leased", "lease_expired"),
    ("running", "succeeded"),
    ("running", "failed_retryable"),
    ("running", "failed_terminal"),
    ("failed_retryable", "authorized"),
)


_ATTEMPT_STATES = (
    "declared",
    "queued",
    "running",
    "waiting",
    "succeeded",
    "failed_recoverable",
    "failed_terminal",
    "canceled",
)
_ATTEMPT_EDGES = (
    ("declared", "queued"),
    ("queued", "running"),
    ("running", "waiting"),
    ("waiting", "running"),
    ("running", "succeeded"),
    ("running", "failed_recoverable"),
    ("running", "failed_terminal"),
    ("running", "canceled"),
)


_REVERSIBILITY_STATES = ("proposed", "open", "warning", "closed", "superseded")
_REVERSIBILITY_EDGES = (
    ("proposed", "open"),
    ("open", "warning"),
    ("open", "superseded"),
    ("warning", "closed"),
    ("warning", "superseded"),
)


def _reversibility_state_machine_schema() -> dict[str, Any]:
    return _state_machine_schema(
        "decisions/reversibility-state-machine.schema.json",
        "Reversibility State Machine Transition",
        "reversibility",
        _REVERSIBILITY_STATES,
        _REVERSIBILITY_EDGES,
        flow_ids=("F02", "F03", "F06", "F16", "F17"),
        extra_properties={
            "reversibility_id": hash_field(),
            "reversibility_class": s_string(
                enum=(
                    "free_until_cutover",
                    "expensive_after_cutover",
                    "closes_on_first_external_exposure",
                    "closes_on_a_clock",
                    "never_reversible",
                )
            ),
            "closed_by_receipt_hash": _nullable_hash(),
            "superseded_by": _nullable_hash(),
        },
        extra_required=(
            "reversibility_id",
            "reversibility_class",
            "closed_by_receipt_hash",
            "superseded_by",
        ),
        extra_all_of=[
            {
                "if": {"properties": {"to_state": {"const": "closed"}}},
                "then": {
                    "properties": {
                        "closed_by_receipt_hash": hash_field(),
                        "superseded_by": {"type": "null"},
                    }
                },
                "else": {
                    "if": {"properties": {"to_state": {"const": "superseded"}}},
                    "then": {
                        "properties": {
                            "closed_by_receipt_hash": {"type": "null"},
                            "superseded_by": hash_field(),
                        }
                    },
                    "else": {
                        "properties": {
                            "closed_by_receipt_hash": {"type": "null"},
                            "superseded_by": {"type": "null"},
                        }
                    },
                },
            }
        ],
    )


def _attempt_state_machine_schema() -> dict[str, Any]:
    return _state_machine_schema(
        "workflow/attempt-state-machine.schema.json",
        "Attempt State Machine Transition",
        "attempt",
        _ATTEMPT_STATES,
        _ATTEMPT_EDGES,
        extra_properties={
            "attempt_id": _id(),
            "attempt_kind": s_string(
                enum=(
                    "snapshot",
                    "snapshot_restore",
                    "golden_self_proof",
                    "rehearsal",
                    "bulk_load",
                    "verification",
                    "rollback_rehearsal",
                    "cutover",
                )
            ),
            "ordinal": s_integer(minimum=1),
            "retry_of_attempt_id": _nullable_id(),
            "terminal_receipt_hash": _nullable_hash(),
        },
        extra_required=(
            "attempt_id",
            "attempt_kind",
            "ordinal",
            "retry_of_attempt_id",
            "terminal_receipt_hash",
        ),
        extra_all_of=[
            {
                "if": {
                    "properties": {
                        "to_state": {
                            "enum": [
                                "succeeded",
                                "failed_recoverable",
                                "failed_terminal",
                                "canceled",
                            ]
                        }
                    }
                },
                "then": {"properties": {"terminal_receipt_hash": hash_field()}},
                "else": {"properties": {"terminal_receipt_hash": {"type": "null"}}},
            }
        ],
    )


def _operation_state_machine_schema() -> dict[str, Any]:
    return _state_machine_schema(
        "workflow/operation-state-machine.schema.json",
        "Operation State Machine Transition",
        "operation",
        _OPERATION_STATES,
        _OPERATION_EDGES,
        extra_properties={
            "operation_id": _id(),
            "attempt_id": _nullable_id(),
            "input_hash": hash_field(),
            "migration_phase": s_string(
                enum=(
                    "connect",
                    "discovery",
                    "foundation",
                    "provision",
                    "snapshot",
                    "census",
                    "design",
                    "rehearsal",
                    "bulk_load",
                    "sync",
                    "verify",
                    "cutover",
                    "watch",
                    "decommission",
                )
            ),
            "mapping_spec_hash": hash_field(),
            "tool_descriptor_hash": hash_field(),
            "cell_write_epoch": s_integer(minimum=0),
            "consequence_class": s_string(
                enum=(
                    "observation",
                    "advisory_analysis",
                    "proposal",
                    "deterministic_effect",
                    "irreversible_boundary",
                )
            ),
            "lease_expires_at": _nullable_timestamp(),
            "terminal_receipt_hash": _nullable_hash(),
        },
        extra_required=(
            "operation_id",
            "attempt_id",
            "input_hash",
            "migration_phase",
            "mapping_spec_hash",
            "tool_descriptor_hash",
            "cell_write_epoch",
            "consequence_class",
            "lease_expires_at",
            "terminal_receipt_hash",
        ),
        extra_all_of=[
            {
                "if": {"properties": {"to_state": {"const": "leased"}}},
                "then": {"properties": {"lease_expires_at": timestamp_field()}},
            },
            {
                "if": {
                    "properties": {
                        "to_state": {
                            "enum": ["succeeded", "failed_terminal", "denied", "canceled"]
                        }
                    }
                },
                "then": {"properties": {"terminal_receipt_hash": hash_field()}},
            },
        ],
    )


def _transition_fixture(
    schema_path: str,
    machine: str,
    states: tuple[str, ...],
    edges: tuple[tuple[str, str], ...],
    *,
    dimensions: dict[tuple[str, str], str] | None = None,
    state_dimensions: dict[str, str] | None = None,
) -> Artifact:
    allowed = set(edges)
    valid = []
    for from_state, to_state in edges:
        record: dict[str, Any] = {
            "from_state": from_state,
            "to_state": to_state,
            "expected": "valid",
        }
        if dimensions is not None:
            record["state_dimension"] = dimensions[(from_state, to_state)]
        valid.append(record)

    invalid = []
    for from_state in states:
        for to_state in states:
            if (from_state, to_state) in allowed:
                continue
            record = {
                "from_state": from_state,
                "to_state": to_state,
                "expected": "invalid",
                "expected_error": "illegal_transition",
            }
            if state_dimensions is not None:
                record["state_dimension"] = state_dimensions[from_state]
                if state_dimensions[from_state] != state_dimensions[to_state]:
                    record["expected_error"] = "cross_dimension_transition"
            invalid.append(record)
    invalid.extend(
        [
            {
                "from_state": "unknown_state",
                "to_state": states[0],
                "expected": "invalid",
                "expected_error": "unknown_from_state",
            },
            {
                "from_state": states[0],
                "to_state": "unknown_state",
                "expected": "invalid",
                "expected_error": "unknown_to_state",
            },
        ]
    )
    return json_artifact(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "exhaustive-state-machine-transition-fixture-set",
            "schema_path": schema_path,
            "machine": machine,
            "states": list(states),
            "valid_transitions": valid,
            "invalid_transitions": invalid,
        },
        "application/json",
    )


def _fixture_identity() -> dict[str, Any]:
    return {
        "workspace_id": "018f0f00-0000-7000-8000-000000000001",
        "migration_id": "018f0f00-0000-7000-8000-000000000002",
        "cell_id": "018f0f00-0000-7000-8000-000000000003",
        "cell_generation": 2,
        "causation_id": "018f0f00-0000-7000-8000-000000000004",
        "correlation_id": "018f0f00-0000-7000-8000-000000000005",
    }


def _certificate_fixtures() -> Artifact:
    # Schema hashes are lowercase hexadecimal. Keep the labels readable while
    # cycling values once the alphabet runs past ``f``.
    hashes = {
        letter: format(index, "x") * 64
        for index, letter in enumerate("abcdefghijklmno", start=1)
    }
    request = {
        "schema_version": SCHEMA_VERSION,
        **_fixture_identity(),
        "certificate_request_id": "018f0f00-0000-7000-8000-000000000006",
        "request_kind": "bootstrap",
        "request_status": "pending",
        "deployment_manifest_id": hashes["a"],
        "deployment_manifest_hash": hashes["b"],
        "cell_release_binding_id": hashes["c"],
        "control_region_epoch": 7,
        "instance_identity_hash": hashes["d"],
        "csr_der_base64": "QUJD" * 32,
        "csr_der_hash": hashes["e"],
        "requested_spiffe_uri": (
            "spiffe://jumpship/cells/018f0f00-0000-7000-8000-000000000003/generations/2"
        ),
        "issuer_region": "us-east-1",
        "ca_generation": 3,
        "certificate_profile_hash": hashes["f"],
        "predecessor_serial_hex": None,
        "failover_manifest_id": None,
        "prior_control_region_epoch": None,
        "control_region_epoch_increment": 0,
        "requested_at": "2026-07-18T00:00:00Z",
        "expires_at": "2026-07-18T00:10:00Z",
    }
    receipt = {
        "schema_version": SCHEMA_VERSION,
        **_fixture_identity(),
        "certificate_receipt_id": hashes["g"],
        "certificate_request_id": request["certificate_request_id"],
        "request_kind": "bootstrap",
        "deployment_manifest_id": hashes["a"],
        "deployment_manifest_hash": hashes["b"],
        "cell_release_binding_id": hashes["c"],
        "control_region_epoch": 7,
        "issuer_region": "us-east-1",
        "ca_generation": 3,
        "issuer_kid": "cell-ca-us-east-1-generation-3",
        "serial_hex": "01a2",
        "spiffe_uri": request["requested_spiffe_uri"],
        "not_before": "2026-07-18T00:00:00Z",
        "not_after": "2026-07-19T00:00:00Z",
        "certificate_der_hash": hashes["h"],
        "certificate_chain_hash": hashes["i"],
        "certificate_profile_hash": hashes["f"],
        "trust_store_version": 4,
        "trust_store_hash": hashes["j"],
        "crl_number": 12,
        "crl_root_hash": hashes["k"],
        "delivery_status": "delivered",
        "issued_at": "2026-07-18T00:01:00Z",
        "delivered_at": "2026-07-18T00:02:00Z",
        "revoked_at": None,
    }
    recovery = {
        "schema_version": SCHEMA_VERSION,
        **_fixture_identity(),
        "recovery_renewal_id": hashes["l"],
        "failover_manifest_id": hashes["m"],
        "failover_manifest_hash": hashes["n"],
        "deployment_manifest_id": hashes["a"],
        "deployment_manifest_hash": hashes["b"],
        "old_serial_hex": "01a2",
        "prior_control_region_epoch": 7,
        "current_control_region_epoch": 8,
        "csr_der_base64": "REVG" * 32,
        "csr_der_hash": hashes["e"],
        "certificate_request_id": "018f0f00-0000-7000-8000-000000000007",
        "poll_secret_hash": hashes["f"],
        "request_nonce_hash": hashes["g"],
        "requested_at": "2026-07-18T01:00:00Z",
        "expires_at": "2026-07-18T01:10:00Z",
        "status": "reserved",
    }
    crl = {
        "schema_version": SCHEMA_VERSION,
        "crl_publication_id": hashes["o"],
        "issuer_region": "us-east-1",
        "ca_generation": 3,
        "issuer_kid": "cell-ca-us-east-1-generation-3",
        "crl_number": 13,
        "previous_crl_root_hash": hashes["k"],
        "revoked_serials": [
            {
                "serial_hex": "01a2",
                "reason": "superseded",
                "revoked_at": "2026-07-18T01:00:00Z",
                "certificate_expires_at": "2026-07-19T00:00:00Z",
                "revocation_intent_hash": hashes["l"],
            }
        ],
        "revoked_serial_set_hash": hashes["m"],
        "tbs_cert_list_hash": hashes["n"],
        "crl_profile_hash": hashes["f"],
        "this_update": "2026-07-18T01:00:00Z",
        "next_update": "2026-07-19T01:00:00Z",
        "status": "reserved",
        "crl_der_hash": None,
        "object_key": None,
        "object_version_id": None,
        "new_crl_root_hash": None,
        "terminal_receipt_hash": None,
        "quarantine_evidence_hash": None,
        "requested_at": "2026-07-18T01:00:00Z",
        "published_at": None,
    }
    return json_artifact(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "certificate-contract-fixture-set",
            "cases": [
                {
                    "name": "bootstrap-request-valid",
                    "schema_path": "contracts/cell/certificate-request.schema.json",
                    "expected": "valid",
                    "document": request,
                },
                {
                    "name": "wrong-spiffe-generation-invalid",
                    "schema_path": "contracts/cell/certificate-request.schema.json",
                    "expected": "invalid",
                    "expected_error": "requested_spiffe_uri",
                    "document": {**request, "requested_spiffe_uri": "spiffe://jumpship/cells/wrong/generations/1"},
                },
                {
                    "name": "certificate-receipt-valid",
                    "schema_path": "contracts/cell/certificate-receipt.schema.json",
                    "expected": "valid",
                    "document": receipt,
                },
                {
                    "name": "zero-serial-invalid",
                    "schema_path": "contracts/cell/certificate-receipt.schema.json",
                    "expected": "invalid",
                    "expected_error": "serial_hex",
                    "document": {**receipt, "serial_hex": "00"},
                },
                {
                    "name": "prior-epoch-recovery-valid",
                    "schema_path": "contracts/cell/certificate-recovery-renewal.schema.json",
                    "expected": "valid",
                    "document": recovery,
                },
                {
                    "name": "missing-failover-binding-invalid",
                    "schema_path": "contracts/cell/certificate-recovery-renewal.schema.json",
                    "expected": "invalid",
                    "expected_error": "failover_manifest_id",
                    "document": {**recovery, "failover_manifest_id": None},
                },
                {
                    "name": "crl-reservation-valid",
                    "schema_path": "contracts/cell/crl-publication.schema.json",
                    "expected": "valid",
                    "document": crl,
                },
                {
                    "name": "empty-initial-crl-set-valid",
                    "schema_path": "contracts/cell/crl-publication.schema.json",
                    "expected": "valid",
                    "document": {**crl, "revoked_serials": []},
                },
                {
                    "name": "published-crl-without-terminal-fields-invalid",
                    "schema_path": "contracts/cell/crl-publication.schema.json",
                    "expected": "invalid",
                    "expected_error": "published_terminal_shape",
                    "document": {**crl, "status": "published"},
                },
                {
                    "name": "bootstrap-with-predecessor-invalid",
                    "schema_path": "contracts/cell/certificate-request.schema.json",
                    "expected": "invalid",
                    "expected_error": "bootstrap_predecessor_forbidden",
                    "document": {**request, "predecessor_serial_hex": "01a2"},
                },
            ],
        },
        "application/json",
    )


def _failover_fixtures() -> Artifact:
    valid = {
        "schema_version": SCHEMA_VERSION,
        "failover_manifest_id": "a" * 64,
        "purpose": "control_region_failover",
        "environment": "production",
        "source_region": "us-east-1",
        "target_region": "us-west-2",
        "prior_control_region_epoch": 7,
        "current_control_region_epoch": 8,
        "primary_fence_receipt_hash": "b" * 64,
        "restore_point_id": "rds-restore-20260718-001",
        "restore_root_hash": "c" * 64,
        "provider_journal_reconciliation_root": "d" * 64,
        "infrastructure_readiness_root": "e" * 64,
        "release_unit_id": "f" * 64,
        "release_unit_hash": "1" * 64,
        "nonce_hash": "2" * 64,
        "approvals": [
            {
                "operator_id": "018f0f00-0000-7000-8000-000000000011",
                "operator_role": "recovery_operator",
                "approved_at": "2026-07-18T02:00:00Z",
                "approval_evidence_hash": "3" * 64,
            },
            {
                "operator_id": "018f0f00-0000-7000-8000-000000000012",
                "operator_role": "security_operator",
                "approved_at": "2026-07-18T02:01:00Z",
                "approval_evidence_hash": "4" * 64,
            },
        ],
        "issued_at": "2026-07-18T02:02:00Z",
        "expires_at": "2026-07-18T02:17:00Z",
    }
    return json_artifact(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "control-region-failover-fixture-set",
            "schema_path": "contracts/recovery/control-region-failover-manifest.schema.json",
            "cases": [
                {"name": "two-operator-failover", "expected": "valid", "document": valid},
                {
                    "name": "one-operator-denied",
                    "expected": "invalid",
                    "expected_error": "approvals.minItems",
                    "document": {**valid, "approvals": valid["approvals"][:1]},
                },
                {
                    "name": "wrong-purpose-denied",
                    "expected": "invalid",
                    "expected_error": "purpose.const",
                    "document": {**valid, "purpose": "cell_lifecycle_command"},
                },
            ],
        },
        "application/json",
    )


def _reversibility_fixtures() -> Artifact:
    base = {
        "schema_version": SCHEMA_VERSION,
        "reversibility_id": "a" * 64,
        "decision_key": "traffic-cutover",
        "decision_version": 1,
        "reversibility_class": "free_until_cutover",
        "state": "open",
        "closure_predicate": "successful_traffic_flip",
        "closes_at": None,
        "clock_source": "provider_receipt",
        "warning_required": True,
        "warning_threshold_seconds": [86400, 14400, 3600],
        "safe_failure": "retain_current_authority",
        "required_operation_id": "cutover",
        "cost_estimate_minor_units": None,
        "cost_currency": None,
        "viability_evidence_roots": ["b" * 64],
        "exposure_subject_hash": None,
        "closed_by_receipt_hash": None,
        "superseded_by": None,
    }
    expensive = {
        **base,
        "decision_key": "post-cutover-reversal",
        "reversibility_class": "expensive_after_cutover",
        "closure_predicate": "priced_rehearsed_operation",
        "clock_source": "not_applicable",
        "required_operation_id": "rollback-rehearsal",
        "cost_estimate_minor_units": 250000,
        "cost_currency": "USD",
    }
    external = {
        **base,
        "decision_key": "external-credential-exposure",
        "reversibility_class": "closes_on_first_external_exposure",
        "closure_predicate": "first_external_exposure",
        "required_operation_id": "requestArtifactAccess",
        "exposure_subject_hash": "c" * 64,
    }
    clock = {
        **base,
        "decision_key": "rollback-window",
        "reversibility_class": "closes_on_a_clock",
        "closure_predicate": "backend_deadline",
        "closes_at": "2026-07-19T00:00:00Z",
        "clock_source": "backend_utc",
        "required_operation_id": "close-rollback-window",
    }
    never = {
        **base,
        "decision_key": "foundation-selection",
        "reversibility_class": "never_reversible",
        "closure_predicate": "first_effect",
        "safe_failure": "block_effect",
        "required_operation_id": "apply-foundation",
    }
    return json_artifact(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "reversibility-taxonomy-fixture-set",
            "schema_path": "contracts/decisions/reversibility.schema.json",
            "cases": [
                {"name": "free-until-cutover", "expected": "valid", "document": base},
                {"name": "expensive-after-cutover", "expected": "valid", "document": expensive},
                {"name": "external-exposure", "expected": "valid", "document": external},
                {"name": "authoritative-clock", "expected": "valid", "document": clock},
                {"name": "never-reversible", "expected": "valid", "document": never},
                {
                    "name": "priced-operation-without-cost-denied",
                    "expected": "invalid",
                    "expected_error": "cost_estimate_minor_units",
                    "document": {**expensive, "cost_estimate_minor_units": None},
                },
                {
                    "name": "external-exposure-without-subject-denied",
                    "expected": "invalid",
                    "expected_error": "exposure_subject_hash",
                    "document": {**external, "exposure_subject_hash": None},
                },
                {
                    "name": "clock-without-deadline-denied",
                    "expected": "invalid",
                    "expected_error": "closes_at",
                    "document": {**clock, "closes_at": None},
                },
                {
                    "name": "closed-without-receipt-denied",
                    "expected": "invalid",
                    "expected_error": "closed_by_receipt_hash",
                    "document": {**base, "state": "closed"},
                },
                {
                    "name": "never-reversible-unknown-safe-failure-denied",
                    "expected": "invalid",
                    "expected_error": "safe_failure",
                    "document": {**never, "safe_failure": "escalate_human"},
                },
            ],
        },
        "application/json",
    )


def _attempt_fixtures() -> Artifact:
    base = {
        "schema_version": SCHEMA_VERSION,
        **_fixture_identity(),
        "operation_id": "018f0f00-0000-7000-8000-000000000006",
        "attempt_id": "018f0f00-0000-7000-8000-000000000007",
        "attempt_kind": "rehearsal",
        "ordinal": 1,
        "parent_attempt_id": None,
        "retry_of_attempt_id": None,
        "state": "declared",
        "concurrency_class": "resource_mutating",
        "spec_version": 1,
        "spec_hash": "a" * 64,
        "rubric_version": 1,
        "rubric_hash": "b" * 64,
        "build_hash": "c" * 64,
        "agent_bundle_id": "d" * 64,
        "cell_write_epoch": 0,
        "started_at": None,
        "finished_at": None,
        "wait_kind": "none",
        "wait_deadline": None,
        "final_reason_code": None,
        "final_safe_summary": None,
        "final_artifact_roots": [],
        "final_metrics": [],
    }
    running = {
        **base,
        "state": "running",
        "started_at": "2026-07-18T00:00:00Z",
    }
    waiting = {
        **running,
        "state": "waiting",
        "wait_kind": "provider",
        "wait_deadline": "2026-07-18T00:10:00Z",
    }
    succeeded = {
        **running,
        "state": "succeeded",
        "finished_at": "2026-07-18T00:05:00Z",
        "final_reason_code": "completed",
        "final_safe_summary": "Rehearsal completed with all declared checks satisfied.",
        "final_artifact_roots": ["e" * 64],
        "final_metrics": [{"name": "elapsed", "unit": "milliseconds", "value": 300000}],
    }
    return json_artifact(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "attempt-state-shape-fixture-set",
            "schema_path": "contracts/workflow/attempt.schema.json",
            "cases": [
                {"name": "declared", "expected": "valid", "document": base},
                {"name": "running", "expected": "valid", "document": running},
                {"name": "waiting", "expected": "valid", "document": waiting},
                {"name": "succeeded", "expected": "valid", "document": succeeded},
                {
                    "name": "running-without-start-denied",
                    "expected": "invalid",
                    "expected_error": "started_at",
                    "document": {**running, "started_at": None},
                },
                {
                    "name": "waiting-without-bounded-kind-denied",
                    "expected": "invalid",
                    "expected_error": "wait_kind",
                    "document": {**waiting, "wait_kind": "none"},
                },
                {
                    "name": "terminal-without-result-denied",
                    "expected": "invalid",
                    "expected_error": "final_safe_summary",
                    "document": {**succeeded, "final_safe_summary": None},
                },
                {
                    "name": "retry-reuses-first-ordinal-denied",
                    "expected": "invalid",
                    "expected_error": "ordinal",
                    "document": {
                        **succeeded,
                        "retry_of_attempt_id": "018f0f00-0000-7000-8000-000000000008",
                        "ordinal": 1,
                    },
                },
            ],
        },
        "application/json",
    )


def _corridor_fixtures() -> Artifact:
    valid = {
        "schema_version": SCHEMA_VERSION,
        "corridor_profile_id": "a" * 64,
        "corridor_family": "mongodb_postgres",
        "profile_version": "1.0.0",
        "profile_hash": "b" * 64,
        "source": {
            "provider": "mongodb_atlas",
            "topology": "replica_set",
            "server_version": "7.0.12",
            "region": "us-east-1",
            "network_rung": "private_endpoint",
            "snapshot_rung": "secondary_dump_oplog",
            "cdc_mode": "change_stream_pre_post_images",
            "cdc_supported": True,
            "pre_post_images_supported": True,
            "read_only_privilege_proof_hash": "c" * 64,
            "probe_hash": "d" * 64,
        },
        "target": {
            "provider": "supabase_postgres",
            "postgres_version": "17",
            "region": "us-east-1",
            "engine_endpoint_mode": "direct",
            "application_endpoint_mode": "direct",
            "application_endpoint_service": "direct",
            "application_endpoint_branch_specific": False,
            "application_endpoint_selection_basis": (
                "workload_semantics_and_plan_network_probes"
            ),
            "application_endpoint_selection_proof_hash": "9" * 64,
            "branching_supported": True,
            "logical_replication_supported": True,
            "required_extensions": ["pgcrypto"],
            "privilege_profile_hash": "e" * 64,
            "probe_hash": "f" * 64,
        },
        "composition_outcome": "supported",
        "fallback_or_refusal_reason": None,
        "pricing_version": "1.0.0",
        "pricing_hash": "1" * 64,
        "created_at": "2026-07-18T00:00:00Z",
    }
    standalone_invalid = {
        **valid,
        "source": {
            **valid["source"],
            "provider": "self_managed_mongodb",
            "topology": "standalone",
            "cdc_supported": True,
            "cdc_mode": "change_stream_lookup",
        },
    }
    return json_artifact(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "corridor-profile-fixture-set",
            "schema_path": "contracts/corridors/mongodb-postgres-profile.schema.json",
            "cases": [
                {"name": "atlas-to-supabase", "expected": "valid", "document": valid},
                {
                    "name": "atlas-to-planetscale",
                    "expected": "valid",
                    "document": {
                        **valid,
                        "target": {
                            **valid["target"],
                            "provider": "planetscale_postgres",
                            "application_endpoint_selection_basis": "direct_endpoint_required",
                        },
                    },
                },
                {
                    "name": "supabase-supavisor-session-selected-by-workload",
                    "expected": "valid",
                    "document": {
                        **valid,
                        "target": {
                            **valid["target"],
                            "application_endpoint_mode": "session_pooler",
                            "application_endpoint_service": "supavisor",
                        },
                    },
                },
                {
                    "name": "supabase-supavisor-transaction-selected-by-workload",
                    "expected": "valid",
                    "document": {
                        **valid,
                        "target": {
                            **valid["target"],
                            "application_endpoint_mode": "transaction_pooler",
                            "application_endpoint_service": "supavisor",
                        },
                    },
                },
                {
                    "name": "planetscale-branch-specific-pgbouncer",
                    "expected": "valid",
                    "document": {
                        **valid,
                        "target": {
                            **valid["target"],
                            "provider": "planetscale_postgres",
                            "application_endpoint_mode": "transaction_pooler",
                            "application_endpoint_service": "pgbouncer",
                            "application_endpoint_branch_specific": True,
                            "application_endpoint_selection_basis": (
                                "transaction_semantics_and_branch_probe"
                            ),
                        },
                    },
                },
                {
                    "name": "direct-engine-endpoint-probe-refusal",
                    "expected": "valid",
                    "document": {
                        **valid,
                        "composition_outcome": "refused",
                        "fallback_or_refusal_reason": "target_endpoint_unsuitable",
                    },
                },
                {
                    "name": "standalone-cdc-claim-denied",
                    "expected": "invalid",
                    "expected_error": "standalone_requires_freeze",
                    "document": standalone_invalid,
                },
                {
                    "name": "unsupported-target-family-denied",
                    "expected": "invalid",
                    "expected_error": "target.provider.enum",
                    "document": {
                        **valid,
                        "target": {**valid["target"], "provider": "generic_postgres"},
                    },
                },
                {
                    "name": "pre-post-mode-without-capability-denied",
                    "expected": "invalid",
                    "expected_error": "pre_post_images_supported.const",
                    "document": {
                        **valid,
                        "source": {
                            **valid["source"],
                            "pre_post_images_supported": False,
                        },
                    },
                },
                {
                    "name": "lookup-mode-cannot-claim-pre-images",
                    "expected": "invalid",
                    "expected_error": "pre_post_images_supported.const",
                    "document": {
                        **valid,
                        "source": {
                            **valid["source"],
                            "cdc_mode": "change_stream_lookup",
                            "pre_post_images_supported": True,
                        },
                    },
                },
                {
                    "name": "freeze-mode-cannot-claim-cdc",
                    "expected": "invalid",
                    "expected_error": "cdc_supported.const",
                    "document": {
                        **valid,
                        "source": {
                            **valid["source"],
                            "cdc_mode": "freeze_only",
                            "cdc_supported": True,
                            "pre_post_images_supported": False,
                        },
                    },
                },
                {
                    "name": "engine-admin-pooler-denied",
                    "expected": "invalid",
                    "expected_error": "engine_endpoint_mode.const",
                    "document": {
                        **valid,
                        "target": {
                            **valid["target"],
                            "engine_endpoint_mode": "transaction_pooler",
                        },
                    },
                },
                {
                    "name": "supabase-pooler-must-be-supavisor",
                    "expected": "invalid",
                    "expected_error": "application_endpoint_service.const",
                    "document": {
                        **valid,
                        "target": {
                            **valid["target"],
                            "application_endpoint_mode": "transaction_pooler",
                            "application_endpoint_service": "pgbouncer",
                        },
                    },
                },
                {
                    "name": "planetscale-pgbouncer-must-be-branch-specific",
                    "expected": "invalid",
                    "expected_error": "application_endpoint_branch_specific.const",
                    "document": {
                        **valid,
                        "target": {
                            **valid["target"],
                            "provider": "planetscale_postgres",
                            "application_endpoint_mode": "transaction_pooler",
                            "application_endpoint_service": "pgbouncer",
                            "application_endpoint_branch_specific": False,
                            "application_endpoint_selection_basis": (
                                "transaction_semantics_and_branch_probe"
                            ),
                        },
                    },
                },
                {
                    "name": "planetscale-session-pooling-is-not-a-released-shape",
                    "expected": "invalid",
                    "expected_error": "application_endpoint_mode.enum",
                    "document": {
                        **valid,
                        "target": {
                            **valid["target"],
                            "provider": "planetscale_postgres",
                            "application_endpoint_mode": "session_pooler",
                            "application_endpoint_service": "pgbouncer",
                            "application_endpoint_branch_specific": True,
                            "application_endpoint_selection_basis": (
                                "transaction_semantics_and_branch_probe"
                            ),
                        },
                    },
                },
                {
                    "name": "supported-profile-requires-live-cdc",
                    "expected": "invalid",
                    "expected_error": "cdc_supported.const",
                    "document": {
                        **valid,
                        "source": {
                            **valid["source"],
                            "snapshot_rung": "freeze_only",
                            "cdc_mode": "freeze_only",
                            "cdc_supported": False,
                            "pre_post_images_supported": False,
                        },
                    },
                },
                {
                    "name": "supported-profile-requires-branching",
                    "expected": "invalid",
                    "expected_error": "branching_supported.const",
                    "document": {
                        **valid,
                        "target": {
                            **valid["target"],
                            "branching_supported": False,
                        },
                    },
                },
            ],
        },
        "application/json",
    )


def artifacts() -> dict[str, Artifact]:
    """Return deterministic core/cell artifacts keyed by repository-relative path."""

    schemas = {
        "contracts/crypto/signature-envelope.schema.json": _signature_envelope_schema(),
        "contracts/crypto/public-key-registry.schema.json": _public_key_registry_schema(),
        "contracts/audit/checkpoint.schema.json": _audit_checkpoint_schema(),
        "contracts/mapping/mapping-spec.schema.json": _mapping_spec_schema(),
        "contracts/verification/verification-rubric.schema.json": _verification_rubric_schema(),
        "contracts/workflow/attempt.schema.json": _attempt_schema(),
        "contracts/decisions/reversibility.schema.json": _reversibility_schema(),
        "contracts/corridors/mongodb-postgres-profile.schema.json": _corridor_profile_schema(),
        "contracts/placement/placement-decision.schema.json": _placement_decision_schema(),
        "contracts/cell/custody-bootstrap-manifest.schema.json": _custody_bootstrap_manifest_schema(),
        "contracts/cell/deployment-manifest.schema.json": _deployment_manifest_schema(),
        "contracts/cell/bootstrap.schema.json": _cell_bootstrap_schema(),
        "contracts/cell/certificate-request.schema.json": _certificate_request_schema(),
        "contracts/cell/certificate-receipt.schema.json": _certificate_receipt_schema(),
        "contracts/cell/certificate-recovery-renewal.schema.json": _certificate_recovery_renewal_schema(),
        "contracts/cell/crl-publication.schema.json": _crl_publication_schema(),
        "contracts/cell/release-binding.schema.json": _release_binding_schema(),
        "contracts/cell/release-upgrade.schema.json": _release_upgrade_schema(),
        "contracts/recovery/control-region-failover-manifest.schema.json": _control_region_failover_manifest_schema(),
        "contracts/lifecycle/cell-command.schema.json": _cell_command_schema(),
        "contracts/lifecycle/cell-receipt.schema.json": _cell_receipt_schema(),
        "contracts/engine/operation-envelope.schema.json": _engine_operation_envelope_schema(),
        "contracts/engine/checkpoint.schema.json": _engine_checkpoint_schema(),
        "contracts/engine/receipt.schema.json": _engine_receipt_schema(),
        "contracts/workflow/migration-state-machine.schema.json": _migration_state_machine_schema(),
        "contracts/workflow/traffic-authority-state-machine.schema.json": _traffic_authority_state_machine_schema(),
        "contracts/workflow/decision-state-machine.schema.json": _decision_state_machine_schema(),
        "contracts/workflow/consent-state-machine.schema.json": _consent_state_machine_schema(),
        "contracts/workflow/artifact-state-machine.schema.json": _artifact_state_machine_schema(),
        "contracts/workflow/cell-state-machine.schema.json": _cell_state_machine_schema(),
        "contracts/workflow/attempt-state-machine.schema.json": _attempt_state_machine_schema(),
        "contracts/workflow/operation-state-machine.schema.json": _operation_state_machine_schema(),
        "contracts/decisions/reversibility-state-machine.schema.json": _reversibility_state_machine_schema(),
    }
    result = {path: json_artifact(document) for path, document in schemas.items()}
    result.update(
        {
            "contracts/cell/certificate-profile.yaml": _certificate_profile(),
            "contracts/cell/crl-profile.yaml": _crl_profile(),
            "contracts/fixtures/core/certificate.json": _certificate_fixtures(),
            "contracts/fixtures/core/control-region-failover.json": _failover_fixtures(),
            "contracts/fixtures/core/corridor-profile.json": _corridor_fixtures(),
            "contracts/fixtures/core/reversibility-taxonomy.json": _reversibility_fixtures(),
            "contracts/fixtures/core/attempt.json": _attempt_fixtures(),
        }
    )

    migration_state_dimensions = {
        **{state: "primary_phase" for state in _MIGRATION_PHASE_STATES},
        **{state: "execution_status" for state in _MIGRATION_EXECUTION_STATES},
    }
    transition_sets = (
        (
            "migration",
            "workflow/migration-state-machine.schema.json",
            _MIGRATION_PHASE_STATES + _MIGRATION_EXECUTION_STATES,
            _MIGRATION_EDGES,
            _MIGRATION_DOMAINS,
            migration_state_dimensions,
        ),
        ("traffic-authority", "workflow/traffic-authority-state-machine.schema.json", _TRAFFIC_STATES, _TRAFFIC_EDGES, None, None),
        ("decision", "workflow/decision-state-machine.schema.json", _DECISION_STATES, _DECISION_EDGES, None, None),
        ("consent", "workflow/consent-state-machine.schema.json", _CONSENT_STATES, _CONSENT_EDGES, None, None),
        ("artifact", "workflow/artifact-state-machine.schema.json", _ARTIFACT_STATES, _ARTIFACT_EDGES, None, None),
        ("cell", "workflow/cell-state-machine.schema.json", _CELL_STATES, _CELL_EDGES, None, None),
        ("attempt", "workflow/attempt-state-machine.schema.json", _ATTEMPT_STATES, _ATTEMPT_EDGES, None, None),
        ("operation", "workflow/operation-state-machine.schema.json", _OPERATION_STATES, _OPERATION_EDGES, None, None),
        ("reversibility", "decisions/reversibility-state-machine.schema.json", _REVERSIBILITY_STATES, _REVERSIBILITY_EDGES, None, None),
    )
    for name, path, states, edges, dimensions, state_dimensions in transition_sets:
        result[f"contracts/fixtures/state-machines/{name}.json"] = _transition_fixture(
            f"contracts/{path}",
            name.replace("-", "_"),
            states,
            edges,
            dimensions=dimensions,
            state_dimensions=state_dimensions,
        )
    return result
