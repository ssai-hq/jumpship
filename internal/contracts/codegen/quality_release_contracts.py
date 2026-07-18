"""P02 agent, quality, release, proof, and recovery contract declarations.

The declarations in this module are intentionally data-only.  They freeze the
interoperability and authority boundaries consumed by later packets without
implementing runtime policy, persistence, signing, activation, or recovery.
All payload collections are bounded and all nested objects are closed.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from model import (
    Artifact,
    HASH_PATTERN,
    RFC3339_PATTERN,
    SEMVER_PATTERN,
    UUID_PATTERN,
    json_artifact,
    nullable,
    s_array,
    s_boolean,
    s_integer,
    s_number,
    s_object,
    s_string,
    schema,
)


MAX_TEXT = 4096
MAX_SAFE_SUMMARY = 1024
ENVIRONMENTS = ("local", "nonprod", "staging", "production")
PROMOTION_ENVIRONMENTS = (*ENVIRONMENTS, "isolated-quality")
STAGES = ("local", "ephemeral", "persistent", "paid")
DEPLOYMENT_PROFILES = (
    "local",
    "ephemeral-nonprod",
    "persistent-nonprod",
    "paid-production",
)
PRODUCTION_REUSE_RUBRIC_IDS = tuple(
    f"JSMVP-R{number:03d}"
    for number in (
        *range(1, 29),
        *range(35, 43),
        *range(45, 54),
        *range(68, 82),
    )
)
BEDROCK_CLAUDE_ARN_PATTERN = (
    r"^arn:aws(?:-us-gov)?:bedrock:[a-z]{2}(?:-gov)?-[a-z]+-[0-9]::"
    r"foundation-model/anthropic\.claude[A-Za-z0-9._:-]+$"
)


def _uuid() -> dict[str, Any]:
    return s_string(pattern=UUID_PATTERN)


def _hash() -> dict[str, Any]:
    return s_string(pattern=HASH_PATTERN)


def _content_id() -> dict[str, Any]:
    """A lowercase SHA-256 typed ID derived from the logical payload."""

    return _hash()


def _time() -> dict[str, Any]:
    return s_string(pattern=RFC3339_PATTERN, fmt="date-time")


def _semver() -> dict[str, Any]:
    return s_string(pattern=SEMVER_PATTERN)


def _text(max_length: int = MAX_TEXT) -> dict[str, Any]:
    return s_string(min_length=1, max_length=max_length)


def _false() -> dict[str, Any]:
    return {"type": "boolean", "const": False}


def _true() -> dict[str, Any]:
    return {"type": "boolean", "const": True}


def _canonical_identity_fields(
    object_type: str,
    id_field: str,
    *,
    additional_excluded_fields: tuple[str, ...] = (),
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Declare the non-recursive JCS projection used for a typed content ID.

    The projection descriptor and digest are storage metadata, not members of
    the logical payload.  Runtime constructors/verifiers must additionally
    prove that ``id_field == logical_payload_sha256`` after applying the typed
    domain separator.
    """

    excluded_fields = (
        id_field,
        "content_sha256",
        "logical_payload_sha256",
        "logical_payload_projection",
        *additional_excluded_fields,
    )
    fields = {
        "logical_payload_sha256": _hash(),
        "logical_payload_projection": s_object(
            {
                "object_type": s_string(const=object_type),
                "id_field": s_string(const=id_field),
                "object_schema_version": s_string(const="1.0.0"),
                "canonical_encoder": s_string(const="RFC8785_JCS"),
                "domain_separator": s_string(
                    const=f"jumpship:{object_type}:1.0.0\u0000"
                ),
                "excluded_fields": {
                    "type": "array",
                    "const": list(dict.fromkeys(excluded_fields)),
                    "minItems": len(dict.fromkeys(excluded_fields)),
                    "maxItems": len(dict.fromkeys(excluded_fields)),
                },
                "id_encoding": s_string(const="lowercase_hex_sha256"),
                "id_equals_logical_payload_sha256": _true(),
            },
            (
                "object_type",
                "id_field",
                "object_schema_version",
                "canonical_encoder",
                "domain_separator",
                "excluded_fields",
                "id_encoding",
                "id_equals_logical_payload_sha256",
            ),
        ),
    }
    return fields, tuple(fields)


def _digest_ref(kind_values: tuple[str, ...] | list[str]) -> dict[str, Any]:
    return s_object(
        {
            "kind": s_string(enum=kind_values),
            "object_id": _text(256),
            "version": _text(128),
            "sha256": _hash(),
        },
        ("kind", "object_id", "version", "sha256"),
    )


def _environment_digest_ref(kind: str, environment: str) -> dict[str, Any]:
    return s_object(
        {
            "kind": s_string(const=kind),
            "environment": s_string(const=environment),
            "object_id": _text(256),
            "version": _text(128),
            "sha256": _hash(),
        },
        ("kind", "environment", "object_id", "version", "sha256"),
    )


def _approval(roles: tuple[str, ...] | list[str]) -> dict[str, Any]:
    return s_object(
        {
            "role": s_string(enum=roles),
            "approver_id": _text(256),
            "decision": s_string(enum=("approved", "denied")),
            "evidence_root": _hash(),
            "approved_at": _time(),
        },
        ("role", "approver_id", "decision", "evidence_root", "approved_at"),
    )


def _schema_artifact(
    path: str,
    title: str,
    properties: dict[str, Any],
    required: tuple[str, ...] | list[str],
    *,
    data_class: str,
    max_bytes: int,
    flow_ids: tuple[str, ...] | list[str],
    description: str,
    one_of: list[dict[str, Any]] | None = None,
    all_of: list[dict[str, Any]] | None = None,
    definitions: dict[str, Any] | None = None,
    semantic_invariants: tuple[str, ...] | list[str] = (),
) -> Artifact:
    document = schema(
        path,
        title,
        properties,
        required,
        data_class=data_class,
        max_bytes=max_bytes,
        flow_ids=flow_ids,
        description=description,
        definitions=definitions,
    )
    if one_of is not None:
        # Keep each conditional branch self-describing.  Besides making the
        # shape legible in the emitted contract, this lets the deterministic
        # fixture synthesizer materialize branch-required fields without
        # weakening the closed root object.
        document["oneOf"] = [
            {
                **branch,
                "properties": {
                    **{
                        field: properties[field]
                        for field in branch.get("required", [])
                        if field in properties
                    },
                    **branch.get("properties", {}),
                },
            }
            for branch in one_of
        ]
    if all_of is not None:
        document["allOf"] = all_of
    if semantic_invariants:
        document["x-jumpship-semantic-invariants"] = list(semantic_invariants)
    return json_artifact(document)


def _forbid(*fields: str) -> dict[str, Any]:
    return {"not": {"anyOf": [{"required": [field]} for field in fields]}}


def _branch(
    *,
    required: tuple[str, ...] | list[str],
    constants: dict[str, Any],
    forbidden: tuple[str, ...] = (),
    property_constraints: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "required": list(required),
        "properties": {
            **{name: {"const": value} for name, value in constants.items()},
            **(property_constraints or {}),
        },
    }
    if forbidden:
        result.update(_forbid(*forbidden))
    return result


def _required_kind_constraints(
    field: str,
    kinds: tuple[str, ...],
    *,
    singleton_kinds: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    singleton = set(singleton_kinds)
    constraints: list[dict[str, Any]] = []
    for kind in kinds:
        contains: dict[str, Any] = {
            "contains": {
                "properties": {"kind": {"const": kind}},
                "required": ["kind"],
            },
            "minContains": 1,
        }
        if kind in singleton:
            contains["maxContains"] = 1
        constraints.append({"properties": {field: contains}})
    return constraints


def _required_kind_array_schema(
    kinds: tuple[str, ...],
    *,
    singleton_kinds: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "allOf": [
            constraint["properties"]["items"]
            for constraint in _required_kind_constraints(
                "items", kinds, singleton_kinds=singleton_kinds
            )
        ]
    }


def _exact_discriminator_array_constraint(
    discriminator: str,
    values: tuple[str, ...],
) -> dict[str, Any]:
    """Require every discriminator value exactly once in a bounded array."""

    return {
        "minItems": len(values),
        "maxItems": len(values),
        "allOf": [
            {
                "contains": {
                    "properties": {discriminator: {"const": value}},
                    "required": [discriminator],
                },
                "minContains": 1,
                "maxContains": 1,
            }
            for value in values
        ],
    }


def _environment_profile_branches() -> list[dict[str, Any]]:
    return [
        _branch(
            required=(),
            constants={
                "environment": environment,
                "stage": stage,
                "deployment_profile_id": profile,
            },
        )
        for environment, stage, profile in (
            ("local", "local", "local"),
            ("nonprod", "ephemeral", "ephemeral-nonprod"),
            ("staging", "persistent", "persistent-nonprod"),
            ("production", "paid", "paid-production"),
        )
    ]


def _agent_artifacts() -> dict[str, Artifact]:
    result: dict[str, Artifact] = {}

    result["contracts/agent/runtime.schema.json"] = _schema_artifact(
        "agent/runtime.schema.json",
        "Agent Runtime Contract",
        {
            "runtime_id": _text(128),
            "runtime_version": _semver(),
            "adapter_kind": s_string(enum=("custom_reference_loop", "conformance_adapter")),
            "checkpoint_schema_hash": _hash(),
            "supported_checkpoint_versions": s_array(_semver(), min_items=1, max_items=16, unique=True),
            "max_model_iterations_per_run": s_integer(minimum=1, maximum=64),
            "max_run_seconds": s_integer(minimum=1, maximum=86400),
            "execution_contract": s_object(
                {
                    "single_active_lease": _true(),
                    "sequential_inline_observations": _true(),
                    "parallel_observations_allowed": _false(),
                    "durable_before_consequence": _true(),
                    "model_driven_cdc_or_watch": _false(),
                },
                (
                    "single_active_lease",
                    "sequential_inline_observations",
                    "parallel_observations_allowed",
                    "durable_before_consequence",
                    "model_driven_cdc_or_watch",
                ),
            ),
            "binary_sha256": _hash(),
        },
        (
            "runtime_id",
            "runtime_version",
            "adapter_kind",
            "checkpoint_schema_hash",
            "supported_checkpoint_versions",
            "max_model_iterations_per_run",
            "max_run_seconds",
            "execution_contract",
            "binary_sha256",
        ),
        data_class="internal_operational",
        max_bytes=32768,
        flow_ids=("F17", "F22"),
        description="Framework-neutral runtime and bounded durable-loop compatibility contract.",
    )

    result["contracts/agent/provider.schema.json"] = _schema_artifact(
        "agent/provider.schema.json",
        "Agent Provider Adapter Contract",
        {
            "provider_id": _text(128),
            "provider_kind": s_string(enum=("amazon_bedrock",)),
            "model_id": s_string(pattern=BEDROCK_CLAUDE_ARN_PATTERN, max_length=512),
            "model_revision": _text(128),
            "aws_region": s_string(pattern=r"^[a-z]{2}-[a-z]+-[0-9]$"),
            "route_id": _text(128),
            "route_config_hash": _hash(),
            "provider_data_use_record_id": _content_id(),
            "provider_data_use_record_hash": _hash(),
            "request_schema_hash": _hash(),
            "result_schema_hash": _hash(),
            "error_codes": s_array(
                s_string(
                    enum=(
                        "route_unavailable",
                        "provider_review_invalid",
                        "provider_hold_open",
                        "provider_lease_expired",
                        "budget_exhausted",
                        "context_rejected",
                    )
                ),
                min_items=1,
                max_items=16,
                unique=True,
            ),
            "max_input_bytes": s_integer(minimum=1, maximum=8_388_608),
            "max_output_bytes": s_integer(minimum=1, maximum=2_097_152),
            "public_fallback_allowed": _false(),
            "cross_region_inference_allowed": _false(),
            "contains_credentials": _false(),
        },
        (
            "provider_id",
            "provider_kind",
            "model_id",
            "model_revision",
            "aws_region",
            "route_id",
            "route_config_hash",
            "provider_data_use_record_id",
            "provider_data_use_record_hash",
            "request_schema_hash",
            "result_schema_hash",
            "error_codes",
            "max_input_bytes",
            "max_output_bytes",
            "public_fallback_allowed",
            "cross_region_inference_allowed",
            "contains_credentials",
        ),
        data_class="internal_operational",
        max_bytes=32768,
        flow_ids=("F17", "F22"),
        description="Exact Bedrock model, region, route, data-use, and typed error seam; no body or credential fields.",
    )

    tool_data_classes = (
        "public",
        "internal_operational",
        "identity_tenant",
        "shared_migration",
        "restricted_customer",
        "credential_secret",
        "security_material",
    )
    inline_data_classes = (
        "public",
        "internal_operational",
        "identity_tenant",
        "shared_migration",
        "restricted_customer",
    )
    migration_phases = (
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
    capability_requirements = s_object(
        {
            "capability_ids": s_array(
                s_string(pattern=r"^MVP-CAP-[A-Z0-9][A-Z0-9-]+$"),
                min_items=1,
                max_items=32,
                unique=True,
            ),
            "grant_purposes": s_array(_text(128), min_items=1, max_items=16, unique=True),
        },
        ("capability_ids", "grant_purposes"),
    )
    retry_policy = s_object(
        {
            "strategy": s_string(enum=("never", "same_identity_only", "reconcile_then_retry")),
            "max_attempts": s_integer(minimum=1, maximum=16),
            "backoff_ms": s_integer(minimum=0, maximum=3_600_000),
            "retryable_error_codes": s_array(_text(128), max_items=32, unique=True),
            "requires_reconciliation": s_boolean(),
        },
        (
            "strategy",
            "max_attempts",
            "backoff_ms",
            "retryable_error_codes",
            "requires_reconciliation",
        ),
    )
    limits = s_object(
        {
            "max_input_bytes": s_integer(minimum=1, maximum=16_777_216),
            "max_output_bytes": s_integer(minimum=1, maximum=16_777_216),
            "max_memory_bytes": s_integer(minimum=1_048_576, maximum=17_179_869_184),
            "max_cpu_millis": s_integer(minimum=1, maximum=86_400_000),
            "max_wall_clock_ms": s_integer(minimum=1, maximum=86_400_000),
            "network_mode": s_string(enum=("none", "provider_allowlist", "cell_internal")),
            "max_artifacts": s_integer(minimum=0, maximum=256),
        },
        (
            "max_input_bytes",
            "max_output_bytes",
            "max_memory_bytes",
            "max_cpu_millis",
            "max_wall_clock_ms",
            "network_mode",
            "max_artifacts",
        ),
    )
    run_brief_authorization = s_object(
        {
            "inline_authorizable": s_boolean(),
            "descriptor_hash": _hash(),
            "authorized_descriptor_set_hash": _hash(),
            "max_cumulative_input_bytes": s_integer(minimum=1, maximum=16_777_216),
            "max_cumulative_output_bytes": s_integer(minimum=1, maximum=104_857_600),
            "max_cumulative_invocations": s_integer(minimum=1, maximum=1_024),
            "max_cumulative_wall_clock_ms": s_integer(minimum=1, maximum=3_600_000),
            "max_cumulative_cpu_millis": s_integer(minimum=1, maximum=3_600_000),
            "max_memory_bytes": s_integer(minimum=1_048_576, maximum=4_294_967_296),
            "max_rate_per_minute": s_integer(minimum=1, maximum=120),
            "allowed_data_classes": s_array(
                s_string(enum=inline_data_classes),
                min_items=1,
                max_items=len(inline_data_classes),
                unique=True,
            ),
            "may_widen_to_durable": s_boolean(),
        },
        (
            "inline_authorizable",
            "descriptor_hash",
            "authorized_descriptor_set_hash",
            "max_cumulative_input_bytes",
            "max_cumulative_output_bytes",
            "max_cumulative_invocations",
            "max_cumulative_wall_clock_ms",
            "max_cumulative_cpu_millis",
            "max_memory_bytes",
            "max_rate_per_minute",
            "allowed_data_classes",
            "may_widen_to_durable",
        ),
    )
    tool_properties = {
        "tool_id": _text(128),
        "tool_version": _semver(),
        "display_summary": _text(256),
        "drilldown_description": _text(2048),
        "allowed_phases": s_array(
            s_string(enum=migration_phases), min_items=1, max_items=len(migration_phases), unique=True
        ),
        "execution_mode": s_string(enum=("inline", "durable")),
        "consequence_class": s_string(
            enum=("observation", "reversible_effect", "closing_door", "irreversible_effect")
        ),
        "reversibility_class": s_string(
            enum=(
                "not_applicable",
                "free_until_cutover",
                "expensive_after_cutover",
                "closes_on_first_external_exposure",
                "closes_on_a_clock",
                "never_reversible",
            )
        ),
        "warning_rule": s_string(
            enum=(
                "none",
                "before_first_effect",
                "before_external_exposure",
                "before_clock_closure",
                "before_irreversible_effect",
            )
        ),
        "safe_failure": s_string(
            enum=("grant_no_effect_authority", "retain_current_authority", "block_effect", "issue_no_external_capability")
        ),
        "input_schema_hash": _hash(),
        "output_schema_hash": _hash(),
        "receipt_schema_id": s_string(
            pattern=r"^https://jumpship\.dev/contracts/[A-Za-z0-9_./-]+\.schema\.json$",
            max_length=512,
        ),
        "receipt_schema_hash": _hash(),
        "capability_requirements": capability_requirements,
        "gate_requirements": s_array(_text(128), max_items=32, unique=True),
        "consent_requirement": s_string(enum=("none", "cutover", "decommission")),
        "idempotency_scope": s_string(
            enum=("none_read_only", "operation", "operation_and_input", "external_effect_identity")
        ),
        "timeout_ms": s_integer(minimum=1, maximum=86_400_000),
        "retry_policy": retry_policy,
        "limits": limits,
        "input_data_class": s_string(enum=tool_data_classes),
        "output_data_class": s_string(enum=tool_data_classes),
        "run_brief_authorization": run_brief_authorization,
    }
    result["contracts/agent/tool.schema.json"] = _schema_artifact(
        "agent/tool.schema.json",
        "Agent Tool Descriptor Contract",
        tool_properties,
        tuple(tool_properties),
        data_class="internal_operational",
        max_bytes=32768,
        flow_ids=("F17", "F18"),
        description=(
            "Versioned bounded tool descriptor with exact schemas, capability/gate/consent "
            "requirements, retry/idempotency, resource limits, data classes, receipt contract, "
            "and non-widening RunBrief inline authorization."
        ),
        one_of=[
            {
                "properties": {
                    "execution_mode": {"const": "inline"},
                    "consequence_class": {"const": "observation"},
                    "reversibility_class": {"const": "not_applicable"},
                    "warning_rule": {"const": "none"},
                    "safe_failure": {"const": "grant_no_effect_authority"},
                    "consent_requirement": {"const": "none"},
                    "idempotency_scope": {"const": "none_read_only"},
                    "input_data_class": {"enum": list(inline_data_classes)},
                    "output_data_class": {"enum": list(inline_data_classes)},
                    "limits": {
                        "properties": {"network_mode": {"const": "none"}}
                    },
                    "run_brief_authorization": {
                        "properties": {
                            "inline_authorizable": {"const": True},
                            "may_widen_to_durable": {"const": False},
                        }
                    },
                }
            },
            {
                "properties": {
                    "execution_mode": {"const": "durable"},
                    "run_brief_authorization": {
                        "properties": {
                            "inline_authorizable": {"const": False},
                            "may_widen_to_durable": {"const": False},
                        }
                    },
                }
            },
        ],
        all_of=[
            {
                "if": {"properties": {"consequence_class": {"const": "reversible_effect"}}},
                "then": {
                    "properties": {
                        "reversibility_class": {"enum": ["free_until_cutover", "expensive_after_cutover"]},
                        "warning_rule": {"enum": ["none", "before_first_effect"]},
                        "safe_failure": {"const": "retain_current_authority"},
                    }
                },
            },
            {
                "if": {"properties": {"consequence_class": {"const": "closing_door"}}},
                "then": {
                    "properties": {
                        "reversibility_class": {"enum": ["closes_on_first_external_exposure", "closes_on_a_clock"]},
                        "warning_rule": {"enum": ["before_external_exposure", "before_clock_closure"]},
                        "safe_failure": {"enum": ["block_effect", "issue_no_external_capability"]},
                    }
                },
            },
            {
                "if": {"properties": {"consequence_class": {"const": "irreversible_effect"}}},
                "then": {
                    "properties": {
                        "reversibility_class": {"const": "never_reversible"},
                        "warning_rule": {"const": "before_irreversible_effect"},
                        "safe_failure": {"const": "block_effect"},
                    }
                },
            },
        ],
    )

    result["contracts/agent/capability-grant.schema.json"] = _schema_artifact(
        "agent/capability-grant.schema.json",
        "Agent Capability Grant Contract",
        {
            "grant_id": _uuid(),
            "workspace_id": _uuid(),
            "migration_id": _uuid(),
            "cell_id": _uuid(),
            "cell_generation": s_integer(minimum=1),
            "run_id": _uuid(),
            "operation_id": _uuid(),
            "tool_id": _text(128),
            "tool_version": _semver(),
            "execution_mode": s_string(enum=("inline", "durable")),
            "consequence_class": s_string(
                enum=("observation", "reversible_effect", "closing_door", "irreversible_effect")
            ),
            "scope_root": _hash(),
            "input_hash": _hash(),
            "control_epoch": s_integer(minimum=1),
            "issued_at": _time(),
            "expires_at": _time(),
            "nonce_hash": _hash(),
            "signature_purpose": s_string(const="agent_capability_grant"),
            "signature_envelope_hash": _hash(),
        },
        (
            "grant_id",
            "workspace_id",
            "migration_id",
            "cell_id",
            "cell_generation",
            "run_id",
            "operation_id",
            "tool_id",
            "tool_version",
            "execution_mode",
            "consequence_class",
            "scope_root",
            "input_hash",
            "control_epoch",
            "issued_at",
            "expires_at",
            "nonce_hash",
            "signature_purpose",
            "signature_envelope_hash",
        ),
        data_class="security_material",
        max_bytes=65536,
        flow_ids=("F17", "F18"),
        description="Exact backend authorization for one bounded tool invocation; it cannot widen descriptor mode.",
    )

    tool_receipt_identity, tool_receipt_identity_required = _canonical_identity_fields(
        "tool_receipt",
        "receipt_id",
        additional_excluded_fields=("signature_envelope_hash",),
    )
    result["contracts/agent/tool-receipt.schema.json"] = _schema_artifact(
        "agent/tool-receipt.schema.json",
        "Agent Tool Receipt Contract",
        {
            "receipt_id": _content_id(),
            "grant_id": _uuid(),
            "grant_hash": _hash(),
            "run_id": _uuid(),
            "operation_id": _uuid(),
            "tool_id": _text(128),
            "tool_version": _semver(),
            "execution_mode": s_string(enum=("inline", "durable")),
            "consequence_class": s_string(
                enum=("observation", "reversible_effect", "closing_door", "irreversible_effect")
            ),
            "status": s_string(enum=("succeeded", "failed", "denied", "timed_out", "reconciled")),
            "request_hash": _hash(),
            "output_hash": nullable(_hash()),
            "effect_identity": nullable(_text(256)),
            "grant_policy_hash": _hash(),
            "executor_image_digest": _hash(),
            "executor_tool_digest": _hash(),
            "safe_summary": _text(MAX_SAFE_SUMMARY),
            "retryable": s_boolean(),
            "target_commit_hash": nullable(_hash()),
            "write_epoch_receipt_hash": nullable(_hash()),
            "causation_id": _uuid(),
            "correlation_id": _uuid(),
            "trace_id": _text(128),
            "no_authority_conferred": _true(),
            "started_at": _time(),
            "finished_at": _time(),
            "previous_receipt_hash": nullable(_hash()),
            "signature_envelope_hash": _hash(),
            **tool_receipt_identity,
        },
        (
            "receipt_id",
            "grant_id",
            "grant_hash",
            "run_id",
            "operation_id",
            "tool_id",
            "tool_version",
            "execution_mode",
            "consequence_class",
            "status",
            "request_hash",
            "output_hash",
            "effect_identity",
            "grant_policy_hash",
            "executor_image_digest",
            "executor_tool_digest",
            "safe_summary",
            "retryable",
            "target_commit_hash",
            "write_epoch_receipt_hash",
            "causation_id",
            "correlation_id",
            "trace_id",
            "no_authority_conferred",
            "started_at",
            "finished_at",
            "previous_receipt_hash",
            "signature_envelope_hash",
            *tool_receipt_identity_required,
        ),
        data_class="restricted_customer",
        max_bytes=131072,
        flow_ids=("F17", "F18"),
        description="Append-only terminal receipt for one exact capability grant and tool request.",
        one_of=[
            _branch(
                required=(),
                constants={
                    "execution_mode": "inline",
                    "consequence_class": "observation",
                    "effect_identity": None,
                    "target_commit_hash": None,
                    "write_epoch_receipt_hash": None,
                    "no_authority_conferred": True,
                },
            ),
            _branch(
                required=(),
                constants={
                    "execution_mode": "durable",
                    "no_authority_conferred": True,
                },
            ),
        ],
    )

    result["contracts/agent/checkpoint.schema.json"] = _schema_artifact(
        "agent/checkpoint.schema.json",
        "Agent Durable Checkpoint Contract",
        {
            "checkpoint_id": _uuid(),
            "checkpoint_version": _semver(),
            "run_id": _uuid(),
            "iteration_sequence": s_integer(minimum=1),
            "lease_epoch": s_integer(minimum=1),
            "lease_expires_at": _time(),
            "event_root": _hash(),
            "prior_checkpoint_hash": nullable(_hash()),
            "context_manifest_id": _uuid(),
            "context_manifest_hash": _hash(),
            "pending_outcome": s_string(
                enum=("continue", "wait", "decision", "effect_request", "complete", "failed")
            ),
            "steering_sequence": s_integer(minimum=0),
            "budget": s_object(
                {
                    "model_calls_used": s_integer(minimum=0, maximum=64),
                    "model_calls_limit": s_integer(minimum=1, maximum=64),
                    "elapsed_seconds": s_integer(minimum=0, maximum=86400),
                    "elapsed_limit_seconds": s_integer(minimum=1, maximum=86400),
                },
                (
                    "model_calls_used",
                    "model_calls_limit",
                    "elapsed_seconds",
                    "elapsed_limit_seconds",
                ),
            ),
            "created_at": _time(),
        },
        (
            "checkpoint_id",
            "checkpoint_version",
            "run_id",
            "iteration_sequence",
            "lease_epoch",
            "lease_expires_at",
            "event_root",
            "prior_checkpoint_hash",
            "context_manifest_id",
            "context_manifest_hash",
            "pending_outcome",
            "steering_sequence",
            "budget",
            "created_at",
        ),
        data_class="restricted_customer",
        max_bytes=262144,
        flow_ids=("F17",),
        description="Per-completed-iteration durable checkpoint using the existing run/event/checkpoint timeline.",
    )

    context_item = s_object(
        {
            "item_id": _text(256),
            "item_kind": s_string(
                enum=("projection", "decision", "artifact", "evidence", "memory", "steering", "policy")
            ),
            "content_hash": _hash(),
            "data_class": s_string(
                enum=(
                    "public",
                    "internal_operational",
                    "identity_tenant",
                    "shared_migration",
                    "restricted_customer",
                )
            ),
            "source_root": _hash(),
            "sequence": s_integer(minimum=0),
            "token_count": s_integer(minimum=0, maximum=2_000_000),
        },
        ("item_id", "item_kind", "content_hash", "data_class", "source_root", "sequence", "token_count"),
    )
    result["contracts/agent/context-manifest.schema.json"] = _schema_artifact(
        "agent/context-manifest.schema.json",
        "Agent Context Manifest Contract",
        {
            "context_manifest_id": _uuid(),
            "run_id": _uuid(),
            "iteration_sequence": s_integer(minimum=1),
            "posture": s_string(enum=("design", "migration_ops")),
            "task_kind": _text(128),
            "items": s_array(context_item, min_items=1, max_items=4096),
            "ordering_algorithm": s_string(const="priority-kind-stable-id-v1"),
            "manifest_root": _hash(),
            "compiled_at": _time(),
        },
        (
            "context_manifest_id",
            "run_id",
            "iteration_sequence",
            "posture",
            "task_kind",
            "items",
            "ordering_algorithm",
            "manifest_root",
            "compiled_at",
        ),
        data_class="restricted_customer",
        max_bytes=2_097_152,
        flow_ids=("F17", "F22"),
        description="Deterministically ordered context inventory with stable identities and hashes for each model call.",
    )

    trajectory_event = s_object(
        {
            "sequence": s_integer(minimum=1),
            "event_kind": _text(128),
            "occurred_at": _time(),
            "safe_summary": _text(MAX_SAFE_SUMMARY),
            "event_root": _hash(),
            "context_manifest_hash": nullable(_hash()),
            "tool_receipt_hash": nullable(_hash()),
        },
        (
            "sequence",
            "event_kind",
            "occurred_at",
            "safe_summary",
            "event_root",
            "context_manifest_hash",
            "tool_receipt_hash",
        ),
    )
    result["contracts/agent/trajectory.schema.json"] = _schema_artifact(
        "agent/trajectory.schema.json",
        "Sanitized Agent Trajectory Export Contract",
        {
            "trajectory_id": _uuid(),
            "bundle_id": _content_id(),
            "run_id": _uuid(),
            "postures_observed": s_array(
                s_string(enum=("design", "migration_ops")), min_items=1, max_items=2, unique=True
            ),
            "events": s_array(trajectory_event, min_items=1, max_items=4096),
            "sanitizer_version": _semver(),
            "sanitizer_policy_hash": _hash(),
            "trajectory_root": _hash(),
            "contains_raw_evidence": _false(),
        },
        (
            "trajectory_id",
            "bundle_id",
            "run_id",
            "postures_observed",
            "events",
            "sanitizer_version",
            "sanitizer_policy_hash",
            "trajectory_root",
            "contains_raw_evidence",
        ),
        data_class="internal_operational",
        max_bytes=4_194_304,
        flow_ids=("F22", "F24"),
        description="Allowlisted trajectory projection for evaluation; raw evidence and chain-of-thought are excluded.",
    )

    bundle_component_kinds = (
        "harness_image",
        "runtime",
        "provider_adapter",
        "model_route",
        "prompt_bundle",
        "skill_bundle",
        "semantic_artifact_manifest",
        "context_compiler",
        "tool_catalog",
        "active_run_budget_profile",
        "analysis_runner_image",
        "analysis_runner_policy",
        "analysis_runner_descriptor",
        "corridor_profile",
        "provider_data_use_record",
        "checkpoint_compatibility",
        "sanitizer",
        "evaluator_contract",
    )
    agent_bundle_identity, agent_bundle_identity_required = _canonical_identity_fields(
        "agent_bundle",
        "agent_bundle_id",
        additional_excluded_fields=("created_at",),
    )
    result["contracts/agent/agent-bundle.schema.json"] = _schema_artifact(
        "agent/agent-bundle.schema.json",
        "Immutable Agent Bundle Contract",
        {
            "agent_bundle_id": _content_id(),
            "bundle_version": _semver(),
            "content_sha256": _hash(),
            "components": s_array(
                _digest_ref(bundle_component_kinds),
                min_items=len(bundle_component_kinds),
                max_items=len(bundle_component_kinds),
                unique=True,
            ),
            "runtime_contract_hash": _hash(),
            "tool_catalog_hash": _hash(),
            "provider_data_use_record_id": _content_id(),
            "provider_data_use_record_hash": _hash(),
            "supported_release_unit_schema_hash": _hash(),
            "created_at": _time(),
            **agent_bundle_identity,
        },
        (
            "agent_bundle_id",
            "bundle_version",
            "content_sha256",
            "components",
            "runtime_contract_hash",
            "tool_catalog_hash",
            "provider_data_use_record_id",
            "provider_data_use_record_hash",
            "supported_release_unit_schema_hash",
            "created_at",
            *agent_bundle_identity_required,
        ),
        data_class="internal_operational",
        max_bytes=131072,
        flow_ids=("F22", "F24"),
        description="Content-addressed executable agent component set; provenance signatures remain detached.",
        all_of=_required_kind_constraints(
            "components",
            bundle_component_kinds,
            singleton_kinds=bundle_component_kinds,
        ),
    )

    provider_record_identity, _ = _canonical_identity_fields(
        "provider_data_use_record",
        "provider_data_use_record_id",
    )
    agreement_kinds = ("model_agreement", "model_eula")
    model_agreement = s_object(
        {
            "agreement_kind": s_string(enum=agreement_kinds),
            "agreement_id": _text(256),
            "agreement_version": _text(128),
            "agreement_sha256": _hash(),
            "source_url": s_string(fmt="uri", min_length=8, max_length=2048),
            "source_content_sha256": _hash(),
            "effective_at": _time(),
        },
        (
            "agreement_kind",
            "agreement_id",
            "agreement_version",
            "agreement_sha256",
            "source_url",
            "source_content_sha256",
            "effective_at",
        ),
    )
    official_source_kinds = (
        "aws_privacy",
        "aws_data_protection",
        "aws_data_retention",
        "aws_service_terms",
    )
    official_source = s_object(
        {
            "source_kind": s_string(enum=official_source_kinds),
            "source_url": s_string(fmt="uri", min_length=8, max_length=2048),
            "content_sha256": _hash(),
            "retrieved_at": _time(),
        },
        ("source_kind", "source_url", "content_sha256", "retrieved_at"),
    )
    provider_record_properties = {
        "provider_data_use_record_id": _content_id(),
        "record_version": _semver(),
        "provider": s_string(const="amazon_bedrock"),
        "aws_account_id": s_string(pattern=r"^[0-9]{12}$"),
        "region": s_string(pattern=r"^[a-z]{2}-[a-z]+-[0-9]$"),
        "api_surface": s_string(const="bedrock-runtime"),
        "model_family": s_string(const="anthropic.claude"),
        "model_id": s_string(pattern=BEDROCK_CLAUDE_ARN_PATTERN, max_length=512),
        "model_revision": _text(128),
        "route_config_hash": _hash(),
        "model_agreements": s_array(
            model_agreement,
            min_items=len(agreement_kinds),
            max_items=len(agreement_kinds),
            unique=True,
        ),
        "official_sources": s_array(
            official_source,
            min_items=len(official_source_kinds),
            max_items=len(official_source_kinds),
            unique=True,
        ),
        "official_source_inventory_root": _hash(),
        "terms_source_hash": _hash(),
        "data_use_policy_hash": _hash(),
        "configured_retention_mode": s_string(
            enum=("no_provider_retention", "provider_operational_retention")
        ),
        "configured_retention_max_days": s_integer(minimum=0, maximum=3650),
        "configured_retention_source_hash": _hash(),
        "provider_sharing_mode": s_string(const="disabled"),
        "no_training_basis": s_string(const="aws_service_terms_and_model_eula"),
        "no_training_basis_root": _hash(),
        "abuse_detection_disclosure": s_object(
            {
                "mode": s_string(
                    enum=(
                        "standard_automated_abuse_detection",
                        "provider_approved_opt_out",
                    )
                ),
                "retention_mode": s_string(
                    enum=("none", "provider_operational_retention")
                ),
                "maximum_retention_days": s_integer(minimum=0, maximum=3650),
                "disclosure_source_hash": _hash(),
            },
            (
                "mode",
                "retention_mode",
                "maximum_retention_days",
                "disclosure_source_hash",
            ),
        ),
        "training_use": s_string(const="prohibited"),
        "cross_region_allowed": _false(),
        "public_endpoint_allowed": _false(),
        "provider_data_sharing_allowed": _false(),
        "effective_at": _time(),
        "content_sha256": _hash(),
        **provider_record_identity,
    }
    result["contracts/agent/provider-data-use.schema.json"] = _schema_artifact(
        "agent/provider-data-use.schema.json",
        "Immutable Provider Data Use Record Contract",
        provider_record_properties,
        tuple(provider_record_properties),
        data_class="internal_operational",
        max_bytes=262144,
        flow_ids=("F17", "F22"),
        description=(
            "Immutable exact AWS account/region/Bedrock Runtime/Claude route, agreement, official-source, "
            "sharing, no-training, retention, and abuse-disclosure binding. Reviewers and review expiry "
            "are deliberately outside executable identity."
        ),
        all_of=[
            *[
                {
                    "properties": {
                        "model_agreements": {
                            "contains": {
                                "properties": {
                                    "agreement_kind": {"const": kind}
                                },
                                "required": ["agreement_kind"],
                            },
                            "minContains": 1,
                            "maxContains": 1,
                        }
                    }
                }
                for kind in agreement_kinds
            ],
            *[
                {
                    "properties": {
                        "official_sources": {
                            "contains": {
                                "properties": {"source_kind": {"const": kind}},
                                "required": ["source_kind"],
                            },
                            "minContains": 1,
                            "maxContains": 1,
                        }
                    }
                }
                for kind in official_source_kinds
            ],
            {
                "oneOf": [
                    _branch(
                        required=(),
                        constants={
                            "configured_retention_mode": "no_provider_retention",
                            "configured_retention_max_days": 0,
                        },
                    ),
                    _branch(
                        required=(),
                        constants={
                            "configured_retention_mode": "provider_operational_retention"
                        },
                        property_constraints={
                            "configured_retention_max_days": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 3650,
                            }
                        },
                    ),
                ]
            },
        ],
    )

    review_approval = _approval(("legal", "security", "product"))
    provider_review_identity, _ = _canonical_identity_fields(
        "provider_data_use_review",
        "review_id",
        additional_excluded_fields=("payload_hash",),
    )
    provider_review_properties = {
        "review_id": _content_id(),
        "provider_data_use_record_id": _content_id(),
        "provider_data_use_record_hash": _hash(),
        "review_version": _semver(),
        "source_snapshot_hash": _hash(),
        "result": s_string(enum=("approved", "denied", "expired")),
        "approvals": s_array(review_approval, min_items=3, max_items=3, unique=True),
        "distinct_approver_count": {"type": "integer", "const": 3},
        "reviewed_at": _time(),
        "valid_until": _time(),
        "validity_seconds": s_integer(minimum=1, maximum=2_592_000),
        "payload_hash": _hash(),
        **provider_review_identity,
    }
    result["contracts/agent/provider-data-use-review.schema.json"] = _schema_artifact(
        "agent/provider-data-use-review.schema.json",
        "Provider Data Use Review Payload Contract",
        provider_review_properties,
        tuple(provider_review_properties),
        data_class="internal_operational",
        max_bytes=131072,
        flow_ids=("F22", "F24"),
        description=(
            "At-most-30-day legal/security/product review payload embedded in a signed review transition; "
            "approval is valid only when all three distinct roles approved."
        ),
        one_of=[
            _branch(
                required=(),
                constants={"result": "approved"},
                property_constraints={
                    "approvals": {
                        "items": {
                            "properties": {"decision": {"const": "approved"}},
                            "required": ["decision"],
                        }
                    }
                },
            ),
            _branch(
                required=(),
                constants={"result": "denied"},
                property_constraints={
                    "approvals": {
                        "contains": {
                            "properties": {"decision": {"const": "denied"}},
                            "required": ["decision"],
                        },
                        "minContains": 1,
                    }
                },
            ),
            _branch(required=(), constants={"result": "expired"}),
        ],
        all_of=[
            *[
                {
                    "properties": {
                        "approvals": {
                            "contains": {
                                "properties": {"role": {"const": role}},
                                "required": ["role"],
                            },
                            "minContains": 1,
                            "maxContains": 1,
                        }
                    }
                }
                for role in ("legal", "security", "product")
            ]
        ],
    )

    provider_status_identity, _ = _canonical_identity_fields(
        "provider_data_use_status",
        "status_id",
        additional_excluded_fields=("payload_hash",),
    )
    provider_status_properties = {
        "status_id": _content_id(),
        "provider_data_use_record_id": _content_id(),
        "provider_data_use_record_hash": _hash(),
        "status": s_string(enum=("review_valid", "expired", "invalidated", "unavailable")),
        "reason_code": s_string(
            enum=(
                "review_accepted",
                "review_expired",
                "provider_terms_changed",
                "model_or_route_changed",
                "source_unavailable",
                "manual_invalidation",
            )
        ),
        "source_check_hash": _hash(),
        "effective_at": _time(),
        "payload_hash": _hash(),
        **provider_status_identity,
    }
    result["contracts/agent/provider-data-use-status.schema.json"] = _schema_artifact(
        "agent/provider-data-use-status.schema.json",
        "Provider Data Use Status Payload Contract",
        provider_status_properties,
        tuple(provider_status_properties),
        data_class="internal_operational",
        max_bytes=65536,
        flow_ids=("F22", "F24"),
        description="Fail-closed provider availability status embedded in the authoritative transition.",
        one_of=[
            _branch(
                required=(),
                constants={"status": "review_valid", "reason_code": "review_accepted"},
            ),
            _branch(
                required=(),
                constants={"status": "expired", "reason_code": "review_expired"},
            ),
            _branch(
                required=(),
                constants={"status": "invalidated"},
                property_constraints={
                    "reason_code": {
                        "enum": [
                            "provider_terms_changed",
                            "model_or_route_changed",
                            "manual_invalidation",
                        ]
                    }
                },
            ),
            _branch(
                required=(),
                constants={"status": "unavailable", "reason_code": "source_unavailable"},
            ),
        ],
    )

    provider_transition_identity, _ = _canonical_identity_fields(
        "provider_evidence_transition",
        "transition_id",
        additional_excluded_fields=("signature_envelope_hash",),
    )
    provider_review_ref = {
        "$ref": "https://jumpship.dev/contracts/agent/provider-data-use-review.schema.json"
    }
    provider_status_ref = {
        "$ref": "https://jumpship.dev/contracts/agent/provider-data-use-status.schema.json"
    }
    transition_properties = {
        "transition_id": _content_id(),
        "transition_kind": s_string(enum=("review", "invalidation")),
        "provider_data_use_record_id": _content_id(),
        "provider_data_use_record_hash": _hash(),
        "sequence": s_integer(minimum=1),
        "predecessor_transition_id": nullable(_content_id()),
        "predecessor_transition_hash": nullable(_hash()),
        "expected_review_head_id": nullable(_content_id()),
        "expected_review_head_hash": nullable(_hash()),
        "expected_status_head_id": nullable(_content_id()),
        "expected_status_head_hash": nullable(_hash()),
        "review_payload": nullable(provider_review_ref),
        "review_payload_hash": nullable(_hash()),
        "status_payload": provider_status_ref,
        "status_payload_hash": _hash(),
        "request_id": _uuid(),
        "reservation_id": _uuid(),
        "object_key_hash": _hash(),
        "binding_inventory_version": s_integer(minimum=0),
        "binding_inventory_root": _hash(),
        "route_hold_root": _hash(),
        "lease_cutoff_at": _time(),
        "signature_purpose": s_string(
            enum=("provider_data_use_review", "provider_data_use_invalidation")
        ),
        "signature_envelope_hash": _hash(),
        "created_at": _time(),
        **provider_transition_identity,
    }
    result["contracts/agent/provider-evidence-transition.schema.json"] = _schema_artifact(
        "agent/provider-evidence-transition.schema.json",
        "Provider Evidence Transition Contract",
        transition_properties,
        tuple(
            field
            for field in transition_properties
            if field not in {"review_payload", "review_payload_hash"}
        ),
        data_class="security_material",
        max_bytes=262144,
        flow_ids=("F22", "F24"),
        description="Sole signed, sequenced provider review or invalidation transition and hold barrier.",
        one_of=[
            _branch(
                required=("review_payload", "review_payload_hash"),
                constants={
                    "transition_kind": "review",
                    "signature_purpose": "provider_data_use_review",
                },
                property_constraints={
                    "review_payload": {
                        "allOf": [
                            provider_review_ref,
                            {
                                "properties": {"result": {"const": "approved"}},
                                "required": ["result"],
                            },
                        ]
                    },
                    "status_payload": {
                        "allOf": [
                            provider_status_ref,
                            {
                                "properties": {
                                    "status": {"const": "review_valid"},
                                    "reason_code": {"const": "review_accepted"},
                                },
                                "required": ["status", "reason_code"],
                            },
                        ]
                    },
                },
            ),
            _branch(
                required=(),
                constants={
                    "transition_kind": "invalidation",
                    "signature_purpose": "provider_data_use_invalidation",
                },
                forbidden=("review_payload", "review_payload_hash"),
                property_constraints={
                    "status_payload": {
                        "allOf": [
                            provider_status_ref,
                            {
                                "properties": {
                                    "status": {"enum": ["invalidated", "unavailable"]}
                                },
                                "required": ["status"],
                            },
                        ]
                    }
                },
            ),
        ],
        all_of=[
            {
                "oneOf": [
                    _branch(
                        required=(),
                        constants={
                            "sequence": 1,
                            "predecessor_transition_id": None,
                            "predecessor_transition_hash": None,
                        },
                    ),
                    {
                        "properties": {
                            "sequence": {"type": "integer", "minimum": 2},
                            "predecessor_transition_id": _content_id(),
                            "predecessor_transition_hash": _hash(),
                        },
                        "required": [
                            "sequence",
                            "predecessor_transition_id",
                            "predecessor_transition_hash",
                        ],
                    },
                ]
            }
        ],
    )

    result["contracts/agent/provider-evidence-journal-checkpoint.schema.json"] = _schema_artifact(
        "agent/provider-evidence-journal-checkpoint.schema.json",
        "Provider Evidence Journal Checkpoint Contract",
        {
            "checkpoint_id": _uuid(),
            "provider_data_use_record_id": _content_id(),
            "maximum_transition_sequence": s_integer(minimum=1),
            "maximum_transition_id": _content_id(),
            "maximum_transition_hash": _hash(),
            "journal_object_count": s_integer(minimum=1, maximum=1_000_000),
            "journal_root": _hash(),
            "registry_version": s_integer(minimum=1),
            "registry_root": _hash(),
            "audit_checkpoint_hash": _hash(),
            "created_at": _time(),
        },
        (
            "checkpoint_id",
            "provider_data_use_record_id",
            "maximum_transition_sequence",
            "maximum_transition_id",
            "maximum_transition_hash",
            "journal_object_count",
            "journal_root",
            "registry_version",
            "registry_root",
            "audit_checkpoint_hash",
            "created_at",
        ),
        data_class="security_material",
        max_bytes=131072,
        flow_ids=("F22", "F24", "F27"),
        description="Replicated append-only provider transition head used for deterministic regional recovery.",
    )

    result["contracts/agent/provider-route-hold.schema.json"] = _schema_artifact(
        "agent/provider-route-hold.schema.json",
        "Provider Route Hold Contract",
        {
            "hold_id": _uuid(),
            "provider_data_use_record_id": _content_id(),
            "transition_id": _content_id(),
            "transition_sequence": s_integer(minimum=1),
            "binding_inventory_version": s_integer(minimum=0),
            "binding_inventory_root": _hash(),
            "reserved_lease_max_expiry": _time(),
            "status": s_string(enum=("open", "acknowledged", "expiry_barrier_reached", "superseded")),
            "opened_at": _time(),
            "completed_at": nullable(_time()),
            "signature_purpose": s_string(const="provider_route_hold"),
            "signature_envelope_hash": _hash(),
        },
        (
            "hold_id",
            "provider_data_use_record_id",
            "transition_id",
            "transition_sequence",
            "binding_inventory_version",
            "binding_inventory_root",
            "reserved_lease_max_expiry",
            "status",
            "opened_at",
            "completed_at",
            "signature_purpose",
            "signature_envelope_hash",
        ),
        data_class="security_material",
        max_bytes=131072,
        flow_ids=("F17", "F22"),
        description="Control-authority hold that atomically blocks new provider lease reservations.",
        one_of=[
            _branch(
                required=(),
                constants={"status": "open", "completed_at": None},
            ),
            _branch(
                required=(),
                constants={"status": "acknowledged"},
                property_constraints={"completed_at": _time()},
            ),
            _branch(
                required=(),
                constants={"status": "expiry_barrier_reached"},
                property_constraints={"completed_at": _time()},
            ),
            _branch(
                required=(),
                constants={"status": "superseded"},
                property_constraints={"completed_at": _time()},
            ),
        ],
    )

    result["contracts/agent/provider-use-lease.schema.json"] = _schema_artifact(
        "agent/provider-use-lease.schema.json",
        "Provider Use Lease Contract",
        {
            "lease_id": _uuid(),
            "reservation_id": _uuid(),
            "cell_id": _uuid(),
            "cell_generation": s_integer(minimum=1),
            "cell_release_binding_hash": _hash(),
            "provider_data_use_record_id": _content_id(),
            "provider_data_use_record_hash": _hash(),
            "accepted_transition_id": _content_id(),
            "accepted_transition_sequence": s_integer(minimum=1),
            "accepted_status_hash": _hash(),
            "agent_bundle_id": _content_id(),
            "agent_bundle_hash": _hash(),
            "release_unit_id": _content_id(),
            "release_unit_hash": _hash(),
            "control_epoch": s_integer(minimum=1),
            "no_unresolved_binding_hold": _true(),
            "issued_at": _time(),
            "expires_at": _time(),
            "ttl_seconds": s_integer(minimum=1, maximum=60),
            "nonce_hash": _hash(),
            "signature_purpose": s_string(const="provider_use_lease"),
            "signature_envelope_hash": _hash(),
        },
        (
            "lease_id",
            "reservation_id",
            "cell_id",
            "cell_generation",
            "cell_release_binding_hash",
            "provider_data_use_record_id",
            "provider_data_use_record_hash",
            "accepted_transition_id",
            "accepted_transition_sequence",
            "accepted_status_hash",
            "agent_bundle_id",
            "agent_bundle_hash",
            "release_unit_id",
            "release_unit_hash",
            "control_epoch",
            "no_unresolved_binding_hold",
            "issued_at",
            "expires_at",
            "ttl_seconds",
            "nonce_hash",
            "signature_purpose",
            "signature_envelope_hash",
        ),
        data_class="security_material",
        max_bytes=131072,
        flow_ids=("F17",),
        description="At-most-60-second inference authorization bound to exact accepted provider heads and release binding.",
        semantic_invariants=(
            "expires_at_minus_issued_at_equals_ttl_seconds",
            "ttl_seconds_at_most_60",
        ),
    )

    result["contracts/agent/provider-review-delivery.schema.json"] = _schema_artifact(
        "agent/provider-review-delivery.schema.json",
        "Provider Review Delivery and Acknowledgement Contract",
        {
            "delivery_id": _uuid(),
            "transition_id": _content_id(),
            "transition_sequence": s_integer(minimum=1),
            "binding_id": _uuid(),
            "cell_id": _uuid(),
            "cell_generation": s_integer(minimum=1),
            "status": s_string(
                enum=("pending", "delivered", "cell_committed", "shared_committed", "superseded", "failed")
            ),
            "attempt_count": s_integer(minimum=0, maximum=128),
            "local_head_hash": nullable(_hash()),
            "shared_head_hash": nullable(_hash()),
            "hold_supersession_root": nullable(_hash()),
            "ack_receipt_hash": nullable(_hash()),
            "last_attempt_at": nullable(_time()),
            "completed_at": nullable(_time()),
        },
        (
            "delivery_id",
            "transition_id",
            "transition_sequence",
            "binding_id",
            "cell_id",
            "cell_generation",
            "status",
            "attempt_count",
            "local_head_hash",
            "shared_head_hash",
            "hold_supersession_root",
            "ack_receipt_hash",
            "last_attempt_at",
            "completed_at",
        ),
        data_class="internal_operational",
        max_bytes=131072,
        flow_ids=("F17", "F22"),
        description="Crash-recoverable local-then-shared provider transition delivery; partial completion remains blocked.",
        one_of=[
            _branch(
                required=(),
                constants={
                    "status": "pending",
                    "local_head_hash": None,
                    "shared_head_hash": None,
                    "hold_supersession_root": None,
                    "ack_receipt_hash": None,
                    "completed_at": None,
                },
            ),
            _branch(
                required=(),
                constants={
                    "status": "delivered",
                    "local_head_hash": None,
                    "shared_head_hash": None,
                    "hold_supersession_root": None,
                    "ack_receipt_hash": None,
                    "completed_at": None,
                },
            ),
            _branch(
                required=(),
                constants={
                    "status": "cell_committed",
                    "shared_head_hash": None,
                    "completed_at": None,
                },
                property_constraints={
                    "local_head_hash": _hash(),
                    "hold_supersession_root": _hash(),
                    "ack_receipt_hash": _hash(),
                },
            ),
            _branch(
                required=(),
                constants={"status": "shared_committed"},
                property_constraints={
                    "local_head_hash": _hash(),
                    "shared_head_hash": _hash(),
                    "hold_supersession_root": _hash(),
                    "ack_receipt_hash": _hash(),
                    "completed_at": _time(),
                },
            ),
            _branch(
                required=(),
                constants={"status": "superseded"},
                property_constraints={
                    "local_head_hash": _hash(),
                    "shared_head_hash": _hash(),
                    "hold_supersession_root": _hash(),
                    "ack_receipt_hash": _hash(),
                    "completed_at": _time(),
                },
            ),
            _branch(
                required=(),
                constants={"status": "failed"},
                property_constraints={"completed_at": _time()},
            ),
        ],
    )

    analysis_input = s_object(
        {
            "artifact_id": _text(256),
            "artifact_version": _text(128),
            "artifact_hash": _hash(),
            "mount_path": s_string(
                pattern=r"^/inputs/[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$",
                max_length=520,
            ),
            "read_only": _true(),
            "data_class": s_string(enum=("restricted_customer", "internal_operational")),
        },
        (
            "artifact_id",
            "artifact_version",
            "artifact_hash",
            "mount_path",
            "read_only",
            "data_class",
        ),
    )
    analysis_sandbox = s_object(
        {
            "rootless": _true(),
            "read_only_root_filesystem": _true(),
            "no_new_privileges": _true(),
            "dropped_capabilities": {
                "type": "array",
                "const": ["ALL"],
                "minItems": 1,
                "maxItems": 1,
            },
            "seccomp_profile_hash": _hash(),
            "user_namespace_enabled": _true(),
            "network_mode": s_string(const="none"),
            "imds_access": _false(),
            "broker_socket_mounted": _false(),
            "container_socket_mounted": _false(),
            "provider_material_mounted": _false(),
            "iam_material_mounted": _false(),
            "secret_material_mounted": _false(),
            "ephemeral_scratch_bytes": s_integer(
                minimum=1,
                maximum=1_073_741_824,
            ),
            "subprocess_allowed": _false(),
            "socket_syscalls_allowed": _false(),
            "ffi_allowed": _false(),
            "dynamic_package_install_allowed": _false(),
            "unapproved_imports_allowed": _false(),
        },
        (
            "rootless",
            "read_only_root_filesystem",
            "no_new_privileges",
            "dropped_capabilities",
            "seccomp_profile_hash",
            "user_namespace_enabled",
            "network_mode",
            "imds_access",
            "broker_socket_mounted",
            "container_socket_mounted",
            "provider_material_mounted",
            "iam_material_mounted",
            "secret_material_mounted",
            "ephemeral_scratch_bytes",
            "subprocess_allowed",
            "socket_syscalls_allowed",
            "ffi_allowed",
            "dynamic_package_install_allowed",
            "unapproved_imports_allowed",
        ),
    )
    analysis_authority = s_object(
        {
            "advisory_only": _true(),
            "may_supply_record_transform": _false(),
            "may_supply_source_or_target_effect": _false(),
            "may_supply_gate_or_consent_fact": _false(),
            "may_supply_parity_or_verification_proof": _false(),
            "may_supply_traffic_authority": _false(),
            "automatic_shared_plane_export": _false(),
        },
        (
            "advisory_only",
            "may_supply_record_transform",
            "may_supply_source_or_target_effect",
            "may_supply_gate_or_consent_fact",
            "may_supply_parity_or_verification_proof",
            "may_supply_traffic_authority",
            "automatic_shared_plane_export",
        ),
    )
    result["contracts/agent/analysis-run.schema.json"] = _schema_artifact(
        "agent/analysis-run.schema.json",
        "Sealed Analysis Run Contract",
        {
            "analysis_run_id": _uuid(),
            "run_id": _uuid(),
            "tool_receipt_id": _content_id(),
            "code_sha256": _hash(),
            "image_digest_sha256": _hash(),
            "tool_descriptor_hash": _hash(),
            "sandbox_policy_hash": _hash(),
            "run_brief_authorization_hash": _hash(),
            "phase": s_string(enum=("discovery", "census", "design", "rehearsal")),
            "analysis_kind": s_string(
                enum=("discovery", "census", "archaeology", "design", "rehearsal")
            ),
            "input_manifest_sha256": _hash(),
            "declared_inputs": s_array(
                analysis_input,
                min_items=1,
                max_items=128,
                unique=True,
            ),
            "output_schema_hash": _hash(),
            "declared_output_manifest_sha256": _hash(),
            "resource_limits": s_object(
                {
                    "cpu_millis": s_integer(minimum=1, maximum=2_000),
                    "memory_bytes": s_integer(minimum=1, maximum=4_294_967_296),
                    "disk_bytes": s_integer(minimum=1, maximum=1_073_741_824),
                    "wall_seconds": s_integer(minimum=1, maximum=60),
                    "processes": s_integer(minimum=1, maximum=64),
                    "max_output_bytes": s_integer(
                        minimum=1, maximum=104_857_600
                    ),
                    "execution_count": {"type": "integer", "const": 1},
                },
                (
                    "cpu_millis",
                    "memory_bytes",
                    "disk_bytes",
                    "wall_seconds",
                    "processes",
                    "max_output_bytes",
                    "execution_count",
                ),
            ),
            "network_enabled": _false(),
            "credentials_mounted": _false(),
            "undeclared_artifacts_allowed": _false(),
            "sandbox": analysis_sandbox,
            "authority": analysis_authority,
            "status": s_string(enum=("accepted", "running", "succeeded", "failed", "quarantined")),
            "output_manifest_sha256": nullable(_hash()),
            "quarantine_root": nullable(_hash()),
            "sanitizer_version": _semver(),
            "exit_reason": nullable(_text(256)),
        },
        (
            "analysis_run_id",
            "run_id",
            "tool_receipt_id",
            "code_sha256",
            "image_digest_sha256",
            "tool_descriptor_hash",
            "sandbox_policy_hash",
            "run_brief_authorization_hash",
            "phase",
            "analysis_kind",
            "input_manifest_sha256",
            "declared_inputs",
            "output_schema_hash",
            "declared_output_manifest_sha256",
            "resource_limits",
            "network_enabled",
            "credentials_mounted",
            "undeclared_artifacts_allowed",
            "sandbox",
            "authority",
            "status",
            "output_manifest_sha256",
            "quarantine_root",
            "sanitizer_version",
            "exit_reason",
        ),
        data_class="restricted_customer",
        max_bytes=262144,
        flow_ids=("F17",),
        description="No-network, no-secret, rootless diagnostic run whose outputs cannot authorize effects or proof.",
        one_of=[
            _branch(
                required=(),
                constants={
                    "status": "accepted",
                    "output_manifest_sha256": None,
                    "quarantine_root": None,
                    "exit_reason": None,
                },
            ),
            _branch(
                required=(),
                constants={
                    "status": "running",
                    "output_manifest_sha256": None,
                    "quarantine_root": None,
                    "exit_reason": None,
                },
            ),
            _branch(
                required=("output_manifest_sha256", "quarantine_root", "exit_reason"),
                constants={"status": "succeeded"},
                property_constraints={
                    "output_manifest_sha256": _hash(),
                    "quarantine_root": _hash(),
                    "exit_reason": _text(256),
                },
            ),
            _branch(
                required=("exit_reason",),
                constants={"status": "failed", "output_manifest_sha256": None},
                property_constraints={"exit_reason": _text(256)},
            ),
            _branch(
                required=("quarantine_root", "exit_reason"),
                constants={"status": "quarantined"},
                property_constraints={
                    "quarantine_root": _hash(),
                    "exit_reason": _text(256),
                },
            ),
        ],
    )
    return result


PROMOTION_IDENTITY_FIELDS, PROMOTION_IDENTITY_REQUIRED = _canonical_identity_fields(
    "promotion_envelope",
    "promotion_envelope_id",
    additional_excluded_fields=("signature_envelope_hash",),
)


def _promotion_properties() -> dict[str, Any]:
    promotion_approval = s_object(
        {
            "role": s_string(
                enum=(
                    "release_owner",
                    "quality_owner",
                    "security_owner",
                    "incident_commander",
                )
            ),
            "approver_id": _text(256),
            "decision": s_string(const="approved"),
            "evidence_root": _hash(),
            "approved_at": _time(),
        },
        ("role", "approver_id", "decision", "evidence_root", "approved_at"),
    )
    approvals = s_array(
        promotion_approval,
        min_items=2,
        max_items=4,
        unique=True,
    )
    return {
        "promotion_envelope_id": _content_id(),
        "kind": s_string(enum=("activate", "rollback", "emergency_stop")),
        "mode": s_string(
            enum=(
                "ordinary",
                "ordinary_rollback_takeover",
                "genesis",
                "bootstrap_recovery",
                "emergency_recovery",
                "emergency_stop_supported",
                "emergency_stop_current_active_not_serving",
            )
        ),
        "purpose": s_string(enum=("bundle_promotion", "release_emergency_stop")),
        "evidence_class": s_string(enum=("release", "boundary_fixture")),
        "synthetic": s_boolean(),
        "environment": s_string(enum=PROMOTION_ENVIRONMENTS),
        "stage": s_string(enum=STAGES),
        "release_unit_id": _content_id(),
        "release_unit_hash": _hash(),
        "agent_bundle_id": _content_id(),
        "agent_bundle_hash": _hash(),
        "qualification_record_id": _content_id(),
        "qualification_record_hash": _hash(),
        "candidate_deployment_id": _uuid(),
        "deployment_generation": s_integer(minimum=1),
        "expected_prior_pointer_id": nullable(_uuid()),
        "expected_pointer_version": s_integer(minimum=0),
        "observed_current_pointer_id": nullable(_uuid()),
        "observed_current_pointer_version": s_integer(minimum=0),
        "current_inventory_version": s_integer(minimum=0),
        "current_inventory_root": _hash(),
        "current_live_binding_count": s_integer(minimum=0),
        "deployment_readiness_receipt_hash": _hash(),
        "readiness_inventory_version": s_integer(minimum=0),
        "readiness_inventory_root": _hash(),
        "rollout_bounds": s_object(
            {
                "maximum_percent": s_integer(minimum=1, maximum=100),
                "maximum_concurrent_bindings": s_integer(minimum=0, maximum=1_000_000),
                "deadline": _time(),
            },
            ("maximum_percent", "maximum_concurrent_bindings", "deadline"),
        ),
        "stop_conditions": s_array(_text(256), min_items=1, max_items=32, unique=True),
        "approved_rollback_target_id": _uuid(),
        "approved_rollback_target_hash": _hash(),
        "rollback_takeover": s_boolean(),
        "expected_failed_activation_transaction_id": _uuid(),
        "expected_failed_activation_fence_generation": s_integer(minimum=1),
        "genesis_transaction_id": _uuid(),
        "zero_binding_inventory_root": _hash(),
        "current_candidate_emergency_revoked": s_boolean(),
        "no_serving_history": s_boolean(),
        "immediate_activation_receipt_hash": _hash(),
        "immediate_emergency_receipt_hash": _hash(),
        "recovery_chain_root": _hash(),
        "all_affected_bindings_stopped": s_boolean(),
        "rollback_candidate_inventory_version": s_integer(minimum=0),
        "rollback_candidate_inventory_root": _hash(),
        "rollback_support_policy_version": _text(128),
        "eligible_supported_rollback_count": s_integer(minimum=0),
        "incident_recovery_root": _hash(),
        "emergency_target_mode": s_string(enum=("supported", "current_active_not_serving")),
        "target_support_record_hash": _hash(),
        "target_activation_transaction_id": _uuid(),
        "target_open_fence_generation": s_integer(minimum=1),
        "incident_id": _uuid(),
        "approval_records": approvals,
        "distinct_approver_count": s_integer(minimum=2, maximum=4),
        "issued_at": _time(),
        "expires_at": _time(),
        "nonce_hash": _hash(),
        "signature_envelope_hash": _hash(),
        **PROMOTION_IDENTITY_FIELDS,
    }


PROMOTION_COMMON = (
    "promotion_envelope_id",
    "kind",
    "mode",
    "purpose",
    "evidence_class",
    "synthetic",
    "environment",
    "stage",
    "release_unit_id",
    "release_unit_hash",
    "agent_bundle_id",
    "agent_bundle_hash",
    "candidate_deployment_id",
    "deployment_generation",
    "expected_pointer_version",
    "observed_current_pointer_id",
    "observed_current_pointer_version",
    "current_inventory_version",
    "current_inventory_root",
    "current_live_binding_count",
    "approval_records",
    "distinct_approver_count",
    "issued_at",
    "expires_at",
    "nonce_hash",
    "signature_envelope_hash",
    *PROMOTION_IDENTITY_REQUIRED,
)


READINESS_FIELDS = (
    "qualification_record_id",
    "qualification_record_hash",
    "deployment_readiness_receipt_hash",
    "readiness_inventory_version",
    "readiness_inventory_root",
    "rollout_bounds",
    "stop_conditions",
)


ROLLBACK_FIELDS = ("approved_rollback_target_id", "approved_rollback_target_hash")
RECOVERY_ONLY_FIELDS = (
    "genesis_transaction_id",
    "zero_binding_inventory_root",
    "current_candidate_emergency_revoked",
    "no_serving_history",
    "immediate_activation_receipt_hash",
    "immediate_emergency_receipt_hash",
    "recovery_chain_root",
    "all_affected_bindings_stopped",
    "rollback_candidate_inventory_version",
    "rollback_candidate_inventory_root",
    "rollback_support_policy_version",
    "eligible_supported_rollback_count",
    "incident_recovery_root",
)
EMERGENCY_STOP_FIELDS = (
    "emergency_target_mode",
    "target_support_record_hash",
    "target_activation_transaction_id",
    "target_open_fence_generation",
    "incident_id",
)


def _approval_role_constraints(*roles: str) -> dict[str, Any]:
    return {
        "allOf": [
            {
                "contains": {
                    "properties": {
                        "role": {"const": role},
                        "decision": {"const": "approved"},
                    },
                    "required": ["role", "decision"],
                },
                "minContains": 1,
                "maxContains": 1,
            }
            for role in roles
        ]
    }


def _ordinary_promotion_constraints() -> dict[str, Any]:
    return {
        "expected_prior_pointer_id": _uuid(),
        "expected_pointer_version": s_integer(minimum=1),
        "observed_current_pointer_id": _uuid(),
        "observed_current_pointer_version": s_integer(minimum=1),
        "approval_records": _approval_role_constraints("release_owner", "quality_owner"),
        "distinct_approver_count": {"type": "integer", "const": 2},
    }


def _recovery_promotion_constraints() -> dict[str, Any]:
    return {
        "expected_prior_pointer_id": _uuid(),
        "expected_pointer_version": s_integer(minimum=1),
        "observed_current_pointer_id": _uuid(),
        "observed_current_pointer_version": s_integer(minimum=1),
        "approval_records": _approval_role_constraints(
            "release_owner", "security_owner", "incident_commander"
        ),
        "distinct_approver_count": {"type": "integer", "const": 3},
    }


def _emergency_stop_constraints() -> dict[str, Any]:
    return {
        "observed_current_pointer_id": _uuid(),
        "observed_current_pointer_version": s_integer(minimum=1),
        "approval_records": _approval_role_constraints(
            "release_owner", "security_owner", "incident_commander"
        ),
        "distinct_approver_count": {"type": "integer", "const": 3},
    }


def _promotion_evidence_constraints() -> list[dict[str, Any]]:
    return [
        {
            "oneOf": [
                _branch(
                    required=(),
                    constants={
                        "evidence_class": "boundary_fixture",
                        "synthetic": True,
                        "environment": "isolated-quality",
                        "stage": "ephemeral",
                    },
                ),
                _branch(
                    required=(),
                    constants={
                        "evidence_class": "release",
                        "synthetic": False,
                        "environment": "staging",
                        "stage": "persistent",
                    },
                ),
                _branch(
                    required=(),
                    constants={
                        "evidence_class": "release",
                        "synthetic": False,
                        "environment": "production",
                        "stage": "paid",
                    },
                ),
            ]
        }
    ]


def _promotion_branches() -> list[dict[str, Any]]:
    return [
        _branch(
            required=(*READINESS_FIELDS, *ROLLBACK_FIELDS, "expected_prior_pointer_id", "rollback_takeover"),
            constants={"kind": "activate", "mode": "ordinary", "purpose": "bundle_promotion", "rollback_takeover": False},
            forbidden=RECOVERY_ONLY_FIELDS + EMERGENCY_STOP_FIELDS + (
                "expected_failed_activation_transaction_id",
                "expected_failed_activation_fence_generation",
            ),
            property_constraints=_ordinary_promotion_constraints(),
        ),
        _branch(
            required=(*READINESS_FIELDS, *ROLLBACK_FIELDS, "expected_prior_pointer_id", "rollback_takeover"),
            constants={"kind": "rollback", "mode": "ordinary", "purpose": "bundle_promotion", "rollback_takeover": False},
            forbidden=RECOVERY_ONLY_FIELDS + EMERGENCY_STOP_FIELDS + (
                "expected_failed_activation_transaction_id",
                "expected_failed_activation_fence_generation",
            ),
            property_constraints=_ordinary_promotion_constraints(),
        ),
        _branch(
            required=(
                *READINESS_FIELDS,
                *ROLLBACK_FIELDS,
                "expected_prior_pointer_id",
                "rollback_takeover",
                "expected_failed_activation_transaction_id",
                "expected_failed_activation_fence_generation",
            ),
            constants={
                "kind": "rollback",
                "mode": "ordinary_rollback_takeover",
                "purpose": "bundle_promotion",
                "rollback_takeover": True,
            },
            forbidden=RECOVERY_ONLY_FIELDS + EMERGENCY_STOP_FIELDS,
            property_constraints=_ordinary_promotion_constraints(),
        ),
        _branch(
            required=(
                *READINESS_FIELDS,
                "expected_prior_pointer_id",
                "genesis_transaction_id",
                "zero_binding_inventory_root",
            ),
            constants={"kind": "activate", "mode": "genesis", "purpose": "bundle_promotion", "expected_prior_pointer_id": None, "expected_pointer_version": 0, "current_live_binding_count": 0},
            forbidden=ROLLBACK_FIELDS
            + RECOVERY_ONLY_FIELDS[2:]
            + EMERGENCY_STOP_FIELDS
            + (
                "rollback_takeover",
                "expected_failed_activation_transaction_id",
                "expected_failed_activation_fence_generation",
            ),
            property_constraints={
                "observed_current_pointer_id": {"type": "null"},
                "observed_current_pointer_version": {
                    "type": "integer",
                    "const": 0,
                },
                "approval_records": _approval_role_constraints("release_owner", "quality_owner"),
                "distinct_approver_count": {"type": "integer", "const": 2},
            },
        ),
        _branch(
            required=(
                *READINESS_FIELDS,
                "expected_prior_pointer_id",
                "genesis_transaction_id",
                "zero_binding_inventory_root",
                "current_candidate_emergency_revoked",
                "no_serving_history",
                "immediate_activation_receipt_hash",
                "immediate_emergency_receipt_hash",
                "recovery_chain_root",
            ),
            constants={
                "kind": "activate",
                "mode": "bootstrap_recovery",
                "purpose": "bundle_promotion",
                "current_candidate_emergency_revoked": True,
                "no_serving_history": True,
                "current_live_binding_count": 0,
            },
            forbidden=ROLLBACK_FIELDS
            + EMERGENCY_STOP_FIELDS
            + (
                "rollback_takeover",
                "expected_failed_activation_transaction_id",
                "expected_failed_activation_fence_generation",
                "all_affected_bindings_stopped",
                "rollback_candidate_inventory_version",
                "rollback_candidate_inventory_root",
                "rollback_support_policy_version",
                "eligible_supported_rollback_count",
                "incident_recovery_root",
            ),
            property_constraints=_recovery_promotion_constraints(),
        ),
        _branch(
            required=(
                *READINESS_FIELDS,
                "expected_prior_pointer_id",
                "current_candidate_emergency_revoked",
                "all_affected_bindings_stopped",
                "rollback_candidate_inventory_version",
                "rollback_candidate_inventory_root",
                "rollback_support_policy_version",
                "eligible_supported_rollback_count",
                "immediate_emergency_receipt_hash",
                "recovery_chain_root",
                "incident_recovery_root",
            ),
            constants={
                "kind": "activate",
                "mode": "emergency_recovery",
                "purpose": "bundle_promotion",
                "current_candidate_emergency_revoked": True,
                "all_affected_bindings_stopped": True,
                "eligible_supported_rollback_count": 0,
            },
            forbidden=ROLLBACK_FIELDS
            + EMERGENCY_STOP_FIELDS
            + (
                "rollback_takeover",
                "expected_failed_activation_transaction_id",
                "expected_failed_activation_fence_generation",
                "genesis_transaction_id",
                "zero_binding_inventory_root",
                "no_serving_history",
                "immediate_activation_receipt_hash",
            ),
            property_constraints=_recovery_promotion_constraints(),
        ),
        _branch(
            required=("emergency_target_mode", "target_support_record_hash", "incident_id"),
            constants={
                "kind": "emergency_stop",
                "mode": "emergency_stop_supported",
                "purpose": "release_emergency_stop",
                "emergency_target_mode": "supported",
            },
            forbidden=READINESS_FIELDS
            + ROLLBACK_FIELDS
            + RECOVERY_ONLY_FIELDS
            + (
                "rollback_takeover",
                "expected_failed_activation_transaction_id",
                "expected_failed_activation_fence_generation",
                "target_activation_transaction_id",
                "target_open_fence_generation",
            ),
            property_constraints=_emergency_stop_constraints(),
        ),
        _branch(
            required=(
                "emergency_target_mode",
                "target_activation_transaction_id",
                "target_open_fence_generation",
                "incident_id",
            ),
            constants={
                "kind": "emergency_stop",
                "mode": "emergency_stop_current_active_not_serving",
                "purpose": "release_emergency_stop",
                "emergency_target_mode": "current_active_not_serving",
            },
            forbidden=READINESS_FIELDS
            + ROLLBACK_FIELDS
            + RECOVERY_ONLY_FIELDS
            + (
                "rollback_takeover",
                "expected_failed_activation_transaction_id",
                "expected_failed_activation_fence_generation",
                "target_support_record_hash",
            ),
            property_constraints=_emergency_stop_constraints(),
        ),
    ]


def _quality_artifacts() -> dict[str, Artifact]:
    result: dict[str, Artifact] = {}
    result["contracts/quality/eval-case.schema.json"] = _schema_artifact(
        "quality/eval-case.schema.json",
        "Agent Evaluation Case Contract",
        {
            "eval_case_id": _uuid(),
            "case_version": _semver(),
            "case_kind": s_string(enum=("deterministic", "trajectory", "security", "application_adaptation", "writer_cutover")),
            "input_fixture_hash": _hash(),
            "expectation_schema_hash": _hash(),
            "expectation_hash": _hash(),
            "required_checker_ids": s_array(_text(128), min_items=1, max_items=64, unique=True),
            "required_grader_ids": s_array(_text(128), min_items=0, max_items=32, unique=True),
            "authority_denials": s_array(_text(256), min_items=0, max_items=64, unique=True),
            "review_root": _hash(),
        },
        (
            "eval_case_id",
            "case_version",
            "case_kind",
            "input_fixture_hash",
            "expectation_schema_hash",
            "expectation_hash",
            "required_checker_ids",
            "required_grader_ids",
            "authority_denials",
            "review_root",
        ),
        data_class="internal_operational",
        max_bytes=262144,
        flow_ids=("F22", "F24"),
        description="Immutable reviewed evaluation case; expectation changes require a new version.",
    )

    eval_report_identity, _ = _canonical_identity_fields(
        "eval_report",
        "eval_report_id",
        additional_excluded_fields=("signature_envelope_hash",),
    )
    eval_report_properties = {
        "eval_report_id": _content_id(),
        "agent_bundle_id": _content_id(),
        "agent_bundle_hash": _hash(),
        "corpus_version": _semver(),
        "corpus_hash": _hash(),
        "checker_set_hash": _hash(),
        "grader_set_hash": _hash(),
        "environment_hash": _hash(),
        "case_count": s_integer(minimum=1, maximum=100_000),
        "hard_gate_pass_count": s_integer(minimum=0, maximum=100_000),
        "hard_gate_fail_count": s_integer(minimum=0, maximum=100_000),
        "qualitative_score": s_number(minimum=0.0, maximum=1.0),
        "result_root": _hash(),
        "sanitizer_version": _semver(),
        "contains_raw_customer_evidence": _false(),
        "completed_at": _time(),
        "signature_envelope_hash": _hash(),
        **eval_report_identity,
    }
    result["contracts/quality/eval-report.schema.json"] = _schema_artifact(
        "quality/eval-report.schema.json",
        "Sanitized Agent Evaluation Report Contract",
        eval_report_properties,
        tuple(eval_report_properties),
        data_class="internal_operational",
        max_bytes=262144,
        flow_ids=("F22", "F24"),
        description="Sanitized bundle/corpus/checker/grader/environment-bound evaluation result.",
    )

    decision_feature = s_object(
        {
            "feature_key": _text(128),
            "value_bucket": _text(128),
            "support_count": s_integer(minimum=1, maximum=1_000_000_000),
            "confidence_lower_bound": s_number(minimum=0.0, maximum=1.0),
        },
        ("feature_key", "value_bucket", "support_count", "confidence_lower_bound"),
    )
    learning_common = {
        "learning_record_id": _uuid(),
        "record_version": _semver(),
        "policy_version": _semver(),
        "features": s_array(decision_feature, min_items=1, max_items=128),
        "provenance_root": _hash(),
        "sanitizer_version": _semver(),
        "sanitizer_policy_hash": _hash(),
        "review_approval_root": _hash(),
        "contains_workspace_identity": _false(),
        "contains_user_identity": _false(),
        "contains_migration_identity": _false(),
        "contains_raw_evidence": _false(),
        "created_at": _time(),
    }
    result["contracts/quality/decision-policy-learning-record.schema.json"] = _schema_artifact(
        "quality/decision-policy-learning-record.schema.json",
        "Privacy Safe Decision Policy Learning Record",
        {**learning_common, "decision_key": _text(128), "outcome_class": _text(128)},
        (*learning_common, "decision_key", "outcome_class"),
        data_class="internal_operational",
        max_bytes=262144,
        flow_ids=("F22", "F24"),
        description="Allowlisted reviewed aggregate for decision policy learning; customer identities and raw evidence are forbidden.",
    )
    result["contracts/quality/platform-profile-learning-record.schema.json"] = _schema_artifact(
        "quality/platform-profile-learning-record.schema.json",
        "Privacy Safe Platform Profile Learning Record",
        {**learning_common, "platform_pair": _text(128), "profile_outcome": _text(128)},
        (*learning_common, "platform_pair", "profile_outcome"),
        data_class="internal_operational",
        max_bytes=262144,
        flow_ids=("F22", "F24"),
        description="Allowlisted reviewed aggregate for platform profiles; no tenant, user, migration, or raw-evidence identity.",
    )

    qualification_identity, _ = _canonical_identity_fields(
        "qualification_record",
        "qualification_record_id",
        additional_excluded_fields=("signature_envelope_hash",),
    )
    qualification_properties = {
        "qualification_record_id": _content_id(),
        "agent_bundle_id": _content_id(),
        "agent_bundle_hash": _hash(),
        "eval_report_ids": s_array(
            _content_id(), min_items=1, max_items=128, unique=True
        ),
        "eval_report_root": _hash(),
        "corpus_hash": _hash(),
        "checker_set_hash": _hash(),
        "grader_set_hash": _hash(),
        "environment_hash": _hash(),
        "hard_gates_passed": s_boolean(),
        "security_gates_passed": s_boolean(),
        "application_adaptation_gates_passed": s_boolean(),
        "writer_cutover_gates_passed": s_boolean(),
        "qualified_at": _time(),
        "valid_until": _time(),
        "signature_envelope_hash": _hash(),
        **qualification_identity,
    }
    result["contracts/quality/qualification-record.schema.json"] = _schema_artifact(
        "quality/qualification-record.schema.json",
        "Agent Bundle Qualification Record",
        qualification_properties,
        tuple(qualification_properties),
        data_class="security_material",
        max_bytes=262144,
        flow_ids=("F22", "F24"),
        description="Independent bundle qualification binding exact eval inputs, results, and expiry.",
    )

    promotion_properties = _promotion_properties()
    result["contracts/quality/promotion-envelope.schema.json"] = _schema_artifact(
        "quality/promotion-envelope.schema.json",
        "Bundle Promotion Envelope",
        promotion_properties,
        PROMOTION_COMMON,
        data_class="security_material",
        max_bytes=524288,
        flow_ids=("F22", "F24"),
        description="One-use, kind-conditional promotion or emergency-stop authorization with disjoint recovery shapes.",
        one_of=_promotion_branches(),
        all_of=_promotion_evidence_constraints(),
    )

    activation_receipt_identity, activation_receipt_identity_required = _canonical_identity_fields(
        "activation_receipt",
        "activation_receipt_id",
        additional_excluded_fields=("signature_envelope_hash",),
    )
    result["contracts/quality/activation-receipt.schema.json"] = _schema_artifact(
        "quality/activation-receipt.schema.json",
        "Bundle Activation Terminal Receipt",
        {
            "activation_receipt_id": _content_id(),
            "promotion_envelope_id": _content_id(),
            "promotion_envelope_hash": _hash(),
            "kind": s_string(enum=("activate", "rollback", "emergency_stop")),
            "mode": s_string(enum=tuple(_promotion_properties()["mode"]["enum"])),
            "evidence_class": s_string(enum=("release", "boundary_fixture")),
            "synthetic": s_boolean(),
            "environment": s_string(enum=PROMOTION_ENVIRONMENTS),
            "stage": s_string(enum=STAGES),
            "release_unit_id": _content_id(),
            "release_unit_hash": _hash(),
            "qualification_record_id": nullable(_content_id()),
            "qualification_record_hash": nullable(_hash()),
            "prior_pointer_id": nullable(_uuid()),
            "resulting_pointer_id": nullable(_uuid()),
            "pointer_version": s_integer(minimum=0),
            "support_state": s_string(enum=("supported", "emergency_revoked")),
            "transaction_id": _uuid(),
            "fence_generation": s_integer(minimum=1),
            "nonce_hash": _hash(),
            "activator_identity": _text(256),
            "outcome": s_string(enum=("activated", "rolled_back", "emergency_stopped", "denied")),
            "committed_at": _time(),
            "signature_envelope_hash": _hash(),
            **activation_receipt_identity,
        },
        (
            "activation_receipt_id",
            "promotion_envelope_id",
            "promotion_envelope_hash",
            "kind",
            "mode",
            "evidence_class",
            "synthetic",
            "environment",
            "stage",
            "release_unit_id",
            "release_unit_hash",
            "qualification_record_id",
            "qualification_record_hash",
            "prior_pointer_id",
            "resulting_pointer_id",
            "pointer_version",
            "support_state",
            "transaction_id",
            "fence_generation",
            "nonce_hash",
            "activator_identity",
            "outcome",
            "committed_at",
            "signature_envelope_hash",
            *activation_receipt_identity_required,
        ),
        data_class="security_material",
        max_bytes=262144,
        flow_ids=("F22", "F24"),
        description="Post-transaction detached-signed terminal receipt for activation, rollback, or emergency stop.",
        all_of=_promotion_evidence_constraints(),
    )

    bundle_states = (
        "registered",
        "offline_qualified",
        "boundary_shadow",
        "boundary_shadow_receipted",
        "boundary_canary",
        "release_eligible",
        "staging_authorized",
        "production_authorized",
        "blocked",
        "superseded",
        "boundary_rolled_back",
    )
    lifecycle_edges = (
        ("registered", "offline_qualified", "qualification", "isolated-quality"),
        ("offline_qualified", "boundary_shadow", "boundary_fixture", "isolated-quality"),
        ("boundary_shadow", "boundary_shadow_receipted", "boundary_fixture", "isolated-quality"),
        ("boundary_shadow_receipted", "boundary_canary", "boundary_fixture", "isolated-quality"),
        ("boundary_canary", "release_eligible", "boundary_fixture", "isolated-quality"),
        ("release_eligible", "staging_authorized", "release", "staging"),
        ("staging_authorized", "production_authorized", "release", "production"),
        ("boundary_shadow", "boundary_rolled_back", "boundary_fixture", "isolated-quality"),
        ("boundary_shadow_receipted", "boundary_rolled_back", "boundary_fixture", "isolated-quality"),
        ("boundary_canary", "boundary_rolled_back", "boundary_fixture", "isolated-quality"),
        ("release_eligible", "boundary_rolled_back", "boundary_fixture", "isolated-quality"),
        ("offline_qualified", "blocked", "qualification", "isolated-quality"),
        ("boundary_shadow", "blocked", "boundary_fixture", "isolated-quality"),
        ("boundary_canary", "blocked", "boundary_fixture", "isolated-quality"),
        ("release_eligible", "blocked", "release", "staging"),
        ("staging_authorized", "blocked", "release", "staging"),
        ("offline_qualified", "superseded", "qualification", "isolated-quality"),
        ("release_eligible", "superseded", "release", "staging"),
        ("staging_authorized", "superseded", "release", "staging"),
        ("production_authorized", "superseded", "release", "production"),
    )
    lifecycle_transition_identity, lifecycle_transition_identity_required = _canonical_identity_fields(
        "bundle_lifecycle_transition",
        "transition_id",
    )
    result["contracts/quality/bundle-lifecycle-transition.schema.json"] = _schema_artifact(
        "quality/bundle-lifecycle-transition.schema.json",
        "Agent Bundle Append Only Lifecycle Transition",
        {
            "transition_id": _content_id(),
            "agent_bundle_id": _content_id(),
            "agent_bundle_hash": _hash(),
            "qualification_record_id": nullable(_content_id()),
            "qualification_record_hash": nullable(_hash()),
            "from_state": s_string(enum=bundle_states),
            "to_state": s_string(enum=bundle_states),
            "evidence_class": s_string(
                enum=("qualification", "boundary_fixture", "release")
            ),
            "environment": s_string(enum=PROMOTION_ENVIRONMENTS),
            "policy_hash": _hash(),
            "corpus_hash": _hash(),
            "environment_hash": _hash(),
            "fixture_or_release_unit_hash": _hash(),
            "actor_id": _text(256),
            "reason_code": _text(128),
            "evidence_root": _hash(),
            "occurred_at": _time(),
            **lifecycle_transition_identity,
        },
        (
            "transition_id",
            "agent_bundle_id",
            "agent_bundle_hash",
            "qualification_record_id",
            "qualification_record_hash",
            "from_state",
            "to_state",
            "evidence_class",
            "environment",
            "policy_hash",
            "corpus_hash",
            "environment_hash",
            "fixture_or_release_unit_hash",
            "actor_id",
            "reason_code",
            "evidence_root",
            "occurred_at",
            *lifecycle_transition_identity_required,
        ),
        data_class="internal_operational",
        max_bytes=262144,
        flow_ids=("F22", "F24"),
        description=(
            "Append-only quality/release lifecycle edge for an immutable AgentBundle; "
            "qualification and boundary-fixture records never mutate the bundle or a real pointer."
        ),
        one_of=[
            _branch(
                required=(),
                constants={
                    "from_state": from_state,
                    "to_state": to_state,
                    "evidence_class": evidence_class,
                    "environment": environment,
                },
            )
            for from_state, to_state, evidence_class, environment in lifecycle_edges
        ],
    )
    return result


def _deployment_profile_schema() -> Artifact:
    resource_class = s_object(
        {
            "class_id": _text(128),
            "minimum_count": s_integer(minimum=0, maximum=10_000),
            "maximum_count": s_integer(minimum=0, maximum=10_000),
        },
        ("class_id", "minimum_count", "maximum_count"),
    )
    profile_properties = {
        "profile_id": s_string(enum=DEPLOYMENT_PROFILES),
        "profile_version": _semver(),
        "profile_hash": _hash(),
        "implementation_default": s_boolean(),
        "roots": s_array(_text(256), min_items=1, max_items=32, unique=True),
        "modules": s_array(_text(256), min_items=1, max_items=128, unique=True),
        "persistent_inventory": s_array(resource_class, min_items=0, max_items=128),
        "windowed_inventory": s_array(resource_class, min_items=0, max_items=128),
        "data_eligibility": s_string(
            enum=("synthetic_only", "sanitized_non_customer", "provider_backed_nonprod", "customer_data")
        ),
        "evidence_requirements": s_array(_text(256), min_items=1, max_items=64, unique=True),
        "forbidden_combinations": s_array(_text(256), min_items=1, max_items=64, unique=True),
        "allows_customer_cells": s_boolean(),
        "allows_cutover": s_boolean(),
        "requires_ha_recovery_support": s_boolean(),
    }
    profile_required = tuple(profile_properties)
    return _schema_artifact(
        "release/deployment-profile.schema.json",
        "Closed Deployment Profile Contract",
        profile_properties,
        profile_required,
        data_class="internal_operational",
        max_bytes=262144,
        flow_ids=("F24", "F27"),
        description="Exact ADR-027 composition profile; unknown IDs and ad-hoc feature flags are invalid.",
        one_of=[
            {
                "required": list(profile),
                "properties": {
                    field: {"const": value} for field, value in profile.items()
                },
            }
            for profile in _profile_registry()["profiles"]
        ],
    )


def _profile_registry() -> dict[str, Any]:
    version = "1.0.0"
    common_forbidden = [
        "unknown profile IDs or undeclared module overrides",
        "evidence substitution from a weaker profile",
        "ad-hoc feature flags that alter authority or recovery guarantees",
    ]
    registry = {
        "schema_version": "1.0.0",
        "registry_version": version,
        "default_profile_id": "ephemeral-nonprod",
        "profiles": [
            {
                "schema_version": "1.0.0",
                "profile_id": "local",
                "profile_version": version,
                "profile_hash": "1" * 64,
                "implementation_default": False,
                "roots": ["infra/local"],
                "modules": ["local-compose", "synthetic-provider-fixtures"],
                "persistent_inventory": [{"class_id": "developer-state", "minimum_count": 0, "maximum_count": 1}],
                "windowed_inventory": [{"class_id": "synthetic-cell", "minimum_count": 0, "maximum_count": 8}],
                "data_eligibility": "synthetic_only",
                "evidence_requirements": ["local-contract-and-unit-evidence"],
                "forbidden_combinations": [*common_forbidden, "customer data or provider credentials", "release qualification or cutover"],
                "allows_customer_cells": False,
                "allows_cutover": False,
                "requires_ha_recovery_support": False,
            },
            {
                "schema_version": "1.0.0",
                "profile_id": "ephemeral-nonprod",
                "profile_version": version,
                "profile_hash": "2" * 64,
                "implementation_default": True,
                "roots": ["infra/live/nonprod-foundation", "infra/live/nonprod-windowed"],
                "modules": ["state-lock", "oidc-deploy", "windowed-shared", "synthetic-cell"],
                "persistent_inventory": [{"class_id": "state-and-security-logs", "minimum_count": 1, "maximum_count": 8}],
                "windowed_inventory": [{"class_id": "nonprod-shared-and-cell", "minimum_count": 0, "maximum_count": 64}],
                "data_eligibility": "sanitized_non_customer",
                "evidence_requirements": ["materialize-smoke-drain-destroy", "zero-windowed-inventory-receipt"],
                "forbidden_combinations": [*common_forbidden, "customer data, production activation, or cutover", "windowed resources retained after the declared run"],
                "allows_customer_cells": False,
                "allows_cutover": False,
                "requires_ha_recovery_support": False,
            },
            {
                "schema_version": "1.0.0",
                "profile_id": "persistent-nonprod",
                "profile_version": version,
                "profile_hash": "3" * 64,
                "implementation_default": False,
                "roots": ["infra/live/nonprod-persistent"],
                "modules": ["shared-control", "mothership", "provider-backed-nonprod", "recovery-drill"],
                "persistent_inventory": [{"class_id": "nonprod-shared-platform", "minimum_count": 1, "maximum_count": 64}],
                "windowed_inventory": [{"class_id": "qualification-cell", "minimum_count": 0, "maximum_count": 128}],
                "data_eligibility": "provider_backed_nonprod",
                "evidence_requirements": ["staging-readiness", "provider-backed-corridor", "restore-and-rollback-drill"],
                "forbidden_combinations": [*common_forbidden, "customer production data or paid cutover", "production readiness claims"],
                "allows_customer_cells": False,
                "allows_cutover": False,
                "requires_ha_recovery_support": True,
            },
            {
                "schema_version": "1.0.0",
                "profile_id": "paid-production",
                "profile_version": version,
                "profile_hash": "4" * 64,
                "implementation_default": False,
                "roots": ["infra/live/prod-control", "infra/live/prod-mothership", "infra/live/prod-cells"],
                "modules": ["multi-az-control", "cross-account-backup", "purpose-bound-signers", "customer-cell", "support-and-monitoring"],
                "persistent_inventory": [{"class_id": "production-shared-and-recovery", "minimum_count": 1, "maximum_count": 256}],
                "windowed_inventory": [{"class_id": "customer-cell", "minimum_count": 0, "maximum_count": 10_000}],
                "data_eligibility": "customer_data",
                "evidence_requirements": ["production-readiness", "paid-support-and-recovery", "fresh-cost-baseline", "production-release-approval"],
                "forbidden_combinations": [*common_forbidden, "weaker-profile readiness import", "customer cell without complete ReleaseUnit"],
                "allows_customer_cells": True,
                "allows_cutover": True,
                "requires_ha_recovery_support": True,
            },
        ],
    }
    for profile in registry["profiles"]:
        canonical_payload = {key: value for key, value in profile.items() if key != "profile_hash"}
        profile["profile_hash"] = hashlib.sha256(
            json.dumps(
                canonical_payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    return registry


RUBRIC_GROUPS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("R001-R003", ("P00",), "P00"),
    ("R004", ("P01",), "P01"),
    ("R005", ("P02", "P20"), "P02"),
    ("R006", ("P02", "P04", "P05", "P08", "P12", "P16", "P21"), "P02"),
    ("R007", ("P00", "P02"), "P00"),
    ("R008", ("P02", "P08"), "P08"),
    ("R009", ("P02", "P20"), "P02"),
    ("R010", ("P02", "P08", "P15", "P26"), "P02"),
    ("R011", ("P00",), "P00"),
    ("R012", ("P01", "P02", "P03", "P08", "P09", "P10", "P11", "P12", "P13", "P19", "P20", "P21"), "P01"),
    ("R013", ("P01", "P03"), "P03"),
    ("R014", ("P04",), "P04"),
    ("R015", ("P05", "P16"), "P05"),
    ("R016", ("P04",), "P04"),
    ("R017", ("P07", "P11", "P13"), "P07"),
    ("R018-R019", ("P13",), "P13"),
    ("R020-R021", ("P15",), "P15"),
    ("R022-R023", ("P16",), "P16"),
    ("R024", ("P13", "P15", "P16", "P17", "P18"), "P16"),
    ("R025", ("P17",), "P17"),
    ("R026", ("P12", "P13", "P17", "P18"), "P17"),
    ("R027", ("P17", "P18"), "P18"),
    ("R028", ("P11", "P15", "P18", "P20"), "P11"),
    ("R029", ("P06", "P10", "P27", "P28"), "P06"),
    ("R030", ("P06",), "P06"),
    ("R031", ("P06", "P10"), "P06"),
    ("R032", ("P07", "P08", "P11", "P12", "P19", "P20"), "P07"),
    ("R033", ("P04", "P06", "P07", "P08", "P10", "P12", "P19", "P20", "P23"), "P08"),
    ("R034", ("P08",), "P08"),
    ("R035", ("P04", "P08", "P10", "P11", "P12"), "P12"),
    ("R036", ("P04", "P08", "P12"), "P12"),
    ("R037", ("P19",), "P19"),
    ("R038", ("P07", "P08", "P11", "P14", "P16", "P23"), "P14"),
    ("R039", ("P07", "P08", "P12", "P19", "P20"), "P20"),
    ("R040", ("P20",), "P20"),
    ("R041", ("P11", "P12"), "P11"),
    ("R042", ("P19", "P20", "P21"), "P21"),
    ("R043", ("P04", "P05", "P08", "P10", "P11", "P12", "P14", "P20", "P21"), "P21"),
    ("R044", ("P00", "P02", "P04", "P06", "P07", "P08", "P10", "P22", "P23", "P24"), "P23"),
    ("R045", ("P08", "P22", "P24"), "P24"),
    ("R046", ("P08", "P22", "P24", "P25"), "P24"),
    ("R047-R048", ("P08", "P14", "P15", "P20", "P22", "P24"), "P24"),
    ("R049", ("P08", "P17", "P22", "P24", "P25"), "P24"),
    ("R050", ("P08", "P22", "P24"), "P24"),
    ("R051", ("P08", "P22", "P24", "P25"), "P24"),
    ("R052", ("P08", "P14", "P23", "P24"), "P23"),
    ("R053", ("P06", "P08", "P25"), "P25"),
    ("R054", ("P22", "P23", "P24", "P25"), "P22"),
    ("R055", ("P09",), "P09"),
    ("R056", ("P02", "P09", "P10", "P11"), "P10"),
    ("R057", ("P04", "P08", "P10", "P11", "P21"), "P10"),
    ("R058", ("P10",), "P10"),
    ("R059", ("P05", "P11", "P12"), "P11"),
    ("R060", ("P04", "P05", "P08", "P11", "P12"), "P11"),
    ("R061", ("P07", "P08", "P11", "P12", "P19", "P20"), "P11"),
    ("R062", ("P03", "P04", "P08", "P10", "P11", "P12", "P13", "P19", "P20", "P21"), "P03"),
    ("R063", ("P08", "P10", "P11", "P12", "P17", "P20"), "P10"),
    ("R064", ("P04", "P05", "P08", "P09", "P10", "P11", "P12"), "P10"),
    ("R065", ("P07", "P08", "P10", "P11", "P26"), "P08"),
    ("R066", ("P04", "P06", "P07", "P08", "P09", "P10", "P11", "P12", "P20"), "P10"),
    ("R067", ("P06", "P07", "P08", "P11", "P14", "P23"), "P23"),
    ("R068", ("P11", "P13", "P17"), "P13"),
    ("R069", ("P07", "P13", "P14", "P20", "P21"), "P14"),
    ("R070", ("P08", "P14", "P19", "P20", "P23"), "P23"),
    ("R071", ("P07", "P08", "P14", "P15", "P19", "P20", "P24"), "P15"),
    ("R072", ("P07", "P08", "P16", "P18", "P24", "P26"), "P16"),
    ("R073", ("P08", "P15", "P16", "P24"), "P16"),
    ("R074", ("P08", "P10", "P12", "P13", "P14", "P15", "P16", "P17", "P18", "P25", "P26"), "P17"),
    ("R075", ("P07", "P08", "P15", "P18", "P20"), "P18"),
    ("R076", ("P04", "P05", "P06", "P07", "P08", "P10", "P12", "P14", "P16", "P17", "P18", "P19", "P20", "P24", "P25", "P26"), "P26"),
    ("R077", ("P04", "P05", "P06", "P07", "P08", "P10", "P12", "P13", "P16", "P17", "P18", "P19", "P20", "P24", "P25", "P26"), "P26"),
    ("R078", ("P04", "P05", "P07", "P08", "P12", "P13", "P16", "P17", "P18", "P19", "P20", "P24", "P25", "P26"), "P26"),
    ("R079", ("P10", "P17", "P25", "P26"), "P26"),
    ("R080", ("P06", "P07", "P08", "P10", "P11", "P25", "P26"), "P26"),
    ("R081", ("P07", "P08", "P10", "P18", "P20", "P24", "P25", "P26"), "P08"),
    ("R082", ("P27", "P28"), "P28"),
)


def _rubric_numbers(expression: str) -> list[int]:
    body = expression.removeprefix("R")
    if "-R" not in body:
        return [int(body)]
    start, end = body.split("-R", 1)
    return list(range(int(start), int(end) + 1))


def _rubric_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for expression, producers, owner in RUBRIC_GROUPS:
        for number in _rubric_numbers(expression):
            qualifiers = {"production": "P28"}
            if number <= 81:
                qualifiers["staging"] = "P27"
            records.append(
                {
                    "rubric_id": f"JSMVP-R{number:03d}",
                    "producer_packets": list(producers),
                    "qualifier_packets_by_stage": qualifiers,
                    "write_owner_packet": owner,
                    "plan_refs": ["acceptance-rubric.md"],
                    "commands": ["make release-qualify"],
                }
            )
    if len(records) != 82 or len({record["rubric_id"] for record in records}) != 82:
        raise ValueError("rubric ownership declaration must expand to exactly 82 unique rows")
    return records


def _rubric_ownership_schema() -> Artifact:
    packet = s_string(pattern=r"^P(?:0[0-9]|1[0-9]|2[0-8])$")
    shared = {
        "producer_packets": s_array(packet, min_items=1, max_items=29, unique=True),
        "write_owner_packet": packet,
        "plan_refs": s_array(_text(256), min_items=1, max_items=32, unique=True),
        "commands": s_array(_text(512), min_items=1, max_items=64, unique=True),
    }
    staged = s_object(
        {"staging": s_string(const="P27"), "production": s_string(const="P28")},
        ("staging", "production"),
    )
    production_only = s_object(
        {"production": s_string(const="P28")},
        ("production",),
    )
    record = {
        "oneOf": [
            s_object(
                {
                    "rubric_id": s_string(pattern=r"^JSMVP-R(?:00[1-9]|0[1-7][0-9]|080|081)$"),
                    **shared,
                    "qualifier_packets_by_stage": staged,
                },
                ("rubric_id", *shared, "qualifier_packets_by_stage"),
            ),
            s_object(
                {
                    "rubric_id": s_string(const="JSMVP-R082"),
                    **shared,
                    "qualifier_packets_by_stage": production_only,
                },
                ("rubric_id", *shared, "qualifier_packets_by_stage"),
            ),
        ]
    }
    rubric_ids = tuple(f"JSMVP-R{number:03d}" for number in range(1, 83))
    return _schema_artifact(
        "release/rubric-ownership.schema.json",
        "MVP Rubric Ownership Map Contract",
        {
            "map_version": _semver(),
            "source_document": s_string(const="acceptance-rubric.md"),
            "records": s_array(record, min_items=82, max_items=82),
        },
        ("map_version", "source_document", "records"),
        data_class="internal_operational",
        max_bytes=2_097_152,
        flow_ids=("F24",),
        description="Exact 82-row producer, stage qualifier, and sole remediation-owner routing map.",
        all_of=[
            {
                "properties": {
                    "records": {
                        "contains": {
                            "properties": {"rubric_id": {"const": rubric_id}},
                            "required": ["rubric_id"],
                        },
                        "minContains": 1,
                        "maxContains": 1,
                    }
                }
            }
            for rubric_id in rubric_ids
        ],
    )


def _release_artifacts() -> dict[str, Artifact]:
    result: dict[str, Artifact] = {
        "contracts/release/deployment-profile.schema.json": _deployment_profile_schema(),
        "contracts/release/rubric-ownership.schema.json": _rubric_ownership_schema(),
    }
    result["contracts/release/deployment-profiles.yaml"] = json_artifact(
        _profile_registry(), "application/yaml"
    )
    result["contracts/release/mvp-rubric-ownership.yaml"] = json_artifact(
        {
            "schema_version": "1.0.0",
            "map_version": "1.0.0",
            "source_document": "acceptance-rubric.md",
            "records": _rubric_records(),
        },
        "application/yaml",
    )

    composition_receipt_identity, composition_receipt_identity_required = _canonical_identity_fields(
        "composition_gate_receipt",
        "composition_gate_receipt_id",
    )
    result["contracts/release/composition-gate-receipt.schema.json"] = _schema_artifact(
        "release/composition-gate-receipt.schema.json",
        "Composition Gate Receipt Contract",
        {
            "composition_gate_receipt_id": _content_id(),
            "gate_id": s_string(enum=("J13", "J19")),
            "owner_packet": s_string(enum=("P13", "P19")),
            "source_commit": s_string(pattern=r"^[0-9a-f]{40}$"),
            "dependency_handoff_root": _hash(),
            "composition_root": _hash(),
            "normal_binary_digest": _hash(),
            "check_binary_digest": _hash(),
            "image_digest": _hash(),
            "command_root": _hash(),
            "test_root": _hash(),
            "import_graph_root": _hash(),
            "ownership_root": _hash(),
            "no_effect_root": _hash(),
            "content_sha256": _hash(),
            "created_at": _time(),
            **composition_receipt_identity,
        },
        (
            "composition_gate_receipt_id",
            "gate_id",
            "owner_packet",
            "source_commit",
            "dependency_handoff_root",
            "composition_root",
            "normal_binary_digest",
            "check_binary_digest",
            "image_digest",
            "command_root",
            "test_root",
            "import_graph_root",
            "ownership_root",
            "no_effect_root",
            "content_sha256",
            "created_at",
            *composition_receipt_identity_required,
        ),
        data_class="internal_operational",
        max_bytes=262144,
        flow_ids=("F24",),
        description="Unsigned content-addressed J13/J19 composition proof consumed by release evidence.",
    )

    no_effect_check_identity, no_effect_check_identity_required = _canonical_identity_fields(
        "no_effect_check",
        "no_effect_check_id",
    )
    result["contracts/release/no-effect-check.schema.json"] = _schema_artifact(
        "release/no-effect-check.schema.json",
        "Deployment No Effect Check Contract",
        {
            "no_effect_check_id": _content_id(),
            "artifact_kind": s_string(enum=("oci_image", "web_deployment", "ami", "binary")),
            "artifact_digest": _hash(),
            "deployment_id": _text(256),
            "config_hash": _hash(),
            "contract_manifest_hash": _hash(),
            "binding_inventory_version": s_integer(minimum=0),
            "binding_inventory_root": _hash(),
            "probe_image_digest": _hash(),
            "listener_count": s_integer(minimum=0, maximum=0),
            "consumer_count": s_integer(minimum=0, maximum=0),
            "scheduler_count": s_integer(minimum=0, maximum=0),
            "writer_authority_count": s_integer(minimum=0, maximum=0),
            "grant_authority_count": s_integer(minimum=0, maximum=0),
            "lifecycle_authority_count": s_integer(minimum=0, maximum=0),
            "route_authority_count": s_integer(minimum=0, maximum=0),
            "signer_authority_count": s_integer(minimum=0, maximum=0),
            "result": s_string(enum=("pass", "fail")),
            "result_root": _hash(),
            "checked_at": _time(),
            **no_effect_check_identity,
        },
        (
            "no_effect_check_id",
            "artifact_kind",
            "artifact_digest",
            "deployment_id",
            "config_hash",
            "contract_manifest_hash",
            "binding_inventory_version",
            "binding_inventory_root",
            "probe_image_digest",
            "listener_count",
            "consumer_count",
            "scheduler_count",
            "writer_authority_count",
            "grant_authority_count",
            "lifecycle_authority_count",
            "route_authority_count",
            "signer_authority_count",
            "result",
            "result_root",
            "checked_at",
            *no_effect_check_identity_required,
        ),
        data_class="internal_operational",
        max_bytes=262144,
        flow_ids=("F24", "F27"),
        description="Zero-traffic probe proving a candidate has no listener, consumer, scheduler, writer, grant, route, lifecycle, or signer authority.",
    )

    readiness_receipt_identity, readiness_receipt_identity_required = _canonical_identity_fields(
        "deployment_readiness_receipt",
        "deployment_readiness_receipt_id",
        additional_excluded_fields=("signature_envelope_hash",),
    )
    result["contracts/release/deployment-readiness-receipt.schema.json"] = _schema_artifact(
        "release/deployment-readiness-receipt.schema.json",
        "Deployment Readiness Receipt Contract",
        {
            "deployment_readiness_receipt_id": _content_id(),
            "release_unit_id": _content_id(),
            "release_unit_hash": _hash(),
            "environment": s_string(enum=ENVIRONMENTS),
            "stage": s_string(enum=STAGES),
            "deployment_profile_id": s_string(enum=DEPLOYMENT_PROFILES),
            "deployment_profile_version": _semver(),
            "deployment_profile_hash": _hash(),
            "prior_deployment_id": nullable(_uuid()),
            "candidate_deployment_id": _uuid(),
            "deployment_generation": s_integer(minimum=1),
            "expand_migration_root": _hash(),
            "registered_artifact_root": _hash(),
            "registered_bundle_id": _content_id(),
            "qualification_record_id": _content_id(),
            "task_inventory_root": _hash(),
            "web_deployment_root": _hash(),
            "no_effect_check_root": _hash(),
            "zero_traffic_health_root": _hash(),
            "backup_root": _hash(),
            "rollback_root": _hash(),
            "active_cell_binding_inventory_version": s_integer(minimum=0),
            "active_cell_binding_inventory_root": _hash(),
            "binding_compatibility_root": _hash(),
            "opentofu_plan_root": _hash(),
            "resource_graph_root": _hash(),
            "materialized_inventory_root": _hash(),
            "issued_at": _time(),
            "expires_at": _time(),
            "signature_purpose": s_string(const="deployment_readiness"),
            "signature_envelope_hash": _hash(),
            **readiness_receipt_identity,
        },
        (
            "deployment_readiness_receipt_id",
            "release_unit_id",
            "release_unit_hash",
            "environment",
            "stage",
            "deployment_profile_id",
            "deployment_profile_version",
            "deployment_profile_hash",
            "prior_deployment_id",
            "candidate_deployment_id",
            "deployment_generation",
            "expand_migration_root",
            "registered_artifact_root",
            "registered_bundle_id",
            "qualification_record_id",
            "task_inventory_root",
            "web_deployment_root",
            "no_effect_check_root",
            "zero_traffic_health_root",
            "backup_root",
            "rollback_root",
            "active_cell_binding_inventory_version",
            "active_cell_binding_inventory_root",
            "binding_compatibility_root",
            "opentofu_plan_root",
            "resource_graph_root",
            "materialized_inventory_root",
            "issued_at",
            "expires_at",
            "signature_purpose",
            "signature_envelope_hash",
            *readiness_receipt_identity_required,
        ),
        data_class="security_material",
        max_bytes=524288,
        flow_ids=("F24", "F27"),
        description="Signed zero-authority readiness proof bound to exact release, profile, generation, inventory, and every active binding.",
        one_of=_environment_profile_branches(),
    )

    fixed_item = s_object(
        {
            "provider": _text(128),
            "product": _text(128),
            "region": _text(64),
            "currency": s_string(pattern=r"^[A-Z]{3}$"),
            "unit": _text(64),
            "quantity": s_number(minimum=0.0, maximum=1_000_000.0),
            "unit_price": s_number(minimum=0.0, maximum=1_000_000_000.0),
            "source_url_hash": _hash(),
            "source_document_hash": _hash(),
            "effective_date": s_string(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"),
        },
        (
            "provider",
            "product",
            "region",
            "currency",
            "unit",
            "quantity",
            "unit_price",
            "source_url_hash",
            "source_document_hash",
            "effective_date",
        ),
    )
    fixed_cost_identity, fixed_cost_identity_required = _canonical_identity_fields(
        "fixed_cost_inputs",
        "fixed_cost_input_id",
    )
    result["contracts/release/fixed-cost-inputs.schema.json"] = _schema_artifact(
        "release/fixed-cost-inputs.schema.json",
        "Reviewed Fixed Cost Inputs Contract",
        {
            "fixed_cost_input_id": _content_id(),
            "input_version": _semver(),
            "items": s_array(fixed_item, min_items=1, max_items=256),
            "currency": s_string(pattern=r"^[A-Z]{3}$"),
            "approver_id": _text(256),
            "approval_evidence_root": _hash(),
            "effective_at": _time(),
            "expires_at": _time(),
            "content_sha256": _hash(),
            **fixed_cost_identity,
        },
        (
            "fixed_cost_input_id",
            "input_version",
            "items",
            "currency",
            "approver_id",
            "approval_evidence_root",
            "effective_at",
            "expires_at",
            "content_sha256",
            *fixed_cost_identity_required,
        ),
        data_class="internal_operational",
        max_bytes=524288,
        flow_ids=("F24",),
        description="Reviewed non-IaC charges such as support and Vercel inputs with immutable sources and expiry.",
    )

    cost_baseline_identity, cost_baseline_identity_required = _canonical_identity_fields(
        "cost_baseline",
        "cost_baseline_id",
    )
    result["contracts/release/cost-baseline.schema.json"] = _schema_artifact(
        "release/cost-baseline.schema.json",
        "Environment Cost Baseline Contract",
        {
            "cost_baseline_id": _content_id(),
            "environment": s_string(enum=ENVIRONMENTS),
            "stage": s_string(enum=STAGES),
            "deployment_profile_id": s_string(enum=DEPLOYMENT_PROFILES),
            "deployment_profile_version": _semver(),
            "deployment_profile_hash": _hash(),
            "opentofu_plan_root": _hash(),
            "resource_graph_root": _hash(),
            "materialized_inventory_root": _hash(),
            "aws_price_list_offer": _text(128),
            "aws_price_list_version": _text(128),
            "aws_price_list_source_root": _hash(),
            "fixed_cost_input_id": _content_id(),
            "fixed_cost_input_hash": _hash(),
            "currency": s_string(pattern=r"^[A-Z]{3}$"),
            "fixed_floor_amount": s_number(minimum=0.0),
            "cell_cost_minimum": s_number(minimum=0.0),
            "cell_cost_maximum": s_number(minimum=0.0),
            "assumptions": s_array(_text(512), min_items=1, max_items=128, unique=True),
            "exclusions": s_array(_text(512), min_items=0, max_items=128, unique=True),
            "variance_policy_id": _text(128),
            "generated_at": _time(),
            "expires_at": _time(),
            "content_sha256": _hash(),
            **cost_baseline_identity,
        },
        (
            "cost_baseline_id",
            "environment",
            "stage",
            "deployment_profile_id",
            "deployment_profile_version",
            "deployment_profile_hash",
            "opentofu_plan_root",
            "resource_graph_root",
            "materialized_inventory_root",
            "aws_price_list_offer",
            "aws_price_list_version",
            "aws_price_list_source_root",
            "fixed_cost_input_id",
            "fixed_cost_input_hash",
            "currency",
            "fixed_floor_amount",
            "cell_cost_minimum",
            "cell_cost_maximum",
            "assumptions",
            "exclusions",
            "variance_policy_id",
            "generated_at",
            "expires_at",
            "content_sha256",
            *cost_baseline_identity_required,
        ),
        data_class="internal_operational",
        max_bytes=524288,
        flow_ids=("F24", "F27"),
        description="Content-addressed profile, plan, inventory, price-source, fixed-input, and variance-policy cost baseline.",
        one_of=_environment_profile_branches(),
    )

    release_member_kinds = (
        "source",
        "source_plan",
        "capability_registry",
        "contract",
        "generated_client",
        "runtime_image",
        "ami",
        "tool",
        "web_deployment",
        "auth_config",
        "composition_gate",
        "agent_bundle",
        "provider_data_use_record",
        "qualification_record",
        "cli",
        "skill",
        "proof_verifier",
        "corpus",
        "checker",
        "grader",
        "infrastructure_module",
        "infrastructure_provider_lock",
        "signer_policy",
        "trust_anchor",
        "crl_profile",
        "customer_incapability_catalog",
        "rubric_ownership",
    )
    release_singletons = (
        "source",
        "source_plan",
        "capability_registry",
        "agent_bundle",
        "provider_data_use_record",
        "qualification_record",
        "proof_verifier",
        "customer_incapability_catalog",
        "rubric_ownership",
    )
    boundary_required_kinds = (
        "source",
        "source_plan",
        "capability_registry",
        "contract",
        "generated_client",
        "runtime_image",
        "tool",
        "agent_bundle",
        "provider_data_use_record",
        "qualification_record",
        "proof_verifier",
        "corpus",
        "checker",
        "grader",
        "customer_incapability_catalog",
        "rubric_ownership",
    )
    release_member = _digest_ref(release_member_kinds)
    release_environment_artifacts = s_object(
        {
            "staging": s_object(
                {
                    "web_deployment": _environment_digest_ref(
                        "web_deployment", "staging"
                    ),
                    "auth_config": _environment_digest_ref("auth_config", "staging"),
                },
                ("web_deployment", "auth_config"),
            ),
            "production": s_object(
                {
                    "web_deployment": _environment_digest_ref(
                        "web_deployment", "production"
                    ),
                    "auth_config": _environment_digest_ref(
                        "auth_config", "production"
                    ),
                },
                ("web_deployment", "auth_config"),
            ),
        },
        ("staging", "production"),
    )
    release_unit_identity, release_unit_identity_required = _canonical_identity_fields(
        "release_unit",
        "release_unit_id",
        additional_excluded_fields=("signature_envelope_hash",),
    )
    result["contracts/release/release-unit.schema.json"] = _schema_artifact(
        "release/release-unit.schema.json",
        "Immutable Release Unit Contract",
        {
            "release_unit_id": _content_id(),
            "release_unit_version": _semver(),
            "evidence_class": s_string(enum=("release", "boundary_fixture")),
            "synthetic": s_boolean(),
            "environment_scope": s_array(
                s_string(enum=("isolated-quality", "staging", "production")),
                min_items=1,
                max_items=2,
                unique=True,
            ),
            "source_commit": s_string(pattern=r"^[0-9a-f]{40}$"),
            "source_plan_hash": _hash(),
            "capability_registry_hash": _hash(),
            "contract_manifest_hash": _hash(),
            "rubric_ownership_schema_hash": _hash(),
            "rubric_ownership_source_hash": _hash(),
            "rubric_ownership_expanded_hash": _hash(),
            "customer_incapability_catalog_hash": _hash(),
            "customer_incapability_source_registry_hash": _hash(),
            "j13_composition_gate_hash": _hash(),
            "j19_composition_gate_hash": _hash(),
            "environment_artifacts": release_environment_artifacts,
            "members": s_array(
                release_member,
                min_items=len(boundary_required_kinds),
                max_items=512,
                unique=True,
            ),
            "content_sha256": _hash(),
            "created_at": _time(),
            "signature_purpose": s_string(
                enum=("release_evidence", "boundary_fixture")
            ),
            "signature_envelope_hash": _hash(),
            **release_unit_identity,
        },
        (
            "release_unit_id",
            "release_unit_version",
            "evidence_class",
            "synthetic",
            "environment_scope",
            "source_commit",
            "source_plan_hash",
            "capability_registry_hash",
            "contract_manifest_hash",
            "rubric_ownership_schema_hash",
            "rubric_ownership_source_hash",
            "rubric_ownership_expanded_hash",
            "customer_incapability_catalog_hash",
            "customer_incapability_source_registry_hash",
            "j13_composition_gate_hash",
            "j19_composition_gate_hash",
            "members",
            "content_sha256",
            "created_at",
            "signature_purpose",
            "signature_envelope_hash",
            *release_unit_identity_required,
        ),
        data_class="security_material",
        max_bytes=2_097_152,
        flow_ids=("F24",),
        description="Canonical content-addressed release composition; any member change creates a new unit. It binds the exact immutable customer-incapability catalog and source-registry hashes one-way; the separately derived reverse binding is not a ReleaseUnit member.",
        semantic_invariants=(
            "customer_incapability_catalog_contains_no_release_unit_or_response_metadata",
            "release_unit_binds_exact_customer_incapability_catalog_and_source_registry_hashes",
            "customer_incapability_catalog_binding_is_derived_only_after_release_unit_identity",
            "customer_incapability_catalog_binding_is_not_a_release_unit_member",
        ),
        one_of=[
            _branch(
                required=(),
                constants={
                    "evidence_class": "boundary_fixture",
                    "synthetic": True,
                    "environment_scope": ["isolated-quality"],
                    "signature_purpose": "boundary_fixture",
                },
                property_constraints={
                    "members": _required_kind_array_schema(
                        boundary_required_kinds,
                        singleton_kinds=tuple(
                            kind
                            for kind in release_singletons
                            if kind in boundary_required_kinds
                        ),
                    )
                },
                forbidden=("environment_artifacts",),
            ),
            _branch(
                required=("environment_artifacts",),
                constants={
                    "evidence_class": "release",
                    "synthetic": False,
                    "environment_scope": ["staging", "production"],
                    "signature_purpose": "release_evidence",
                },
                property_constraints={
                    "members": _required_kind_array_schema(
                        release_member_kinds,
                        singleton_kinds=release_singletons,
                    )
                },
            ),
        ],
    )

    lane_run = s_object(
        {
            "lane_id": _text(128),
            "command": _text(512),
            "window_start": _time(),
            "window_end": _time(),
            "input_root": _hash(),
        },
        ("lane_id", "command", "window_start", "window_end", "input_root"),
    )
    test_manifest_identity, test_manifest_identity_required = _canonical_identity_fields(
        "test_run_manifest",
        "test_run_manifest_id",
        additional_excluded_fields=(
            "manifest_root",
            "signature_envelope_hash",
        ),
    )
    result["contracts/release/test-run-manifest.schema.json"] = _schema_artifact(
        "release/test-run-manifest.schema.json",
        "Immutable Qualification Test Run Manifest",
        {
            "test_run_manifest_id": _content_id(),
            "qualification_run_id": _uuid(),
            "environment": s_string(enum=("staging", "production")),
            "stage": s_string(enum=("persistent", "paid")),
            "release_unit_id": _content_id(),
            "release_unit_hash": _hash(),
            "deployment_profile_id": s_string(enum=("persistent-nonprod", "paid-production")),
            "deployment_profile_version": _semver(),
            "deployment_profile_hash": _hash(),
            "materialized_inventory_root": _hash(),
            "rubric_ownership_source_hash": _hash(),
            "rubric_ownership_expanded_hash": _hash(),
            "deployment_readiness_receipt_hash": _hash(),
            "promotion_envelope_hash": _hash(),
            "activation_receipt_hash": _hash(),
            "selected_web_deployment_hash": _hash(),
            "selected_auth_config_hash": _hash(),
            "selected_environment_config_hash": _hash(),
            "provider_data_use_review_hash": _hash(),
            "provider_evidence_transition_hash": _hash(),
            "registry_inventory_root": _hash(),
            "crl_inventory_root": _hash(),
            "presentation_key_inventory_root": _hash(),
            "cost_baseline_id": _content_id(),
            "cost_baseline_hash": _hash(),
            "cost_baseline_environment": s_string(enum=("staging", "production")),
            "cost_baseline_stage": s_string(enum=("persistent", "paid")),
            "cost_baseline_generated_at": _time(),
            "cost_baseline_expires_at": _time(),
            "opentofu_plan_root": _hash(),
            "resource_graph_root": _hash(),
            "aws_price_list_source_root": _hash(),
            "fixed_cost_input_hash": _hash(),
            "variance_policy_id": _text(128),
            "dataset_root": _hash(),
            "corpus_root": _hash(),
            "lane_runs": s_array(lane_run, min_items=1, max_items=256),
            "manifest_root": _hash(),
            "created_at": _time(),
            "signature_envelope_hash": _hash(),
            **test_manifest_identity,
        },
        (
            "test_run_manifest_id",
            "qualification_run_id",
            "environment",
            "stage",
            "release_unit_id",
            "release_unit_hash",
            "deployment_profile_id",
            "deployment_profile_version",
            "deployment_profile_hash",
            "materialized_inventory_root",
            "rubric_ownership_source_hash",
            "rubric_ownership_expanded_hash",
            "deployment_readiness_receipt_hash",
            "promotion_envelope_hash",
            "activation_receipt_hash",
            "selected_web_deployment_hash",
            "selected_auth_config_hash",
            "selected_environment_config_hash",
            "provider_data_use_review_hash",
            "provider_evidence_transition_hash",
            "registry_inventory_root",
            "crl_inventory_root",
            "presentation_key_inventory_root",
            "cost_baseline_id",
            "cost_baseline_hash",
            "cost_baseline_environment",
            "cost_baseline_stage",
            "cost_baseline_generated_at",
            "cost_baseline_expires_at",
            "opentofu_plan_root",
            "resource_graph_root",
            "aws_price_list_source_root",
            "fixed_cost_input_hash",
            "variance_policy_id",
            "dataset_root",
            "corpus_root",
            "lane_runs",
            "manifest_root",
            "created_at",
            "signature_envelope_hash",
            *test_manifest_identity_required,
        ),
        data_class="security_material",
        max_bytes=2_097_152,
        flow_ids=("F24", "F27"),
        description="One immutable environment/stage qualification manifest; outcomes never rewrite it.",
        one_of=[
            _branch(
                required=(),
                constants={
                    "environment": "staging",
                    "stage": "persistent",
                    "deployment_profile_id": "persistent-nonprod",
                    "cost_baseline_environment": "staging",
                    "cost_baseline_stage": "persistent",
                },
            ),
            _branch(
                required=(),
                constants={
                    "environment": "production",
                    "stage": "paid",
                    "deployment_profile_id": "paid-production",
                    "cost_baseline_environment": "production",
                    "cost_baseline_stage": "paid",
                },
            ),
        ],
    )

    acceptance_result_identity, acceptance_result_identity_required = _canonical_identity_fields(
        "acceptance_result",
        "acceptance_result_id",
        additional_excluded_fields=(
            "applicability_rule_signature_envelope_hash",
            "signature_envelope_hash",
        ),
    )
    result["contracts/release/acceptance-result.schema.json"] = _schema_artifact(
        "release/acceptance-result.schema.json",
        "Manifest Bound Acceptance Result",
        {
            "acceptance_result_id": _content_id(),
            "rubric_id": s_string(pattern=r"^JSMVP-R(?:00[1-9]|0[1-7][0-9]|08[0-2])$"),
            "test_run_manifest_id": _content_id(),
            "test_run_manifest_hash": _hash(),
            "qualifier_packet": s_string(enum=("P27", "P28")),
            "environment": s_string(enum=("staging", "production")),
            "status": s_string(enum=("pass", "fail", "blocked", "not_applicable")),
            "evidence_mode": s_string(enum=("fresh", "reused")),
            "lane_run_root": _hash(),
            "artifact_root": _hash(),
            "source_result_hash": nullable(_hash()),
            "source_manifest_hash": nullable(_hash()),
            "source_evidence_index_hash": nullable(_hash()),
            "source_environment": nullable(s_string(enum=("staging",))),
            "reuse_policy_id": nullable(_text(128)),
            "applicability_rule_hash": nullable(_hash()),
            "applicability_rule_signature_envelope_hash": nullable(_hash()),
            "applicability_evidence_root": nullable(_hash()),
            "reviewer_id": _text(256),
            "result_root": _hash(),
            "completed_at": _time(),
            "signature_envelope_hash": _hash(),
            **acceptance_result_identity,
        },
        (
            "acceptance_result_id",
            "rubric_id",
            "test_run_manifest_id",
            "test_run_manifest_hash",
            "qualifier_packet",
            "environment",
            "status",
            "evidence_mode",
            "lane_run_root",
            "artifact_root",
            "source_result_hash",
            "source_manifest_hash",
            "source_evidence_index_hash",
            "source_environment",
            "reuse_policy_id",
            "applicability_rule_hash",
            "applicability_rule_signature_envelope_hash",
            "applicability_evidence_root",
            "reviewer_id",
            "result_root",
            "completed_at",
            "signature_envelope_hash",
            *acceptance_result_identity_required,
        ),
        data_class="security_material",
        max_bytes=262144,
        flow_ids=("F24",),
        description="Fresh environment-manifest-bound result; not-applicable and reused evidence require explicit provenance.",
        one_of=[
            _branch(
                required=(),
                constants={
                    "evidence_mode": "fresh",
                    "environment": "staging",
                    "qualifier_packet": "P27",
                    "source_result_hash": None,
                    "source_manifest_hash": None,
                    "source_evidence_index_hash": None,
                    "source_environment": None,
                    "reuse_policy_id": None,
                },
            ),
            _branch(
                required=(),
                constants={
                    "evidence_mode": "fresh",
                    "environment": "production",
                    "qualifier_packet": "P28",
                    "source_result_hash": None,
                    "source_manifest_hash": None,
                    "source_evidence_index_hash": None,
                    "source_environment": None,
                    "reuse_policy_id": None,
                },
            ),
            _branch(
                required=(
                    "source_result_hash",
                    "source_manifest_hash",
                    "source_evidence_index_hash",
                    "source_environment",
                    "reuse_policy_id",
                ),
                constants={
                    "evidence_mode": "reused",
                    "environment": "production",
                    "qualifier_packet": "P28",
                    "source_environment": "staging",
                },
                property_constraints={
                    "rubric_id": {"enum": list(PRODUCTION_REUSE_RUBRIC_IDS)},
                    "source_result_hash": _hash(),
                    "source_manifest_hash": _hash(),
                    "source_evidence_index_hash": _hash(),
                    "reuse_policy_id": _text(128),
                },
            ),
        ],
        all_of=[
            {
                "if": {
                    "properties": {"status": {"const": "not_applicable"}},
                    "required": ["status"],
                },
                "then": {
                    "properties": {
                        "applicability_rule_hash": _hash(),
                        "applicability_rule_signature_envelope_hash": _hash(),
                        "applicability_evidence_root": _hash(),
                    }
                },
                "else": {
                    "properties": {
                        "applicability_rule_hash": {"type": "null"},
                        "applicability_rule_signature_envelope_hash": {
                            "type": "null"
                        },
                        "applicability_evidence_root": {"type": "null"},
                    }
                },
            }
        ],
    )

    evidence_entry = s_object(
        {
            "rubric_id": s_string(pattern=r"^JSMVP-R(?:00[1-9]|0[1-7][0-9]|08[0-2])$"),
            "acceptance_result_id": _content_id(),
            "acceptance_result_hash": _hash(),
            "plan_refs_root": _hash(),
            "mode": s_string(enum=("fresh", "reused")),
            "status": s_string(enum=("pass", "fail", "blocked", "not_applicable")),
            "lane_run_root": _hash(),
            "artifact_root": _hash(),
            "source_root": nullable(_hash()),
        },
        (
            "rubric_id",
            "acceptance_result_id",
            "acceptance_result_hash",
            "plan_refs_root",
            "mode",
            "status",
            "lane_run_root",
            "artifact_root",
            "source_root",
        ),
    )
    evidence_entry["oneOf"] = [
        _branch(
            required=(),
            constants={"mode": "fresh", "source_root": None},
        ),
        _branch(
            required=("source_root",),
            constants={"mode": "reused"},
            property_constraints={"source_root": _hash()},
        ),
    ]
    staging_rubric_ids = tuple(
        f"JSMVP-R{number:03d}" for number in range(1, 82)
    )
    production_rubric_ids = tuple(
        f"JSMVP-R{number:03d}" for number in range(1, 83)
    )
    mandatory_production_rerun_ids = tuple(
        rubric_id
        for rubric_id in production_rubric_ids
        if rubric_id not in PRODUCTION_REUSE_RUBRIC_IDS
    )
    staging_entry_constraint = _exact_discriminator_array_constraint(
        "rubric_id", staging_rubric_ids
    )
    staging_entry_constraint["items"] = {
        "properties": {"mode": {"const": "fresh"}},
        "required": ["mode"],
    }
    production_entry_constraint = _exact_discriminator_array_constraint(
        "rubric_id", production_rubric_ids
    )
    production_entry_constraint["allOf"].extend(
        {
            "contains": {
                "properties": {
                    "rubric_id": {"const": rubric_id},
                    "mode": {"const": "fresh"},
                },
                "required": ["rubric_id", "mode"],
            },
            "minContains": 1,
            "maxContains": 1,
        }
        for rubric_id in mandatory_production_rerun_ids
    )
    evidence_index_identity, evidence_index_identity_required = _canonical_identity_fields(
        "evidence_index",
        "evidence_index_id",
        additional_excluded_fields=("index_root", "signature_envelope_hash"),
    )
    result["contracts/release/evidence-index.schema.json"] = _schema_artifact(
        "release/evidence-index.schema.json",
        "Qualification Evidence Index",
        {
            "evidence_index_id": _content_id(),
            "test_run_manifest_id": _content_id(),
            "test_run_manifest_hash": _hash(),
            "release_unit_id": _content_id(),
            "release_unit_hash": _hash(),
            "environment": s_string(enum=("staging", "production")),
            "qualifier_packet": s_string(enum=("P27", "P28")),
            "rubric_ownership_source_hash": _hash(),
            "rubric_ownership_expanded_hash": _hash(),
            "entries": s_array(
                evidence_entry,
                min_items=81,
                max_items=82,
                unique=True,
            ),
            "provider_transition_chain_root": _hash(),
            "registry_supersession_chain_root": _hash(),
            "crl_supersession_chain_root": _hash(),
            "cost_variance_root": _hash(),
            "index_root": _hash(),
            "created_at": _time(),
            "signature_purpose": s_string(const="release_evidence"),
            "signature_envelope_hash": _hash(),
            **evidence_index_identity,
        },
        (
            "evidence_index_id",
            "test_run_manifest_id",
            "test_run_manifest_hash",
            "release_unit_id",
            "release_unit_hash",
            "environment",
            "qualifier_packet",
            "rubric_ownership_source_hash",
            "rubric_ownership_expanded_hash",
            "entries",
            "provider_transition_chain_root",
            "registry_supersession_chain_root",
            "crl_supersession_chain_root",
            "cost_variance_root",
            "index_root",
            "created_at",
            "signature_purpose",
            "signature_envelope_hash",
            *evidence_index_identity_required,
        ),
        data_class="security_material",
        max_bytes=4_194_304,
        flow_ids=("F24", "F27"),
        description="Signed complete staging or production result index including fresh/reused provenance and supersession chains.",
        one_of=[
            _branch(
                required=(),
                constants={"environment": "staging", "qualifier_packet": "P27"},
                property_constraints={
                    "entries": staging_entry_constraint
                },
            ),
            _branch(
                required=(),
                constants={"environment": "production", "qualifier_packet": "P28"},
                property_constraints={
                    "entries": production_entry_constraint
                },
            ),
        ],
    )
    return result


def _proof_artifacts() -> dict[str, Artifact]:
    result: dict[str, Artifact] = {}
    integrity_identity, integrity_identity_required = _canonical_identity_fields(
        "integrity_envelope",
        "integrity_envelope_id",
        additional_excluded_fields=("signature_envelope_hash",),
    )
    result["contracts/proof/integrity-envelope.schema.json"] = _schema_artifact(
        "proof/integrity-envelope.schema.json",
        "Migration Integrity Envelope Contract",
        {
            "integrity_envelope_id": _content_id(),
            "workspace_id": _uuid(),
            "migration_id": _uuid(),
            "cell_id": _uuid(),
            "cell_generation": s_integer(minimum=1),
            "proof_version": _semver(),
            "mapping_spec_hash": _hash(),
            "verification_rubric_hash": _hash(),
            "source_manifest_root": _hash(),
            "target_manifest_root": _hash(),
            "both_direction_set_root": _hash(),
            "query_semantic_root": _hash(),
            "evidence_index_root": _hash(),
            "public_key_fingerprint": _hash(),
            "signature_purpose": s_string(const="migration_integrity_proof"),
            "signature_envelope_hash": _hash(),
            "issued_at": _time(),
            **integrity_identity,
        },
        (
            "integrity_envelope_id",
            "workspace_id",
            "migration_id",
            "cell_id",
            "cell_generation",
            "proof_version",
            "mapping_spec_hash",
            "verification_rubric_hash",
            "source_manifest_root",
            "target_manifest_root",
            "both_direction_set_root",
            "query_semantic_root",
            "evidence_index_root",
            "public_key_fingerprint",
            "signature_purpose",
            "signature_envelope_hash",
            "issued_at",
            *integrity_identity_required,
        ),
        data_class="security_material",
        max_bytes=524288,
        flow_ids=("F20", "F24"),
        description="Detached purpose-specific signed migration integrity proof with all schema and evidence roots.",
    )

    deletion_component = s_object(
        {
            "component_id": _text(256),
            "component_kind": s_string(
                enum=("credential", "cell", "ebs", "s3_object", "kms_key", "provider_resource", "monitoring")
            ),
            "state": s_string(enum=("access_disabled", "deletion_scheduled", "deleted", "retained_until")),
            "receipt_hash": _hash(),
            "retain_until": nullable(_time()),
        },
        ("component_id", "component_kind", "state", "receipt_hash", "retain_until"),
    )
    deletion_request_identity, deletion_request_identity_required = _canonical_identity_fields(
        "deletion_attestation_request",
        "deletion_attestation_request_id",
    )
    result["contracts/proof/deletion-attestation-request.schema.json"] = _schema_artifact(
        "proof/deletion-attestation-request.schema.json",
        "Deletion Attestation Request Contract",
        {
            "deletion_attestation_request_id": _content_id(),
            "workspace_id": _uuid(),
            "migration_id": _uuid(),
            "decommission_consent_id": _uuid(),
            "decommission_consent_hash": _hash(),
            "attestation_stage": s_string(enum=("preliminary", "final")),
            "component_inventory_version": s_integer(minimum=1),
            "components": s_array(deletion_component, min_items=1, max_items=4096),
            "component_inventory_root": _hash(),
            "object_lock_root": _hash(),
            "kms_deletion_root": _hash(),
            "provider_deletion_root": _hash(),
            "requested_at": _time(),
            **deletion_request_identity,
        },
        (
            "deletion_attestation_request_id",
            "workspace_id",
            "migration_id",
            "decommission_consent_id",
            "decommission_consent_hash",
            "attestation_stage",
            "component_inventory_version",
            "components",
            "component_inventory_root",
            "object_lock_root",
            "kms_deletion_root",
            "provider_deletion_root",
            "requested_at",
            *deletion_request_identity_required,
        ),
        data_class="security_material",
        max_bytes=2_097_152,
        flow_ids=("F20", "F24", "F27"),
        description="Complete component receipt inventory submitted to the isolated deletion attestor.",
    )

    deletion_envelope_identity, deletion_envelope_identity_required = _canonical_identity_fields(
        "deletion_attestation_envelope",
        "deletion_attestation_envelope_id",
        additional_excluded_fields=("signature_envelope_hash",),
    )
    result["contracts/proof/deletion-attestation-envelope.schema.json"] = _schema_artifact(
        "proof/deletion-attestation-envelope.schema.json",
        "Deletion Attestation Envelope Contract",
        {
            "deletion_attestation_envelope_id": _content_id(),
            "deletion_attestation_request_id": _content_id(),
            "deletion_attestation_request_hash": _hash(),
            "attestation_stage": s_string(enum=("preliminary", "final")),
            "result": s_string(enum=("access_disabled_and_scheduled", "fully_deleted", "blocked")),
            "component_inventory_root": _hash(),
            "remaining_retention_count": s_integer(minimum=0, maximum=4096),
            "earliest_remaining_retain_until": nullable(_time()),
            "kms_waiting_count": s_integer(minimum=0, maximum=4096),
            "issued_at": _time(),
            "signature_purpose": s_string(const="deletion_attestation"),
            "signature_envelope_hash": _hash(),
            **deletion_envelope_identity,
        },
        (
            "deletion_attestation_envelope_id",
            "deletion_attestation_request_id",
            "deletion_attestation_request_hash",
            "attestation_stage",
            "result",
            "component_inventory_root",
            "remaining_retention_count",
            "earliest_remaining_retain_until",
            "kms_waiting_count",
            "issued_at",
            "signature_purpose",
            "signature_envelope_hash",
            *deletion_envelope_identity_required,
        ),
        data_class="security_material",
        max_bytes=262144,
        flow_ids=("F20", "F24", "F27"),
        description="Dedicated surviving-key preliminary or final deletion attestation; it cannot claim deletion before retention ends.",
        one_of=[
            _branch(
                required=(),
                constants={"attestation_stage": "preliminary", "result": "access_disabled_and_scheduled"},
            ),
            _branch(
                required=(),
                constants={
                    "attestation_stage": "final",
                    "result": "fully_deleted",
                    "remaining_retention_count": 0,
                    "kms_waiting_count": 0,
                    "earliest_remaining_retain_until": None,
                },
            ),
            _branch(required=(), constants={"result": "blocked"}),
        ],
    )

    return result


FIXTURE_UUIDS = {
    "one": "00000000-0000-7000-8000-000000000001",
    "two": "00000000-0000-7000-8000-000000000002",
    "three": "00000000-0000-7000-8000-000000000003",
    "four": "00000000-0000-7000-8000-000000000004",
}
FIXTURE_HASH = "a" * 64
FIXTURE_TIME = "2026-07-18T00:00:00Z"
FIXTURE_EXPIRY = "2026-07-18T00:05:00Z"


def _canonical_identity_fixture(
    object_type: str,
    id_field: str,
    *,
    additional_excluded_fields: tuple[str, ...] = (),
) -> dict[str, Any]:
    excluded_fields = (
        id_field,
        "content_sha256",
        "logical_payload_sha256",
        "logical_payload_projection",
        *additional_excluded_fields,
    )
    return {
        "logical_payload_sha256": FIXTURE_HASH,
        "logical_payload_projection": {
            "object_type": object_type,
            "id_field": id_field,
            "object_schema_version": "1.0.0",
            "canonical_encoder": "RFC8785_JCS",
            "domain_separator": f"jumpship:{object_type}:1.0.0\u0000",
            "excluded_fields": list(dict.fromkeys(excluded_fields)),
            "id_encoding": "lowercase_hex_sha256",
            "id_equals_logical_payload_sha256": True,
        },
    }


def _fixture_case(schema_path: str, expectation: str, reason: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_path": schema_path,
        "expectation": expectation,
        "reason": reason,
        "payload": payload,
    }


def _tool_fixture(mode: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "tool_id": "repo.inspect.v1",
        "tool_version": "1.0.0",
        "display_summary": "Inspect repository metadata",
        "drilldown_description": "Read-only bounded repository inspection with no durable authority.",
        "allowed_phases": ["discovery", "design"],
        "execution_mode": mode,
        "consequence_class": "observation",
        "reversibility_class": "not_applicable",
        "warning_rule": "none",
        "safe_failure": "grant_no_effect_authority",
        "input_schema_hash": FIXTURE_HASH,
        "output_schema_hash": FIXTURE_HASH,
        "receipt_schema_id": "https://jumpship.dev/contracts/agent/tool-receipt.schema.json",
        "receipt_schema_hash": FIXTURE_HASH,
        "capability_requirements": {
            "capability_ids": ["MVP-CAP-ARCHAEOLOGY"],
            "grant_purposes": ["repository_inspection"],
        },
        "gate_requirements": [],
        "consent_requirement": "none",
        "idempotency_scope": "none_read_only",
        "timeout_ms": 30000,
        "retry_policy": {
            "strategy": "same_identity_only",
            "max_attempts": 1,
            "backoff_ms": 0,
            "retryable_error_codes": [],
            "requires_reconciliation": False,
        },
        "limits": {
            "max_input_bytes": 4096,
            "max_output_bytes": 4096,
            "max_memory_bytes": 67108864,
            "max_cpu_millis": 30000,
            "max_wall_clock_ms": 30000,
            "network_mode": "none",
            "max_artifacts": 0,
        },
        "input_data_class": "internal_operational",
        "output_data_class": "internal_operational",
        "run_brief_authorization": {
            "inline_authorizable": True,
            "descriptor_hash": FIXTURE_HASH,
            "authorized_descriptor_set_hash": FIXTURE_HASH,
            "max_cumulative_input_bytes": 16384,
            "max_cumulative_output_bytes": 16384,
            "max_cumulative_invocations": 4,
            "max_cumulative_wall_clock_ms": 60000,
            "max_cumulative_cpu_millis": 60000,
            "max_memory_bytes": 67108864,
            "max_rate_per_minute": 4,
            "allowed_data_classes": ["internal_operational"],
            "may_widen_to_durable": False,
        },
    }


def _promotion_base(
    kind: str,
    mode: str,
    purpose: str,
    *,
    evidence_class: str = "release",
) -> dict[str, Any]:
    is_boundary = evidence_class == "boundary_fixture"
    return {
        "schema_version": "1.0.0",
        "promotion_envelope_id": FIXTURE_HASH,
        "kind": kind,
        "mode": mode,
        "purpose": purpose,
        "evidence_class": evidence_class,
        "synthetic": is_boundary,
        "environment": "isolated-quality" if is_boundary else "staging",
        "stage": "ephemeral" if is_boundary else "persistent",
        "release_unit_id": FIXTURE_HASH,
        "release_unit_hash": FIXTURE_HASH,
        "agent_bundle_id": FIXTURE_HASH,
        "agent_bundle_hash": FIXTURE_HASH,
        "candidate_deployment_id": FIXTURE_UUIDS["four"],
        "deployment_generation": 1,
        "expected_pointer_version": 1,
        "observed_current_pointer_id": FIXTURE_UUIDS["two"],
        "observed_current_pointer_version": 1,
        "current_inventory_version": 1,
        "current_inventory_root": FIXTURE_HASH,
        "current_live_binding_count": 0,
        "approval_records": [
            {
                "role": role,
                "approver_id": f"fixture-{role}",
                "decision": "approved",
                "evidence_root": FIXTURE_HASH,
                "approved_at": FIXTURE_TIME,
            }
            for role in ("release_owner", "quality_owner")
        ],
        "distinct_approver_count": 2,
        "issued_at": FIXTURE_TIME,
        "expires_at": FIXTURE_EXPIRY,
        "nonce_hash": FIXTURE_HASH,
        "signature_envelope_hash": FIXTURE_HASH,
        **_canonical_identity_fixture(
            "promotion_envelope",
            "promotion_envelope_id",
            additional_excluded_fields=("signature_envelope_hash",),
        ),
    }


def _emergency_approvals() -> dict[str, Any]:
    return {
        "approval_records": [
            {
                "role": role,
                "approver_id": f"fixture-{role}",
                "decision": "approved",
                "evidence_root": FIXTURE_HASH,
                "approved_at": FIXTURE_TIME,
            }
            for role in ("release_owner", "security_owner", "incident_commander")
        ],
        "distinct_approver_count": 3,
    }


def _readiness_fields() -> dict[str, Any]:
    return {
        "qualification_record_id": FIXTURE_HASH,
        "qualification_record_hash": FIXTURE_HASH,
        "deployment_readiness_receipt_hash": FIXTURE_HASH,
        "readiness_inventory_version": 1,
        "readiness_inventory_root": FIXTURE_HASH,
        "rollout_bounds": {
            "maximum_percent": 10,
            "maximum_concurrent_bindings": 1,
            "deadline": FIXTURE_EXPIRY,
        },
        "stop_conditions": ["any readiness or inventory drift"],
    }


def _fixture_artifacts() -> dict[str, Artifact]:
    ordinary = {
        **_promotion_base("activate", "ordinary", "bundle_promotion"),
        **_readiness_fields(),
        "expected_prior_pointer_id": FIXTURE_UUIDS["two"],
        "approved_rollback_target_id": FIXTURE_UUIDS["two"],
        "approved_rollback_target_hash": FIXTURE_HASH,
        "rollback_takeover": False,
    }
    ordinary_rollback = {
        **_promotion_base("rollback", "ordinary", "bundle_promotion"),
        **_readiness_fields(),
        "expected_prior_pointer_id": FIXTURE_UUIDS["two"],
        "approved_rollback_target_id": FIXTURE_UUIDS["three"],
        "approved_rollback_target_hash": FIXTURE_HASH,
        "rollback_takeover": False,
    }
    rollback_takeover = {
        **_promotion_base(
            "rollback", "ordinary_rollback_takeover", "bundle_promotion"
        ),
        **_readiness_fields(),
        "expected_prior_pointer_id": FIXTURE_UUIDS["two"],
        "approved_rollback_target_id": FIXTURE_UUIDS["three"],
        "approved_rollback_target_hash": FIXTURE_HASH,
        "rollback_takeover": True,
        "expected_failed_activation_transaction_id": FIXTURE_UUIDS["four"],
        "expected_failed_activation_fence_generation": 2,
    }
    genesis = {
        **_promotion_base("activate", "genesis", "bundle_promotion"),
        **_readiness_fields(),
        "expected_prior_pointer_id": None,
        "expected_pointer_version": 0,
        "observed_current_pointer_id": None,
        "observed_current_pointer_version": 0,
        "genesis_transaction_id": FIXTURE_UUIDS["one"],
        "zero_binding_inventory_root": FIXTURE_HASH,
    }
    bootstrap = {
        **_promotion_base("activate", "bootstrap_recovery", "bundle_promotion"),
        **_emergency_approvals(),
        **_readiness_fields(),
        "expected_prior_pointer_id": FIXTURE_UUIDS["two"],
        "genesis_transaction_id": FIXTURE_UUIDS["one"],
        "zero_binding_inventory_root": FIXTURE_HASH,
        "current_candidate_emergency_revoked": True,
        "no_serving_history": True,
        "immediate_activation_receipt_hash": FIXTURE_HASH,
        "immediate_emergency_receipt_hash": FIXTURE_HASH,
        "recovery_chain_root": FIXTURE_HASH,
    }
    emergency_recovery = {
        **_promotion_base("activate", "emergency_recovery", "bundle_promotion"),
        **_emergency_approvals(),
        **_readiness_fields(),
        "expected_prior_pointer_id": FIXTURE_UUIDS["two"],
        "current_candidate_emergency_revoked": True,
        "all_affected_bindings_stopped": True,
        "rollback_candidate_inventory_version": 2,
        "rollback_candidate_inventory_root": FIXTURE_HASH,
        "rollback_support_policy_version": "support-policy-v1",
        "eligible_supported_rollback_count": 0,
        "immediate_emergency_receipt_hash": FIXTURE_HASH,
        "recovery_chain_root": FIXTURE_HASH,
        "incident_recovery_root": FIXTURE_HASH,
    }
    emergency_stop = {
        **_promotion_base(
            "emergency_stop",
            "emergency_stop_current_active_not_serving",
            "release_emergency_stop",
        ),
        **_emergency_approvals(),
        "emergency_target_mode": "current_active_not_serving",
        "target_activation_transaction_id": FIXTURE_UUIDS["one"],
        "target_open_fence_generation": 1,
        "incident_id": FIXTURE_UUIDS["two"],
    }
    emergency_stop_supported = {
        **_promotion_base(
            "emergency_stop",
            "emergency_stop_supported",
            "release_emergency_stop",
        ),
        **_emergency_approvals(),
        "emergency_target_mode": "supported",
        "target_support_record_hash": FIXTURE_HASH,
        "incident_id": FIXTURE_UUIDS["two"],
    }
    boundary_ordinary = {
        **_promotion_base(
            "activate",
            "ordinary",
            "bundle_promotion",
            evidence_class="boundary_fixture",
        ),
        **_readiness_fields(),
        "expected_prior_pointer_id": FIXTURE_UUIDS["two"],
        "approved_rollback_target_id": FIXTURE_UUIDS["two"],
        "approved_rollback_target_hash": FIXTURE_HASH,
        "rollback_takeover": False,
    }
    provider_lease = {
        "schema_version": "1.0.0",
        "lease_id": FIXTURE_UUIDS["one"],
        "reservation_id": FIXTURE_UUIDS["two"],
        "cell_id": FIXTURE_UUIDS["three"],
        "cell_generation": 1,
        "cell_release_binding_hash": FIXTURE_HASH,
        "provider_data_use_record_id": FIXTURE_HASH,
        "provider_data_use_record_hash": FIXTURE_HASH,
        "accepted_transition_id": FIXTURE_HASH,
        "accepted_transition_sequence": 1,
        "accepted_status_hash": FIXTURE_HASH,
        "agent_bundle_id": FIXTURE_HASH,
        "agent_bundle_hash": FIXTURE_HASH,
        "release_unit_id": FIXTURE_HASH,
        "release_unit_hash": FIXTURE_HASH,
        "control_epoch": 1,
        "no_unresolved_binding_hold": True,
        "issued_at": FIXTURE_TIME,
        "expires_at": "2026-07-18T00:01:00Z",
        "ttl_seconds": 60,
        "nonce_hash": FIXTURE_HASH,
        "signature_purpose": "provider_use_lease",
        "signature_envelope_hash": FIXTURE_HASH,
    }
    provider_review = {
        "schema_version": "1.0.0",
        "review_id": FIXTURE_HASH,
        "provider_data_use_record_id": FIXTURE_HASH,
        "provider_data_use_record_hash": FIXTURE_HASH,
        "review_version": "1.0.0",
        "source_snapshot_hash": FIXTURE_HASH,
        "result": "approved",
        "approvals": [
            {
                "role": role,
                "approver_id": f"fixture-provider-{role}",
                "decision": "approved",
                "evidence_root": FIXTURE_HASH,
                "approved_at": FIXTURE_TIME,
            }
            for role in ("legal", "security", "product")
        ],
        "distinct_approver_count": 3,
        "reviewed_at": FIXTURE_TIME,
        "valid_until": FIXTURE_EXPIRY,
        "validity_seconds": 300,
        "payload_hash": FIXTURE_HASH,
        **_canonical_identity_fixture(
            "provider_data_use_review",
            "review_id",
            additional_excluded_fields=("payload_hash",),
        ),
    }
    provider_status = {
        "schema_version": "1.0.0",
        "status_id": FIXTURE_HASH,
        "provider_data_use_record_id": FIXTURE_HASH,
        "provider_data_use_record_hash": FIXTURE_HASH,
        "status": "review_valid",
        "reason_code": "review_accepted",
        "source_check_hash": FIXTURE_HASH,
        "effective_at": FIXTURE_TIME,
        "payload_hash": FIXTURE_HASH,
        **_canonical_identity_fixture(
            "provider_data_use_status",
            "status_id",
            additional_excluded_fields=("payload_hash",),
        ),
    }
    provider_transition = {
        "schema_version": "1.0.0",
        "transition_id": FIXTURE_HASH,
        "transition_kind": "review",
        "provider_data_use_record_id": FIXTURE_HASH,
        "provider_data_use_record_hash": FIXTURE_HASH,
        "sequence": 1,
        "predecessor_transition_id": None,
        "predecessor_transition_hash": None,
        "expected_review_head_id": None,
        "expected_review_head_hash": None,
        "expected_status_head_id": None,
        "expected_status_head_hash": None,
        "review_payload": provider_review,
        "review_payload_hash": FIXTURE_HASH,
        "status_payload": provider_status,
        "status_payload_hash": FIXTURE_HASH,
        "request_id": FIXTURE_UUIDS["one"],
        "reservation_id": FIXTURE_UUIDS["two"],
        "object_key_hash": FIXTURE_HASH,
        "binding_inventory_version": 0,
        "binding_inventory_root": FIXTURE_HASH,
        "route_hold_root": FIXTURE_HASH,
        "lease_cutoff_at": FIXTURE_EXPIRY,
        "signature_purpose": "provider_data_use_review",
        "signature_envelope_hash": FIXTURE_HASH,
        "created_at": FIXTURE_TIME,
        **_canonical_identity_fixture(
            "provider_evidence_transition",
            "transition_id",
            additional_excluded_fields=("signature_envelope_hash",),
        ),
    }
    bundle_transition = {
        "schema_version": "1.0.0",
        "transition_id": FIXTURE_HASH,
        "agent_bundle_id": FIXTURE_HASH,
        "agent_bundle_hash": FIXTURE_HASH,
        "qualification_record_id": FIXTURE_HASH,
        "qualification_record_hash": FIXTURE_HASH,
        "from_state": "offline_qualified",
        "to_state": "boundary_shadow",
        "evidence_class": "boundary_fixture",
        "environment": "isolated-quality",
        "policy_hash": FIXTURE_HASH,
        "corpus_hash": FIXTURE_HASH,
        "environment_hash": FIXTURE_HASH,
        "fixture_or_release_unit_hash": FIXTURE_HASH,
        "actor_id": "fixture-quality-owner",
        "reason_code": "shadow_window_started",
        "evidence_root": FIXTURE_HASH,
        "occurred_at": FIXTURE_TIME,
        **_canonical_identity_fixture(
            "bundle_lifecycle_transition",
            "transition_id",
        ),
    }
    profile = _profile_registry()["profiles"][1]
    return {
        "contracts/agent/fixtures/execution-mode-valid.json": json_artifact(
            {
                "schema_version": "1.0.0",
                "cases": [_fixture_case("contracts/agent/tool.schema.json", "valid", "declared inline observation", _tool_fixture("inline"))],
            },
            "application/json",
        ),
        "contracts/agent/fixtures/execution-mode-invalid.json": json_artifact(
            {
                "schema_version": "1.0.0",
                "cases": [_fixture_case("contracts/agent/tool.schema.json", "invalid", "undeclared unrestricted mode", _tool_fixture("unrestricted"))],
            },
            "application/json",
        ),
        "contracts/agent/fixtures/provider-control-valid.json": json_artifact(
            {
                "schema_version": "1.0.0",
                "cases": [
                    _fixture_case("contracts/agent/provider-use-lease.schema.json", "valid", "60-second hold-free lease", provider_lease),
                    _fixture_case(
                        "contracts/agent/provider-evidence-transition.schema.json",
                        "valid",
                        "three-role review embeds approved review and review-valid status",
                        provider_transition,
                    ),
                ],
            },
            "application/json",
        ),
        "contracts/agent/fixtures/provider-control-invalid.json": json_artifact(
            {
                "schema_version": "1.0.0",
                "semantic_cases": [
                    {
                        "expectation": "invalid",
                        "reason": "declared TTL does not equal the signed lease interval",
                        "payload": {
                            **provider_lease,
                            "expires_at": "2026-07-18T00:05:00Z",
                        },
                    },
                    {
                        "expectation": "invalid",
                        "reason": "signed lease interval exceeds the 60-second ceiling",
                        "payload": {
                            **provider_lease,
                            "expires_at": "2026-07-19T00:00:00Z",
                        },
                    },
                ],
                "cases": [
                    _fixture_case(
                        "contracts/agent/provider-use-lease.schema.json",
                        "invalid",
                        "lease exceeds maximum declared lifetime",
                        {
                            **provider_lease,
                            "expires_at": "2026-07-18T00:01:01Z",
                            "ttl_seconds": 61,
                        },
                    ),
                    _fixture_case(
                        "contracts/agent/provider-data-use-review.schema.json",
                        "invalid",
                        "approved review cannot duplicate a role or omit product approval",
                        {
                            **provider_review,
                            "approvals": [
                                provider_review["approvals"][0],
                                provider_review["approvals"][1],
                                {
                                    **provider_review["approvals"][1],
                                    "approver_id": "fixture-second-security",
                                },
                            ],
                        },
                    ),
                    _fixture_case(
                        "contracts/agent/provider-evidence-transition.schema.json",
                        "invalid",
                        "review transition cannot embed an invalidated status",
                        {
                            **provider_transition,
                            "status_payload": {
                                **provider_status,
                                "status": "invalidated",
                                "reason_code": "manual_invalidation",
                            },
                        },
                    ),
                ],
            },
            "application/json",
        ),
        "contracts/quality/fixtures/promotion-modes-valid.json": json_artifact(
            {
                "schema_version": "1.0.0",
                "cases": [
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "valid", "ordinary activation with rollback", ordinary),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "valid", "ordinary rollback with fresh readiness", ordinary_rollback),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "valid", "rollback takeover binds failed activation fence", rollback_takeover),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "valid", "strict empty-stage genesis", genesis),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "valid", "receipt-chained unserved bootstrap recovery", bootstrap),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "valid", "post-serving emergency recovery with empty rollback inventory", emergency_recovery),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "valid", "current active-not-serving emergency stop", emergency_stop),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "valid", "supported target emergency stop", emergency_stop_supported),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "valid", "isolated boundary-fixture activation", boundary_ordinary),
                ],
            },
            "application/json",
        ),
        "contracts/quality/fixtures/promotion-modes-invalid.json": json_artifact(
            {
                "schema_version": "1.0.0",
                "cases": [
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "invalid", "ordinary activation omits rollback target", {key: value for key, value in ordinary.items() if key not in {"approved_rollback_target_id", "approved_rollback_target_hash"}}),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "invalid", "ordinary activation cannot omit its predecessor", {**ordinary, "expected_prior_pointer_id": None}),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "invalid", "promotion cannot carry a denied approval", {**ordinary, "approval_records": [{**ordinary["approval_records"][0], "decision": "denied"}]}),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "invalid", "genesis carries a rollback target", {**genesis, "approved_rollback_target_id": FIXTURE_UUIDS["two"], "approved_rollback_target_hash": FIXTURE_HASH}),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "invalid", "rollback takeover omits failed fence", {key: value for key, value in rollback_takeover.items() if key != "expected_failed_activation_fence_generation"}),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "invalid", "bootstrap recovery is under-approved", {**bootstrap, "approval_records": [bootstrap["approval_records"][0]], "distinct_approver_count": 1}),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "invalid", "emergency recovery has an eligible supported rollback", {**emergency_recovery, "eligible_supported_rollback_count": 1}),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "invalid", "emergency stop attempts to carry readiness", {**emergency_stop, "deployment_readiness_receipt_hash": FIXTURE_HASH}),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "invalid", "supported emergency stop carries active-fence authority", {**emergency_stop_supported, "target_open_fence_generation": 3}),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "invalid", "boundary fixture cannot target staging", {**boundary_ordinary, "environment": "staging", "stage": "persistent"}),
                    _fixture_case("contracts/quality/promotion-envelope.schema.json", "invalid", "release envelope cannot target isolated quality", {**ordinary, "environment": "isolated-quality", "stage": "ephemeral"}),
                ],
            },
            "application/json",
        ),
        "contracts/quality/fixtures/bundle-lifecycle-valid.json": json_artifact(
            {
                "schema_version": "1.0.0",
                "cases": [
                    _fixture_case(
                        "contracts/quality/bundle-lifecycle-transition.schema.json",
                        "valid",
                        "offline qualification enters isolated boundary shadow",
                        bundle_transition,
                    )
                ],
            },
            "application/json",
        ),
        "contracts/quality/fixtures/bundle-lifecycle-invalid.json": json_artifact(
            {
                "schema_version": "1.0.0",
                "cases": [
                    _fixture_case(
                        "contracts/quality/bundle-lifecycle-transition.schema.json",
                        "invalid",
                        "boundary fixture cannot jump directly to production authorization",
                        {
                            **bundle_transition,
                            "to_state": "production_authorized",
                            "environment": "production",
                            "evidence_class": "release",
                        },
                    )
                ],
            },
            "application/json",
        ),
        "contracts/release/fixtures/deployment-profile-valid.json": json_artifact(
            {
                "schema_version": "1.0.0",
                "cases": [_fixture_case("contracts/release/deployment-profile.schema.json", "valid", "closed implementation-default profile", profile)],
            },
            "application/json",
        ),
        "contracts/release/fixtures/deployment-profile-invalid.json": json_artifact(
            {
                "schema_version": "1.0.0",
                "cases": [
                    _fixture_case("contracts/release/deployment-profile.schema.json", "invalid", "unknown ad-hoc profile ID", {**profile, "profile_id": "cheap-production"}),
                    _fixture_case(
                        "contracts/release/deployment-profile.schema.json",
                        "invalid",
                        "weaker profile cannot substitute paid-production composition",
                        {
                            **_profile_registry()["profiles"][3],
                            "profile_id": "local",
                        },
                    ),
                ],
            },
            "application/json",
        ),
    }


def artifacts() -> dict[str, Artifact]:
    """Return the deterministic P02 agent/quality/release artifact set."""

    result: dict[str, Artifact] = {}
    for producer in (
        _agent_artifacts,
        _quality_artifacts,
        _release_artifacts,
        _proof_artifacts,
        _fixture_artifacts,
    ):
        for path, artifact in producer().items():
            if path in result:
                raise ValueError(f"duplicate quality/release artifact path: {path}")
            result[path] = artifact
    return result
