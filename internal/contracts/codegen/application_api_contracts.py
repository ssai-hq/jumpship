"""P02 API, cell protocol, client, auth, and application contracts.

This declaration module is intentionally dependency-free.  It describes the
public boundary as data, then emits deterministic JSON-compatible OpenAPI,
strict JSON Schemas, protocol source, and contract fixtures.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from model import (
    Artifact,
    HASH_PATTERN,
    RFC3339_PATTERN,
    SCHEMA_VERSION,
    SEMVER_PATTERN,
    UUID_PATTERN,
    hash_field,
    json_artifact,
    nullable,
    s_array,
    s_boolean,
    s_integer,
    s_object,
    s_string,
    schema,
    text_artifact,
    timestamp_field,
)


def _id() -> dict[str, Any]:
    return s_string(pattern=UUID_PATTERN)


def _hash() -> dict[str, Any]:
    return hash_field()


def _sha() -> dict[str, Any]:
    return s_string(pattern="^[0-9a-f]{40,64}$")


def _name(max_length: int = 128) -> dict[str, Any]:
    return s_string(pattern="^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$", min_length=1, max_length=max_length)


def _safe_text(max_length: int = 4096) -> dict[str, Any]:
    return s_string(min_length=1, max_length=max_length)


def _version() -> dict[str, Any]:
    return s_integer(minimum=1)


def _coverage_state() -> dict[str, Any]:
    return s_string(
        enum=(
            "patched_and_tested",
            "already_target_compatible_with_evidence",
            "customer_validated",
            "explicitly_retired_by_customer",
            "external_unmanaged_writer_with_proven_fence",
            "blocked_manual",
            "blocking_unknown",
        )
    )


def _repository() -> dict[str, Any]:
    return s_object(
        {
            "repository_id": _id(),
            "installation_id": _id(),
            "owner": _name(128),
            "name": _name(128),
            "base_ref": _name(255),
            "pinned_commit_sha": _sha(),
            "permission_proof_version": _version(),
            "permission_proof_root": _hash(),
            "language_profiles": s_array(_name(128), max_items=64, unique=True),
            "build_profiles": s_array(_name(128), max_items=64, unique=True),
            "package_profiles": s_array(_name(128), max_items=128, unique=True),
            "instruction_hashes": s_array(_hash(), max_items=64, unique=True),
            "ci_test_command_hashes": s_array(_hash(), max_items=64, unique=True),
            "coverage_state": _coverage_state(),
            "evidence_root": _hash(),
        },
        (
            "repository_id",
            "installation_id",
            "owner",
            "name",
            "base_ref",
            "pinned_commit_sha",
            "permission_proof_version",
            "permission_proof_root",
            "language_profiles",
            "build_profiles",
            "package_profiles",
            "instruction_hashes",
            "ci_test_command_hashes",
            "coverage_state",
            "evidence_root",
        ),
    )


def _deploy_unit() -> dict[str, Any]:
    return s_object(
        {
            "deploy_unit_id": _id(),
            "repository_id": _id(),
            "path_hash": _hash(),
            "environment": _name(64),
            "deployment_controller": _name(128),
            "coverage_state": _coverage_state(),
            "evidence_root": _hash(),
        },
        ("deploy_unit_id", "repository_id", "path_hash", "environment", "deployment_controller", "coverage_state", "evidence_root"),
    )


def _workload() -> dict[str, Any]:
    return s_object(
        {
            "workload_id": _id(),
            "deploy_unit_id": _id(),
            "kind": s_string(
                enum=(
                    "http_service",
                    "worker",
                    "cron",
                    "queue_consumer",
                    "serverless",
                    "cli",
                    "migration_job",
                    "mobile",
                    "shared_library",
                    "unknown",
                )
            ),
            "runtime": _name(128),
            "language": _name(64),
            "framework": nullable(_name(128)),
            "data_library": nullable(_name(128)),
            "coverage_state": _coverage_state(),
            "evidence_root": _hash(),
        },
        ("workload_id", "deploy_unit_id", "kind", "runtime", "language", "framework", "data_library", "coverage_state", "evidence_root"),
    )


def _data_access_site() -> dict[str, Any]:
    return s_object(
        {
            "site_id": _id(),
            "repository_id": _id(),
            "commit_sha": _sha(),
            "path_hash": _hash(),
            "symbol_hash": _hash(),
            "range_hash": _hash(),
            "content_hash": _hash(),
            "effect": s_string(enum=("read", "write", "admin")),
            "source_namespace_hash": _hash(),
            "query_id": _id(),
            "semantics_root": _hash(),
            "coverage_state": _coverage_state(),
            "evidence_root": _hash(),
        },
        (
            "site_id",
            "repository_id",
            "commit_sha",
            "path_hash",
            "symbol_hash",
            "range_hash",
            "content_hash",
            "effect",
            "source_namespace_hash",
            "query_id",
            "semantics_root",
            "coverage_state",
            "evidence_root",
        ),
    )


def _writer() -> dict[str, Any]:
    return s_object(
        {
            "writer_id": _id(),
            "workload_id": _id(),
            "cohort_id": _id(),
            "principal_hash": _hash(),
            "config_source_hash": _hash(),
            "namespace_roots": s_array(_hash(), min_items=1, max_items=128, unique=True),
            "effect_classes": s_array(_name(64), min_items=1, max_items=32, unique=True),
            "freeze_control_hash": _hash(),
            "drain_control_hash": _hash(),
            "fence_control_hash": _hash(),
            "activation_control_hash": _hash(),
            "smoke_control_hash": _hash(),
            "rollback_control_hash": _hash(),
            "coverage_state": _coverage_state(),
            "evidence_root": _hash(),
        },
        (
            "writer_id",
            "workload_id",
            "cohort_id",
            "principal_hash",
            "config_source_hash",
            "namespace_roots",
            "effect_classes",
            "freeze_control_hash",
            "drain_control_hash",
            "fence_control_hash",
            "activation_control_hash",
            "smoke_control_hash",
            "rollback_control_hash",
            "coverage_state",
            "evidence_root",
        ),
    )


def _application_schemas() -> dict[str, dict[str, Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    schemas["contracts/application/application-estate.schema.json"] = schema(
        "application/application-estate.schema.json",
        "Jumpship Application Estate Manifest Contract",
        {
            "application_estate_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "revision": _version(),
            "repository_set_root": _hash(),
            "evidence_root": _hash(),
            "repositories": s_array(_repository(), min_items=1, max_items=4096),
            "deploy_units": s_array(_deploy_unit(), min_items=1, max_items=8192),
            "workloads": s_array(_workload(), min_items=1, max_items=32768),
            "data_access_sites": s_array(_data_access_site(), min_items=1, max_items=200000),
            "writers": s_array(_writer(), min_items=1, max_items=100000),
            "edge_roots": s_array(_hash(), max_items=200000, unique=True),
            "unknown_finding_roots": s_array(_hash(), max_items=100000, unique=True),
            "coverage_root": _hash(),
            "coverage_complete": s_boolean(),
            "created_at": timestamp_field(),
        },
        (
            "application_estate_id",
            "workspace_id",
            "migration_id",
            "revision",
            "repository_set_root",
            "evidence_root",
            "repositories",
            "deploy_units",
            "workloads",
            "data_access_sites",
            "writers",
            "edge_roots",
            "unknown_finding_roots",
            "coverage_root",
            "coverage_complete",
            "created_at",
        ),
        data_class="restricted_customer",
        max_bytes=67_108_864,
        flow_ids=("F11", "F13"),
        description="Immutable exact-commit census. Unknown or unsupported sites remain explicit blockers.",
    )
    estate_count = s_object(
        {
            "repository_count": s_integer(minimum=0, maximum=4096),
            "deploy_unit_count": s_integer(minimum=0, maximum=8192),
            "workload_count": s_integer(minimum=0, maximum=32768),
            "data_access_site_count": s_integer(minimum=0, maximum=200000),
            "writer_count": s_integer(minimum=0, maximum=100000),
            "blocking_unknown_count": s_integer(minimum=0, maximum=100000),
            "unfenceable_writer_count": s_integer(minimum=0, maximum=100000),
        },
        (
            "repository_count",
            "deploy_unit_count",
            "workload_count",
            "data_access_site_count",
            "writer_count",
            "blocking_unknown_count",
            "unfenceable_writer_count",
        ),
    )
    schemas["contracts/application/application-estate-safe-projection.schema.json"] = schema(
        "application/application-estate-safe-projection.schema.json",
        "Jumpship Shared-Safe Application Estate Projection Contract",
        {
            "application_estate_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "revision": _version(),
            "coverage_complete": s_boolean(),
            "counts": estate_count,
            "coverage_state": s_string(enum=("incomplete", "blocked", "complete")),
            "safe_summary": _safe_text(2048),
            "projection_root": _hash(),
            "updated_at": timestamp_field(),
        },
        (
            "application_estate_id",
            "workspace_id",
            "migration_id",
            "revision",
            "coverage_complete",
            "counts",
            "coverage_state",
            "safe_summary",
            "projection_root",
            "updated_at",
        ),
        data_class="shared_migration",
        max_bytes=65_536,
        flow_ids=("F02", "F03"),
        description="Browser/API projection containing counts and safe status only; repository names, refs, paths, symbols, content hashes, and raw findings remain cell-local.",
    )

    adaptation_site = s_object(
        {
            "site_id": _id(),
            "query_id": _id(),
            "workload_id": _id(),
            "writer_id": nullable(_id()),
            "target_semantics_root": _hash(),
            "state": _coverage_state(),
            "dependency_ids": s_array(_id(), max_items=256, unique=True),
            "change_requirement_root": _hash(),
            "dormant_rollout_root": _hash(),
            "activation_root": _hash(),
            "smoke_root": _hash(),
            "rollback_root": _hash(),
            "proof_obligation_roots": s_array(_hash(), min_items=1, max_items=64, unique=True),
        },
        (
            "site_id",
            "query_id",
            "workload_id",
            "writer_id",
            "target_semantics_root",
            "state",
            "dependency_ids",
            "change_requirement_root",
            "dormant_rollout_root",
            "activation_root",
            "smoke_root",
            "rollback_root",
            "proof_obligation_roots",
        ),
    )
    schemas["contracts/application/application-adaptation-spec.schema.json"] = schema(
        "application/application-adaptation-spec.schema.json",
        "Jumpship Application Adaptation Specification Contract",
        {
            "adaptation_spec_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "version": _version(),
            "application_estate_root": _hash(),
            "target_profile_root": _hash(),
            "mapping_root": _hash(),
            "query_root": _hash(),
            "writer_root": _hash(),
            "dependency_order": s_array(_id(), min_items=1, max_items=200000),
            "site_adaptations": s_array(adaptation_site, min_items=1, max_items=200000),
            "blocker_roots": s_array(_hash(), max_items=100000, unique=True),
            "coverage_root": _hash(),
            "sealed_at": timestamp_field(),
        },
        (
            "adaptation_spec_id",
            "workspace_id",
            "migration_id",
            "version",
            "application_estate_root",
            "target_profile_root",
            "mapping_root",
            "query_root",
            "writer_root",
            "dependency_order",
            "site_adaptations",
            "blocker_roots",
            "coverage_root",
            "sealed_at",
        ),
        data_class="restricted_customer",
        max_bytes=67_108_864,
        flow_ids=("F10", "F11", "F13"),
        description="Versioned target-semantics binding for every discovered call site and writer.",
    )

    adapter = s_object(
        {
            "adapter_id": _name(128),
            "version": s_string(pattern=SEMVER_PATTERN),
            "language_ranges": s_array(_safe_text(128), min_items=1, max_items=64, unique=True),
            "runtime_ranges": s_array(_safe_text(128), min_items=1, max_items=64, unique=True),
            "framework_ranges": s_array(_safe_text(128), max_items=128, unique=True),
            "data_library_ranges": s_array(_safe_text(128), max_items=128, unique=True),
            "capabilities": s_array(
                s_string(enum=("detect", "parse", "patch", "test", "generic_fallback")),
                min_items=1,
                max_items=5,
                unique=True,
            ),
            "tool_hashes": s_array(_hash(), min_items=1, max_items=64, unique=True),
            "fixture_ids": s_array(_name(128), min_items=1, max_items=4096, unique=True),
            "eval_ids": s_array(_name(128), min_items=1, max_items=4096, unique=True),
            "behavior": s_string(enum=("supported", "generic_fallback", "blocking_unsupported")),
            "evidence_root": _hash(),
        },
        (
            "adapter_id",
            "version",
            "language_ranges",
            "runtime_ranges",
            "framework_ranges",
            "data_library_ranges",
            "capabilities",
            "tool_hashes",
            "fixture_ids",
            "eval_ids",
            "behavior",
            "evidence_root",
        ),
    )
    schemas["contracts/application/application-adapter-manifest.schema.json"] = schema(
        "application/application-adapter-manifest.schema.json",
        "Jumpship Release Application Adapter Manifest Contract",
        {
            "manifest_id": _id(),
            "release_unit_id": _hash(),
            "version": s_string(pattern=SEMVER_PATTERN),
            "adapters": s_array(adapter, min_items=1, max_items=4096),
            "fixture_corpus_root": _hash(),
            "evaluation_root": _hash(),
            "manifest_root": _hash(),
            "issued_at": timestamp_field(),
        },
        ("manifest_id", "release_unit_id", "version", "adapters", "fixture_corpus_root", "evaluation_root", "manifest_root", "issued_at"),
        data_class="internal_operational",
        max_bytes=8_388_608,
        flow_ids=("F11", "F15"),
        description="Release-bound, open-ended inventory of exact qualified application adapters.",
    )

    patch_file = s_object(
        {
            "path_hash": _hash(),
            "before_blob_hash": nullable(_hash()),
            "after_blob_hash": nullable(_hash()),
            "change_kind": s_string(enum=("add", "modify", "rename", "delete")),
        },
        ("path_hash", "before_blob_hash", "after_blob_hash", "change_kind"),
    )
    validation = s_object(
        {
            "command_hash": _hash(),
            "result": s_string(enum=("passed", "failed", "not_run", "validation_degraded")),
            "receipt_root": _hash(),
        },
        ("command_hash", "result", "receipt_root"),
    )
    repo_patch_set = s_object(
        {
            "patch_set_id": _id(),
            "repository_id": _id(),
            "base_sha": _sha(),
            "generated_head_sha": _sha(),
            "state": s_string(
                enum=(
                    "planned",
                    "generated",
                    "sealed",
                    "validated",
                    "validation_degraded",
                    "publishable",
                    "published",
                    "superseded",
                    "failed",
                )
            ),
            "affected_workload_ids": s_array(_id(), max_items=32768, unique=True),
            "affected_writer_ids": s_array(_id(), max_items=32768, unique=True),
            "affected_query_ids": s_array(_id(), max_items=200000, unique=True),
            "files": s_array(patch_file, min_items=1, max_items=100000),
            "canonical_patch_hash": _hash(),
            "validation_results": s_array(validation, min_items=1, max_items=4096),
            "leak_scan_root": _hash(),
            "branch_automation_preflight_root": _hash(),
            "pull_request_binding_id": nullable(_id()),
        },
        (
            "patch_set_id",
            "repository_id",
            "base_sha",
            "generated_head_sha",
            "state",
            "affected_workload_ids",
            "affected_writer_ids",
            "affected_query_ids",
            "files",
            "canonical_patch_hash",
            "validation_results",
            "leak_scan_root",
            "branch_automation_preflight_root",
            "pull_request_binding_id",
        ),
    )
    schemas["contracts/application/application-change-set.schema.json"] = schema(
        "application/application-change-set.schema.json",
        "Jumpship Multi-Repository Application Change Set Contract",
        {
            "change_set_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "version": _version(),
            "estate_root": _hash(),
            "adaptation_spec_root": _hash(),
            "mapping_root": _hash(),
            "query_root": _hash(),
            "writer_root": _hash(),
            "dependency_order": s_array(_id(), min_items=1, max_items=4096),
            "coverage_summary_root": _hash(),
            "repo_patch_sets": s_array(repo_patch_set, min_items=1, max_items=4096),
            "blocker_roots": s_array(_hash(), max_items=100000, unique=True),
            "provenance_root": _hash(),
            "sealed_at": timestamp_field(),
        },
        (
            "change_set_id",
            "workspace_id",
            "migration_id",
            "version",
            "estate_root",
            "adaptation_spec_root",
            "mapping_root",
            "query_root",
            "writer_root",
            "dependency_order",
            "coverage_summary_root",
            "repo_patch_sets",
            "blocker_roots",
            "provenance_root",
            "sealed_at",
        ),
        data_class="restricted_customer",
        max_bytes=67_108_864,
        flow_ids=("F11", "F13"),
        description="Exact-base, sealed multi-repository patch and validation projection; source bodies remain cell-local.",
    )
    schemas["contracts/application/application-change-set-safe-projection.schema.json"] = schema(
        "application/application-change-set-safe-projection.schema.json",
        "Jumpship Shared-Safe Application Change Set Projection Contract",
        {
            "change_set_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "version": _version(),
            "state": s_string(enum=("planned", "generating", "validating", "blocked", "publishable", "published", "superseded", "failed")),
            "repository_count": s_integer(minimum=0, maximum=4096),
            "patch_set_count": s_integer(minimum=0, maximum=4096),
            "validated_patch_set_count": s_integer(minimum=0, maximum=4096),
            "degraded_validation_count": s_integer(minimum=0, maximum=4096),
            "blocker_count": s_integer(minimum=0, maximum=100000),
            "customer_validation_current": s_boolean(),
            "safe_summary": _safe_text(2048),
            "projection_root": _hash(),
            "updated_at": timestamp_field(),
        },
        (
            "change_set_id",
            "workspace_id",
            "migration_id",
            "version",
            "state",
            "repository_count",
            "patch_set_count",
            "validated_patch_set_count",
            "degraded_validation_count",
            "blocker_count",
            "customer_validation_current",
            "safe_summary",
            "projection_root",
            "updated_at",
        ),
        data_class="shared_migration",
        max_bytes=65_536,
        flow_ids=("F02", "F03", "F11"),
        description="Browser/API projection containing aggregate status only; repositories, refs, file paths, diffs, validation output, and customer content remain cell-local.",
    )

    schemas["contracts/application/pull-request-binding.schema.json"] = schema(
        "application/pull-request-binding.schema.json",
        "Jumpship Draft Pull Request Binding Contract",
        {
            "pr_binding_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "change_set_id": _id(),
            "change_set_version": _version(),
            "patch_set_id": _id(),
            "repository_id": _id(),
            "installation_id": _id(),
            "provider_pr_id": _safe_text(128),
            "namespaced_ref": s_string(pattern=r"^jumpship/mig-[A-Za-z0-9_-]+/app-r[1-9][0-9]*-[A-Za-z0-9_-]+$", max_length=255),
            "base_sha": _sha(),
            "head_sha": _sha(),
            "head_tree_hash": _hash(),
            "canonical_patch_hash": _hash(),
            "state": s_string(
                enum=("opening", "open", "changes_requested", "customer_validated", "merged", "deployed", "runtime_proven", "stale_head", "stale_base", "closed_unmerged")
            ),
            "publication_idempotency_hash": _hash(),
            "provider_observation_root": _hash(),
            "updated_at": timestamp_field(),
        },
        (
            "pr_binding_id",
            "workspace_id",
            "migration_id",
            "change_set_id",
            "change_set_version",
            "patch_set_id",
            "repository_id",
            "installation_id",
            "provider_pr_id",
            "namespaced_ref",
            "base_sha",
            "head_sha",
            "head_tree_hash",
            "canonical_patch_hash",
            "state",
            "publication_idempotency_hash",
            "provider_observation_root",
            "updated_at",
        ),
        data_class="shared_migration",
        max_bytes=65_536,
        flow_ids=("F03", "F11"),
        description="Safe exact-head binding for an automatically published same-repository draft pull request.",
    )

    schemas["contracts/application/external-review.schema.json"] = schema(
        "application/external-review.schema.json",
        "Jumpship External Advisory Review Contract",
        {
            "external_review_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "pr_binding_id": _id(),
            "reviewer": s_string(enum=("codex", "claude_code")),
            "state": s_string(
                enum=("unavailable", "configuration_required", "ready", "queued", "acknowledged", "reviewing", "findings", "no_blocking_findings", "failed", "timed_out", "superseded")
            ),
            "base_sha": _sha(),
            "head_sha": _sha(),
            "expected_reviewer_actor_hash": _hash(),
            "trigger_nonce_hash": _hash(),
            "command_manifest_hash": _hash(),
            "dispatch_receipt_root": nullable(_hash()),
            "safe_findings_root": nullable(_hash()),
            "copy_command_hash": nullable(_hash()),
            "updated_at": timestamp_field(),
        },
        (
            "external_review_id",
            "workspace_id",
            "migration_id",
            "pr_binding_id",
            "reviewer",
            "state",
            "base_sha",
            "head_sha",
            "expected_reviewer_actor_hash",
            "trigger_nonce_hash",
            "command_manifest_hash",
            "dispatch_receipt_root",
            "safe_findings_root",
            "copy_command_hash",
            "updated_at",
        ),
        data_class="shared_migration",
        max_bytes=131_072,
        flow_ids=("F11", "F24"),
        description="Exact-head advisory review state. Findings never constitute customer approval or write authority.",
    )

    schemas["contracts/application/merge-equivalence.schema.json"] = schema(
        "application/merge-equivalence.schema.json",
        "Jumpship Merge Equivalence Proof Contract",
        {
            "merge_equivalence_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "pr_binding_id": _id(),
            "merge_method": s_string(enum=("merge", "squash", "rebase", "merge_queue")),
            "actual_merge_base_sha": _sha(),
            "validated_head_sha": _sha(),
            "merge_commit_sha": _sha(),
            "merged_tree_hash": _hash(),
            "canonical_patch_hash": _hash(),
            "path_inclusion_root": _hash(),
            "equivalent": s_boolean(),
            "proof_root": _hash(),
            "observed_at": timestamp_field(),
        },
        (
            "merge_equivalence_id",
            "workspace_id",
            "migration_id",
            "pr_binding_id",
            "merge_method",
            "actual_merge_base_sha",
            "validated_head_sha",
            "merge_commit_sha",
            "merged_tree_hash",
            "canonical_patch_hash",
            "path_inclusion_root",
            "equivalent",
            "proof_root",
            "observed_at",
        ),
        data_class="shared_migration",
        max_bytes=131_072,
        flow_ids=("F11", "F28"),
        description="Deterministic inclusion proof that the customer-merged tree preserves the validated patch effect.",
    )

    schemas["contracts/application/deployment-evidence-provider.schema.json"] = schema(
        "application/deployment-evidence-provider.schema.json",
        "Jumpship Deployment Evidence Provider Trust Contract",
        {
            "provider_id": _id(),
            "version": _version(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "deploy_unit_id": _id(),
            "mode": s_string(enum=("controller", "runtime_challenge", "customer_ci_joined_runtime")),
            "account_scope_hash": _hash(),
            "resource_scope_hash": _hash(),
            "environment": _name(64),
            "read_only_permission_proof_root": _hash(),
            "issuer": _safe_text(512),
            "subject_pattern_hash": _hash(),
            "audience": _name(255),
            "workload_identity_profile": _name(128),
            "allowed_algorithms": s_array(s_string(enum=("ES256", "ES384", "EdDSA")), min_items=1, max_items=3, unique=True),
            "allowed_key_ids": s_array(_name(255), min_items=1, max_items=128, unique=True),
            "trust_root_hash": _hash(),
            "valid_from": timestamp_field(),
            "valid_until": timestamp_field(),
            "predecessor_provider_id": nullable(_id()),
            "successor_provider_id": nullable(_id()),
            "revocation_state": s_string(enum=("active", "overlap", "revoked", "expired")),
            "artifact_claim_source": _name(128),
            "rollout_runtime_binding_method": _name(128),
            "challenge_issuer": _name(255),
            "challenge_key_id": _name(255),
            "challenge_ttl_seconds": s_integer(minimum=1, maximum=300),
            "runtime_evidence_max_age_seconds": s_integer(minimum=1, maximum=600),
            "provider_proof_version": _version(),
            "evidence_root": _hash(),
        },
        (
            "provider_id",
            "version",
            "workspace_id",
            "migration_id",
            "deploy_unit_id",
            "mode",
            "account_scope_hash",
            "resource_scope_hash",
            "environment",
            "read_only_permission_proof_root",
            "issuer",
            "subject_pattern_hash",
            "audience",
            "workload_identity_profile",
            "allowed_algorithms",
            "allowed_key_ids",
            "trust_root_hash",
            "valid_from",
            "valid_until",
            "predecessor_provider_id",
            "successor_provider_id",
            "revocation_state",
            "artifact_claim_source",
            "rollout_runtime_binding_method",
            "challenge_issuer",
            "challenge_key_id",
            "challenge_ttl_seconds",
            "runtime_evidence_max_age_seconds",
            "provider_proof_version",
            "evidence_root",
        ),
        data_class="security_material",
        max_bytes=262_144,
        flow_ids=("F03", "F28"),
        description="Versioned non-secret trust bootstrap for independent artifact-to-runtime deployment proof.",
    )

    schemas["contracts/application/deployment-attestation.schema.json"] = schema(
        "application/deployment-attestation.schema.json",
        "Jumpship Customer Deployment Identification Contract",
        {
            "deployment_attestation_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "deployment_id": _id(),
            "deploy_unit_id": _id(),
            "provider_id": _id(),
            "pr_binding_id": _id(),
            "merge_equivalence_root": _hash(),
            "expected_artifact_digest": _hash(),
            "expected_config_digest": _hash(),
            "environment": _name(64),
            "actor_id": _id(),
            "actor_role": s_string(const="deployment_owner"),
            "expected_version": _version(),
            "identified_at": timestamp_field(),
            "reconciliation_state": s_string(enum=("pending", "observed", "runtime_proven", "stale", "rejected")),
            "evidence_root": _hash(),
        },
        (
            "deployment_attestation_id",
            "workspace_id",
            "migration_id",
            "deployment_id",
            "deploy_unit_id",
            "provider_id",
            "pr_binding_id",
            "merge_equivalence_root",
            "expected_artifact_digest",
            "expected_config_digest",
            "environment",
            "actor_id",
            "actor_role",
            "expected_version",
            "identified_at",
            "reconciliation_state",
            "evidence_root",
        ),
        data_class="shared_migration",
        max_bytes=131_072,
        flow_ids=("F02", "F03", "F28"),
        description="Browser-human identification for reconciliation; it never proves deployment or grants deploy authority.",
    )

    challenge = s_object(
        {
            "challenge_id": _id(),
            "nonce_hash": _hash(),
            "issued_at": timestamp_field(),
            "expires_at": timestamp_field(),
            "consumed_at": nullable(timestamp_field()),
            "state": s_string(enum=("issued", "consumed", "expired", "replayed", "rejected")),
        },
        ("challenge_id", "nonce_hash", "issued_at", "expires_at", "consumed_at", "state"),
    )
    runtime_identity = s_object(
        {
            "workload_identity_hash": _hash(),
            "process_identity_hash": _hash(),
            "process_started_at": timestamp_field(),
            "observed_at": timestamp_field(),
            "heartbeat_root": _hash(),
        },
        (
            "workload_identity_hash",
            "process_identity_hash",
            "process_started_at",
            "observed_at",
            "heartbeat_root",
        ),
    )
    schemas["contracts/application/deployment-runtime-proof.schema.json"] = schema(
        "application/deployment-runtime-proof.schema.json",
        "Jumpship Independent Deployment Runtime Proof Contract",
        {
            "runtime_proof_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "deployment_id": _id(),
            "deploy_unit_id": _id(),
            "provider_id": _id(),
            "provider_version": _version(),
            "pr_binding_id": _id(),
            "merge_equivalence_root": _hash(),
            "challenge": challenge,
            "runtime_identity": runtime_identity,
            "reported_artifact_digest": _hash(),
            "reported_config_digest": _hash(),
            "rollout_identity_hash": _hash(),
            "runtime_evidence_chain_root": _hash(),
            "proof_state": s_string(enum=("observed", "verified", "stale", "rejected", "revoked")),
            "expires_at": timestamp_field(),
        },
        (
            "runtime_proof_id",
            "workspace_id",
            "migration_id",
            "deployment_id",
            "deploy_unit_id",
            "provider_id",
            "provider_version",
            "pr_binding_id",
            "merge_equivalence_root",
            "challenge",
            "runtime_identity",
            "reported_artifact_digest",
            "reported_config_digest",
            "rollout_identity_hash",
            "runtime_evidence_chain_root",
            "proof_state",
            "expires_at",
        ),
        data_class="shared_migration",
        max_bytes=262_144,
        flow_ids=("F03", "F28"),
        description="One-use challenge proof joining customer merge, artifact/config, rollout, and live workload/process identity without deploy authority.",
    )

    schemas["contracts/application/writer-control.schema.json"] = schema(
        "application/writer-control.schema.json",
        "Jumpship Application Writer Cohort Control Contract",
        {
            "writer_control_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "writer_id": _id(),
            "cohort_id": _id(),
            "deploy_unit_id": _id(),
            "authority": s_string(enum=("source", "none", "target")),
            "application_authority_epoch": _version(),
            "cell_write_epoch": _version(),
            "current_cohort_generation": _version(),
            "reserved_cohort_generation": nullable(_version()),
            "state": s_string(enum=("source_enabled", "freezing", "fenced", "target_pending", "target_enabled", "revoking", "target_fenced", "source_pending", "source_resumed", "tombstoned", "blocked")),
            "build_digest": _hash(),
            "config_digest": _hash(),
            "identity_proof_root": _hash(),
            "provider_gate_receipt_root": nullable(_hash()),
            "activation_receipt_root": nullable(_hash()),
            "source_resume_stream_receipt_root": nullable(_hash()),
            "denial_receipt_root": nullable(_hash()),
            "updated_at": timestamp_field(),
        },
        (
            "writer_control_id",
            "workspace_id",
            "migration_id",
            "writer_id",
            "cohort_id",
            "deploy_unit_id",
            "authority",
            "application_authority_epoch",
            "cell_write_epoch",
            "current_cohort_generation",
            "reserved_cohort_generation",
            "state",
            "build_digest",
            "config_digest",
            "identity_proof_root",
            "provider_gate_receipt_root",
            "activation_receipt_root",
            "source_resume_stream_receipt_root",
            "denial_receipt_root",
            "updated_at",
        ),
        data_class="shared_migration",
        max_bytes=131_072,
        flow_ids=("F03", "F26", "F27"),
        description="Fail-closed writer cohort authority projection with distinct A, W, and G generations.",
    )
    schemas["contracts/application/writer-control.schema.json"]["allOf"] = [
        {
            "oneOf": [
                {
                    "properties": {
                        "authority": {"const": "source"},
                        "state": {"const": "source_enabled"},
                        "reserved_cohort_generation": {"type": "null"},
                        "provider_gate_receipt_root": {"type": "null"},
                        "activation_receipt_root": {"type": "null"},
                        "source_resume_stream_receipt_root": {"type": "null"},
                        "denial_receipt_root": {"type": "null"},
                    }
                },
                {
                    "properties": {
                        "authority": {"const": "none"},
                        "state": {"enum": ["freezing", "fenced"]},
                        "reserved_cohort_generation": {"type": "null"},
                        "provider_gate_receipt_root": {"type": "null"},
                        "activation_receipt_root": {"type": "null"},
                        "source_resume_stream_receipt_root": {"type": "null"},
                        "denial_receipt_root": {"type": "null"},
                    }
                },
                {
                    "properties": {
                        "authority": {"const": "none"},
                        "state": {"const": "target_pending"},
                        "reserved_cohort_generation": _version(),
                        "provider_gate_receipt_root": _hash(),
                        "activation_receipt_root": {"type": "null"},
                        "source_resume_stream_receipt_root": {"type": "null"},
                        "denial_receipt_root": {"type": "null"},
                    }
                },
                {
                    "properties": {
                        "authority": {"const": "target"},
                        "state": {"const": "target_enabled"},
                        "reserved_cohort_generation": {"type": "null"},
                        "provider_gate_receipt_root": _hash(),
                        "activation_receipt_root": _hash(),
                        "source_resume_stream_receipt_root": {"type": "null"},
                        "denial_receipt_root": {"type": "null"},
                    }
                },
                {
                    "properties": {
                        "authority": {"const": "none"},
                        "state": {"enum": ["revoking", "target_fenced", "tombstoned"]},
                        "reserved_cohort_generation": {"type": "null"},
                        "provider_gate_receipt_root": _hash(),
                        "activation_receipt_root": _hash(),
                        "source_resume_stream_receipt_root": {"type": "null"},
                        "denial_receipt_root": _hash(),
                    }
                },
                {
                    "properties": {
                        "authority": {"const": "none"},
                        "state": {"const": "source_pending"},
                        "reserved_cohort_generation": _version(),
                        "provider_gate_receipt_root": _hash(),
                        "activation_receipt_root": {"type": "null"},
                        "source_resume_stream_receipt_root": _hash(),
                        "denial_receipt_root": {"type": "null"},
                    }
                },
                {
                    "properties": {
                        "authority": {"const": "source"},
                        "state": {"const": "source_resumed"},
                        "reserved_cohort_generation": {"type": "null"},
                        "provider_gate_receipt_root": _hash(),
                        "activation_receipt_root": _hash(),
                        "source_resume_stream_receipt_root": _hash(),
                        "denial_receipt_root": {"type": "null"},
                    }
                },
                {
                    "properties": {
                        "authority": {"const": "none"},
                        "state": {"const": "blocked"},
                        "reserved_cohort_generation": {"type": "null"},
                        "provider_gate_receipt_root": nullable(_hash()),
                        "activation_receipt_root": {"type": "null"},
                        "source_resume_stream_receipt_root": {"type": "null"},
                        "denial_receipt_root": _hash(),
                    }
                },
            ]
        }
    ]

    schemas["contracts/application/application-writer-grant.schema.json"] = schema(
        "application/application-writer-grant.schema.json",
        "Jumpship Signed Application Writer Grant Contract",
        {
            "grant_id": _id(),
            "purpose": s_string(const="application_writer_grant"),
            "workspace_id": _id(),
            "migration_id": _id(),
            "writer_id": _id(),
            "cohort_id": _id(),
            "deploy_unit_id": _id(),
            "workload_identity_hash": _hash(),
            "build_digest": _hash(),
            "artifact_digest": _hash(),
            "config_digest": _hash(),
            "environment": _name(64),
            "store": s_string(enum=("source", "target")),
            "application_authority_epoch": _version(),
            "reserved_cohort_generation": _version(),
            "credential_generation": _version(),
            "audience": s_string(const="jumpship-application-writer"),
            "state": s_string(const="signed_dormant"),
            "encrypted_credential_envelope_hash": _hash(),
            "not_before": timestamp_field(),
            "expires_at": timestamp_field(),
            "nonce": s_string(pattern="^[A-Za-z0-9_-]{32,128}$"),
            "payload_hash": _hash(),
            "signature_envelope_hash": _hash(),
        },
        (
            "grant_id",
            "purpose",
            "workspace_id",
            "migration_id",
            "writer_id",
            "cohort_id",
            "deploy_unit_id",
            "workload_identity_hash",
            "build_digest",
            "artifact_digest",
            "config_digest",
            "environment",
            "store",
            "application_authority_epoch",
            "reserved_cohort_generation",
            "credential_generation",
            "audience",
            "state",
            "encrypted_credential_envelope_hash",
            "not_before",
            "expires_at",
            "nonce",
            "payload_hash",
            "signature_envelope_hash",
        ),
        data_class="security_material",
        max_bytes=65_536,
        flow_ids=("F26", "F27"),
        description="Immutable short-lived exact-workload signed grant claims. This object is always signed_dormant; reservation and activation/revocation state live in the separate writer-control projection so signed bytes never mutate.",
    )

    schemas["contracts/application/reverse-apply-attribution.schema.json"] = schema(
        "application/reverse-apply-attribution.schema.json",
        "Jumpship Reverse Apply Attribution Contract",
        {
            "attribution_id": _id(),
            "workspace_id": _id(),
            "migration_id": _id(),
            "cell_id": _id(),
            "cell_generation": _version(),
            "application_authority_epoch": _version(),
            "cell_write_epoch": _version(),
            "effect_id": _id(),
            "reservation_id": _id(),
            "reservation_hash": _hash(),
            "target_event_hash": _hash(),
            "source_transaction_hash": _hash(),
            "namespace_key_root": _hash(),
            "post_state_root": _hash(),
            "mac_key_id": _name(255),
            "mac": s_string(pattern="^[A-Za-z0-9_-]{43,128}$"),
            "replay_sequence": _version(),
            "nonce_hash": _hash(),
            "signature_purpose": s_string(const="reverse_apply_attribution"),
            "signature_envelope_hash": _hash(),
            "source_sentinel_root": nullable(_hash()),
            "change_stream_root": nullable(_hash()),
            "cell_completion_root": nullable(_hash()),
            "conflict_evidence_root": nullable(_hash()),
            "state": s_string(enum=("reserved", "reverse_attribution_pending", "completed", "authority_conflict_frozen")),
            "deadline": timestamp_field(),
            "created_at": timestamp_field(),
        },
        (
            "attribution_id",
            "workspace_id",
            "migration_id",
            "cell_id",
            "cell_generation",
            "application_authority_epoch",
            "cell_write_epoch",
            "effect_id",
            "reservation_id",
            "reservation_hash",
            "target_event_hash",
            "source_transaction_hash",
            "namespace_key_root",
            "post_state_root",
            "mac_key_id",
            "mac",
            "replay_sequence",
            "nonce_hash",
            "signature_purpose",
            "signature_envelope_hash",
            "source_sentinel_root",
            "change_stream_root",
            "cell_completion_root",
            "conflict_evidence_root",
            "state",
            "deadline",
            "created_at",
        ),
        data_class="restricted_customer",
        max_bytes=131_072,
        flow_ids=("F09", "F13", "F27"),
        description="Atomic source-write attribution bound to immutable pre-reservation bytes, A/W epochs, replay sequence/nonce, detached signature, and post-commit completion.",
    )
    schemas["contracts/application/reverse-apply-attribution.schema.json"]["allOf"] = [
        {
            "oneOf": [
                {
                    "properties": {
                        "state": {"const": "reserved"},
                        "source_sentinel_root": {"type": "null"},
                        "change_stream_root": {"type": "null"},
                        "cell_completion_root": {"type": "null"},
                        "conflict_evidence_root": {"type": "null"},
                    }
                },
                {
                    "properties": {
                        "state": {"const": "reverse_attribution_pending"},
                        "source_sentinel_root": _hash(),
                        "change_stream_root": _hash(),
                        "cell_completion_root": {"type": "null"},
                        "conflict_evidence_root": {"type": "null"},
                    }
                },
                {
                    "properties": {
                        "state": {"const": "completed"},
                        "source_sentinel_root": _hash(),
                        "change_stream_root": _hash(),
                        "cell_completion_root": _hash(),
                        "conflict_evidence_root": {"type": "null"},
                    }
                },
                {
                    "properties": {
                        "state": {"const": "authority_conflict_frozen"},
                        "source_sentinel_root": _hash(),
                        "change_stream_root": nullable(_hash()),
                        "cell_completion_root": nullable(_hash()),
                        "conflict_evidence_root": _hash(),
                    }
                },
            ]
        }
    ]
    return schemas


def _auth_schema() -> dict[str, Any]:
    host = s_string(pattern=r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$", max_length=253)
    origin = s_string(pattern=r"^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?$", max_length=512)
    provider = s_object(
        {
            "provider": s_string(enum=("google", "github")),
            "client_id_hash": _hash(),
            "discovery_url_hash": _hash(),
            "scope_set_hash": _hash(),
            "redirect_uri_hash": _hash(),
            "pkce_method": s_string(const="S256"),
        },
        ("provider", "client_id_hash", "discovery_url_hash", "scope_set_hash", "redirect_uri_hash", "pkce_method"),
    )
    providers = s_array(provider, min_items=2, max_items=2, unique=True)
    providers["allOf"] = [
        {
            "contains": {"properties": {"provider": {"const": provider_name}}, "required": ["provider"]},
            "minContains": 1,
            "maxContains": 1,
        }
        for provider_name in ("google", "github")
    ]
    route = s_object(
        {
            "host_role": s_string(enum=("api", "auth_callback", "connector_callback", "cell_control")),
            "method": s_string(enum=("GET", "POST", "PUT", "PATCH", "DELETE")),
            "path_template": s_string(pattern=r"^/v1/[A-Za-z0-9_{}./-]+$", max_length=512),
            "route_build_digest": _hash(),
            "body_policy": s_string(enum=("none", "json", "form_redacted", "suppressed_binary")),
            "access_logs": s_string(enum=("enabled_redacted", "disabled")),
            "csrf_exempt": s_boolean(),
            "origin_policy_hash": _hash(),
        },
        (
            "host_role",
            "method",
            "path_template",
            "route_build_digest",
            "body_policy",
            "access_logs",
            "csrf_exempt",
            "origin_policy_hash",
        ),
    )

    def route_case(host_role: str, method: str, path_template: str, body_policy: str, csrf_exempt: bool) -> dict[str, Any]:
        properties = {
            "host_role": {"const": host_role},
            "method": {"const": method},
            "path_template": {"const": path_template},
            "body_policy": {"const": body_policy},
            "csrf_exempt": {"const": csrf_exempt},
        }
        return {"properties": properties, "required": list(properties)}

    protocol_routes = (
        route_case("api", "POST", "/v1/auth/oauth/{provider}/start", "json", True),
        route_case("auth_callback", "POST", "/v1/auth/oauth/{provider}/prepare", "form_redacted", True),
        route_case("auth_callback", "GET", "/v1/auth/oauth/{provider}/callback", "none", True),
        route_case("api", "POST", "/v1/auth/oauth/complete", "form_redacted", True),
        route_case("connector_callback", "POST", "/v1/connectors/{kind}/oauth/prepare", "form_redacted", True),
        route_case("connector_callback", "GET", "/v1/connectors/{kind}/callback", "none", True),
        route_case("api", "POST", "/v1/connectors/oauth/complete", "form_redacted", True),
        route_case("cell_control", "POST", "/v1/internal/cell-certificates/bootstrap/request", "suppressed_binary", True),
        route_case("cell_control", "POST", "/v1/internal/cell-certificates/bootstrap/complete", "suppressed_binary", True),
    )
    route["allOf"] = [
        {
            "if": {"properties": {"csrf_exempt": {"const": True}}, "required": ["csrf_exempt"]},
            "then": {"oneOf": list(protocol_routes)},
        }
    ]

    route_tuples = s_array(route, min_items=len(protocol_routes), max_items=len(protocol_routes), unique=True)
    route_tuples["allOf"] = [
        {"contains": candidate, "minContains": 1, "maxContains": 1}
        for candidate in protocol_routes
    ]

    sensitive_routes_required = (
        protocol_routes[1],
        protocol_routes[3],
        protocol_routes[4],
        protocol_routes[6],
        route_case("api", "PUT", "/v1/workspaces/{workspace_id}/migrations/{migration_id}/connectors/mongodb/credential", "json", False),
        route_case("api", "POST", "/v1/invitations/accept", "json", False),
        route_case("api", "POST", "/v1/auth/device/authorizations/approve", "json", False),
        route_case("api", "POST", "/v1/auth/device/token", "json", False),
        route_case("api", "POST", "/v1/auth/webauthn/registration/options", "json", False),
        route_case("api", "POST", "/v1/auth/webauthn/registration/verify", "json", False),
        route_case("api", "POST", "/v1/cli/browser-ceremonies/{ceremony_id}/decision", "json", False),
        route_case("api", "POST", "/v1/workspaces/{workspace_id}/migrations/{migration_id}/consents/{consent_kind}/confirm", "json", False),
        protocol_routes[7],
        protocol_routes[8],
    )
    sensitive_body_routes = s_array(
        route,
        min_items=len(sensitive_routes_required),
        max_items=len(sensitive_routes_required),
        unique=True,
    )
    sensitive_body_routes["allOf"] = [
        {"contains": candidate, "minContains": 1, "maxContains": 1}
        for candidate in sensitive_routes_required
    ]

    def exact_string_set(values: tuple[str, ...]) -> dict[str, Any]:
        result = s_array(s_string(enum=values), min_items=len(values), max_items=len(values), unique=True)
        result["allOf"] = [
            {"contains": {"const": value}, "minContains": 1, "maxContains": 1}
            for value in values
        ]
        return result

    cors_methods = exact_string_set(("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"))
    cors_headers = exact_string_set(("Content-Type", "X-CSRF-Token", "Idempotency-Key", "If-Match", "X-Request-ID", "traceparent"))
    csrf_route_classes = exact_string_set(("ordinary_mutation", "security_sensitive_mutation", "credential_intake", "consent_execution"))
    csrf_exempt_operation_ids = exact_string_set(
        (
            "startIdentityOAuth",
            "prepareIdentityOAuthCallback",
            "consumeIdentityOAuthCallback",
            "completeIdentityOAuth",
            "prepareConnectorOAuthCallback",
            "consumeConnectorOAuthCallback",
            "completeConnectorOAuth",
        )
    )
    cookie = s_object(
        {
            "name": s_string(enum=("__Host-js_session", "__Host-js_oauth_start", "__Host-js_oauth_callback", "__Secure-js_present")),
            "host_role": s_string(enum=("api", "auth_callback", "presentation")),
            "domain_scope": s_string(enum=("host_only", "parent_domain")),
            "authoritative": s_boolean(),
            "secure": {"const": True},
            "http_only": {"const": True},
            "same_site": s_string(const="Lax"),
            "path": s_string(const="/"),
            "max_age_seconds": s_integer(minimum=1, maximum=604_800),
        },
        ("name", "host_role", "domain_scope", "authoritative", "secure", "http_only", "same_site", "path", "max_age_seconds"),
    )
    cookie["allOf"] = [
        {
            "oneOf": [
                {
                    "properties": {
                        "name": {"const": "__Host-js_session"},
                        "host_role": {"const": "api"},
                        "domain_scope": {"const": "host_only"},
                        "authoritative": {"const": True},
                        "max_age_seconds": {"const": 604_800},
                    }
                },
                {
                    "properties": {
                        "name": {"const": "__Host-js_oauth_start"},
                        "host_role": {"const": "api"},
                        "domain_scope": {"const": "host_only"},
                        "authoritative": {"const": False},
                        "max_age_seconds": {"const": 600},
                    }
                },
                {
                    "properties": {
                        "name": {"const": "__Host-js_oauth_callback"},
                        "host_role": {"const": "auth_callback"},
                        "domain_scope": {"const": "host_only"},
                        "authoritative": {"const": False},
                        "max_age_seconds": {"const": 600},
                    }
                },
                {
                    "properties": {
                        "name": {"const": "__Secure-js_present"},
                        "host_role": {"const": "presentation"},
                        "domain_scope": {"const": "parent_domain"},
                        "authoritative": {"const": False},
                        "max_age_seconds": {"const": 300},
                    }
                },
            ]
        }
    ]
    cookies = s_array(cookie, min_items=4, max_items=4, unique=True)
    cookies["allOf"] = [
        {
            "contains": {"properties": {"name": {"const": cookie_name}}, "required": ["name"]},
            "minContains": 1,
            "maxContains": 1,
        }
        for cookie_name in (
            "__Host-js_session",
            "__Host-js_oauth_start",
            "__Host-js_oauth_callback",
            "__Secure-js_present",
        )
    ]
    return schema(
        "auth/deployed-auth-config.schema.json",
        "Jumpship Complete Deployed Authentication Configuration Contract",
        {
            "environment": s_string(enum=("staging", "production")),
            "release_unit_id": _hash(),
            "domain_policy_version": s_string(pattern=SEMVER_PATTERN),
            "domain_policy_hash": _hash(),
            "application_host": host,
            "api_host": host,
            "auth_callback_host": host,
            "connector_callback_host": host,
            "cell_control_host": host,
            "allowed_origins": s_array(origin, min_items=1, max_items=32, unique=True),
            "providers": providers,
            "route_tuples": route_tuples,
            "route_digest": _hash(),
            "cookies": cookies,
            "session_idle_seconds": s_integer(minimum=43_200, maximum=43_200),
            "session_absolute_seconds": s_integer(minimum=604_800, maximum=604_800),
            "session_touch_interval_seconds": s_integer(minimum=300, maximum=300),
            "cors_policy_hash": _hash(),
            "cors_allow_credentials": {"const": True},
            "cors_methods": cors_methods,
            "cors_headers": cors_headers,
            "csrf_policy_hash": _hash(),
            "csrf_token_transport": s_string(const="synchronizer_header"),
            "csrf_header_name": s_string(const="X-CSRF-Token"),
            "csrf_session_binding": s_string(const="session_id_and_route_class"),
            "csrf_storage": s_string(const="page_memory_only"),
            "csrf_route_classes": csrf_route_classes,
            "csrf_exempt_operation_ids": csrf_exempt_operation_ids,
            "session_policy_hash": _hash(),
            "presentation_jwks_policy_hash": _hash(),
            "presentation_jwks_url": s_string(pattern=r"^https://[A-Za-z0-9.-]+/v1/auth/jwks\.json$", max_length=512),
            "presentation_jwks_cache_max_seconds": s_integer(minimum=1, maximum=300),
            "presentation_rotation_cadence": s_string(const="monthly"),
            "presentation_key_overlap_seconds": s_integer(minimum=300, maximum=2_678_400),
            "presentation_issuer_hash": _hash(),
            "presentation_audience": s_string(const="jumpship-presentation"),
            "presentation_purpose": s_string(const="route_shaping_only"),
            "presentation_algorithms": s_array(s_string(enum=("ES256", "EdDSA")), min_items=1, max_items=2, unique=True),
            "presentation_payload_max_age_seconds": s_integer(minimum=300, maximum=300),
            "presentation_unknown_kid_behavior": s_string(const="fail_closed"),
            "handoff_expiry_seconds": s_integer(minimum=1, maximum=60),
            "handoff_binding_schema_hash": _hash(),
            "interstitial_csp_hash": _hash(),
            "interstitial_script_hash": _hash(),
            "interstitial_form_action_hash": _hash(),
            "referrer_policy": s_string(const="no-referrer"),
            "webauthn_rp_id": host,
            "webauthn_origins": s_array(origin, min_items=1, max_items=8, unique=True),
            "webauthn_user_verification": s_string(const="required"),
            "webauthn_attestation": s_string(const="none"),
            "webauthn_resident_key": s_string(enum=("preferred", "required")),
            "webauthn_algorithm_policy_hash": _hash(),
            "webauthn_challenge_policy_hash": _hash(),
            "listener_rule_digest": _hash(),
            "waf_redaction_policy_hash": _hash(),
            "telemetry_suppression_policy_hash": _hash(),
            "main_host_callback_denial_hash": _hash(),
            "sensitive_body_routes": sensitive_body_routes,
            "body_inspection_exclusion_hash": _hash(),
            "handler_compensation_policy_hash": _hash(),
            "config_hash": _hash(),
        },
        (
            "environment",
            "release_unit_id",
            "domain_policy_version",
            "domain_policy_hash",
            "application_host",
            "api_host",
            "auth_callback_host",
            "connector_callback_host",
            "cell_control_host",
            "allowed_origins",
            "providers",
            "route_tuples",
            "route_digest",
            "cookies",
            "session_idle_seconds",
            "session_absolute_seconds",
            "session_touch_interval_seconds",
            "cors_policy_hash",
            "cors_allow_credentials",
            "cors_methods",
            "cors_headers",
            "csrf_policy_hash",
            "csrf_token_transport",
            "csrf_header_name",
            "csrf_session_binding",
            "csrf_storage",
            "csrf_route_classes",
            "csrf_exempt_operation_ids",
            "session_policy_hash",
            "presentation_jwks_policy_hash",
            "presentation_jwks_url",
            "presentation_jwks_cache_max_seconds",
            "presentation_rotation_cadence",
            "presentation_key_overlap_seconds",
            "presentation_issuer_hash",
            "presentation_audience",
            "presentation_purpose",
            "presentation_algorithms",
            "presentation_payload_max_age_seconds",
            "presentation_unknown_kid_behavior",
            "handoff_expiry_seconds",
            "handoff_binding_schema_hash",
            "interstitial_csp_hash",
            "interstitial_script_hash",
            "interstitial_form_action_hash",
            "referrer_policy",
            "webauthn_rp_id",
            "webauthn_origins",
            "webauthn_user_verification",
            "webauthn_attestation",
            "webauthn_resident_key",
            "webauthn_algorithm_policy_hash",
            "webauthn_challenge_policy_hash",
            "listener_rule_digest",
            "waf_redaction_policy_hash",
            "telemetry_suppression_policy_hash",
            "main_host_callback_denial_hash",
            "sensitive_body_routes",
            "body_inspection_exclusion_hash",
            "handler_compensation_policy_hash",
            "config_hash",
        ),
        data_class="security_material",
        max_bytes=1_048_576,
        flow_ids=("F01", "F02", "F19", "F22"),
        description="Complete non-secret release-bound auth topology. Secret values and live JWKS key material have no representable field.",
    )


def _client_schemas() -> dict[str, dict[str, Any]]:
    local_broker = schema(
        "client/local-broker.schema.json",
        "Jumpship Local Credential Broker Frame Contract",
        {
            "protocol_version": s_string(pattern=SEMVER_PATTERN),
            "frame_type": s_string(enum=("request", "response", "receipt", "error")),
            "request_id": _id(),
            "client_audience": s_string(enum=("jumpship-cli-human", "jumpship-coding-agent")),
            "peer_uid": s_integer(minimum=0),
            "method": s_string(
                enum=(
                    "session.status",
                    "session.logout",
                    "api.read",
                    "api.safe_command",
                    "browser_ceremony.create",
                    "browser_ceremony.status",
                    "capability.revoke",
                )
            ),
            "capability_handle": nullable(s_string(pattern="^jlc_[A-Za-z0-9_-]{32,128}$")),
            "scope_hash": _hash(),
            "request_payload_hash": _hash(),
            "safe_response_hash": nullable(_hash()),
            "receipt_id": nullable(_id()),
            "error_code": nullable(_name(128)),
            "expires_at": timestamp_field(),
        },
        (
            "protocol_version",
            "frame_type",
            "request_id",
            "client_audience",
            "peer_uid",
            "method",
            "capability_handle",
            "scope_hash",
            "request_payload_hash",
            "safe_response_hash",
            "receipt_id",
            "error_code",
            "expires_at",
        ),
        data_class="identity_tenant",
        max_bytes=65_536,
        flow_ids=("F23",),
        description="Length-framed peer-bound broker protocol. Bearers, refresh tokens, credential values, and presigned URLs are unrepresentable.",
    )
    local_broker["allOf"] = [
        {
            "oneOf": [
                {
                    "properties": {
                        "client_audience": {"const": "jumpship-cli-human"},
                        "method": {
                            "enum": [
                                "session.status",
                                "session.logout",
                                "api.read",
                                "api.safe_command",
                                "browser_ceremony.create",
                                "browser_ceremony.status",
                                "capability.revoke",
                            ]
                        },
                    }
                },
                {
                    "properties": {
                        "client_audience": {"const": "jumpship-coding-agent"},
                        "method": {
                            "enum": [
                                "session.status",
                                "session.logout",
                                "api.read",
                                "api.safe_command",
                                "capability.revoke",
                            ]
                        },
                    }
                },
            ]
        }
    ]
    ceremony = schema(
        "client/browser-ceremony.schema.json",
        "Jumpship Exact Browser Ceremony Contract",
        {
            "ceremony_id": _id(),
            "human_cli_principal_id": _id(),
            "token_family_id": _id(),
            "workspace_id": _id(),
            "migration_id": nullable(_id()),
            "operation_id": _name(128),
            "action": _name(128),
            "resource_id": _id(),
            "canonical_input_hash": _hash(),
            "evidence_root": _hash(),
            "spec_version": _version(),
            "rubric_version": _version(),
            "state_version": _version(),
            "reversibility": s_string(enum=("ordinary", "conditional", "foundation", "never_reversible", "external_exposure")),
            "expected_version": _version(),
            "nonce_hash": _hash(),
            "state": s_string(enum=("requested", "browser_pending", "completed", "declined", "expired", "invalidated")),
            "app_path": s_string(pattern=r"^/cli/ceremonies/[0-9a-f-]{36}$", max_length=128),
            "expires_at": timestamp_field(),
            "receipt_root": nullable(_hash()),
        },
        (
            "ceremony_id",
            "human_cli_principal_id",
            "token_family_id",
            "workspace_id",
            "migration_id",
            "operation_id",
            "action",
            "resource_id",
            "canonical_input_hash",
            "evidence_root",
            "spec_version",
            "rubric_version",
            "state_version",
            "reversibility",
            "expected_version",
            "nonce_hash",
            "state",
            "app_path",
            "expires_at",
            "receipt_root",
        ),
        data_class="identity_tenant",
        max_bytes=65_536,
        flow_ids=("F02", "F23"),
        description="Five-minute create-only human-CLI request completed atomically only by a current stepped-up browser session.",
    )
    catalog_item = s_object(
        {
            "capability_id": s_string(pattern=r"^MVP-CAP-[A-Z0-9][A-Z0-9-]+$", max_length=128),
            "incapability_id": _name(128),
            "operation_id": _name(128),
            "reason_code": _name(128),
            "safe_explanation": _safe_text(2048),
            "safe_remediation": _safe_text(2048),
            "required_human_surface": s_string(enum=("browser", "human_cli", "support", "unavailable")),
            "coding_agent_denied": {"type": "boolean", "const": True},
            "structural_denial_contract_ids": s_array(_name(128), min_items=1, max_items=32, unique=True),
            "negative_test_receipt_hashes": s_array(_hash(), min_items=1, max_items=64, unique=True),
        },
        (
            "capability_id",
            "incapability_id",
            "operation_id",
            "reason_code",
            "safe_explanation",
            "safe_remediation",
            "required_human_surface",
            "coding_agent_denied",
            "structural_denial_contract_ids",
            "negative_test_receipt_hashes",
        ),
    )
    catalog = schema(
        "client/customer-incapability-catalog.schema.json",
        "Jumpship Release-Selected Customer Incapability Catalog Contract",
        {
            "catalog_id": hash_field(),
            "logical_payload_sha256": hash_field(),
            "logical_payload_projection": s_object(
                {
                    "object_type": s_string(const="customer_incapability_catalog"),
                    "id_field": s_string(const="catalog_id"),
                    "object_schema_version": s_string(const=SCHEMA_VERSION),
                    "canonical_encoder": s_string(const="RFC8785_JCS"),
                    "domain_separator": s_string(
                        const="jumpship:customer_incapability_catalog:1.0.0\u0000"
                    ),
                    "excluded_fields": {
                        "type": "array",
                        "const": [
                            "catalog_id",
                            "catalog_hash",
                            "logical_payload_sha256",
                            "logical_payload_projection",
                        ],
                        "minItems": 4,
                        "maxItems": 4,
                    },
                    "equivalent_digest_fields": {
                        "type": "array",
                        "const": ["catalog_hash"],
                        "minItems": 1,
                        "maxItems": 1,
                    },
                    "id_encoding": s_string(const="lowercase_hex_sha256"),
                    "id_equals_logical_payload_sha256": {
                        "type": "boolean",
                        "const": True,
                    },
                },
                (
                    "object_type",
                    "id_field",
                    "object_schema_version",
                    "canonical_encoder",
                    "domain_separator",
                    "excluded_fields",
                    "equivalent_digest_fields",
                    "id_encoding",
                    "id_equals_logical_payload_sha256",
                ),
            ),
            "selection_mode": s_string(enum=("new_admission_release", "pinned_cell_release_binding")),
            "release_unit_id": _hash(),
            "release_unit_hash": _hash(),
            "catalog_hash": _hash(),
            "source_registry_hash": _hash(),
            "sort_order": s_string(const="capability_id_then_incapability_id"),
            "migration_id": nullable(_id()),
            "release_evidence_chain": s_array(
                _hash(), min_items=1, max_items=64, unique=True
            ),
            "items": s_array(
                catalog_item,
                min_items=1,
                max_items=2048,
                unique=True,
            ),
            "issued_at": timestamp_field(),
        },
        (
            "catalog_id",
            "logical_payload_sha256",
            "logical_payload_projection",
            "selection_mode",
            "release_unit_id",
            "release_unit_hash",
            "catalog_hash",
            "source_registry_hash",
            "sort_order",
            "migration_id",
            "release_evidence_chain",
            "items",
            "issued_at",
        ),
        data_class="public",
        max_bytes=1_048_576,
        flow_ids=("F01", "F02", "F23"),
        description="Release-bound capability disclosure resolved from the serving or migration-pinned ReleaseUnit with no newest-release fallback or independent signature.",
    )
    return {
        "contracts/client/local-broker.schema.json": local_broker,
        "contracts/client/browser-ceremony.schema.json": ceremony,
        "contracts/client/customer-incapability-catalog.schema.json": catalog,
    }


def _session_event_schema() -> dict[str, Any]:
    event_types = (
        "message.created",
        "attempt.started",
        "attempt.progress",
        "attempt.finished",
        "decision.required",
        "decision.updated",
        "decision.resolved",
        "checklist.updated",
        "spec.changed",
        "artifact.available",
        "artifact.lifecycle_changed",
        "sync.health",
        "consent.ready",
        "consent.changed",
        "incident.opened",
        "incident.updated",
        "migration.phase_changed",
        "notification.changed",
    )
    actor = s_object(
        {
            "type": s_string(enum=("user", "service", "agent", "cell", "provider", "workload")),
            "id": _name(255),
        },
        ("type", "id"),
    )
    link = s_object(
        {
            "relation": s_string(enum=("self", "conversation", "operation", "decision", "artifact", "projection")),
            "resource_id": _name(255),
            "resource_version": _version(),
            "path": s_string(pattern=r"^/v1/[A-Za-z0-9_{}./-]+$", max_length=512),
        },
        ("relation", "resource_id", "resource_version", "path"),
    )
    payload = s_object(
        {
            "resource_id": nullable(_name(255)),
            "resource_version": nullable(_version()),
            "projection_root": nullable(_hash()),
            "safe_status": nullable(_name(128)),
            "progress_percent": nullable(s_integer(minimum=0, maximum=100)),
        },
        ("resource_id", "resource_version", "projection_root", "safe_status", "progress_percent"),
    )
    return schema(
        "events/session-event.schema.json",
        "Jumpship Exhaustive Session Event Projection Contract",
        {
            "event_id": _id(),
            "migration_id": _id(),
            "conversation_id": _id(),
            "migration_sequence": s_integer(minimum=1),
            "event_type": {
                "type": "string",
                "pattern": r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
                "maxLength": 128,
                "x-jumpship-known-values": list(event_types),
            },
            "actor": actor,
            "occurred_at": timestamp_field(),
            "recorded_at": timestamp_field(),
            "effective_at": timestamp_field(),
            "phase": s_string(enum=("connect", "discovery", "foundation", "provision", "snapshot", "census", "design", "rehearsal", "bulk_load", "sync", "verify", "cutover", "watch", "decommission", "complete", "aborted")),
            "causation_id": _id(),
            "correlation_id": _id(),
            "run_id": nullable(_id()),
            "iteration_sequence": nullable(s_integer(minimum=1)),
            "operation_id": nullable(_id()),
            "decision_id": nullable(_id()),
            "evidence_refs": s_array(s_string(pattern="^evh_[A-Za-z0-9_-]{16,128}$"), max_items=64, unique=True),
            "safe_summary": _safe_text(4096),
            "trace_id": s_string(pattern=r"^[0-9a-f]{32}$"),
            "payload": payload,
            "links": s_array(link, max_items=32),
        },
        (
            "event_id",
            "migration_id",
            "conversation_id",
            "migration_sequence",
            "event_type",
            "actor",
            "occurred_at",
            "recorded_at",
            "effective_at",
            "phase",
            "causation_id",
            "correlation_id",
            "run_id",
            "iteration_sequence",
            "operation_id",
            "decision_id",
            "evidence_refs",
            "safe_summary",
            "trace_id",
            "payload",
            "links",
        ),
        data_class="shared_migration",
        max_bytes=65_536,
        flow_ids=("F02", "F03", "F06", "F17"),
        description="Durable ordered flight-recorder projection. Bounded unknown event types remain valid visible unsupported states and trigger projection refetch rather than silent drop.",
    )


_CELL_PROTO = r'''syntax = "proto3";

package jumpship.cell.v1;

option go_package = "github.com/ssai-hq/jumpship/internal/contracts/cell/v1;cellv1";

// EnvelopeContext is mandatory on every supervisor and recovery message.  The
// server validates UUIDv7/hash/time encodings, signature purpose, channel
// binding, epochs, monotonic sequence, and release protocol compatibility.
message EnvelopeContext {
  string workspace_id = 1;
  string migration_id = 2;
  string cell_id = 3;
  uint64 cell_generation = 4;
  uint64 control_region_epoch = 5;
  uint64 target_write_epoch = 6;
  string protocol_version = 7;
  uint64 sequence = 8;
  string causation_id = 9;
  string correlation_id = 10;
  string trace_id = 11;
  string signature_envelope_hash = 12;
  string channel_binding_hash = 13;
}

message CellHello {
  reserved 1; // EnvelopeContext is carried exactly once by SupervisorFrame.
  string release_unit_id = 2;
  string release_unit_hash = 3;
  string cell_release_binding_hash = 4;
  string capability_hash = 5;
  string projection_root = 6;
  repeated ProviderControlHead provider_control_heads = 7;
}

message Heartbeat {
  reserved 1;
  string liveness_state = 2;
  string health_root = 3;
  string current_command_lease_id = 4;
  string observed_at = 5;
}

message CommandLease {
  reserved 1;
  string command_lease_id = 2;
  string command_type = 3;
  string command_payload_hash = 4;
  string prerequisite_root = 5;
  string not_before = 6;
  string expires_at = 7;
}

message CommandAck {
  reserved 1;
  string command_lease_id = 2;
  string state = 3;
  string receipt_root = 4;
  string safe_error_code = 5;
}

message ProjectionSnapshot {
  reserved 1;
  uint64 projection_version = 2;
  string projection_root = 3;
  string migration_phase = 4;
  string traffic_authority = 5;
  uint64 application_authority_epoch = 6;
}

message OperationGrant {
  reserved 1;
  string operation_id = 2;
  string tool_id = 3;
  string tool_version = 4;
  string descriptor_hash = 5;
  string input_hash = 6;
  string gate_root = 7;
  string capability_grant_hash = 8;
  string expires_at = 9;
}

message ToolReceipt {
  reserved 1;
  string operation_id = 2;
  string tool_id = 3;
  string descriptor_hash = 4;
  string input_hash = 5;
  string output_hash = 6;
  string outcome = 7;
  string effect_receipt_root = 8;
  string safe_error_code = 9;
}

message CellEvent {
  string event_id = 1;
  uint64 cell_sequence = 2;
  string event_type = 3;
  string payload_hash = 4;
  string data_class = 5;
  uint64 payload_bytes = 6;
  string safe_summary = 7;
}

message CellEventBatch {
  reserved 1;
  string batch_id = 2;
  uint64 first_sequence = 3;
  uint64 last_sequence = 4;
  repeated CellEvent events = 5;
  string batch_root = 6;
}

message EventAck {
  reserved 1;
  string batch_id = 2;
  uint64 accepted_through_sequence = 3;
  string inbox_receipt_root = 4;
}

message EvidenceAccessRequest {
  reserved 1;
  string request_id = 2;
  string artifact_handle = 3;
  string actor_id = 4;
  string purpose = 5;
  uint64 range_start = 6;
  uint64 range_length = 7;
  string expected_artifact_hash = 8;
  string expires_at = 9;
}

message EvidenceAccessReceipt {
  reserved 1;
  string request_id = 2;
  string issuance_nonce_hash = 3;
  string access_policy_hash = 4;
  string outcome = 5;
  string access_receipt_root = 6;
}

message CredentialLeaseRequest {
  reserved 1;
  string request_id = 2;
  string credential_handle = 3;
  string operation_id = 4;
  string tool_descriptor_hash = 5;
  string purpose = 6;
  string expires_at = 7;
}

message CredentialLeaseReceipt {
  reserved 1;
  string request_id = 2;
  string lease_id = 3;
  string credential_version_hash = 4;
  string outcome = 5;
  string lease_receipt_root = 6;
}

message RecoveryPointer {
  reserved 1;
  string recovery_pointer_id = 2;
  string checkpoint_root = 3;
  uint64 checkpoint_sequence = 4;
  string recovery_manifest_hash = 5;
  string observed_at = 6;
}

// ProviderControlHead is the reconnect truth for one immutable provider-data
// record. Every ID is paired with the accepted canonical hash so a cell cannot
// report a same-ID substitution or roll a head backward.
message ProviderControlHead {
  string provider_data_use_record_id = 1;
  string provider_data_use_record_hash = 2;
  string provider_review_id = 3;
  string provider_review_hash = 4;
  string provider_status_id = 5;
  string provider_status_hash = 6;
  string provider_transition_id = 7;
  string provider_transition_hash = 8;
  uint64 provider_transition_sequence = 9;
  string public_key_registry_id = 10;
  string public_key_registry_hash = 11;
  string route_hold_id = 12;
  string route_hold_hash = 13;
  string provider_use_lease_id = 14;
  string provider_use_lease_hash = 15;
}

message ProviderEvidenceTransitionDelivery {
  reserved 1;
  string delivery_id = 2;
  string cell_release_binding_hash = 3;
  string provider_data_use_record_id = 4;
  string provider_data_use_record_hash = 5;
  string transition_id = 6;
  string transition_hash = 7;
  uint64 transition_sequence = 8;
  string predecessor_transition_hash = 9;
  string embedded_review_hash = 10;
  string embedded_status_hash = 11;
  string transition_object_key = 12;
  string signature_envelope_hash = 13;
  string public_key_registry_id = 14;
  string public_key_registry_hash = 15;
  string registry_predecessor_hash = 16;
}

message ProviderRouteHoldFrame {
  reserved 1;
  string hold_id = 2;
  string hold_hash = 3;
  string provider_data_use_record_id = 4;
  string transition_id = 5;
  string cell_release_binding_hash = 6;
  string state = 7;
  string maximum_pre_hold_lease_expiry = 8;
  string safe_reason_code = 9;
}

message ProviderUseLeaseFrame {
  reserved 1;
  string lease_id = 2;
  string reservation_id = 3;
  string cell_id = 4;
  uint64 cell_generation = 5;
  string cell_release_binding_hash = 6;
  string provider_data_use_record_id = 7;
  string provider_data_use_record_hash = 8;
  string accepted_transition_id = 9;
  uint64 accepted_transition_sequence = 10;
  string accepted_status_hash = 11;
  string agent_bundle_id = 12;
  string agent_bundle_hash = 13;
  string release_unit_id = 14;
  string release_unit_hash = 15;
  uint64 control_epoch = 16;
  bool no_unresolved_binding_hold = 17;
  string issued_at = 18;
  string expires_at = 19;
  uint32 ttl_seconds = 20;
  string nonce_hash = 21;
  string signature_purpose = 22;
  string signature_envelope_hash = 23;
}

message ProviderControlAck {
  reserved 1;
  string delivery_id = 2;
  string transition_id = 3;
  string transition_hash = 4;
  string route_hold_id = 5;
  string accepted_head_hash = 6;
  string state = 7;
  string accepted_at = 8;
  string signature_envelope_hash = 9;
}

message SupervisorFrame {
  EnvelopeContext context = 1;
  oneof frame {
    CellHello cell_hello = 2;
    Heartbeat heartbeat = 3;
    CommandLease command_lease = 4;
    CommandAck command_ack = 5;
    ProjectionSnapshot projection_snapshot = 6;
    OperationGrant operation_grant = 7;
    ToolReceipt tool_receipt = 8;
    CellEventBatch cell_event_batch = 9;
    EventAck event_ack = 10;
    EvidenceAccessRequest evidence_access_request = 11;
    EvidenceAccessReceipt evidence_access_receipt = 12;
    CredentialLeaseRequest credential_lease_request = 13;
    CredentialLeaseReceipt credential_lease_receipt = 14;
    RecoveryPointer recovery_pointer = 15;
    ProviderEvidenceTransitionDelivery provider_evidence_transition = 16;
    ProviderRouteHoldFrame provider_route_hold = 17;
    ProviderUseLeaseFrame provider_use_lease = 18;
    ProviderControlAck provider_control_ack = 19;
  }
}

message RenewRequest {
  EnvelopeContext context = 1;
  string failover_manifest_id = 2;
  string failover_manifest_hash = 3;
  uint64 prior_control_region_epoch = 4;
  uint64 current_control_region_epoch = 5;
  string old_certificate_serial = 6;
  string csr_der_sha256 = 7;
  bytes csr_der = 8;
  string instance_identity_hash = 9;
}

message RenewResponse {
  EnvelopeContext context = 1;
  string request_id = 2;
  string poll_secret = 3;
  string poll_secret_hash = 4;
  string expires_at = 5;
  string recovery_receipt_root = 6;
  // This response carries no command, stream, operation, credential, or grant authority.
}

service SupervisorControl {
  rpc Connect(stream SupervisorFrame) returns (stream SupervisorFrame);
}

service CellCertificateRecovery {
  // Renew is the sole prior-epoch exception and yields only bootstrap polling material.
  rpc Renew(RenewRequest) returns (RenewResponse);
}
'''


def _endpoint(
    method: str,
    path: str,
    operation_id: str,
    summary: str,
    *,
    audiences: tuple[str, ...] = ("jumpship-browser", "jumpship-cli-human", "jumpship-coding-agent"),
    roles: tuple[str, ...] = ("workspace_member",),
    sensitive: bool = False,
    protocol_identity: bool = False,
    csrf_exempt: bool = False,
    body_media_type: str = "application/json",
    asynchronous: bool = False,
    data_class: str = "shared_migration",
    max_bytes: int = 1_048_576,
    callback: bool = False,
    internal: bool = False,
) -> dict[str, Any]:
    return {
        "method": method.lower(),
        "path": path,
        "operation_id": operation_id,
        "summary": summary,
        "audiences": audiences,
        "roles": roles,
        "sensitive": sensitive,
        "protocol_identity": protocol_identity,
        "csrf_exempt": csrf_exempt,
        "body_media_type": body_media_type,
        "asynchronous": asynchronous,
        "data_class": data_class,
        "max_bytes": max_bytes,
        "callback": callback,
        "internal": internal,
    }


def _endpoints() -> list[dict[str, Any]]:
    browser = ("jumpship-browser",)
    callback = ("oauth-callback-transaction",)
    human_cli = ("jumpship-cli-human",)
    workload = ("jumpship-application-writer",)
    cell_bootstrap = ("jumpship-cell-bootstrap",)
    migration = "/v1/workspaces/{workspace_id}/migrations/{migration_id}"
    endpoints = [
        _endpoint("POST", "/v1/auth/oauth/{provider}/start", "startIdentityOAuth", "Start identity login or linking", audiences=browser, roles=("anonymous_or_session",), sensitive=True, protocol_identity=True, csrf_exempt=True, data_class="identity_tenant"),
        _endpoint("POST", "/v1/auth/oauth/{provider}/prepare", "prepareIdentityOAuthCallback", "Establish callback-host browser binding", audiences=callback, roles=("protocol_transaction",), sensitive=True, protocol_identity=True, csrf_exempt=True, body_media_type="application/x-www-form-urlencoded", callback=True, data_class="credential_secret", max_bytes=16_384),
        _endpoint("GET", "/v1/auth/oauth/{provider}/callback", "consumeIdentityOAuthCallback", "Consume provider identity callback", audiences=callback, roles=("protocol_transaction",), sensitive=True, protocol_identity=True, csrf_exempt=True, callback=True, data_class="credential_secret", max_bytes=16_384),
        _endpoint("POST", "/v1/auth/oauth/complete", "completeIdentityOAuth", "Complete callback-to-API login handoff", audiences=browser, roles=("protocol_transaction",), sensitive=True, protocol_identity=True, csrf_exempt=True, body_media_type="application/x-www-form-urlencoded", data_class="credential_secret", max_bytes=16_384),
        _endpoint("GET", "/v1/auth/session", "getAuthSession", "Present current identity and session", audiences=browser, roles=("session",), data_class="identity_tenant"),
        _endpoint("POST", "/v1/auth/logout", "logoutSession", "Revoke current browser session", audiences=browser, roles=("session",), data_class="identity_tenant"),
        _endpoint("POST", "/v1/auth/logout-all", "logoutAllSessions", "Revoke every browser and CLI session", audiences=browser, roles=("fresh_security_reauth",), sensitive=True, data_class="identity_tenant"),
        _endpoint("POST", "/v1/auth/webauthn/registration/options", "createWebAuthnRegistration", "Create passkey enrollment challenge", audiences=browser, roles=("fresh_session",), sensitive=True, protocol_identity=True, data_class="security_material"),
        _endpoint("POST", "/v1/auth/webauthn/registration/verify", "verifyWebAuthnRegistration", "Verify and enroll passkey", audiences=browser, roles=("fresh_session",), sensitive=True, protocol_identity=True, data_class="security_material"),
        _endpoint("GET", "/v1/auth/webauthn/credentials", "listWebAuthnCredentials", "List safe passkey metadata", audiences=browser, roles=("session",), data_class="identity_tenant"),
        _endpoint("DELETE", "/v1/auth/webauthn/credentials/{credential_id}", "revokeWebAuthnCredential", "Revoke passkey", audiences=browser, roles=("fresh_security_reauth",), sensitive=True, data_class="security_material"),
        _endpoint("POST", "/v1/auth/device/authorizations", "createDeviceAuthorization", "Start CLI device authorization", audiences=human_cli, roles=("local_client",), protocol_identity=True, data_class="identity_tenant"),
        _endpoint("POST", "/v1/auth/device/authorizations/approve", "approveDeviceAuthorization", "Approve a local CLI in browser", audiences=browser, roles=("session",), sensitive=True, protocol_identity=True, data_class="credential_secret", max_bytes=16_384),
        _endpoint("POST", "/v1/auth/device/token", "exchangeDeviceToken", "Poll or exchange one-use device code", audiences=human_cli, roles=("protocol_transaction",), protocol_identity=True, data_class="credential_secret", max_bytes=16_384),
        _endpoint("POST", "/v1/cli/browser-ceremonies", "createBrowserCeremony", "Request exact consequential browser review", audiences=human_cli, roles=("human_cli",), sensitive=True, data_class="identity_tenant"),
        _endpoint("GET", "/v1/cli/browser-ceremonies/{ceremony_id}", "getBrowserCeremony", "Read safe ceremony status", audiences=human_cli, roles=("human_cli",), data_class="identity_tenant"),
        _endpoint("POST", "/v1/cli/browser-ceremonies/{ceremony_id}/decision", "decideBrowserCeremony", "Approve or decline an exact ceremony in browser", audiences=browser, roles=("fresh_security_reauth",), sensitive=True, protocol_identity=True, data_class="identity_tenant"),
        _endpoint("GET", "/v1/workspaces", "listWorkspaces", "List workspaces", data_class="identity_tenant"),
        _endpoint("POST", "/v1/workspaces", "createWorkspace", "Create workspace and atomic owner", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("authenticated_user",), data_class="identity_tenant"),
        _endpoint("GET", "/v1/workspaces/{workspace_id}", "getWorkspace", "Read workspace", data_class="identity_tenant"),
        _endpoint("PATCH", "/v1/workspaces/{workspace_id}", "updateWorkspace", "Versioned workspace update", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("workspace_owner", "workspace_admin"), data_class="identity_tenant"),
        _endpoint("GET", "/v1/workspaces/{workspace_id}/members", "listWorkspaceMembers", "List members and responsibilities", data_class="identity_tenant"),
        _endpoint("POST", "/v1/workspaces/{workspace_id}/invitations", "inviteWorkspaceMember", "Invite workspace member", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("workspace_owner", "workspace_admin"), data_class="identity_tenant"),
        _endpoint("POST", "/v1/invitations/accept", "acceptWorkspaceInvitation", "Accept invitation with separately delivered code", audiences=browser, roles=("verified_identity",), sensitive=True, protocol_identity=True, data_class="credential_secret", max_bytes=16_384),
        _endpoint("PATCH", "/v1/workspaces/{workspace_id}/members/{user_id}", "updateWorkspaceMember", "Update role or responsibility", audiences=browser, roles=("workspace_owner", "workspace_admin"), sensitive=True, data_class="identity_tenant"),
        _endpoint("DELETE", "/v1/workspaces/{workspace_id}/members/{user_id}", "removeWorkspaceMember", "Remove member and revoke access", audiences=browser, roles=("workspace_owner", "workspace_admin"), sensitive=True, data_class="identity_tenant"),
        _endpoint("GET", "/v1/workspaces/{workspace_id}/migrations", "listMigrations", "List migrations"),
        _endpoint("POST", "/v1/workspaces/{workspace_id}/migrations", "createMigration", "Create migration and cell identity", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("workspace_owner", "workspace_admin", "engineer"), asynchronous=True),
        _endpoint("GET", migration, "getMigration", "Read canonical migration projection"),
        _endpoint("PATCH", migration, "updateMigration", "Update safe migration metadata", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("workspace_owner", "workspace_admin", "engineer")),
        _endpoint("POST", migration + "/start", "startMigrationFromPrompt", "Atomically append first prompt and start discovery", audiences=browser, roles=("workspace_owner", "workspace_admin", "engineer"), sensitive=True, asynchronous=True, max_bytes=65_536),
        _endpoint("GET", migration + "/access-manifest", "getAccessManifest", "Read tiered grant and coverage state"),
        _endpoint("GET", migration + "/connectors", "listConnectors", "Read connector status and safe resources"),
        _endpoint("POST", migration + "/connectors/{kind}/begin", "beginConnectorGrant", "Start exact provider grant or manual intake", audiences=browser, roles=("workspace_owner", "workspace_admin"), sensitive=True, protocol_identity=True, data_class="identity_tenant"),
        _endpoint("POST", "/v1/connectors/{kind}/oauth/prepare", "prepareConnectorOAuthCallback", "Establish connector callback-host browser binding", audiences=callback, roles=("protocol_transaction",), sensitive=True, protocol_identity=True, csrf_exempt=True, body_media_type="application/x-www-form-urlencoded", callback=True, data_class="credential_secret", max_bytes=16_384),
        _endpoint("POST", "/v1/connectors/oauth/complete", "completeConnectorOAuth", "Activate pending connector grant", audiences=browser, roles=("protocol_transaction",), sensitive=True, protocol_identity=True, csrf_exempt=True, body_media_type="application/x-www-form-urlencoded", data_class="credential_secret", max_bytes=16_384),
        _endpoint("PUT", migration + "/connectors/mongodb/credential", "putMongoDBCredential", "Store source URI through no-log intake", audiences=browser, roles=("workspace_owner", "workspace_admin"), sensitive=True, protocol_identity=True, data_class="credential_secret", max_bytes=16_384),
        _endpoint("GET", "/v1/connectors/{kind}/callback", "consumeConnectorOAuthCallback", "Consume provider connector callback", audiences=callback, roles=("protocol_transaction",), sensitive=True, protocol_identity=True, csrf_exempt=True, callback=True, data_class="credential_secret", max_bytes=16_384),
        _endpoint("POST", migration + "/connectors/{connector_id}/verify", "verifyConnector", "Enqueue cell connector verification", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("workspace_owner", "workspace_admin", "engineer"), asynchronous=True),
        _endpoint("DELETE", migration + "/connectors/{connector_id}", "disconnectConnector", "Revoke connector and dependent access", audiences=browser, roles=("workspace_owner", "workspace_admin"), sensitive=True),
        _endpoint("GET", migration + "/connector-recommendations", "listConnectorRecommendations", "Read evidence-derived optional grants"),
        _endpoint("POST", migration + "/approvers/{consent_kind}", "assignConsentApprover", "Assign named cutover or decommission approver", audiences=browser, roles=("workspace_owner",), sensitive=True, data_class="identity_tenant"),
        _endpoint("GET", migration + "/application-estate", "getApplicationEstate", "Read safe application estate coverage"),
        _endpoint("GET", migration + "/application-change-sets/{version}", "getApplicationChangeSet", "Read safe exact change-set projection"),
        _endpoint("POST", migration + "/connectors/github/pr-authority", "configureDraftPRAuthority", "Grant or revoke standing namespaced draft-PR authority", audiences=browser, roles=("workspace_owner", "workspace_admin"), sensitive=True),
        _endpoint("POST", migration + "/pull-requests/{pr_binding_id}/reviews/{reviewer}", "dispatchExternalReview", "Dispatch exact-head advisory review", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("workspace_owner", "workspace_admin", "engineer"), asynchronous=True),
        _endpoint("POST", migration + "/pull-requests/{pr_binding_id}/customer-validation", "recordCustomerValidation", "Record exact-head customer validation", audiences=browser, roles=("application_validator",), sensitive=True),
        _endpoint("PUT", migration + "/deploy-units/{deploy_unit_id}/deployment-evidence-provider", "putDeploymentEvidenceProvider", "Register or rotate read-only deployment evidence trust", audiences=browser, roles=("deployment_owner",), sensitive=True, data_class="security_material"),
        _endpoint("POST", migration + "/deployments/{deployment_id}/attest", "identifyDeployment", "Identify customer deployment for reconciliation", audiences=browser, roles=("deployment_owner",), sensitive=True),
        _endpoint("GET", migration + "/deployments/{deployment_id}", "getDeploymentProof", "Read merge, build, rollout, and runtime proof"),
        _endpoint("GET", migration + "/writer-cohorts", "listWriterCohorts", "Read writer cohort readiness and authority"),
        _endpoint("POST", "/v1/application-writer/identity-exchanges", "exchangeApplicationWriterIdentity", "Exchange workload attestation and ephemeral key", audiences=workload, roles=("released_workload",), sensitive=True, protocol_identity=True, data_class="security_material"),
        _endpoint("POST", "/v1/application-writer/grants", "requestApplicationWriterGrant", "Request or renew exact short-lived writer grant", audiences=workload, roles=("released_workload",), sensitive=True, asynchronous=True, data_class="security_material"),
        _endpoint("GET", migration + "/conversations", "listConversations", "List migration conversation streams"),
        _endpoint("POST", migration + "/conversations", "createConversation", "Create permitted fork or btw conversation"),
        _endpoint("GET", migration + "/conversations/{conversation_id}/events", "listConversationEvents", "Replay immutable ordered conversation events"),
        _endpoint("POST", migration + "/conversations/{conversation_id}/messages", "createConversationMessage", "Send bounded shared-safe message or handle", max_bytes=65_536),
        _endpoint("GET", migration + "/decisions", "listDecisions", "List and filter decision cards"),
        _endpoint("GET", migration + "/decisions/{decision_key}", "getDecision", "Read current decision workspace"),
        _endpoint("POST", migration + "/decisions/{decision_key}/messages", "createDecisionMessage", "Add decision context or counter-proposal", max_bytes=65_536),
        _endpoint("POST", migration + "/decisions/{decision_key}/delegate", "delegateDecision", "Delegate decision to an active member", audiences=("jumpship-browser", "jumpship-cli-human")),
        _endpoint("POST", migration + "/decisions/{decision_key}/resolve", "resolveDecision", "Resolve ordinary or conditional decision", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("decision_owner",), sensitive=True),
        _endpoint("GET", migration + "/ledger", "getDecisionLedger", "Read append-only decision and repair ledger"),
        _endpoint("GET", migration + "/specs", "listSpecs", "List canonical spec versions and safe diffs"),
        _endpoint("POST", migration + "/specs/{spec_id}/confirm", "confirmSpec", "Bind approved reversible specification", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("decision_owner",)),
        _endpoint("GET", migration + "/rubrics", "listRubrics", "List verification rubric versions"),
        _endpoint("POST", migration + "/rubrics/{rubric_id}/confirm", "confirmRubric", "Bind preregistered rubric", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("decision_owner",)),
        _endpoint("GET", migration + "/attempts", "listAttempts", "Read attempt timeline"),
        _endpoint("GET", migration + "/operations/{operation_id}", "getOperation", "Read operation status and safe receipt"),
        _endpoint("POST", migration + "/operations", "requestOperation", "Request named deterministic operation", audiences=("jumpship-browser", "jumpship-cli-human"), asynchronous=True),
        _endpoint("POST", migration + "/operations/{operation_id}/cancel", "cancelOperation", "Request safe cancellation", audiences=("jumpship-browser", "jumpship-cli-human"), asynchronous=True),
        _endpoint("GET", migration + "/gates", "listGates", "Read current blockers and freshness"),
        _endpoint("POST", migration + "/phase-transitions", "requestPhaseTransition", "Request a guarded allowed phase edge", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("workspace_owner", "workspace_admin", "engineer"), sensitive=True, asynchronous=True),
        _endpoint("GET", migration + "/traffic-authority", "getTrafficAuthority", "Read writer authority, epoch, and rollback viability"),
        _endpoint("GET", migration + "/health", "getMigrationHealth", "Read safe sync and readiness projection"),
        _endpoint("GET", migration + "/events", "streamMigrationEvents", "Stream durable migration-wide SSE"),
        _endpoint("GET", migration + "/consents/{consent_kind}", "getConsent", "Read cutover or decommission consent readiness", audiences=browser, roles=("workspace_member",)),
        _endpoint("POST", migration + "/consents/{consent_kind}/challenge", "challengeConsent", "Issue bound consent challenge", audiences=browser, roles=("named_approver",), sensitive=True, protocol_identity=True),
        _endpoint("POST", migration + "/consents/{consent_kind}/confirm", "confirmConsent", "Confirm WebAuthn and typed-phrase consent", audiences=browser, roles=("named_approver",), sensitive=True, protocol_identity=True),
        _endpoint("POST", migration + "/consents/{consent_kind}/decline", "declineConsent", "Decline or postpone consent", audiences=browser, roles=("named_approver",), sensitive=True),
        _endpoint("GET", migration + "/artifacts", "listArtifacts", "List shared-safe artifact catalog"),
        _endpoint("POST", migration + "/artifacts/{artifact_id}/access", "requestArtifactAccess", "Request direct-cell evidence capability", audiences=browser, roles=("evidence_reader",), sensitive=True, asynchronous=True),
        _endpoint("POST", migration + "/artifact-uploads", "requestArtifactUpload", "Request exact direct-cell upload capability", audiences=browser, roles=("workspace_member",), sensitive=True, asynchronous=True),
        _endpoint("POST", migration + "/reports", "requestReport", "Request deterministic report or dossier", audiences=("jumpship-browser", "jumpship-cli-human"), asynchronous=True),
        _endpoint("GET", migration + "/reports/{report_id}", "getReport", "Read report status and safe handle"),
        _endpoint("GET", migration + "/incidents", "listIncidents", "Read incident forks and rollback currency"),
        _endpoint("POST", migration + "/abort", "abortMigration", "Abort or postpone and authorize safe cleanup", audiences=("jumpship-browser", "jumpship-cli-human"), roles=("workspace_owner", "workspace_admin"), sensitive=True, asynchronous=True),
        _endpoint("GET", migration + "/deletion", "getDeletionState", "Read retained, disabled, scheduled, and deleted state"),
        _endpoint("POST", "/v1/webhooks/{provider}", "receiveProviderWebhook", "Receive allowlisted signed provider webhook", audiences=("provider-webhook",), roles=("provider_signature",), protocol_identity=True, data_class="internal_operational", max_bytes=2_097_152),
        _endpoint("POST", "/v1/internal/cell-certificates/bootstrap/request", "requestCellCertificateBootstrap", "Request first or failover cell certificate", audiences=cell_bootstrap, roles=("one_use_bootstrap",), sensitive=True, protocol_identity=True, data_class="security_material", max_bytes=65_536, internal=True),
        _endpoint("POST", "/v1/internal/cell-certificates/bootstrap/complete", "completeCellCertificateBootstrap", "Poll and atomically mark first certificate delivery", audiences=cell_bootstrap, roles=("one_use_bootstrap",), sensitive=True, protocol_identity=True, data_class="security_material", max_bytes=65_536, internal=True),
        _endpoint("GET", "/v1/meta/agent-incapabilities", "getEnvironmentAgentIncapabilities", "Read serving-release agent incapability catalog", audiences=("jumpship-browser", "jumpship-cli-human", "jumpship-coding-agent", "anonymous"), roles=("public_metadata",), data_class="public"),
        _endpoint("GET", "/v1/migrations/{migration_id}/agent-incapabilities", "getMigrationAgentIncapabilities", "Read migration-pinned agent incapability catalog", roles=("migration_member",), data_class="public"),
    ]
    return endpoints


def _parameter(name: str) -> dict[str, Any]:
    if name in {"workspace_id", "migration_id", "credential_id", "ceremony_id", "connector_id", "pr_binding_id", "deploy_unit_id", "deployment_id", "conversation_id", "operation_id", "artifact_id", "report_id", "spec_id", "rubric_id", "user_id"}:
        value = {"type": "string", "pattern": UUID_PATTERN}
    elif name == "version":
        value = {"type": "integer", "minimum": 1}
    elif name in {"provider", "kind"}:
        value = {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[a-z][a-z0-9_-]*$"}
    elif name == "consent_kind":
        value = {"type": "string", "enum": ["cutover", "decommission"]}
    elif name == "reviewer":
        value = {"type": "string", "enum": ["codex", "claude_code"]}
    else:
        value = {"type": "string", "minLength": 1, "maxLength": 255}
    return {"name": name, "in": "path", "required": True, "schema": value}


def _path_parameters(path: str) -> list[dict[str, Any]]:
    names: list[str] = []
    cursor = 0
    while True:
        start = path.find("{", cursor)
        if start < 0:
            break
        end = path.find("}", start)
        names.append(path[start + 1 : end])
        cursor = end + 1
    return [_parameter(name) for name in names]


def _openapi_component_name(operation_id: str, suffix: str) -> str:
    return operation_id[:1].upper() + operation_id[1:] + suffix


def _api_nullable(value: dict[str, Any]) -> dict[str, Any]:
    return {"anyOf": [value, {"type": "null"}]}


def _api_object(
    properties: dict[str, Any],
    required: tuple[str, ...],
    description: str,
) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "description": description,
        "required": list(required),
        "properties": properties,
    }


def _operation_request_schema(endpoint: dict[str, Any]) -> dict[str, Any]:
    operation_id = endpoint["operation_id"]
    properties: dict[str, Any] = {
        "schema_version": {"const": SCHEMA_VERSION},
        "request_id": {"type": "string", "pattern": UUID_PATTERN},
    }
    required = ["schema_version", "request_id"]
    create_without_version = {
        "startIdentityOAuth",
        "createDeviceAuthorization",
        "createWorkspace",
        "acceptWorkspaceInvitation",
        "createMigration",
        "requestCellCertificateBootstrap",
        "exchangeApplicationWriterIdentity",
        "receiveProviderWebhook",
    }
    if not endpoint["protocol_identity"] and operation_id not in create_without_version:
        properties["expected_version"] = {"type": "integer", "minimum": 1}
        required.append("expected_version")
    elif endpoint["protocol_identity"] and operation_id not in {
        "startIdentityOAuth",
        "createDeviceAuthorization",
        "createWebAuthnRegistration",
        "requestCellCertificateBootstrap",
        "exchangeApplicationWriterIdentity",
        "receiveProviderWebhook",
    }:
        properties["transaction_id"] = {"type": "string", "pattern": UUID_PATTERN}
        required.append("transaction_id")

    text = {"type": "string", "minLength": 1, "maxLength": 65_536}
    short_text = {"type": "string", "minLength": 1, "maxLength": 255}
    hash_value = {"type": "string", "pattern": HASH_PATTERN}
    uuid_value = {"type": "string", "pattern": UUID_PATTERN}
    phase = {
        "type": "string",
        "enum": [
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
            "aborted",
        ],
    }
    overrides: dict[str, tuple[dict[str, Any], tuple[str, ...]]] = {
        "startIdentityOAuth": (
            {
                "provider_action": {"type": "string", "enum": ["login", "link"]},
                "return_path": {"type": "string", "pattern": r"^/[A-Za-z0-9_./?=&%-]*$", "maxLength": 1024},
                "browser_nonce_hash": hash_value,
            },
            ("provider_action", "return_path", "browser_nonce_hash"),
        ),
        "prepareIdentityOAuthCallback": (
            {"prepare_secret": {"type": "string", "minLength": 43, "maxLength": 128, "writeOnly": True}},
            ("prepare_secret",),
        ),
        "completeIdentityOAuth": (
            {"completion_secret": {"type": "string", "minLength": 43, "maxLength": 128, "writeOnly": True}},
            ("completion_secret",),
        ),
        "logoutAllSessions": (
            {"session_family_version": {"type": "integer", "minimum": 1}, "reauthentication_evidence_hash": hash_value},
            ("session_family_version", "reauthentication_evidence_hash"),
        ),
        "createWebAuthnRegistration": (
            {"credential_label": {"type": "string", "minLength": 1, "maxLength": 128}},
            ("credential_label",),
        ),
        "verifyWebAuthnRegistration": (
            {"credential_response": {"type": "string", "minLength": 32, "maxLength": 65_536, "writeOnly": True}, "challenge_hash": hash_value},
            ("credential_response", "challenge_hash"),
        ),
        "createDeviceAuthorization": (
            {
                "workspace_id": _api_nullable(uuid_value),
                "requested_scopes": {"type": "array", "minItems": 1, "maxItems": 32, "uniqueItems": True, "items": short_text},
                "pkce_challenge": {"type": "string", "minLength": 43, "maxLength": 128},
            },
            ("workspace_id", "requested_scopes", "pkce_challenge"),
        ),
        "approveDeviceAuthorization": (
            {"user_code": {"type": "string", "pattern": r"^[A-Z0-9-]{6,32}$", "writeOnly": True}, "decision": {"type": "string", "enum": ["approve", "deny"]}},
            ("user_code", "decision"),
        ),
        "exchangeDeviceToken": (
            {"device_code": {"type": "string", "minLength": 32, "maxLength": 256, "writeOnly": True}, "pkce_verifier": {"type": "string", "minLength": 43, "maxLength": 128, "writeOnly": True}},
            ("device_code", "pkce_verifier"),
        ),
        "createBrowserCeremony": (
            {"operation_id": short_text, "action": short_text, "resource_id": uuid_value, "canonical_input_hash": hash_value, "evidence_root": hash_value, "expected_state_version": {"type": "integer", "minimum": 1}},
            ("operation_id", "action", "resource_id", "canonical_input_hash", "evidence_root", "expected_state_version"),
        ),
        "decideBrowserCeremony": (
            {"decision": {"type": "string", "enum": ["approve", "decline"]}, "browser_challenge_hash": hash_value, "step_up_evidence_hash": hash_value, "canonical_input_hash": hash_value},
            ("decision", "browser_challenge_hash", "step_up_evidence_hash", "canonical_input_hash"),
        ),
        "acceptWorkspaceInvitation": (
            {"invitation_id": uuid_value, "code": {"type": "string", "minLength": 8, "maxLength": 128, "writeOnly": True}},
            ("invitation_id", "code"),
        ),
        "createWorkspace": ({"name": short_text}, ("name",)),
        "updateWorkspace": ({"name": short_text}, ("name",)),
        "inviteWorkspaceMember": (
            {"email": {"type": "string", "format": "email", "minLength": 3, "maxLength": 320}, "role": {"type": "string", "enum": ["owner", "admin", "engineer", "viewer"]}, "responsibilities": {"type": "array", "maxItems": 32, "uniqueItems": True, "items": short_text}},
            ("email", "role", "responsibilities"),
        ),
        "updateWorkspaceMember": (
            {"role": {"type": "string", "enum": ["owner", "admin", "engineer", "viewer"]}, "responsibilities": {"type": "array", "maxItems": 32, "uniqueItems": True, "items": short_text}},
            ("role", "responsibilities"),
        ),
        "createMigration": (
            {
                "name": short_text,
                "corridor_profile_hash": hash_value,
                "selected_target": {"type": "string", "enum": ["supabase_postgres", "planetscale_postgres"]},
            },
            ("name", "corridor_profile_hash", "selected_target"),
        ),
        "updateMigration": (
            {"name": short_text, "safe_description": {"type": "string", "maxLength": 2048}},
            ("name", "safe_description"),
        ),
        "startMigrationFromPrompt": (
            {
                "first_prompt": text,
                "expected_migration_version": {"type": "integer", "minimum": 1},
                "expected_start_readiness_version": {"type": "integer", "minimum": 1},
                "mandatory_connector_proof_roots": {"type": "array", "minItems": 3, "maxItems": 3, "uniqueItems": True, "items": hash_value},
            },
            ("first_prompt", "expected_migration_version", "expected_start_readiness_version", "mandatory_connector_proof_roots"),
        ),
        "putMongoDBCredential": (
            {"connection_uri": {"type": "string", "minLength": 16, "maxLength": 16_384, "writeOnly": True}, "custody_manifest_hash": hash_value},
            ("connection_uri", "custody_manifest_hash"),
        ),
        "beginConnectorGrant": (
            {"grant_action": {"type": "string", "enum": ["connect", "replace", "reauthorize"]}, "requested_resource_root": hash_value, "return_path": {"type": "string", "pattern": r"^/[A-Za-z0-9_./?=&%-]*$", "maxLength": 1024}},
            ("grant_action", "requested_resource_root", "return_path"),
        ),
        "prepareConnectorOAuthCallback": (
            {"prepare_secret": {"type": "string", "minLength": 43, "maxLength": 128, "writeOnly": True}},
            ("prepare_secret",),
        ),
        "completeConnectorOAuth": (
            {"completion_secret": {"type": "string", "minLength": 43, "maxLength": 128, "writeOnly": True}},
            ("completion_secret",),
        ),
        "verifyConnector": (
            {"access_manifest_version": {"type": "integer", "minimum": 1}, "access_manifest_hash": hash_value},
            ("access_manifest_version", "access_manifest_hash"),
        ),
        "assignConsentApprover": ({"approver_user_id": uuid_value, "expected_membership_version": {"type": "integer", "minimum": 1}}, ("approver_user_id", "expected_membership_version")),
        "configureDraftPRAuthority": (
            {"action": {"type": "string", "enum": ["grant", "revoke"]}, "installation_id": uuid_value, "repository_id": uuid_value, "namespace_root": hash_value, "authority_expires_at": _api_nullable({"type": "string", "format": "date-time"})},
            ("action", "installation_id", "repository_id", "namespace_root", "authority_expires_at"),
        ),
        "dispatchExternalReview": (
            {"base_sha": {"type": "string", "pattern": r"^[0-9a-f]{40}$"}, "head_sha": {"type": "string", "pattern": r"^[0-9a-f]{40}$"}, "head_tree_hash": hash_value, "command_nonce_hash": hash_value, "review_deadline": {"type": "string", "format": "date-time"}},
            ("base_sha", "head_sha", "head_tree_hash", "command_nonce_hash", "review_deadline"),
        ),
        "createConversationMessage": ({"safe_text": text, "artifact_handles": {"type": "array", "maxItems": 64, "uniqueItems": True, "items": {"type": "string", "pattern": r"^evh_[A-Za-z0-9_-]{16,128}$"}}}, ("safe_text", "artifact_handles")),
        "requestOperation": ({"tool_id": short_text, "tool_version": {"type": "string", "pattern": SEMVER_PATTERN}, "input_hash": hash_value, "gate_evaluation_root": hash_value}, ("tool_id", "tool_version", "input_hash", "gate_evaluation_root")),
        "requestPhaseTransition": ({"expected_from_phase": phase, "requested_to_phase": phase, "gate_evaluation_root": hash_value, "evidence_roots": {"type": "array", "minItems": 1, "maxItems": 64, "uniqueItems": True, "items": hash_value}}, ("expected_from_phase", "requested_to_phase", "gate_evaluation_root", "evidence_roots")),
        "challengeConsent": ({"expected_consent_version": {"type": "integer", "minimum": 1}, "evidence_root": hash_value, "application_authority_epoch": {"type": "integer", "minimum": 1}, "cell_write_epoch": {"type": "integer", "minimum": 1}}, ("expected_consent_version", "evidence_root", "application_authority_epoch", "cell_write_epoch")),
        "confirmConsent": ({"challenge_id": uuid_value, "webauthn_assertion": {"type": "string", "minLength": 32, "maxLength": 16_384, "writeOnly": True}, "typed_phrase_hash": hash_value, "evidence_root": hash_value, "application_authority_epoch": {"type": "integer", "minimum": 1}, "cell_write_epoch": {"type": "integer", "minimum": 1}}, ("challenge_id", "webauthn_assertion", "typed_phrase_hash", "evidence_root", "application_authority_epoch", "cell_write_epoch")),
        "recordCustomerValidation": ({"base_sha": {"type": "string", "pattern": r"^[0-9a-f]{40}$"}, "head_sha": {"type": "string", "pattern": r"^[0-9a-f]{40}$"}, "head_tree_hash": hash_value, "canonical_patch_hash": hash_value, "test_evidence_root": hash_value}, ("base_sha", "head_sha", "head_tree_hash", "canonical_patch_hash", "test_evidence_root")),
        "putDeploymentEvidenceProvider": (
            {"provider_config_id": uuid_value, "controller_issuer_hash": hash_value, "workload_issuer_hash": hash_value, "ci_issuer_hash": hash_value, "audience_hash": hash_value, "allowed_algorithms": {"type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": True, "items": {"type": "string", "enum": ["ES256", "EdDSA", "RS256"]}}, "trust_root_version": {"type": "integer", "minimum": 1}, "trust_root_hash": hash_value},
            ("provider_config_id", "controller_issuer_hash", "workload_issuer_hash", "ci_issuer_hash", "audience_hash", "allowed_algorithms", "trust_root_version", "trust_root_hash"),
        ),
        "identifyDeployment": ({"deploy_unit_id": uuid_value, "pr_binding_id": uuid_value, "merge_equivalence_root": hash_value, "expected_artifact_digest": hash_value, "expected_config_digest": hash_value}, ("deploy_unit_id", "pr_binding_id", "merge_equivalence_root", "expected_artifact_digest", "expected_config_digest")),
        "exchangeApplicationWriterIdentity": ({"workload_attestation": {"type": "string", "minLength": 32, "maxLength": 16_384, "writeOnly": True}, "deploy_unit_id": uuid_value, "artifact_digest": hash_value, "config_digest": hash_value, "ephemeral_public_key": {"type": "string", "minLength": 64, "maxLength": 4096}}, ("workload_attestation", "deploy_unit_id", "artifact_digest", "config_digest", "ephemeral_public_key")),
        "requestApplicationWriterGrant": ({"writer_id": uuid_value, "cohort_id": uuid_value, "store": {"type": "string", "enum": ["source", "target"]}, "application_authority_epoch": {"type": "integer", "minimum": 1}, "expected_current_cohort_generation": {"type": "integer", "minimum": 1}, "workload_identity_hash": hash_value}, ("writer_id", "cohort_id", "store", "application_authority_epoch", "expected_current_cohort_generation", "workload_identity_hash")),
        "createConversation": (
            {"conversation_kind": {"type": "string", "enum": ["main", "fork", "btw", "incident"]}, "parent_conversation_id": _api_nullable(uuid_value), "safe_subject": {"type": "string", "minLength": 1, "maxLength": 255}},
            ("conversation_kind", "parent_conversation_id", "safe_subject"),
        ),
        "createDecisionMessage": (
            {"safe_text": text, "artifact_handles": {"type": "array", "maxItems": 64, "uniqueItems": True, "items": {"type": "string", "pattern": r"^evh_[A-Za-z0-9_-]{16,128}$"}}},
            ("safe_text", "artifact_handles"),
        ),
        "delegateDecision": (
            {"delegate_user_id": uuid_value, "delegation_scope_hash": hash_value, "delegation_expires_at": {"type": "string", "format": "date-time"}},
            ("delegate_user_id", "delegation_scope_hash", "delegation_expires_at"),
        ),
        "resolveDecision": (
            {"resolution": {"type": "string", "enum": ["approve", "reject", "postpone", "override"]}, "reversibility_class": {"type": "string", "enum": ["free_until_cutover", "expensive_after_cutover", "closes_on_first_external_exposure", "closes_on_a_clock", "never_reversible"]}, "canonical_answer_hash": hash_value, "consequence_version": {"type": "integer", "minimum": 1}, "evidence_roots": {"type": "array", "minItems": 1, "maxItems": 64, "uniqueItems": True, "items": hash_value}},
            ("resolution", "reversibility_class", "canonical_answer_hash", "consequence_version", "evidence_roots"),
        ),
        "confirmSpec": ({"spec_version": {"type": "integer", "minimum": 1}, "spec_hash": hash_value, "evidence_root": hash_value}, ("spec_version", "spec_hash", "evidence_root")),
        "confirmRubric": ({"rubric_version": {"type": "integer", "minimum": 1}, "rubric_hash": hash_value, "evidence_root": hash_value}, ("rubric_version", "rubric_hash", "evidence_root")),
        "cancelOperation": ({"reason_code": short_text, "expected_operation_version": {"type": "integer", "minimum": 1}}, ("reason_code", "expected_operation_version")),
        "declineConsent": ({"reason_code": short_text, "expected_consent_version": {"type": "integer", "minimum": 1}}, ("reason_code", "expected_consent_version")),
        "requestArtifactAccess": (
            {"artifact_version": {"type": "integer", "minimum": 1}, "access_purpose": short_text, "requested_range_max_bytes": {"type": "integer", "minimum": 1, "maximum": 536_870_912}, "evidence_root": hash_value},
            ("artifact_version", "access_purpose", "requested_range_max_bytes", "evidence_root"),
        ),
        "requestArtifactUpload": (
            {"artifact_kind": short_text, "content_type": {"type": "string", "minLength": 1, "maxLength": 255}, "declared_size_bytes": {"type": "integer", "minimum": 1, "maximum": 5_368_709_120}, "declared_sha256": hash_value, "data_class": {"type": "string", "enum": ["shared_migration", "restricted_customer"]}},
            ("artifact_kind", "content_type", "declared_size_bytes", "declared_sha256", "data_class"),
        ),
        "requestReport": ({"report_kind": short_text, "input_root": hash_value, "format": {"type": "string", "enum": ["json", "markdown", "pdf"]}}, ("report_kind", "input_root", "format")),
        "abortMigration": ({"mode": {"type": "string", "enum": ["abort", "postpone"]}, "reason_code": short_text, "expected_phase": phase, "cleanup_scope_hash": hash_value}, ("mode", "reason_code", "expected_phase", "cleanup_scope_hash")),
        "receiveProviderWebhook": (
            {"delivery_id": {"type": "string", "minLength": 1, "maxLength": 255}, "delivered_at": {"type": "string", "format": "date-time"}, "payload_sha256": hash_value, "payload_base64": {"type": "string", "minLength": 4, "maxLength": 2_796_204, "writeOnly": True}},
            ("delivery_id", "delivered_at", "payload_sha256", "payload_base64"),
        ),
        "requestCellCertificateBootstrap": (
            {"deployment_manifest_id": hash_value, "deployment_manifest_hash": hash_value, "cell_release_binding_id": hash_value, "instance_identity_hash": hash_value, "csr_der_base64": {"type": "string", "minLength": 128, "maxLength": 16_384, "writeOnly": True}, "csr_der_hash": hash_value},
            ("deployment_manifest_id", "deployment_manifest_hash", "cell_release_binding_id", "instance_identity_hash", "csr_der_base64", "csr_der_hash"),
        ),
        "completeCellCertificateBootstrap": (
            {"certificate_request_id": uuid_value, "poll_secret": {"type": "string", "minLength": 32, "maxLength": 256, "writeOnly": True}, "csr_der_hash": hash_value},
            ("certificate_request_id", "poll_secret", "csr_der_hash"),
        ),
    }
    extra_properties, extra_required = overrides.get(operation_id, ({}, ()))
    properties.update(extra_properties)
    required.extend(extra_required)
    return _api_object(properties, tuple(dict.fromkeys(required)), f"Exact request body for {operation_id}.")


def _operation_response_schema(endpoint: dict[str, Any]) -> dict[str, Any]:
    operation_id = endpoint["operation_id"]
    hash_value = {"type": "string", "pattern": HASH_PATTERN}
    uuid_value = {"type": "string", "pattern": UUID_PATTERN}
    properties: dict[str, Any] = {
        "schema_version": {"const": SCHEMA_VERSION},
        "request_id": uuid_value,
        "resource_id": {"type": "string", "minLength": 1, "maxLength": 255},
        "resource_version": {"type": "integer", "minimum": 1},
        "projection_root": hash_value,
        "safe_summary": _api_nullable({"type": "string", "maxLength": 4096}),
    }
    required = list(properties)
    overrides: dict[str, tuple[dict[str, Any], tuple[str, ...]]] = {
        "startIdentityOAuth": (
            {
                "authorization_transaction_id": uuid_value,
                "prepare_url": {"type": "string", "format": "uri", "maxLength": 1024},
                "prepare_secret": {"type": "string", "minLength": 43, "maxLength": 128, "writeOnly": True},
                "expires_at": {"type": "string", "format": "date-time"},
            },
            ("authorization_transaction_id", "prepare_url", "prepare_secret", "expires_at"),
        ),
        "startMigrationFromPrompt": (
            {
                "migration_id": uuid_value,
                "migration_version": {"type": "integer", "minimum": 1},
                "start_readiness_version": {"type": "integer", "minimum": 1},
                "conversation_id": uuid_value,
                "message_id": uuid_value,
                "phase": {"const": "discovery"},
                "wakeup_id": uuid_value,
                "receipt_root": hash_value,
            },
            ("migration_id", "migration_version", "start_readiness_version", "conversation_id", "message_id", "phase", "wakeup_id", "receipt_root"),
        ),
        "requestApplicationWriterGrant": (
            {
                "grant_id": uuid_value,
                "grant_state": {"type": "string", "enum": ["signed_dormant", "active", "denied"]},
                "encrypted_credential_envelope": _api_nullable({"type": "string", "minLength": 32, "maxLength": 65_536}),
                "activation_receipt_root": _api_nullable(hash_value),
            },
            ("grant_id", "grant_state", "encrypted_credential_envelope", "activation_receipt_root"),
        ),
    }
    extra_properties, extra_required = overrides.get(operation_id, ({}, ()))
    properties.update(extra_properties)
    required.extend(extra_required)
    return _api_object(properties, tuple(dict.fromkeys(required)), f"Exact safe response for {operation_id}.")


def _openapi_operation_components(endpoints: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    components: dict[str, dict[str, Any]] = {}
    external_responses = {
        "getApplicationEstate": "https://jumpship.dev/contracts/application/application-estate-safe-projection.schema.json",
        "getApplicationChangeSet": "https://jumpship.dev/contracts/application/application-change-set-safe-projection.schema.json",
        "getEnvironmentAgentIncapabilities": "https://jumpship.dev/contracts/client/customer-incapability-catalog.schema.json",
        "getMigrationAgentIncapabilities": "https://jumpship.dev/contracts/client/customer-incapability-catalog.schema.json",
    }
    for endpoint in endpoints:
        operation_id = endpoint["operation_id"]
        if endpoint["method"] in {"post", "put", "patch", "delete"}:
            components[_openapi_component_name(operation_id, "Request")] = _operation_request_schema(endpoint)
        response_name = _openapi_component_name(operation_id, "Response")
        components[response_name] = (
            {"$ref": external_responses[operation_id]}
            if operation_id in external_responses
            else _operation_response_schema(endpoint)
        )
    return components


def _operation(endpoint: dict[str, Any]) -> dict[str, Any]:
    mutation = endpoint["method"] in {"post", "put", "patch", "delete"}
    protocol_identity = endpoint["protocol_identity"]
    csrf_exempt = endpoint["csrf_exempt"]
    sensitive = endpoint["sensitive"]
    audiences = list(endpoint["audiences"])
    stable_errors = [
        "invalid_request",
        "session_expired",
        "step_up_required",
        "authorization_denied",
        "resource_not_found",
        "stale_version",
        "idempotency_key_reused",
        "browser_interaction_required",
        "capability_expired",
        "rate_limited",
        "dependency_unavailable",
    ]
    policy: dict[str, Any] = {
        "authorization": {"roles": list(endpoint["roles"]), "scopes": [endpoint["operation_id"]]},
        "allowed_audiences": audiences,
        "browser_only": sensitive and audiences == ["jumpship-browser"],
        "coding_agent_denied": sensitive or "jumpship-coding-agent" not in audiences,
        "coding_agent_denial_code": "browser_interaction_required" if sensitive else "audience_not_allowed",
        "idempotency": {
            "required": mutation and not protocol_identity,
            "identity": "protocol_one_time_transaction" if protocol_identity else "principal_workspace_operation_id_key",
            "same_key_different_hash_error": "idempotency_key_reused",
        },
        "audit": {"action": endpoint["operation_id"], "required": True, "body_logged": False},
        "concurrency": {
            "mode": "protocol_one_time_transaction" if protocol_identity else ("if_match_or_expected_version" if mutation else "strong_etag"),
            "stale_error": "stale_version",
        },
        "stable_errors": stable_errors,
        "data_class": endpoint["data_class"],
        "max_request_bytes": endpoint["max_bytes"],
        "raw_restricted_customer_body_allowed": False,
        "csrf": {
            "required_for_cookie_authenticated_browser": mutation and "jumpship-browser" in audiences and not endpoint["callback"] and not csrf_exempt,
            "exempt": csrf_exempt,
            "exemption_kind": "frozen_cross_host_protocol_tuple" if csrf_exempt else "none",
        },
    }
    if endpoint["operation_id"] == "resolveDecision":
        policy["conditional_browser_only_actions"] = ["foundation", "never_reversible", "external_exposure"]
    if endpoint["operation_id"] == "requestOperation":
        policy["conditional_browser_only_actions"] = ["billing_ratchet", "traffic_authority", "rollback", "recutover", "break_glass"]
    operation: dict[str, Any] = {
        "operationId": endpoint["operation_id"],
        "summary": endpoint["summary"],
        "parameters": _path_parameters(endpoint["path"]),
        "x-jumpship-policy": policy,
        "responses": {
            "202" if endpoint["asynchronous"] else "200": {
                "description": "Accepted durable operation" if endpoint["asynchronous"] else "Safe canonical response",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": f"#/components/schemas/{_openapi_component_name(endpoint['operation_id'], 'Response')}"
                        }
                    }
                },
            },
            "400": {"$ref": "#/components/responses/Problem400"},
            "401": {"$ref": "#/components/responses/Problem401"},
            "403": {"$ref": "#/components/responses/Problem403"},
            "409": {"$ref": "#/components/responses/Problem409"},
            "410": {"$ref": "#/components/responses/Problem410"},
            "412": {"$ref": "#/components/responses/Problem412"},
            "422": {"$ref": "#/components/responses/Problem422"},
            "429": {"$ref": "#/components/responses/Problem429"},
        },
    }
    operation["parameters"].extend(
        [
            {"name": "X-Request-ID", "in": "header", "required": False, "schema": {"type": "string", "pattern": UUID_PATTERN}},
            {"name": "traceparent", "in": "header", "required": False, "schema": {"type": "string", "pattern": r"^00-[0-9a-f]{32}-[0-9a-f]{16}-0[01]$"}},
        ]
    )
    if endpoint["path"].endswith("/events") and endpoint["method"] == "get":
        operation["responses"]["200"] = {
            "description": "Durable server-sent event stream",
            "content": {"text/event-stream": {"schema": {"$ref": "https://jumpship.dev/contracts/events/session-event.schema.json"}}},
        }
    if endpoint["operation_id"] in {"consumeIdentityOAuthCallback", "consumeConnectorOAuthCallback"}:
        operation["parameters"].extend(
            [
                {"name": "state", "in": "query", "required": True, "schema": {"type": "string", "minLength": 32, "maxLength": 512}},
                {"name": "code", "in": "query", "required": False, "schema": {"type": "string", "minLength": 1, "maxLength": 4096}},
                {"name": "error", "in": "query", "required": False, "schema": {"type": "string", "maxLength": 256}},
                {"name": "error_description", "in": "query", "required": False, "schema": {"type": "string", "maxLength": 1024}},
            ]
        )
        operation["x-jumpship-query-one-of"] = [["code"], ["error"]]
        operation["responses"]["200"] = {
            "description": "No-store fixed-script body-POST handoff interstitial",
            "headers": {
                "Cache-Control": {"required": True, "schema": {"const": "no-store"}},
                "Referrer-Policy": {"required": True, "schema": {"const": "no-referrer"}},
            },
            "content": {"text/html": {"schema": {"type": "string", "maxLength": 65_536}}},
        }
    if endpoint["operation_id"] in {"prepareIdentityOAuthCallback", "prepareConnectorOAuthCallback"}:
        operation["responses"].pop("200", None)
        operation["responses"]["303"] = {
            "description": "Redirect to the exact provider authorization endpoint",
            "headers": {"Location": {"required": True, "schema": {"type": "string", "format": "uri", "maxLength": 2048}}},
        }
    if endpoint["operation_id"] in {"completeIdentityOAuth", "completeConnectorOAuth"}:
        operation["responses"].pop("200", None)
        operation["responses"]["303"] = {
            "description": "Complete one-use handoff and redirect to the stored clean application path",
            "headers": {"Location": {"required": True, "schema": {"type": "string", "pattern": r"^/[A-Za-z0-9_./?=&%-]*$", "maxLength": 1024}}},
        }
    if endpoint["callback"]:
        operation["servers"] = [{"url": "https://auth-callback.{domain}", "variables": {"domain": {"default": "example.invalid"}}}]
        operation["security"] = []
    elif endpoint["internal"]:
        operation["security"] = [{"CellBootstrapSecret": []}]
    elif audiences == ["jumpship-application-writer"]:
        operation["security"] = [{"ApplicationWriterBearer": []}]
    elif audiences == ["provider-webhook"]:
        operation["security"] = [{"ProviderSignature": []}]
    elif endpoint["operation_id"] == "startIdentityOAuth":
        operation["security"] = [{}, {"CookieSession": []}]
    elif "anonymous" in audiences:
        operation["security"] = []
    else:
        operation["security"] = [{"CookieSession": []}, {"OAuthBearer": []}]
    if mutation:
        headers: list[dict[str, Any]] = []
        if not protocol_identity:
            headers.append({"name": "Idempotency-Key", "in": "header", "required": True, "schema": {"type": "string", "minLength": 16, "maxLength": 255}})
        if not protocol_identity:
            headers.append({"name": "If-Match", "in": "header", "required": False, "schema": {"type": "string", "maxLength": 128}})
        requires_origin = (
            ("jumpship-browser" in audiences and not endpoint["callback"])
            or endpoint["operation_id"] in {"prepareIdentityOAuthCallback", "prepareConnectorOAuthCallback"}
        )
        if requires_origin:
            headers.append({"name": "Origin", "in": "header", "required": True, "schema": {"type": "string", "format": "uri", "maxLength": 512}})
            if "jumpship-browser" in audiences and not csrf_exempt:
                headers.append({"name": "X-CSRF-Token", "in": "header", "required": True, "schema": {"type": "string", "minLength": 32, "maxLength": 512}})
        operation["parameters"].extend(headers)
        body_schema = _openapi_component_name(endpoint["operation_id"], "Request")
        operation["requestBody"] = {
            "required": endpoint["method"] != "delete",
            "content": {endpoint["body_media_type"]: {"schema": {"$ref": f"#/components/schemas/{body_schema}"}}},
            "x-jumpship-max-bytes": endpoint["max_bytes"],
            "x-jumpship-data-class": endpoint["data_class"],
        }
    return operation


def _openapi() -> dict[str, Any]:
    endpoints = _endpoints()
    paths: dict[str, dict[str, Any]] = {}
    sensitive_operations: list[str] = []
    for endpoint in endpoints:
        path_item = paths.setdefault(endpoint["path"], {})
        if endpoint["method"] in path_item:
            raise ValueError(f"duplicate OpenAPI operation {endpoint['method']} {endpoint['path']}")
        path_item[endpoint["method"]] = _operation(endpoint)
        if endpoint["sensitive"]:
            sensitive_operations.append(endpoint["operation_id"])
    problem = {
        "type": "object",
        "additionalProperties": False,
        "required": ["type", "title", "code", "status", "detail", "request_id", "field_errors"],
        "properties": {
            "type": {"type": "string", "format": "uri", "maxLength": 512},
            "title": {"type": "string", "maxLength": 256},
            "code": {"type": "string", "pattern": "^[a-z][a-z0-9_]{2,127}$"},
            "status": {"type": "integer", "minimum": 400, "maximum": 599},
            "detail": {"type": "string", "maxLength": 2048},
            "request_id": {"type": "string", "pattern": UUID_PATTERN},
            "field_errors": {
                "type": "array",
                "maxItems": 64,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["field", "code"],
                    "properties": {
                        "field": {"type": "string", "maxLength": 256},
                        "code": {"type": "string", "pattern": "^[a-z][a-z0-9_]{2,127}$"},
                    },
                },
            },
        },
    }
    response_codes = {400: "Bad request", 401: "Session expired", 403: "Step-up or authorization required", 409: "Stale version or conflict", 410: "Capability expired", 412: "Version precondition failed", 422: "Semantically invalid", 429: "Rate limited"}
    responses = {
        f"Problem{code}": {
            "description": description,
            "content": {"application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}},
        }
        for code, description in response_codes.items()
    }
    return {
        "openapi": "3.1.0",
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "info": {
            "title": "Jumpship MVP Control API",
            "version": SCHEMA_VERSION,
            "description": "Authoritative P02 public, callback, workload, and narrow bootstrap API contract.",
        },
        "servers": [{"url": "https://api.{domain}", "variables": {"domain": {"default": "example.invalid"}}}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "CookieSession": {"type": "apiKey", "in": "cookie", "name": "__Host-js_session"},
                "OAuthBearer": {"type": "http", "scheme": "bearer", "bearerFormat": "opaque"},
                "ApplicationWriterBearer": {"type": "http", "scheme": "bearer", "bearerFormat": "workload-bound"},
                "ProviderSignature": {"type": "apiKey", "in": "header", "name": "X-Provider-Signature"},
                "CellBootstrapSecret": {"type": "apiKey", "in": "header", "name": "X-Jumpship-Bootstrap"},
            },
            "schemas": {
                "Problem": problem,
                "ConsentKind": {"type": "string", "enum": ["cutover", "decommission"]},
                **_openapi_operation_components(endpoints),
            },
            "responses": responses,
        },
        "x-jumpship-default-json-max-bytes": 1_048_576,
        "x-jumpship-chat-max-bytes": 65_536,
        "x-jumpship-secret-intake-max-bytes": 16_384,
        "x-jumpship-webhook-max-bytes": 2_097_152,
        "x-jumpship-idempotency-scope": ["principal", "workspace", "operation_id", "idempotency_key"],
        "x-jumpship-cursor-binding": ["workspace", "query_hash", "filter_hash", "sort_direction", "expiry"],
        "x-jumpship-sensitive-coding-agent-denylist": sorted(sensitive_operations),
        "x-jumpship-forbidden-public-operations": [
            "merge_pull_request",
            "deploy_application",
            "set_arbitrary_traffic_authority",
            "activate_release",
            "rollback_release",
            "emergency_stop_release",
            "create_cell_lifecycle_authority",
        ],
    }


def _fixtures() -> dict[str, Artifact]:
    zero = "0" * 64
    one = "1" * 64
    uid = "018f0f7e-7b8a-7abc-8def-0123456789ab"
    uid2 = "018f0f7e-7b8a-7abc-8def-0123456789ac"
    fixtures: dict[str, Artifact] = {}

    def content_identity(
        payload: dict[str, Any],
        *,
        object_type: str,
        id_field: str,
        equivalent_digest_fields: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        """Attach the exact RFC 8785-compatible identity projection metadata.

        Fixture values use only I-JSON primitives whose Python sorted compact
        encoding is byte-identical to JCS, so generation stays dependency-free.
        The Go and TypeScript canonical libraries independently recompute this
        value in their acceptance tests.
        """

        excluded = [
            id_field,
            *equivalent_digest_fields,
            "logical_payload_sha256",
            "logical_payload_projection",
        ]
        logical = {
            key: value
            for key, value in payload.items()
            if key not in excluded
        }
        canonical = json.dumps(
            logical,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256(
            f"jumpship:{object_type}:{SCHEMA_VERSION}\0".encode("utf-8")
            + canonical
        ).hexdigest()
        payload[id_field] = digest
        for field in equivalent_digest_fields:
            payload[field] = digest
        payload["logical_payload_sha256"] = digest
        payload["logical_payload_projection"] = {
            "object_type": object_type,
            "id_field": id_field,
            "object_schema_version": SCHEMA_VERSION,
            "canonical_encoder": "RFC8785_JCS",
            "domain_separator": f"jumpship:{object_type}:{SCHEMA_VERSION}\0",
            "excluded_fields": excluded,
            "equivalent_digest_fields": list(equivalent_digest_fields),
            "id_encoding": "lowercase_hex_sha256",
            "id_equals_logical_payload_sha256": True,
        }
        return payload

    def transition_partition(
        states: tuple[str, ...],
        edges: tuple[tuple[str, str], ...],
    ) -> dict[str, Any]:
        allowed = set(edges)
        return {
            "states": list(states),
            "valid_transitions": [
                {"from_state": source, "to_state": target, "expected": "valid"}
                for source, target in edges
            ],
            "invalid_transitions": [
                {
                    "from_state": source,
                    "to_state": target,
                    "expected": "invalid",
                    "expected_error": "illegal_transition",
                }
                for source in states
                for target in states
                if (source, target) not in allowed
            ]
            + [
                {"from_state": "unknown_state", "to_state": states[0], "expected": "invalid", "expected_error": "unknown_from_state"},
                {"from_state": states[0], "to_state": "unknown_state", "expected": "invalid", "expected_error": "unknown_to_state"},
            ],
        }
    fixtures["contracts/fixtures/api/mutation-policy.json"] = json_artifact(
        {
            "fixture_version": SCHEMA_VERSION,
            "required_extension": "x-jumpship-policy",
            "required_mutation_fields": [
                "authorization",
                "allowed_audiences",
                "browser_only",
                "coding_agent_denied",
                "idempotency",
                "audit",
                "concurrency",
                "stable_errors",
                "data_class",
                "max_request_bytes",
            ],
            "browser_only_denials": [
                {"operation_id": "confirmConsent", "audience": "jumpship-coding-agent", "expected_code": "browser_interaction_required"},
                {"operation_id": "recordCustomerValidation", "audience": "jumpship-application-writer", "expected_code": "browser_interaction_required"},
                {"operation_id": "putMongoDBCredential", "audience": "jumpship-cli-human", "expected_code": "browser_interaction_required"},
                {"operation_id": "requestApplicationWriterGrant", "audience": "jumpship-browser", "expected_code": "audience_not_allowed"},
            ],
            "forbidden_operation_ids": ["mergePullRequest", "deployApplication", "setTrafficAuthority", "activateRelease"],
        },
        "application/json",
    )
    fixtures["contracts/fixtures/api/invalid-mutation-policy.json"] = json_artifact(
        {
            "fixture_version": SCHEMA_VERSION,
            "case_id": "mutation-missing-audience-and-idempotency",
            "operation": {"operationId": "unsafeMutation", "x-jumpship-policy": {"audit": {"required": False}}},
            "expected_valid": False,
            "expected_errors": ["missing_allowed_audiences", "missing_idempotency", "audit_required", "missing_concurrency", "missing_stable_errors"],
        },
        "application/json",
    )
    boundary_actions: dict[str, dict[str, Any]] = {
        "putMongoDBCredential": {"reversibility_class": "closes_on_first_external_exposure", "warning_rule": "before_secret_intake", "safe_failure": "do_not_store_or_log"},
        "completeConnectorOAuth": {"reversibility_class": "closes_on_first_external_exposure", "warning_rule": "before_provider_grant_activation", "safe_failure": "leave_grant_pending"},
        "dispatchExternalReview": {"reversibility_class": "closes_on_first_external_exposure", "warning_rule": "before_external_reviewer_dispatch", "safe_failure": "do_not_dispatch"},
        "requestArtifactAccess": {"reversibility_class": "closes_on_first_external_exposure", "warning_rule": "before_capability_issuance", "safe_failure": "issue_no_capability"},
        "confirmConsent": {"reversibility_class": "never_reversible", "warning_rule": "typed_phrase_and_webauthn_before_confirmation", "safe_failure": "leave_consent_unexecuted"},
        "revokeWebAuthnCredential": {"reversibility_class": "expensive_after_cutover", "warning_rule": "before_last_credential_revocation", "safe_failure": "retain_current_credential"},
        "removeWorkspaceMember": {"reversibility_class": "expensive_after_cutover", "warning_rule": "before_access_revocation", "safe_failure": "retain_current_membership"},
        "disconnectConnector": {"reversibility_class": "expensive_after_cutover", "warning_rule": "before_connector_revocation", "safe_failure": "retain_current_connector"},
        "resolveDecision": {"reversibility_class": "request_bound_five_class", "warning_rule": "from_request_reversibility_and_closure", "safe_failure": "leave_decision_open"},
        "requestOperation": {"reversibility_class": "descriptor_and_request_bound", "warning_rule": "from_tool_descriptor_and_operation_contract", "safe_failure": "grant_no_effect_authority"},
        "requestPhaseTransition": {"reversibility_class": "transition_bound", "warning_rule": "from_target_phase_and_current_closure", "safe_failure": "retain_current_phase"},
        "abortMigration": {"reversibility_class": "request_mode_bound", "warning_rule": "before_abort_cleanup_authorization", "safe_failure": "retain_current_migration_state"},
    }
    endpoint_inventory = []
    for endpoint in _endpoints():
        boundary = boundary_actions.get(endpoint["operation_id"])
        endpoint_inventory.append(
            {
                "operation_id": endpoint["operation_id"],
                "method": endpoint["method"].upper(),
                "path": endpoint["path"],
                "coverage_disposition": "boundary_classified" if boundary else "not_irreversible_or_clock_exposure_closing",
                **(boundary or {"reason": "Operation has no irreversible effect and does not close a clock or first-exposure boundary."}),
            }
        )
    fixtures["contracts/fixtures/core/reversibility-taxonomy-coverage.json"] = json_artifact(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "reversibility-taxonomy-coverage-report",
            "coverage_status": "complete",
            "openapi_operation_count": len(endpoint_inventory),
            "openapi_operations": endpoint_inventory,
            "tool_descriptor_policy": {
                "coverage": "all_future_and_release_registered_descriptors",
                "closing_consequence_classes": ["closing_door", "irreversible_effect"],
                "required_fields": ["reversibility_class", "warning_rule", "safe_failure"],
                "inline_effect_authority": "forbidden",
            },
        },
        "application/json",
    )
    fixtures["contracts/fixtures/application/state-transitions.json"] = json_artifact(
        {
            "fixture_version": SCHEMA_VERSION,
            "machines": {
                "patch_set": {
                    **transition_partition(
                        ("planned", "generated", "sealed", "validated", "validation_degraded", "publishable", "published", "superseded", "failed"),
                        (
                            ("planned", "generated"),
                            ("generated", "sealed"),
                            ("sealed", "validated"),
                            ("sealed", "validation_degraded"),
                            ("validated", "publishable"),
                            ("validation_degraded", "publishable"),
                            ("publishable", "published"),
                            ("published", "superseded"),
                            ("planned", "failed"),
                            ("generated", "failed"),
                            ("sealed", "failed"),
                            ("validated", "failed"),
                            ("validation_degraded", "failed"),
                            ("publishable", "failed"),
                        ),
                    ),
                    "initial": "planned",
                    "terminal": ["superseded", "failed"],
                },
                "pull_request": {
                    **transition_partition(
                        ("opening", "open", "changes_requested", "customer_validated", "merged", "deployed", "runtime_proven", "stale_head", "stale_base", "closed_unmerged"),
                        (
                            ("opening", "open"),
                            ("opening", "closed_unmerged"),
                            ("open", "changes_requested"),
                            ("open", "customer_validated"),
                            ("open", "stale_head"),
                            ("open", "stale_base"),
                            ("open", "closed_unmerged"),
                            ("changes_requested", "open"),
                            ("changes_requested", "customer_validated"),
                            ("changes_requested", "stale_head"),
                            ("changes_requested", "stale_base"),
                            ("changes_requested", "closed_unmerged"),
                            ("customer_validated", "changes_requested"),
                            ("customer_validated", "merged"),
                            ("customer_validated", "stale_head"),
                            ("customer_validated", "stale_base"),
                            ("customer_validated", "closed_unmerged"),
                            ("merged", "deployed"),
                            ("deployed", "runtime_proven"),
                        ),
                    ),
                    "initial": "opening",
                    "invalidation": {"head_changed": ["customer_validated", "stale_head"]},
                },
                "external_review": {
                    **transition_partition(
                        ("unavailable", "configuration_required", "ready", "queued", "acknowledged", "reviewing", "findings", "no_blocking_findings", "failed", "timed_out", "superseded"),
                        (
                            ("unavailable", "ready"),
                            ("configuration_required", "ready"),
                            ("ready", "queued"),
                            ("queued", "acknowledged"),
                            ("queued", "failed"),
                            ("queued", "timed_out"),
                            ("queued", "superseded"),
                            ("acknowledged", "reviewing"),
                            ("acknowledged", "failed"),
                            ("acknowledged", "timed_out"),
                            ("acknowledged", "superseded"),
                            ("reviewing", "findings"),
                            ("reviewing", "no_blocking_findings"),
                            ("reviewing", "failed"),
                            ("reviewing", "timed_out"),
                            ("reviewing", "superseded"),
                            ("findings", "superseded"),
                            ("no_blocking_findings", "superseded"),
                        ),
                    ),
                    "initial": ["unavailable", "configuration_required", "ready"],
                    "never_authorizes": ["customer_validation", "merge", "deployment", "writer_authority"],
                },
                "writer_grant": {
                    **transition_partition(
                        ("reserved", "signed_dormant", "active", "revoked", "expired", "tombstoned"),
                        (
                            ("reserved", "signed_dormant"),
                            ("reserved", "expired"),
                            ("reserved", "tombstoned"),
                            ("signed_dormant", "active"),
                            ("signed_dormant", "revoked"),
                            ("signed_dormant", "expired"),
                            ("active", "revoked"),
                            ("active", "expired"),
                            ("revoked", "tombstoned"),
                            ("expired", "tombstoned"),
                        ),
                    ),
                    "activation_requires": ["current_application_authority_epoch", "exact_workload_identity", "build_config_match", "provider_gate_receipt", "encrypted_envelope_hash", "next_cohort_generation"],
                },
                "writer_control": {
                    **transition_partition(
                        ("source_enabled", "freezing", "fenced", "target_pending", "target_enabled", "revoking", "target_fenced", "source_pending", "source_resumed", "tombstoned", "blocked"),
                        (
                            ("source_enabled", "freezing"),
                            ("freezing", "fenced"),
                            ("freezing", "blocked"),
                            ("fenced", "target_pending"),
                            ("fenced", "blocked"),
                            ("target_pending", "target_enabled"),
                            ("target_pending", "blocked"),
                            ("target_enabled", "revoking"),
                            ("target_enabled", "blocked"),
                            ("revoking", "target_fenced"),
                            ("revoking", "tombstoned"),
                            ("revoking", "blocked"),
                            ("target_fenced", "source_pending"),
                            ("target_fenced", "blocked"),
                            ("source_pending", "source_resumed"),
                            ("source_pending", "blocked"),
                        ),
                    ),
                    "authority_by_state": {
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
                    "rollback_requires": ["target_provider_denial", "fresh_source_resume_stream", "fresh_source_grant_generation", "source_provider_gate", "source_activation_receipt"],
                    "epoch_dimensions": ["application_authority_epoch", "cell_write_epoch", "cohort_generation"],
                },
            },
        },
        "application/json",
    )
    fixtures["contracts/fixtures/application/valid-writer-grant.json"] = json_artifact(
        {
            "schema_path": "contracts/application/application-writer-grant.schema.json",
            "expected_valid": True,
            "instance": {
                "schema_version": SCHEMA_VERSION,
                "grant_id": uid,
                "purpose": "application_writer_grant",
                "workspace_id": uid,
                "migration_id": uid2,
                "writer_id": uid,
                "cohort_id": uid2,
                "deploy_unit_id": uid,
                "workload_identity_hash": zero,
                "build_digest": one,
                "artifact_digest": zero,
                "config_digest": one,
                "environment": "production",
                "store": "target",
                "application_authority_epoch": 4,
                "reserved_cohort_generation": 8,
                "credential_generation": 3,
                "audience": "jumpship-application-writer",
                "state": "signed_dormant",
                "encrypted_credential_envelope_hash": zero,
                "not_before": "2026-07-18T00:00:00Z",
                "expires_at": "2026-07-18T00:15:00Z",
                "nonce": "abcdefghijklmnopqrstuvwxyzABCDEF0123456789_-",
                "payload_hash": one,
                "signature_envelope_hash": zero,
            },
        },
        "application/json",
    )
    fixtures["contracts/fixtures/application/invalid-writer-grant.json"] = json_artifact(
        {
            "schema_path": "contracts/application/application-writer-grant.schema.json",
            "expected_valid": False,
            "expected_errors": ["wrong_audience", "stale_generation", "unknown_property"],
            "instance_patch": {"audience": "jumpship-coding-agent", "reserved_cohort_generation": 0, "plaintext_database_password": "forbidden"},
        },
        "application/json",
    )
    fixtures["contracts/fixtures/events/valid-session-event.json"] = json_artifact(
        {
            "schema_path": "contracts/events/session-event.schema.json",
            "expected_valid": True,
            "instance": {
                "schema_version": SCHEMA_VERSION,
                "event_id": uid,
                "migration_id": uid2,
                "conversation_id": uid,
                "migration_sequence": 7,
                "event_type": "migration.phase_changed",
                "actor": {"type": "service", "id": "control-api"},
                "occurred_at": "2026-07-18T00:00:00Z",
                "recorded_at": "2026-07-18T00:00:01Z",
                "effective_at": "2026-07-18T00:00:00Z",
                "phase": "discovery",
                "causation_id": uid,
                "correlation_id": uid2,
                "run_id": None,
                "iteration_sequence": None,
                "operation_id": None,
                "decision_id": None,
                "evidence_refs": [],
                "safe_summary": "Discovery started after connector readiness was proven.",
                "trace_id": "1" * 32,
                "payload": {
                    "resource_id": uid2,
                    "resource_version": 3,
                    "projection_root": zero,
                    "safe_status": "discovery",
                    "progress_percent": None,
                },
                "links": [],
            },
        },
        "application/json",
    )
    fixtures["contracts/fixtures/events/invalid-session-event.json"] = json_artifact(
        {
            "schema_path": "contracts/events/session-event.schema.json",
            "expected_valid": False,
            "expected_errors": ["raw_payload_forbidden"],
            "instance_patch": {"event_type": "model.summary", "raw_payload": {"secret": "forbidden"}},
        },
        "application/json",
    )
    fixtures["contracts/fixtures/events/valid-unknown-session-event.json"] = json_artifact(
        {
            "schema_path": "contracts/events/session-event.schema.json",
            "expected_valid": True,
            "instance_patch_from": "contracts/fixtures/events/valid-session-event.json",
            "instance_patch": {
                "event_type": "future.safe_projection",
                "safe_summary": "Unsupported event type; refetch the canonical projection.",
            },
            "expected_client_behavior": "visible_unsupported_then_refetch",
        },
        "application/json",
    )
    fixtures["contracts/fixtures/client/local-broker-denials.json"] = json_artifact(
        {
            "fixture_version": SCHEMA_VERSION,
            "cases": [
                {"case_id": "coding-agent-browser-ceremony", "audience": "jumpship-coding-agent", "method": "browser_ceremony.create", "expected": "audience_not_allowed"},
                {"case_id": "peer-uid-mismatch", "peer_uid": 501, "socket_owner_uid": 502, "expected": "peer_identity_mismatch"},
                {"case_id": "handle-replay", "handle_state": "consumed", "expected": "capability_handle_replayed"},
                {"case_id": "bearer-field", "extra_property": "access_token", "expected": "unknown_property"},
            ],
        },
        "application/json",
    )
    fixtures["contracts/fixtures/client/valid-local-broker-frame.json"] = json_artifact(
        {
            "schema_path": "contracts/client/local-broker.schema.json",
            "expected_valid": True,
            "instance": {
                "schema_version": SCHEMA_VERSION,
                "protocol_version": "1.0.0",
                "frame_type": "request",
                "request_id": uid,
                "client_audience": "jumpship-coding-agent",
                "peer_uid": 501,
                "method": "api.read",
                "capability_handle": "jlc_abcdefghijklmnopqrstuvwxyzABCDEF0123456789_-",
                "scope_hash": zero,
                "request_payload_hash": one,
                "safe_response_hash": None,
                "receipt_id": None,
                "error_code": None,
                "expires_at": "2026-07-18T00:05:00Z",
            },
        },
        "application/json",
    )
    fixtures["contracts/fixtures/client/invalid-coding-agent-ceremony.json"] = json_artifact(
        {
            "schema_path": "contracts/client/local-broker.schema.json",
            "expected_valid": False,
            "instance_patch_from": "contracts/fixtures/client/valid-local-broker-frame.json",
            "instance_patch": {"method": "browser_ceremony.create"},
            "expected_errors": ["coding_agent_ceremony_denied"],
        },
        "application/json",
    )
    catalog_instance = content_identity(
        {
            "schema_version": SCHEMA_VERSION,
            "selection_mode": "new_admission_release",
            "release_unit_id": "2" * 64,
            "release_unit_hash": "2" * 64,
            "source_registry_hash": "3" * 64,
            "sort_order": "capability_id_then_incapability_id",
            "migration_id": None,
            "release_evidence_chain": ["4" * 64],
            "items": [
                {
                    "capability_id": "MVP-CAP-APPLICATION-ADAPTATION",
                    "incapability_id": "cannot-customer-validate",
                    "operation_id": "recordCustomerValidation",
                    "reason_code": "human-validation-required",
                    "safe_explanation": "Jumpship cannot perform customer-owned validation.",
                    "safe_remediation": "A customer operator validates the proposed application change.",
                    "required_human_surface": "browser",
                    "coding_agent_denied": True,
                    "structural_denial_contract_ids": ["browser-ceremony-human-principal"],
                    "negative_test_receipt_hashes": ["5" * 64],
                },
                {
                    "capability_id": "MVP-CAP-PR-DELIVERY",
                    "incapability_id": "cannot-merge",
                    "operation_id": "mergePullRequest",
                    "reason_code": "customer-authority-required",
                    "safe_explanation": "Jumpship can publish a draft pull request but cannot merge it.",
                    "safe_remediation": "An authorized customer operator reviews and merges the pull request.",
                    "required_human_surface": "unavailable",
                    "coding_agent_denied": True,
                    "structural_denial_contract_ids": ["openapi-forbidden-public-operation"],
                    "negative_test_receipt_hashes": ["6" * 64],
                },
            ],
            "issued_at": "2026-07-18T00:00:00Z",
        },
        object_type="customer_incapability_catalog",
        id_field="catalog_id",
        equivalent_digest_fields=("catalog_hash",),
    )
    fixtures["contracts/fixtures/client/valid-customer-incapability-catalog.json"] = json_artifact(
        {
            "schema_path": "contracts/client/customer-incapability-catalog.schema.json",
            "expected_valid": True,
            "instance": catalog_instance,
        },
        "application/json",
    )
    fixtures["contracts/fixtures/auth/deployed-config-denials.json"] = json_artifact(
        {
            "schema_path": "contracts/auth/deployed-auth-config.schema.json",
            "fixture_version": SCHEMA_VERSION,
            "cases": [
                {"case_id": "secret-material", "extra_property": "client_secret", "expected": "unknown_property"},
                {"case_id": "live-jwks", "extra_property": "jwks", "expected": "unknown_property"},
                {"case_id": "incomplete-route-set", "remove": "route_tuples", "expected": "required_property"},
                {"case_id": "handoff-too-long", "patch": {"handoff_expiry_seconds": 61}, "expected": "maximum"},
            ],
        },
        "application/json",
    )
    auth_route = {
        "host_role": "api",
        "method": "POST",
        "path_template": "/v1/auth/oauth/complete",
        "route_build_digest": zero,
        "body_policy": "form_redacted",
        "access_logs": "enabled_redacted",
        "csrf_exempt": True,
        "origin_policy_hash": one,
    }
    callback_route = {
        "host_role": "auth_callback",
        "method": "POST",
        "path_template": "/v1/auth/oauth/{provider}/prepare",
        "route_build_digest": one,
        "body_policy": "form_redacted",
        "access_logs": "disabled",
        "csrf_exempt": True,
        "origin_policy_hash": zero,
    }
    internal_route = {
        "host_role": "cell_control",
        "method": "POST",
        "path_template": "/v1/internal/cell-certificates/bootstrap/request",
        "route_build_digest": zero,
        "body_policy": "suppressed_binary",
        "access_logs": "disabled",
        "csrf_exempt": True,
        "origin_policy_hash": one,
    }
    browser_sensitive_route = {
        **auth_route,
        "path_template": "/v1/invitations/accept",
        "body_policy": "json",
        "csrf_exempt": False,
    }
    identity_start_route = {
        **auth_route,
        "path_template": "/v1/auth/oauth/{provider}/start",
        "body_policy": "json",
    }
    identity_callback_route = {
        **callback_route,
        "method": "GET",
        "path_template": "/v1/auth/oauth/{provider}/callback",
        "body_policy": "none",
    }
    connector_prepare_route = {
        **callback_route,
        "host_role": "connector_callback",
        "path_template": "/v1/connectors/{kind}/oauth/prepare",
    }
    connector_callback_route = {
        **connector_prepare_route,
        "method": "GET",
        "path_template": "/v1/connectors/{kind}/callback",
        "body_policy": "none",
    }
    connector_complete_route = {
        **auth_route,
        "path_template": "/v1/connectors/oauth/complete",
    }
    fixtures["contracts/fixtures/auth/valid-deployed-config.json"] = json_artifact(
        {
            "schema_path": "contracts/auth/deployed-auth-config.schema.json",
            "expected_valid": True,
            "instance": {
                "schema_version": SCHEMA_VERSION,
                "environment": "production",
                "release_unit_id": "2" * 64,
                "domain_policy_version": "1.0.0",
                "domain_policy_hash": one,
                "application_host": "app.example.com",
                "api_host": "api.example.com",
                "auth_callback_host": "auth-callback.example.com",
                "connector_callback_host": "auth-callback.example.com",
                "cell_control_host": "cell-control.example.com",
                "allowed_origins": ["https://app.example.com"],
                "providers": [
                    {"provider": "google", "client_id_hash": zero, "discovery_url_hash": one, "scope_set_hash": zero, "redirect_uri_hash": one, "pkce_method": "S256"},
                    {"provider": "github", "client_id_hash": one, "discovery_url_hash": zero, "scope_set_hash": one, "redirect_uri_hash": zero, "pkce_method": "S256"},
                ],
                "route_tuples": [identity_start_route, callback_route, identity_callback_route, auth_route, connector_prepare_route, connector_callback_route, connector_complete_route, internal_route, {**internal_route, "path_template": "/v1/internal/cell-certificates/bootstrap/complete"}],
                "route_digest": zero,
                "cookies": [
                    {"name": "__Host-js_session", "host_role": "api", "domain_scope": "host_only", "authoritative": True, "secure": True, "http_only": True, "same_site": "Lax", "path": "/", "max_age_seconds": 604800},
                    {"name": "__Host-js_oauth_start", "host_role": "api", "domain_scope": "host_only", "authoritative": False, "secure": True, "http_only": True, "same_site": "Lax", "path": "/", "max_age_seconds": 600},
                    {"name": "__Host-js_oauth_callback", "host_role": "auth_callback", "domain_scope": "host_only", "authoritative": False, "secure": True, "http_only": True, "same_site": "Lax", "path": "/", "max_age_seconds": 600},
                    {"name": "__Secure-js_present", "host_role": "presentation", "domain_scope": "parent_domain", "authoritative": False, "secure": True, "http_only": True, "same_site": "Lax", "path": "/", "max_age_seconds": 300},
                ],
                "session_idle_seconds": 43200,
                "session_absolute_seconds": 604800,
                "session_touch_interval_seconds": 300,
                "cors_policy_hash": zero,
                "cors_allow_credentials": True,
                "cors_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                "cors_headers": ["Content-Type", "X-CSRF-Token", "Idempotency-Key", "If-Match", "X-Request-ID", "traceparent"],
                "csrf_policy_hash": one,
                "csrf_token_transport": "synchronizer_header",
                "csrf_header_name": "X-CSRF-Token",
                "csrf_session_binding": "session_id_and_route_class",
                "csrf_storage": "page_memory_only",
                "csrf_route_classes": ["ordinary_mutation", "security_sensitive_mutation", "credential_intake", "consent_execution"],
                "csrf_exempt_operation_ids": ["startIdentityOAuth", "prepareIdentityOAuthCallback", "consumeIdentityOAuthCallback", "completeIdentityOAuth", "prepareConnectorOAuthCallback", "consumeConnectorOAuthCallback", "completeConnectorOAuth"],
                "session_policy_hash": zero,
                "presentation_jwks_policy_hash": one,
                "presentation_jwks_url": "https://api.example.com/v1/auth/jwks.json",
                "presentation_jwks_cache_max_seconds": 300,
                "presentation_rotation_cadence": "monthly",
                "presentation_key_overlap_seconds": 604800,
                "presentation_issuer_hash": zero,
                "presentation_audience": "jumpship-presentation",
                "presentation_purpose": "route_shaping_only",
                "presentation_algorithms": ["ES256"],
                "presentation_payload_max_age_seconds": 300,
                "presentation_unknown_kid_behavior": "fail_closed",
                "handoff_expiry_seconds": 60,
                "handoff_binding_schema_hash": zero,
                "interstitial_csp_hash": one,
                "interstitial_script_hash": zero,
                "interstitial_form_action_hash": one,
                "referrer_policy": "no-referrer",
                "webauthn_rp_id": "example.com",
                "webauthn_origins": ["https://app.example.com"],
                "webauthn_user_verification": "required",
                "webauthn_attestation": "none",
                "webauthn_resident_key": "preferred",
                "webauthn_algorithm_policy_hash": zero,
                "webauthn_challenge_policy_hash": one,
                "listener_rule_digest": zero,
                "waf_redaction_policy_hash": one,
                "telemetry_suppression_policy_hash": zero,
                "main_host_callback_denial_hash": one,
                "sensitive_body_routes": [
                    callback_route,
                    auth_route,
                    connector_prepare_route,
                    connector_complete_route,
                    {**browser_sensitive_route, "method": "PUT", "path_template": "/v1/workspaces/{workspace_id}/migrations/{migration_id}/connectors/mongodb/credential"},
                    browser_sensitive_route,
                    {**browser_sensitive_route, "path_template": "/v1/auth/device/authorizations/approve"},
                    {**browser_sensitive_route, "path_template": "/v1/auth/device/token"},
                    {**browser_sensitive_route, "path_template": "/v1/auth/webauthn/registration/options"},
                    {**browser_sensitive_route, "path_template": "/v1/auth/webauthn/registration/verify"},
                    {**browser_sensitive_route, "path_template": "/v1/cli/browser-ceremonies/{ceremony_id}/decision"},
                    {**browser_sensitive_route, "path_template": "/v1/workspaces/{workspace_id}/migrations/{migration_id}/consents/{consent_kind}/confirm"},
                    internal_route,
                    {**internal_route, "path_template": "/v1/internal/cell-certificates/bootstrap/complete"},
                ],
                "body_inspection_exclusion_hash": zero,
                "handler_compensation_policy_hash": one,
                "config_hash": zero,
            },
        },
        "application/json",
    )
    fixtures["contracts/fixtures/cell/protocol-policy.json"] = json_artifact(
        {
            "fixture_version": SCHEMA_VERSION,
            "required_services": {"SupervisorControl.Connect": "bidirectional_stream", "CellCertificateRecovery.Renew": "unary_no_authority"},
            "required_context_fields": ["workspace_id", "migration_id", "cell_id", "cell_generation", "control_region_epoch", "target_write_epoch", "protocol_version", "sequence", "causation_id", "correlation_id", "trace_id", "signature_envelope_hash", "channel_binding_hash"],
            "renew_allowed_response_fields": ["context", "request_id", "poll_secret", "poll_secret_hash", "expires_at", "recovery_receipt_root"],
            "renew_forbidden_authority": ["command", "operation_grant", "credential_lease", "stream_token", "traffic_authority"],
        },
        "application/json",
    )
    fixtures["contracts/fixtures/cell/recovery-renew-cases.json"] = json_artifact(
        {
            "fixture_version": SCHEMA_VERSION,
            "valid": {
                "prior_epoch": 8,
                "current_epoch": 9,
                "leaf_state": "unexpired_unrevoked",
                "manifest_state": "activated",
                "old_serial_use": "unused",
                "response_authority": "poll_only",
            },
            "invalid": [
                {"case_id": "expired-leaf", "leaf_state": "expired", "expected": "prior_leaf_invalid"},
                {"case_id": "replayed-serial", "old_serial_use": "consumed", "expected": "recovery_replayed"},
                {"case_id": "changed-csr-retry", "same_request": True, "csr_changed": True, "expected": "recovery_binding_mismatch"},
                {"case_id": "stream-with-prior-epoch", "rpc": "SupervisorControl.Connect", "certificate_epoch": 8, "current_epoch": 9, "expected": "control_epoch_stale"},
            ],
        },
        "application/json",
    )
    return fixtures


def artifacts() -> dict[str, Artifact]:
    """Return every API/application-owned P02 artifact."""

    result: dict[str, Artifact] = {}
    schemas = _application_schemas()
    schemas["contracts/auth/deployed-auth-config.schema.json"] = _auth_schema()
    schemas.update(_client_schemas())
    schemas["contracts/events/session-event.schema.json"] = _session_event_schema()
    for path, document in schemas.items():
        result[path] = json_artifact(document)
    result["contracts/openapi/openapi.yaml"] = json_artifact(_openapi(), "application/vnd.oai.openapi+json")
    result["contracts/proto/jumpship/cell/v1/cell.proto"] = text_artifact(_CELL_PROTO, "text/x-protobuf")
    result.update(_fixtures())
    return result
