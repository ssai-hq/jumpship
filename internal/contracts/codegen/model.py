"""Shared builders for the P02 contract generator.

The checked-in JSON Schema and protocol artifacts are generated from small,
reviewable Python declarations.  This module intentionally uses only the
standard library so a clean clone can reproduce P02 without hidden tooling.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
CONTRACT_BASE = "https://jumpship.dev/contracts/"
GENERATOR = "internal/contracts/codegen/generate.py"
SCHEMA_VERSION = "1.0.0"
DATA_CLASSES = (
    "public",
    "internal_operational",
    "identity_tenant",
    "shared_migration",
    "restricted_customer",
    "credential_secret",
    "security_material",
)
HASH_PATTERN = "^[0-9a-f]{64}$"
UUID_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
SEMVER_PATTERN = r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$"
RFC3339_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"


@dataclass(frozen=True)
class Artifact:
    """One deterministic repository artifact."""

    content: bytes
    media_type: str


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def json_artifact(value: Any, media_type: str = "application/schema+json") -> Artifact:
    return Artifact(json_bytes(value), media_type)


def text_artifact(value: str, media_type: str = "text/plain") -> Artifact:
    if not value.endswith("\n"):
        value += "\n"
    return Artifact(value.encode("utf-8"), media_type)


def s_string(
    *,
    enum: list[str] | tuple[str, ...] | None = None,
    const: str | None = None,
    pattern: str | None = None,
    fmt: str | None = None,
    min_length: int | None = None,
    max_length: int | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "string"}
    if enum is not None:
        result["enum"] = list(enum)
    if const is not None:
        result["const"] = const
    if pattern is not None:
        result["pattern"] = pattern
    if fmt is not None:
        result["format"] = fmt
    if min_length is not None:
        result["minLength"] = min_length
    if max_length is not None:
        result["maxLength"] = max_length
    if description is not None:
        result["description"] = description
    return result


def s_integer(*, minimum: int | None = None, maximum: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "integer"}
    if minimum is not None:
        result["minimum"] = minimum
    if maximum is not None:
        result["maximum"] = maximum
    return result


def s_number(*, minimum: float | None = None, maximum: float | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "number"}
    if minimum is not None:
        result["minimum"] = minimum
    if maximum is not None:
        result["maximum"] = maximum
    return result


def s_boolean() -> dict[str, Any]:
    return {"type": "boolean"}


def s_array(
    items: dict[str, Any],
    *,
    min_items: int = 0,
    max_items: int = 256,
    unique: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "array",
        "items": items,
        "minItems": min_items,
        "maxItems": max_items,
    }
    if unique:
        result["uniqueItems"] = True
    return result


def s_object(
    properties: dict[str, Any],
    required: list[str] | tuple[str, ...],
    *,
    additional: bool = False,
) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": additional,
        "required": list(required),
        "properties": properties,
    }


def nullable(value: dict[str, Any]) -> dict[str, Any]:
    return {"anyOf": [value, {"type": "null"}]}


def ref(path: str) -> dict[str, Any]:
    return {"$ref": f"{CONTRACT_BASE}{path}"}


def schema(
    path: str,
    title: str,
    properties: dict[str, Any],
    required: list[str] | tuple[str, ...],
    *,
    data_class: str,
    max_bytes: int,
    flow_ids: list[str] | tuple[str, ...],
    description: str,
    all_of: list[dict[str, Any]] | None = None,
    definitions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not path.endswith(".schema.json"):
        raise ValueError(f"schema path must end in .schema.json: {path}")
    if data_class not in DATA_CLASSES:
        raise ValueError(f"unknown data class {data_class!r}")
    if not flow_ids or any(re.fullmatch(r"F(?:0[1-9]|1[0-9]|2[0-8])", value) is None for value in flow_ids):
        raise ValueError(f"invalid flow IDs for {path}: {flow_ids!r}")
    all_properties = {"schema_version": {"const": SCHEMA_VERSION}, **properties}
    document: dict[str, Any] = {
        "$schema": SCHEMA_DIALECT,
        "$id": f"{CONTRACT_BASE}{path}",
        "title": title,
        "description": description,
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", *required],
        "properties": all_properties,
        "x-generated-by": GENERATOR,
        "x-jumpship-data-class": data_class,
        "x-jumpship-flow-ids": list(flow_ids),
        "x-jumpship-max-bytes": max_bytes,
        "x-jumpship-compatibility": "additive-with-versioned-breaking-change",
    }
    if all_of:
        document["allOf"] = all_of
    if definitions:
        document["$defs"] = definitions
    return document


def common_identity_properties(*, include_operation: bool = False) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "workspace_id": s_string(pattern=UUID_PATTERN),
        "migration_id": s_string(pattern=UUID_PATTERN),
        "cell_id": s_string(pattern=UUID_PATTERN),
        "cell_generation": s_integer(minimum=1),
        "causation_id": s_string(pattern=UUID_PATTERN),
        "correlation_id": s_string(pattern=UUID_PATTERN),
    }
    if include_operation:
        fields["operation_id"] = s_string(pattern=UUID_PATTERN)
    return fields


def hash_field() -> dict[str, Any]:
    return s_string(pattern=HASH_PATTERN)


def timestamp_field() -> dict[str, Any]:
    return s_string(pattern=RFC3339_PATTERN, fmt="date-time")
