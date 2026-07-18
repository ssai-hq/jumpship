#!/usr/bin/env python3
"""Generate all P02 contract artifacts with the pinned repository toolchain."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from model import Artifact, GENERATOR, json_artifact, json_bytes, text_artifact


REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_TESTS = REPO_ROOT / "internal/contracts/tests"
sys.path.insert(0, str(CONTRACT_TESTS))
from schema_validator import (  # noqa: E402 - repository root is resolved above
    Registry as StrictSchemaRegistry,
    ValidationError as StrictSchemaValidationError,
    validate as strict_schema_validate,
)

ALLOWED_PREFIXES = (
    "contracts/",
    "internal/contracts/",
    "web/src/lib/api/generated/",
)
COMPATIBILITY_BASELINE_PATH = "contracts/compatibility-baseline.json"
COMPATIBILITY_REPORT_PATH = "contracts/compatibility-report.json"
SCHEMA_ANNOTATIONS = {
    "$comment",
    "$schema",
    "default",
    "deprecated",
    "description",
    "examples",
    "readOnly",
    "title",
    "writeOnly",
}
APPROVED_VERSIONED_SCHEMA_REPLACEMENTS = {
    "contracts/client/customer-incapability-catalog.schema.json": {
        "from": "1.0.0",
        "to": "2.0.0",
        "authority": "P02-CATALOG-RU-HASH-CYCLE",
    }
}
APPROVED_OPENAPI_COMPONENT_REPLACEMENTS = {
    "GetEnvironmentAgentIncapabilitiesResponse": "P02-CATALOG-RU-HASH-CYCLE",
    "GetMigrationAgentIncapabilitiesResponse": "P02-CATALOG-RU-HASH-CYCLE",
}


def _type_name(title: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", " ", title)
    name = "".join(part[:1].upper() + part[1:] for part in value.split())
    if not name or name[0].isdigit():
        name = "Contract" + name
    return name


def _go_field_name(name: str) -> str:
    result = _type_name(name)
    replacements = {"Id": "ID", "Ids": "IDs", "Uri": "URI", "Url": "URL", "Sha256": "SHA256"}
    for source, target in replacements.items():
        if result.endswith(source):
            result = result[: -len(source)] + target
    return result


def _resolve_schema_ref(
    reference: str,
    registry: dict[str, dict[str, Any]],
    root: dict[str, Any],
) -> tuple[dict[str, Any], str | None]:
    base, marker, fragment = reference.partition("#")
    document = registry.get(base) if base else root
    if document is None:
        raise ValueError(f"unknown generated schema reference {reference!r}")
    target: Any = document
    if marker and fragment:
        if not fragment.startswith("/"):
            raise ValueError(f"unsupported generated schema fragment {reference!r}")
        for token in fragment[1:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            target = target[token]
    if not isinstance(target, dict):
        raise ValueError(f"generated schema reference is not an object {reference!r}")
    type_name = _type_name(document["title"]) if target is document and "title" in document else None
    return target, type_name


def _nullable_schema(spec: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    variants = spec.get("anyOf")
    if isinstance(variants, list):
        non_null = [variant for variant in variants if variant.get("type") != "null"]
        if len(non_null) == 1 and len(non_null) != len(variants):
            return non_null[0], True
    kinds = spec.get("type")
    if isinstance(kinds, list) and "null" in kinds and len(kinds) == 2:
        return {**spec, "type": next(kind for kind in kinds if kind != "null")}, True
    return spec, False


def _optional_go_type(base: str, required: bool, nullable: bool) -> str:
    if required and not nullable:
        return base
    if base.startswith(("[]", "map[")) or base == "json.RawMessage":
        return base
    return "*" + base


def _go_type(
    spec: dict[str, Any],
    required: bool,
    registry: dict[str, dict[str, Any]],
    root: dict[str, Any],
    depth: int = 1,
) -> str:
    spec, nullable = _nullable_schema(spec)
    if "$ref" in spec:
        target, type_name = _resolve_schema_ref(str(spec["$ref"]), registry, root)
        if type_name is not None:
            return _optional_go_type(type_name, required, nullable)
        return _go_type(target, required and not nullable, registry, root, depth)
    has_structural_type = (
        "type" in spec or "properties" in spec or "items" in spec
    )
    if not has_structural_type and (
        "oneOf" in spec or "anyOf" in spec or "allOf" in spec
    ):
        return "json.RawMessage"
    kind = spec.get("type")
    if kind == "string":
        base = "string"
    elif kind == "integer":
        base = "int64"
    elif kind == "number":
        base = "float64"
    elif kind == "boolean":
        base = "bool"
    elif kind == "array":
        item = _go_type(spec.get("items", {}), True, registry, root, depth).removeprefix("*")
        base = "[]" + item
    elif kind == "object" or "properties" in spec:
        properties = spec.get("properties", {})
        additional = spec.get("additionalProperties", False)
        if not properties and isinstance(additional, dict):
            value_type = _go_type(additional, True, registry, root, depth).removeprefix("*")
            base = f"map[string]{value_type}"
        elif properties and additional is not False:
            base = "json.RawMessage"
        else:
            nested_required = set(spec.get("required", []))
            prefix = "\t" * (depth + 1)
            closing = "\t" * depth
            fields = []
            for field, child in properties.items():
                child_required = field in nested_required
                child_type = _go_type(child, child_required, registry, root, depth + 1)
                suffix = "" if child_required else ",omitempty"
                fields.append(f"{prefix}{_go_field_name(field)} {child_type} `json:\"{field}{suffix}\"`")
            base = "struct {\n" + "\n".join(fields) + f"\n{closing}}}"
    elif "const" in spec or "enum" in spec:
        values = [spec["const"]] if "const" in spec else spec["enum"]
        if values and all(isinstance(value, bool) for value in values):
            base = "bool"
        elif values and all(isinstance(value, int) and not isinstance(value, bool) for value in values):
            base = "int64"
        elif values and all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in values):
            base = "float64"
        else:
            base = "string"
    else:
        base = "json.RawMessage"
    return _optional_go_type(base, required, nullable)


def _ts_property_name(value: str) -> str:
    return value if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value) else json.dumps(value)


def _ts_type(
    spec: dict[str, Any],
    registry: dict[str, dict[str, Any]],
    root: dict[str, Any],
) -> str:
    spec, nullable = _nullable_schema(spec)
    if "$ref" in spec:
        target, type_name = _resolve_schema_ref(str(spec["$ref"]), registry, root)
        base = type_name if type_name is not None else _ts_type(target, registry, root)
    elif "const" in spec:
        base = json.dumps(spec["const"], ensure_ascii=False)
    elif isinstance(spec.get("enum"), list):
        base = " | ".join(json.dumps(item, ensure_ascii=False) for item in spec["enum"])
    elif "oneOf" in spec and not (
        "type" in spec or "properties" in spec or "items" in spec
    ):
        base = " | ".join(f"({_ts_type(child, registry, root)})" for child in spec["oneOf"])
    elif "anyOf" in spec and not (
        "type" in spec or "properties" in spec or "items" in spec
    ):
        base = " | ".join(f"({_ts_type(child, registry, root)})" for child in spec["anyOf"])
    elif "allOf" in spec and not (
        "type" in spec or "properties" in spec or "items" in spec
    ):
        base = " & ".join(f"({_ts_type(child, registry, root)})" for child in spec["allOf"])
    else:
        kind = spec.get("type")
        if kind == "string":
            base = "string"
        elif kind in {"integer", "number"}:
            base = "number"
        elif kind == "boolean":
            base = "boolean"
        elif kind == "null":
            base = "null"
        elif kind == "array":
            base = f"ReadonlyArray<{_ts_type(spec.get('items', {}), registry, root)}>"
        elif kind == "object" or "properties" in spec:
            properties = spec.get("properties", {})
            required = set(spec.get("required", []))
            fields = [
                f"readonly {_ts_property_name(field)}{'' if field in required else '?'}: {_ts_type(child, registry, root)};"
                for field, child in properties.items()
            ]
            base = "{ " + " ".join(fields) + " }"
            additional = spec.get("additionalProperties", False)
            if isinstance(additional, dict):
                mapped = f"Readonly<Record<string, {_ts_type(additional, registry, root)}>>"
                base = f"({base} & {mapped})" if properties else mapped
        else:
            base = "unknown"
    return f"({base}) | null" if nullable else base


def render_generated_types(schemas: dict[str, dict[str, Any]]) -> dict[str, Artifact]:
    ordered = sorted(schemas.items())
    registry = {document["$id"]: document for document in schemas.values()}
    seen: set[str] = set()
    go_lines = [
        "// Code generated by internal/contracts/codegen/generate.py; DO NOT EDIT.",
        "// P02 schema-derived transport types. Domain policy does not belong here.",
        "package generated",
        "",
    ]
    canonical_go_lines = [
        "// Code generated by internal/contracts/codegen/generate.py; DO NOT EDIT.",
        "// Canonical verification DTOs generated from their frozen schemas.",
        "package canonical",
        "",
    ]
    ts_lines = [
        "// Code generated by internal/contracts/codegen/generate.py; DO NOT EDIT.",
        "// Sole browser-facing schema type source; do not handwrite duplicate DTOs.",
        "",
    ]
    inventory: list[dict[str, Any]] = []
    sanitized_lines = [
        "// Code generated by internal/contracts/codegen/generate.py; DO NOT EDIT.",
        "// This allowlisted type is the only trajectory shape permitted across the quality boundary.",
        "package sanitizedtrajectory",
        "",
    ]
    for path, document in ordered:
        name = _type_name(document["title"])
        if name in seen:
            raise ValueError(f"duplicate generated type name {name} from {path}")
        seen.add(name)
        required = set(document.get("required", []))
        properties = document.get("properties", {})
        canonical_contract = path in {
            "contracts/crypto/public-key-registry.schema.json",
            "contracts/crypto/signature-envelope.schema.json",
        }
        target_go_lines = canonical_go_lines if canonical_contract else go_lines
        signature_envelope = path == "contracts/crypto/signature-envelope.schema.json"
        if signature_envelope:
            claim_fields = {
                field: spec
                for field, spec in properties.items()
                if field not in {"envelope_id", "signature_base64"}
            }
            target_go_lines.extend(
                [
                    f"// SignatureClaims is the signed projection generated from {path}.",
                    "type SignatureClaims struct {",
                ]
            )
            for field, spec in claim_fields.items():
                target_go_lines.append(
                    f"\t{_go_field_name(field)} {_go_type(spec, field in required, registry, document)} `json:\"{field}{'' if field in required else ',omitempty'}\"`"
                )
            target_go_lines.extend(
                [
                    "}",
                    "",
                    f"// {name} is generated from {path}.",
                    f"type {name} struct {{",
                ]
            )
        else:
            target_go_lines.extend(
                [f"// {name} is generated from {path}.", f"type {name} struct {{"]
            )
        ts_lines.extend([f"/** Generated from {path}. */", f"export interface {name} {{"])
        for field, spec in properties.items():
            target_go_lines.append(
                f"\t{_go_field_name(field)} {_go_type(spec, field in required, registry, document)} `json:\"{field}{'' if field in required else ',omitempty'}\"`"
            )
            optional = "" if field in required else "?"
            ts_lines.append(f"  readonly {_ts_property_name(field)}{optional}: {_ts_type(spec, registry, document)};")
        target_go_lines.extend(["}", ""])
        ts_lines.extend(["}", ""])
        destinations = [
            (
                "internal/contracts/canonical/contract_types.gen.go"
                if canonical_contract
                else "internal/contracts/generated/types.gen.go"
            ),
            "web/src/lib/api/generated/contracts.gen.ts",
        ]
        if path == "contracts/agent/trajectory.schema.json":
            sanitized_name = "SanitizedTrajectory"
            sanitized_lines.extend([f"// {sanitized_name} is generated from {path}.", f"type {sanitized_name} struct {{"])
            for field, spec in properties.items():
                sanitized_lines.append(
                    f"\t{_go_field_name(field)} {_go_type(spec, field in required, registry, document)} `json:\"{field}{'' if field in required else ',omitempty'}\"`"
                )
            sanitized_lines.extend(["}", ""])
            destinations.append("internal/contracts/quality/sanitizedtrajectory/types.gen.go")
        inventory.append({"path": path, "type": name, "id": document["$id"], "destinations": destinations})
    if any("json.RawMessage" in line for line in go_lines):
        go_lines[4:4] = ['import "encoding/json"', ""]
    if any("json.RawMessage" in line for line in canonical_go_lines):
        canonical_go_lines[4:4] = ['import "encoding/json"', ""]
    if any("json.RawMessage" in line for line in sanitized_lines):
        sanitized_lines[4:4] = ['import "encoding/json"', ""]
    return {
        "internal/contracts/generated/types.gen.go": text_artifact("\n".join(go_lines), "text/x-go"),
        "internal/contracts/canonical/contract_types.gen.go": text_artifact(
            "\n".join(canonical_go_lines), "text/x-go"
        ),
        "web/src/lib/api/generated/contracts.gen.ts": text_artifact("\n".join(ts_lines), "text/typescript"),
        "internal/contracts/quality/sanitizedtrajectory/types.gen.go": text_artifact("\n".join(sanitized_lines), "text/x-go"),
        "contracts/generated-type-inventory.json": json_artifact(
            {
                "_generated": f"generated by {GENERATOR}; DO NOT EDIT",
                "schema_version": "1.0.0",
                "types": inventory,
            },
            "application/json",
        ),
    }


def _sample_string(spec: dict[str, Any]) -> str:
    if "const" in spec:
        return str(spec["const"])
    if spec.get("enum"):
        return str(spec["enum"][0])
    pattern = str(spec.get("pattern", ""))
    if pattern == "^[0-9a-f]{64}$":
        return "a" * 64
    if pattern == "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$":
        return "018f1234-5678-7abc-8def-0123456789ab"
    if spec.get("format") == "date-time" or "T[0-9]" in pattern:
        return "2026-07-18T01:00:00Z"
    if spec.get("format") == "uri" and not pattern:
        return "https://example.invalid/value"
    minimum = int(spec.get("minLength", 1))
    candidates = [
        "1.0.0",
        "1.0",
        "value",
        "us-east-1",
        "USD",
        "P00",
        "JSMVP-R001",
        "MVP-CAP-ARCHAEOLOGY",
        "jumpship.read",
        "https://jumpship.dev/contracts/agent/tool-receipt.schema.json",
        "https://example.invalid",
        "https://api.example.invalid/v1/auth/jwks.json",
        "/inputs/value",
        "/v1/workspaces/{workspace_id}",
        "2026-07-18",
        "01",
        "123456789012",
        "sha256:" + "a" * 64,
        "spiffe://jumpship/cells/018f1234-5678-7abc-8def-0123456789ab/generations/1",
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude3.sonnet:1",
        "cell-ca/crl/us-east-1/1/" + "a" * 64 + ".crl",
        "art_" + "A" * 16,
        "evh_" + "A" * 16,
        "jlc_" + "A" * 32,
        "/cli/ceremonies/018f1234-5678-7abc-8def-0123456789ab",
        "jumpship/mig-value/app-r1-value",
        "__Host-js_session",
        "A" * max(32, minimum),
        "A" * max(43, minimum),
        "A" * max(64, minimum),
        "a" * max(32, minimum),
        "a" * max(40, minimum),
        "-----BEGIN PUBLIC KEY-----" + "A" * 128 + "-----END PUBLIC KEY-----",
    ]
    for candidate in candidates:
        if len(candidate) < minimum or len(candidate) > int(spec.get("maxLength", 1_000_000)):
            continue
        try:
            if not pattern or re.fullmatch(pattern, candidate):
                return candidate
        except re.error as error:
            raise ValueError(f"invalid generated schema pattern {pattern!r}: {error}") from error
    raise ValueError(f"cannot synthesize fixture string for pattern {pattern!r}")


def _sample_value(
    spec: dict[str, Any],
    registry: dict[str, dict[str, Any]] | None = None,
    seen_refs: frozenset[str] = frozenset(),
) -> Any:
    if "const" in spec:
        return copy.deepcopy(spec["const"])
    if spec.get("enum"):
        return copy.deepcopy(spec["enum"][0])
    if "$ref" in spec:
        reference = spec["$ref"]
        if registry is None or reference not in registry or reference in seen_refs:
            return {"schema_version": "1.0.0"}
        return _sample_value(registry[reference], registry, seen_refs | {reference})
    if "anyOf" in spec and "type" not in spec and "properties" not in spec:
        choices = [choice for choice in spec["anyOf"] if choice.get("type") != "null"]
        return _sample_value(choices[0] if choices else spec["anyOf"][0], registry, seen_refs)
    if "oneOf" in spec and "type" not in spec and "properties" not in spec:
        return _sample_value(spec["oneOf"][0], registry, seen_refs)
    if "allOf" in spec and "type" not in spec and "properties" not in spec:
        value = _sample_value(spec["allOf"][0], registry, seen_refs)
        if isinstance(value, dict):
            for constraint in spec["allOf"][1:]:
                _merge_sample(value, constraint, registry, seen_refs)
        return value
    kind = spec.get("type")
    if kind == "string":
        return _sample_string(spec)
    if kind == "integer":
        return int(spec.get("minimum", 0))
    if kind == "number":
        return float(spec.get("minimum", 0))
    if kind == "boolean":
        return False
    if kind == "array":
        count = max(0, int(spec.get("minItems", 0)))
        item_schema = spec.get("items", {})
        values = [_sample_value(item_schema, registry, seen_refs) for _ in range(count)]
        if spec.get("uniqueItems"):
            for index in range(1, len(values)):
                values[index] = _vary_sample(
                    values[index], item_schema, index, registry, seen_refs
                )
        _merge_array_sample(values, spec, registry, seen_refs, item_schema)
        return values
    if kind == "object" or "properties" in spec:
        result: dict[str, Any] = {}
        properties = spec.get("properties", {})
        for field in spec.get("required", []):
            if field in properties:
                result[field] = _sample_value(properties[field], registry, seen_refs)
        _apply_sample_branches(result, spec, registry, seen_refs)
        return result
    return None


def _vary_sample(
    value: Any,
    spec: dict[str, Any],
    index: int,
    registry: dict[str, dict[str, Any]] | None = None,
    seen_refs: frozenset[str] = frozenset(),
) -> Any:
    if "$ref" in spec and registry is not None:
        reference = spec["$ref"]
        if reference in registry and reference not in seen_refs:
            return _vary_sample(
                value,
                registry[reference],
                index,
                registry,
                seen_refs | {reference},
            )
    if spec.get("enum") and len(spec["enum"]) > index:
        return copy.deepcopy(spec["enum"][index])
    kind = spec.get("type")
    if kind == "integer":
        candidate = int(spec.get("minimum", 0)) + index
        if candidate <= int(spec.get("maximum", candidate)):
            return candidate
    if kind == "number":
        candidate = float(spec.get("minimum", 0)) + index
        if candidate <= float(spec.get("maximum", candidate)):
            return candidate
    if kind == "string" and isinstance(value, str) and "const" not in spec:
        pattern = spec.get("pattern", "")
        candidates = [
            hashlib.sha256(f"contract-fixture-{index}".encode("utf-8")).hexdigest(),
            f"018f1234-5678-7abc-8def-{index:012x}",
            f"JSMVP-R{index + 1:03d}",
            "b" * 64,
            "018f1234-5678-7abc-8def-0123456789ac",
            "2026-07-18T01:00:01Z",
            "value-2",
            "security_operator",
            "P01",
            "JSMVP-R002",
        ]
        for candidate in candidates:
            if candidate == value or len(candidate) < spec.get("minLength", 0) or len(candidate) > spec.get("maxLength", 1_000_000):
                continue
            if not pattern or re.fullmatch(pattern, candidate):
                return candidate
    if isinstance(value, dict):
        properties = spec.get("properties", {})
        for field in spec.get("required", []):
            if field not in value or field not in properties:
                continue
            varied = _vary_sample(
                value[field], properties[field], index, registry, seen_refs
            )
            if varied != value[field]:
                result = copy.deepcopy(value)
                result[field] = varied
                return result
    return value


def _condition_matches(value: dict[str, Any], condition: dict[str, Any]) -> bool:
    if any(field not in value for field in condition.get("required", [])):
        return False
    for field, field_spec in condition.get("properties", {}).items():
        if field not in value:
            continue
        field_value = value[field]
        if "const" in field_spec and field_value != field_spec["const"]:
            return False
        if "enum" in field_spec and field_value not in field_spec["enum"]:
            return False
        if isinstance(field_value, dict) and isinstance(field_spec, dict):
            if not _condition_matches(field_value, field_spec):
                return False
    return True


def _sample_matches(value: Any, condition: dict[str, Any]) -> bool:
    """Evaluate the small assertion subset used by generated array witnesses."""

    if "const" in condition and value != condition["const"]:
        return False
    if "enum" in condition and value not in condition["enum"]:
        return False
    kind = condition.get("type")
    if kind == "null" and value is not None:
        return False
    if kind == "string" and not isinstance(value, str):
        return False
    if kind == "boolean" and not isinstance(value, bool):
        return False
    if kind == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        return False
    if kind == "number" and (
        not isinstance(value, (int, float)) or isinstance(value, bool)
    ):
        return False
    if kind == "array" and not isinstance(value, list):
        return False
    if kind == "object" and not isinstance(value, dict):
        return False
    if isinstance(value, dict):
        return _condition_matches(value, condition)
    return not condition.get("properties") and not condition.get("required")


def _resolved_sample_schema(
    spec: dict[str, Any],
    registry: dict[str, dict[str, Any]] | None,
    seen_refs: frozenset[str],
) -> dict[str, Any]:
    current = spec
    visited = set(seen_refs)
    while "$ref" in current and registry is not None:
        reference = current["$ref"]
        if reference not in registry or reference in visited:
            break
        visited.add(reference)
        current = registry[reference]
    return current


def _merge_discriminated_oneofs(
    value: dict[str, Any],
    schema: dict[str, Any],
    discriminator: dict[str, Any],
    registry: dict[str, dict[str, Any]] | None,
    seen_refs: frozenset[str],
) -> None:
    desired = {
        field: field_schema["const"]
        for field, field_schema in discriminator.get("properties", {}).items()
        if "const" in field_schema
    }
    for branch_container in [schema, *schema.get("allOf", [])]:
        branches = branch_container.get("oneOf", [])
        selected = next(
            (
                branch
                for branch in branches
                if any(
                    branch.get("properties", {}).get(field, {}).get("const")
                    == expected
                    for field, expected in desired.items()
                )
                and all(
                    "const" not in branch.get("properties", {}).get(field, {})
                    or branch["properties"][field]["const"] == expected
                    for field, expected in desired.items()
                )
            ),
            None,
        )
        if selected is not None:
            _merge_sample(value, selected, registry, seen_refs)


def _merge_array_sample(
    values: list[Any],
    constraint: dict[str, Any],
    registry: dict[str, dict[str, Any]] | None,
    seen_refs: frozenset[str],
    item_schema: dict[str, Any] | None = None,
    maximum: int | None = None,
    reserved_indices: set[int] | None = None,
) -> None:
    """Materialize array assertions that are needed by the generated valid corpus.

    In particular, ``contains`` is an existential assertion: cloning the first
    item ``minItems`` times does not prove it.  Keep complete item samples and
    refine their discriminators so nested ``allOf`` constraints retain all of
    the fields required by the item schema.
    """

    if item_schema is None and isinstance(constraint.get("items"), dict):
        item_schema = constraint["items"]
    if "maxItems" in constraint:
        maximum = int(constraint["maxItems"])
    if reserved_indices is None:
        reserved_indices = set()

    minimum_items = int(constraint.get("minItems", 0))
    while len(values) < minimum_items:
        if item_schema is None:
            raise ValueError("cannot materialize minItems without an item schema")
        values.append(_sample_value(item_schema, registry, seen_refs))

    contains = constraint.get("contains")
    if isinstance(contains, dict):
        minimum_contains = int(constraint.get("minContains", 1))
        matching = [
            index
            for index, value in enumerate(values)
            if _sample_matches(value, contains)
        ]
        resolved_item = _resolved_sample_schema(item_schema or {}, registry, seen_refs)
        for index in matching[:minimum_contains]:
            if isinstance(values[index], dict):
                _merge_sample(values[index], resolved_item, registry, seen_refs)
                _merge_sample(values[index], contains, registry, seen_refs)
                _merge_discriminated_oneofs(
                    values[index], resolved_item, contains, registry, seen_refs
                )
            reserved_indices.add(index)
        while len(matching) < minimum_contains:
            can_append = maximum is None or len(values) < maximum
            if can_append:
                if values:
                    candidate = copy.deepcopy(values[0])
                elif item_schema is not None:
                    candidate = _sample_value(item_schema, registry, seen_refs)
                else:
                    candidate = _sample_value(contains, registry, seen_refs)
                target_index = len(values)
            else:
                available = [
                    index
                    for index in range(len(values))
                    if index not in reserved_indices and index not in matching
                ]
                if not available:
                    raise ValueError("cannot materialize contains within maxItems")
                target_index = available[0]
                candidate = copy.deepcopy(values[target_index])
            if isinstance(candidate, dict):
                _merge_sample(candidate, contains, registry, seen_refs)
                _merge_sample(candidate, resolved_item, registry, seen_refs)
                _merge_sample(candidate, contains, registry, seen_refs)
                _merge_discriminated_oneofs(
                    candidate, resolved_item, contains, registry, seen_refs
                )
            else:
                candidate = _sample_value(contains, registry, seen_refs)
            if not _sample_matches(candidate, contains):
                raise ValueError("cannot synthesize an item satisfying contains")
            if can_append:
                values.append(candidate)
            else:
                values[target_index] = candidate
            matching.append(target_index)
            reserved_indices.add(target_index)

    for branch in constraint.get("allOf", []):
        _merge_array_sample(
            values,
            branch,
            registry,
            seen_refs,
            item_schema,
            maximum,
            reserved_indices,
        )
    if constraint.get("oneOf"):
        _merge_array_sample(
            values,
            constraint["oneOf"][0],
            registry,
            seen_refs,
            item_schema,
            maximum,
            reserved_indices,
        )

    if constraint.get("uniqueItems"):
        for index, value in enumerate(values):
            if value in values[:index]:
                raise ValueError("cannot synthesize unique array items")


def _merge_sample(
    value: dict[str, Any],
    constraint: dict[str, Any],
    registry: dict[str, dict[str, Any]] | None,
    seen_refs: frozenset[str],
    inherited_properties: dict[str, dict[str, Any]] | None = None,
    array_reservations: dict[int, set[int]] | None = None,
) -> None:
    if array_reservations is None:
        array_reservations = {}
    properties = constraint.get("properties", {})
    property_schemas = dict(inherited_properties or {})
    for field, field_schema in properties.items():
        if field not in property_schemas or "items" in field_schema:
            property_schemas[field] = field_schema
    for field in constraint.get("required", []):
        if field in properties:
            value[field] = _sample_value(properties[field], registry, seen_refs)
    for field, field_constraint in properties.items():
        if field not in value:
            continue
        if "const" in field_constraint:
            value[field] = copy.deepcopy(field_constraint["const"])
        elif field_constraint.get("enum") and value[field] not in field_constraint["enum"]:
            value[field] = copy.deepcopy(field_constraint["enum"][0])
        elif field_constraint.get("type") == "null":
            value[field] = None
        elif "anyOf" in field_constraint:
            value[field] = _sample_value(field_constraint, registry, seen_refs)
        elif field_constraint.get("type") in {"integer", "number"}:
            value[field] = _sample_value(field_constraint, registry, seen_refs)
        elif (
            isinstance(value[field], (int, float))
            and not isinstance(value[field], bool)
            and "minimum" in field_constraint
            and value[field] < field_constraint["minimum"]
        ):
            value[field] = field_constraint["minimum"]
        elif isinstance(value[field], dict):
            _merge_sample(
                value[field],
                field_constraint,
                registry,
                seen_refs,
                array_reservations=array_reservations,
            )
        elif isinstance(value[field], list):
            base_array_schema = property_schemas.get(field, {})
            _merge_array_sample(
                value[field],
                field_constraint,
                registry,
                seen_refs,
                base_array_schema.get("items"),
                int(base_array_schema["maxItems"])
                if "maxItems" in base_array_schema
                else None,
                array_reservations.setdefault(id(value[field]), set()),
            )
    for branch in constraint.get("allOf", []):
        if "if" in branch:
            selected = branch.get("then", {}) if _condition_matches(value, branch["if"]) else branch.get("else", {})
            _merge_sample(
                value,
                selected,
                registry,
                seen_refs,
                property_schemas,
                array_reservations,
            )
        else:
            _merge_sample(
                value,
                branch,
                registry,
                seen_refs,
                property_schemas,
                array_reservations,
            )
    if "if" in constraint:
        selected = (
            constraint.get("then", {})
            if _condition_matches(value, constraint["if"])
            else constraint.get("else", {})
        )
        _merge_sample(
            value,
            selected,
            registry,
            seen_refs,
            property_schemas,
            array_reservations,
        )
    if constraint.get("oneOf"):
        selected = next(
            (
                branch
                for branch in constraint["oneOf"]
                if _condition_matches(value, branch)
            ),
            constraint["oneOf"][0],
        )
        _merge_sample(
            value,
            selected,
            registry,
            seen_refs,
            property_schemas,
            array_reservations,
        )


def _apply_sample_branches(
    value: dict[str, Any],
    spec: dict[str, Any],
    registry: dict[str, dict[str, Any]] | None,
    seen_refs: frozenset[str],
) -> None:
    array_reservations: dict[int, set[int]] = {}
    for _ in range(3):
        _merge_sample(
            value,
            spec,
            registry,
            seen_refs,
            array_reservations=array_reservations,
        )


def render_schema_corpus(schemas: dict[str, dict[str, Any]]) -> Artifact:
    registry = {document["$id"]: document for document in schemas.values()}
    strict_registry = StrictSchemaRegistry(registry)
    records = []
    for path, document in sorted(schemas.items()):
        try:
            valid = _sample_value(document, registry, frozenset({document["$id"]}))
        except ValueError as error:
            raise ValueError(
                f"cannot synthesize schema corpus fixture for {path}: {error}"
            ) from error
        if not isinstance(valid, dict):
            raise ValueError(f"contract schema root must be an object: {path}")
        try:
            strict_schema_validate(valid, document, strict_registry)
        except StrictSchemaValidationError as error:
            raise ValueError(
                f"synthesized valid fixture does not satisfy {path}: {error}"
            ) from error
        invalid = copy.deepcopy(valid)
        invalid["__unknown_property"] = True
        try:
            strict_schema_validate(invalid, document, strict_registry)
        except StrictSchemaValidationError:
            pass
        else:
            raise ValueError(
                f"synthesized invalid fixture unexpectedly satisfies {path}"
            )
        records.append(
            {
                "schema_path": path,
                "schema_id": document["$id"],
                "valid": valid,
                "invalid": invalid,
                "invalid_reason": "strict unknown property",
            }
        )
    return json_artifact(
        {
            "_generated": f"generated by {GENERATOR}; DO NOT EDIT",
            "schema_version": "1.0.0",
            "records": records,
        },
        "application/json",
    )


def _go_literal(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _operation_name(value: str) -> str:
    return _type_name(value)


def render_openapi_clients(openapi: dict[str, Any]) -> dict[str, Artifact]:
    operations: list[dict[str, Any]] = []
    for path, path_item in sorted(openapi.get("paths", {}).items()):
        for method in ("get", "post", "put", "patch", "delete"):
            if method not in path_item:
                continue
            operation = path_item[method]
            operation_id = operation.get("operationId") or f"{method}_{re.sub(r'[^a-zA-Z0-9]+', '_', path).strip('_')}"
            policy = operation.get("x-jumpship-policy", {})
            concurrency = operation.get("x-jumpship-concurrency", policy.get("concurrency", "none"))
            concurrency_mode = concurrency.get("mode", "none") if isinstance(concurrency, dict) else concurrency
            idempotency = operation.get("x-jumpship-idempotency", policy.get("idempotency", {}))
            idempotency_required = (
                bool(idempotency.get("required", False))
                if isinstance(idempotency, dict)
                else bool(idempotency)
            )
            audiences = operation.get("x-jumpship-allowed-audiences", policy.get("allowed_audiences", []))
            if not isinstance(audiences, list) or not audiences or not all(isinstance(value, str) for value in audiences):
                raise ValueError(f"OpenAPI operation {operation_id} has no valid allowed-audience policy")
            request_content = operation.get("requestBody", {}).get("content", {})
            if not isinstance(request_content, dict) or len(request_content) > 1:
                raise ValueError(f"OpenAPI operation {operation_id} must declare at most one request media type")
            request_media_type = next(iter(request_content), "")
            if request_media_type not in {"", "application/json", "application/x-www-form-urlencoded"}:
                raise ValueError(f"OpenAPI operation {operation_id} uses unsupported request media type {request_media_type!r}")
            operations.append(
                {
                    "id": operation_id,
                    "name": _operation_name(operation_id),
                    "method": method.upper(),
                    "path": path,
                    "mutation": method != "get",
                    "idempotency_required": idempotency_required,
                    "concurrency_mode": str(concurrency_mode),
                    "max_body": int(operation.get("x-jumpship-max-body-bytes", policy.get("max_request_bytes", 0))),
                    "audiences": list(audiences),
                    "request_media_type": request_media_type,
                    "manual_redirect": "303" in operation.get("responses", {}),
                }
            )
    if not operations:
        raise ValueError("OpenAPI contract must declare operations")

    go = [
        "// Code generated by internal/contracts/codegen/generate.py; DO NOT EDIT.",
        "// Thin policy-aware client generated from contracts/openapi/openapi.yaml.",
        "package api",
        "",
        "import (",
        '\t"bytes"',
        '\t"context"',
        '\t"encoding/json"',
        '\t"errors"',
        '\t"fmt"',
        '\t"io"',
        '\t"net/http"',
        '\t"net/url"',
        '\t"strings"',
        ")",
        "",
        "type OperationID string",
        "",
        "const (",
    ]
    for operation in operations:
        go.append(f"\tOperation{operation['name']} OperationID = {_go_literal(operation['id'])}")
    go.extend(
        [
            ")",
            "",
            "type Operation struct {",
            "\tMethod string",
            "\tPath string",
            "\tMutation bool",
            "\tIdempotencyRequired bool",
            "\tConcurrencyMode string",
            "\tMaxBodyBytes int64",
            "\tAllowedAudiences []string",
            "\tRequestMediaType string",
            "\tManualRedirect bool",
            "}",
            "",
            "var Operations = map[OperationID]Operation{",
        ]
    )
    for operation in operations:
        audiences = ", ".join(_go_literal(value) for value in operation["audiences"])
        go.append(
            f"\tOperation{operation['name']}: {{Method: {_go_literal(operation['method'])}, Path: {_go_literal(operation['path'])}, "
            f"Mutation: {str(operation['mutation']).lower()}, IdempotencyRequired: {str(operation['idempotency_required']).lower()}, "
            f"ConcurrencyMode: {_go_literal(operation['concurrency_mode'])}, "
            f"MaxBodyBytes: {operation['max_body']}, AllowedAudiences: []string{{{audiences}}}, "
            f"RequestMediaType: {_go_literal(operation['request_media_type'])}, ManualRedirect: {str(operation['manual_redirect']).lower()}}},"
        )
    go.extend(
        [
            "}",
            "",
            "type Request struct {",
            "\tAudience string",
            "\tPathParameters map[string]string",
            "\tQuery url.Values",
            "\tBody json.RawMessage",
            "\tForm url.Values",
            "\tIdempotencyKey string",
            "\tIfMatch string",
            "\tCSRFToken string",
            "\tRequestID string",
            "}",
            "",
            "type Response struct {",
            "\tStatusCode int",
            "\tHeader http.Header",
            "\tBody []byte",
            "}",
            "",
            "type Problem struct {",
            "\tType string `json:\"type\"`",
            "\tCode string `json:\"code\"`",
            "\tStatus int `json:\"status\"`",
            "\tDetail string `json:\"detail\"`",
            "\tRequestID string `json:\"request_id\"`",
            "}",
            "",
            "type Client struct {",
            "\tbaseURL *url.URL",
            "\thttpClient *http.Client",
            "}",
            "",
            "func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {",
            "\tparsed, err := url.Parse(baseURL)",
            "\tif err != nil || (parsed.Scheme != \"http\" && parsed.Scheme != \"https\") || parsed.Host == \"\" || parsed.User != nil || parsed.Fragment != \"\" {",
            "\t\treturn nil, errors.New(\"invalid API base URL\")",
            "\t}",
            "\tif !strings.HasSuffix(parsed.Path, \"/\") { parsed.Path += \"/\" }",
            "\tif httpClient == nil { httpClient = http.DefaultClient }",
            "\treturn &Client{baseURL: parsed, httpClient: httpClient}, nil",
            "}",
            "",
            "func (client *Client) Do(ctx context.Context, operationID OperationID, input Request) (Response, error) {",
            "\toperation, ok := Operations[operationID]",
            "\tif !ok { return Response{}, errors.New(\"unknown generated operation\") }",
            "\tif !audienceAllowed(operation.AllowedAudiences, input.Audience) { return Response{}, errors.New(\"operation audience is not allowed\") }",
            "\tif operation.IdempotencyRequired && input.IdempotencyKey == \"\" { return Response{}, errors.New(\"operation requires idempotency key\") }",
            "\tif (operation.ConcurrencyMode == \"if_match\" || operation.ConcurrencyMode == \"if_match_required\") && input.IfMatch == \"\" { return Response{}, errors.New(\"operation requires If-Match\") }",
            "\tvar body []byte",
            "\tswitch operation.RequestMediaType {",
            "\tcase \"application/json\":",
            "\t\tif len(input.Form) != 0 { return Response{}, errors.New(\"JSON operation does not accept form fields\") }",
            "\t\tbody = input.Body",
            "\tcase \"application/x-www-form-urlencoded\":",
            "\t\tif len(input.Body) != 0 { return Response{}, errors.New(\"form operation does not accept a JSON body\") }",
            "\t\tbody = []byte(input.Form.Encode())",
            "\tdefault:",
            "\t\tif len(input.Body) != 0 || len(input.Form) != 0 { return Response{}, errors.New(\"operation does not accept a request body\") }",
            "\t}",
            "\tif operation.MaxBodyBytes > 0 && int64(len(body)) > operation.MaxBodyBytes { return Response{}, errors.New(\"request body exceeds contract limit\") }",
            "\trendered := operation.Path",
            "\tfor name, value := range input.PathParameters { rendered = strings.ReplaceAll(rendered, \"{\"+name+\"}\", url.PathEscape(value)) }",
            "\tif strings.ContainsAny(rendered, \"{}\") { return Response{}, errors.New(\"missing path parameter\") }",
            "\trelative, err := url.Parse(strings.TrimPrefix(rendered, \"/\"))",
            "\tif err != nil { return Response{}, err }",
            "\trelative.RawQuery = input.Query.Encode()",
            "\trequestURL := client.baseURL.ResolveReference(relative)",
            "\trequest, err := http.NewRequestWithContext(ctx, operation.Method, requestURL.String(), bytes.NewReader(body))",
            "\tif err != nil { return Response{}, err }",
            "\trequest.Header.Set(\"Accept\", \"application/json, application/problem+json\")",
            "\tif len(body) > 0 { request.Header.Set(\"Content-Type\", operation.RequestMediaType) }",
            "\tif input.IdempotencyKey != \"\" { request.Header.Set(\"Idempotency-Key\", input.IdempotencyKey) }",
            "\tif input.IfMatch != \"\" { request.Header.Set(\"If-Match\", input.IfMatch) }",
            "\tif input.CSRFToken != \"\" { request.Header.Set(\"X-CSRF-Token\", input.CSRFToken) }",
            "\tif input.RequestID != \"\" { request.Header.Set(\"X-Request-ID\", input.RequestID) }",
            "\thttpClient := client.httpClient",
            "\tif operation.ManualRedirect {",
            "\t\tclone := *client.httpClient",
            "\t\tclone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }",
            "\t\thttpClient = &clone",
            "\t}",
            "\tresponse, err := httpClient.Do(request)",
            "\tif err != nil { return Response{}, err }",
            "\tdefer response.Body.Close()",
            "\tconst maxResponseBytes = int64(2 << 20)",
            "\tbody, err = io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))",
            "\tif err != nil { return Response{}, err }",
            "\tif int64(len(body)) > maxResponseBytes { return Response{}, errors.New(\"response exceeds contract limit\") }",
            "\tresult := Response{StatusCode: response.StatusCode, Header: response.Header.Clone(), Body: body}",
            "\tif response.StatusCode >= 400 {",
            "\t\tvar problem Problem",
            "\t\tif err := json.Unmarshal(body, &problem); err != nil { return result, fmt.Errorf(\"API error %d\", response.StatusCode) }",
            "\t\treturn result, fmt.Errorf(\"API error %s (%d): %s\", problem.Code, problem.Status, problem.Detail)",
            "\t}",
            "\treturn result, nil",
            "}",
            "",
            "func audienceAllowed(allowed []string, audience string) bool {",
            "\tif audience == \"\" { return false }",
            "\tfor _, candidate := range allowed {",
            "\t\tif candidate == audience { return true }",
            "\t}",
            "\treturn false",
            "}",
        ]
    )

    browser_operations = [
        operation
        for operation in operations
        if "jumpship-browser" in operation["audiences"]
        and operation["request_media_type"] != "application/x-www-form-urlencoded"
    ]
    if not browser_operations:
        raise ValueError("OpenAPI contract has no browser-audience operations")
    operation_rows = []
    for operation in browser_operations:
        audiences = ", ".join(json.dumps(value) for value in operation["audiences"])
        operation_rows.append(
            f"  {json.dumps(operation['id'])}: {{ method: {json.dumps(operation['method'])}, path: {json.dumps(operation['path'])}, "
            f"idempotencyRequired: {str(operation['idempotency_required']).lower()}, concurrencyMode: {json.dumps(operation['concurrency_mode'])}, "
            f"maxBodyBytes: {operation['max_body']}, requestMediaType: {json.dumps(operation['request_media_type'])}, allowedAudiences: [{audiences}] }},"
        )
    union = " | ".join(json.dumps(operation["id"]) for operation in browser_operations)
    ts = f'''// Code generated by internal/contracts/codegen/generate.py; DO NOT EDIT.
// Thin policy-aware client generated from contracts/openapi/openapi.yaml.
export type OperationID = {union};
export interface APIRequest {{ readonly pathParameters?: Readonly<Record<string, string>>; readonly query?: Readonly<Record<string, string>>; readonly body?: unknown; readonly idempotencyKey?: string; readonly ifMatch?: string; readonly csrfToken?: string; readonly requestID?: string; }}
export interface APIResponse<T = unknown> {{ readonly status: number; readonly headers: Headers; readonly data: T; }}
export class APIProblem extends Error {{
  readonly status: number;
  readonly code: string;
  readonly requestID: string;
  constructor(status: number, code: string, requestID: string, detail: string) {{
    super(detail);
    this.status = status;
    this.code = code;
    this.requestID = requestID;
  }}
}}
const operations: Readonly<Record<OperationID, {{ method: string; path: string; idempotencyRequired: boolean; concurrencyMode: string; maxBodyBytes: number; requestMediaType: string; allowedAudiences: ReadonlyArray<string> }}>> = {{
{chr(10).join(operation_rows)}
}};
export class JumpshipAPIClient {{
  private readonly baseURL: string;
  private readonly fetcher: typeof fetch;
  constructor(baseURL: string, fetcher: typeof fetch = fetch) {{
    this.baseURL = baseURL;
    this.fetcher = fetcher;
  }}
  async call<T>(operationID: OperationID, input: APIRequest = {{}}): Promise<APIResponse<T>> {{
    const operation = operations[operationID];
    if (operation.idempotencyRequired && !input.idempotencyKey) throw new TypeError("operation requires idempotency key");
    if ((operation.concurrencyMode === "if_match" || operation.concurrencyMode === "if_match_required") && !input.ifMatch) throw new TypeError("operation requires If-Match");
    let path = operation.path;
    for (const [name, value] of Object.entries(input.pathParameters ?? {{}})) path = path.replaceAll(`{{${{name}}}}`, encodeURIComponent(value));
    if (/[{{}}]/.test(path)) throw new TypeError("missing path parameter");
    const url = new URL(path.replace(/^[/]/, ""), this.baseURL.endsWith("/") ? this.baseURL : `${{this.baseURL}}/`);
    for (const [name, value] of Object.entries(input.query ?? {{}})) url.searchParams.set(name, value);
    if (operation.requestMediaType !== "application/json" && input.body !== undefined) throw new TypeError("operation does not accept a JSON body");
    const body = input.body === undefined ? undefined : JSON.stringify(input.body);
    if (operation.maxBodyBytes > 0 && body !== undefined && new TextEncoder().encode(body).length > operation.maxBodyBytes) throw new RangeError("request body exceeds contract limit");
    const headers = new Headers({{ Accept: "application/json, application/problem+json" }});
    if (body !== undefined) headers.set("Content-Type", operation.requestMediaType);
    if (input.idempotencyKey) headers.set("Idempotency-Key", input.idempotencyKey);
    if (input.ifMatch) headers.set("If-Match", input.ifMatch);
    if (input.csrfToken) headers.set("X-CSRF-Token", input.csrfToken);
    if (input.requestID) headers.set("X-Request-ID", input.requestID);
    const response = await this.fetcher(url, {{ method: operation.method, headers, body, credentials: "include", redirect: "error" }});
    const text = await response.text();
    if (new TextEncoder().encode(text).length > 2 * 1024 * 1024) throw new RangeError("response exceeds contract limit");
    const data = text === "" ? null : JSON.parse(text) as unknown;
    if (!response.ok) {{ const problem = data as {{ code?: string; detail?: string; request_id?: string }}; throw new APIProblem(response.status, problem.code ?? "unknown_error", problem.request_id ?? "", problem.detail ?? "request failed"); }}
    return {{ status: response.status, headers: response.headers, data: data as T }};
  }}
}}
'''
    return {
        "internal/contracts/api/openapi.gen.go": text_artifact("\n".join(go), "text/x-go"),
        "web/src/lib/api/generated/openapi.gen.ts": text_artifact(ts, "text/typescript"),
    }


def _proto_go_type(proto_type: str, repeated: bool, enum_names: set[str]) -> str:
    scalars = {
        "string": "string",
        "bytes": "[]byte",
        "bool": "bool",
        "int32": "int32",
        "sint32": "int32",
        "fixed32": "uint32",
        "uint32": "uint32",
        "int64": "int64",
        "sint64": "int64",
        "fixed64": "uint64",
        "uint64": "uint64",
        "double": "float64",
        "float": "float32",
    }
    if proto_type.startswith("map<"):
        key, value = [part.strip() for part in proto_type[4:-1].split(",", 1)]
        base = f"map[{_proto_go_type(key, False, enum_names)}]{_proto_go_type(value, False, enum_names).removeprefix('*')}"
    elif proto_type in scalars:
        base = scalars[proto_type]
    elif proto_type in enum_names:
        base = proto_type
    elif proto_type.startswith("google.protobuf."):
        base = "string"
    else:
        base = "*" + proto_type.split(".")[-1]
    if repeated:
        return "[]" + base.removeprefix("*")
    return base


def _proto_wire_type(proto_type: str, enum_names: set[str]) -> str:
    if proto_type in {"double", "fixed64", "sfixed64"}:
        return "fixed64"
    if proto_type in {"float", "fixed32", "sfixed32"}:
        return "fixed32"
    if proto_type in {
        "bool",
        "int32",
        "sint32",
        "uint32",
        "int64",
        "sint64",
        "uint64",
    } or proto_type in enum_names:
        return "varint"
    return "bytes"


def _proto_json_name(field: str) -> str:
    """Return protobuf's default lowerCamel JSON name for a proto field."""
    head, *tail = field.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


def _proto_json_tag(field: str, proto_type: str) -> str:
    """Return the encoding/json tag that matches the protobuf JSON form."""
    options = ["omitempty"]
    if proto_type in {
        "fixed64",
        "int64",
        "sfixed64",
        "sint64",
        "uint64",
    }:
        options.append("string")
    return ",".join((_proto_json_name(field), *options))


def render_cell_clients(proto: str) -> dict[str, Artifact]:
    enum_names: set[str] = set()
    enum_blocks = list(re.finditer(r"enum\s+(\w+)\s*\{(.*?)\n\}", proto, re.S))
    for match in enum_blocks:
        enum_names.add(match.group(1))
    types = [
        "// Code generated by internal/contracts/codegen/generate.py from cell.proto; DO NOT EDIT.",
        "// These dependency-free structs preserve the frozen wire field numbers and JSON names.",
        "package cellv1",
        "",
    ]
    for match in enum_blocks:
        name, body = match.groups()
        types.extend([f"type {name} int32", "", "const ("])
        for entry, number in re.findall(r"(?m)^\s*(\w+)\s*=\s*(\d+)\s*;", body):
            types.append(f"\t{name}{_type_name(entry.lower())} {name} = {number}")
        types.extend([")", ""])
    field_pattern = r"(?m)^\s*(?:(repeated|optional)\s+)?(map<[^>]+>|[.A-Za-z_][.A-Za-z0-9_]*)\s+(\w+)\s*=\s*(\d+)\s*;"
    oneof_variants: list[tuple[str, str, str, str, str]] = []
    message_fields: dict[str, list[tuple[str, str, str, str]]] = {}
    message_order: list[str] = []
    message_oneofs: dict[str, tuple[str, str]] = {}
    for match in re.finditer(r"message\s+(\w+)\s*\{(.*?)\n\}", proto, re.S):
        name, body = match.groups()
        message_order.append(name)
        types.append(f"type {name} struct {{")
        oneof_start = body.find("oneof ")
        ordinary_body = body[:oneof_start] if oneof_start >= 0 else body
        ordinary_fields = re.findall(field_pattern, ordinary_body)
        message_fields[name] = ordinary_fields
        for qualifier, proto_type, field, number in ordinary_fields:
            go_type = _proto_go_type(proto_type, qualifier == "repeated", enum_names)
            wire = _proto_wire_type(proto_type, enum_names)
            types.append(
                f"\t{_go_field_name(field)} {go_type} `protobuf:\"{wire},{number},opt,name={field},proto3\" json:\"{_proto_json_tag(field, proto_type)}\"`"
            )
        if oneof_start >= 0:
            declaration = re.match(r"oneof\s+(\w+)\s*\{", body[oneof_start:])
            if declaration is None:
                raise ValueError(f"cannot parse oneof declaration in {name}")
            oneof_name = declaration.group(1)
            oneof_suffix = _type_name(oneof_name)
            interface_name = (
                f"{name}Variant"
                if name.endswith(oneof_suffix)
                else f"{name}{oneof_suffix}Variant"
            )
            message_oneofs[name] = (oneof_name, interface_name)
            types.append(f"\t{_go_field_name(oneof_name)} {interface_name} `json:\"-\"`")
            for qualifier, proto_type, field, number in re.findall(field_pattern, body[oneof_start:]):
                if qualifier:
                    raise ValueError(f"oneof field cannot be {qualifier}: {name}.{field}")
                oneof_variants.append((name, interface_name, proto_type, field, number))
        types.extend(["}", ""])

    types.extend(
        r'''
func decodeProtoJSONObject(messageName string, data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("decode %s JSON object: %w", messageName, err)
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		return nil, fmt.Errorf("decode %s JSON object: expected object", messageName)
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		fieldToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("decode %s JSON field: %w", messageName, err)
		}
		field, ok := fieldToken.(string)
		if !ok {
			return nil, fmt.Errorf("decode %s JSON field: expected field name", messageName)
		}
		if _, duplicate := object[field]; duplicate {
			return nil, fmt.Errorf("%s contains duplicate field %q", messageName, field)
		}
		var payload json.RawMessage
		if err := decoder.Decode(&payload); err != nil {
			return nil, fmt.Errorf("decode %s.%s: %w", messageName, field, err)
		}
		object[field] = payload
	}
	closing, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("decode %s JSON object: %w", messageName, err)
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
		return nil, fmt.Errorf("decode %s JSON object: expected closing delimiter", messageName)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode %s JSON object: trailing value", messageName)
		}
		return nil, fmt.Errorf("decode %s JSON object: %w", messageName, err)
	}
	return object, nil
}

func normalizeProtoJSONFields(messageName string, object map[string]json.RawMessage, aliases map[string]string) (map[string]json.RawMessage, error) {
	normalized := make(map[string]json.RawMessage, len(object))
	for field, payload := range object {
		canonical, ok := aliases[field]
		if !ok {
			return nil, fmt.Errorf("%s contains unknown field %q", messageName, field)
		}
		if _, duplicate := normalized[canonical]; duplicate {
			return nil, fmt.Errorf("%s contains duplicate spellings for field %q", messageName, canonical)
		}
		normalized[canonical] = payload
	}
	return normalized, nil
}
'''.strip().splitlines()
    )
    types.append("")

    for message_name in message_order:
        if message_name in message_oneofs:
            continue
        alias_name = message_name[:1].lower() + message_name[1:] + "JSONAlias"
        aliases: list[tuple[str, str]] = []
        for _, _, field, _ in message_fields[message_name]:
            json_name = _proto_json_name(field)
            aliases.append((json_name, json_name))
            if field != json_name:
                aliases.append((field, json_name))
        types.extend(
            [
                f"type {alias_name} {message_name}",
                "",
                f"func (message *{message_name}) UnmarshalJSON(data []byte) error {{",
                "\tif message == nil {",
                f'\t\treturn fmt.Errorf("cannot decode JSON into nil *{message_name}")',
                "\t}",
                f'\tobject, err := decodeProtoJSONObject("{message_name}", data)',
                "\tif err != nil {",
                "\t\treturn err",
                "\t}",
                "\tnormalized, err := normalizeProtoJSONFields(",
                f'\t\t"{message_name}",',
                "\t\tobject,",
                "\t\tmap[string]string{",
            ]
        )
        for spelling, canonical in aliases:
            types.append(f'\t\t\t"{spelling}": "{canonical}",')
        types.extend(
            [
                "\t\t},",
                "\t)",
                "\tif err != nil {",
                "\t\treturn err",
                "\t}",
                "\tnormalizedPayload, err := json.Marshal(normalized)",
                "\tif err != nil {",
                f'\t\treturn fmt.Errorf("normalize {message_name} JSON: %w", err)',
                "\t}",
                f"\tvar decoded {alias_name}",
                "\tif err := json.Unmarshal(normalizedPayload, &decoded); err != nil {",
                f'\t\treturn fmt.Errorf("decode {message_name}: %w", err)',
                "\t}",
                f"\t*message = {message_name}(decoded)",
                "\treturn nil",
                "}",
                "",
            ]
        )
    grouped_variants: dict[str, list[tuple[str, str, str, str, str]]] = {}
    for message_name, interface_name, proto_type, field, number in oneof_variants:
        grouped_variants.setdefault(interface_name, []).append(
            (message_name, interface_name, proto_type, field, number)
        )
    for interface_name, variants in grouped_variants.items():
        types.extend([f"type {interface_name} interface {{", f"\tis{interface_name}()", "}", ""])
        for message_name, _, proto_type, field, number in variants:
            wrapper_name = f"{message_name}{_type_name(field)}"
            go_type = _proto_go_type(proto_type, False, enum_names)
            wire = _proto_wire_type(proto_type, enum_names)
            types.extend(
                [
                    f"type {wrapper_name} struct {{",
                    f"\t{_go_field_name(field)} {go_type} `protobuf:\"{wire},{number},opt,name={field},proto3,oneof\" json:\"{_proto_json_tag(field, proto_type)}\"`",
                    "}",
                    "",
                    f"func (*{wrapper_name}) is{interface_name}() {{}}",
                    "",
                ]
            )
        message_name = variants[0][0]
        oneof_field = re.search(r"oneof\s+(\w+)\s*\{", proto[proto.find(f"message {message_name}") :])
        if oneof_field is None:
            raise ValueError(f"cannot recover oneof field for {message_name}")
        field_name = _go_field_name(oneof_field.group(1))
        types.extend([f"func (message *{message_name}) HasValid{_type_name(oneof_field.group(1))}() bool {{", "\tif message == nil {", "\t\treturn false", "\t}", f"\tswitch variant := message.{field_name}.(type) {{"])
        for variant_message, _, variant_proto_type, field, _ in variants:
            wrapper_name = f"{variant_message}{_type_name(field)}"
            variant_go_type = _proto_go_type(
                variant_proto_type, False, enum_names
            )
            valid_expression = (
                f"variant != nil && variant.{_go_field_name(field)} != nil"
                if variant_go_type.startswith("*")
                else "variant != nil"
            )
            types.extend(
                [
                    f"\tcase *{wrapper_name}:",
                    f"\t\treturn {valid_expression}",
                ]
            )
        types.extend(["\tdefault:", "\t\treturn false", "\t}", "}", ""])
        alias_name = message_name[:1].lower() + message_name[1:] + "JSONAlias"
        types.extend(
            [
                f"type {alias_name} {message_name}",
                "",
                f"func (message {message_name}) MarshalJSON() ([]byte, error) {{",
                f"\tbase, err := json.Marshal({alias_name}(message))",
                "\tif err != nil {",
                "\t\treturn nil, err",
                "\t}",
                "\tvar object map[string]json.RawMessage",
                "\tif err := json.Unmarshal(base, &object); err != nil {",
                "\t\treturn nil, err",
                "\t}",
                f"\tswitch variant := message.{field_name}.(type) {{",
                "\tcase nil:",
                f'\t\treturn nil, fmt.Errorf("{message_name}.{field_name} requires exactly one variant")',
            ]
        )
        for variant_message, _, variant_proto_type, field, _ in variants:
            wrapper_name = f"{variant_message}{_type_name(field)}"
            go_field = _go_field_name(field)
            variant_go_type = _proto_go_type(
                variant_proto_type, False, enum_names
            )
            invalid_expression = (
                f"variant == nil || variant.{go_field} == nil"
                if variant_go_type.startswith("*")
                else "variant == nil"
            )
            types.extend(
                [
                    f"\tcase *{wrapper_name}:",
                    f"\t\tif {invalid_expression} {{",
                    f'\t\t\treturn nil, fmt.Errorf("{message_name}.{field_name} contains a nil {field} variant")',
                    "\t\t}",
                    f"\t\tpayload, err := json.Marshal(variant.{go_field})",
                    "\t\tif err != nil {",
                    "\t\t\treturn nil, err",
                    "\t\t}",
                    f'\t\tobject["{_proto_json_name(field)}"] = payload',
                ]
            )
        accepted_spellings: list[tuple[str, str]] = []
        accepted_fields = [field for _, _, field, _ in message_fields[message_name]]
        accepted_fields.extend(field for _, _, _, field, _ in variants)
        for field in accepted_fields:
            json_name = _proto_json_name(field)
            accepted_spellings.append((json_name, json_name))
            if field != json_name:
                accepted_spellings.append((field, json_name))
        types.extend(
            [
                "\tdefault:",
                f'\t\treturn nil, fmt.Errorf("{message_name}.{field_name} contains an unknown variant %T", variant)',
                "\t}",
                "\treturn json.Marshal(object)",
                "}",
                "",
                f"func (message *{message_name}) UnmarshalJSON(data []byte) error {{",
                "\tif message == nil {",
                f'\t\treturn fmt.Errorf("cannot decode JSON into nil *{message_name}")',
                "\t}",
                f'\tobject, err := decodeProtoJSONObject("{message_name}", data)',
                "\tif err != nil {",
                "\t\treturn err",
                "\t}",
                "\tnormalized, err := normalizeProtoJSONFields(",
                f'\t\t"{message_name}",',
                "\t\tobject,",
                "\t\tmap[string]string{",
                *[
                    f'\t\t\t"{spelling}": "{canonical}",'
                    for spelling, canonical in accepted_spellings
                ],
                "\t\t},",
                "\t)",
                "\tif err != nil {",
                "\t\treturn err",
                "\t}",
                "\tnormalizedPayload, err := json.Marshal(normalized)",
                "\tif err != nil {",
                f'\t\treturn fmt.Errorf("normalize {message_name} JSON: %w", err)',
                "\t}",
                f"\tvar decoded {alias_name}",
                "\tif err := json.Unmarshal(normalizedPayload, &decoded); err != nil {",
                f'\t\treturn fmt.Errorf("decode {message_name}: %w", err)',
                "\t}",
                f"\tvar selected {interface_name}",
                "\tvariantSeen := false",
            ]
        )
        for variant_message, _, variant_proto_type, field, _ in variants:
            wrapper_name = f"{variant_message}{_type_name(field)}"
            go_field = _go_field_name(field)
            variant_go_type = _proto_go_type(
                variant_proto_type, False, enum_names
            )
            decoded_go_type = variant_go_type.removeprefix("*")
            wrapper_value = (
                f"&value" if variant_go_type.startswith("*") else "value"
            )
            types.extend(
                [
                    f'\tif payload, ok := normalized["{_proto_json_name(field)}"]; ok {{',
                    "\t\tif variantSeen {",
                    f'\t\t\treturn fmt.Errorf("{message_name}.{field_name} contains multiple variants")',
                    "\t\t}",
                    "\t\tvariantSeen = true",
                    "\t\tif !bytes.Equal(bytes.TrimSpace(payload), []byte(\"null\")) {",
                    f"\t\t\tvar value {decoded_go_type}",
                    "\t\t\tif err := json.Unmarshal(payload, &value); err != nil {",
                    f'\t\t\t\treturn fmt.Errorf("decode {message_name}.{field}: %w", err)',
                    "\t\t\t}",
                    f"\t\t\tselected = &{wrapper_name}{{{go_field}: {wrapper_value}}}",
                    "\t\t}",
                    "\t}",
                ]
            )
        types.extend(
            [
                "\tif selected == nil {",
                f'\t\treturn fmt.Errorf("{message_name}.{field_name} requires exactly one non-null variant")',
                "\t}",
                f"\tdecoded.{field_name} = selected",
                f"\t*message = {message_name}(decoded)",
                "\treturn nil",
                "}",
                "",
            ]
        )
    if message_order:
        types[4:4] = [
            "import (",
            '\t"bytes"',
            '\t"encoding/json"',
            '\t"fmt"',
            '\t"io"',
            ")",
            "",
        ]
    package_match = re.search(r"(?m)^\s*package\s+([.A-Za-z_][.A-Za-z0-9_]*)\s*;", proto)
    if package_match is None:
        raise ValueError("cell.proto must declare a protobuf package")
    proto_package = package_match.group(1)
    services: list[tuple[str, list[tuple[str, str, str, str, str]]]] = []
    for service in re.finditer(r"service\s+(\w+)\s*\{(.*?)\n\}", proto, re.S):
        service_name, body = service.groups()
        methods = re.findall(
            r"rpc\s+(\w+)\s*\(\s*(stream\s+)?([.\w]+)\s*\)\s+returns\s*\(\s*(stream\s+)?([.\w]+)\s*\)\s*;",
            body,
        )
        if not methods:
            raise ValueError(f"protobuf service has no methods: {service_name}")
        services.append((service_name, methods))

    clients = [
        "// Code generated by internal/contracts/codegen/generate.py from cell.proto; DO NOT EDIT.",
        "// Dependency-free net/http adapters implement these frozen Connect protocol seams.",
        "package cellv1",
        "",
        "import (",
        '\t"bytes"',
        '\t"context"',
        '\t"encoding/binary"',
        '\t"encoding/json"',
        '\t"fmt"',
        '\t"io"',
        '\t"mime"',
        '\t"net/http"',
        '\t"net/url"',
        '\t"strings"',
        '\t"sync"',
        ")",
        "",
        "type Metadata map[string][]string",
        "",
        "type RPCRequest[T any] struct {",
        "\tMessage *T",
        "\tHeader Metadata",
        "}",
        "",
        "type RPCResponse[T any] struct {",
        "\tMessage *T",
        "\tHeader Metadata",
        "\tTrailer Metadata",
        "}",
        "",
    ]
    for service_name, methods in services:
        clients.append(f"type {service_name}Client interface {{")
        for method, request_stream, request_type, response_stream, response_type in methods:
            request_name = request_type.split(".")[-1]
            response_name = response_type.split(".")[-1]
            stream_name = f"{service_name}{method}Client"
            if request_stream or response_stream:
                if bool(request_stream) != bool(response_stream):
                    raise ValueError(
                        "dependency-free Connect generator supports unary and "
                        f"bidirectional methods only: {service_name}.{method}"
                    )
                clients.append(
                    f"\t{method}(context.Context, Metadata) ({stream_name}, error)"
                )
            else:
                clients.append(
                    f"\t{method}(context.Context, *RPCRequest[{request_name}]) (*RPCResponse[{response_name}], error)"
                )
        clients.extend(["}", ""])
        for method, request_stream, request_type, response_stream, response_type in methods:
            if not request_stream and not response_stream:
                continue
            request_name = request_type.split(".")[-1]
            response_name = response_type.split(".")[-1]
            stream_name = f"{service_name}{method}Client"
            clients.extend(
                [
                    f"type {stream_name} interface {{",
                    "\tContext() context.Context",
                    f"\tSend(*{request_name}) error",
                    "\tCloseRequest() error",
                    f"\tReceive() (*{response_name}, error)",
                    "\tResponseHeader() (Metadata, error)",
                    "\tResponseTrailer() Metadata",
                    "\tCloseResponse() error",
                    "}",
                    "",
                ]
            )

    clients.extend(
        r'''
const (
	connectProtocolVersion  = "1"
	connectUnaryContentType = "application/json"
	connectStreamContentType = "application/connect+json"
	maxConnectMessageBytes  = 2 * 1024 * 1024
	maxConnectErrorBytes    = 64 * 1024
	connectFlagCompressed   = byte(0x01)
	connectFlagEndStream    = byte(0x02)
)

// ConnectError is a protocol error returned by a Connect server. Details is
// retained as raw JSON so callers can opt into service-specific decoding.
type ConnectError struct {
	Code       string
	Message    string
	Details    json.RawMessage
	HTTPStatus int
	Metadata   Metadata
}

func (connectErr *ConnectError) Error() string {
	if connectErr == nil {
		return "<nil>"
	}
	if connectErr.Message == "" {
		return fmt.Sprintf("connect: %s", connectErr.Code)
	}
	return fmt.Sprintf("connect: %s: %s", connectErr.Code, connectErr.Message)
}

type connectErrorPayload struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Details json.RawMessage `json:"details,omitempty"`
}

type connectEndStream struct {
	Error    *connectErrorPayload `json:"error,omitempty"`
	Metadata Metadata             `json:"metadata,omitempty"`
}

type connectHTTPClient struct {
	baseURL    *url.URL
	httpClient *http.Client
}

func newConnectHTTPClient(baseURL string, httpClient *http.Client) (*connectHTTPClient, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse Connect base URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("Connect base URL must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("Connect base URL must not contain credentials, a query, or a fragment")
	}
	base := *parsed
	base.Path = strings.TrimRight(base.Path, "/") + "/"
	base.RawPath = ""
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &connectHTTPClient{baseURL: &base, httpClient: httpClient}, nil
}

func (client *connectHTTPClient) procedureURL(procedure string) string {
	relative := &url.URL{Path: strings.TrimPrefix(procedure, "/")}
	return client.baseURL.ResolveReference(relative).String()
}

func cloneMetadata(source map[string][]string) Metadata {
	if len(source) == 0 {
		return nil
	}
	clone := make(Metadata, len(source))
	for key, values := range source {
		clone[key] = append([]string(nil), values...)
	}
	return clone
}

func mergeMetadata(first, second Metadata) Metadata {
	merged := cloneMetadata(first)
	if merged == nil && len(second) != 0 {
		merged = make(Metadata, len(second))
	}
	for key, values := range second {
		merged[key] = append(merged[key], values...)
	}
	return merged
}

func applyMetadata(header http.Header, metadata Metadata) {
	for key, values := range metadata {
		for _, value := range values {
			header.Add(key, value)
		}
	}
}

func requireConnectContentType(response *http.Response, expected string) error {
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != expected {
		return fmt.Errorf("connect: unexpected response content type %q", response.Header.Get("Content-Type"))
	}
	return nil
}

func marshalConnectMessage(message any) ([]byte, error) {
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshal Connect JSON message: %w", err)
	}
	if len(payload) > maxConnectMessageBytes {
		return nil, fmt.Errorf("connect: message exceeds %d-byte limit", maxConnectMessageBytes)
	}
	return payload, nil
}

func readConnectBody(reader io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("connect: response exceeds %d-byte limit", limit)
	}
	return payload, nil
}

func connectErrorFromPayload(payload *connectErrorPayload, status int, metadata Metadata) error {
	if payload == nil {
		return fmt.Errorf("connect: HTTP %d returned no error payload", status)
	}
	code := payload.Code
	if code == "" {
		code = "unknown"
	}
	return &ConnectError{
		Code:       code,
		Message:    payload.Message,
		Details:    append(json.RawMessage(nil), payload.Details...),
		HTTPStatus: status,
		Metadata:   cloneMetadata(metadata),
	}
}

func readConnectHTTPError(response *http.Response) error {
	payload, err := readConnectBody(response.Body, maxConnectErrorBytes)
	metadata := mergeMetadata(cloneMetadata(response.Header), cloneMetadata(response.Trailer))
	if err != nil {
		return fmt.Errorf("connect: read HTTP %d error response: %w", response.StatusCode, err)
	}
	var decoded connectErrorPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return fmt.Errorf("connect: malformed HTTP %d error response: %w", response.StatusCode, err)
	}
	return connectErrorFromPayload(&decoded, response.StatusCode, metadata)
}

func callConnectUnary[Request any, Response any](
	ctx context.Context,
	transport *connectHTTPClient,
	procedure string,
	request *RPCRequest[Request],
) (*RPCResponse[Response], error) {
	if request == nil || request.Message == nil {
		return nil, fmt.Errorf("connect: unary request message is required")
	}
	payload, err := marshalConnectMessage(request.Message)
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		transport.procedureURL(procedure),
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("create Connect unary request: %w", err)
	}
	applyMetadata(httpRequest.Header, request.Header)
	httpRequest.Header.Set("Content-Type", connectUnaryContentType)
	httpRequest.Header.Set("Accept", connectUnaryContentType)
	httpRequest.Header.Set("Connect-Protocol-Version", connectProtocolVersion)
	response, err := transport.httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("execute Connect unary request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, readConnectHTTPError(response)
	}
	if err := requireConnectContentType(response, connectUnaryContentType); err != nil {
		return nil, err
	}
	responsePayload, err := readConnectBody(response.Body, maxConnectMessageBytes)
	if err != nil {
		return nil, fmt.Errorf("read Connect unary response: %w", err)
	}
	var message Response
	if err := json.Unmarshal(responsePayload, &message); err != nil {
		return nil, fmt.Errorf("decode Connect unary response: %w", err)
	}
	return &RPCResponse[Response]{
		Message: &message,
		Header:  cloneMetadata(response.Header),
		Trailer: cloneMetadata(response.Trailer),
	}, nil
}

type connectHTTPResult struct {
	response *http.Response
	err      error
}

type connectBidiStream[Request any, Response any] struct {
	ctx              context.Context
	cancel           context.CancelFunc
	requestWriter    *io.PipeWriter
	responseResult   <-chan connectHTTPResult
	sendMu           sync.Mutex
	requestClosed    bool
	requestCloseErr  error
	responseOnce     sync.Once
	response         *http.Response
	responseErr      error
	responseHeader   Metadata
	receiveMu        sync.Mutex
	responseEnded    bool
	trailerMu        sync.RWMutex
	responseTrailer  Metadata
	closeResponseOnce sync.Once
	closeResponseErr error
}

func newConnectBidiStream[Request any, Response any](
	ctx context.Context,
	transport *connectHTTPClient,
	procedure string,
	metadata Metadata,
) (*connectBidiStream[Request, Response], error) {
	if ctx == nil {
		return nil, fmt.Errorf("connect: stream context is required")
	}
	streamContext, cancel := context.WithCancel(ctx)
	requestReader, requestWriter := io.Pipe()
	httpRequest, err := http.NewRequestWithContext(
		streamContext,
		http.MethodPost,
		transport.procedureURL(procedure),
		requestReader,
	)
	if err != nil {
		cancel()
		requestReader.Close()
		requestWriter.Close()
		return nil, fmt.Errorf("create Connect stream request: %w", err)
	}
	applyMetadata(httpRequest.Header, metadata)
	httpRequest.Header.Set("Content-Type", connectStreamContentType)
	httpRequest.Header.Set("Accept", connectStreamContentType)
	httpRequest.Header.Set("Connect-Protocol-Version", connectProtocolVersion)
	result := make(chan connectHTTPResult, 1)
	go func() {
		response, requestErr := transport.httpClient.Do(httpRequest)
		result <- connectHTTPResult{response: response, err: requestErr}
	}()
	return &connectBidiStream[Request, Response]{
		ctx:            streamContext,
		cancel:         cancel,
		requestWriter:  requestWriter,
		responseResult: result,
	}, nil
}

func encodeConnectEnvelope(flags byte, payload []byte) ([]byte, error) {
	if len(payload) > maxConnectMessageBytes {
		return nil, fmt.Errorf("connect: message exceeds %d-byte limit", maxConnectMessageBytes)
	}
	envelope := make([]byte, 5+len(payload))
	envelope[0] = flags
	binary.BigEndian.PutUint32(envelope[1:5], uint32(len(payload)))
	copy(envelope[5:], payload)
	return envelope, nil
}

func readConnectEnvelope(reader io.Reader) (byte, []byte, error) {
	var prefix [5]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(prefix[1:5])
	if uint64(length) > uint64(maxConnectMessageBytes) {
		return 0, nil, fmt.Errorf("connect: message exceeds %d-byte limit", maxConnectMessageBytes)
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	return prefix[0], payload, nil
}

func (stream *connectBidiStream[Request, Response]) Context() context.Context {
	return stream.ctx
}

func (stream *connectBidiStream[Request, Response]) Send(message *Request) error {
	if message == nil {
		return fmt.Errorf("connect: stream request message is required")
	}
	payload, err := marshalConnectMessage(message)
	if err != nil {
		return err
	}
	envelope, err := encodeConnectEnvelope(0, payload)
	if err != nil {
		return err
	}
	stream.sendMu.Lock()
	defer stream.sendMu.Unlock()
	if stream.requestClosed {
		return io.ErrClosedPipe
	}
	if err := stream.ctx.Err(); err != nil {
		return err
	}
	if _, err := stream.requestWriter.Write(envelope); err != nil {
		return fmt.Errorf("write Connect request envelope: %w", err)
	}
	return nil
}

func (stream *connectBidiStream[Request, Response]) CloseRequest() error {
	stream.sendMu.Lock()
	defer stream.sendMu.Unlock()
	if !stream.requestClosed {
		stream.requestCloseErr = stream.requestWriter.Close()
		stream.requestClosed = true
	}
	return stream.requestCloseErr
}

func (stream *connectBidiStream[Request, Response]) abortRequest(cause error) {
	stream.sendMu.Lock()
	defer stream.sendMu.Unlock()
	if stream.requestClosed {
		return
	}
	stream.requestCloseErr = stream.requestWriter.CloseWithError(cause)
	stream.requestClosed = true
}

func (stream *connectBidiStream[Request, Response]) awaitResponse() (*http.Response, error) {
	stream.responseOnce.Do(func() {
		result := <-stream.responseResult
		if result.err != nil {
			stream.responseErr = fmt.Errorf("execute Connect stream request: %w", result.err)
			stream.abortRequest(stream.responseErr)
			return
		}
		if result.response == nil {
			stream.responseErr = fmt.Errorf("connect: stream transport returned no response")
			stream.abortRequest(stream.responseErr)
			return
		}
		if result.response.StatusCode != http.StatusOK {
			stream.responseErr = readConnectHTTPError(result.response)
			result.response.Body.Close()
			stream.abortRequest(stream.responseErr)
			return
		}
		if err := requireConnectContentType(result.response, connectStreamContentType); err != nil {
			stream.responseErr = err
			result.response.Body.Close()
			stream.abortRequest(err)
			return
		}
		stream.response = result.response
		stream.responseHeader = cloneMetadata(result.response.Header)
	})
	return stream.response, stream.responseErr
}

func (stream *connectBidiStream[Request, Response]) ResponseHeader() (Metadata, error) {
	if _, err := stream.awaitResponse(); err != nil {
		return nil, err
	}
	return cloneMetadata(stream.responseHeader), nil
}

func (stream *connectBidiStream[Request, Response]) setResponseTrailer(metadata Metadata) {
	stream.trailerMu.Lock()
	stream.responseTrailer = cloneMetadata(metadata)
	stream.trailerMu.Unlock()
}

func (stream *connectBidiStream[Request, Response]) ResponseTrailer() Metadata {
	stream.trailerMu.RLock()
	defer stream.trailerMu.RUnlock()
	return cloneMetadata(stream.responseTrailer)
}

func (stream *connectBidiStream[Request, Response]) Receive() (*Response, error) {
	stream.receiveMu.Lock()
	defer stream.receiveMu.Unlock()
	if stream.responseEnded {
		return nil, io.EOF
	}
	response, err := stream.awaitResponse()
	if err != nil {
		return nil, err
	}
	flags, payload, err := readConnectEnvelope(response.Body)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("read Connect response envelope: %w", err)
	}
	if flags&connectFlagCompressed != 0 {
		return nil, fmt.Errorf("connect: compressed stream envelopes were not negotiated")
	}
	if flags&^(connectFlagCompressed|connectFlagEndStream) != 0 {
		return nil, fmt.Errorf("connect: unsupported stream envelope flags 0x%02x", flags)
	}
	if flags&connectFlagEndStream != 0 {
		var endStream connectEndStream
		if err := json.Unmarshal(payload, &endStream); err != nil {
			return nil, fmt.Errorf("decode Connect end-stream envelope: %w", err)
		}
		// The end-stream envelope must be the final protocol message. Reading to
		// HTTP EOF both rejects trailing bytes and materializes HTTP trailers.
		if _, err := readConnectBody(response.Body, 0); err != nil {
			return nil, fmt.Errorf("read after Connect end-stream envelope: %w", err)
		}
		stream.responseEnded = true
		stream.setResponseTrailer(
			mergeMetadata(cloneMetadata(response.Trailer), endStream.Metadata),
		)
		_ = stream.CloseRequest()
		if endStream.Error != nil {
			return nil, connectErrorFromPayload(
				endStream.Error,
				http.StatusOK,
				stream.ResponseTrailer(),
			)
		}
		return nil, io.EOF
	}
	var message Response
	if err := json.Unmarshal(payload, &message); err != nil {
		return nil, fmt.Errorf("decode Connect response message: %w", err)
	}
	return &message, nil
}

func (stream *connectBidiStream[Request, Response]) CloseResponse() error {
	stream.closeResponseOnce.Do(func() {
		// Cancellation closes the transport's request reader and guarantees a
		// concurrent blocked Send can release sendMu before the writer is closed.
		stream.cancel()
		if err := stream.CloseRequest(); err != nil {
			stream.closeResponseErr = err
		}
		response, responseErr := stream.awaitResponse()
		if response != nil {
			if err := response.Body.Close(); err != nil && stream.closeResponseErr == nil {
				stream.closeResponseErr = err
			}
		}
		if responseErr != nil && stream.closeResponseErr == nil && stream.ctx.Err() == nil {
			stream.closeResponseErr = responseErr
		}
	})
	return stream.closeResponseErr
}
'''.strip().splitlines()
    )

    for service_name, methods in services:
        implementation = service_name[:1].lower() + service_name[1:] + "HTTPClient"
        clients.extend(
            [
                "",
                f"type {implementation} struct {{",
                "\ttransport *connectHTTPClient",
                "}",
                "",
                f"func New{service_name}Client(baseURL string, httpClient *http.Client) ({service_name}Client, error) {{",
                "\ttransport, err := newConnectHTTPClient(baseURL, httpClient)",
                "\tif err != nil {",
                "\t\treturn nil, err",
                "\t}",
                f"\treturn &{implementation}{{transport: transport}}, nil",
                "}",
                "",
            ]
        )
        for method, request_stream, request_type, response_stream, response_type in methods:
            request_name = request_type.split(".")[-1]
            response_name = response_type.split(".")[-1]
            procedure = f"/{proto_package}.{service_name}/{method}"
            if request_stream or response_stream:
                stream_name = f"{service_name}{method}Client"
                clients.extend(
                    [
                        f"func (client *{implementation}) {method}(ctx context.Context, header Metadata) ({stream_name}, error) {{",
                        f"\treturn newConnectBidiStream[{request_name}, {response_name}](",
                        "\t\tctx,",
                        "\t\tclient.transport,",
                        f'\t\t"{procedure}",',
                        "\t\theader,",
                        "\t)",
                        "}",
                        "",
                    ]
                )
            else:
                clients.extend(
                    [
                        f"func (client *{implementation}) {method}(ctx context.Context, request *RPCRequest[{request_name}]) (*RPCResponse[{response_name}], error) {{",
                        f"\treturn callConnectUnary[{request_name}, {response_name}](",
                        "\t\tctx,",
                        "\t\tclient.transport,",
                        f'\t\t"{procedure}",',
                        "\t\trequest,",
                        "\t)",
                        "}",
                        "",
                    ]
                )
    transport_tests = r'''
// Code generated by internal/contracts/codegen/generate.py from cell.proto; DO NOT EDIT.
package cellv1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func metadataValue(metadata Metadata, key string) string {
	for candidate, values := range metadata {
		if strings.EqualFold(candidate, key) && len(values) != 0 {
			return values[0]
		}
	}
	return ""
}

type handlerRoundTripper struct {
	handler http.Handler
}

func (transport handlerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	serverRequest := httptest.NewRequest(request.Method, request.URL.String(), request.Body)
	serverRequest.Header = request.Header.Clone()
	serverRequest = serverRequest.WithContext(request.Context())
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, serverRequest)
	response := recorder.Result()
	response.Request = request
	return response, nil
}

func handlerHTTPClient(handler http.Handler) *http.Client {
	return &http.Client{Transport: handlerRoundTripper{handler: handler}}
}

func TestCellProtoJSONNamesAndOneofStrictness(t *testing.T) {
	encoded, err := json.Marshal(&RenewResponse{
		Context:   &EnvelopeContext{WorkspaceID: "workspace", CellGeneration: 4},
		RequestID: "request",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{
		[]byte(`"workspaceId":"workspace"`),
		[]byte(`"cellGeneration":"4"`),
		[]byte(`"requestId":"request"`),
	} {
		if !bytes.Contains(encoded, expected) {
			t.Fatalf("ProtoJSON output %s does not contain %s", encoded, expected)
		}
	}
	if bytes.Contains(encoded, []byte("workspace_id")) || bytes.Contains(encoded, []byte("request_id")) {
		t.Fatalf("ProtoJSON output retained proto field spelling: %s", encoded)
	}

	var compatibility RenewResponse
	if err := json.Unmarshal(
		[]byte(`{"context":{"workspace_id":"workspace"},"request_id":"request"}`),
		&compatibility,
	); err != nil {
		t.Fatalf("protobuf parsers must accept original proto field spellings: %v", err)
	}
	if compatibility.Context == nil || compatibility.Context.WorkspaceID != "workspace" || compatibility.RequestID != "request" {
		t.Fatalf("compatibility spelling decoded incorrectly: %#v", compatibility)
	}
	if err := json.Unmarshal(
		[]byte(`{"context":{"workspaceId":"workspace","unknownField":true},"requestId":"request"}`),
		&compatibility,
	); err == nil {
		t.Fatal("unknown nested ProtoJSON field was accepted")
	}

	var frame SupervisorFrame
	if err := json.Unmarshal(
		[]byte(`{"context":{"workspaceId":"workspace"},"heartbeat":{"livenessState":"healthy"}}`),
		&frame,
	); err != nil {
		t.Fatalf("standard lowerCamel ProtoJSON frame was rejected: %v", err)
	}
	heartbeat, ok := frame.Frame.(*SupervisorFrameHeartbeat)
	if !ok || heartbeat.Heartbeat == nil || heartbeat.Heartbeat.LivenessState != "healthy" {
		t.Fatalf("standard lowerCamel frame decoded incorrectly: %#v", frame.Frame)
	}
	if err := json.Unmarshal(
		[]byte(`{"context":{"workspace_id":"workspace"},"cell_hello":{"release_unit_id":"release"}}`),
		&frame,
	); err != nil {
		t.Fatalf("original proto field compatibility spelling was rejected: %v", err)
	}
	encodedFrame, err := json.Marshal(&frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encodedFrame, []byte(`"cellHello"`)) || !bytes.Contains(encodedFrame, []byte(`"releaseUnitId"`)) {
		t.Fatalf("compatibility input was not normalized on output: %s", encodedFrame)
	}

	invalid := map[string]string{
		"missing variant":         `{"context":{"workspaceId":"workspace"}}`,
		"null variant":            `{"heartbeat":null}`,
		"multiple variants":       `{"heartbeat":{},"commandAck":{}}`,
		"unknown variant":         `{"notAFrame":{}}`,
		"duplicate variant":       `{"heartbeat":{},"heartbeat":{}}`,
		"duplicate variant alias": `{"cellHello":{},"cell_hello":{}}`,
	}
	for name, payload := range invalid {
		t.Run(name, func(t *testing.T) {
			var invalidFrame SupervisorFrame
			if err := json.Unmarshal([]byte(payload), &invalidFrame); err == nil {
				t.Fatalf("invalid oneof payload was accepted: %s", payload)
			}
		})
	}
	if _, err := json.Marshal(&SupervisorFrame{Context: &EnvelopeContext{WorkspaceID: "workspace"}}); err == nil {
		t.Fatal("SupervisorFrame without a oneof variant was marshaled")
	}
}

func TestCellCertificateRecoveryConnectUnaryTransport(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", request.Method)
		}
		if request.URL.Path != "/jumpship.cell.v1.CellCertificateRecovery/Renew" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if request.Header.Get("Content-Type") != connectUnaryContentType || request.Header.Get("Accept") != connectUnaryContentType {
			t.Errorf("unary media types = %q / %q", request.Header.Get("Content-Type"), request.Header.Get("Accept"))
		}
		if request.Header.Get("Connect-Protocol-Version") != connectProtocolVersion {
			t.Errorf("Connect protocol version = %q", request.Header.Get("Connect-Protocol-Version"))
		}
		if request.Header.Get("X-Request-Metadata") != "present" {
			t.Errorf("request metadata was not forwarded")
		}
		payload, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if !bytes.Contains(payload, []byte(`"priorControlRegionEpoch":"7"`)) || bytes.Contains(payload, []byte("prior_control_region_epoch")) {
			t.Errorf("request is not standard ProtoJSON: %s", payload)
		}
		var decoded RenewRequest
		if err := json.Unmarshal(payload, &decoded); err != nil || decoded.PriorControlRegionEpoch != 7 {
			t.Errorf("decode request: value=%#v err=%v", decoded, err)
		}

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("X-Reply-Metadata", "present")
		writer.Header().Add("Trailer", "X-Reply-Trailer")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, `{"context":{"workspaceId":"workspace","cellGeneration":"8"},"requestId":"request","pollSecret":"secret"}`)
		writer.Header().Set("X-Reply-Trailer", "complete")
	})

	client, err := NewCellCertificateRecoveryClient(
		"https://jumpship.test",
		handlerHTTPClient(handler),
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Renew(context.Background(), &RPCRequest[RenewRequest]{
		Message: &RenewRequest{
			Context:                 &EnvelopeContext{WorkspaceID: "workspace"},
			PriorControlRegionEpoch: 7,
		},
		Header: Metadata{"X-Request-Metadata": {"present"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Message == nil || response.Message.RequestID != "request" || response.Message.Context == nil || response.Message.Context.CellGeneration != 8 {
		t.Fatalf("unexpected unary response: %#v", response.Message)
	}
	if metadataValue(response.Header, "X-Reply-Metadata") != "present" || metadataValue(response.Trailer, "X-Reply-Trailer") != "complete" {
		t.Fatalf("unary metadata not preserved: header=%v trailer=%v", response.Header, response.Trailer)
	}
}

func TestSupervisorControlConnectBidiTransport(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/jumpship.cell.v1.SupervisorControl/Connect" {
			http.Error(writer, "unexpected procedure", http.StatusNotFound)
			return
		}
		if request.Header.Get("Content-Type") != connectStreamContentType || request.Header.Get("Accept") != connectStreamContentType {
			t.Errorf("stream media types = %q / %q", request.Header.Get("Content-Type"), request.Header.Get("Accept"))
		}
		if request.Header.Get("Connect-Protocol-Version") != connectProtocolVersion || request.Header.Get("X-Stream-Metadata") != "present" {
			t.Errorf("stream protocol headers were not forwarded")
		}
		flags, payload, err := readConnectEnvelope(request.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if flags != 0 {
			t.Errorf("request envelope flags = 0x%02x, want 0", flags)
		}
		if !bytes.Contains(payload, []byte(`"cellHello"`)) || !bytes.Contains(payload, []byte(`"releaseUnitId"`)) || bytes.Contains(payload, []byte("cell_hello")) {
			t.Errorf("stream request is not standard ProtoJSON: %s", payload)
		}
		var requestFrame SupervisorFrame
		if err := json.Unmarshal(payload, &requestFrame); err != nil || !requestFrame.HasValidFrame() {
			t.Errorf("decode request frame: value=%#v err=%v", requestFrame, err)
		}

		writer.Header().Set("Content-Type", "application/connect+json; charset=utf-8")
		writer.Header().Set("X-Stream-Reply", "present")
		writer.Header().Add("Trailer", "X-HTTP-Trailer")
		writer.WriteHeader(http.StatusOK)
		messageEnvelope, err := encodeConnectEnvelope(
			0,
			[]byte(`{"context":{"workspaceId":"workspace"},"heartbeat":{"livenessState":"healthy"}}`),
		)
		if err != nil {
			t.Errorf("encode response envelope: %v", err)
			return
		}
		if _, err := writer.Write(messageEnvelope); err != nil {
			t.Errorf("write response envelope: %v", err)
			return
		}
		endEnvelope, err := encodeConnectEnvelope(
			connectFlagEndStream,
			[]byte(`{"metadata":{"X-End":["complete"]}}`),
		)
		if err != nil {
			t.Errorf("encode end-stream envelope: %v", err)
			return
		}
		if _, err := writer.Write(endEnvelope); err != nil {
			t.Errorf("write end-stream envelope: %v", err)
			return
		}
		writer.Header().Set("X-HTTP-Trailer", "transport-complete")
	})

	client, err := NewSupervisorControlClient(
		"https://jumpship.test",
		handlerHTTPClient(handler),
	)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.Connect(
		context.Background(),
		Metadata{"X-Stream-Metadata": {"present"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&SupervisorFrame{
		Context: &EnvelopeContext{WorkspaceID: "workspace"},
		Frame: &SupervisorFrameCellHello{
			CellHello: &CellHello{ReleaseUnitID: "release"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseRequest(); err != nil {
		t.Fatal(err)
	}
	header, err := stream.ResponseHeader()
	if err != nil {
		t.Fatal(err)
	}
	if metadataValue(header, "X-Stream-Reply") != "present" {
		t.Fatalf("stream response metadata not preserved: %v", header)
	}
	response, err := stream.Receive()
	if err != nil {
		t.Fatal(err)
	}
	heartbeat, ok := response.Frame.(*SupervisorFrameHeartbeat)
	if !ok || heartbeat.Heartbeat == nil || heartbeat.Heartbeat.LivenessState != "healthy" {
		t.Fatalf("unexpected stream response: %#v", response.Frame)
	}
	if _, err := stream.Receive(); !errors.Is(err, io.EOF) {
		t.Fatalf("end-stream Receive error = %v, want EOF", err)
	}
	trailer := stream.ResponseTrailer()
	if metadataValue(trailer, "X-End") != "complete" || metadataValue(trailer, "X-HTTP-Trailer") != "transport-complete" {
		t.Fatalf("stream trailers not preserved: %v", trailer)
	}
	if err := stream.CloseResponse(); err != nil {
		t.Fatal(err)
	}
}
'''
    return {
        "internal/contracts/cell/v1/cell.types.gen.go": text_artifact("\n".join(types), "text/x-go"),
        "internal/contracts/cell/v1/cell.connect.gen.go": text_artifact("\n".join(clients), "text/x-go"),
        "internal/contracts/cell/v1/cell.connect.gen_test.go": text_artifact(transport_tests, "text/x-go"),
    }


def render_protocol_clients(artifacts: dict[str, Artifact]) -> dict[str, Artifact]:
    openapi_path = "contracts/openapi/openapi.yaml"
    proto_path = "contracts/proto/jumpship/cell/v1/cell.proto"
    if openapi_path not in artifacts or proto_path not in artifacts:
        raise ValueError("P02 API and cell protocol sources are required")
    openapi = json.loads(artifacts[openapi_path].content)
    proto = artifacts[proto_path].content.decode("utf-8")
    return {**render_openapi_clients(openapi), **render_cell_clients(proto)}


def validate_typescript_surface(artifacts: dict[str, Artifact]) -> None:
    modules = {
        path: artifact.content.decode("utf-8")
        for path, artifact in artifacts.items()
        if artifact.media_type == "text/typescript"
    }
    exports = {
        path: set(
            re.findall(
                r"(?m)^export\s+(?:(?:abstract|async)\s+)?(?:class|const|enum|function|interface|type)\s+(\w+)",
                source,
            )
        )
        for path, source in modules.items()
    }

    def local_target(source_path: str, reference: str) -> str:
        if not reference.startswith("./") or ".." in PurePosixPath(reference).parts:
            raise ValueError(
                f"generated TypeScript import must be same-directory relative: {source_path} -> {reference}"
            )
        return str(PurePosixPath(source_path).parent / reference[2:])

    for path, source in sorted(modules.items()):
        for names, reference in re.findall(
            r'import\s+(?:type\s+)?\{([^}]+)\}\s+from\s+"([^"]+)"',
            source,
            re.S,
        ):
            if not reference.startswith("."):
                continue
            target = local_target(path, reference)
            if target not in modules:
                raise ValueError(
                    f"generated TypeScript import target is missing: {path} -> {target}"
                )
            imported = {
                item.strip()
                .removeprefix("type ")
                .split(" as ", 1)[0]
                .strip()
                for item in names.split(",")
                if item.strip()
            }
            missing = sorted(imported - exports[target])
            if missing:
                raise ValueError(
                    f"generated TypeScript import references missing exports in {target}: {missing}"
                )

        star_targets = [
            local_target(path, reference)
            for reference in re.findall(
                r'(?m)^export\s+\*\s+from\s+"([^"]+)"\s*;', source
            )
        ]
        owners: dict[str, str] = {}
        for target in star_targets:
            if target not in modules:
                raise ValueError(
                    f"generated TypeScript barrel target is missing: {path} -> {target}"
                )
            for name in exports[target]:
                if name in owners:
                    raise ValueError(
                        f"ambiguous generated TypeScript barrel export {name}: {owners[name]} and {target}"
                    )
                owners[name] = target

        completed = subprocess.run(
            [
                "node",
                "--no-warnings",
                "-e",
                'const fs=require("node:fs");const {stripTypeScriptTypes}=require("node:module");stripTypeScriptTypes(fs.readFileSync(0,"utf8"));',
            ],
            input=source.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"generated TypeScript does not compile: {path}: {detail}")


def _schema_assertions(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _schema_assertions(child)
            for key, child in sorted(value.items())
            if key not in SCHEMA_ANNOTATIONS and not key.startswith("x-")
        }
    if isinstance(value, list):
        return [_schema_assertions(child) for child in value]
    return value


def _proto_surface(proto: str) -> dict[str, Any]:
    enums: dict[str, dict[str, int]] = {}
    for match in re.finditer(r"enum\s+(\w+)\s*\{(.*?)\n\}", proto, re.S):
        name, body = match.groups()
        enums[name] = {
            entry: int(number)
            for entry, number in re.findall(
                r"(?m)^\s*(\w+)\s*=\s*(\d+)\s*;", body
            )
        }

    messages: dict[str, dict[str, Any]] = {}
    field_pattern = r"(?m)^\s*(?:(repeated|optional)\s+)?(map<[^>]+>|[.A-Za-z_][.A-Za-z0-9_]*)\s+(\w+)\s*=\s*(\d+)\s*;"
    for match in re.finditer(r"message\s+(\w+)\s*\{(.*?)\n\}", proto, re.S):
        name, body = match.groups()
        oneof_numbers: dict[str, str] = {}
        for oneof in re.finditer(r"oneof\s+(\w+)\s*\{(.*?)\n\s*\}", body, re.S):
            oneof_name, oneof_body = oneof.groups()
            for _, _, _, number in re.findall(field_pattern, oneof_body):
                oneof_numbers[number] = oneof_name
        messages[name] = {
            number: {
                "name": field,
                "type": proto_type,
                "qualifier": qualifier or "singular",
                "oneof": oneof_numbers.get(number),
            }
            for qualifier, proto_type, field, number in re.findall(
                field_pattern, body
            )
        }

    services: dict[str, dict[str, Any]] = {}
    for match in re.finditer(r"service\s+(\w+)\s*\{(.*?)\n\}", proto, re.S):
        name, body = match.groups()
        services[name] = {
            method: {
                "request": request_type,
                "request_stream": bool(request_stream),
                "response": response_type,
                "response_stream": bool(response_stream),
            }
            for method, request_stream, request_type, response_stream, response_type in re.findall(
                r"rpc\s+(\w+)\s*\(\s*(stream\s+)?([.\w]+)\s*\)\s+returns\s*\(\s*(stream\s+)?([.\w]+)\s*\)\s*;",
                body,
            )
        }
    package = re.search(r"(?m)^package\s+([.\w]+)\s*;", proto)
    syntax = re.search(r'(?m)^syntax\s*=\s*"([^"]+)"\s*;', proto)
    return {
        "syntax": syntax.group(1) if syntax else None,
        "package": package.group(1) if package else None,
        "enums": enums,
        "messages": messages,
        "services": services,
    }


def _openapi_surface(document: dict[str, Any]) -> dict[str, Any]:
    operations: dict[str, Any] = {}
    for path, path_item in sorted(document.get("paths", {}).items()):
        for method, operation in sorted(path_item.items()):
            if method not in {"delete", "get", "head", "options", "patch", "post", "put", "trace"}:
                continue
            operations[f"{method.upper()} {path}"] = {
                key: copy.deepcopy(operation[key])
                for key in (
                    "callbacks",
                    "deprecated",
                    "operationId",
                    "parameters",
                    "requestBody",
                    "responses",
                    "security",
                    "x-jumpship-policy",
                )
                if key in operation
            }
    return {
        "version": document.get("openapi"),
        "servers": copy.deepcopy(document.get("servers", [])),
        "operations": operations,
        "components": copy.deepcopy(document.get("components", {})),
    }


def _compatibility_surface(artifacts: dict[str, Artifact]) -> dict[str, Any]:
    schemas: dict[str, Any] = {}
    for path, artifact in sorted(artifacts.items()):
        if not path.endswith(".schema.json"):
            continue
        assertions = _schema_assertions(json.loads(artifact.content))
        schemas[path] = {
            "root": {
                key: value
                for key, value in assertions.items()
                if key != "properties"
            },
            "properties": assertions.get("properties", {}),
        }
    openapi = json.loads(artifacts["contracts/openapi/openapi.yaml"].content)
    proto = artifacts["contracts/proto/jumpship/cell/v1/cell.proto"].content.decode(
        "utf-8"
    )
    return {
        "json_schemas": schemas,
        "openapi": _openapi_surface(openapi),
        "protobuf": _proto_surface(proto),
    }


def _compare_exact_additive_map(
    label: str,
    baseline: dict[str, Any],
    current: dict[str, Any],
    changes: list[str],
    breaking: list[str],
    approved_replacements: dict[str, str] | None = None,
) -> None:
    for key in sorted(baseline.keys() - current.keys()):
        breaking.append(f"removed {label} {key}")
    for key in sorted(baseline.keys() & current.keys()):
        if baseline[key] != current[key]:
            authority = (approved_replacements or {}).get(key)
            if authority is None:
                breaking.append(f"changed {label} {key}")
            else:
                changes.append(f"approved replacement of {label} {key} under {authority}")
    for key in sorted(current.keys() - baseline.keys()):
        changes.append(f"added {label} {key}")


def _compare_compatibility(
    baseline: dict[str, Any], current: dict[str, Any]
) -> tuple[list[str], list[str]]:
    changes: list[str] = []
    breaking: list[str] = []

    old_schemas = baseline.get("json_schemas", {})
    new_schemas = current.get("json_schemas", {})
    for path in sorted(old_schemas.keys() - new_schemas.keys()):
        breaking.append(f"removed JSON Schema {path}")
    for path in sorted(new_schemas.keys() - old_schemas.keys()):
        changes.append(f"added JSON Schema {path}")
    for path in sorted(old_schemas.keys() & new_schemas.keys()):
        old_schema = old_schemas[path]
        new_schema = new_schemas[path]
        if old_schema.get("root") != new_schema.get("root"):
            replacement = APPROVED_VERSIONED_SCHEMA_REPLACEMENTS.get(path)
            old_version = old_schema.get("properties", {}).get("schema_version", {}).get("const")
            new_version = new_schema.get("properties", {}).get("schema_version", {}).get("const")
            if replacement is None or old_version != replacement["from"] or new_version != replacement["to"]:
                breaking.append(f"changed JSON Schema assertions {path}")
                continue
            changes.append(
                f"approved versioned replacement of JSON Schema {path} "
                f"{old_version}->{new_version} under {replacement['authority']}"
            )
            continue
        _compare_exact_additive_map(
            f"optional property in {path}",
            old_schema.get("properties", {}),
            new_schema.get("properties", {}),
            changes,
            breaking,
        )

    old_openapi = baseline.get("openapi", {})
    new_openapi = current.get("openapi", {})
    if old_openapi.get("version") != new_openapi.get("version"):
        breaking.append("changed OpenAPI version")
    if old_openapi.get("servers") != new_openapi.get("servers"):
        breaking.append("changed OpenAPI servers")
    _compare_exact_additive_map(
        "OpenAPI operation",
        old_openapi.get("operations", {}),
        new_openapi.get("operations", {}),
        changes,
        breaking,
    )
    old_components = old_openapi.get("components", {})
    new_components = new_openapi.get("components", {})
    for category in sorted(old_components.keys() | new_components.keys()):
        old_category = old_components.get(category, {})
        new_category = new_components.get(category, {})
        if not isinstance(old_category, dict) or not isinstance(new_category, dict):
            if old_category != new_category:
                breaking.append(f"changed OpenAPI component category {category}")
            continue
        _compare_exact_additive_map(
            f"OpenAPI {category} component",
            old_category,
            new_category,
            changes,
            breaking,
            APPROVED_OPENAPI_COMPONENT_REPLACEMENTS if category == "schemas" else None,
        )

    old_proto = baseline.get("protobuf", {})
    new_proto = current.get("protobuf", {})
    for key in ("syntax", "package"):
        if old_proto.get(key) != new_proto.get(key):
            breaking.append(f"changed protobuf {key}")
    for category, member_label in (
        ("enums", "enum value"),
        ("messages", "field number"),
        ("services", "RPC method"),
    ):
        old_groups = old_proto.get(category, {})
        new_groups = new_proto.get(category, {})
        for group in sorted(old_groups.keys() - new_groups.keys()):
            breaking.append(f"removed protobuf {category[:-1]} {group}")
        for group in sorted(new_groups.keys() - old_groups.keys()):
            changes.append(f"added protobuf {category[:-1]} {group}")
        for group in sorted(old_groups.keys() & new_groups.keys()):
            _compare_exact_additive_map(
                f"protobuf {member_label} in {group}",
                old_groups[group],
                new_groups[group],
                changes,
                breaking,
            )
    return changes, breaking


def render_compatibility_artifacts(
    artifacts: dict[str, Artifact], *, refresh_baseline: bool = False
) -> dict[str, Artifact]:
    current_surface = _compatibility_surface(artifacts)
    baseline_file = REPO_ROOT / COMPATIBILITY_BASELINE_PATH
    existing: dict[str, Any] | None = None
    if baseline_file.exists():
        if not baseline_file.is_file() or baseline_file.is_symlink():
            raise ValueError("compatibility baseline must be a regular file")
        existing = json.loads(baseline_file.read_bytes())
        if existing.get("kind") != "jumpship-contract-compatibility-baseline":
            raise ValueError("invalid compatibility baseline kind")
        if not isinstance(existing.get("surface"), dict):
            raise ValueError("compatibility baseline is missing its surface")

    if existing is None:
        changes: list[str] = []
        breaking: list[str] = []
        baseline_surface = current_surface
        status = "compatible_unchanged"
    else:
        changes, breaking = _compare_compatibility(
            existing["surface"], current_surface
        )
        if breaking:
            detail = "\n".join(f"  - {item}" for item in breaking)
            raise ValueError(
                "breaking contract compatibility change; retain the v1 surface or add a versioned path:\n"
                + detail
            )
        if refresh_baseline:
            baseline_surface = current_surface
            changes = []
            status = "compatible_unchanged"
        else:
            baseline_surface = existing["surface"]
            status = "compatible_additive" if changes else "compatible_unchanged"

    baseline = {
        "_generated": f"generated by {GENERATOR}; DO NOT EDIT",
        "schema_version": "1.0.0",
        "kind": "jumpship-contract-compatibility-baseline",
        "policy": "Existing assertions, operations, component definitions, protobuf field numbers, enum values, and RPC methods are immutable in v1; optional additions are permitted. The only approved replacement is the P02-CATALOG-RU-HASH-CYCLE catalog 1.0.0 to 2.0.0 correction and its two API response components.",
        "surface": baseline_surface,
    }
    baseline_surface_hash = hashlib.sha256(json_bytes(baseline_surface)).hexdigest()
    current_surface_hash = hashlib.sha256(json_bytes(current_surface)).hexdigest()
    report = {
        "_generated": f"generated by {GENERATOR}; DO NOT EDIT",
        "schema_version": "1.0.0",
        "kind": "jumpship-contract-compatibility-report",
        "status": status,
        "compatible": True,
        "baseline_surface_sha256": baseline_surface_hash,
        "current_surface_sha256": current_surface_hash,
        "changes": changes,
        "breaking_changes": [],
    }
    return {
        COMPATIBILITY_BASELINE_PATH: json_artifact(baseline, "application/json"),
        COMPATIBILITY_REPORT_PATH: json_artifact(report, "application/json"),
    }


def collect_artifacts(*, refresh_compatibility_baseline: bool = False) -> dict[str, Artifact]:
    from application_api_contracts import artifacts as application_artifacts
    from client_templates import artifacts as client_artifacts
    from core_contracts import artifacts as core_artifacts
    from quality_release_contracts import artifacts as quality_artifacts

    result: dict[str, Artifact] = {}
    for producer in (core_artifacts, application_artifacts, quality_artifacts, client_artifacts):
        for path, artifact in producer().items():
            if path in result:
                raise ValueError(f"duplicate generated artifact: {path}")
            result[path] = artifact
    schemas: dict[str, dict[str, Any]] = {}
    for path, artifact in result.items():
        if path.endswith(".schema.json"):
            schemas[path] = json.loads(artifact.content)
    for path, artifact in render_generated_types(schemas).items():
        if path in result:
            raise ValueError(f"duplicate generated artifact: {path}")
        result[path] = artifact
    result["contracts/fixtures/schema-corpus.json"] = render_schema_corpus(schemas)
    for path, artifact in render_protocol_clients(result).items():
        if path not in result:
            result[path] = artifact
    validate_typescript_surface(result)
    for path, artifact in render_compatibility_artifacts(
        result, refresh_baseline=refresh_compatibility_baseline
    ).items():
        if path in result:
            raise ValueError(f"duplicate generated artifact: {path}")
        result[path] = artifact

    # Generated Go is part of the repository's public contract surface. Format
    # it before hashing so ``make gen``, ``make gen-check`` and ``make fmt`` all
    # compare the same canonical bytes produced by the pinned Go toolchain.
    for path, artifact in list(result.items()):
        if artifact.media_type != "text/x-go":
            continue
        completed = subprocess.run(
            ["gofmt"],
            input=artifact.content,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"gofmt failed for {path}: {detail}")
        result[path] = Artifact(completed.stdout, artifact.media_type)

    manifest_records = []
    for path, artifact in sorted(result.items()):
        manifest_records.append(
            {
                "path": path,
                "media_type": artifact.media_type,
                "sha256": hashlib.sha256(artifact.content).hexdigest(),
            }
        )
    library_sources = []
    canonical_directory = REPO_ROOT / "internal/contracts/canonical"
    for source in sorted(canonical_directory.glob("*.go")):
        if (
            source.name.endswith(("_test.go", ".gen.go"))
            or source.is_symlink()
        ):
            continue
        relative = source.relative_to(REPO_ROOT).as_posix()
        library_sources.append(
            {
                "path": relative,
                "media_type": "text/x-go",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }
        )
    if not library_sources:
        raise ValueError("canonical Go library sources are missing")
    result["contracts/contract-manifest.json"] = json_artifact(
        {
            "_generated": f"generated by {GENERATOR}; DO NOT EDIT",
            "schema_version": "1.0.0",
            "kind": "jumpship-contract-freeze",
            "canonicalization": "RFC8785-JCS",
            "typed_digest_domain": "jumpship:<object-type>:<schema-version>\\u0000",
            "compatibility_policy": "additive changes remain in v1; breaking changes require a versioned path and fixture migration",
            "change_request": {
                "required_reviews": ["contract-owner", "affected-consumer-owner", "security-owner"],
                "required_evidence": ["compatibility-report", "generated-diff", "replay-fixture-update"],
            },
            "artifacts": manifest_records,
            "library_sources": library_sources,
        },
        "application/json",
    )
    return result


def _safe_destination(relative: str) -> Path:
    if relative.startswith("/") or ".." in Path(relative).parts:
        raise ValueError(f"unsafe generated path: {relative}")
    if not relative.startswith(ALLOWED_PREFIXES):
        raise ValueError(f"generated path outside P02 ownership: {relative}")
    destination = REPO_ROOT / relative
    resolved_parent = destination.parent.resolve()
    resolved_parent.relative_to(REPO_ROOT.resolve())
    return destination


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="reject missing or stale generated outputs")
    parser.add_argument("--list", action="store_true", help="print the generated path inventory")
    parser.add_argument(
        "--refresh-compatibility-baseline",
        action="store_true",
        help="advance the checked-in baseline after a compatible reviewed addition",
    )
    arguments = parser.parse_args()
    if arguments.check and arguments.refresh_compatibility_baseline:
        parser.error("--check cannot refresh the compatibility baseline")
    artifacts = collect_artifacts(
        refresh_compatibility_baseline=arguments.refresh_compatibility_baseline
    )
    if arguments.list:
        print("\n".join(sorted(artifacts)))
        return 0
    stale: list[str] = []
    for relative, artifact in sorted(artifacts.items()):
        destination = _safe_destination(relative)
        actual = destination.read_bytes() if destination.is_file() and not destination.is_symlink() else None
        if actual != artifact.content:
            stale.append(relative)
            if not arguments.check:
                _write_atomic(destination, artifact.content)
    if arguments.check and stale:
        print("generated contract drift; run internal/contracts/codegen/generate.py:", file=sys.stderr)
        for path in stale:
            print(f"  {path}", file=sys.stderr)
        return 1
    action = "verified" if arguments.check else "generated"
    print(f"P02 contracts {action}: {len(artifacts)} artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
