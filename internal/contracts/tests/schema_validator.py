"""Small, strict Draft 2020-12 validator for the P02 contract keyword set.

This is deliberately not a general replacement for a standards package.  It
implements every keyword permitted by P02 and fails closed when a generated
schema uses an unsupported assertion keyword.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any


Schema = dict[str, Any] | bool


class ValidationError(ValueError):
    pass


ASSERTION_KEYWORDS = {
    "$ref",
    "type",
    "const",
    "enum",
    "required",
    "properties",
    "additionalProperties",
    "patternProperties",
    "propertyNames",
    "minProperties",
    "maxProperties",
    "items",
    "prefixItems",
    "minItems",
    "maxItems",
    "uniqueItems",
    "contains",
    "minContains",
    "maxContains",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "pattern",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "if",
    "then",
    "else",
    "dependentRequired",
}

ANNOTATION_KEYWORDS = {
    "$comment",
    "$id",
    "$schema",
    "$defs",
    "title",
    "description",
    "default",
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
    "format",
    "contentEncoding",
    "contentMediaType",
}

SCHEMA_MAP_KEYWORDS = {"$defs", "properties", "patternProperties"}
SCHEMA_LIST_KEYWORDS = {"allOf", "anyOf", "oneOf", "prefixItems"}
SCHEMA_VALUE_KEYWORDS = {
    "additionalProperties",
    "contains",
    "else",
    "if",
    "items",
    "not",
    "propertyNames",
    "then",
}


@dataclass(frozen=True)
class Registry:
    by_id: dict[str, dict[str, Any]]

    def __post_init__(self) -> None:
        for identifier, document in self.by_id.items():
            if not isinstance(document, dict):
                raise ValidationError(f"registry document {identifier!r} is not an object schema")
            if document.get("$id") != identifier:
                raise ValidationError(f"registry key does not match schema $id: {identifier!r}")
            _validate_schema_definition(document, f"schema<{identifier}>")

    def resolve(self, reference: str, root: dict[str, Any]) -> Schema:
        if reference.startswith("#"):
            document = root
            fragment = reference[1:]
        else:
            base, marker, fragment = reference.partition("#")
            if base not in self.by_id:
                raise ValidationError(f"unknown schema reference {reference}")
            document = self.by_id[base]
            fragment = fragment if marker else ""
        if not fragment:
            return document
        if not fragment.startswith("/"):
            raise ValidationError(f"unsupported schema fragment {reference}")
        current: Any = document
        for token in fragment[1:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            current = current[token]
        if not isinstance(current, (dict, bool)):
            raise ValidationError(f"reference does not resolve to a schema: {reference}")
        return current


def validate(instance: Any, schema: Schema, registry: Registry, root: Schema | None = None, path: str = "$") -> None:
    if schema is True:
        return
    if schema is False:
        raise ValidationError(f"{path}: rejected by false schema")
    if root is None:
        _validate_schema_definition(schema, "$schema")
        root = schema
    if "$ref" in schema:
        reference = schema["$ref"]
        if not isinstance(root, dict):
            raise ValidationError(f"{path}: cannot resolve a reference from a boolean root")
        resolved = registry.resolve(reference, root)
        resolved_root: Schema = (
            root
            if reference.startswith("#")
            else registry.by_id[reference.partition("#")[0]]
        )
        validate(instance, resolved, registry, resolved_root, path)
    if "allOf" in schema:
        for child in schema["allOf"]:
            validate(instance, child, registry, root, path)
    if "anyOf" in schema:
        if not any(_valid(instance, child, registry, root, path) for child in schema["anyOf"]):
            raise ValidationError(f"{path}: no anyOf branch matched")
    if "oneOf" in schema:
        count = sum(_valid(instance, child, registry, root, path) for child in schema["oneOf"])
        if count != 1:
            raise ValidationError(f"{path}: expected exactly one oneOf match, got {count}")
    if "not" in schema and _valid(instance, schema["not"], registry, root, path):
        raise ValidationError(f"{path}: forbidden by not")
    if "if" in schema:
        selected = schema.get("then") if _valid(instance, schema["if"], registry, root, path) else schema.get("else")
        if selected is not None:
            validate(instance, selected, registry, root, path)
    if "const" in schema and not _json_equal(instance, schema["const"]):
        raise ValidationError(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and not any(_json_equal(instance, candidate) for candidate in schema["enum"]):
        raise ValidationError(f"{path}: value is outside enum")
    if "type" in schema:
        _validate_type(instance, schema["type"], path)
    if isinstance(instance, dict):
        _validate_object(instance, schema, registry, root, path)
    elif isinstance(instance, list):
        _validate_array(instance, schema, registry, root, path)
    elif isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0) or len(instance) > schema.get("maxLength", math.inf):
            raise ValidationError(f"{path}: string length out of range")
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            raise ValidationError(f"{path}: string does not match pattern")
    elif isinstance(instance, (int, float)) and not isinstance(instance, bool):
        _validate_number(instance, schema, path)


def _valid(instance: Any, schema: Schema, registry: Registry, root: Schema, path: str) -> bool:
    try:
        validate(instance, schema, registry, root, path)
        return True
    except (ValidationError, KeyError, TypeError):
        return False


def _validate_schema_definition(schema: Any, path: str) -> None:
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise ValidationError(f"{path}: schema must be an object or boolean")
    supported = ASSERTION_KEYWORDS | ANNOTATION_KEYWORDS
    unknown = sorted(
        key for key in schema if key not in supported and not key.startswith("x-")
    )
    if unknown:
        raise ValidationError(f"{path}: unsupported schema keywords {unknown}")

    if "$ref" in schema and not isinstance(schema["$ref"], str):
        raise ValidationError(f"{path}.$ref: expected string")
    if "type" in schema:
        declared = schema["type"]
        types = [declared] if isinstance(declared, str) else declared
        allowed_types = {
            "array",
            "boolean",
            "integer",
            "null",
            "number",
            "object",
            "string",
        }
        if (
            not isinstance(types, list)
            or not types
            or not all(isinstance(value, str) for value in types)
            or len(types) != len(set(types))
            or any(value not in allowed_types for value in types)
        ):
            raise ValidationError(f"{path}.type: invalid JSON Schema type declaration")
    if "enum" in schema:
        values = schema["enum"]
        if not isinstance(values, list) or not values:
            raise ValidationError(f"{path}.enum: expected non-empty array")
        if any(
            any(_json_equal(value, prior) for prior in values[:index])
            for index, value in enumerate(values)
        ):
            raise ValidationError(f"{path}.enum: expected unique JSON values")
    if "required" in schema:
        required = schema["required"]
        if (
            not isinstance(required, list)
            or not all(isinstance(field, str) for field in required)
            or len(required) != len(set(required))
        ):
            raise ValidationError(f"{path}.required: expected unique string array")
    for keyword in (
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minProperties",
        "maxProperties",
        "minContains",
        "maxContains",
    ):
        if keyword in schema and (
            not isinstance(schema[keyword], int)
            or isinstance(schema[keyword], bool)
            or schema[keyword] < 0
        ):
            raise ValidationError(f"{path}.{keyword}: expected non-negative integer")
    for minimum, maximum in (
        ("minItems", "maxItems"),
        ("minLength", "maxLength"),
        ("minProperties", "maxProperties"),
        ("minContains", "maxContains"),
    ):
        if (
            minimum in schema
            and maximum in schema
            and schema[minimum] > schema[maximum]
        ):
            raise ValidationError(f"{path}: {minimum} exceeds {maximum}")
    for keyword in (
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
    ):
        if keyword in schema and (
            not isinstance(schema[keyword], (int, float))
            or isinstance(schema[keyword], bool)
            or not _finite_number(schema[keyword])
        ):
            raise ValidationError(f"{path}.{keyword}: expected finite number")
    if "multipleOf" in schema and schema["multipleOf"] <= 0:
        raise ValidationError(f"{path}.multipleOf: expected positive number")
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            raise ValidationError(f"{path}.pattern: expected string")
        try:
            re.compile(schema["pattern"])
        except re.error as error:
            raise ValidationError(f"{path}.pattern: invalid regular expression") from error
    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        raise ValidationError(f"{path}.uniqueItems: expected boolean")

    for keyword in SCHEMA_MAP_KEYWORDS:
        if keyword not in schema:
            continue
        children = schema[keyword]
        if not isinstance(children, dict):
            raise ValidationError(f"{path}.{keyword}: expected object")
        for name, child in children.items():
            _validate_schema_definition(child, f"{path}.{keyword}[{name!r}]")
    for keyword in SCHEMA_LIST_KEYWORDS:
        if keyword not in schema:
            continue
        children = schema[keyword]
        if not isinstance(children, list) or not children:
            raise ValidationError(f"{path}.{keyword}: expected non-empty schema array")
        for index, child in enumerate(children):
            _validate_schema_definition(child, f"{path}.{keyword}[{index}]")
    for keyword in SCHEMA_VALUE_KEYWORDS:
        if keyword in schema:
            _validate_schema_definition(schema[keyword], f"{path}.{keyword}")

    if "dependentRequired" in schema:
        dependencies = schema["dependentRequired"]
        if not isinstance(dependencies, dict) or any(
            not isinstance(fields, list)
            or not all(isinstance(field, str) for field in fields)
            or len(fields) != len(set(fields))
            for fields in dependencies.values()
        ):
            raise ValidationError(f"{path}.dependentRequired: expected unique string-array map")


def _json_equal(left: Any, right: Any) -> bool:
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right
    if isinstance(left, (int, float)) or isinstance(right, (int, float)):
        return (
            isinstance(left, (int, float))
            and not isinstance(left, bool)
            and isinstance(right, (int, float))
            and not isinstance(right, bool)
            and _finite_number(left)
            and _finite_number(right)
            and left == right
        )
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
            and all(_json_equal(a, b) for a, b in zip(left, right, strict=True))
        )
    if isinstance(left, dict) or isinstance(right, dict):
        return (
            isinstance(left, dict)
            and isinstance(right, dict)
            and left.keys() == right.keys()
            and all(_json_equal(left[key], right[key]) for key in left)
        )
    return type(left) is type(right) and left == right


def _finite_number(value: int | float) -> bool:
    return isinstance(value, int) or math.isfinite(value)


def _validate_type(instance: Any, expected: str | list[str], path: str) -> None:
    expected_values = [expected] if isinstance(expected, str) else expected
    checks = {
        "null": instance is None,
        "boolean": isinstance(instance, bool),
        "integer": (
            isinstance(instance, int)
            and not isinstance(instance, bool)
        ) or (
            isinstance(instance, float)
            and _finite_number(instance)
            and instance.is_integer()
        ),
        "number": isinstance(instance, (int, float)) and not isinstance(instance, bool) and _finite_number(instance),
        "string": isinstance(instance, str),
        "array": isinstance(instance, list),
        "object": isinstance(instance, dict),
    }
    if not any(checks.get(value, False) for value in expected_values):
        raise ValidationError(f"{path}: expected type {expected_values}, got {type(instance).__name__}")


def _validate_object(instance: dict[str, Any], schema: dict[str, Any], registry: Registry, root: dict[str, Any], path: str) -> None:
    required = schema.get("required", [])
    missing = [field for field in required if field not in instance]
    if missing:
        raise ValidationError(f"{path}: missing required fields {missing}")
    if len(instance) < schema.get("minProperties", 0) or len(instance) > schema.get("maxProperties", math.inf):
        raise ValidationError(f"{path}: property count out of range")
    properties = schema.get("properties", {})
    patterns = schema.get("patternProperties", {})
    for key, value in instance.items():
        matches = []
        if key in properties:
            matches.append(properties[key])
        matches.extend(child for pattern, child in patterns.items() if re.search(pattern, key))
        if not matches:
            additional = schema.get("additionalProperties", True)
            if additional is False:
                raise ValidationError(f"{path}: unknown property {key!r}")
            if isinstance(additional, dict):
                matches.append(additional)
        for child in matches:
            validate(value, child, registry, root, f"{path}.{key}")
    if "propertyNames" in schema:
        for key in instance:
            validate(key, schema["propertyNames"], registry, root, f"{path}.<name>")
    for key, dependencies in schema.get("dependentRequired", {}).items():
        if key in instance:
            missing_deps = [field for field in dependencies if field not in instance]
            if missing_deps:
                raise ValidationError(f"{path}: {key} requires {missing_deps}")


def _validate_array(instance: list[Any], schema: dict[str, Any], registry: Registry, root: dict[str, Any], path: str) -> None:
    if len(instance) < schema.get("minItems", 0) or len(instance) > schema.get("maxItems", math.inf):
        raise ValidationError(f"{path}: array length out of range")
    if schema.get("uniqueItems"):
        for index, value in enumerate(instance):
            if any(_json_equal(value, prior) for prior in instance[:index]):
                raise ValidationError(f"{path}: duplicate array item")
    prefix = schema.get("prefixItems", [])
    for index, child in enumerate(prefix):
        if index < len(instance):
            validate(instance[index], child, registry, root, f"{path}[{index}]")
    if "items" in schema:
        start = len(prefix)
        for index in range(start, len(instance)):
            validate(instance[index], schema["items"], registry, root, f"{path}[{index}]")
    if "contains" in schema:
        matches = sum(_valid(value, schema["contains"], registry, root, f"{path}[]") for value in instance)
        if matches < schema.get("minContains", 1) or matches > schema.get("maxContains", math.inf):
            raise ValidationError(f"{path}: contains count out of range")


def _validate_number(instance: int | float, schema: dict[str, Any], path: str) -> None:
    if instance < schema.get("minimum", -math.inf) or instance > schema.get("maximum", math.inf):
        raise ValidationError(f"{path}: number out of range")
    if "exclusiveMinimum" in schema and instance <= schema["exclusiveMinimum"]:
        raise ValidationError(f"{path}: number below exclusive minimum")
    if "exclusiveMaximum" in schema and instance >= schema["exclusiveMaximum"]:
        raise ValidationError(f"{path}: number above exclusive maximum")
    if "multipleOf" in schema and not math.isclose(instance / schema["multipleOf"], round(instance / schema["multipleOf"])):
        raise ValidationError(f"{path}: number is not a multiple")
