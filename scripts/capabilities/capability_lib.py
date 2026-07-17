#!/usr/bin/env python3
"""Shared, dependency-free capability-registry validation helpers."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unicodedata
from pathlib import Path
from typing import Any, Iterable


ANCHOR_ALGORITHM = "jumpship-capability-anchors-v1"
NUMBERED_RE = re.compile(r"^(?P<label>[0-9]+[a-z]?)\.\s+(?P<body>.+)$")
HEADING_RE = re.compile(r"^(?P<marks>#{2,4})\s+(?P<title>.+?)\s*$")
CAPABILITY_ID_RE = re.compile(r"^MVP-CAP-[A-Z0-9][A-Z0-9-]+$")
INCAPABILITY_ID_RE = re.compile(r"^MVP-INCAP-[A-Z0-9][A-Z0-9-]+$")
NUMBERED_ANCHOR_RE = re.compile(
    r"^numbered-list:(?P<label>[0-9]+[a-z]?):(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*)$"
)
ADDENDUM_ANCHOR_RE = re.compile(r"^addendum:[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?$")
AUTHORITY_ANCHOR_RE = re.compile(
    r"^(?:plan:[a-z0-9][a-z0-9-]*:[a-z0-9][a-z0-9-]*|adr:ADR-[0-9]{3})$"
)
RUBRIC_ID_RE = re.compile(r"^JSMVP-R(?P<number>[0-9]{3})$")


class CapabilityError(ValueError):
    """Raised when an accepted capability input is malformed."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def load_json_yaml(path: Path) -> Any:
    """Load the repository's JSON-compatible YAML without a third-party parser."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CapabilityError(f"cannot parse JSON-compatible YAML {path}: {exc}") from exc


def write_canonical_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))


def _strip_markdown(value: str) -> str:
    value = re.sub(r"`([^`]*)`", r"\1", value)
    value = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", value)
    value = value.replace("&", " and ")
    value = unicodedata.normalize("NFKD", value)
    return value.encode("ascii", "ignore").decode("ascii")


def slugify(value: str, *, limit_words: int | None = None) -> str:
    words = re.findall(r"[a-z0-9]+", _strip_markdown(value).lower())
    if limit_words is not None:
        words = words[:limit_words]
    slug = "-".join(words)
    if not slug:
        raise CapabilityError(f"cannot derive a stable slug from {value!r}")
    return slug


def source_plan_sha256(
    logical_source_version: str,
    source_sha256: str,
    planning_inputs: list[dict[str, str]],
) -> str:
    identity = {
        "logical_source_version": logical_source_version,
        "planning_inputs": planning_inputs,
        "source_sha256": source_sha256,
    }
    return sha256_bytes(
        json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )


def _section_end(lines: list[str], start: int, level: int) -> int:
    for index in range(start + 1, len(lines)):
        match = HEADING_RE.match(lines[index])
        if match and len(match.group("marks")) <= level:
            return index
    return len(lines)


def parse_living_source(path: Path) -> tuple[str, list[dict[str, Any]]]:
    """Return raw source hash and stable numbered/addendum anchors."""
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CapabilityError(f"living source is not UTF-8: {path}: {exc}") from exc
    lines = text.splitlines()
    addendum_start = next(
        (index for index, line in enumerate(lines) if line.startswith("## Addendum")),
        None,
    )
    if addendum_start is None:
        raise CapabilityError("living source has no binding addendum boundary")

    numbered_candidates: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines):
        match = NUMBERED_RE.match(line)
        if not match:
            continue
        numeric_label = int(re.match(r"[0-9]+", match.group("label")).group(0))
        # The numbered product list continues as 142..198 inside the first two
        # addenda. Later small numbered lists are prose structure, not product
        # capability occurrences.
        if index < addendum_start or numeric_label >= 142:
            numbered_candidates.append((index, match.group("label"), match.group("body")))
    if not numbered_candidates:
        raise CapabilityError("living source has no numbered capability occurrences")

    label_counts: dict[str, int] = {}
    for _index, label, _body in numbered_candidates:
        label_counts[label] = label_counts.get(label, 0) + 1
    seen_labels: dict[str, int] = {}
    used_ids: set[str] = set()
    anchors: list[dict[str, Any]] = []
    for index, label, body in numbered_candidates:
        seen_labels[label] = seen_labels.get(label, 0) + 1
        base_slug = slugify(body, limit_words=8)
        anchor_id = f"numbered-list:{label}:{base_slug}"
        if anchor_id in used_ids:
            anchor_id = f"{anchor_id}-{sha256_bytes(lines[index].encode('utf-8'))[:8]}"
        used_ids.add(anchor_id)
        anchors.append(
            {
                "anchor_id": anchor_id,
                "content_sha256": sha256_bytes((lines[index] + "\n").encode("utf-8")),
                "display": label,
                "kind": "numbered-list",
                "occurrence": seen_labels[label],
                "occurrence_count": label_counts[label],
                "source_line": index + 1,
                "title": body,
            }
        )

    heading_stack: dict[int, str] = {}
    for index in range(addendum_start, len(lines)):
        match = HEADING_RE.match(lines[index])
        if not match:
            continue
        level = len(match.group("marks"))
        title = match.group("title")
        heading_stack[level] = slugify(title)
        for stale in [candidate for candidate in heading_stack if candidate > level]:
            del heading_stack[stale]
        path_slug = "--".join(heading_stack[candidate] for candidate in sorted(heading_stack))
        anchor_id = f"addendum:{path_slug}"
        if anchor_id in used_ids:
            anchor_id = f"{anchor_id}-{index + 1}"
        used_ids.add(anchor_id)
        end = _section_end(lines, index, level)
        section = "\n".join(lines[index:end]) + "\n"
        anchors.append(
            {
                "anchor_id": anchor_id,
                "content_sha256": sha256_bytes(section.encode("utf-8")),
                "heading_level": level,
                "heading_path": [heading_stack[candidate] for candidate in sorted(heading_stack)],
                "kind": "addendum",
                "source_line": index + 1,
                "title": title,
            }
        )

    return sha256_bytes(raw), anchors


def build_source_manifest(source: Path, accepted: dict[str, Any]) -> dict[str, Any]:
    source_hash, anchors = parse_living_source(source)
    logical_version = accepted["logical_source_version"]
    planning_inputs = accepted["planning_inputs"]
    return {
        "$schema": "./mvp-source-anchors.schema.json",
        "anchor_algorithm": ANCHOR_ALGORITHM,
        "anchors": anchors,
        "logical_source_version": logical_version,
        "planning_inputs": planning_inputs,
        "schema_version": "1.0.0",
        "source": {
            "path": accepted["source"]["path"],
            "sha256": source_hash,
        },
        "source_plan_sha256": source_plan_sha256(logical_version, source_hash, planning_inputs),
    }


def _json_type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise CapabilityError(f"unsupported schema type {expected!r}")


def validate_schema(value: Any, schema: dict[str, Any], location: str = "$") -> list[str]:
    """Validate the JSON-Schema subset used by the P00 public contracts."""
    errors: list[str] = []
    expected = schema.get("type")
    if expected is not None:
        expected_types = [expected] if isinstance(expected, str) else expected
        if not any(_json_type_matches(value, item) for item in expected_types):
            return [f"{location}: expected type {expected_types}, got {type(value).__name__}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{location}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{location}: value {value!r} is not in the closed enum")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{location}: string is shorter than minLength")
        pattern = schema.get("pattern")
        if pattern is not None and re.fullmatch(pattern, value) is None:
            errors.append(f"{location}: string does not match {pattern!r}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{location}: array has fewer than minItems")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{location}: array items are not unique")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                errors.extend(validate_schema(item, item_schema, f"{location}[{index}]"))
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for required in schema.get("required", []):
            if required not in value:
                errors.append(f"{location}: missing required property {required!r}")
        if schema.get("additionalProperties") is False:
            for extra in sorted(set(value) - set(properties)):
                errors.append(f"{location}: unexpected property {extra!r}")
        for key, child in value.items():
            if key in properties:
                errors.extend(validate_schema(child, properties[key], f"{location}.{key}"))
    return errors


def rubric_id_is_known(value: str) -> bool:
    match = RUBRIC_ID_RE.fullmatch(value)
    return bool(match and 1 <= int(match.group("number")) <= 82)


def git_value(root: Path, *args: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def iter_truth_files(root: Path) -> Iterable[Path]:
    checked_suffixes = {
        ".go", ".js", ".json", ".jsx", ".md", ".proto", ".py", ".sh",
        ".ts", ".tsx", ".txt", ".yaml", ".yml",
    }
    excluded_roots = {".git", "build", "delivery", "node_modules"}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in checked_suffixes:
            continue
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] in excluded_roots:
            continue
        yield path
