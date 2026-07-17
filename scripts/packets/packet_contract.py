#!/usr/bin/env python3
"""Public packet-graph and command-contract validation.

The delivery files use the JSON subset of YAML so a clean clone needs only the
Python standard library.  This module deliberately resolves every input below
the repository root; private planning material is never a runtime dependency.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


GRAPH_PATH = Path("delivery/mvp/packet-graph.yaml")
COMMAND_PATH = Path("delivery/mvp/command-contract.yaml")
MANIFEST_PATH = Path("docs/generated/packet-execution-manifest.json")
MAKE_SAFETY_TOKEN = "JUMPSHIP_PACKET_MAKE_SAFETY_OK"
ROOT_MAKE_SAFETY_GATE = (
    "ifneq ($(shell python3 ./scripts/packets/check make-safety),JUMPSHIP_PACKET_MAKE_SAFETY_OK)",
    "$(error packet Make safety check failed)",
    "endif",
)
ROOT_PACKET_INCLUDE = "include $(sort $(wildcard mk/packets/P??.mk))"

EXPECTED_NODE_IDS = {f"P{number:02d}" for number in range(29)} | {"J13", "J19"}
EXPECTED_JOIN_OWNERS = {"J13": "P13", "J19": "P19"}
LIFECYCLES = {"planned", "present", "active"}
SELECTOR_KEYS = {"SUITE", "PHASE", "PLANE", "LAYER"}
NODE_RE = re.compile(r"^(?:P(?:0[0-9]|1[0-9]|2[0-8])|J(?:13|19))$")
RANGE_RE = re.compile(r"^(P\d{2})\.\.(P\d{2})$")
TARGET_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SELECTOR_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
MAKE_TARGET_RE = re.compile(r"^([A-Za-z0-9_./%-]+(?:\s+[A-Za-z0-9_./%-]+)*)\s*:(?![=])")
PACKET_FRAGMENT_RE = re.compile(r"^P(\d{2})\.mk$")
RECEIPT_PATH_RE = re.compile(
    r"^delivery/mvp/handoffs/(?P<node>P(?:0[0-9]|1[0-9]|2[0-8])|J(?:13|19))/"
    r"(?P<commit>[0-9a-f]{40})\.json$"
)


class ContractError(ValueError):
    """A deterministic, user-actionable contract validation error."""


def _fail(message: str) -> None:
    raise ContractError(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json_yaml(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        _fail(f"cannot read {path}: {exc}")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"{path} must be UTF-8 JSON-compatible YAML: {exc}")
    if not isinstance(value, dict):
        _fail(f"{path} root must be an object")
    return value, raw


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def validate_public_references(
    repo_root: Path, graph_document: dict[str, Any], command_document: dict[str, Any]
) -> None:
    """Reject dangling rubric, capability, and public-contract references."""
    registry, _ = load_json_yaml(repo_root / "contracts/capabilities/mvp.yaml")
    capability_rows = registry.get("capabilities")
    if not isinstance(capability_rows, list):
        _fail("public capability registry capabilities must be an array")
    capability_ids = {
        row.get("id") for row in capability_rows if isinstance(row, dict) and isinstance(row.get("id"), str)
    }

    contract_ids: set[str] = set()
    contracts_root = repo_root / "contracts"
    if contracts_root.is_dir():
        for path in sorted(contracts_root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            contract_ids.update(
                match.group(1)
                for match in re.finditer(r'"\$id"\s*:\s*"([^"]+)"', text)
            )

    for value in _walk_strings([graph_document, command_document]):
        for raw in re.findall(r"JSMVP-R[A-Za-z0-9.-]+", value):
            reference = raw.rstrip(".,;:")
            match = re.fullmatch(r"JSMVP-R(\d{3})", reference)
            if match is None or not 1 <= int(match.group(1)) <= 82:
                _fail(f"unknown or malformed rubric reference: {reference}")
        for reference in re.findall(r"MVP-CAP-[A-Za-z0-9_-]+", value):
            if reference not in capability_ids:
                _fail(f"unknown public capability reference: {reference}")
        for raw in re.findall(r"(?<![A-Za-z0-9_])contracts/[^\s`\"'<>]+", value):
            reference = raw.rstrip(".,;:)")
            if re.fullmatch(r"contracts/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", reference) is None:
                _fail(f"malformed public contract path reference: {reference}")
            path = repo_root / reference
            if path.is_symlink() or not path.is_file():
                _fail(f"unknown public contract path reference: {reference}")
        for raw in re.findall(r"https://jumpship\.dev/[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+", value):
            reference = raw.rstrip(".,;:)")
            if reference not in contract_ids:
                _fail(f"unknown public contract ID reference: {reference}")


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        _fail(f"{field} must be an array of strings")
    return value


def expand_dependencies(expressions: Any, field: str, known: set[str]) -> list[str]:
    items = _string_list(expressions, field)
    expanded: list[str] = []
    seen: set[str] = set()
    for expression in items:
        match = RANGE_RE.fullmatch(expression)
        if match:
            start, end = (int(token[1:]) for token in match.groups())
            if start > end:
                _fail(f"{field}: reversed range {expression!r}")
            if end > 28:
                _fail(f"{field}: unknown packet in range {expression!r}")
            values = [f"P{number:02d}" for number in range(start, end + 1)]
        else:
            if ".." in expression or expression.startswith("J") and any(char in expression for char in ".-"):
                _fail(f"{field}: join IDs cannot appear in ranges: {expression!r}")
            if not NODE_RE.fullmatch(expression):
                _fail(f"{field}: invalid dependency expression {expression!r}")
            values = [expression]
        for value in values:
            if value not in known:
                _fail(f"{field}: unknown dependency {value}")
            if value in seen:
                _fail(f"{field}: duplicate expanded dependency {value}")
            seen.add(value)
            expanded.append(value)
    return expanded


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    owner: str
    lifecycle: str
    start_requires: tuple[str, ...]
    completion_requires: tuple[str, ...]


def validate_graph(document: dict[str, Any]) -> tuple[list[GraphNode], list[str]]:
    if document.get("schema_version") != "1.0.0":
        _fail("packet graph schema_version must be 1.0.0")
    if document.get("kind") != "jumpship-mvp-packet-graph":
        _fail("packet graph kind must be jumpship-mvp-packet-graph")
    raw_nodes = document.get("nodes")
    if not isinstance(raw_nodes, list):
        _fail("packet graph nodes must be an array")

    ids: list[str] = []
    for index, raw in enumerate(raw_nodes):
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            _fail(f"nodes[{index}] must be an object with a string id")
        ids.append(raw["id"])
    duplicates = sorted({node_id for node_id in ids if ids.count(node_id) > 1})
    if duplicates:
        _fail(f"duplicate graph nodes: {', '.join(duplicates)}")
    actual = set(ids)
    if actual != EXPECTED_NODE_IDS:
        missing = sorted(EXPECTED_NODE_IDS - actual)
        extra = sorted(actual - EXPECTED_NODE_IDS)
        _fail(f"graph node set mismatch; missing={missing}, extra={extra}")

    nodes: list[GraphNode] = []
    for index, raw in enumerate(raw_nodes):
        node_id = raw["id"]
        kind = raw.get("kind")
        expected_kind = "join" if node_id.startswith("J") else "packet"
        if kind != expected_kind:
            _fail(f"nodes[{index}].kind for {node_id} must be {expected_kind}")
        owner = raw.get("owner")
        expected_owner = EXPECTED_JOIN_OWNERS.get(node_id, node_id)
        if owner != expected_owner:
            _fail(f"nodes[{index}].owner for {node_id} must be {expected_owner}")
        lifecycle = raw.get("lifecycle")
        if lifecycle not in LIFECYCLES:
            _fail(f"nodes[{index}].lifecycle must be one of {sorted(LIFECYCLES)}")
        start = expand_dependencies(raw.get("start_requires"), f"nodes[{index}].start_requires", actual)
        completion = expand_dependencies(
            raw.get("completion_requires"), f"nodes[{index}].completion_requires", actual
        )
        if node_id in start or node_id in completion:
            _fail(f"{node_id} cannot depend on itself")
        overlap = sorted(set(start) & set(completion))
        if overlap:
            _fail(f"{node_id} repeats dependencies across start/completion: {overlap}")
        nodes.append(GraphNode(node_id, kind, owner, lifecycle, tuple(start), tuple(completion)))

    by_id = {node.id: node for node in nodes}
    if by_id["J13"].start_requires != ("P13", "P14", "P15", "P16", "P17", "P18", "P26"):
        _fail("J13 must depend exactly on P13..P18 and P26")
    if by_id["J19"].start_requires != ("P19", "P20"):
        _fail("J19 must depend exactly on P19 and P20")

    indegree = {node.id: 0 for node in nodes}
    consumers: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        for dependency in (*node.start_requires, *node.completion_requires):
            indegree[node.id] += 1
            consumers[dependency].append(node.id)
    order_index = {node.id: index for index, node in enumerate(nodes)}
    ready = sorted((node_id for node_id, count in indegree.items() if count == 0), key=order_index.get)
    topological: list[str] = []
    while ready:
        current = ready.pop(0)
        topological.append(current)
        for consumer in sorted(consumers[current], key=order_index.get):
            indegree[consumer] -= 1
            if indegree[consumer] == 0:
                ready.append(consumer)
                ready.sort(key=order_index.get)
    if len(topological) != len(nodes):
        cyclic = sorted(node_id for node_id, count in indegree.items() if count)
        _fail(f"packet graph contains a cycle involving: {', '.join(cyclic)}")
    return nodes, topological


def _expand_target_groups(document: dict[str, Any], graph_ids: set[str]) -> list[dict[str, Any]]:
    groups = document.get("target_groups")
    if not isinstance(groups, list):
        _fail("command contract target_groups must be an array")
    result: list[dict[str, Any]] = []
    for group_index, group in enumerate(groups):
        if not isinstance(group, dict):
            _fail(f"target_groups[{group_index}] must be an object")
        owner = group.get("owner")
        if owner not in graph_ids or str(owner).startswith("J"):
            _fail(f"target_groups[{group_index}].owner must be a packet ID")
        kind = group.get("kind")
        if kind not in {"direct", "aggregate", "composite", "dispatcher"}:
            _fail(f"target_groups[{group_index}].kind is invalid")
        targets = group.get("targets")
        if not isinstance(targets, dict) or not targets:
            _fail(f"target_groups[{group_index}].targets must be a non-empty object")
        for name, description in targets.items():
            if not isinstance(name, str) or not TARGET_RE.fullmatch(name):
                _fail(f"invalid public target name {name!r}")
            if not isinstance(description, str) or not description.strip():
                _fail(f"target {name} must have a description")
            result.append({"name": name, "owner": owner, "kind": kind, "description": description.strip()})
    names = [target["name"] for target in result]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        _fail(f"duplicate public targets: {', '.join(duplicates)}")
    return result


def _hidden_hook_name(owner: str, dispatcher: str, key: str, selector: str) -> str:
    return f"_{owner.lower()}_{dispatcher}_{key}-{selector}"


def validate_commands(
    document: dict[str, Any], graph_nodes: list[GraphNode]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    if document.get("schema_version") != "1.0.0":
        _fail("command contract schema_version must be 1.0.0")
    if document.get("kind") != "jumpship-mvp-command-contract":
        _fail("command contract kind must be jumpship-mvp-command-contract")
    declared_keys = document.get("selector_keys")
    if not isinstance(declared_keys, list) or set(declared_keys) != SELECTOR_KEYS or len(declared_keys) != 4:
        _fail(f"selector_keys must declare exactly {sorted(SELECTOR_KEYS)}")

    graph_ids = {node.id for node in graph_nodes}
    graph_by_id = {node.id: node for node in graph_nodes}
    targets = _expand_target_groups(document, graph_ids)
    target_by_name = {target["name"]: target for target in targets}

    raw_selectors = document.get("selectors")
    if not isinstance(raw_selectors, list):
        _fail("command contract selectors must be an array")
    selectors: list[dict[str, Any]] = []
    selector_keys_seen: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(raw_selectors):
        if not isinstance(raw, dict):
            _fail(f"selectors[{index}] must be an object")
        target = raw.get("target")
        key = raw.get("key")
        value = raw.get("value")
        owner = raw.get("owner")
        if target not in target_by_name:
            _fail(f"selectors[{index}] references unknown target {target!r}")
        if key not in SELECTOR_KEYS:
            _fail(f"selectors[{index}].key is invalid")
        if not isinstance(value, str) or not SELECTOR_RE.fullmatch(value):
            _fail(f"selectors[{index}].value is unsafe")
        if owner not in graph_ids or str(owner).startswith("J"):
            _fail(f"selectors[{index}].owner must be a packet ID")
        identity = (target, key, value)
        if identity in selector_keys_seen:
            _fail(f"duplicate selector registration {target} {key}={value}")
        selector_keys_seen.add(identity)
        hook_refs = raw.get("hook_refs", [])
        if not isinstance(hook_refs, list) or any(not isinstance(item, str) for item in hook_refs):
            _fail(f"selectors[{index}].hook_refs must be an array of strings")
        selectors.append({"target": target, "key": key, "value": value, "owner": owner, "hook_refs": hook_refs})

    raw_hooks = document.get("hooks")
    if not isinstance(raw_hooks, list):
        _fail("command contract hooks must be an array")
    hooks: list[dict[str, Any]] = []
    hook_names: set[str] = set()
    hook_ownership: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(raw_hooks):
        if not isinstance(raw, dict):
            _fail(f"hooks[{index}] must be an object")
        dispatcher = raw.get("dispatcher")
        key = raw.get("selector_key")
        selector = raw.get("selector")
        owner = raw.get("owner")
        lifecycle = raw.get("lifecycle")
        if dispatcher not in target_by_name:
            _fail(f"hooks[{index}] references unknown dispatcher {dispatcher!r}")
        if target_by_name[dispatcher]["kind"] not in {"aggregate", "composite", "dispatcher"}:
            _fail(f"hooks[{index}] target {dispatcher} is not a dispatcher")
        if key not in SELECTOR_KEYS:
            _fail(f"hooks[{index}].selector_key is invalid")
        if not isinstance(selector, str) or not SELECTOR_RE.fullmatch(selector):
            _fail(f"hooks[{index}].selector is unsafe")
        if owner not in graph_by_id or owner.startswith("J"):
            _fail(f"hooks[{index}].owner must be a packet ID")
        if lifecycle != "planned":
            _fail(f"hooks[{index}].lifecycle must be planned in the design catalog")
        dependency_field = f"hooks[{index}].depends_on"
        dependencies = expand_dependencies(raw.get("depends_on"), dependency_field, graph_ids)
        if tuple(dependencies) != graph_by_id[owner].start_requires:
            _fail(f"{dependency_field} must equal {owner}'s expanded start dependencies")
        identity = (dispatcher, key, selector)
        if identity in hook_ownership:
            _fail(f"duplicate hook ownership for {dispatcher} {key}={selector}")
        hook_ownership.add(identity)
        hidden_target = raw.get("target")
        expected_target = _hidden_hook_name(owner, dispatcher, key, selector)
        if hidden_target != expected_target:
            _fail(f"hooks[{index}].target must be {expected_target}")
        if hidden_target in hook_names:
            _fail(f"duplicate hidden hook target {hidden_target}")
        hook_names.add(hidden_target)
        hooks.append(
            {
                "target": hidden_target,
                "dispatcher": dispatcher,
                "selector_key": key,
                "selector": selector,
                "owner": owner,
                "depends_on": dependencies,
                "lifecycle": lifecycle,
            }
        )

    hook_by_name = {hook["target"]: hook for hook in hooks}
    referenced_hooks: set[str] = set()
    for selector in selectors:
        for hook_ref in selector["hook_refs"]:
            if hook_ref not in hook_by_name:
                _fail(
                    f"selector {selector['target']} {selector['key']}={selector['value']} "
                    f"references unknown hook {hook_ref}"
                )
            if hook_ref in referenced_hooks:
                _fail(f"hidden hook {hook_ref} is referenced by multiple public selectors")
            if hook_by_name[hook_ref]["dispatcher"] != selector["target"]:
                _fail(f"selector {selector['target']} cannot reference hook {hook_ref}")
            referenced_hooks.add(hook_ref)
        if selector["hook_refs"] and selector["owner"] != "P01":
            _fail("only P01-owned composite selectors may reference multiple internal hooks")
    selector_by_identity = {
        (selector["target"], selector["key"], selector["value"]): selector for selector in selectors
    }
    for hook in hooks:
        identity = (hook["dispatcher"], hook["selector_key"], hook["selector"])
        selector = selector_by_identity.get(identity)
        if selector is None and hook["target"] not in referenced_hooks:
            _fail(f"hidden hook {hook['target']} has no public selector registration")
        if selector is not None and selector["owner"] != hook["owner"]:
            _fail(f"selector ownership for {hook['target']} must be {hook['owner']}")

    raw_adapters = document.get("adapters", [])
    if not isinstance(raw_adapters, list):
        _fail("command contract adapters must be an array")
    adapters: list[dict[str, Any]] = []
    adapter_targets: set[str] = set()
    for index, raw in enumerate(raw_adapters):
        if not isinstance(raw, dict):
            _fail(f"adapters[{index}] must be an object")
        target = raw.get("target")
        public_target = raw.get("public_target")
        owner = raw.get("owner")
        if not isinstance(target, str) or not re.fullmatch(r"_p\d{2}_[a-z][a-z0-9-]*", target):
            _fail(f"adapters[{index}].target is invalid")
        if target in adapter_targets or target in hook_names:
            _fail(f"duplicate internal target {target}")
        if public_target not in target_by_name:
            _fail(f"adapters[{index}].public_target is unknown")
        if owner not in graph_by_id or owner.startswith("J"):
            _fail(f"adapters[{index}].owner must be a packet ID")
        adapter_targets.add(target)
        adapters.append({"target": target, "public_target": public_target, "owner": owner})
    return targets, selectors, hooks + adapters


def _definition_owner(path: Path, repo_root: Path) -> str | None:
    relative = path.relative_to(repo_root)
    if relative == Path("Makefile"):
        return "P01"
    if relative.parent == Path("mk/packets"):
        match = PACKET_FRAGMENT_RE.fullmatch(relative.name)
        if match:
            return f"P{match.group(1)}"
    return None


def _validate_makefile_safety(path: Path, repo_root: Path, text: str) -> None:
    relative = path.relative_to(repo_root)
    is_packet_fragment = relative.parent == Path("mk/packets")
    if relative == Path("Makefile"):
        lines = text.splitlines()
        positions: list[int] = []
        for required_line in ROOT_MAKE_SAFETY_GATE:
            if lines.count(required_line) != 1:
                _fail(f"root Makefile must contain exact safety gate line: {required_line}")
            positions.append(lines.index(required_line))
        if positions != list(range(positions[0], positions[0] + len(positions))):
            _fail("root Make safety gate lines must be contiguous and ordered")
        if lines.count(ROOT_PACKET_INCLUDE) != 1 or positions[-1] >= lines.index(ROOT_PACKET_INCLUDE):
            _fail("root Make safety gate must appear exactly once before the packet include")
        text = "\n".join(
            "# validated packet Make safety gate" if line in ROOT_MAKE_SAFETY_GATE else line
            for line in lines
        )
    forbidden_expansions = ("$(shell", "${shell", "$(eval", "${eval", "$(file", "${file", "$(guile", "${guile")
    for marker in forbidden_expansions:
        if marker in text:
            _fail(f"parse-time Make execution is forbidden ({marker}) in {relative}")
    if re.search(r"\$\$\(", text):
        _fail(f"shell command substitution is forbidden in {relative}")
    if "`" in text:
        _fail(f"backtick command substitution is forbidden in {relative}")
    if re.search(r"(?m)^\s*[^#\n]+\s!=", text):
        _fail(f"shell assignment (!=) is forbidden in {relative}")
    if re.search(r"(?m)^\s*(?:override\s+|export\s+|unexport\s+)?(?:SUITE|PHASE|PLANE|LAYER|REQUIRE_COMPLETE)\s*[:?+]?=", text):
        _fail(f"selector and completeness variables may not be assigned in {relative}")
    if re.search(r"(?m)^\s*(?:define|endef|load|vpath)\b", text):
        _fail(f"dynamic Make directives are forbidden in {relative}")
    if re.search(r"(?m)^\s*(?:ifeq|ifneq|ifdef|ifndef|else|endif)\b", text):
        _fail(f"conditional Make directives are forbidden in {relative}")
    if re.search(r"\$\((?:call|foreach)\b|\$\(\$\(|\$\(\$\{|\$\{\$\{", text):
        _fail(f"indirect Make expansion is forbidden in {relative}")
    if re.search(r"(?m)\\\s*$", text):
        _fail(f"Make line continuations are forbidden in {relative}")

    approved_root_includes = {
        ROOT_PACKET_INCLUDE,
    }
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^(?:-?include|sinclude)\b", stripped):
            if relative != Path("Makefile") or stripped not in approved_root_includes:
                _fail(f"unapproved Make include at {relative}:{line_number}")
            continue
        if is_packet_fragment and not line.startswith(("\t", " ")):
            if stripped.startswith(".") and not stripped.startswith(".PHONY:"):
                _fail(f"special Make targets are forbidden in packet fragments at {relative}:{line_number}")
            if re.match(
                r"^(?:(?:override|private|export|unexport)\s+)?[A-Za-z_.][A-Za-z0-9_.-]*\s*[:?+!]?=",
                stripped,
            ) or re.match(r"^(?:export|unexport|override|private|undefine)\b", stripped):
                _fail(f"Make variable mutation is forbidden in packet fragments at {relative}:{line_number}")
        if re.match(r"^\.DEFAULT\s*:", stripped):
            _fail(f".DEFAULT is forbidden at {relative}:{line_number}")
        if stripped.startswith(".SECONDEXPANSION"):
            _fail(f".SECONDEXPANSION is forbidden at {relative}:{line_number}")
        if any(f"$({key})" in line or f"${{{key}}}" in line for key in (*SELECTOR_KEYS, "REQUIRE_COMPLETE")):
            _fail(f"selector interpolation is forbidden at {relative}:{line_number}")
        if not line.startswith(("\t", " ")) and ("$(" in line or "${" in line):
            assignment = re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*[:?+]?=", stripped)
            if not assignment:
                _fail(f"dynamic Make target/directive expansion is forbidden at {relative}:{line_number}")
        if "::" in stripped and not re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*[:?+]?=", stripped):
            _fail(f"double-colon Make rules are forbidden at {relative}:{line_number}")


def packet_fragment_paths(repo_root: Path) -> list[Path]:
    fragment_dir = repo_root / "mk/packets"
    fragments: list[Path] = []
    if fragment_dir.is_dir():
        for fragment in sorted(fragment_dir.glob("*.mk")):
            match = PACKET_FRAGMENT_RE.fullmatch(fragment.name)
            if fragment.is_symlink() or match is None or int(match.group(1)) > 28:
                _fail(f"unapproved packet Make fragment: {fragment.relative_to(repo_root)}")
            fragments.append(fragment)
    return fragments


def scan_packet_make_safety(repo_root: Path) -> None:
    # This runs before GNU Make includes any packet fragment.  Syntax-only
    # screening is insufficient: a parse-safe later fragment can otherwise
    # replace an earlier packet's public recipe.  Validate the complete live
    # definition set against the public ownership catalog before Make parses it.
    _validated_make_definitions(repo_root, build_catalog(repo_root))


def scan_make_definitions(repo_root: Path) -> dict[str, tuple[str, str]]:
    candidates = [repo_root / "Makefile", *packet_fragment_paths(repo_root)]
    definitions: dict[str, tuple[str, str]] = {}
    phony: dict[str, tuple[str, str]] = {}
    for path in candidates:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        _validate_makefile_safety(path, repo_root, text)
        if re.search(r"\bPKG\s*(?::|\?|\+)?=", text):
            _fail(f"arbitrary PKG passthrough is forbidden: {path.relative_to(repo_root)}")
        owner = _definition_owner(path, repo_root)
        if owner is None:
            _fail(f"cannot determine command owner for {path.relative_to(repo_root)}")
        current_targets: list[str] = []
        substantive_recipe: dict[str, bool] = {}
        for line_number, line in enumerate(text.splitlines(), start=1):
            if line.startswith("\t"):
                if not current_targets:
                    _fail(f"orphan Make recipe at {path.relative_to(repo_root)}:{line_number}")
                recipe = line[1:].strip()
                substantive = bool(recipe) and not re.fullmatch(
                    r"@?(?::|true|/bin/true)(?:\s*(?:#.*)?)?", recipe
                )
                for target in current_targets:
                    substantive_recipe[target] = substantive_recipe[target] or substantive
                continue
            if line.startswith(" "):
                if line.strip() and not line.lstrip().startswith("#"):
                    _fail(f"space-indented Make syntax is forbidden at {path.relative_to(repo_root)}:{line_number}")
                continue
            if line.startswith(".PHONY"):
                current_targets = []
                if not line.startswith(".PHONY:"):
                    _fail(f"invalid .PHONY declaration at {path.relative_to(repo_root)}:{line_number}")
                location = f"{path.relative_to(repo_root)}:{line_number}"
                for target in line.removeprefix(".PHONY:").split():
                    if not (
                        TARGET_RE.fullmatch(target)
                        or re.fullmatch(r"_p\d{2}_[A-Za-z0-9-]+(?:_[A-Z]+-[a-z0-9-]+)?", target)
                    ):
                        _fail(f"unsafe .PHONY target {target!r} at {location}")
                    previous = phony.get(target)
                    if previous is not None:
                        _fail(f"duplicate .PHONY target {target}: {previous[1]} and {location}")
                    phony[target] = (owner, location)
                continue
            match = MAKE_TARGET_RE.match(line)
            if not match:
                current_targets = []
                stripped = line.strip()
                if ":" in stripped and not re.match(
                    r"^(?:[A-Za-z_][A-Za-z0-9_]*|\.[A-Z_]+)\s*[:?+]?=", stripped
                ):
                    _fail(f"unsupported Make rule syntax at {path.relative_to(repo_root)}:{line_number}")
                continue
            current_targets = []
            for target in match.group(1).split():
                if "%" in target:
                    _fail(f"pattern rules are forbidden at {path.relative_to(repo_root)}:{line_number}")
                if target.startswith("."):
                    continue
                if not (TARGET_RE.fullmatch(target) or re.fullmatch(r"_p\d{2}_[A-Za-z0-9-]+(?:_[A-Z]+-[a-z0-9-]+)?", target)):
                    _fail(f"unsafe Make target {target!r} at {path.relative_to(repo_root)}:{line_number}")
                location = f"{path.relative_to(repo_root)}:{line_number}"
                if target in definitions:
                    previous = definitions[target][1]
                    _fail(f"duplicate Make target {target}: {previous} and {location}")
                definitions[target] = (owner, location)
                substantive_recipe[target] = False
                current_targets.append(target)
        no_recipe = sorted(target for target, substantive in substantive_recipe.items() if not substantive)
        if no_recipe:
            _fail(f"Make targets without a substantive recipe in {path.relative_to(repo_root)}: {no_recipe}")
    orphan_phony = sorted(set(phony) - set(definitions))
    if orphan_phony:
        _fail(f".PHONY declarations without rules: {orphan_phony}")
    non_phony = sorted(set(definitions) - set(phony))
    if non_phony:
        _fail(f"Make rules missing .PHONY declarations: {non_phony}")
    return definitions


def _git(repo_root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *arguments], cwd=repo_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )


def _regular_blob_at_commit(repo_root: Path, commit: str, relative_path: str) -> bytes | None:
    tree = _git(repo_root, "ls-tree", commit, "--", relative_path)
    if tree.returncode or not tree.stdout:
        return None
    try:
        metadata, recorded_path = tree.stdout.rstrip(b"\n").split(b"\t", 1)
        mode, kind, _object_id = metadata.split(b" ", 2)
    except ValueError:
        return None
    if recorded_path.decode("utf-8", "strict") != relative_path:
        return None
    if kind != b"blob" or mode not in {b"100644", b"100755"}:
        return None
    blob = _git(repo_root, "show", f"{commit}:{relative_path}")
    return blob.stdout if blob.returncode == 0 else None


def committed_receipt_markers_untrusted(repo_root: Path, graph_nodes: list[GraphNode]) -> set[str]:
    """Observe minimal committed receipt markers; never infer acceptance or readiness."""
    known_nodes = {node.id for node in graph_nodes}
    tree = _git(repo_root, "ls-tree", "-r", "--name-only", "HEAD", "--", "delivery/mvp/handoffs")
    if tree.returncode:
        return set()
    markers: set[str] = set()
    for relative_path in sorted(tree.stdout.decode("utf-8", "strict").splitlines()):
        match = RECEIPT_PATH_RE.fullmatch(relative_path)
        if match is None or match.group("node") not in known_nodes:
            continue
        raw = _regular_blob_at_commit(repo_root, "HEAD", relative_path)
        if raw is None:
            continue
        try:
            document = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if (
            isinstance(document, dict)
            and document.get("schema_version") == "1.0.0"
            and document.get("packet_id") == match.group("node")
            and document.get("outcome") == "complete"
            and document.get("ending_commit") == match.group("commit")
        ):
            markers.add(match.group("node"))
    return markers


def _command_lifecycle(present: bool, dependencies: Iterable[str], marker_nodes: set[str]) -> str:
    if not present:
        return "planned"
    return "active" if set(dependencies).issubset(marker_nodes) else "present"


def build_catalog(repo_root: Path) -> dict[str, Any]:
    """Build the checked-in catalog from the two public source files only."""
    graph_document, graph_raw = load_json_yaml(repo_root / GRAPH_PATH)
    command_document, command_raw = load_json_yaml(repo_root / COMMAND_PATH)
    validate_public_references(repo_root, graph_document, command_document)
    nodes, topological = validate_graph(graph_document)
    targets, selectors, internals = validate_commands(command_document, nodes)
    node_by_id = {node.id: node for node in nodes}
    consumers: dict[str, dict[str, list[str]]] = {
        node.id: {"start": [], "completion": []} for node in nodes
    }
    for node in nodes:
        for dependency in node.start_requires:
            consumers[dependency]["start"].append(node.id)
        for dependency in node.completion_requires:
            consumers[dependency]["completion"].append(node.id)

    graph_manifest = []
    for node in nodes:
        graph_manifest.append(
            {
                "id": node.id,
                "kind": node.kind,
                "owner": node.owner,
                "lifecycle": node.lifecycle,
                "start_requires": list(node.start_requires),
                "completion_requires": list(node.completion_requires),
                "start_consumers": consumers[node.id]["start"],
                "completion_consumers": consumers[node.id]["completion"],
            }
        )

    command_targets = []
    for target in targets:
        dependencies = list(node_by_id[target["owner"]].start_requires)
        command_targets.append(
            {
                **target,
                "depends_on": dependencies,
                "lifecycle": "planned",
            }
        )

    command_internals = []
    for internal in internals:
        owner = internal["owner"]
        dependencies = internal.get("depends_on", list(node_by_id[owner].start_requires))
        command_internals.append(
            {
                **internal,
                "depends_on": dependencies,
                "lifecycle": "planned",
            }
        )

    return {
        "_generated": "generated by scripts/packets/check; DO NOT EDIT",
        "schema_version": "1.0.0",
        "kind": "jumpship-mvp-packet-execution-manifest",
        "catalog_semantics": (
            "Static public design catalog derived only from delivery/mvp/packet-graph.yaml and "
            "delivery/mvp/command-contract.yaml; runtime availability is intentionally excluded."
        ),
        "sources": {
            str(GRAPH_PATH): {"sha256": sha256_bytes(graph_raw)},
            str(COMMAND_PATH): {"sha256": sha256_bytes(command_raw)},
        },
        "graph": {"topological_order": topological, "nodes": graph_manifest},
        "commands": {
            "targets": command_targets,
            "selectors": selectors,
            "internal_targets": command_internals,
        },
    }


def build_runtime_inventory(repo_root: Path) -> dict[str, Any]:
    """Compute live presence/availability without changing checked-in catalog bytes."""
    catalog = build_catalog(repo_root)
    graph_document, _ = load_json_yaml(repo_root / GRAPH_PATH)
    nodes, _ = validate_graph(graph_document)
    marker_nodes = committed_receipt_markers_untrusted(repo_root, nodes)
    definitions = _validated_make_definitions(repo_root, catalog)
    inventory = copy.deepcopy(catalog)
    inventory["_generated"] = "computed live by scripts/packets/check; NOT A SCHEDULING AUTHORITY"
    inventory["kind"] = "jumpship-mvp-packet-runtime-inventory"
    inventory["runtime_semantics"] = (
        "Informational local hook availability only. Committed receipt markers are untrusted hints; "
        "active and REQUIRE_COMPLETE=1 mean local hook coverage only and do not establish packet "
        "acceptance or readiness. Frozen planctl readiness and handoff-check remain the sole authorities."
    )
    inventory["catalog_sha256"] = sha256_bytes(canonical_json(catalog))
    inventory["committed_complete_receipt_markers_untrusted_not_acceptance"] = sorted(marker_nodes)

    owners_present = {owner for owner, _location in definitions.values()}
    for node in inventory["graph"]["nodes"]:
        node["lifecycle"] = (
            "active" if node["id"] in marker_nodes
            else "present" if node["id"] in owners_present
            else "planned"
        )
    for target in inventory["commands"]["targets"]:
        target["lifecycle"] = _command_lifecycle(
            target["name"] in definitions, target["depends_on"], marker_nodes
        )
    for internal in inventory["commands"]["internal_targets"]:
        internal["lifecycle"] = _command_lifecycle(
            internal["target"] in definitions, internal.get("depends_on", []), marker_nodes
        )
    return inventory


def _validated_make_definitions(
    repo_root: Path, catalog: dict[str, Any]
) -> dict[str, tuple[str, str]]:
    """Validate every live Make definition against its declared packet owner."""
    definitions = scan_make_definitions(repo_root)
    target_by_name = {target["name"]: target for target in catalog["commands"]["targets"]}
    internal_by_name = {
        target["target"]: target for target in catalog["commands"]["internal_targets"]
    }
    documented = set(target_by_name) | set(internal_by_name)
    undocumented = sorted(set(definitions) - documented)
    if undocumented:
        rendered = ", ".join(f"{name} ({definitions[name][1]})" for name in undocumented)
        _fail(f"undocumented Make targets: {rendered}")
    for name, (definition_owner, location) in definitions.items():
        expected_owner = (
            target_by_name[name]["owner"] if name in target_by_name else internal_by_name[name]["owner"]
        )
        if definition_owner != expected_owner:
            _fail(
                f"target {name} is owned by {expected_owner} but defined by {definition_owner} at {location}"
            )
    return definitions


def verify_catalog(repo_root: Path, catalog: dict[str, Any]) -> None:
    path = repo_root / MANIFEST_PATH
    expected = canonical_json(catalog)
    if path.is_symlink() or not path.is_file():
        _fail(f"generated manifest must be a regular file, never a symlink: {MANIFEST_PATH}")
    try:
        actual = path.read_bytes()
    except OSError as exc:
        _fail(f"cannot read generated manifest {path}: {exc}")
    if actual != expected:
        _fail(f"generated catalog drift: run scripts/packets/check generate")


def _prepare_output_path(
    repo_root: Path, requested_path: Path
) -> tuple[Path, Path, Path]:
    """Resolve a lexical repository output path and reject aliased parents."""
    root = repo_root.resolve()
    if requested_path.is_absolute():
        try:
            relative = requested_path.relative_to(root)
        except ValueError:
            _fail(f"output path must be inside repository root: {requested_path}")
    else:
        relative = requested_path
    if not relative.parts or relative == Path(".") or ".." in relative.parts:
        _fail(f"output path must be a normalized repository-relative file: {requested_path}")

    parent = root
    for component in relative.parts[:-1]:
        parent = parent / component
        if os.path.lexists(parent):
            mode = parent.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                _fail(f"output parent component is not a real directory: {parent.relative_to(root)}")
        else:
            parent.mkdir(mode=0o755)
        if parent.is_symlink() or parent.resolve() != parent:
            _fail(f"symlinked output parent is forbidden: {parent.relative_to(root)}")

    output = root / relative
    return relative, parent, output


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_atomic_output(repo_root: Path, requested_path: Path, data: bytes) -> Path:
    """Atomically replace one regular repo output without following symlinks."""
    relative, parent, output = _prepare_output_path(repo_root, requested_path)
    if os.path.lexists(output):
        mode = output.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            _fail(f"refusing to replace non-regular output: {relative}")

    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

        # Re-check after writing.  os.replace replaces a raced symlink itself;
        # it never opens or follows that symlink's target.
        if parent.is_symlink() or parent.resolve() != parent:
            _fail(f"symlinked output parent is forbidden: {parent}")
        if os.path.lexists(output):
            mode = output.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                _fail(f"refusing to replace non-regular output: {relative}")
        os.replace(temporary_path, output)
        _fsync_directory(parent)
    finally:
        temporary_path.unlink(missing_ok=True)
    return output


def write_exclusive_output(repo_root: Path, requested_path: Path, data: bytes) -> Path:
    """Publish deterministic evidence inside the repo without following links or overwriting."""
    relative, parent, output = _prepare_output_path(repo_root, requested_path)
    if os.path.lexists(output):
        _fail(f"refusing to overwrite output: {relative}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary_path, output, follow_symlinks=False)
        except FileExistsError:
            _fail(f"refusing to overwrite output: {relative}")
        _fsync_directory(parent)
    finally:
        temporary_path.unlink(missing_ok=True)
    return output


def render_help(manifest: dict[str, Any]) -> str:
    lines = [
        "LOCAL HOOK INVENTORY ONLY: active/REQUIRE_COMPLETE do not establish packet acceptance or readiness; use planctl."
    ]
    for target in manifest["commands"]["targets"]:
        selectors = [
            f"{selector['key']}={selector['value']}"
            for selector in manifest["commands"]["selectors"]
            if selector["target"] == target["name"]
        ]
        selector_suffix = f" [selectors: {', '.join(selectors)}]" if selectors else ""
        lines.append(
            f"{target['name']:<42} {target['owner']:<4} {target['lifecycle']:<7} "
            f"{target['description']}{selector_suffix}"
        )
    return "\n".join(lines) + "\n"
