#!/usr/bin/env python3
"""Validate root locks and seal one accepted dependency request at a time."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import datetime as dt
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Iterator


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
DEV_SCRIPT_DIR = ROOT / "scripts" / "dev"
if str(DEV_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(DEV_SCRIPT_DIR))

from tool_lock import ToolLockError, assert_safe_mutable_paths, tool_operation_lock
import toolchain as repository_toolchain

MANIFEST_PATH = ROOT / "tools" / "manifest.yaml"
SCHEMA_PATH = ROOT / "dependency" / "requests" / "schema.yaml"
TOOLS_ROOT = ROOT / "build" / "tools"
SUPPORTED_PLATFORMS = {"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64"}
BOOTSTRAP_NAMES = {"go", "node", "pnpm", "opentofu", "golangci-lint", "trivy"}
LOCK_PATHS = {
    ".tool-versions",
    "go.mod",
    "go.sum",
    "mise.toml",
    "package.json",
    "pnpm-lock.yaml",
    "tools/manifest.yaml",
    "web/package.json",
}
ALLOWED_LICENSES = {
    "Apache-2.0",
    "BSD-3-Clause",
    "GPL-3.0-only",
    "LGPL-2.1-or-later",
    "MIT",
    "MPL-2.0",
    "PostgreSQL",
}
PACKAGE_LICENSE_ALLOWLIST = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC-BY-4.0",
    "ISC",
    "LGPL-3.0-or-later",
    "MIT",
}
REQUEST_LICENSE_ALLOWLIST = PACKAGE_LICENSE_ALLOWLIST | ALLOWED_LICENSES | {
    "BlueOak-1.0.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-or-later",
    "LGPL-2.1-only",
    "LGPL-3.0-only",
    "Unicode-3.0",
}
EXACT_VERSION_RE = re.compile(r"^v?[0-9]+(?:\.[0-9A-Za-z-]+)+(?:\+[0-9A-Za-z.-]+)?$")
PACKET_RE = re.compile(r"^P(?:0[2-9]|1[0-9]|2[0-8])$")
REQUEST_ID_RE = re.compile(r"^(P[0-9]{2})-dep-[a-z0-9]+(?:-[a-z0-9]+)*$")
HEX_RE = {"sha256": re.compile(r"^[0-9a-f]{64}$"), "sha512": re.compile(r"^[0-9a-f]{128}$")}
RFC3339_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
PROVENANCE_HOSTS = {
    "files.pythonhosted.org",
    "github.com",
    "proxy.golang.org",
    "pypi.org",
    "registry.npmjs.org",
    "release-assets.githubusercontent.com",
}
OFFICIAL_NPM_REGISTRY = "https://registry.npmjs.org/"
TRIVY_DB_REPOSITORY = "ghcr.io/aquasecurity/trivy-db:2"


class LockError(RuntimeError):
    """A dependency contract or serialized-apply violation."""


def _load_json_yaml(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LockError(f"cannot parse JSON-compatible YAML {path}: {exc}") from exc


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_file(path: Path) -> str:
    return _digest_bytes(path.read_bytes())


def _is_https(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
    )


def _exact_version(value: Any) -> bool:
    return isinstance(value, str) and EXACT_VERSION_RE.fullmatch(value) is not None and "latest" not in value.lower()


def _utc_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or RFC3339_UTC_RE.fullmatch(value) is None:
        return None
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def _integrity_value_valid(algorithm: Any, value: Any) -> bool:
    if not isinstance(algorithm, str) or not isinstance(value, str):
        return False
    if algorithm in HEX_RE:
        return HEX_RE[algorithm].fullmatch(value) is not None
    if algorithm == "oci-digest":
        return re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    prefixes = {"npm-sri": "sha512-", "go-sum": "h1:"}
    if algorithm not in prefixes or not value.startswith(prefixes[algorithm]):
        return False
    encoded = value[len(prefixes[algorithm]) :]
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) == (64 if algorithm == "npm-sri" else 32)


def _one_checksum(value: dict[str, Any], label: str, errors: list[str]) -> None:
    present = [name for name in ("sha256", "sha512") if name in value]
    if len(present) != 1:
        errors.append(f"{label}: exactly one sha256 or sha512 is required")
        return
    algorithm = present[0]
    checksum = value[algorithm]
    if not isinstance(checksum, str) or HEX_RE[algorithm].fullmatch(checksum) is None:
        errors.append(f"{label}: malformed {algorithm}")


def _manifest_errors(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != 1:
        errors.append("tools manifest: schema_version must be 1")
    policy = manifest.get("policy")
    if not isinstance(policy, dict):
        errors.append("tools manifest: policy is required")
        return errors
    if policy.get("install_root") != "build/tools":
        errors.append("tools manifest: install_root must be build/tools")
    if policy.get("global_installs_allowed") is not False:
        errors.append("tools manifest: global installs must be disabled")
    if policy.get("mutable_installers_allowed") is not False:
        errors.append("tools manifest: mutable installers must be disabled")
    if set(policy.get("supported_platforms", [])) != SUPPORTED_PLATFORMS:
        errors.append("tools manifest: supported platform set drifted")

    records = manifest.get("runtimes", []) + manifest.get("tools", [])
    if not isinstance(records, list):
        return errors + ["tools manifest: runtimes and tools must be arrays"]
    names: list[str] = []
    for index, record in enumerate(records):
        label = f"tools manifest record {index}"
        if not isinstance(record, dict):
            errors.append(f"{label}: expected object")
            continue
        name = record.get("name")
        names.append(name if isinstance(name, str) else "")
        label = f"tool {name!r}"
        if not isinstance(name, str) or not name:
            errors.append(f"{label}: name is required")
        if not _exact_version(record.get("version")):
            errors.append(f"{label}: version must be exact and non-floating")
        if record.get("license") not in ALLOWED_LICENSES:
            errors.append(f"{label}: license is absent from the reviewed allowlist")
        if not isinstance(record.get("purpose"), str) or len(record["purpose"]) < 8:
            errors.append(f"{label}: purpose is required")
        if not _is_https(record.get("source", "")):
            errors.append(f"{label}: source must be credential-free HTTPS")
        bootstrap = record.get("bootstrap")
        if not isinstance(bootstrap, bool):
            errors.append(f"{label}: bootstrap must be boolean")
            continue
        if bootstrap:
            artifacts = record.get("artifacts")
            if not isinstance(artifacts, dict):
                errors.append(f"{label}: bootstrap artifacts are required")
                continue
            expected = {"all"} if name == "pnpm" else SUPPORTED_PLATFORMS
            if set(artifacts) != expected:
                errors.append(f"{label}: artifact platform set must equal {sorted(expected)}")
            for platform_name, artifact in artifacts.items():
                artifact_label = f"{label} artifact {platform_name}"
                if not isinstance(artifact, dict):
                    errors.append(f"{artifact_label}: expected object")
                    continue
                if not _is_https(artifact.get("url", "")):
                    errors.append(f"{artifact_label}: URL must be credential-free HTTPS")
                if artifact.get("archive") not in {"tar.gz", "zip"}:
                    errors.append(f"{artifact_label}: unsupported archive type")
                if not isinstance(artifact.get("root"), str):
                    errors.append(f"{artifact_label}: archive root is required")
                else:
                    root = artifact["root"]
                    pure_root = PurePosixPath(root)
                    if not root or pure_root.is_absolute() or ".." in pure_root.parts or "\\" in root:
                        errors.append(f"{artifact_label}: archive root must be safe and relative")
                _one_checksum(artifact, artifact_label, errors)
        elif name != "postgresql":
            activation = record.get("activation")
            if name in {"sqlc", "duckdb"}:
                expected_activation = {
                    "status": "blocked",
                    "reason": "platform-integrity-incomplete",
                    "required_platforms": sorted(SUPPORTED_PLATFORMS),
                    "pinned_platforms": ["darwin-arm64"],
                }
                if activation != expected_activation:
                    errors.append(
                        f"{label}: activation must remain blocked until all platform pins exist"
                    )
            elif activation is not None:
                errors.append(f"{label}: unexpected activation override")
            integrity = record.get("integrity")
            if not isinstance(integrity, dict):
                errors.append(f"{label}: deferred tool requires immutable integrity metadata")
            else:
                version = str(record.get("version", ""))
                if not version or version not in str(record.get("source", "")):
                    errors.append(f"{label}: source does not bind the exact deferred version")
                if version not in str(integrity.get("url", "")):
                    errors.append(
                        f"{label}: integrity provenance URL does not bind the exact deferred version"
                    )
                if integrity.get("kind") == "go-sum":
                    expected_fields = {"kind", "url", "module", "sum", "go_mod_sum", "origin_sha1"}
                    if set(integrity) != expected_fields:
                        errors.append(f"{label}: go-sum integrity has missing or extra fields")
                    if re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", str(integrity.get("sum", ""))) is None:
                        errors.append(f"{label}: malformed Go module sum")
                    if re.fullmatch(
                        r"h1:[A-Za-z0-9+/]{43}=", str(integrity.get("go_mod_sum", ""))
                    ) is None:
                        errors.append(f"{label}: malformed Go go.mod sum")
                    if re.fullmatch(r"[0-9a-f]{40}", str(integrity.get("origin_sha1", ""))) is None:
                        errors.append(f"{label}: malformed Go origin commit")
                    if not isinstance(integrity.get("module"), str) or not integrity["module"].endswith(
                        f"@v{version}"
                    ):
                        errors.append(f"{label}: Go module identity does not bind the exact version")
                else:
                    checksum_fields = [field for field in ("sha256", "sha512") if field in integrity]
                    if len(checksum_fields) != 1:
                        errors.append(f"{label}: deferred tool needs one source or artifact checksum")
                    else:
                        algorithm = checksum_fields[0]
                        if HEX_RE[algorithm].fullmatch(str(integrity[algorithm])) is None:
                            errors.append(f"{label}: malformed deferred {algorithm}")
                if not _is_https(integrity.get("url", "")):
                    errors.append(f"{label}: integrity provenance must be credential-free HTTPS")
    if len(names) != len(set(names)):
        errors.append("tools manifest: duplicate tool names")
    if not BOOTSTRAP_NAMES.issubset(set(names)):
        errors.append(f"tools manifest: missing bootstrap records {sorted(BOOTSTRAP_NAMES - set(names))}")
    return errors


def _record_versions(manifest: dict[str, Any]) -> dict[str, str]:
    return {
        record["name"]: record["version"]
        for record in manifest["runtimes"] + manifest["tools"]
    }


def _tool_versions_file() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in (ROOT / ".tool-versions").read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise LockError(f".tool-versions has malformed line: {line!r}")
        result[parts[0]] = parts[1]
    return result


def _mise_versions() -> dict[str, str]:
    text = (ROOT / "mise.toml").read_text(encoding="utf-8")
    match = re.search(r"(?ms)^\[tools\]\s*(.*?)(?=^\[|\Z)", text)
    if match is None:
        raise LockError("mise.toml has no [tools] table")
    return dict(re.findall(r'^([a-z0-9_-]+)\s*=\s*"([^"]+)"\s*$', match.group(1), re.MULTILINE))


def _workspace_errors(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    versions = _record_versions(manifest)
    expected_tools = {
        "golang": versions["go"],
        "nodejs": versions["node"],
        "pnpm": versions["pnpm"],
        "opentofu": versions["opentofu"],
    }
    if _tool_versions_file() != expected_tools:
        errors.append(".tool-versions does not exactly match tools/manifest.yaml")
    expected_mise = {
        "go": versions["go"],
        "node": versions["node"],
        "pnpm": versions["pnpm"],
        "opentofu": versions["opentofu"],
    }
    if _mise_versions() != expected_mise:
        errors.append("mise.toml does not exactly match tools/manifest.yaml")

    go_mod = (ROOT / "go.mod").read_text(encoding="utf-8")
    if re.search(rf"(?m)^go {re.escape(versions['go'])}$", go_mod) is None:
        errors.append("go.mod go directive does not match the Go pin")
    toolchain_match = re.search(r"(?m)^toolchain go([^\s]+)$", go_mod)
    if toolchain_match is not None and toolchain_match.group(1) != versions["go"]:
        errors.append("go.mod toolchain directive conflicts with the exact Go pin")

    root_package = _load_json_yaml(ROOT / "package.json")
    web_package = _load_json_yaml(ROOT / "web" / "package.json")
    expected_manager_prefix = f"pnpm@{versions['pnpm']}+sha512."
    manager = root_package.get("packageManager", "")
    if not manager.startswith(expected_manager_prefix):
        errors.append("root packageManager does not bind the exact pnpm version and SHA-512")
    else:
        encoded = manager[len(expected_manager_prefix) :]
        try:
            decoded = base64.b64decode(encoded, validate=True).hex()
        except (binascii.Error, ValueError):
            errors.append("root packageManager has malformed pnpm SRI")
        else:
            pnpm_record = next(item for item in manifest["runtimes"] if item["name"] == "pnpm")
            if decoded != pnpm_record["artifacts"]["all"]["sha512"]:
                errors.append("root packageManager integrity differs from tools/manifest.yaml")
    for package_name, package in (("root", root_package), ("web", web_package)):
        if package.get("private") is not True:
            errors.append(f"{package_name} package must be private")
        engines = package.get("engines", {})
        if engines != {"node": versions["node"], "pnpm": versions["pnpm"]}:
            errors.append(f"{package_name} engines do not exactly match the runtime pins")
        for dependency_kind in ("dependencies", "devDependencies", "optionalDependencies"):
            dependencies = package.get(dependency_kind, {})
            if not isinstance(dependencies, dict):
                errors.append(f"{package_name} {dependency_kind} must be an object")
                continue
            for dependency_name, version in dependencies.items():
                if not _exact_version(version):
                    errors.append(
                        f"{package_name} {dependency_kind} {dependency_name!r} is not exactly pinned"
                    )

    workspace_text = (ROOT / "pnpm-workspace.yaml").read_text(encoding="utf-8")
    expected_workspace = (
        "packages:\n"
        "  - web\n"
        "\n"
        "onlyBuiltDependencies: []\n"
    )
    if workspace_text != expected_workspace:
        errors.append("pnpm-workspace.yaml supported architecture policy drifted")
    package_entries = re.findall(r"(?m)^\s{2}-\s+([^#\s]+)\s*$", workspace_text)
    if package_entries != ["web"]:
        errors.append("pnpm-workspace.yaml must list exactly the web package")
    lockfiles: list[str] = []
    excluded_directories = {".git", ".tools", "build", "node_modules", ".next"}
    for directory, child_directories, files in os.walk(ROOT, topdown=True, followlinks=False):
        directory_path = Path(directory)
        child_directories[:] = sorted(
            child
            for child in child_directories
            if child not in excluded_directories and not (directory_path / child).is_symlink()
        )
        if "pnpm-lock.yaml" in files:
            lockfiles.append((directory_path / "pnpm-lock.yaml").relative_to(ROOT).as_posix())
    lockfiles.sort()
    if lockfiles != ["pnpm-lock.yaml"]:
        errors.append(f"exactly one root pnpm lockfile is allowed; observed {lockfiles}")
    else:
        lock_text = (ROOT / "pnpm-lock.yaml").read_text(encoding="utf-8")
        if re.search(r"(?m)^lockfileVersion:\s*['\"]?9\.0['\"]?\s*$", lock_text) is None:
            errors.append("pnpm-lock.yaml must use the pnpm 11 lockfileVersion 9.0")
        if re.search(r"(?m)^\s{2}\.\s*:\s*(?:\{\})?\s*$", lock_text) is None:
            errors.append("pnpm-lock.yaml is missing the root importer")
        if re.search(r"(?m)^\s{2}web\s*:\s*$", lock_text) is None:
            errors.append("pnpm-lock.yaml is missing the web importer")
    return errors


def _canonical_receipt_path(request: dict[str, Any], *, root: Path | None = None) -> Path:
    if root is None:
        root = ROOT
    return (
        root
        / "delivery"
        / "mvp"
        / "evidence"
        / request["packet_id"]
        / "dependency-locks"
        / f"{request['request_id']}.json"
    )


def _digest_string(value: Any) -> bool:
    return isinstance(value, str) and HEX_RE["sha256"].fullmatch(value) is not None


def _receipt_validation_errors(
    request_path: Path,
    request: dict[str, Any],
    receipt_path: Path,
    *,
    root: Path | None = None,
) -> list[str]:
    if root is None:
        root = ROOT
    errors: list[str] = []
    if receipt_path.is_symlink() or not receipt_path.is_file():
        return ["applied request receipt must be a non-symlink regular file"]
    try:
        receipt = _load_json_yaml(receipt_path)
    except LockError as exc:
        return [str(exc)]
    if not isinstance(receipt, dict):
        return ["applied request receipt must be an object"]
    expected_keys = {
        "schema_version",
        "receipt_kind",
        "status",
        "request_id",
        "packet_id",
        "request_path",
        "accepted_request_sha256",
        "applied_request_sha256",
        "base_commit",
        "candidate_commit",
        "completed_at",
        "root_lock_changes",
        "tool_manifest_sha256",
        "validations",
        "approval",
    }
    if set(receipt) != expected_keys:
        errors.append("applied request receipt has missing or extra top-level fields")
    if receipt.get("schema_version") != 1:
        errors.append("applied request receipt schema_version must be 1")
    if receipt.get("receipt_kind") != "jumpship-serialized-dependency-lock-update":
        errors.append("applied request receipt kind is invalid")
    if receipt.get("status") != "complete":
        errors.append("applied request receipt status must be complete")
    if receipt.get("request_id") != request.get("request_id"):
        errors.append("applied request receipt request_id does not match")
    if receipt.get("packet_id") != request.get("packet_id"):
        errors.append("applied request receipt packet_id does not match")
    try:
        expected_request_path = request_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return errors + ["applied request path is outside the repository"]
    if receipt.get("request_path") != expected_request_path:
        errors.append("applied request receipt request_path does not match")
    try:
        request_bytes = request_path.read_bytes()
    except OSError as exc:
        return errors + [f"cannot read applied request bytes: {exc}"]
    canonical_request_bytes = _canonical_bytes(request)
    if request_bytes != canonical_request_bytes:
        errors.append("applied request file must use canonical serialized bytes")
    applied_sha256 = _digest_bytes(canonical_request_bytes)
    if receipt.get("applied_request_sha256") != applied_sha256:
        errors.append("applied request receipt does not bind the applied request hash")
    if not _digest_string(receipt.get("accepted_request_sha256")):
        errors.append("applied request receipt accepted_request_sha256 is malformed")
    if receipt.get("accepted_request_sha256") == applied_sha256:
        errors.append("accepted and applied request hashes must represent distinct lifecycle states")
    if receipt.get("approval") != request.get("approval"):
        errors.append("applied request receipt approval does not match the request")
    if _utc_timestamp(receipt.get("completed_at")) is None:
        errors.append("applied request receipt completed_at must be a real UTC timestamp")
    for field in ("base_commit", "candidate_commit"):
        if re.fullmatch(r"[0-9a-f]{40}", str(receipt.get(field, ""))) is None:
            errors.append(f"applied request receipt {field} must be a full commit ID")

    manifest_path = root / "tools" / "manifest.yaml"
    candidate_commit_value = receipt.get("candidate_commit")
    historical_git_context = (
        root.resolve() == ROOT.resolve()
        and re.fullmatch(r"[0-9a-f]{40}", str(candidate_commit_value or "")) is not None
    )
    if historical_git_context:
        receipt_manifest_bytes = _commit_bytes(candidate_commit_value, "tools/manifest.yaml")
    else:
        try:
            receipt_manifest_bytes = manifest_path.read_bytes()
        except OSError:
            receipt_manifest_bytes = None
    if receipt_manifest_bytes is None or receipt.get("tool_manifest_sha256") != _digest_bytes(
        receipt_manifest_bytes
    ):
        errors.append("applied request receipt tool manifest hash does not match")

    changes = receipt.get("root_lock_changes")
    changed_paths: list[str] = []
    if not isinstance(changes, list) or not changes:
        errors.append("applied request receipt root_lock_changes must be non-empty")
    else:
        for index, change in enumerate(changes):
            label = f"applied request receipt root_lock_changes[{index}]"
            if not isinstance(change, dict) or set(change) != {
                "path",
                "before_sha256",
                "after_sha256",
            }:
                errors.append(f"{label} has missing or extra fields")
                continue
            path = change.get("path")
            if path not in LOCK_PATHS:
                errors.append(f"{label} path is not a root lock")
            else:
                changed_paths.append(path)
            before = change.get("before_sha256")
            if before is not None and not _digest_string(before):
                errors.append(f"{label} before_sha256 is malformed")
            if not _digest_string(change.get("after_sha256")):
                errors.append(f"{label} after_sha256 is malformed")
        if len(changed_paths) != len(set(changed_paths)):
            errors.append("applied request receipt repeats a root lock path")
        declared = request.get("affected_lockfiles", [])
        if not set(changed_paths).issubset(set(declared) if isinstance(declared, list) else set()):
            errors.append("applied request receipt contains an undeclared root lock path")

    validations = receipt.get("validations")
    validation_keys = {
        "toolchain",
        "deferred_provenance",
        "license",
        "vulnerability",
        "clean_clone",
    }
    if not isinstance(validations, dict) or set(validations) != validation_keys:
        errors.append("applied request receipt validations are incomplete")
    else:
        toolchain = validations.get("toolchain")
        if not isinstance(toolchain, dict) or toolchain.get("command") != [
            "internal:toolchain._bootstrap_unlocked(repair=True)",
        ] or not _digest_string(toolchain.get("stdout_sha256")):
            errors.append("applied request receipt toolchain validation is invalid")
        provenance = validations.get("deferred_provenance")
        if not isinstance(provenance, dict) or provenance.get("command") != [
            "internal:_verify_deferred_provenance_unlocked"
        ] or not _digest_string(provenance.get("stdout_sha256")):
            errors.append("applied request receipt deferred provenance validation is invalid")
        license_validation = validations.get("license")
        if not isinstance(license_validation, dict) or not _digest_string(
            license_validation.get("stdout_sha256")
        ) or license_validation.get("command") != [
            "pnpm",
            "licenses",
            "list",
            "--json",
        ] or not _digest_string(
            license_validation.get("candidate_install_stdout_sha256")
        ) or not _digest_string(
            license_validation.get("go_module_inventory_sha256")
        ) or not _digest_string(license_validation.get("pnpm_inventory_sha256")):
            errors.append("applied request receipt license validation is invalid")
        else:
            coverage = license_validation.get("pnpm_supported_platform_coverage")
            if (
                not isinstance(coverage, dict)
                or not isinstance(coverage.get("supported_lock_packages"), int)
                or coverage.get("supported_lock_packages", 0) <= 0
                or coverage.get("covered_lock_packages")
                != coverage.get("supported_lock_packages")
                or not isinstance(coverage.get("host_inventory_packages"), int)
                or not isinstance(coverage.get("tarball_derived_packages"), list)
                or coverage.get("host_inventory_packages")
                + len(coverage.get("tarball_derived_packages", []))
                != coverage.get("supported_lock_packages")
            ):
                errors.append("applied request receipt pnpm platform license coverage is invalid")
            elif any(
                not isinstance(item, dict)
                or item.get("license") not in PACKAGE_LICENSE_ALLOWLIST
                or not _integrity_value_valid("npm-sri", item.get("integrity"))
                or not _is_https(item.get("source_url", ""))
                or not str(item.get("source_url", "")).startswith(OFFICIAL_NPM_REGISTRY)
                for item in coverage["tarball_derived_packages"]
            ):
                errors.append("applied request receipt pnpm tarball license evidence is invalid")
            reviewed = license_validation.get("requested_dependencies")
            expected_dependencies = sorted(
                request["dependencies"], key=lambda item: (item["ecosystem"], item["name"])
            )
            if not isinstance(reviewed, list) or len(reviewed) != len(expected_dependencies):
                errors.append(
                    "applied request receipt license review does not bind requested dependencies"
                )
            else:
                for dependency, item in zip(expected_dependencies, reviewed, strict=True):
                    expected_core = {
                        "ecosystem": dependency["ecosystem"],
                        "name": dependency["name"],
                        "version": dependency["version"],
                        "license": dependency["license"],
                        "integrity": dependency["integrity"],
                        "source_url": dependency["source_url"],
                        "direct_runtime_dependency": dependency["direct_runtime_dependency"],
                    }
                    if not isinstance(item, dict) or any(
                        item.get(key) != value for key, value in expected_core.items()
                    ) or not isinstance(item.get("integrity_binding"), str) or item.get(
                        "license_basis"
                    ) not in {
                        "pnpm-installed-inventory",
                        "steward-reviewed-manifest",
                        "steward-reviewed-request",
                    }:
                        errors.append(
                            "applied request receipt dependency review contains an invalid binding"
                        )
                        break
            try:
                receipt_manifest = json.loads(receipt_manifest_bytes or b"")
                manifest_licenses = {
                    record["name"]: record["license"]
                    for record in receipt_manifest["runtimes"] + receipt_manifest["tools"]
                }
            except (json.JSONDecodeError, KeyError, TypeError):
                errors.append("applied request receipt candidate tool manifest is invalid")
            else:
                if license_validation.get("tool_manifest_licenses") != manifest_licenses:
                    errors.append("applied request receipt tool license inventory drifted")
        vulnerability = validations.get("vulnerability")
        if not isinstance(vulnerability, dict) or not _digest_string(
            vulnerability.get("pnpm_audit_stdout_sha256")
        ) or not _digest_string(vulnerability.get("trivy_stdout_sha256")) or vulnerability.get(
            "trivy_high_critical_findings"
        ) != 0:
            errors.append("applied request receipt vulnerability validation is invalid")
        else:
            pnpm_counts = vulnerability.get("pnpm_counts")
            if (
                not isinstance(pnpm_counts, dict)
                or pnpm_counts.get("high", 0) != 0
                or pnpm_counts.get("critical", 0) != 0
            ):
                errors.append("applied request receipt vulnerability counts are invalid")
            database = vulnerability.get("trivy_database")
            if (
                not isinstance(database, dict)
                or database.get("repository") != TRIVY_DB_REPOSITORY
                or not _digest_string(database.get("metadata_sha256"))
                or not _digest_string(database.get("database_sha256"))
                or not isinstance(database.get("metadata"), dict)
                or database["metadata"].get("Version") != 2
            ):
                errors.append("applied request receipt Trivy database evidence is invalid")
        clean_clone = validations.get("clean_clone")
        environment = clean_clone.get("environment") if isinstance(clean_clone, dict) else None
        if (
            not isinstance(clean_clone, dict)
            or clean_clone.get("source_commit") != receipt.get("candidate_commit")
            or not _digest_string(clean_clone.get("report_sha256"))
            or not _digest_string(clean_clone.get("stdout_sha256"))
            or not isinstance(environment, dict)
            or environment.get("isolated_home") is not True
            or environment.get("local_clone_no_hardlinks") is not True
            or environment.get("source_worktree_clean") is not True
            or environment.get("cloud_credentials_forwarded") is not False
        ):
            errors.append("applied request receipt clean-clone validation is invalid")

    if root.resolve() == ROOT.resolve() and not any(
        "commit ID" in error for error in errors
    ):
        base_commit = receipt["base_commit"]
        candidate_commit = receipt["candidate_commit"]
        accepted_bytes = _commit_bytes(candidate_commit, expected_request_path)
        if accepted_bytes is None or _digest_bytes(accepted_bytes) != receipt.get(
            "accepted_request_sha256"
        ):
            errors.append("applied request receipt does not bind the accepted candidate bytes")
        try:
            candidate_changes = _candidate_changes(base_commit, candidate_commit)
        except LockError as exc:
            errors.append(f"applied request receipt commit range is invalid: {exc}")
        else:
            expected_changed = set(changed_paths) | {expected_request_path}
            if set(candidate_changes) != expected_changed:
                errors.append("applied request receipt changed-path set does not match its candidate")
            for change in changes if isinstance(changes, list) else []:
                if not isinstance(change, dict) or change.get("path") not in LOCK_PATHS:
                    continue
                before = _commit_bytes(base_commit, change["path"])
                after = _commit_bytes(candidate_commit, change["path"])
                if (None if before is None else _digest_bytes(before)) != change.get(
                    "before_sha256"
                ):
                    errors.append(f"applied request receipt before hash drifted: {change['path']}")
                if after is None or _digest_bytes(after) != change.get("after_sha256"):
                    errors.append(f"applied request receipt after hash drifted: {change['path']}")
    return errors


def _request_lifecycle_errors(
    request_path: Path, request: dict[str, Any], *, root: Path | None = None
) -> list[str]:
    if root is None:
        root = ROOT
    if (
        not isinstance(request.get("packet_id"), str)
        or PACKET_RE.fullmatch(request["packet_id"]) is None
        or not isinstance(request.get("request_id"), str)
        or REQUEST_ID_RE.fullmatch(request["request_id"]) is None
    ):
        return []
    receipt_path = _canonical_receipt_path(request, root=root)
    receipt_exists = receipt_path.exists() or receipt_path.is_symlink()
    status = request.get("status")
    if status == "accepted" and receipt_exists:
        return [
            "accepted request has a canonical receipt but the applied transition is incomplete; "
            "automatic recovery is forbidden"
        ]
    if status in {"proposed", "rejected"} and receipt_exists:
        return ["non-applied request has an unexpected canonical receipt"]
    if status == "applied":
        if not receipt_exists:
            return [
                "applied status requires its canonical complete receipt; only apply-request may transition"
            ]
        return _receipt_validation_errors(request_path, request, receipt_path, root=root)
    return []


def check_root_locks() -> None:
    schema = _load_json_yaml(SCHEMA_PATH)
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise LockError("dependency request schema must be JSON Schema 2020-12")
    manifest = _load_json_yaml(MANIFEST_PATH)
    errors = _manifest_errors(manifest) + _workspace_errors(manifest)
    request_dir = ROOT / "dependency" / "requests"
    for request_path in sorted(request_dir.glob("P[0-9][0-9].yaml")):
        request_path_errors = request_errors(request_path)
        if not request_path_errors:
            request = _load_json_yaml(request_path)
            request_path_errors.extend(_request_lifecycle_errors(request_path, request))
        errors.extend(
            f"{request_path.relative_to(ROOT)}: {item}" for item in request_path_errors
        )
    if errors:
        raise LockError("dependency lock validation failed:\n- " + "\n- ".join(errors))
    print("dependency-lock-check: manifest, runtime pins, workspace, root lock, and requests valid")


def _provenance_url(url: str, *, allow_redirect_query: bool = False) -> None:
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in PROVENANCE_HOSTS
        or parsed.username
        or parsed.password
        or parsed.fragment
        or (parsed.query and not allow_redirect_query)
    ):
        raise LockError(f"provenance URL is outside the closed HTTPS host set: {url}")


def _url_digest(url: str, algorithm: str) -> str:
    _provenance_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "jumpship-provenance-check/1"})
    digest = hashlib.new(algorithm)
    observed_size = 0
    with urllib.request.urlopen(request, timeout=120) as response:
        _provenance_url(response.geturl(), allow_redirect_query=True)
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            observed_size += len(chunk)
            if observed_size > 512 * 1024 * 1024:
                raise LockError(f"provenance artifact exceeds the 512 MiB verification limit: {url}")
            digest.update(chunk)
    return digest.hexdigest()


@contextlib.contextmanager
def _temporary_process_environment(environment: dict[str, str] | None) -> Iterator[None]:
    if environment is None:
        yield
        return
    original = dict(os.environ)
    os.environ.clear()
    os.environ.update(environment)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def _verify_deferred_provenance_unlocked(
    *, command_env: dict[str, str] | None = None
) -> None:
    """Verify deferred pins while the caller owns the tool-operation lock."""

    with _temporary_process_environment(command_env):
        manifest = _load_json_yaml(MANIFEST_PATH)
        errors = _manifest_errors(manifest)
        if errors:
            raise LockError("cannot verify malformed tool manifest:\n- " + "\n- ".join(errors))
        for record in manifest["tools"]:
            if record["bootstrap"]:
                continue
            integrity = record["integrity"]
            kind = integrity["kind"]
            if kind == "go-sum":
                command = [
                    str(TOOLS_ROOT / "bin" / "go"),
                    "mod",
                    "download",
                    "-json",
                    integrity["module"],
                ]
                env = _tool_env() if command_env is None else command_env.copy()
                env.update({"GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org"})
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=env,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=300,
                )
                if result.returncode != 0:
                    raise LockError(
                        f"{record['name']}: Go provenance check failed: {result.stderr.strip()}"
                    )
                value = json.loads(result.stdout)
                if (
                    value.get("Sum") != integrity["sum"]
                    or value.get("GoModSum") != integrity["go_mod_sum"]
                    or value.get("Origin", {}).get("Hash") != integrity["origin_sha1"]
                ):
                    raise LockError(f"{record['name']}: Go proxy/checksum provenance drifted")
            elif kind == "pypi-sdist":
                _provenance_url(integrity["url"])
                request = urllib.request.Request(
                    integrity["url"], headers={"User-Agent": "jumpship-provenance-check/1"}
                )
                with urllib.request.urlopen(request, timeout=60) as response:
                    _provenance_url(response.geturl(), allow_redirect_query=True)
                    metadata = json.load(response)
                candidates = [
                    item
                    for item in metadata.get("urls", [])
                    if item.get("filename") == integrity["artifact"]
                    and item.get("packagetype") == "sdist"
                ]
                if (
                    len(candidates) != 1
                    or candidates[0].get("digests", {}).get("sha256") != integrity["sha256"]
                ):
                    raise LockError(f"{record['name']}: PyPI sdist metadata drifted")
                if _url_digest(candidates[0]["url"], "sha256") != integrity["sha256"]:
                    raise LockError(f"{record['name']}: downloaded PyPI sdist checksum mismatch")
            else:
                algorithm = "sha512" if "sha512" in integrity else "sha256"
                if _url_digest(integrity["url"], algorithm) != integrity[algorithm]:
                    raise LockError(f"{record['name']}: downloaded provenance checksum mismatch")
            print(f"dependency-provenance-check: {record['name']} {record['version']} verified")
            activation = record.get("activation")
            if isinstance(activation, dict) and activation.get("status") == "blocked":
                print(
                    f"dependency-provenance-check: {record['name']} activation blocked "
                    f"({activation['reason']}; pinned {activation['pinned_platforms']})"
                )


def verify_deferred_provenance() -> None:
    """Standalone provenance entry serialized with bootstrap/apply writers."""

    with tool_operation_lock(exclusive=False):
        _preflight_dependency_mutable_paths()
        _verify_deferred_provenance_unlocked()


def _keys_containing_secrets(value: Any, location: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if re.search(r"(?i)(password|private[_-]?key|secret|token|credential)", str(key)):
                findings.append(f"{location}.{key}")
            findings.extend(_keys_containing_secrets(child, f"{location}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_keys_containing_secrets(child, f"{location}[{index}]"))
    return findings


def request_errors(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        request = _load_json_yaml(path)
    except LockError as exc:
        return [str(exc)]
    if not isinstance(request, dict):
        return ["request must be an object"]
    allowed_top = {
        "schema_version",
        "request_id",
        "packet_id",
        "status",
        "created_at",
        "requested_by",
        "dependencies",
        "affected_lockfiles",
        "affected_builds",
        "risk",
        "validation_requirements",
        "approval",
        "rejection_reason",
    }
    required_top = allowed_top - {"approval", "rejection_reason"}
    errors.extend(f"unexpected property {key!r}" for key in sorted(set(request) - allowed_top))
    errors.extend(f"missing property {key!r}" for key in sorted(required_top - set(request)))
    packet_id = request.get("packet_id")
    if not isinstance(packet_id, str) or PACKET_RE.fullmatch(packet_id) is None:
        errors.append("packet_id must be P02..P28")
    request_id = request.get("request_id")
    request_match = REQUEST_ID_RE.fullmatch(request_id) if isinstance(request_id, str) else None
    if request_match is None or request_match.group(1) != packet_id:
        errors.append("request_id must be namespaced to packet_id")
    if path.name != f"{packet_id}.yaml":
        errors.append("request filename must equal <packet_id>.yaml")
    if request.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if not isinstance(request.get("requested_by"), str) or not request["requested_by"].strip():
        errors.append("requested_by must be a non-empty string")
    created_at = _utc_timestamp(request.get("created_at"))
    if created_at is None:
        errors.append("created_at must be a real UTC RFC3339 timestamp with second precision")
    status = request.get("status")
    if status not in {"proposed", "accepted", "rejected", "applied"}:
        errors.append("status is outside the closed lifecycle")
    if status == "proposed":
        if "approval" in request:
            errors.append("proposed request must not contain approval")
        if "rejection_reason" in request:
            errors.append("proposed request must not contain rejection_reason")
    if status in {"accepted", "applied"}:
        approval = request.get("approval")
        if not isinstance(approval, dict):
            errors.append("accepted/applied request requires a real approval record")
        else:
            expected_keys = {"decision_id", "approved_by", "approver_role", "approved_at"}
            if set(approval) != expected_keys:
                errors.append("approval has missing or extra fields")
            if approval.get("approver_role") != "p01-root-lock-steward":
                errors.append("approval role must be p01-root-lock-steward")
            for key in ("decision_id", "approved_by", "approved_at"):
                if not isinstance(approval.get(key), str) or not approval[key]:
                    errors.append(f"approval {key} is required")
            approved_at = _utc_timestamp(approval.get("approved_at"))
            if approved_at is None:
                errors.append("approval approved_at must be a real UTC RFC3339 timestamp")
            elif created_at is not None and approved_at < created_at:
                errors.append("approval approved_at cannot precede created_at")
        if "rejection_reason" in request:
            errors.append("accepted/applied request must not contain rejection_reason")
    if status == "rejected" and (
        not isinstance(request.get("rejection_reason"), str) or not request["rejection_reason"].strip()
    ):
        errors.append("rejected request requires a non-empty string rejection_reason")
    if status == "rejected" and "approval" in request:
        errors.append("rejected request must not contain approval")

    dependencies = request.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        errors.append("dependencies must be a non-empty array")
    else:
        identities: list[tuple[Any, Any]] = []
        required_dependency = {
            "ecosystem",
            "name",
            "version",
            "license",
            "purpose",
            "source_url",
            "integrity",
            "direct_runtime_dependency",
        }
        for index, dependency in enumerate(dependencies):
            label = f"dependencies[{index}]"
            if not isinstance(dependency, dict):
                errors.append(f"{label} must be an object")
                continue
            if set(dependency) != required_dependency:
                errors.append(f"{label} has missing or extra fields")
            if dependency.get("ecosystem") not in {"go", "pnpm", "tool"}:
                errors.append(f"{label} has unknown ecosystem")
            if not isinstance(dependency.get("name"), str) or not dependency["name"]:
                errors.append(f"{label} name is required")
            if not _exact_version(dependency.get("version")):
                errors.append(f"{label} version must be exact and non-floating")
            if dependency.get("license") not in REQUEST_LICENSE_ALLOWLIST:
                errors.append(f"{label} license is not a reviewed SPDX identifier")
            if not isinstance(dependency.get("purpose"), str) or len(dependency["purpose"]) < 8:
                errors.append(f"{label} purpose is required")
            if not _is_https(dependency.get("source_url", "")):
                errors.append(f"{label} source_url must be credential-free HTTPS")
            if not isinstance(dependency.get("direct_runtime_dependency"), bool):
                errors.append(f"{label} direct_runtime_dependency must be boolean")
            integrity = dependency.get("integrity")
            if not isinstance(integrity, dict) or set(integrity) != {"algorithm", "value", "source_url"}:
                errors.append(f"{label} integrity must contain exactly algorithm/value/source_url")
            else:
                if integrity.get("algorithm") not in {
                    "sha256",
                    "sha512",
                    "npm-sri",
                    "go-sum",
                    "oci-digest",
                }:
                    errors.append(f"{label} integrity algorithm is unsupported")
                if not _integrity_value_valid(integrity.get("algorithm"), integrity.get("value")):
                    errors.append(f"{label} integrity value does not match its algorithm")
                if not _is_https(integrity.get("source_url", "")):
                    errors.append(f"{label} integrity source_url must be credential-free HTTPS")
            identities.append((dependency.get("ecosystem"), dependency.get("name")))
        if len(identities) != len(set(identities)):
            errors.append("dependency ecosystem/name identities must be unique")

    affected = request.get("affected_lockfiles")
    if not isinstance(affected, list) or not affected or not set(affected).issubset(LOCK_PATHS):
        errors.append("affected_lockfiles must be a non-empty subset of root lock paths")
    elif len(affected) != len(set(affected)):
        errors.append("affected_lockfiles must be unique")
    affected_builds = request.get("affected_builds")
    if (
        not isinstance(affected_builds, list)
        or not affected_builds
        or any(not isinstance(item, str) or not item.strip() for item in affected_builds)
    ):
        errors.append("affected_builds must contain non-empty strings")
    elif len(affected_builds) != len(set(affected_builds)):
        errors.append("affected_builds must be unique")
    requirements = request.get("validation_requirements")
    if not isinstance(requirements, list) or len(requirements) != 3 or set(requirements) != {
        "license",
        "vulnerability",
        "clean-clone",
    }:
        errors.append("validation_requirements must contain license, vulnerability, and clean-clone")
    risk = request.get("risk")
    if not isinstance(risk, dict) or set(risk) != {
        "security_sensitive",
        "data_boundary_impact",
        "justification",
    }:
        errors.append("risk must contain exactly security_sensitive/data_boundary_impact/justification")
    else:
        if not isinstance(risk.get("security_sensitive"), bool):
            errors.append("risk security_sensitive must be boolean")
        if risk.get("data_boundary_impact") not in {"none", "review-required"}:
            errors.append("risk data_boundary_impact is invalid")
        if not isinstance(risk.get("justification"), str) or len(risk["justification"].strip()) < 8:
            errors.append("risk justification must contain at least 8 characters")
    secret_keys = _keys_containing_secrets(request)
    if secret_keys:
        errors.append(f"request contains forbidden secret-bearing fields: {secret_keys}")
    return errors


def validate_request(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise LockError("dependency request must not be a symlink")
    try:
        relative = path.resolve().relative_to(ROOT.resolve())
    except ValueError as exc:
        raise LockError("request must be inside the repository") from exc
    if relative.parent.as_posix() != "dependency/requests":
        raise LockError("request must be dependency/requests/Pxx.yaml")
    errors = request_errors(path)
    request = _load_json_yaml(path)
    if not errors:
        errors.extend(_request_lifecycle_errors(path, request))
    if errors:
        raise LockError("dependency request validation failed:\n- " + "\n- ".join(errors))
    print(f"dependency-request-check: {request['request_id']} is schema-valid ({request['status']})")
    return request


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and result.returncode != 0:
        raise LockError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result


def _parse_status_z(output: str) -> set[str]:
    entries = output.split("\0")
    paths: set[str] = set()
    index = 0
    while index < len(entries):
        entry = entries[index]
        index += 1
        if not entry:
            continue
        status = entry[:2]
        path = entry[3:]
        if "R" in status or "C" in status:
            raise LockError(
                f"serialized root-lock apply forbids rename/copy status {status!r} for {path!r}"
            )
        paths.add(path)
    return paths


def _status_paths() -> set[str]:
    return _parse_status_z(
        _git("status", "--porcelain=v1", "--untracked-files=all", "-z").stdout
    )


def _commit_bytes(commit: str, path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{commit}:{path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return result.stdout if result.returncode == 0 else None


def _parse_diff_name_status_z(output: str) -> dict[str, str]:
    entries = output.split("\0")
    changes: dict[str, str] = {}
    index = 0
    while index < len(entries):
        status = entries[index]
        index += 1
        if not status:
            continue
        if index >= len(entries) or not entries[index]:
            raise LockError("cannot parse candidate commit name-status output")
        path = entries[index]
        index += 1
        code = status[:1]
        if code in {"R", "C"}:
            raise LockError(f"serialized root-lock apply forbids rename/copy of {path!r}")
        if code not in {"A", "M", "D"}:
            raise LockError(f"serialized root-lock apply rejects status {status!r} for {path!r}")
        if path in changes:
            raise LockError(f"candidate commit repeats changed path {path!r}")
        changes[path] = code
    return changes


def _candidate_changes(base_commit: str, candidate_commit: str) -> dict[str, str]:
    parent_line = _git("rev-list", "--parents", "-n", "1", candidate_commit).stdout.strip().split()
    if len(parent_line) != 2:
        raise LockError("candidate commit must be a non-merge commit with exactly one parent")
    if parent_line[1] != base_commit:
        raise LockError("--base-commit must be the candidate commit's immediate parent")
    output = _git(
        "diff",
        "--name-status",
        "--no-renames",
        "-z",
        base_commit,
        candidate_commit,
    ).stdout
    return _parse_diff_name_status_z(output)


def _tool_env() -> dict[str, str]:
    bin_root = TOOLS_ROOT / "bin"
    env = os.environ.copy()
    env.update(
        {
            "COREPACK_HOME": str(TOOLS_ROOT / "corepack"),
            "GOCACHE": str(TOOLS_ROOT / "go-build"),
            "GOLANGCI_LINT_CACHE": str(TOOLS_ROOT / "golangci-cache"),
            "GOMODCACHE": str(TOOLS_ROOT / "go-mod"),
            "GOTOOLCHAIN": "local",
            "NPM_CONFIG_CACHE": str(TOOLS_ROOT / "npm-cache"),
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
            "PNPM_HOME": str(bin_root),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    env["PATH"] = str(bin_root) + os.pathsep + env.get("PATH", "")
    return env


def _validation_env() -> dict[str, str]:
    _preflight_dependency_mutable_paths()
    inherited_allowlist = {
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "LANG",
        "LC_ALL",
        "NO_PROXY",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
    }
    env = {name: value for name, value in os.environ.items() if name in inherited_allowlist}
    # Keep command discovery deterministic without inheriting an arbitrary host
    # PATH. These are the only host programs the documented preflight permits.
    host_directories = {"/bin", "/usr/bin"}
    for command in ("git", "make", "sh"):
        executable = shutil.which(command)
        if executable is None:
            raise LockError(f"closed validation environment cannot locate host prerequisite {command}")
        host_directories.add(str(Path(executable).resolve().parent))
    host_directories.add(str(Path(sys.executable).resolve().parent))
    validation_home = TOOLS_ROOT / "validation-home"
    config_home = validation_home / "config"
    cache_home = validation_home / "cache"
    docker_config = validation_home / "docker"
    temporary_home = validation_home / "tmp"
    for directory in (validation_home, config_home, cache_home, docker_config, temporary_home):
        if directory.is_symlink():
            raise LockError(f"closed validation environment refuses symlinked path: {directory}")
        directory.mkdir(parents=True, exist_ok=True)
        if not directory.is_dir():
            raise LockError(f"closed validation environment path is not a directory: {directory}")
    env.update(
        {
            "CI": "true",
            "DOCKER_CONFIG": str(docker_config),
            "COREPACK_HOME": str(TOOLS_ROOT / "corepack"),
            "GOCACHE": str(TOOLS_ROOT / "go-build"),
            "GOLANGCI_LINT_CACHE": str(TOOLS_ROOT / "golangci-cache"),
            "GOMODCACHE": str(TOOLS_ROOT / "go-mod"),
            "GOPROXY": "https://proxy.golang.org",
            "GOSUMDB": "sum.golang.org",
            "GOTOOLCHAIN": "local",
            "HOME": str(validation_home),
            "NPM_CONFIG_ALWAYS_AUTH": "false",
            "NPM_CONFIG_AUDIT_REGISTRY": OFFICIAL_NPM_REGISTRY,
            "NPM_CONFIG_CACHE": str(cache_home / "npm"),
            "NPM_CONFIG_GLOBALCONFIG": os.devnull,
            "NPM_CONFIG_REGISTRY": OFFICIAL_NPM_REGISTRY,
            "NPM_CONFIG_STRICT_SSL": "true",
            "NPM_CONFIG_USERCONFIG": os.devnull,
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
            "PATH": os.pathsep.join(sorted(host_directories)),
            "PNPM_HOME": str(TOOLS_ROOT / "bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "TMPDIR": str(temporary_home),
            "XDG_CACHE_HOME": str(cache_home),
            "XDG_CONFIG_HOME": str(config_home),
        }
    )
    for name in env:
        lowered = name.lower()
        if lowered.startswith("trivy_") or (
            ("npm" in lowered or "pnpm" in lowered)
            and ("token" in lowered or "config" in lowered)
            and name
            not in {
                "NPM_CONFIG_ALWAYS_AUTH",
                "NPM_CONFIG_AUDIT_REGISTRY",
                "NPM_CONFIG_CACHE",
                "NPM_CONFIG_GLOBALCONFIG",
                "NPM_CONFIG_REGISTRY",
                "NPM_CONFIG_STRICT_SSL",
                "NPM_CONFIG_USERCONFIG",
                "NPM_CONFIG_UPDATE_NOTIFIER",
            }
        ):
            raise LockError(f"closed validation environment retained forbidden variable {name}")
    return env


def _preflight_dependency_mutable_paths() -> None:
    assert_safe_mutable_paths(
        (
            ROOT,
            ROOT / "build",
            TOOLS_ROOT,
            TOOLS_ROOT / ".operation.lock",
            TOOLS_ROOT / "dependency-apply.lock",
            TOOLS_ROOT / "bin",
            TOOLS_ROOT / "_toolchains",
            TOOLS_ROOT / "cache",
            TOOLS_ROOT / "corepack",
            TOOLS_ROOT / "go-build",
            TOOLS_ROOT / "go-mod",
            TOOLS_ROOT / "golangci-cache",
            TOOLS_ROOT / "npm-cache",
            TOOLS_ROOT / "pnpm-store",
            TOOLS_ROOT / "trivy-cache",
            TOOLS_ROOT / "trivy-cache" / "db",
            TOOLS_ROOT / "trivy-cache" / "db" / "metadata.json",
            TOOLS_ROOT / "trivy-cache" / "db" / "trivy.db",
            TOOLS_ROOT / "validation-home",
            TOOLS_ROOT / "validation-home" / "cache",
            TOOLS_ROOT / "validation-home" / "config",
            TOOLS_ROOT / "validation-home" / "docker",
            TOOLS_ROOT / "validation-home" / "empty.trivyignore",
            TOOLS_ROOT / "validation-home" / "tmp",
            ROOT / "node_modules",
            ROOT / "web" / "node_modules",
        )
    )


def _capture(
    command: list[str],
    label: str,
    *,
    timeout: int = 900,
    env: dict[str, str] | None = None,
) -> tuple[str, int]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=_tool_env() if env is None else env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        tail = "\n".join(result.stdout.splitlines()[-20:])
        raise LockError(f"{label} failed with exit {result.returncode}:\n{tail}")
    return result.stdout, result.returncode


def _capture_json(
    command: list[str],
    label: str,
    *,
    timeout: int = 900,
    env: dict[str, str] | None = None,
) -> tuple[Any, str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=_tool_env() if env is None else env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        combined = result.stdout + "\n" + result.stderr
        tail = "\n".join(combined.splitlines()[-20:])
        raise LockError(f"{label} failed with exit {result.returncode}:\n{tail}")
    output = result.stdout
    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise LockError(f"{label} did not emit valid JSON: {exc}") from exc
    return value, _digest_bytes(output.encode("utf-8"))


def _json_stream(output: str, label: str) -> list[Any]:
    decoder = json.JSONDecoder()
    values: list[Any] = []
    offset = 0
    while offset < len(output):
        while offset < len(output) and output[offset].isspace():
            offset += 1
        if offset == len(output):
            break
        try:
            value, offset = decoder.raw_decode(output, offset)
        except json.JSONDecodeError as exc:
            raise LockError(f"{label} did not emit a valid JSON stream: {exc}") from exc
        values.append(value)
    return values


def _pnpm_package_versions(value: Any) -> set[tuple[str, str]]:
    versions: set[tuple[str, str]] = set()
    if isinstance(value, dict):
        name = value.get("name")
        version = value.get("version")
        if isinstance(name, str) and isinstance(version, str):
            versions.add((name, version))
        for child in value.values():
            versions.update(_pnpm_package_versions(child))
    elif isinstance(value, list):
        for child in value:
            versions.update(_pnpm_package_versions(child))
    return versions


def _go_proxy_escape(value: str) -> str:
    rendered: list[str] = []
    for character in value:
        if "A" <= character <= "Z":
            rendered.extend(("!", character.lower()))
        else:
            rendered.append(character)
    return "".join(rendered)


def _go_sum_values(module: str, version: str) -> dict[str, str]:
    path = ROOT / "go.sum"
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[0] != module:
            continue
        if parts[1] == version:
            values["module"] = parts[2]
        elif parts[1] == f"{version}/go.mod":
            values["go.mod"] = parts[2]
    return values


def _pnpm_lock_integrity(name: str, version: str) -> str | None:
    text = (ROOT / "pnpm-lock.yaml").read_text(encoding="utf-8")
    in_packages = False
    current: str | None = None
    expected = f"{name}@{version}"
    for line in text.splitlines():
        if line == "packages:":
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            break
        key_match = re.fullmatch(r"  ([^ ].*):", line)
        if key_match is not None:
            current = key_match.group(1).strip("'\"")
            continue
        if current == expected:
            integrity_match = re.search(r"\bintegrity:\s*([^, }]+)", line)
            if integrity_match is not None:
                return integrity_match.group(1)
    return None


def _pnpm_supported_lock_records() -> dict[tuple[str, str], str]:
    targets = {
        ("darwin", "arm64", None),
        ("darwin", "x64", None),
        ("linux", "arm64", "glibc"),
        ("linux", "x64", "glibc"),
    }
    text = (ROOT / "pnpm-lock.yaml").read_text(encoding="utf-8")
    records: list[tuple[str, dict[str, set[str]], str | None]] = []
    in_packages = False
    current_key: str | None = None
    current_constraints: dict[str, set[str]] = {}
    current_integrity: str | None = None

    def finish() -> None:
        nonlocal current_key, current_constraints, current_integrity
        if current_key is not None:
            records.append((current_key, current_constraints, current_integrity))
        current_key = None
        current_constraints = {}
        current_integrity = None

    for line in text.splitlines():
        if line == "packages:":
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            finish()
            break
        if not in_packages:
            continue
        key_match = re.fullmatch(r"  ([^ ].*):", line)
        if key_match is not None:
            finish()
            current_key = key_match.group(1).strip("'\"")
            continue
        constraint_match = re.fullmatch(r"    (os|cpu|libc): \[([^]]*)\]", line)
        if constraint_match is not None:
            current_constraints[constraint_match.group(1)] = {
                value.strip().strip("'\"")
                for value in constraint_match.group(2).split(",")
                if value.strip()
            }
        integrity_match = re.search(r"\bintegrity:\s*([^, }]+)", line)
        if integrity_match is not None:
            current_integrity = integrity_match.group(1)
    else:
        finish()

    def allows(values: set[str], observed: str | None) -> bool:
        if not values:
            return True
        if observed is None:
            return False
        if f"!{observed}" in values:
            return False
        positives = {value for value in values if not value.startswith("!")}
        return not positives or observed in positives

    required: dict[tuple[str, str], str] = {}
    for key, constraints, integrity in records:
        if not any(
            allows(constraints.get("os", set()), os_name)
            and allows(constraints.get("cpu", set()), cpu)
            and allows(constraints.get("libc", set()), libc)
            for os_name, cpu, libc in targets
        ):
            continue
        separator = key.rfind("@")
        if separator <= 0:
            raise LockError(f"cannot parse pnpm lock package identity {key!r}")
        if integrity is None or not _integrity_value_valid("npm-sri", integrity):
            raise LockError(f"supported pnpm lock package lacks valid SRI: {key}")
        required[(key[:separator], key[separator + 1 :])] = integrity
    if not required:
        raise LockError("pnpm lock contains no packages for supported architectures")
    return required


def _pnpm_supported_lock_packages() -> set[tuple[str, str]]:
    return set(_pnpm_supported_lock_records())


def _fetch_pnpm_tarball_license(name: str, version: str, integrity: str) -> dict[str, str]:
    unscoped_name = name.rsplit("/", 1)[-1]
    encoded_name = urllib.parse.quote(name, safe="@/")
    url = f"{OFFICIAL_NPM_REGISTRY}{encoded_name}/-/{unscoped_name}-{version}.tgz"
    _provenance_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "jumpship-license-check/1"})
    digest = hashlib.sha512()
    archive_bytes = bytearray()
    with urllib.request.urlopen(request, timeout=120) as response:
        _provenance_url(response.geturl(), allow_redirect_query=True)
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            archive_bytes.extend(chunk)
            digest.update(chunk)
            if len(archive_bytes) > 128 * 1024 * 1024:
                raise LockError(f"pnpm license tarball exceeds 128 MiB: {name}@{version}")
    observed_integrity = "sha512-" + base64.b64encode(digest.digest()).decode("ascii")
    if observed_integrity != integrity:
        raise LockError(f"pnpm license tarball SRI mismatch: {name}@{version}")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            member = archive.getmember("package/package.json")
            if not member.isfile() or member.size > 1024 * 1024:
                raise LockError(f"pnpm package manifest is not a bounded regular file: {name}")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise LockError(f"pnpm package manifest cannot be read: {name}")
            package = json.load(extracted)
    except (KeyError, tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LockError(f"cannot inspect pnpm package license: {name}@{version}: {exc}") from exc
    license_value = package.get("license") if isinstance(package, dict) else None
    if isinstance(license_value, dict):
        license_value = license_value.get("type")
    if license_value not in PACKAGE_LICENSE_ALLOWLIST:
        raise LockError(
            f"pnpm package has an unapproved or ambiguous tarball license: "
            f"{name}@{version} ({license_value!r})"
        )
    return {
        "name": name,
        "version": version,
        "license": license_value,
        "source_url": url,
        "integrity": integrity,
    }


def _pnpm_license_coverage(
    licenses: dict[str, Any], *, fetch_missing: bool = False
) -> dict[str, Any]:
    required_records = _pnpm_supported_lock_records()
    required = set(required_records)
    covered: set[tuple[str, str]] = set()
    for entries in licenses.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                continue
            versions = entry.get("versions", [])
            if isinstance(versions, list):
                covered.update(
                    (entry["name"], version) for version in versions if isinstance(version, str)
                )
    missing = sorted(required - covered)
    derived: list[dict[str, str]] = []
    if fetch_missing:
        for name, version in missing:
            derived.append(
                _fetch_pnpm_tarball_license(name, version, required_records[(name, version)])
            )
            covered.add((name, version))
        missing = sorted(required - covered)
    if missing:
        rendered = [f"{name}@{version}" for name, version in missing[:20]]
        suffix = " ..." if len(missing) > 20 else ""
        raise LockError(
            "pnpm license inventory omitted supported-platform lock packages: "
            + ", ".join(rendered)
            + suffix
        )
    return {
        "supported_lock_packages": len(required),
        "covered_lock_packages": len(required & covered),
        "host_inventory_packages": len(required & (covered - {(item['name'], item['version']) for item in derived})),
        "tarball_derived_packages": derived,
    }


def _tool_integrity_binding(record: dict[str, Any], dependency: dict[str, Any]) -> str | None:
    activation = record.get("activation")
    if isinstance(activation, dict) and activation.get("status") == "blocked":
        return None
    requested = dependency["integrity"]
    candidates: list[tuple[str, str, str, str]] = []
    integrity = record.get("integrity")
    if isinstance(integrity, dict):
        if integrity.get("kind") == "go-sum":
            candidates.append(("go-sum", integrity["sum"], integrity["url"], "go-module-sum"))
        for algorithm in ("sha256", "sha512"):
            if algorithm in integrity:
                candidates.append(
                    (algorithm, integrity[algorithm], integrity["url"], "deferred-provenance")
                )
    artifacts = record.get("artifacts")
    if isinstance(artifacts, dict):
        for platform_name, artifact in artifacts.items():
            if not isinstance(artifact, dict):
                continue
            for algorithm in ("sha256", "sha512"):
                if algorithm in artifact:
                    candidates.append(
                        (
                            algorithm,
                            artifact[algorithm],
                            artifact["url"],
                            f"bootstrap-artifact:{platform_name}",
                        )
                    )
    for algorithm, value, source_url, binding in candidates:
        if (
            requested.get("algorithm") == algorithm
            and requested.get("value") == value
            and requested.get("source_url") == source_url
        ):
            return binding
    return None


def _requested_dependency_review(
    request: dict[str, Any],
    manifest: dict[str, Any],
    go_modules: list[Any],
    pnpm_inventory: Any,
    pnpm_licenses: dict[str, Any],
) -> list[dict[str, Any]]:
    manifest_records = {
        record["name"]: record for record in manifest["runtimes"] + manifest["tools"]
    }
    go_records = {
        (item.get("Path"), item.get("Version")): item
        for item in go_modules
        if isinstance(item, dict) and isinstance(item.get("Path"), str)
    }
    pnpm_versions = _pnpm_package_versions(pnpm_inventory)
    declared_pnpm: dict[tuple[str, str], set[bool]] = {}
    for relative in ("package.json", "web/package.json"):
        package = _load_json_yaml(ROOT / relative)
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            values = package.get(field, {}) if isinstance(package, dict) else {}
            if isinstance(values, dict):
                for name, version in values.items():
                    if isinstance(name, str) and isinstance(version, str):
                        declared_pnpm.setdefault((name, version), set()).add(
                            field in {"dependencies", "optionalDependencies"}
                        )
    review: list[dict[str, Any]] = []
    for dependency in request["dependencies"]:
        ecosystem = dependency["ecosystem"]
        name = dependency["name"]
        version = dependency["version"]
        license_name = dependency["license"]
        if license_name not in REQUEST_LICENSE_ALLOWLIST:
            raise LockError(f"requested dependency {ecosystem}:{name} has an unapproved license")
        if ecosystem == "tool":
            record = manifest_records.get(name)
            if record is None or record.get("version") != version or record.get("license") != license_name:
                raise LockError(
                    f"requested tool {name} does not match the candidate manifest version/license"
                )
            if dependency["source_url"] != record.get("source"):
                raise LockError(f"requested tool {name} source does not match the candidate manifest")
            activation = record.get("activation")
            if isinstance(activation, dict) and activation.get("status") == "blocked":
                raise LockError(
                    f"requested tool {name} activation is blocked: {activation.get('reason')}"
                )
            integrity_binding = _tool_integrity_binding(record, dependency)
            if integrity_binding is None:
                raise LockError(
                    f"requested tool {name} integrity does not match a candidate manifest artifact"
                )
            if dependency["direct_runtime_dependency"] is not False:
                raise LockError(f"requested tool {name} cannot be a direct product runtime dependency")
            license_basis = "steward-reviewed-manifest"
        elif ecosystem == "go":
            allowed_versions = {version, version if version.startswith("v") else f"v{version}"}
            matches = [
                (observed, record)
                for (path, observed), record in go_records.items()
                if path == name and observed in allowed_versions
            ]
            if len(matches) != 1:
                raise LockError(f"requested Go module {name}@{version} is absent from candidate go.mod")
            observed_version, go_record = matches[0]
            observed_direct = not bool(go_record.get("Indirect", False))
            if dependency["direct_runtime_dependency"] is not observed_direct:
                raise LockError(f"requested Go module {name}@{version} directness does not match go.mod")
            sums = _go_sum_values(name, observed_version)
            requested_integrity = dependency["integrity"]
            matching_sum = (
                "module"
                if requested_integrity.get("algorithm") == "go-sum"
                and requested_integrity.get("value") == sums.get("module")
                else None
            )
            expected_integrity_source = (
                f"https://sum.golang.org/lookup/{_go_proxy_escape(name)}@{observed_version}"
            )
            expected_source = (
                f"https://proxy.golang.org/{_go_proxy_escape(name)}/@v/{observed_version}.info"
            )
            if matching_sum is None or requested_integrity.get("source_url") != expected_integrity_source:
                raise LockError(f"requested Go module {name}@{version} integrity does not match go.sum")
            if dependency["source_url"] != expected_source:
                raise LockError(f"requested Go module {name}@{version} source is not the exact Go proxy record")
            integrity_binding = "go.sum:module"
            license_basis = "steward-reviewed-request"
        elif ecosystem == "pnpm":
            directness = declared_pnpm.get((name, version), set())
            if not directness or (name, version) not in pnpm_versions:
                raise LockError(
                    f"requested pnpm package {name}@{version} is not installed from a candidate manifest"
                )
            if directness != {dependency["direct_runtime_dependency"]}:
                raise LockError(
                    f"requested pnpm package {name}@{version} directness conflicts with package manifests"
                )
            lock_integrity = _pnpm_lock_integrity(name, version)
            requested_integrity = dependency["integrity"]
            expected_source = (
                OFFICIAL_NPM_REGISTRY + urllib.parse.quote(name, safe="@/") + f"/{version}"
            )
            if (
                lock_integrity is None
                or requested_integrity.get("algorithm") != "npm-sri"
                or requested_integrity.get("value") != lock_integrity
                or requested_integrity.get("source_url") != expected_source
                or dependency["source_url"] != expected_source
            ):
                raise LockError(
                    f"requested pnpm package {name}@{version} provenance does not match pnpm-lock.yaml"
                )
            license_matches = [
                entry
                for observed_license, entries in pnpm_licenses.items()
                if observed_license == license_name and isinstance(entries, list)
                for entry in entries
                if isinstance(entry, dict)
                and entry.get("name") == name
                and version in entry.get("versions", [])
            ]
            if not license_matches:
                raise LockError(
                    f"requested pnpm package {name}@{version} license differs from installed inventory"
                )
            integrity_binding = "pnpm-lock.yaml:resolution.integrity"
            license_basis = "pnpm-installed-inventory"
        review.append(
            {
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
                "license": license_name,
                "integrity": dependency["integrity"],
                "source_url": dependency["source_url"],
                "direct_runtime_dependency": dependency["direct_runtime_dependency"],
                "integrity_binding": integrity_binding,
                "license_basis": license_basis,
            }
        )
    return sorted(review, key=lambda item: (item["ecosystem"], item["name"]))


def _trivy_database_evidence(cache_root: Path) -> dict[str, Any]:
    metadata_path = cache_root / "db" / "metadata.json"
    database_path = cache_root / "db" / "trivy.db"
    if metadata_path.is_symlink() or database_path.is_symlink():
        raise LockError("Trivy database evidence must not follow symlinks")
    metadata = _load_json_yaml(metadata_path)
    if not isinstance(metadata, dict) or set(metadata) != {
        "Version",
        "NextUpdate",
        "UpdatedAt",
        "DownloadedAt",
    }:
        raise LockError("Trivy database metadata has an unexpected shape")
    if metadata.get("Version") != 2 or not database_path.is_file():
        raise LockError("Trivy database schema/file is invalid")
    for field in ("NextUpdate", "UpdatedAt", "DownloadedAt"):
        value = metadata.get(field)
        if not isinstance(value, str):
            raise LockError(f"Trivy database metadata {field} is invalid")
        try:
            dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise LockError(f"Trivy database metadata {field} is invalid") from exc
    return {
        "repository": TRIVY_DB_REPOSITORY,
        "metadata": metadata,
        "metadata_sha256": _digest_file(metadata_path),
        "database_sha256": _digest_file(database_path),
    }


def _run_dependency_validations(candidate_commit: str, request: dict[str, Any]) -> dict[str, Any]:
    _preflight_dependency_mutable_paths()
    validation_env = _validation_env()
    tool_output_buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(tool_output_buffer):
            repository_toolchain._bootstrap_unlocked(
                offline=False,
                repair=True,
                command_env=validation_env,
            )
            repository_toolchain._check_unlocked()
    except repository_toolchain.ToolchainError as exc:
        raise LockError(f"verified toolchain repair/check failed: {exc}") from exc
    tool_output = tool_output_buffer.getvalue()
    check_root_locks()
    provenance_output_buffer = io.StringIO()
    with contextlib.redirect_stdout(provenance_output_buffer):
        _verify_deferred_provenance_unlocked(command_env=validation_env)
    provenance_output = provenance_output_buffer.getvalue()
    pnpm = str(TOOLS_ROOT / "bin" / "pnpm")
    trivy = str(TOOLS_ROOT / "bin" / "trivy")
    store_arg = f"--config.store-dir={TOOLS_ROOT / 'pnpm-store'}"
    registry_arg = f"--config.registry={OFFICIAL_NPM_REGISTRY}"
    install_output, _ = _capture(
        [
            pnpm,
            store_arg,
            registry_arg,
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--force",
        ],
        "candidate frozen pnpm install",
        timeout=1200,
        env=validation_env,
    )
    licenses, license_hash = _capture_json(
        [pnpm, store_arg, registry_arg, "licenses", "list", "--json"],
        "pnpm license inventory",
        env=validation_env,
    )
    if not isinstance(licenses, dict):
        raise LockError("pnpm license inventory must be a JSON object")
    unknown_licenses = sorted(set(licenses) - PACKAGE_LICENSE_ALLOWLIST)
    if unknown_licenses:
        raise LockError(f"dependency license review found unapproved licenses: {unknown_licenses}")
    pnpm_license_coverage = _pnpm_license_coverage(licenses, fetch_missing=True)
    license_counts = {
        license_name: len(entries) if isinstance(entries, list) else 0
        for license_name, entries in sorted(licenses.items())
    }

    audit, audit_hash = _capture_json(
        [pnpm, store_arg, registry_arg, "audit", "--audit-level", "high", "--json"],
        "pnpm vulnerability audit",
        env=validation_env,
    )
    audit_metadata = audit.get("metadata", {}) if isinstance(audit, dict) else {}
    vulnerability_counts = audit_metadata.get("vulnerabilities", {})
    if not isinstance(vulnerability_counts, dict):
        vulnerability_counts = {}
    if int(vulnerability_counts.get("high", 0)) or int(vulnerability_counts.get("critical", 0)):
        raise LockError(f"pnpm audit found high/critical vulnerabilities: {vulnerability_counts}")

    trivy_ignore_path = TOOLS_ROOT / "validation-home" / "empty.trivyignore"
    if trivy_ignore_path.is_symlink():
        raise LockError("closed Trivy ignore file must not be a symlink")
    ignore_flags = os.O_WRONLY | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        ignore_flags |= os.O_NOFOLLOW
    ignore_descriptor = os.open(trivy_ignore_path, ignore_flags, 0o600)
    try:
        ignore_metadata = os.fstat(ignore_descriptor)
        if not stat.S_ISREG(ignore_metadata.st_mode) or ignore_metadata.st_nlink != 1:
            raise LockError("closed Trivy ignore file must be a private regular file")
        os.ftruncate(ignore_descriptor, 0)
        os.fsync(ignore_descriptor)
    finally:
        os.close(ignore_descriptor)
    trivy_report, trivy_hash = _capture_json(
        [
            trivy,
            "--config",
            os.devnull,
            "--cache-dir",
            str(TOOLS_ROOT / "trivy-cache"),
            "fs",
            "--db-repository",
            TRIVY_DB_REPOSITORY,
            "--ignorefile",
            str(trivy_ignore_path),
            "--offline-scan",
            "--quiet",
            "--scanners",
            "vuln",
            "--severity",
            "HIGH,CRITICAL",
            "--exit-code",
            "1",
            "--format",
            "json",
            "--skip-dirs",
            "build/tools",
            "--skip-dirs",
            "node_modules",
            ".",
        ],
        "Trivy lockfile vulnerability scan",
        timeout=1200,
        env=validation_env,
    )
    trivy_findings = 0
    if isinstance(trivy_report, dict):
        for result in trivy_report.get("Results", []) or []:
            if isinstance(result, dict):
                trivy_findings += len(result.get("Vulnerabilities", []) or [])
    if trivy_findings:
        raise LockError(f"Trivy found {trivy_findings} high/critical vulnerabilities")
    trivy_database = _trivy_database_evidence(TOOLS_ROOT / "trivy-cache")

    go_output, _ = _capture(
        [str(TOOLS_ROOT / "bin" / "go"), "list", "-m", "-json", "all"],
        "Go module inventory",
        env=validation_env,
    )
    go_modules = _json_stream(go_output, "Go module inventory")
    pnpm_inventory, pnpm_inventory_hash = _capture_json(
        [pnpm, store_arg, registry_arg, "list", "--recursive", "--depth", "Infinity", "--json"],
        "pnpm installed inventory",
        env=validation_env,
    )
    manifest = _load_json_yaml(MANIFEST_PATH)
    requested_dependencies = _requested_dependency_review(
        request, manifest, go_modules, pnpm_inventory, licenses
    )

    clean_clone, clean_clone_hash = _capture_json(
        [str(ROOT / "scripts" / "dev" / "clean-clone"), "--machine"],
        "clean-clone acceptance",
        timeout=1800,
        env=validation_env,
    )
    if not isinstance(clean_clone, dict) or clean_clone.get("result") != "pass":
        raise LockError("clean-clone acceptance did not produce a passing report")
    if clean_clone.get("source_commit") != candidate_commit:
        raise LockError("clean-clone report does not bind the candidate commit")
    return {
        "toolchain": {
            "command": ["internal:toolchain._bootstrap_unlocked(repair=True)"],
            "stdout_sha256": _digest_bytes(tool_output.encode("utf-8")),
        },
        "deferred_provenance": {
            "command": ["internal:_verify_deferred_provenance_unlocked"],
            "stdout_sha256": _digest_bytes(provenance_output.encode("utf-8")),
        },
        "license": {
            "candidate_install_stdout_sha256": _digest_bytes(install_output.encode("utf-8")),
            "command": ["pnpm", "licenses", "list", "--json"],
            "stdout_sha256": license_hash,
            "license_counts": license_counts,
            "pnpm_supported_platform_coverage": pnpm_license_coverage,
            "go_module_inventory_sha256": _digest_bytes(go_output.encode("utf-8")),
            "pnpm_inventory_sha256": pnpm_inventory_hash,
            "requested_dependencies": requested_dependencies,
            "tool_manifest_licenses": {
                record["name"]: record["license"]
                for record in manifest["runtimes"] + manifest["tools"]
            },
        },
        "vulnerability": {
            "pnpm_audit_stdout_sha256": audit_hash,
            "pnpm_counts": vulnerability_counts,
            "trivy_stdout_sha256": trivy_hash,
            "trivy_high_critical_findings": trivy_findings,
            "trivy_database": trivy_database,
        },
        "clean_clone": {
            "report_sha256": clean_clone_hash,
            "source_commit": clean_clone["source_commit"],
            "command": clean_clone["command"],
            "stdout_sha256": clean_clone["stdout_sha256"],
            "environment": clean_clone["environment"],
        },
    }


def _applied_request(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("status") != "accepted":
        raise LockError("only an accepted request can transition to applied")
    applied = json.loads(json.dumps(request))
    applied["status"] = "applied"
    return applied


def _safe_apply_paths(paths: tuple[Path, ...]) -> None:
    try:
        assert_safe_mutable_paths(paths)
    except ToolLockError as exc:
        raise LockError(f"serialized apply mutable-path containment failed: {exc}") from exc


def _private_regular_file(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LockError(f"{label} is missing or unreadable: {path}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise LockError(f"{label} must be a private non-symlink regular file: {path}")
    return metadata


def _ensure_safe_repository_directory(path: Path) -> None:
    _safe_apply_paths((path,))
    root = Path(os.path.abspath(ROOT))
    target = Path(os.path.abspath(path))
    try:
        relative = target.relative_to(root)
    except ValueError as exc:  # Defensive duplicate of the shared containment check.
        raise LockError(f"directory escapes repository: {target}") from exc
    current = root
    root_metadata = current.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise LockError(f"repository root is not a directory: {root}")
    for part in relative.parts:
        current = current / part
        try:
            os.mkdir(current, 0o755)
        except FileExistsError:
            pass
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise LockError(f"receipt parent is not a non-symlink directory: {current}")


def _preflight_apply_journal_paths(request_path: Path, receipt_path: Path | None = None) -> None:
    paths = [request_path.parent, request_path]
    if receipt_path is not None:
        paths.extend((receipt_path.parent, receipt_path))
    _safe_apply_paths(tuple(paths))
    _private_regular_file(request_path, "dependency request")


def _write_exclusive(path: Path, value: dict[str, Any]) -> None:
    _ensure_safe_repository_directory(path.parent)
    _safe_apply_paths((path,))
    parent_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        parent_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    parent_descriptor = os.open(path.parent, parent_flags)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path.name, flags, 0o644, dir_fd=parent_descriptor)
        with os.fdopen(descriptor, "wb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise LockError("canonical receipt must be a private regular file")
            handle.write(_canonical_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _fsync_directory(path: Path) -> None:
    _safe_apply_paths((path,))
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise LockError(f"fsync target is not a directory: {path}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_replace(path: Path, value: dict[str, Any]) -> None:
    _preflight_apply_journal_paths(path)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    _safe_apply_paths((temporary,))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        parent_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    parent_descriptor = os.open(path.parent, parent_flags)
    created = False
    try:
        descriptor = os.open(temporary.name, flags, 0o644, dir_fd=parent_descriptor)
        created = True
        with os.fdopen(descriptor, "wb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise LockError("applied-request temporary must be a private regular file")
            handle.write(_canonical_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary.name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)
    finally:
        if created:
            try:
                os.unlink(temporary.name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def _ensure_receipt_absent(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise LockError(
            "canonical dependency receipt already exists; automatic recovery and replay are forbidden"
        )


def _final_apply_cas(
    *,
    request_path: Path,
    accepted_sha256: str,
    candidate_commit: str,
    changed_locks: list[str],
    receipt_path: Path,
    expected_status_paths: set[str],
    expected_receipt_sha256: str | None,
) -> None:
    _preflight_apply_journal_paths(request_path, receipt_path)
    if _git("branch", "--show-current").stdout.strip() != "main":
        raise LockError("serialized apply lost the main branch before its journal write")
    if _git("rev-parse", "HEAD").stdout.strip() != candidate_commit:
        raise LockError("serialized apply candidate HEAD changed during validation")
    observed_status = _status_paths()
    if observed_status != expected_status_paths:
        raise LockError(
            "serialized apply worktree changed during validation: "
            f"expected {sorted(expected_status_paths)}, observed {sorted(observed_status)}"
        )
    if request_path.is_symlink() or not request_path.is_file():
        raise LockError("serialized apply request path changed type during validation")
    if _digest_file(request_path) != accepted_sha256:
        raise LockError("serialized apply request bytes changed during validation")
    request_relative = request_path.relative_to(ROOT).as_posix()
    committed_request = _commit_bytes(candidate_commit, request_relative)
    if committed_request is None or _digest_bytes(committed_request) != accepted_sha256:
        raise LockError("serialized apply candidate request binding changed during validation")
    for relative in changed_locks:
        path = ROOT / relative
        committed = _commit_bytes(candidate_commit, relative)
        if (
            path.is_symlink()
            or not path.is_file()
            or committed is None
            or _digest_file(path) != _digest_bytes(committed)
        ):
            raise LockError(f"serialized apply root lock changed during validation: {relative}")
    if expected_receipt_sha256 is None:
        _ensure_receipt_absent(receipt_path)
    elif (
        receipt_path.is_symlink()
        or not receipt_path.is_file()
        or _digest_file(receipt_path) != expected_receipt_sha256
    ):
        raise LockError("serialized apply receipt journal changed before status transition")


@contextlib.contextmanager
def _apply_lock() -> Iterator[None]:
    for path in (ROOT, ROOT / "build", TOOLS_ROOT):
        if path.is_symlink():
            raise LockError(f"dependency apply lock refuses symlinked path: {path}")
    (ROOT / "build").mkdir(mode=0o755, exist_ok=True)
    TOOLS_ROOT.mkdir(mode=0o755, exist_ok=True)
    if not (ROOT / "build").is_dir() or not TOOLS_ROOT.is_dir():
        raise LockError("dependency apply lock parent is not a directory")
    path = TOOLS_ROOT / "dependency-apply.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "a+b") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise LockError("dependency apply lock is not a private regular file")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def apply_request(args: argparse.Namespace) -> None:
    request_path = Path(os.path.abspath(args.request))
    _preflight_apply_journal_paths(request_path)
    request = validate_request(request_path)
    accepted_sha256 = _digest_file(request_path)
    if args.expected_request_sha256 != accepted_sha256:
        raise LockError("--expected-request-sha256 does not match the request bytes")
    if args.confirm != request["request_id"]:
        raise LockError("--confirm must equal the exact request_id")

    with tool_operation_lock(exclusive=True), _apply_lock():
        branch = _git("branch", "--show-current").stdout.strip()
        if branch != "main":
            raise LockError(f"serialized root-lock apply requires main; observed {branch!r}")
        candidate_commit = _git("rev-parse", "HEAD").stdout.strip()
        if request.get("status") != "accepted":
            raise LockError("only an actually accepted request may enter serialized apply")
        if re.fullmatch(r"[0-9a-f]{40}", args.base_commit) is None:
            raise LockError("--base-commit must be a full lowercase 40-hex commit ID")
        resolved_base = _git("rev-parse", "--verify", f"{args.base_commit}^{{commit}}").stdout.strip()
        if resolved_base != args.base_commit:
            raise LockError("--base-commit did not resolve to the exact supplied commit")
        changed_worktree = _status_paths()
        if changed_worktree:
            raise LockError(
                f"serialized apply requires a clean committed candidate; changed paths: {sorted(changed_worktree)}"
            )
        request_relative = request_path.relative_to(ROOT).as_posix()
        head_request = _commit_bytes(candidate_commit, request_relative)
        if head_request is None or _digest_bytes(head_request) != accepted_sha256:
            raise LockError("candidate commit does not contain the exact accepted request bytes")
        changes = _candidate_changes(args.base_commit, candidate_commit)
        unexpected = sorted(set(changes) - LOCK_PATHS - {request_relative})
        if unexpected:
            raise LockError(f"candidate commit contains unrelated paths: {unexpected}")
        if any(status == "D" for status in changes.values()):
            raise LockError("serialized apply forbids deleting a request or root lock")
        changed_locks = sorted(set(changes) & LOCK_PATHS)
        declared = set(request["affected_lockfiles"])
        if not changed_locks:
            raise LockError("candidate commit contains no root lock change")
        if not set(changed_locks).issubset(declared):
            raise LockError(
                f"changed root locks were not declared by request: {sorted(set(changed_locks) - declared)}"
            )
        if changes.get(request_relative) not in {"A", "M"}:
            raise LockError("candidate commit must add or modify exactly its accepted request")

        receipt_path = _canonical_receipt_path(request)
        _preflight_apply_journal_paths(request_path, receipt_path)
        _ensure_receipt_absent(receipt_path)
        validations = _run_dependency_validations(candidate_commit, request)
        applied = _applied_request(request)
        applied_sha256 = _digest_bytes(_canonical_bytes(applied))
        lock_digests: list[dict[str, Any]] = []
        for relative in changed_locks:
            before = _commit_bytes(args.base_commit, relative)
            after = _commit_bytes(candidate_commit, relative)
            if after is None:
                raise LockError(f"candidate commit is missing root lock {relative}")
            lock_digests.append(
                {
                    "path": relative,
                    "before_sha256": _digest_bytes(before) if before is not None else None,
                    "after_sha256": _digest_bytes(after),
                }
            )
        receipt = {
            "schema_version": 1,
            "receipt_kind": "jumpship-serialized-dependency-lock-update",
            "status": "complete",
            "request_id": request["request_id"],
            "packet_id": request["packet_id"],
            "request_path": request_relative,
            "accepted_request_sha256": accepted_sha256,
            "applied_request_sha256": applied_sha256,
            "base_commit": args.base_commit,
            "candidate_commit": candidate_commit,
            "completed_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "root_lock_changes": lock_digests,
            "tool_manifest_sha256": _digest_file(MANIFEST_PATH),
            "validations": validations,
            "approval": request["approval"],
        }
        receipt_relative = receipt_path.relative_to(ROOT).as_posix()
        receipt_sha256 = _digest_bytes(_canonical_bytes(receipt))
        _final_apply_cas(
            request_path=request_path,
            accepted_sha256=accepted_sha256,
            candidate_commit=candidate_commit,
            changed_locks=changed_locks,
            receipt_path=receipt_path,
            expected_status_paths=set(),
            expected_receipt_sha256=None,
        )
        _write_exclusive(receipt_path, receipt)
        _final_apply_cas(
            request_path=request_path,
            accepted_sha256=accepted_sha256,
            candidate_commit=candidate_commit,
            changed_locks=changed_locks,
            receipt_path=receipt_path,
            expected_status_paths={receipt_relative},
            expected_receipt_sha256=receipt_sha256,
        )
        _atomic_replace(request_path, applied)
        print(
            f"dependency-apply: sealed {request['request_id']} receipt at "
            f"{receipt_path.relative_to(ROOT)} and transitioned request to applied"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check")
    subparsers.add_parser("verify-provenance")
    validate_parser = subparsers.add_parser("validate-request")
    validate_parser.add_argument("request", type=Path)
    apply_parser = subparsers.add_parser("apply-request")
    apply_parser.add_argument("--request", type=Path, required=True)
    apply_parser.add_argument("--base-commit", required=True)
    apply_parser.add_argument("--expected-request-sha256", required=True)
    apply_parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        if args.command == "check":
            check_root_locks()
        elif args.command == "verify-provenance":
            verify_deferred_provenance()
        elif args.command == "validate-request":
            validate_request(args.request)
        elif args.command == "apply-request":
            apply_request(args)
        else:  # pragma: no cover
            raise LockError(f"unsupported command: {args.command}")
    except (LockError, OSError, subprocess.SubprocessError, ToolLockError) as exc:
        print(f"dependency-locks: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
