#!/usr/bin/env python3
"""Fail-closed validation for deployment profiles used by CI workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, Sequence


CLOSED_PROFILES = (
    "local",
    "ephemeral-nonprod",
    "persistent-nonprod",
    "paid-production",
)

MODE_PROFILES = {
    "local": frozenset({"local"}),
    "cloud": frozenset({"ephemeral-nonprod", "persistent-nonprod"}),
    "release": frozenset({"paid-production"}),
}

STATIC_CREDENTIAL_ENV = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
)

RELEASE_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
PROFILE_HASH_RE = re.compile(r"\A[0-9a-f]{64}\Z")
P02_CONTRACT_MANIFEST = Path("contracts/contract-manifest.json")
P02_CONTRACT_MANIFEST_SHA256 = (
    "b3fb6c6950659a336c85e4085dbc52c3f42b4a66aa9db26a08e04fa97318b85e"
)
PROFILE_REGISTRY = Path("contracts/release/deployment-profiles.yaml")
PROFILE_REGISTRY_SHA256 = (
    "22fe40ca1b510144e95e25fe716262a5f2069ceecc7f8f93fcc022e3546f0f90"
)


class ProfileGuardError(ValueError):
    """A selector or credential boundary is unsafe."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _read_regular_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProfileGuardError(f"required P02 artifact is unavailable: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ProfileGuardError(f"required P02 artifact is not a regular file: {path}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_json_bytes(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileGuardError(f"{label} is not canonical JSON-compatible data") from exc


def _canonical_profile_hash(profile: Mapping[str, Any]) -> str:
    payload = dict(profile)
    payload.pop("profile_hash", None)
    encoded = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_registry_semantics(document: Any) -> dict[str, Mapping[str, Any]]:
    """Validate ADR-027's closed IDs, default, and content-bound profile hashes."""

    if not isinstance(document, dict) or set(document) != {
        "default_profile_id",
        "profiles",
        "registry_version",
        "schema_version",
    }:
        raise ProfileGuardError("deployment profile registry has an unexpected shape")
    if document.get("schema_version") != "1.0.0" or document.get(
        "registry_version"
    ) != "1.0.0":
        raise ProfileGuardError("deployment profile registry version is invalid")
    if document.get("default_profile_id") != "ephemeral-nonprod":
        raise ProfileGuardError("deployment profile default must be ephemeral-nonprod")
    profiles = document.get("profiles")
    if not isinstance(profiles, list) or len(profiles) != len(CLOSED_PROFILES):
        raise ProfileGuardError("deployment profile registry must contain exactly four profiles")

    by_id: dict[str, Mapping[str, Any]] = {}
    defaults: list[str] = []
    for profile in profiles:
        if not isinstance(profile, dict):
            raise ProfileGuardError("deployment profile registry contains a non-object profile")
        profile_id = profile.get("profile_id")
        if not isinstance(profile_id, str) or profile_id in by_id:
            raise ProfileGuardError("deployment profile IDs must be unique strings")
        if (
            profile.get("schema_version") != "1.0.0"
            or profile.get("profile_version") != "1.0.0"
        ):
            raise ProfileGuardError(f"deployment profile {profile_id!r} version is invalid")
        profile_hash = profile.get("profile_hash")
        if not isinstance(profile_hash, str) or PROFILE_HASH_RE.fullmatch(profile_hash) is None:
            raise ProfileGuardError(f"deployment profile {profile_id!r} has an invalid hash")
        if _canonical_profile_hash(profile) != profile_hash:
            raise ProfileGuardError(f"deployment profile {profile_id!r} content hash does not match")
        if profile.get("implementation_default") is True:
            defaults.append(profile_id)
        elif profile.get("implementation_default") is not False:
            raise ProfileGuardError(
                f"deployment profile {profile_id!r} has an invalid default marker"
            )
        by_id[profile_id] = profile

    if tuple(by_id) != CLOSED_PROFILES or set(by_id) != set(CLOSED_PROFILES):
        raise ProfileGuardError("deployment profile registry IDs/order do not match ADR-027")
    if defaults != ["ephemeral-nonprod"]:
        raise ProfileGuardError(
            "ephemeral-nonprod must be the registry's sole implementation default"
        )
    return by_id


def load_profile_registry(root: Path | None = None) -> dict[str, Mapping[str, Any]]:
    """Load the registry only after verifying its exact accepted P02 manifest binding."""

    source_root = repository_root() if root is None else root.resolve()
    manifest_raw = _read_regular_bytes(source_root / P02_CONTRACT_MANIFEST)
    if hashlib.sha256(manifest_raw).hexdigest() != P02_CONTRACT_MANIFEST_SHA256:
        raise ProfileGuardError("P02 contract manifest SHA-256 does not match its accepted handoff")
    manifest = _load_json_bytes(manifest_raw, "P02 contract manifest")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("artifacts"), list):
        raise ProfileGuardError("P02 contract manifest has an unexpected shape")
    registry_entries = [
        item
        for item in manifest["artifacts"]
        if isinstance(item, dict) and item.get("path") == PROFILE_REGISTRY.as_posix()
    ]
    if len(registry_entries) != 1:
        raise ProfileGuardError("P02 contract manifest must bind one deployment profile registry")
    entry = registry_entries[0]
    if (
        entry.get("media_type") != "application/yaml"
        or entry.get("sha256") != PROFILE_REGISTRY_SHA256
    ):
        raise ProfileGuardError("P02 deployment profile registry manifest entry is invalid")

    registry_raw = _read_regular_bytes(source_root / PROFILE_REGISTRY)
    if hashlib.sha256(registry_raw).hexdigest() != PROFILE_REGISTRY_SHA256:
        raise ProfileGuardError("deployment profile registry SHA-256 does not match P02")
    return validate_registry_semantics(
        _load_json_bytes(registry_raw, "deployment profile registry")
    )


def validate_profile(
    profile: str,
    mode: str,
    *,
    environment: Mapping[str, str] | None = None,
    release_digest: str | None = None,
    require_main_ref: bool = False,
    root: Path | None = None,
) -> dict[str, str | bool]:
    """Validate one exact profile without aliases or implicit promotion."""

    if mode not in MODE_PROFILES:
        raise ProfileGuardError(f"unsupported guard mode: {mode!r}")
    if profile not in CLOSED_PROFILES:
        allowed = ", ".join(CLOSED_PROFILES)
        raise ProfileGuardError(
            f"unknown deployment profile {profile!r}; expected one of: {allowed}"
        )
    if profile not in MODE_PROFILES[mode]:
        allowed = ", ".join(sorted(MODE_PROFILES[mode]))
        raise ProfileGuardError(
            f"profile {profile!r} is not permitted in {mode!r} mode; "
            f"expected one of: {allowed}"
        )

    profiles = load_profile_registry(root)
    profile_contract = profiles.get(profile)
    if profile_contract is None:
        raise ProfileGuardError(f"profile {profile!r} is absent from the P02 registry")

    current_environment = os.environ if environment is None else environment
    if require_main_ref and current_environment.get("GITHUB_REF") != "refs/heads/main":
        raise ProfileGuardError("protected cloud/release handoff requires refs/heads/main")
    present_credentials = sorted(
        name for name in STATIC_CREDENTIAL_ENV if current_environment.get(name, "")
    )
    if present_credentials:
        raise ProfileGuardError(
            "static AWS credential environment is forbidden before OIDC: "
            + ", ".join(present_credentials)
        )

    if mode == "release":
        if release_digest is None or not RELEASE_DIGEST_RE.fullmatch(release_digest):
            raise ProfileGuardError(
                "release mode requires an immutable sha256:<64 lowercase hex> digest"
            )
    elif release_digest is not None:
        raise ProfileGuardError("release digests are accepted only in release mode")

    result: dict[str, str | bool] = {
        "profile": profile,
        "profile_version": str(profile_contract["profile_version"]),
        "profile_hash": str(profile_contract["profile_hash"]),
        "mode": mode,
        "is_production": profile == "paid-production",
    }
    if release_digest is not None:
        result["release_digest"] = release_digest
    return result


def write_github_output(path: Path, result: Mapping[str, str | bool]) -> None:
    """Append the small, non-secret validated selector result to GitHub output."""

    entries = {
        "profile": str(result["profile"]),
        "profile_version": str(result["profile_version"]),
        "profile_hash": str(result["profile_hash"]),
        "mode": str(result["mode"]),
        "is_production": str(result["is_production"]).lower(),
    }
    if "release_digest" in result:
        entries["release_digest"] = str(result["release_digest"])

    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "a", encoding="utf-8") as output:
            for key, value in entries.items():
                output.write(f"{key}={value}\n")
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a closed Jumpship deployment profile before OIDC."
    )
    parser.add_argument("--profile", required=True, help="Exact closed profile ID")
    parser.add_argument(
        "--mode", required=True, choices=tuple(MODE_PROFILES), help="Workflow boundary"
    )
    parser.add_argument(
        "--release-digest",
        help="Immutable release digest; required only for release mode",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        help="Optional GitHub output file supplied by the workflow runner",
    )
    parser.add_argument(
        "--require-main-ref",
        action="store_true",
        help="Deny unless GITHUB_REF is exactly refs/heads/main",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = validate_profile(
            args.profile,
            args.mode,
            release_digest=args.release_digest,
            require_main_ref=args.require_main_ref,
        )
        if args.github_output is not None:
            write_github_output(args.github_output, result)
    except (OSError, ProfileGuardError) as exc:
        print(f"profile guard: DENY: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
