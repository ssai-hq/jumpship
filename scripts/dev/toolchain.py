#!/usr/bin/env python3
"""Provision and verify Jumpship's repository-local pinned toolchain."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from tool_lock import ToolLockError, assert_safe_mutable_paths, tool_operation_lock

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "tools" / "manifest.yaml"
TOOLS_ROOT = ROOT / "build" / "tools"
BIN_ROOT = TOOLS_ROOT / "bin"
TOOLCHAINS_ROOT = TOOLS_ROOT / "_toolchains"
CACHE_ROOT = TOOLS_ROOT / "cache"
STATE_PATH = TOOLS_ROOT / "state.json"
BOOTSTRAP_NAMES = ("go", "node", "pnpm", "opentofu", "golangci-lint", "trivy")
EXECUTABLE_PATHS = {
    "go": ("bin/go", "bin/gofmt"),
    "node": ("bin/node",),
    "opentofu": ("tofu",),
    "golangci-lint": ("golangci-lint",),
    "trivy": ("trivy",),
}
EXPECTED_VERSIONS = {
    "go": ("go", ("version",), re.compile(r"\bgo1\.26\.5\b")),
    "node": ("node", ("--version",), re.compile(r"^v24\.18\.0$")),
    "pnpm": ("pnpm", ("--version",), re.compile(r"^11\.4\.0$")),
    "opentofu": ("tofu", ("version",), re.compile(r"^OpenTofu v1\.11\.0\b")),
    "golangci-lint": (
        "golangci-lint",
        ("version",),
        re.compile(r"\bversion 2\.12\.2\b"),
    ),
    "trivy": ("trivy", ("--version",), re.compile(r"\bVersion:\s*0\.72\.0\b")),
}
ALLOWED_DOWNLOAD_HOSTS = {
    "dl.google.com",
    "go.dev",
    "github.com",
    "nodejs.org",
    "registry.npmjs.org",
    "release-assets.githubusercontent.com",
}
SAFE_PATH_ATOM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
VERSION_PROBE_TIMEOUT_SECONDS = 60


class ToolchainError(RuntimeError):
    """A deterministic bootstrap or verification failure."""


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest() -> dict[str, Any]:
    try:
        value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolchainError(f"cannot parse JSON-compatible {MANIFEST_PATH}: {exc}") from exc
    if value.get("schema_version") != 1:
        raise ToolchainError("unsupported tools manifest schema_version")
    return value


def _records(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = manifest.get("runtimes", []) + manifest.get("tools", [])
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ToolchainError(f"tools manifest record {index} is not an object")
        for field in ("name", "version"):
            value = record.get(field)
            if (
                not isinstance(value, str)
                or value in {".", ".."}
                or SAFE_PATH_ATOM_RE.fullmatch(value) is None
            ):
                raise ToolchainError(
                    f"tools manifest record {index} has unsafe {field} path atom: {value!r}"
                )
    by_name = {record.get("name"): record for record in records}
    missing = sorted(set(BOOTSTRAP_NAMES) - set(by_name))
    if missing:
        raise ToolchainError(f"tools manifest is missing bootstrap records: {missing}")
    return by_name


def _platform_key() -> str:
    os_name = platform.system().lower()
    machine = platform.machine().lower()
    os_map = {"darwin": "darwin", "linux": "linux"}
    arch_map = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}
    if os_name not in os_map or machine not in arch_map:
        raise ToolchainError(f"unsupported bootstrap platform: {os_name}-{machine}")
    return f"{os_map[os_name]}-{arch_map[machine]}"


def _artifact(record: dict[str, Any], platform_key: str) -> dict[str, str]:
    artifacts = record.get("artifacts", {})
    artifact = artifacts.get(platform_key) or artifacts.get("all")
    if not isinstance(artifact, dict):
        raise ToolchainError(f"{record.get('name')}: no pinned artifact for {platform_key}")
    return artifact


def _checksum(artifact: dict[str, str]) -> tuple[str, str]:
    values = [(algorithm, artifact.get(algorithm)) for algorithm in ("sha256", "sha512")]
    present = [(algorithm, value) for algorithm, value in values if value]
    if len(present) != 1:
        raise ToolchainError("artifact must declare exactly one sha256 or sha512")
    algorithm, expected = present[0]
    assert isinstance(expected, str)
    expected_length = 64 if algorithm == "sha256" else 128
    if re.fullmatch(rf"[0-9a-f]{{{expected_length}}}", expected) is None:
        raise ToolchainError(f"artifact has malformed {algorithm}")
    return algorithm, expected


def _digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_url(url: str, *, allow_redirect_query: bool = False) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        raise ToolchainError(f"artifact URL is outside the closed HTTPS source allowlist: {url}")
    if parsed.username or parsed.password or parsed.fragment:
        raise ToolchainError("artifact URL must not contain credentials or a fragment")
    if parsed.query and not allow_redirect_query:
        raise ToolchainError("persisted artifact URL must not contain a query")


def _assert_no_symlink_chain(root: Path, target: Path) -> None:
    root = root.absolute()
    target = target.absolute()
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise ToolchainError(f"mutable bootstrap path escapes repository: {target}") from exc
    candidates = [root]
    current = root
    for part in relative.parts:
        current = current / part
        candidates.append(current)
    for candidate in candidates:
        if candidate.is_symlink():
            raise ToolchainError(f"bootstrap refuses symlinked mutable path: {candidate}")


def _preflight_mutable_paths() -> None:
    mutable_paths = (
        ROOT,
        ROOT / "build",
        TOOLS_ROOT,
        BIN_ROOT,
        TOOLCHAINS_ROOT,
        CACHE_ROOT,
        STATE_PATH,
        TOOLS_ROOT / ".operation.lock",
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
    assert_safe_mutable_paths(mutable_paths)
    for path in mutable_paths:
        _assert_no_symlink_chain(ROOT, path)
    for directory in (ROOT / "build", TOOLS_ROOT, BIN_ROOT, TOOLCHAINS_ROOT, CACHE_ROOT):
        if directory.exists() and not directory.is_dir():
            raise ToolchainError(f"bootstrap mutable directory path is not a directory: {directory}")
    if STATE_PATH.exists() and not STATE_PATH.is_file():
        raise ToolchainError(f"bootstrap state path is not a regular file: {STATE_PATH}")


def _host_prerequisite_errors() -> list[str]:
    errors: list[str] = []
    if sys.version_info < (3, 10):
        errors.append(f"Python >=3.10 is required; observed {platform.python_version()}")
    commands = {
        "POSIX sh": ("sh", ("-c", ":")),
        "Git": ("git", ("--version",)),
        "Make": ("make", ("--version",)),
    }
    for label, (command, args) in commands.items():
        executable = shutil.which(command)
        if executable is None:
            errors.append(f"{label} prerequisite is missing ({command})")
            continue
        result = subprocess.run(
            [executable, *args],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        if result.returncode != 0:
            errors.append(f"{label} prerequisite is not executable ({executable})")
    return errors


def _download(artifact: dict[str, str], *, offline: bool) -> Path:
    url = artifact["url"]
    _safe_url(url)
    algorithm, expected = _checksum(artifact)
    basename = Path(urllib.parse.urlparse(url).path).name
    if not basename:
        raise ToolchainError(f"artifact URL has no file name: {url}")
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    destination = CACHE_ROOT / f"{algorithm}-{expected}-{basename}"
    _assert_no_symlink_chain(ROOT, destination)
    if destination.is_file() and _digest(destination, algorithm) == expected:
        return destination
    if destination.exists():
        destination.unlink()
    if offline:
        raise ToolchainError(f"offline cache miss for pinned artifact {basename}")

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "jumpship-repository-bootstrap/1"},
        method="GET",
    )
    temporary = destination.with_suffix(destination.suffix + f".tmp-{os.getpid()}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("xb") as output:
            _safe_url(response.geturl(), allow_redirect_query=True)
            if response.status != 200:
                raise ToolchainError(f"download failed for {basename}: HTTP {response.status}")
            shutil.copyfileobj(response, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        observed = _digest(temporary, algorithm)
        if observed != expected:
            raise ToolchainError(
                f"checksum mismatch for {basename}: expected {expected}, observed {observed}"
            )
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def _safe_archive_name(name: str) -> None:
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts:
        raise ToolchainError(f"archive contains unsafe path: {name!r}")


def _safe_tar(archive: tarfile.TarFile) -> None:
    for member in archive.getmembers():
        _safe_archive_name(member.name)
        if member.ischr() or member.isblk() or member.isfifo():
            raise ToolchainError(f"archive contains forbidden special file: {member.name!r}")
        if member.issym():
            if posixpath.isabs(member.linkname):
                raise ToolchainError(f"archive contains absolute symlink: {member.name!r}")
            target = posixpath.normpath(
                posixpath.join(posixpath.dirname(member.name), member.linkname)
            )
            _safe_archive_name(target)
        if member.islnk():
            _safe_archive_name(posixpath.normpath(member.linkname))


def _extract(archive_path: Path, archive_kind: str, destination: Path) -> None:
    if archive_kind == "tar.gz":
        with tarfile.open(archive_path, "r:gz") as archive:
            _safe_tar(archive)
            try:
                archive.extractall(destination, filter="data")
            except TypeError:  # pragma: no cover - Python <3.12 clean-clone compatibility.
                archive.extractall(destination)
        return
    if archive_kind == "zip":
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                _safe_archive_name(info.filename)
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ToolchainError(f"zip contains forbidden symlink: {info.filename!r}")
            archive.extractall(destination)
        return
    raise ToolchainError(f"unsupported archive type: {archive_kind!r}")


def _marker(record: dict[str, Any], artifact: dict[str, str], platform_key: str) -> dict[str, Any]:
    algorithm, checksum = _checksum(artifact)
    return {
        "manifest_sha256": _sha256(MANIFEST_PATH),
        "name": record["name"],
        "platform": platform_key,
        "source": artifact["url"],
        "version": record["version"],
        algorithm: checksum,
    }


def _install_record(
    record: dict[str, Any], platform_key: str, *, offline: bool, repair: bool
) -> Path:
    name = record["name"]
    version = record["version"]
    for field, value in (("name", name), ("version", version)):
        if value in {".", ".."} or SAFE_PATH_ATOM_RE.fullmatch(value) is None:
            raise ToolchainError(f"{name!r}: unsafe {field} path atom {value!r}")
    artifact = _artifact(record, platform_key)
    destination = TOOLCHAINS_ROOT / name / version
    _assert_no_symlink_chain(ROOT, destination)
    marker_path = destination / ".jumpship-tool.json"
    expected_marker = _marker(record, artifact, platform_key)
    # Bootstrap never trusts mutable extracted bytes or their adjacent marker.
    # The verified archive cache is re-hashed and re-extracted on every run so
    # local tampering is detected and repaired without a global install.
    _ = repair
    if destination.exists():
        shutil.rmtree(destination)

    archive_path = _download(artifact, offline=offline)
    TOOLCHAINS_ROOT.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{name}-{version}-", dir=TOOLS_ROOT))
    try:
        _extract(archive_path, artifact["archive"], stage)
        root_name = artifact.get("root", ".")
        if not isinstance(root_name, str) or not root_name:
            raise ToolchainError(f"{name}: archive root must be a non-empty relative path")
        _safe_archive_name(root_name)
        source = stage if root_name == "." else stage / root_name
        if not source.is_dir():
            raise ToolchainError(f"{name}: archive does not contain expected root {root_name!r}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, destination)
        for relative in EXECUTABLE_PATHS.get(name, ()):
            executable = destination / relative
            if not executable.is_file():
                raise ToolchainError(f"{name}: archive is missing executable {relative!r}")
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        _write_exclusive_file(marker_path, _canonical_bytes(expected_marker), mode=0o644)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return destination


def _open_safe_directory(path: Path) -> int:
    _assert_no_symlink_chain(ROOT, path)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ToolchainError(f"mutable parent is not a directory: {path}")
    return descriptor


def _write_exclusive_file(path: Path, data: bytes, *, mode: int) -> None:
    _assert_no_symlink_chain(ROOT, path)
    parent_descriptor = _open_safe_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path.name, flags, mode, dir_fd=parent_descriptor)
        with os.fdopen(descriptor, "wb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ToolchainError(f"mutable file is not a private regular file: {path}")
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _write_wrapper(name: str, body: str) -> None:
    BIN_ROOT.mkdir(parents=True, exist_ok=True)
    path = BIN_ROOT / name
    _assert_no_symlink_chain(ROOT, path)
    temporary = path.with_suffix(f".tmp-{os.getpid()}")
    _assert_no_symlink_chain(ROOT, temporary)
    parent_descriptor = _open_safe_directory(BIN_ROOT)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    created = False
    try:
        descriptor = os.open(temporary.name, flags, 0o755, dir_fd=parent_descriptor)
        created = True
        with os.fdopen(descriptor, "wb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ToolchainError(f"wrapper temporary is not a private regular file: {temporary}")
            handle.write(("#!/bin/sh\nset -eu\n" + body).encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), 0o755)
        _assert_no_symlink_chain(ROOT, path)
        os.replace(
            temporary.name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        created = False
        os.fsync(parent_descriptor)
    finally:
        if created:
            try:
                os.unlink(temporary.name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def _write_wrappers(records: dict[str, dict[str, Any]]) -> None:
    versions = {name: records[name]["version"] for name in BOOTSTRAP_NAMES}
    prefix = 'REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)\n'
    go_root = f'$REPO_ROOT/build/tools/_toolchains/go/{versions["go"]}'
    node_root = f'$REPO_ROOT/build/tools/_toolchains/node/{versions["node"]}'
    pnpm_root = f'$REPO_ROOT/build/tools/_toolchains/pnpm/{versions["pnpm"]}'
    tofu_root = f'$REPO_ROOT/build/tools/_toolchains/opentofu/{versions["opentofu"]}'
    lint_root = f'$REPO_ROOT/build/tools/_toolchains/golangci-lint/{versions["golangci-lint"]}'
    trivy_root = f'$REPO_ROOT/build/tools/_toolchains/trivy/{versions["trivy"]}'
    _write_wrapper("go", prefix + f'exec "{go_root}/bin/go" "$@"\n')
    _write_wrapper("gofmt", prefix + f'exec "{go_root}/bin/gofmt" "$@"\n')
    _write_wrapper("node", prefix + f'exec "{node_root}/bin/node" "$@"\n')
    _write_wrapper("npm", prefix + f'exec "{node_root}/bin/npm" "$@"\n')
    _write_wrapper("npx", prefix + f'exec "{node_root}/bin/npx" "$@"\n')
    corepack = TOOLCHAINS_ROOT / "node" / versions["node"] / "bin" / "corepack"
    if corepack.exists():
        _write_wrapper("corepack", prefix + f'exec "{node_root}/bin/corepack" "$@"\n')
    _write_wrapper(
        "pnpm",
        prefix + f'exec "{node_root}/bin/node" "{pnpm_root}/bin/pnpm.cjs" "$@"\n',
    )
    _write_wrapper("tofu", prefix + f'exec "{tofu_root}/tofu" "$@"\n')
    _write_wrapper("golangci-lint", prefix + f'exec "{lint_root}/golangci-lint" "$@"\n')
    _write_wrapper("trivy", prefix + f'exec "{trivy_root}/trivy" "$@"\n')


def _tool_env() -> dict[str, str]:
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
            "PNPM_HOME": str(BIN_ROOT),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    env["PATH"] = str(BIN_ROOT) + os.pathsep + env.get("PATH", "")
    return env


def _version_output(command: str, args: tuple[str, ...], *, repo_local: bool) -> str | None:
    executable = BIN_ROOT / command if repo_local else shutil.which(command)
    if executable is None or not Path(executable).exists():
        return None
    result = subprocess.run(
        [str(executable), *args],
        cwd=ROOT,
        env=_tool_env(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        # A freshly extracted, notarized macOS binary can spend several
        # seconds in the first kernel/Gatekeeper launch. Keep the probe bounded
        # without making a clean bootstrap depend on a warmed host cache.
        timeout=VERSION_PROBE_TIMEOUT_SECONDS,
    )
    output = result.stdout.strip()
    if result.returncode != 0:
        return f"<exit {result.returncode}> {output}"
    return output


def verify_repo_toolchain() -> list[str]:
    errors: list[str] = []
    for name in BOOTSTRAP_NAMES:
        command, args, expected = EXPECTED_VERSIONS[name]
        output = _version_output(command, args, repo_local=True)
        if output is None:
            errors.append(f"{name}: repository-local command is missing")
        elif expected.search(output) is None:
            errors.append(f"{name}: expected {expected.pattern!r}, observed {output!r}")
    return errors


def _state(manifest: dict[str, Any], platform_key: str) -> dict[str, Any]:
    records = _records(manifest)
    return {
        "manifest_id": manifest["manifest_id"],
        "manifest_sha256": _sha256(MANIFEST_PATH),
        "platform": platform_key,
        "tools": {name: records[name]["version"] for name in BOOTSTRAP_NAMES},
    }


def _run_bootstrap_command(
    command: list[str], label: str, *, command_env: dict[str, str] | None = None
) -> None:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=_tool_env() if command_env is None else command_env,
        check=False,
    )
    if result.returncode != 0:
        raise ToolchainError(f"{label} failed with exit {result.returncode}")


def _check_unlocked() -> None:
    _preflight_mutable_paths()
    manifest = _load_manifest()
    expected_state = _state(manifest, _platform_key())
    try:
        observed_state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolchainError(f"repository-local bootstrap state is missing or invalid: {exc}") from exc
    if observed_state != expected_state:
        raise ToolchainError("repository-local bootstrap state does not match tools/manifest.yaml")
    errors = verify_repo_toolchain()
    if errors:
        raise ToolchainError("repository-local tool verification failed:\n- " + "\n- ".join(errors))
    print("toolchain-check: exact repository-local versions verified")


def _bootstrap_unlocked(
    *, offline: bool, repair: bool, command_env: dict[str, str] | None = None
) -> None:
    _preflight_mutable_paths()
    manifest = _load_manifest()
    records = _records(manifest)
    platform_key = _platform_key()
    if platform_key not in manifest["policy"]["supported_platforms"]:
        raise ToolchainError(f"platform is not authorized by tools manifest: {platform_key}")
    # Validate every immutable root/dependency contract before removing or
    # replacing any previously verified tool bytes.
    _run_bootstrap_command(
        [str(ROOT / "scripts" / "dependency-locks" / "check")],
        "dependency lock check",
        command_env=command_env,
    )
    STATE_PATH.unlink(missing_ok=True)
    for name in BOOTSTRAP_NAMES:
        record = records[name]
        if record.get("bootstrap") is not True:
            raise ToolchainError(f"{name}: bootstrap record is not enabled")
        print(f"bootstrap: {name} {record['version']} ({platform_key})", flush=True)
        _install_record(record, platform_key, offline=offline, repair=repair)
    _write_wrappers(records)
    errors = verify_repo_toolchain()
    if errors:
        raise ToolchainError("repository-local tool verification failed:\n- " + "\n- ".join(errors))
    print(f"bootstrap: verified repository-local toolchain at {TOOLS_ROOT}")
    pnpm_command = [
        str(BIN_ROOT / "pnpm"),
        "install",
        "--frozen-lockfile",
        "--ignore-scripts",
        "--store-dir",
        str(TOOLS_ROOT / "pnpm-store"),
    ]
    if offline:
        pnpm_command.append("--offline")
    _run_bootstrap_command(
        pnpm_command, "frozen pnpm install", command_env=command_env
    )
    _write_exclusive_file(
        STATE_PATH,
        _canonical_bytes(_state(manifest, platform_key)),
        mode=0o644,
    )
    _check_unlocked()
    print("bootstrap: dependency lock installed without lifecycle scripts")


def bootstrap(*, offline: bool, repair: bool) -> None:
    prerequisite_errors = _host_prerequisite_errors()
    if prerequisite_errors:
        raise ToolchainError("host prerequisite check failed:\n- " + "\n- ".join(prerequisite_errors))
    with tool_operation_lock(exclusive=True):
        _bootstrap_unlocked(offline=offline, repair=repair)


def _doctor_unlocked() -> None:
    manifest = _load_manifest()
    records = _records(manifest)
    platform_key = _platform_key()
    prerequisite_errors = _host_prerequisite_errors()
    if prerequisite_errors:
        raise ToolchainError("host prerequisite check failed:\n- " + "\n- ".join(prerequisite_errors))
    _preflight_mutable_paths()
    print(f"doctor: supported platform {platform_key}")
    print(
        f"doctor: host prerequisites exact enough "
        f"(POSIX sh, Git, Make, Python {platform.python_version()})"
    )
    repo_errors = verify_repo_toolchain()
    if repo_errors:
        print("doctor: repository-local toolchain needs bootstrap")
        for error in repo_errors:
            print(f"  warn: {error}")
    else:
        print("doctor: repository-local toolchain is exact")
    for name in BOOTSTRAP_NAMES:
        command, args, expected = EXPECTED_VERSIONS[name]
        output = _version_output(command, args, repo_local=False)
        desired = records[name]["version"]
        if output is None:
            print(f"doctor: host {name}: absent (repo pin {desired})")
        elif expected.search(output):
            print(f"doctor: host {name}: exact ({desired})")
        else:
            first_line = output.splitlines()[0]
            print(f"doctor: host {name}: {first_line} (repo pin {desired}; isolated)")
    print("doctor: global installation is disabled; bootstrap writes only build/tools/")


def doctor() -> None:
    prerequisite_errors = _host_prerequisite_errors()
    if prerequisite_errors:
        raise ToolchainError("host prerequisite check failed:\n- " + "\n- ".join(prerequisite_errors))
    with tool_operation_lock(exclusive=False):
        _doctor_unlocked()


def check() -> None:
    with tool_operation_lock(exclusive=False):
        _check_unlocked()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    bootstrap_parser = subparsers.add_parser("bootstrap")
    bootstrap_parser.add_argument("--offline", action="store_true")
    bootstrap_parser.add_argument("--repair", action="store_true")
    subparsers.add_parser("doctor")
    subparsers.add_parser("check")
    args = parser.parse_args()
    try:
        if args.command == "bootstrap":
            bootstrap(offline=args.offline, repair=args.repair)
        elif args.command == "doctor":
            doctor()
        elif args.command == "check":
            check()
        else:  # pragma: no cover - argparse closes the command set.
            raise ToolchainError(f"unsupported command: {args.command}")
    except (
        OSError,
        subprocess.SubprocessError,
        ToolchainError,
        ToolLockError,
        urllib.error.URLError,
    ) as exc:
        print(f"toolchain: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
