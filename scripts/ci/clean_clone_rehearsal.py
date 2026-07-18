#!/usr/bin/env python3
"""Run the P03 reproducibility vector from an isolated committed-HEAD clone."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
P03_VECTOR = [
    "make",
    "doctor",
    "bootstrap",
    "gen-check",
    "fmt",
    "lint",
    "test-unit",
    "verify",
]
FORWARDED_NETWORK_ENVIRONMENT = (
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
)


class RehearsalError(RuntimeError):
    """Raised when the shared clean-clone harness cannot be loaded safely."""


def _load_p01_harness() -> ModuleType:
    path = ROOT / "scripts" / "dev" / "clean_clone.py"
    spec = importlib.util.spec_from_file_location("jumpship_clean_clone", path)
    if spec is None or spec.loader is None:
        raise RehearsalError(f"cannot load clean-clone harness from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _compose_candidates() -> list[Path]:
    candidates: list[Path] = []
    standalone = shutil.which("docker-compose")
    if standalone:
        candidates.append(Path(standalone))
    candidates.extend(
        Path(value)
        for value in (
            "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
            "/opt/homebrew/lib/docker/cli-plugins/docker-compose",
            "/usr/local/lib/docker/cli-plugins/docker-compose",
            "/usr/local/libexec/docker/cli-plugins/docker-compose",
            "/usr/lib/docker/cli-plugins/docker-compose",
            "/usr/libexec/docker/cli-plugins/docker-compose",
        )
    )
    configured = os.environ.get("DOCKER_CONFIG", "").strip()
    if configured:
        candidates.append(Path(configured) / "cli-plugins" / "docker-compose")
    candidates.append(Path.home() / ".docker" / "cli-plugins" / "docker-compose")
    return candidates


def _resolve_compose_plugin() -> tuple[Path, str, str]:
    seen: set[Path] = set()
    for candidate in _compose_candidates():
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except OSError:
            continue
        if resolved in seen or not resolved.is_file() or not os.access(resolved, os.X_OK):
            continue
        seen.add(resolved)
        with tempfile.TemporaryDirectory(prefix="jumpship-p03-compose-version-") as temporary:
            probe_root = Path(temporary)
            probe_home = probe_root / "home"
            probe_config = probe_home / ".docker"
            probe_config.mkdir(parents=True, mode=0o700)
            version = subprocess.run(
                [str(resolved), "version"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
                env={
                    "DOCKER_CONFIG": str(probe_config),
                    "HOME": str(probe_home),
                    "LANG": os.environ.get("LANG", "C.UTF-8"),
                    "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "TMPDIR": str(probe_root),
                },
            )
        value = version.stdout.strip()
        if version.returncode != 0 or re.search(r"\bv2\.[0-9]", value) is None:
            continue
        if len(value) > 160 or any(character in value for character in "\r\n"):
            continue
        return resolved, value, _sha256_file(resolved)
    raise RehearsalError(
        "Docker Compose v2 executable is required for isolated Compose validation"
    )


def _git(harness: ModuleType, *arguments: str) -> str:
    value = harness._git(*arguments)  # type: ignore[attr-defined]
    if not isinstance(value, str):
        raise RehearsalError("shared clean-clone Git helper returned an invalid value")
    return value


def _isolated_environment(
    home: Path, temporary_root: Path, docker_config: Path
) -> dict[str, str]:
    environment = {
        "DOCKER_CONFIG": str(docker_config),
        "HOME": str(home),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(temporary_root),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_CONFIG_HOME": str(home / ".config"),
    }
    for name in FORWARDED_NETWORK_ENVIRONMENT:
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _isolated_rehearsal(harness: ModuleType) -> dict[str, Any]:
    if _git(harness, "status", "--porcelain=v1"):
        raise RehearsalError("clean-clone rehearsal requires a clean source worktree")
    branch = _git(harness, "branch", "--show-current")
    if branch != "main":
        raise RehearsalError(f"clean-clone rehearsal requires main; observed {branch!r}")
    commit = _git(harness, "rev-parse", "HEAD")
    compose_plugin, compose_version, compose_sha256 = _resolve_compose_plugin()
    started_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

    with tempfile.TemporaryDirectory(prefix="jumpship-p03-clean-clone-") as temporary:
        temporary_root = Path(temporary)
        clone = temporary_root / "jumpship"
        cloned = subprocess.run(
            [
                "git",
                "clone",
                "--local",
                "--no-hardlinks",
                "--single-branch",
                "--branch",
                "main",
                str(ROOT),
                str(clone),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        if cloned.returncode != 0:
            raise RehearsalError(f"local clone failed: {cloned.stdout.strip()}")
        observed = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        if observed != commit:
            raise RehearsalError(
                f"clone HEAD mismatch: expected {commit}, observed {observed}"
            )

        home = temporary_root / "home"
        home.mkdir(mode=0o700)
        docker_config = home / ".docker"
        plugin_directory = docker_config / "cli-plugins"
        plugin_directory.mkdir(parents=True, mode=0o700)
        isolated_plugin = plugin_directory / "docker-compose"
        shutil.copyfile(compose_plugin, isolated_plugin)
        isolated_plugin.chmod(0o500)
        if _sha256_file(isolated_plugin) != compose_sha256:
            raise RehearsalError("isolated Docker Compose plugin copy failed integrity check")

        environment = _isolated_environment(home, temporary_root, docker_config)
        forwarded_values = [
            environment[name]
            for name in FORWARDED_NETWORK_ENVIRONMENT
            if name in environment
        ]
        run = subprocess.run(
            P03_VECTOR,
            cwd=clone,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=1800,
        )
        output = run.stdout
        ended_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        redaction_input = output.replace(str(compose_plugin), "<compose-plugin>")
        tail = harness._redacted_tail(  # type: ignore[attr-defined]
            redaction_input,
            clone,
            home,
            temporary_root,
            forwarded_values,
        )
        report = {
            "schema_version": 1,
            "evidence_kind": "p03-clean-clone-rehearsal",
            "rubric_rows": ["JSMVP-R013"],
            "source_commit": commit,
            "command": P03_VECTOR,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_seconds": int((ended_at - started_at).total_seconds()),
            "result": "pass" if run.returncode == 0 else "fail",
            "exit_code": run.returncode,
            "stdout_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
            "output_tail": tail,
            "environment": {
                "isolated_home": True,
                "isolated_docker_config": True,
                "local_clone_no_hardlinks": True,
                "source_worktree_clean": True,
                "cloud_credentials_forwarded": False,
                "docker_credentials_forwarded": False,
                "docker_context_forwarded": False,
                "docker_compose_plugin": {
                    "copied_by_sha256": compose_sha256,
                    "version": compose_version,
                },
                "packet_profile": "local-static-validation",
            },
        }
        if run.returncode != 0:
            for line in tail:
                print(line, file=sys.stderr)
            raise RehearsalError(f"isolated acceptance exited {run.returncode}")
        return report


def _resolve_output(value: Path | None) -> Path | None:
    if value is None:
        return None
    output = Path(os.path.abspath(value if value.is_absolute() else ROOT / value))
    try:
        relative = output.relative_to(ROOT)
    except ValueError as exc:
        raise RehearsalError("--output must remain inside the source repository") from exc
    current = ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RehearsalError(f"--output refuses symlinked path component: {current}")
    return output


def _write_exclusive(output: Path, report: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(_canonical_bytes(report))
        handle.flush()
        os.fsync(handle.fileno())


def rehearse(output: Path | None, *, quiet: bool = False) -> dict[str, Any]:
    output = _resolve_output(output)
    harness = _load_p01_harness()
    report = _isolated_rehearsal(harness)
    if output is not None:
        _write_exclusive(output, report)
        if not quiet:
            print(f"p03 clean-clone: report written to {output.relative_to(ROOT)}")
    if not quiet:
        print(
            f"p03 clean-clone: {report['result']} at {report['source_commit']} "
            f"(stdout sha256 {report['stdout_sha256']})"
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--machine", action="store_true")
    arguments = parser.parse_args()
    try:
        report = rehearse(arguments.output, quiet=arguments.machine)
        if arguments.machine:
            sys.stdout.buffer.write(_canonical_bytes(report))
    except (RehearsalError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"p03 clean-clone: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
