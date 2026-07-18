#!/usr/bin/env python3
"""Rehearse P01 acceptance in an isolated clone with an isolated HOME."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Iterable


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
P03_FRAGMENT = ROOT / "mk" / "packets" / "P03.mk"
ACCEPTANCE = [
    "make",
    "doctor",
    "bootstrap",
    "docs-check",
    "capability-check",
    "command-check",
    "packet-graph-check",
    "gen-check",
    "fmt",
    "lint",
    "test-unit",
    "architecture-check",
]


class CleanCloneError(RuntimeError):
    """An isolated clone precondition or acceptance failure."""


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


def _docker_candidates() -> list[Path]:
    candidates: list[Path] = []
    command = shutil.which("docker")
    if command:
        candidates.append(Path(command))
    candidates.extend(
        Path(value)
        for value in (
            "/Applications/Docker.app/Contents/Resources/bin/docker",
            "/opt/homebrew/bin/docker",
            "/usr/local/bin/docker",
            "/usr/bin/docker",
        )
    )
    return candidates


def _resolve_docker_cli() -> tuple[Path, str, str]:
    seen: set[Path] = set()
    for candidate in _docker_candidates():
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except OSError:
            continue
        if resolved in seen or not resolved.is_file() or not os.access(resolved, os.X_OK):
            continue
        seen.add(resolved)
        with tempfile.TemporaryDirectory(prefix="jumpship-p01-docker-version-") as temporary:
            temporary_root = Path(temporary)
            isolated_home = temporary_root / "home"
            isolated_config = isolated_home / ".docker"
            isolated_config.mkdir(parents=True, mode=0o700)
            version = subprocess.run(
                [str(resolved), "--version"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
                env={
                    "DOCKER_CONFIG": str(isolated_config),
                    "HOME": str(isolated_home),
                    "LANG": os.environ.get("LANG", "C.UTF-8"),
                    "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "TMPDIR": str(temporary_root),
                },
            )
        value = version.stdout.strip()
        if version.returncode != 0 or not value.startswith("Docker version "):
            continue
        if len(value) > 160 or any(character in value for character in "\r\n"):
            continue
        return resolved, value, _sha256_file(resolved)
    raise CleanCloneError("Docker CLI is required once the P03 packet fragment is present")


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
        with tempfile.TemporaryDirectory(prefix="jumpship-p01-compose-version-") as temporary:
            temporary_root = Path(temporary)
            isolated_home = temporary_root / "home"
            isolated_config = isolated_home / ".docker"
            isolated_config.mkdir(parents=True, mode=0o700)
            version = subprocess.run(
                [str(resolved), "version"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
                env={
                    "DOCKER_CONFIG": str(isolated_config),
                    "HOME": str(isolated_home),
                    "LANG": os.environ.get("LANG", "C.UTF-8"),
                    "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "TMPDIR": str(temporary_root),
                },
            )
        value = version.stdout.strip()
        if version.returncode != 0 or re.search(r"\bv2\.[0-9]", value) is None:
            continue
        if len(value) > 160 or any(character in value for character in "\r\n"):
            continue
        return resolved, value, _sha256_file(resolved)
    raise CleanCloneError(
        "Docker Compose v2 executable is required once the P03 packet fragment is present"
    )


def _isolated_environment(
    home: Path, temporary_root: Path, docker_config: Path | None = None
) -> dict[str, str]:
    environment = {
        "HOME": str(home),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(temporary_root),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_CONFIG_HOME": str(home / ".config"),
    }
    if docker_config is not None:
        environment["DOCKER_CONFIG"] = str(docker_config)
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_DIR", "SSL_CERT_FILE"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise CleanCloneError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _resolve_output(path: Path | None) -> Path | None:
    if path is None:
        return None
    candidate = path if path.is_absolute() else ROOT / path
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(ROOT)
    except ValueError as exc:
        raise CleanCloneError("--output must be inside the source repository") from exc
    current = ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise CleanCloneError(f"--output refuses symlinked path component: {current}")
    return candidate


def _redacted_tail(
    output: str,
    clone: Path,
    home: Path,
    temporary_root: Path,
    sensitive_values: Iterable[str] = (),
) -> list[str]:
    redacted = output
    replacements = [
        (str(home), "<isolated-home>"),
        (str(clone), "<clean-clone>"),
        (str(temporary_root), "<clean-clone>"),
        (str(ROOT), "<source-root>"),
        (str(Path.home()), "<source-home>"),
        (os.environ.get("HOME", ""), "<source-home>"),
    ]
    replacements.extend((value, "<forwarded-network-value>") for value in sensitive_values)
    for prefix, marker in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        if not prefix:
            continue
        redacted = redacted.replace(prefix, marker)

    def redact_url(match: re.Match[str]) -> str:
        value = match.group(0)
        parsed = urllib.parse.urlsplit(value.rstrip(".,);]"))
        if parsed.username or parsed.password or parsed.query:
            return "<redacted-url>"
        return value

    redacted = re.sub(r"https?://[^\s\"'<>]+", redact_url, redacted)
    return redacted.splitlines()[-40:]


def rehearse(output_path: Path | None, *, quiet: bool = False) -> dict[str, Any]:
    output_path = _resolve_output(output_path)
    if _git("status", "--porcelain=v1"):
        raise CleanCloneError("clean-clone rehearsal requires a clean source worktree")
    branch = _git("branch", "--show-current")
    if branch != "main":
        raise CleanCloneError(f"clean-clone rehearsal requires main; observed {branch!r}")
    commit = _git("rev-parse", "HEAD")
    docker_cli = _resolve_docker_cli() if P03_FRAGMENT.is_file() else None
    compose = _resolve_compose_plugin() if P03_FRAGMENT.is_file() else None
    started_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    with tempfile.TemporaryDirectory(prefix="jumpship-p01-clean-clone-") as temporary:
        temporary_root = Path(temporary)
        clone = temporary_root / "jumpship"
        result = subprocess.run(
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
        if result.returncode != 0:
            raise CleanCloneError(f"local clone failed: {result.stdout.strip()}")
        observed = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        if observed != commit:
            raise CleanCloneError(f"clone HEAD mismatch: expected {commit}, observed {observed}")
        home = temporary_root / "home"
        home.mkdir(mode=0o700)
        docker_config: Path | None = None
        docker_evidence: dict[str, str] | None = None
        compose_evidence: dict[str, str] | None = None
        isolated_bin: Path | None = None
        if docker_cli is not None:
            docker_binary, docker_version, docker_sha256 = docker_cli
            isolated_bin = temporary_root / "bin"
            isolated_bin.mkdir(mode=0o700)
            isolated_docker = isolated_bin / "docker"
            shutil.copyfile(docker_binary, isolated_docker)
            isolated_docker.chmod(0o500)
            if _sha256_file(isolated_docker) != docker_sha256:
                raise CleanCloneError("isolated Docker CLI copy failed integrity check")
            docker_evidence = {
                "copied_by_sha256": docker_sha256,
                "version": docker_version,
            }
        if compose is not None:
            compose_plugin, compose_version, compose_sha256 = compose
            docker_config = home / ".docker"
            plugin_directory = docker_config / "cli-plugins"
            plugin_directory.mkdir(parents=True, mode=0o700)
            isolated_plugin = plugin_directory / "docker-compose"
            shutil.copyfile(compose_plugin, isolated_plugin)
            isolated_plugin.chmod(0o500)
            if _sha256_file(isolated_plugin) != compose_sha256:
                raise CleanCloneError("isolated Docker Compose plugin copy failed integrity check")
            compose_evidence = {
                "copied_by_sha256": compose_sha256,
                "version": compose_version,
            }
        env = _isolated_environment(home, temporary_root, docker_config)
        if isolated_bin is not None:
            env["PATH"] = f"{isolated_bin}{os.pathsep}{env['PATH']}"
        forwarded_values = [
            env[name]
            for name in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_DIR", "SSL_CERT_FILE")
            if name in env
        ]
        run = subprocess.run(
            ACCEPTANCE,
            cwd=clone,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=1800,
        )
        output = run.stdout
        redaction_input = output
        if docker_cli is not None:
            redaction_input = redaction_input.replace(str(docker_cli[0]), "<docker-cli>")
        if compose is not None:
            redaction_input = redaction_input.replace(str(compose[0]), "<compose-plugin>")
        ended_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        report = {
            "schema_version": 1,
            "evidence_kind": "p01-clean-clone-rehearsal",
            "source_commit": commit,
            "command": ACCEPTANCE,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_seconds": int((ended_at - started_at).total_seconds()),
            "result": "pass" if run.returncode == 0 else "fail",
            "exit_code": run.returncode,
            "stdout_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
            "output_tail": _redacted_tail(
                redaction_input, clone, home, temporary_root, forwarded_values
            ),
            "environment": {
                "isolated_home": True,
                "isolated_docker_config": docker_config is not None,
                "local_clone_no_hardlinks": True,
                "source_worktree_clean": True,
                "cloud_credentials_forwarded": False,
                "docker_credentials_forwarded": False,
                "docker_context_forwarded": False,
                "docker_cli": docker_evidence,
                "docker_compose_plugin": compose_evidence,
            },
        }
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(_canonical_bytes(report))
                handle.flush()
                os.fsync(handle.fileno())
            if not quiet:
                print(f"clean-clone: report written to {output_path.relative_to(ROOT)}")
        if not quiet:
            print(
                f"clean-clone: {report['result']} at {commit} "
                f"(stdout sha256 {report['stdout_sha256']})"
            )
        if run.returncode != 0:
            for line in report["output_tail"]:
                print(line, file=sys.stderr)
            raise CleanCloneError(f"isolated acceptance exited {run.returncode}")
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--machine", action="store_true", help="emit only the canonical report JSON")
    args = parser.parse_args()
    try:
        report = rehearse(args.output, quiet=args.machine)
        if args.machine:
            sys.stdout.buffer.write(_canonical_bytes(report))
    except (CleanCloneError, OSError, subprocess.SubprocessError) as exc:
        print(f"clean-clone: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
