#!/usr/bin/env python3
"""Scan repository source for secrets with the pinned, offline Trivy binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Sequence


class SecretScanError(RuntimeError):
    """The scanner boundary or its machine report is unsafe or invalid."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def pinned_trivy(root: Path) -> tuple[Path, str]:
    """Resolve the bootstrap-pinned Trivy wrapper and verify its live version."""

    manifest_path = root / "tools" / "manifest.yaml"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        matches = [
            item
            for item in manifest["tools"]
            if isinstance(item, dict) and item.get("name") == "trivy"
        ]
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SecretScanError("the pinned tool manifest is unavailable or malformed") from exc
    if len(matches) != 1:
        raise SecretScanError("the pinned tool manifest must contain exactly one Trivy entry")
    entry = matches[0]
    version = entry.get("version")
    if (
        not isinstance(version, str)
        or entry.get("command") != "trivy"
        or entry.get("bootstrap") is not True
    ):
        raise SecretScanError("the Trivy manifest entry is not a bootstrap-pinned tool")

    executable = root / "build" / "tools" / "bin" / "trivy"
    if executable.is_symlink() or not executable.is_file():
        raise SecretScanError("the repository-local Trivy wrapper is missing or unsafe")
    try:
        completed = subprocess.run(
            [str(executable), "--version"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecretScanError("the repository-local Trivy version check failed") from exc
    if completed.returncode != 0 or completed.stdout.strip() != f"Version: {version}":
        raise SecretScanError("the live Trivy binary does not match the pinned version")
    return executable, version


def repository_files(root: Path) -> list[Path]:
    """Return tracked and non-ignored candidate source paths without reading .git history."""

    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecretScanError("repository source inventory could not execute") from exc
    if completed.returncode != 0:
        raise SecretScanError("repository source inventory was rejected")

    paths: list[Path] = []
    for raw_path in completed.stdout.split(b"\0"):
        if not raw_path:
            continue
        try:
            relative = Path(os.fsdecode(raw_path))
        except UnicodeError as exc:
            raise SecretScanError("repository source inventory contains an invalid path") from exc
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise SecretScanError("repository source inventory contains an unsafe path")
        paths.append(relative)
    if not paths or len(paths) != len(set(paths)):
        raise SecretScanError("repository source inventory is empty or contains duplicates")
    return sorted(paths, key=lambda item: item.as_posix())


def materialize_source(root: Path, destination: Path, paths: Sequence[Path]) -> int:
    """Copy the exact worktree source set without following repository symlinks."""

    count = 0
    for relative in paths:
        source = root / relative
        try:
            metadata = source.lstat()
        except FileNotFoundError:
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if stat.S_ISREG(metadata.st_mode):
            with source.open("rb") as input_file, target.open("xb") as output_file:
                shutil.copyfileobj(input_file, output_file)
        elif stat.S_ISLNK(metadata.st_mode):
            target.write_text(os.readlink(source), encoding="utf-8")
        else:
            raise SecretScanError(
                "repository source inventory contains a non-file entry"
            )
        count += 1
    if count == 0:
        raise SecretScanError("repository source materialization produced no files")
    return count


def count_secret_findings(report: Any) -> int:
    """Count findings without rendering paths, rules, code, or matched secret bytes."""

    if not isinstance(report, dict):
        raise SecretScanError("Trivy returned a non-object report")
    results = report.get("Results") or []
    if not isinstance(results, list):
        raise SecretScanError("Trivy returned malformed result entries")
    count = 0
    for result in results:
        if not isinstance(result, dict):
            raise SecretScanError("Trivy returned a malformed result")
        findings = result.get("Secrets") or []
        if not isinstance(findings, list) or any(
            not isinstance(finding, dict) for finding in findings
        ):
            raise SecretScanError("Trivy returned malformed secret findings")
        count += len(findings)
    return count


def scan(root: Path) -> dict[str, Any]:
    executable, version = pinned_trivy(root)
    paths = repository_files(root)
    with tempfile.TemporaryDirectory(prefix="jumpship-p03-secret-scan-") as temporary:
        temporary_root = Path(temporary)
        source_root = temporary_root / "source"
        source_root.mkdir(mode=0o700)
        file_count = materialize_source(root, source_root, paths)
        config = temporary_root / "trivy.yaml"
        ignore = temporary_root / "trivy.ignore"
        config.write_text("{}\n", encoding="utf-8")
        ignore.write_text("", encoding="utf-8")
        home = temporary_root / "home"
        home.mkdir(mode=0o700)
        environment = {
            "HOME": str(home),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "TMPDIR": str(temporary_root),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_CONFIG_HOME": str(home / ".config"),
        }
        command = [
            str(executable),
            "--config",
            str(config),
            "--cache-dir",
            str(temporary_root / "cache"),
            "filesystem",
            "--scanners",
            "secret",
            "--detection-priority",
            "precise",
            "--format",
            "json",
            "--exit-code",
            "0",
            "--ignorefile",
            str(ignore),
            "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--disable-telemetry",
            "--skip-version-check",
            "--quiet",
            "--no-progress",
            str(source_root),
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SecretScanError("the pinned Trivy secret scan could not execute") from exc
        if completed.returncode != 0:
            raise SecretScanError(
                f"the pinned Trivy secret scan failed with exit {completed.returncode}"
            )
        report_sha256 = hashlib.sha256(completed.stdout).hexdigest()
        try:
            report = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretScanError("the pinned Trivy secret scan returned invalid JSON") from exc
        finding_count = count_secret_findings(report)

    return {
        "schema_version": "1.0.0",
        "scanner": "trivy",
        "scanner_version": version,
        "source_file_count": file_count,
        "finding_count": finding_count,
        "raw_report_sha256": report_sha256,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        result = scan(repository_root())
    except SecretScanError as exc:
        print(f"secret scan: DENY: {exc}; raw scanner output suppressed", file=sys.stderr)
        return 2
    except OSError:
        print(
            "secret scan: DENY: repository source materialization failed; "
            "raw scanner output suppressed",
            file=sys.stderr,
        )
        return 2
    if result["finding_count"]:
        print(
            "secret scan: DENY: pinned Trivy detected "
            f"{result['finding_count']} secret finding(s) across "
            f"{result['source_file_count']} repository source files; "
            "raw matches suppressed",
            file=sys.stderr,
        )
        return 1
    print(
        "secret scan: PASS: pinned Trivy "
        f"{result['scanner_version']} scanned {result['source_file_count']} "
        "repository source files; findings=0; "
        f"raw-report-sha256={result['raw_report_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
