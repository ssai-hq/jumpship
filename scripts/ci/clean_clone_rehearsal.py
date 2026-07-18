#!/usr/bin/env python3
"""Run the P03 reproducibility vector from an isolated committed-HEAD clone."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
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
    harness.ACCEPTANCE = list(P03_VECTOR)
    report = harness.rehearse(None, quiet=True)
    report["evidence_kind"] = "p03-clean-clone-rehearsal"
    report["rubric_rows"] = ["JSMVP-R013"]
    report["environment"]["packet_profile"] = "local-static-validation"
    report["environment"]["docker_credentials_forwarded"] = False
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
