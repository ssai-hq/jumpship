#!/usr/bin/env python3
"""Dependency-free format, lint, and unit-test front door for P01."""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable


sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from tool_lock import ToolLockError, tool_operation_lock

ROOT = Path(__file__).resolve().parents[2]
TOOLS_ROOT = ROOT / "build" / "tools"
TOOLS_BIN = TOOLS_ROOT / "bin"
TEXT_SUFFIXES = {
    ".go",
    ".json",
    ".md",
    ".mk",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
EXCLUDED_PARTS = {".git", ".tools", "build", "node_modules", ".next"}


class QualityError(RuntimeError):
    """A format, lint, or unit-test failure."""


def _env() -> dict[str, str]:
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
            "PNPM_HOME": str(TOOLS_BIN),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    env["PATH"] = str(TOOLS_BIN) + os.pathsep + env.get("PATH", "")
    return env


def _run(command: list[str], *, timeout: int = 300) -> None:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=_env(),
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise QualityError(f"command failed ({result.returncode}): {' '.join(command)}")


def _repo_files() -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise QualityError(f"git ls-files failed: {result.stderr.decode(errors='replace').strip()}")
    files: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = Path(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise QualityError("repository contains a non-UTF-8 path") from exc
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        path = ROOT / relative
        if path.is_file():
            files.append(path)
    return sorted(files)


def _text_files(files: Iterable[Path]) -> list[Path]:
    selected: list[Path] = []
    for path in files:
        if path.name in {"Makefile", "go.mod", "go.sum", "LICENSE"} or path.suffix in TEXT_SUFFIXES:
            selected.append(path)
    return selected


def _go_files(files: Iterable[Path]) -> list[Path]:
    return [path for path in files if path.suffix == ".go"]


def _go_packages(files: Iterable[Path]) -> list[str]:
    directories = sorted({path.parent.relative_to(ROOT) for path in _go_files(files)})
    return ["." if not directory.parts else f"./{directory.as_posix()}" for directory in directories]


def _python_files(files: Iterable[Path]) -> list[Path]:
    return [path for path in files if path.suffix == ".py" or path.read_bytes().startswith(b"#!/usr/bin/env python3")]


def _shell_files(files: Iterable[Path]) -> list[Path]:
    result: list[Path] = []
    for path in files:
        if path.suffix == ".sh":
            result.append(path)
            continue
        try:
            first_line = path.open("rb").readline()
        except OSError:
            continue
        if first_line in {b"#!/bin/sh\n", b"#!/usr/bin/env sh\n", b"#!/bin/bash\n"}:
            result.append(path)
    return result


def _test_directories(files: Iterable[Path]) -> list[Path]:
    directories = sorted(
        {
            path.parent
            for path in files
            if path.name.startswith("test_")
            and path.suffix == ".py"
            and path.parent.name == "tests"
            and "scripts" in path.relative_to(ROOT).parts
        }
    )
    if not directories:
        raise QualityError("no scripts/**/tests/test_*.py suites were discovered")
    return directories


def _text_errors(files: Iterable[Path]) -> list[str]:
    errors: list[str] = []
    for path in _text_files(files):
        relative = path.relative_to(ROOT)
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{relative}: text file is not UTF-8")
            continue
        if b"\r" in raw:
            errors.append(f"{relative}: CR/CRLF line ending is forbidden")
        if raw and not raw.endswith(b"\n"):
            errors.append(f"{relative}: missing final newline")
        if path.suffix != ".md":
            for number, line in enumerate(text.splitlines(), start=1):
                if line.rstrip(" \t") != line:
                    errors.append(f"{relative}:{number}: trailing whitespace")
    return errors


def _python_errors(files: Iterable[Path]) -> list[str]:
    errors: list[str] = []
    for path in _python_files(files):
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            errors.append(f"{path.relative_to(ROOT)}: {exc}")
    return errors


def _json_errors(files: Iterable[Path]) -> list[str]:
    errors: list[str] = []
    for path in files:
        should_parse = path.suffix == ".json"
        if path.suffix in {".yaml", ".yml"}:
            try:
                first = path.read_text(encoding="utf-8").lstrip()[:1]
            except (OSError, UnicodeDecodeError) as exc:
                errors.append(f"{path.relative_to(ROOT)}: {exc}")
                continue
            should_parse = first in {"{", "["}
        if not should_parse:
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"{path.relative_to(ROOT)}: invalid JSON-compatible data: {exc}")
    return errors


def _shell_errors(files: Iterable[Path]) -> list[str]:
    errors: list[str] = []
    for path in _shell_files(files):
        result = subprocess.run(
            ["sh", "-n", str(path)],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            errors.append(f"{path.relative_to(ROOT)}: {result.stderr.strip()}")
    return errors


def _gofmt_errors(files: Iterable[Path]) -> list[str]:
    go_files = _go_files(files)
    if not go_files:
        return []
    gofmt = TOOLS_BIN / "gofmt"
    if not gofmt.is_file():
        return ["repository-local gofmt is missing; run make bootstrap"]
    result = subprocess.run(
        [str(gofmt), "-l", *[str(path) for path in go_files]],
        cwd=ROOT,
        env=_env(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    errors: list[str] = []
    if result.returncode != 0:
        errors.append(f"gofmt failed: {result.stderr.strip()}")
    for line in result.stdout.splitlines():
        try:
            relative = Path(line).resolve().relative_to(ROOT)
        except ValueError:
            relative = Path(line)
        errors.append(f"{relative}: gofmt drift")
    return errors


def _format_check_unlocked(*, write: bool) -> None:
    files = _repo_files()
    if write:
        go_files = _go_files(files)
        if go_files:
            gofmt = TOOLS_BIN / "gofmt"
            if not gofmt.is_file():
                raise QualityError("repository-local gofmt is missing; run make bootstrap")
            _run([str(gofmt), "-w", *[str(path) for path in go_files]])
        print("fmt: wrote gofmt output; text policy remains check-only")
        files = _repo_files()
    errors = _text_errors(files) + _gofmt_errors(files)
    if errors:
        raise QualityError("format validation failed:\n- " + "\n- ".join(errors))
    print("fmt: UTF-8/LF/final-newline/text policy and gofmt are clean")


def format_check(*, write: bool) -> None:
    with tool_operation_lock(exclusive=False):
        _format_check_unlocked(write=write)


def _lint_unlocked() -> None:
    files = _repo_files()
    errors = _text_errors(files) + _python_errors(files) + _json_errors(files) + _shell_errors(files)
    if errors:
        raise QualityError("source lint failed:\n- " + "\n- ".join(errors))
    go_packages = _go_packages(files)
    if not go_packages:
        raise QualityError("no repository Go packages were discovered")
    _run([str(ROOT / "scripts" / "dependency-locks" / "check")])
    _run([str(TOOLS_BIN / "go"), "vet", *go_packages])
    _run([str(TOOLS_BIN / "golangci-lint"), "run", *go_packages], timeout=600)
    _run([str(TOOLS_BIN / "pnpm"), "--recursive", "--if-present", "run", "lint"])
    print("lint: manifests, Python, shell, Go, and workspace checks passed")


def lint() -> None:
    with tool_operation_lock(exclusive=False):
        _lint_unlocked()


def test_unit() -> None:
    with tool_operation_lock(exclusive=False):
        files = _repo_files()
    test_directories = _test_directories(files)
    for directory in test_directories:
        _run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(directory.relative_to(ROOT)),
                "-p",
                "test_*.py",
                "-v",
            ],
            timeout=600,
        )
    go_packages = _go_packages(files)
    if not go_packages:
        raise QualityError("no repository Go packages were discovered")
    with tool_operation_lock(exclusive=False):
        _run([str(TOOLS_BIN / "go"), "test", *go_packages], timeout=600)
        _run([str(TOOLS_BIN / "pnpm"), "--recursive", "--if-present", "run", "test"], timeout=600)
    print(
        f"test-unit: {len(test_directories)} Python suites plus Go and present workspace unit tests passed"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    format_parser = subparsers.add_parser("fmt")
    format_parser.add_argument("--write", action="store_true")
    subparsers.add_parser("lint")
    subparsers.add_parser("test-unit")
    args = parser.parse_args()
    try:
        if args.command == "fmt":
            format_check(write=args.write)
        elif args.command == "lint":
            lint()
        elif args.command == "test-unit":
            test_unit()
        else:  # pragma: no cover
            raise QualityError(f"unsupported command: {args.command}")
    except (OSError, subprocess.SubprocessError, QualityError, ToolLockError) as exc:
        print(f"quality: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
