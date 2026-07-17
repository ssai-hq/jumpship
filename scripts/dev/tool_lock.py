#!/usr/bin/env python3
"""Cross-process reader/writer lock for repository-local tool operations."""

from __future__ import annotations

import contextlib
import fcntl
import os
import stat
from pathlib import Path
from typing import Iterable, Iterator


ROOT = Path(__file__).resolve().parents[2]
TOOLS_ROOT = ROOT / "build" / "tools"
LOCK_PATH = TOOLS_ROOT / ".operation.lock"


class ToolLockError(RuntimeError):
    """The tool-operation lock cannot be acquired without following a symlink."""


def assert_safe_mutable_paths(paths: Iterable[Path]) -> None:
    """Reject any mutable path that escapes ROOT or has a symlinked ancestor."""

    root = Path(os.path.abspath(ROOT))
    for raw_path in paths:
        target = Path(os.path.abspath(raw_path))
        try:
            relative = target.relative_to(root)
        except ValueError as exc:
            raise ToolLockError(f"mutable tool path escapes repository: {target}") from exc
        current = root
        for part in (".", *relative.parts):
            if part != ".":
                current = current / part
            if current.is_symlink():
                raise ToolLockError(f"mutable tool path follows a symlink: {current}")


def _prepare_lock_path() -> None:
    assert_safe_mutable_paths((ROOT, ROOT / "build", TOOLS_ROOT, LOCK_PATH))
    (ROOT / "build").mkdir(mode=0o755, exist_ok=True)
    TOOLS_ROOT.mkdir(mode=0o755, exist_ok=True)
    if not (ROOT / "build").is_dir() or not TOOLS_ROOT.is_dir():
        raise ToolLockError("tool lock parent is not a directory")


@contextlib.contextmanager
def tool_operation_lock(*, exclusive: bool) -> Iterator[None]:
    """Hold the stable repository tool lock in exclusive or shared mode."""

    _prepare_lock_path()
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(LOCK_PATH, flags, 0o600)
    except OSError as exc:
        raise ToolLockError(f"cannot safely open tool lock {LOCK_PATH}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ToolLockError(f"tool lock is not a private regular file: {LOCK_PATH}")
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
