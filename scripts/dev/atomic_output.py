#!/usr/bin/env python3
"""Symlink-safe atomic replacement for deterministic repository outputs."""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path


class AtomicOutputError(RuntimeError):
    """A requested output path is unsafe or changed during publication."""


def _fail(message: str) -> None:
    raise AtomicOutputError(message)


def _prepare_parent(repo_root: Path, requested_path: Path) -> tuple[Path, Path, Path]:
    root = repo_root.resolve()
    if requested_path.is_absolute():
        candidate = Path(os.path.abspath(requested_path))
        try:
            relative = candidate.relative_to(root)
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
            try:
                parent.mkdir(mode=0o755)
            except FileExistsError:
                pass
        if parent.is_symlink() or parent.resolve() != parent:
            _fail(f"symlinked output parent is forbidden: {parent.relative_to(root)}")
    return relative, parent, root / relative


def _assert_parent_identity(parent: Path, descriptor: int) -> None:
    opened = os.fstat(descriptor)
    try:
        lexical = os.stat(parent, follow_symlinks=False)
    except OSError as exc:
        _fail(f"cannot revalidate output parent {parent}: {exc}")
    if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
        lexical.st_dev,
        lexical.st_ino,
    ):
        _fail(f"output parent changed during validation: {parent}")
    if parent.is_symlink() or parent.resolve() != parent:
        _fail(f"symlinked output parent is forbidden: {parent}")


def _open_parent(parent: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(parent, flags)
    except OSError as exc:
        _fail(f"cannot open real output parent {parent}: {exc}")
    try:
        _assert_parent_identity(parent, descriptor)
    except (AtomicOutputError, OSError):
        os.close(descriptor)
        raise
    return descriptor


def _entry_stat(parent_descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _regular_identity(parent_descriptor: int, name: str) -> tuple[int, int] | None:
    details = _entry_stat(parent_descriptor, name)
    if details is None:
        return None
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        _fail(f"refusing to replace non-regular output: {name}")
    return details.st_dev, details.st_ino


def atomic_replace_regular(repo_root: Path, requested_path: Path, data: bytes) -> Path:
    """Replace a stable regular repo file without following any output symlink."""
    relative, parent, output = _prepare_parent(repo_root, requested_path)
    parent_descriptor = _open_parent(parent)
    temporary_name = ""
    try:
        original_identity = _regular_identity(parent_descriptor, output.name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        for _attempt in range(16):
            temporary_name = f".{output.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
            try:
                output_descriptor = os.open(
                    temporary_name,
                    flags,
                    0o644,
                    dir_fd=parent_descriptor,
                )
                break
            except FileExistsError:
                temporary_name = ""
                continue
            except OSError:
                temporary_name = ""
                raise
        else:
            _fail(f"cannot allocate temporary output beside {relative}")

        with os.fdopen(output_descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

        _assert_parent_identity(parent, parent_descriptor)
        if _regular_identity(parent_descriptor, output.name) != original_identity:
            _fail(f"output changed during publication: {relative}")
        os.replace(
            temporary_name,
            output.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = ""
        os.fsync(parent_descriptor)
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)
    return output
