#!/usr/bin/env python3
"""Repository-owned static import and trust-boundary checker.

The checker intentionally parses every Go source file, including tests, generated
files, and files excluded by the current build tags.  Build selection is not an
authority boundary.  Local imports are resolved across every nested Go module and
then checked transitively so an intermediate package cannot launder a forbidden
dependency.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

sys.dont_write_bytecode = True

DEV_SCRIPT_DIR = Path(__file__).resolve().parents[1] / "dev"
if str(DEV_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(DEV_SCRIPT_DIR))

from atomic_output import AtomicOutputError, atomic_replace_regular


EXCLUDED_DIRECTORIES = {
    ".git",
    ".next",
    ".pnpm-store",
    ".tools",
    "build",
    "dist",
    "node_modules",
    "vendor",
}
SOURCE_ROOTS = {"agent", "cmd", "contracts", "evals", "internal", "test", "web"}
WEB_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
EXTERNAL_GO_TARGET_PREFIX = "external:"
SANITIZED_TRAJECTORY_CONTRACT_PACKAGE = "internal/contracts/quality/sanitizedtrajectory"
MODEL_PROVIDER_IMPORT_PREFIXES = (
    "github.com/anthropics/anthropic-sdk-go",
    "github.com/google/generative-ai-go",
    "github.com/openai/openai-go",
    "github.com/sashabaranov/go-openai",
    "google.golang.org/genai",
)
MODEL_PROVIDER_IMPORT_FAMILY_PREFIXES = (
    "github.com/aws/aws-sdk-go-v2/service/bedrock",
    "github.com/aws/aws-sdk-go/service/bedrock",
)
AWS_PROVISIONING_IMPORT_PREFIXES = (
    "github.com/aws/aws-sdk-go-v2/service/autoscaling",
    "github.com/aws/aws-sdk-go-v2/service/cloudformation",
    "github.com/aws/aws-sdk-go-v2/service/ec2",
    "github.com/aws/aws-sdk-go-v2/service/ecs",
    "github.com/aws/aws-sdk-go-v2/service/iam",
    "github.com/aws/aws-sdk-go-v2/service/rds",
    "github.com/aws/aws-sdk-go/service/autoscaling",
    "github.com/aws/aws-sdk-go/service/cloudformation",
    "github.com/aws/aws-sdk-go/service/ec2",
    "github.com/aws/aws-sdk-go/service/ecs",
    "github.com/aws/aws-sdk-go/service/iam",
    "github.com/aws/aws-sdk-go/service/rds",
)
DIRECT_DATABASE_DRIVER_IMPORT_PREFIXES = (
    "github.com/go-sql-driver/mysql",
    "github.com/jackc/pgx",
    "github.com/lib/pq",
    "go.mongodb.org/mongo-driver",
)


@dataclass(frozen=True)
class Module:
    directory: Path
    import_path: str


@dataclass(frozen=True)
class ImportSite:
    source: str
    target: str
    source_file: str
    line: int
    ecosystem: str


@dataclass(frozen=True)
class LexToken:
    kind: str
    value: str
    line: int
    offset: int


@dataclass(frozen=True)
class BoundaryRule:
    name: str
    explanation: str
    source_matches: Callable[[str], bool]
    target_matches: Callable[[str], bool]


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _has_prefix(path: str, prefixes: Iterable[str]) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)


def _external_import_path(path: str) -> str | None:
    if not path.startswith(EXTERNAL_GO_TARGET_PREFIX):
        return None
    return path.removeprefix(EXTERNAL_GO_TARGET_PREFIX)


def _matches_external_import(
    path: str,
    prefixes: Iterable[str],
    family_prefixes: Iterable[str] = (),
) -> bool:
    imported = _external_import_path(path)
    if imported is None:
        return False
    return _has_prefix(imported, prefixes) or any(
        imported.startswith(prefix) for prefix in family_prefixes
    )


def _is_repository_domain(path: str) -> bool:
    return path.split("/", 1)[0] in SOURCE_ROOTS


def _is_quality_forbidden_target(path: str) -> bool:
    if _external_import_path(path) is not None:
        return True
    if not _is_repository_domain(path):
        return False
    if _has_prefix(path, ("internal/quality",)):
        return False
    return path != SANITIZED_TRAJECTORY_CONTRACT_PACKAGE


def _is_guarded_external_target(path: str) -> bool:
    return (
        _matches_external_import(
            path,
            MODEL_PROVIDER_IMPORT_PREFIXES,
            MODEL_PROVIDER_IMPORT_FAMILY_PREFIXES,
        )
        or _matches_external_import(path, AWS_PROVISIONING_IMPORT_PREFIXES)
        or _matches_external_import(path, DIRECT_DATABASE_DRIVER_IMPORT_PREFIXES)
    )


def _is_direct_driver(path: str) -> bool:
    parts = path.split("/")
    if _has_prefix(path, ("internal/persistence/target",)):
        return True
    if len(parts) >= 4 and parts[0:2] == ["internal", "corridors"]:
        return parts[3] in {"source", "target"}
    return False


def _is_implementation_from_contracts(path: str) -> bool:
    return path.startswith("internal/") and not _has_prefix(path, ("internal/contracts",))


RULES = (
    BoundaryRule(
        name="mothership-narrow-authority",
        explanation=(
            "mothership lifecycle code cannot reach harness, engine, decision, or evidence implementations"
        ),
        source_matches=lambda path: _has_prefix(path, ("cmd/mothership", "internal/mothership")),
        target_matches=lambda path: _has_prefix(
            path,
            ("internal/harness", "internal/engine", "internal/decisions", "internal/evidence"),
        ),
    ),
    BoundaryRule(
        name="harness-no-provisioning-or-drivers",
        explanation="harness code cannot reach provisioning authority or direct source/target drivers",
        source_matches=lambda path: _has_prefix(
            path,
            ("cmd/cell-agent", "cmd/analysis-runner", "internal/harness"),
        ),
        target_matches=lambda path: _has_prefix(path, ("internal/mothership",))
        or _has_prefix(path, ("infra",))
        or _is_direct_driver(path)
        or _matches_external_import(path, AWS_PROVISIONING_IMPORT_PREFIXES)
        or _matches_external_import(path, DIRECT_DATABASE_DRIVER_IMPORT_PREFIXES),
    ),
    BoundaryRule(
        name="engine-no-model-provider",
        explanation="the deterministic engine cannot reach model or provider implementations",
        source_matches=lambda path: _has_prefix(path, ("cmd/engine", "internal/engine")),
        target_matches=lambda path: _has_prefix(
            path,
            ("internal/harness/provider", "internal/provider", "internal/providers"),
        )
        or _matches_external_import(
            path,
            MODEL_PROVIDER_IMPORT_PREFIXES,
            MODEL_PROVIDER_IMPORT_FAMILY_PREFIXES,
        ),
    ),
    BoundaryRule(
        name="engine-typed-data-ports-only",
        explanation=(
            "the deterministic engine must use typed ports and cannot reach provisioning or direct database drivers"
        ),
        source_matches=lambda path: _has_prefix(path, ("cmd/engine", "internal/engine")),
        target_matches=lambda path: _has_prefix(path, ("infra", "internal/mothership"))
        or _is_direct_driver(path)
        or _matches_external_import(path, AWS_PROVISIONING_IMPORT_PREFIXES)
        or _matches_external_import(path, DIRECT_DATABASE_DRIVER_IMPORT_PREFIXES),
    ),
    BoundaryRule(
        name="quality-sanitized-input-only",
        explanation=(
            "internal quality code may import only its own packages and the explicit sanitized-trajectory contract"
        ),
        source_matches=lambda path: _has_prefix(path, ("internal/quality",)),
        target_matches=_is_quality_forbidden_target,
    ),
    BoundaryRule(
        name="quality-composition-no-restricted-state",
        explanation="quality composition code cannot reach cell artifacts, evidence stores, persistence, or corridor drivers",
        source_matches=lambda path: _has_prefix(
            path,
            (
                "cmd/agent-quality",
                "cmd/agent-eval",
                "cmd/bundle-activator",
                "evals",
            ),
        ),
        target_matches=lambda path: _has_prefix(
            path,
            (
                "internal/cell",
                "internal/cellidentity",
                "internal/corridors",
                "internal/evidence",
                "internal/persistence/cell",
                "internal/persistence/target",
            ),
        ),
    ),
    BoundaryRule(
        name="contracts-no-implementation",
        explanation="contract packages cannot import implementation packages",
        source_matches=lambda path: _has_prefix(path, ("contracts", "internal/contracts")),
        target_matches=_is_implementation_from_contracts,
    ),
)


def _relative(root: Path, path: Path) -> str:
    value = path.relative_to(root).as_posix()
    return value or "."


def _walk_files(root: Path) -> tuple[list[Path], list[dict[str, str]]]:
    """Return regular files and deterministic symlink violations.

    Symlinks in source roots are rejected even when they remain in-repository.
    That prevents one logical import path from silently resolving to another
    ownership domain.  Any repository symlink that escapes the checkout is also
    rejected.
    """

    files: list[Path] = []
    violations: list[dict[str, str]] = []
    root_real = root.resolve()
    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        directory_names[:] = sorted(name for name in directory_names if name not in EXCLUDED_DIRECTORIES)
        for name in tuple(directory_names):
            candidate = current / name
            if candidate.is_symlink():
                resolved = candidate.resolve(strict=False)
                rel = _relative(root, candidate)
                if not _is_within(resolved, root_real):
                    violations.append(
                        {"kind": "symlink-escape", "path": rel, "resolved": "<outside-repository>"}
                    )
                elif rel.split("/", 1)[0] in SOURCE_ROOTS:
                    violations.append(
                        {
                            "kind": "source-symlink",
                            "path": rel,
                            "resolved": _relative(root_real, resolved),
                        }
                    )
                directory_names.remove(name)
        for name in sorted(file_names):
            candidate = current / name
            if candidate.is_symlink():
                resolved = candidate.resolve(strict=False)
                rel = _relative(root, candidate)
                if not _is_within(resolved, root_real):
                    violations.append(
                        {"kind": "symlink-escape", "path": rel, "resolved": "<outside-repository>"}
                    )
                elif rel.split("/", 1)[0] in SOURCE_ROOTS:
                    violations.append(
                        {
                            "kind": "source-symlink",
                            "path": rel,
                            "resolved": _relative(root_real, resolved),
                        }
                    )
                continue
            if candidate.is_file():
                files.append(candidate)
    return sorted(files), sorted(violations, key=lambda item: (item["kind"], item["path"]))


def _read_module_path(path: Path) -> str | None:
    try:
        content = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    match = re.search(r"(?m)^\s*module\s+([^\s]+)\s*$", content)
    if match is None:
        return None
    value = match.group(1)
    if value.startswith('"') and value.endswith('"'):
        value = _decode_go_string(value[1:-1]) or ""
    elif value.startswith("`") and value.endswith("`"):
        value = value[1:-1].replace("\r", "")
    return value if value else None


def _discover_modules(files: Iterable[Path]) -> list[Module]:
    modules = [
        Module(path.parent.resolve(), module_path)
        for path in files
        if path.name == "go.mod" and (module_path := _read_module_path(path)) is not None
    ]
    return sorted(modules, key=lambda item: (-len(item.directory.parts), item.import_path))


def _web_identifier_escape(content: str, index: int) -> tuple[str, int] | None:
    if content[index : index + 2] != "\\u":
        return None
    if content[index + 2 : index + 3] == "{":
        close = content.find("}", index + 3)
        if close == -1:
            return None
        digits = content[index + 3 : close]
        next_index = close + 1
        if re.fullmatch(r"[0-9A-Fa-f]{1,6}", digits) is None:
            return None
    else:
        digits = content[index + 2 : index + 6]
        next_index = index + 6
        if len(digits) != 4 or re.fullmatch(r"[0-9A-Fa-f]{4}", digits) is None:
            return None
    codepoint = int(digits, 16)
    if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
        return None
    return chr(codepoint), next_index


def _lex_source(content: str, language: str) -> list[LexToken]:
    """Tokenize only the syntax needed for static import discovery.

    Keeping strings as tokens, rather than applying import regexes to source
    text, prevents comments, diagnostics, and template literals from inventing
    dependencies.
    """

    tokens: list[LexToken] = []
    index = 0
    line = 1
    while index < len(content):
        char = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""
        if char.isspace():
            if char == "\n":
                tokens.append(LexToken("newline", "\n", line, index))
                line += 1
            index += 1
            continue
        if char == "/" and following == "/":
            index += 2
            while index < len(content) and content[index] != "\n":
                index += 1
            continue
        if char == "/" and following == "*":
            index += 2
            while index < len(content):
                if content[index] == "\n":
                    line += 1
                if content[index : index + 2] == "*/":
                    index += 2
                    break
                index += 1
            continue
        allowed_quotes = {'"', "`"} if language == "go" else {'"', "'", "`"}
        if char in allowed_quotes:
            quote = char
            start = index
            start_line = line
            index += 1
            value: list[str] = []
            while index < len(content):
                current = content[index]
                if current == "\n":
                    line += 1
                if current == quote:
                    index += 1
                    break
                if current == "\\" and quote != "`" and index + 1 < len(content):
                    # Preserve escapes for the language-specific decoder. Import
                    # boundaries apply to the compiler/runtime value, not the
                    # source spelling (for example Go ``\\x70rovider``).
                    value.extend((current, content[index + 1]))
                    if content[index + 1] == "\n":
                        line += 1
                    index += 2
                    continue
                value.append(current)
                index += 1
            if language == "go" and quote == "`":
                kind = "raw-string"
            elif language != "go" and quote == "`":
                kind = "template"
            else:
                kind = "string"
            tokens.append(LexToken(kind, "".join(value), start_line, start))
            continue
        escaped_identifier = _web_identifier_escape(content, index) if language != "go" else None
        if char.isalpha() or char == "_" or (language != "go" and (char == "$" or escaped_identifier)):
            start = index
            identifier: list[str] = []
            if escaped_identifier is not None:
                decoded, index = escaped_identifier
                identifier.append(decoded)
            else:
                identifier.append(char)
                index += 1
            while index < len(content):
                escaped_identifier = (
                    _web_identifier_escape(content, index) if language != "go" else None
                )
                if escaped_identifier is not None:
                    decoded, index = escaped_identifier
                    identifier.append(decoded)
                    continue
                if content[index].isalnum() or content[index] == "_" or (
                    language != "go" and content[index] == "$"
                ):
                    identifier.append(content[index])
                    index += 1
                    continue
                break
            tokens.append(LexToken("identifier", "".join(identifier), line, start))
            continue
        tokens.append(LexToken("punctuation", char, line, index))
        index += 1
    return tokens


_GO_SIMPLE_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    '"': '"',
    "'": "'",
}


def _decode_go_string(value: str) -> str | None:
    """Decode the escape forms accepted in a Go interpreted string literal."""

    decoded: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            decoded.append(value[index])
            index += 1
            continue
        if index + 1 >= len(value):
            return None
        escape = value[index + 1]
        if escape in _GO_SIMPLE_ESCAPES:
            decoded.append(_GO_SIMPLE_ESCAPES[escape])
            index += 2
            continue
        if escape == "x":
            width, start = 2, index + 2
        elif escape == "u":
            width, start = 4, index + 2
        elif escape == "U":
            width, start = 8, index + 2
        elif escape in "01234567":
            width, start = 3, index + 1
        else:
            return None
        digits = value[start : start + width]
        base = 8 if escape in "01234567" else 16
        if len(digits) != width or re.fullmatch(
            r"[0-7]+" if base == 8 else r"[0-9A-Fa-f]+", digits
        ) is None:
            return None
        codepoint = int(digits, base)
        if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
            return None
        decoded.append(chr(codepoint))
        index = start + width
    return "".join(decoded)


def _decode_web_string(value: str) -> str | None:
    """Decode JavaScript string escapes relevant to module specifiers."""

    decoded: list[str] = []
    index = 0
    simple = {
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "0": "\0",
        "\\": "\\",
        '"': '"',
        "'": "'",
    }
    while index < len(value):
        if value[index] != "\\":
            decoded.append(value[index])
            index += 1
            continue
        if index + 1 >= len(value):
            return None
        escape = value[index + 1]
        if escape in simple:
            decoded.append(simple[escape])
            index += 2
            continue
        if escape in {"\n", "\r"}:
            index += 2
            if escape == "\r" and index < len(value) and value[index] == "\n":
                index += 1
            continue
        if escape == "x":
            digits = value[index + 2 : index + 4]
            if len(digits) != 2 or re.fullmatch(r"[0-9A-Fa-f]{2}", digits) is None:
                return None
            decoded.append(chr(int(digits, 16)))
            index += 4
            continue
        if escape == "u":
            if value[index + 2 : index + 3] == "{":
                close = value.find("}", index + 3)
                if close == -1:
                    return None
                digits = value[index + 3 : close]
                if re.fullmatch(r"[0-9A-Fa-f]{1,6}", digits) is None:
                    return None
                index = close + 1
            else:
                digits = value[index + 2 : index + 6]
                if len(digits) != 4 or re.fullmatch(r"[0-9A-Fa-f]{4}", digits) is None:
                    return None
                index += 6
            codepoint = int(digits, 16)
            if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
                return None
            decoded.append(chr(codepoint))
            continue
        # JavaScript identity escapes (for example ``\q``) evaluate to the
        # escaped character in non-template strings.
        decoded.append(escape)
        index += 2
    return "".join(decoded)


def _go_imports(path: Path) -> list[tuple[str, int]]:
    try:
        # ``Path.read_text`` enables universal-newline translation and would
        # turn CR into LF. Go discards CR bytes inside raw string literals, so
        # preserve source bytes and apply the language rule explicitly.
        content = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    tokens = _lex_source(content, "go")
    imports: list[tuple[str, int]] = []
    for position, token in enumerate(tokens):
        if token.kind != "identifier" or token.value != "import":
            continue
        cursor = position + 1
        while cursor < len(tokens) and tokens[cursor].kind == "newline":
            cursor += 1
        if cursor >= len(tokens):
            continue
        if tokens[cursor].value == "(":
            cursor += 1
            depth = 1
            while cursor < len(tokens) and depth:
                candidate = tokens[cursor]
                if candidate.value == "(":
                    depth += 1
                elif candidate.value == ")":
                    depth -= 1
                elif depth == 1 and candidate.kind in {"string", "raw-string"} and candidate.value:
                    decoded = (
                        candidate.value.replace("\r", "")
                        if candidate.kind == "raw-string"
                        else _decode_go_string(candidate.value)
                    )
                    if decoded:
                        imports.append((decoded, candidate.line))
                cursor += 1
            continue
        if tokens[cursor].kind == "identifier" or tokens[cursor].value == ".":
            cursor += 1
            while cursor < len(tokens) and tokens[cursor].kind == "newline":
                cursor += 1
        if cursor < len(tokens) and tokens[cursor].kind in {"string", "raw-string"} and tokens[cursor].value:
            decoded = (
                tokens[cursor].value.replace("\r", "")
                if tokens[cursor].kind == "raw-string"
                else _decode_go_string(tokens[cursor].value)
            )
            if decoded:
                imports.append((decoded, tokens[cursor].line))
    return imports


def _module_for_file(path: Path, modules: Iterable[Module]) -> Module | None:
    resolved = path.resolve()
    return next((module for module in modules if _is_within(resolved, module.directory)), None)


def _package_for_file(root: Path, path: Path, modules: Iterable[Module]) -> tuple[str, str] | None:
    module = _module_for_file(path, modules)
    if module is None:
        return None
    package_directory = path.parent.resolve()
    suffix = package_directory.relative_to(module.directory).as_posix()
    import_path = module.import_path if suffix == "." else f"{module.import_path}/{suffix}"
    return import_path, _relative(root.resolve(), package_directory)


def _resolve_go_import(
    root: Path, import_path: str, modules: Iterable[Module]
) -> tuple[str, str] | None:
    for module in sorted(modules, key=lambda item: (-len(item.import_path), item.import_path)):
        if import_path == module.import_path:
            target = module.directory
        elif import_path.startswith(module.import_path + "/"):
            target = module.directory / import_path[len(module.import_path) + 1 :]
        else:
            continue
        target = target.resolve(strict=False)
        if not _is_within(target, module.directory) or not _is_within(target, root.resolve()):
            return None
        return import_path, _relative(root.resolve(), target)
    return None


def _go_sites(root: Path, files: Iterable[Path], modules: list[Module]) -> list[ImportSite]:
    sites: set[ImportSite] = set()
    for path in files:
        if path.suffix != ".go":
            continue
        source_package = _package_for_file(root, path, modules)
        if source_package is None:
            continue
        _, source_directory = source_package
        for imported, line in _go_imports(path):
            target_package = _resolve_go_import(root, imported, modules)
            target_directories: list[str] = []
            if target_package is None:
                # Standard-library imports have no dotted first path element.
                # Preserve every third-party module import as an explicit graph
                # edge so authority checks cannot be bypassed by importing an
                # SDK or database driver directly instead of a local adapter.
                if "." not in imported.split("/", 1)[0]:
                    continue
                target_directories.append(f"{EXTERNAL_GO_TARGET_PREFIX}{imported}")
            else:
                _, target_directory = target_package
                target_directories.append(target_directory)
                guarded_external = f"{EXTERNAL_GO_TARGET_PREFIX}{imported}"
                if _is_guarded_external_target(guarded_external):
                    # A nested/replaced module may claim a provider or driver
                    # import path while living under an innocuous local folder.
                    # Preserve the authority-bearing module identity too.
                    target_directories.append(guarded_external)
            for target_directory in target_directories:
                sites.add(
                    ImportSite(
                        source=source_directory,
                        target=target_directory,
                        source_file=_relative(root, path),
                        line=line,
                        ecosystem="go",
                    )
                )
    return sorted(sites, key=lambda item: (item.source, item.target, item.source_file, item.line))


def _web_imports(
    content: str,
) -> tuple[list[tuple[str, int, int]], list[tuple[str, int, int]]]:
    tokens = _lex_source(content, "web")
    imports: list[tuple[str, int, int]] = []
    dynamic: list[tuple[str, int, int]] = []
    for position, token in enumerate(tokens):
        if token.kind != "identifier" or token.value not in {"import", "export", "require"}:
            continue
        if position and tokens[position - 1].value == ".":
            is_module_require = (
                token.value == "require"
                and position >= 2
                and tokens[position - 2].kind == "identifier"
                and tokens[position - 2].value == "module"
            )
            if not is_module_require:
                if token.value == "require":
                    dynamic.append((token.value, token.line, token.offset))
                continue
        cursor = position + 1
        while cursor < len(tokens) and tokens[cursor].kind == "newline":
            cursor += 1
        if cursor >= len(tokens):
            continue
        if token.value == "import" and tokens[cursor].value == ".":
            # ``import.meta`` is an expression, not module resolution.
            continue
        if token.value in {"import", "require"} and tokens[cursor].value == "(":
            cursor += 1
            while cursor < len(tokens) and tokens[cursor].kind == "newline":
                cursor += 1
            if cursor < len(tokens) and tokens[cursor].kind == "string":
                candidate = tokens[cursor]
                decoded = _decode_web_string(candidate.value)
                closing = cursor + 1
                while closing < len(tokens) and tokens[closing].kind == "newline":
                    closing += 1
                # A literal followed by concatenation, interpolation, a second
                # argument, or another expression is still dynamic.
                if decoded is not None and closing < len(tokens) and tokens[closing].value == ")":
                    imports.append((decoded, candidate.line, candidate.offset))
                else:
                    dynamic.append((token.value, candidate.line, candidate.offset))
            else:
                dynamic.append((token.value, token.line, token.offset))
            continue
        if token.value == "import" and tokens[cursor].kind == "string":
            candidate = tokens[cursor]
            decoded = _decode_web_string(candidate.value)
            if decoded is not None:
                imports.append((decoded, candidate.line, candidate.offset))
            else:
                dynamic.append((token.value, candidate.line, candidate.offset))
            continue
        if token.value == "require":
            # A bare reference can be aliased and invoked later, defeating a
            # call-site-only import graph. Only a directly proven literal
            # require/module.require call is accepted above.
            dynamic.append((token.value, token.line, token.offset))
            continue
        # Static import/export declarations end at a semicolon or the next
        # declaration keyword. Newlines are valid inside named import lists.
        limit = min(len(tokens), cursor + 200)
        while cursor < limit:
            candidate = tokens[cursor]
            if candidate.value == ";":
                break
            if (
                cursor > position + 1
                and candidate.kind == "identifier"
                and candidate.value in {"import", "export"}
            ):
                break
            if candidate.kind == "identifier" and candidate.value == "from":
                string_position = cursor + 1
                while string_position < limit and tokens[string_position].kind == "newline":
                    string_position += 1
                if string_position < limit and tokens[string_position].kind == "string":
                    source = tokens[string_position]
                    decoded = _decode_web_string(source.value)
                    if decoded is not None:
                        imports.append((decoded, source.line, source.offset))
                    else:
                        dynamic.append((token.value, source.line, source.offset))
                break
            cursor += 1
    return (
        sorted(set(imports), key=lambda item: (item[2], item[0])),
        sorted(set(dynamic), key=lambda item: (item[2], item[0])),
    )


def _resolve_web_relative(source: Path, specifier: str) -> Path:
    base = source.parent / specifier
    candidates = [base]
    if base.suffix == "":
        candidates.extend(base.with_suffix(extension) for extension in WEB_EXTENSIONS)
        candidates.extend(base / f"index{extension}" for extension in WEB_EXTENSIONS)
    return next((candidate for candidate in candidates if candidate.exists()), base).resolve(strict=False)


def _strip_jsonc_comments(content: str) -> str:
    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(content):
        char = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == "/" and following == "/":
            output.extend((" ", " "))
            index += 2
            while index < len(content) and content[index] != "\n":
                output.append(" ")
                index += 1
            continue
        if char == "/" and following == "*":
            output.extend((" ", " "))
            index += 2
            while index < len(content):
                if content[index : index + 2] == "*/":
                    output.extend((" ", " "))
                    index += 2
                    break
                output.append("\n" if content[index] == "\n" else " ")
                index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _strip_jsonc_trailing_commas(content: str) -> str:
    output: list[str] = []
    in_string = False
    escaped = False
    for index, char in enumerate(content):
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            output.append(char)
            continue
        if char == ",":
            cursor = index + 1
            while cursor < len(content) and content[cursor].isspace():
                cursor += 1
            if cursor < len(content) and content[cursor] in "}]":
                output.append(" ")
                continue
        output.append(char)
    return "".join(output)


def _load_jsonc(path: Path) -> dict[str, object] | None:
    try:
        content = path.read_text(encoding="utf-8")
        value = json.loads(_strip_jsonc_trailing_commas(_strip_jsonc_comments(content)))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _web_config_violations(root: Path, files: Iterable[Path]) -> list[dict[str, object]]:
    web_root = (root / "web").resolve(strict=False)
    violations: list[dict[str, object]] = []
    validated: set[Path] = set()
    active: set[Path] = set()

    def record(path: Path, target: Path | str, explanation: str) -> None:
        target_path = target if isinstance(target, Path) else None
        if target_path is not None and _is_within(target_path, root.resolve()):
            target_label = _relative(root, target_path)
        elif target_path is not None:
            target_label = "<outside-repository>"
        else:
            target_label = target
        violations.append(
            {
                "direct": True,
                "explanation": explanation,
                "line": 1,
                "path": [_relative(root, path.parent), target_label],
                "rule": "web-configuration-boundary",
                "source": _relative(root, path.parent),
                "source_file": _relative(root, path),
                "target": target_label,
            }
        )

    def resolve_pattern(base: Path, pattern: str) -> Path:
        # TypeScript normalizes both separators on every host. Match that
        # behavior so a Windows-spelled escape is not harmless on macOS/Linux.
        neutral = re.sub(r"[*?\[\]{}]", "_", pattern.replace("\\", "/"))
        if re.match(r"^[A-Za-z]:/", neutral):
            neutral = "/" + neutral
        return (base / neutral).resolve(strict=False)

    def resolve_extends(path: Path, value: str) -> Path | None:
        normalized = value.replace("\\", "/")
        if not normalized.startswith((".", "/")) and re.match(r"^[A-Za-z]:/", normalized) is None:
            # Bare package configs are dependency inputs, not repository source
            # aliases. Dependency pinning governs them.
            return None
        if re.match(r"^[A-Za-z]:/", normalized):
            normalized = "/" + normalized
        candidate = (path.parent / normalized).resolve(strict=False)
        candidates = [candidate]
        if candidate.suffix == "":
            candidates.extend((candidate.with_suffix(".json"), candidate / "tsconfig.json"))
        return next((item for item in candidates if item.is_file()), candidate)

    def validate(path: Path) -> None:
        path = path.resolve(strict=False)
        if path in validated:
            return
        if path in active:
            record(path, "<extends-cycle>", "TypeScript extends graph contains a cycle")
            return
        active.add(path)
        config = _load_jsonc(path)
        if config is None:
            record(path, "<invalid-jsonc>", "web TypeScript configuration must parse deterministically")
            active.remove(path)
            validated.add(path)
            return

        extends_value = config.get("extends")
        if extends_value is None:
            extends_values: list[str] = []
        elif isinstance(extends_value, str):
            extends_values = [extends_value]
        elif isinstance(extends_value, list) and all(isinstance(item, str) for item in extends_value):
            extends_values = extends_value
        else:
            record(path, "<invalid-extends>", "TypeScript extends must be a string or string array")
            extends_values = []
        for value in extends_values:
            if "${" in value:
                record(path, "<dynamic-extends>", "dynamic TypeScript extends paths are not permitted")
                continue
            resolved = resolve_extends(path, value)
            if resolved is None:
                continue
            if not _is_within(resolved, web_root):
                record(path, resolved, "TypeScript extends path escapes the web trust domain")
            elif not resolved.is_file():
                record(path, resolved, "TypeScript extends path does not resolve to a file")
            else:
                validate(resolved)

        compiler = config.get("compilerOptions", {})
        if not isinstance(compiler, dict):
            record(path, "<invalid-compiler-options>", "compilerOptions must be an object")
        else:
            base_url = compiler.get("baseUrl", ".")
            if not isinstance(base_url, str):
                record(path, "<invalid-base-url>", "compilerOptions.baseUrl must be a string")
                resolved_base = path.parent.resolve()
            elif "${" in base_url:
                record(path, "<dynamic-base-url>", "dynamic TypeScript baseUrl is not permitted")
                resolved_base = path.parent.resolve()
            else:
                resolved_base = resolve_pattern(path.parent, base_url)
                if not _is_within(resolved_base, web_root):
                    record(path, resolved_base, "TypeScript baseUrl escapes the web trust domain")
            paths = compiler.get("paths", {})
            if not isinstance(paths, dict):
                record(path, "<invalid-paths>", "compilerOptions.paths must be an object")
            else:
                for alias, targets in sorted(paths.items()):
                    if not isinstance(alias, str) or not isinstance(targets, list) or not targets:
                        record(path, "<invalid-path-alias>", "TypeScript path aliases must be non-empty arrays")
                        continue
                    for target in targets:
                        if not isinstance(target, str):
                            record(path, "<invalid-path-target>", "TypeScript path targets must be strings")
                            continue
                        if "${" in target:
                            record(path, "<dynamic-path-target>", "dynamic TypeScript path targets are not permitted")
                            continue
                        resolved = resolve_pattern(resolved_base, target)
                        if not _is_within(resolved, web_root):
                            record(path, resolved, f"TypeScript path alias {alias!r} escapes the web trust domain")
            for field in ("rootDirs", "typeRoots"):
                values = compiler.get(field, [])
                if values is None:
                    continue
                if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                    record(path, f"<invalid-{field}>", f"compilerOptions.{field} must be a string array")
                    continue
                for value in values:
                    if "${" in value:
                        record(path, f"<dynamic-{field}>", f"dynamic compilerOptions.{field} entries are not permitted")
                        continue
                    resolved = resolve_pattern(path.parent, value)
                    if not _is_within(resolved, web_root):
                        record(path, resolved, f"compilerOptions.{field} entry escapes the web trust domain")
            plugins = compiler.get("plugins", [])
            if plugins not in (None, []):
                record(
                    path,
                    "<unverified-typescript-plugin>",
                    "TypeScript compiler plugins require an architecture-checker policy before use",
                )

        for field in ("files", "include"):
            values = config.get(field, [])
            if values is None:
                continue
            if not isinstance(values, list):
                record(path, f"<invalid-{field}>", f"TypeScript {field} must be an array")
                continue
            for value in values:
                if not isinstance(value, str):
                    record(path, f"<invalid-{field}-entry>", f"TypeScript {field} entries must be strings")
                    continue
                if "${" in value:
                    record(path, f"<dynamic-{field}-entry>", f"dynamic TypeScript {field} entries are not permitted")
                    continue
                resolved = resolve_pattern(path.parent, value)
                if not _is_within(resolved, web_root):
                    record(path, resolved, f"TypeScript {field} entry escapes the web trust domain")
        references = config.get("references", [])
        if references is None:
            references = []
        if not isinstance(references, list):
            record(path, "<invalid-references>", "TypeScript references must be an array")
        else:
            for reference in references:
                if not isinstance(reference, dict) or not isinstance(reference.get("path"), str):
                    record(path, "<invalid-reference>", "TypeScript references require string paths")
                    continue
                if "${" in reference["path"]:
                    record(path, "<dynamic-reference>", "dynamic TypeScript project references are not permitted")
                    continue
                resolved = resolve_pattern(path.parent, reference["path"])
                if not _is_within(resolved, web_root):
                    record(path, resolved, "TypeScript project reference escapes the web trust domain")
        active.remove(path)
        validated.add(path)

    for path in files:
        if (
            path.name.startswith(("tsconfig", "jsconfig"))
            and path.suffix == ".json"
            and _is_within(path.resolve(), web_root)
        ):
            validate(path)

    config_prefixes = (
        "next.config.",
        "webpack.config.",
        "vite.config.",
        "vitest.config.",
        "rollup.config.",
        "rspack.config.",
        "babel.config.",
        "jest.config.",
        ".babelrc.",
    )
    alias_tokens = {
        "alias",
        "resolve",
        "resolveAlias",
        "moduleNameMapper",
        "module-resolver",
        "turbopack",
        "webpack",
    }
    for path in files:
        if not _is_within(path.resolve(), web_root) or not path.name.startswith(config_prefixes):
            continue
        if path.suffix not in WEB_EXTENSIONS:
            continue
        try:
            tokens = _lex_source(path.read_text(encoding="utf-8"), "web")
        except (OSError, UnicodeDecodeError):
            continue
        if any(token.value in alias_tokens for token in tokens):
            record(
                path,
                "<unverified-bundler-alias>",
                "bundler/test aliases are forbidden; use a web-contained tsconfig/jsconfig mapping",
            )
    return sorted(
        violations,
        key=lambda item: (str(item["source_file"]), str(item["target"]), str(item["explanation"])),
    )


def _web_sites(root: Path, files: Iterable[Path]) -> tuple[list[ImportSite], list[dict[str, object]]]:
    web_root = (root / "web").resolve(strict=False)
    module_path = next(
        (item.import_path for item in _discover_modules(files) if item.directory == root.resolve()),
        "",
    )
    sites: set[ImportSite] = set()
    violations: list[dict[str, object]] = _web_config_violations(root, files)
    for path in files:
        if path.suffix not in WEB_EXTENSIONS or not _is_within(path.resolve(), web_root):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        imports, dynamic_imports = _web_imports(content)
        source_rel = _relative(root, path.parent)
        for operation, line, _offset in dynamic_imports:
            violations.append(
                {
                    "direct": True,
                    "explanation": (
                        "web dynamic module resolution is forbidden because its trust-domain target "
                        "cannot be proven statically"
                    ),
                    "path": [source_rel, "<dynamic-module>"],
                    "rule": "web-presentation-boundary",
                    "source": source_rel,
                    "source_file": _relative(root, path),
                    "line": line,
                    "target": f"<{operation}-dynamic>",
                }
            )
        for specifier, line, _offset in imports:
            # TypeScript/bundlers normalize backslashes in path-like module
            # specifiers. Use the conservative normalized value for boundary
            # classification on every host.
            specifier = specifier.replace("\\", "/")
            if specifier.startswith("."):
                target = _resolve_web_relative(path, specifier)
                if not _is_within(target, web_root):
                    target_label = (
                        _relative(root, target)
                        if _is_within(target, root.resolve())
                        else "<outside-repository>"
                    )
                    violations.append(
                        {
                            "direct": True,
                            "explanation": "web relative import escapes the web trust domain",
                            "path": [source_rel, target_label],
                            "rule": "web-presentation-boundary",
                            "source": source_rel,
                            "source_file": _relative(root, path),
                            "line": line,
                            "target": target_label,
                        }
                    )
                    continue
                target_rel = _relative(root, target if target.is_dir() else target.parent)
                sites.add(ImportSite(source_rel, target_rel, _relative(root, path), line, "web"))
                continue
            forbidden_bare = _has_prefix(specifier, ("cmd", "contracts", "internal")) or (
                module_path and (specifier == module_path or specifier.startswith(module_path + "/"))
            )
            if forbidden_bare:
                violations.append(
                    {
                        "direct": True,
                        "explanation": "web may consume only its generated TypeScript contracts, never Go/domain source",
                        "path": [source_rel, specifier],
                        "rule": "web-presentation-boundary",
                        "source": source_rel,
                        "source_file": _relative(root, path),
                        "line": line,
                        "target": specifier,
                    }
                )
    return (
        sorted(sites, key=lambda item: (item.source, item.target, item.source_file, item.line)),
        sorted(violations, key=lambda item: (str(item["source"]), str(item["target"]), int(item["line"]))),
    )


def _shortest_paths(graph: dict[str, set[str]], start: str) -> dict[str, list[str]]:
    queue: deque[list[str]] = deque([[start]])
    visited = {start}
    paths: dict[str, list[str]] = {}
    while queue:
        path = queue.popleft()
        for target in sorted(graph.get(path[-1], set())):
            if target in visited:
                continue
            candidate = [*path, target]
            visited.add(target)
            paths[target] = candidate
            queue.append(candidate)
    return paths


def _boundary_violations(sites: list[ImportSite]) -> list[dict[str, object]]:
    graph: dict[str, set[str]] = {}
    site_by_edge: dict[tuple[str, str], ImportSite] = {}
    for site in sites:
        graph.setdefault(site.source, set()).add(site.target)
        site_by_edge.setdefault((site.source, site.target), site)
    nodes = sorted(set(graph) | {target for targets in graph.values() for target in targets})
    violations: list[dict[str, object]] = []
    for rule in RULES:
        for source in (node for node in nodes if rule.source_matches(node)):
            for target, path in sorted(_shortest_paths(graph, source).items()):
                if not rule.target_matches(target):
                    continue
                path_sites = [site_by_edge[(left, right)] for left, right in zip(path, path[1:])]
                first_site = path_sites[0]
                violations.append(
                    {
                        "direct": len(path) == 2,
                        "edges": [
                            {
                                "from": site.source,
                                "line": site.line,
                                "source_file": site.source_file,
                                "to": site.target,
                            }
                            for site in path_sites
                        ],
                        "explanation": rule.explanation,
                        "line": first_site.line,
                        "path": path,
                        "rule": rule.name,
                        "source": source,
                        "source_file": first_site.source_file,
                        "target": target,
                    }
                )
    return sorted(
        violations,
        key=lambda item: (str(item["rule"]), str(item["source"]), str(item["target"]), item["path"]),
    )


def check(root: Path) -> dict[str, object]:
    root = root.resolve()
    files, symlink_violations = _walk_files(root)
    modules = _discover_modules(files)
    go_sites = _go_sites(root, files, modules)
    web_sites, web_violations = _web_sites(root, files)
    sites = sorted(
        [*go_sites, *web_sites],
        key=lambda item: (item.ecosystem, item.source, item.target, item.source_file, item.line),
    )
    boundary_violations = [*_boundary_violations(go_sites), *web_violations]
    boundary_violations = sorted(
        boundary_violations,
        key=lambda item: (str(item["rule"]), str(item["source"]), str(item["target"]), item["path"]),
    )
    package_nodes = {
        package[1]
        for path in files
        if path.suffix == ".go"
        and (package := _package_for_file(root, path, modules)) is not None
    }
    package_nodes.update(
        _relative(root, path.parent)
        for path in files
        if path.suffix in WEB_EXTENSIONS
        and _is_within(path.resolve(), (root / "web").resolve(strict=False))
    )
    nodes = sorted(package_nodes | {item.source for item in sites} | {item.target for item in sites})
    graph = {
        "edges": [
            {
                "ecosystem": item.ecosystem,
                "from": item.source,
                "line": item.line,
                "source_file": item.source_file,
                "to": item.target,
            }
            for item in sites
        ],
        "modules": [
            {"directory": _relative(root, item.directory), "import_path": item.import_path}
            for item in sorted(modules, key=lambda module: (_relative(root, module.directory), module.import_path))
        ],
        "nodes": nodes,
    }
    return {
        "forbidden_edge_report": {
            "count": len(boundary_violations),
            "violations": boundary_violations,
        },
        "import_graph": graph,
        "schema_version": "1.0.0",
        "status": "pass" if not boundary_violations and not symlink_violations else "fail",
        "symlink_report": {
            "count": len(symlink_violations),
            "violations": symlink_violations,
        },
    }


def _write_json(root: Path, path: Path, payload: object) -> None:
    atomic_replace_regular(
        root,
        path,
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--graph-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    parser.add_argument("--json", action="store_true", help="print the complete deterministic report")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    report = check(root)
    try:
        if args.graph_output:
            _write_json(root, args.graph_output, report["import_graph"])
        if args.report_output:
            _write_json(
                root,
                args.report_output,
                {
                    "forbidden_edge_report": report["forbidden_edge_report"],
                    "schema_version": report["schema_version"],
                    "status": report["status"],
                    "symlink_report": report["symlink_report"],
                },
            )
    except (AtomicOutputError, OSError) as exc:
        print(f"architecture check: ERROR: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        graph = report["import_graph"]
        forbidden = report["forbidden_edge_report"]
        symlinks = report["symlink_report"]
        print(
            f"architecture check: {str(report['status']).upper()} "
            f"modules={len(graph['modules'])} nodes={len(graph['nodes'])} "
            f"edges={len(graph['edges'])} forbidden={forbidden['count']} "
            f"symlinks={symlinks['count']}"
        )
        for violation in forbidden["violations"]:
            print(
                f"ERROR {violation['rule']}: {' -> '.join(violation['path'])} "
                f"({violation['source_file']}:{violation['line']})",
                file=sys.stderr,
            )
        for violation in symlinks["violations"]:
            print(
                f"ERROR {violation['kind']}: {violation['path']} -> {violation['resolved']}",
                file=sys.stderr,
            )
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
