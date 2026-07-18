#!/usr/bin/env python3
"""Run stable Make gates while representing not-yet-owned gates honestly."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping, Sequence


TARGET_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]*\Z")
MAKE_VAR_RE = re.compile(r"\A[A-Z][A-Z0-9_]*=[A-Za-z0-9._:/+@-]+\Z")
MAKE_VARIABLE_POLICIES = {
    "ENV": re.compile(r"\A(?:nonprod|production)\Z"),
    "PHASE": re.compile(r"\A(?:cdc|cutover)\Z"),
    "PROFILE": re.compile(
        r"\A(?:local|ephemeral-nonprod|persistent-nonprod|paid-production)\Z"
    ),
    "RELEASE_DIGEST": re.compile(r"\Asha256:[0-9a-f]{64}\Z"),
    "ROOT": re.compile(r"\Acontrol-plane\Z"),
    "SUITE": re.compile(r"\Amvp\Z"),
}
URL_RE = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mongodb(?:\+srv)?)://[^\s\"'<>]+")
AWS_RESOURCE_RE = re.compile(r"\barn:aws(?:-[a-z0-9-]+)?:[^\s\"']+")
AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
PROVIDER_TOKEN_RE = re.compile(
    r"\b(?:github_pat_[A-Za-z0-9_]{30,}|gh[oprsu]_[A-Za-z0-9]{30,}|"
    r"xox[baprs]-[A-Za-z0-9-]{20,}|npm_[A-Za-z0-9]{30,})\b"
)
CLOUD_ENDPOINT_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:amazonaws\.com(?:\.cn)?|awsapps\.com|cloudfront\.net|"
    r"googleapis\.com|cloudfunctions\.net|run\.app|"
    r"azurewebsites\.net|database\.windows\.net|blob\.core\.windows\.net|"
    r"vault\.azure\.net|vercel\.app)\b(?::[0-9]{1,5})?"
)
IPV4_RE = re.compile(
    r"(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9])"
)
HEADER_SECRET_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie)\b"
    r"(\s*[:=]\s*)([^\r\n]+)"
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])"
    r"(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
    r"AWS_SHARED_CREDENTIALS_FILE|AWS_WEB_IDENTITY_TOKEN_FILE|AWS_ROLE_ARN|"
    r"GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|"
    r"(?:[A-Za-z0-9]+[_-])*(?:dsn|pass(?:word|wd)?|pwd|secret|token|"
    r"api[_-]?key|access[_-]?key|private[_-]?key))"
    r"(?![A-Za-z0-9_])"
    r"(\s*[:=]\s*)([^\r\n]*)"
)
ENDPOINT_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])"
    r"((?:[A-Za-z0-9]+[_-])*(?:host|hostname|endpoint|uri|url|addr|address))"
    r"(?![A-Za-z0-9_])"
    r"(\s*[:=]\s*)([^\r\n]*)"
)


class GateRunnerError(RuntimeError):
    """A canonical gate input or lifecycle source is unavailable or invalid."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def artifact_directory(root: Path, requested: str) -> Path:
    relative = Path(requested)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("artifact directory must be a repository-relative path")
    if not relative.parts or relative.parts[0] != ".ci-artifacts":
        raise ValueError("artifact directory must be rooted under .ci-artifacts/")
    resolved = (root / relative).resolve()
    if root.resolve() not in resolved.parents:
        raise ValueError("artifact directory escapes the repository")
    return resolved


def make_variable_is_allowed(value: str) -> bool:
    """Accept only the closed, non-secret selectors used by governed workflows."""

    if MAKE_VAR_RE.fullmatch(value) is None:
        return False
    name, raw_value = value.split("=", 1)
    policy = MAKE_VARIABLE_POLICIES.get(name)
    return policy is not None and policy.fullmatch(raw_value) is not None


def load_runtime_inventory(root: Path) -> Mapping[str, Any]:
    """Load the canonical live Make inventory without trusting the static catalog."""

    try:
        completed = subprocess.run(
            [str(root / "scripts" / "packets" / "check"), "inventory"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateRunnerError("canonical packet runtime inventory could not execute") from exc
    if completed.returncode != 0:
        raise GateRunnerError("canonical packet runtime inventory rejected the repository")
    try:
        inventory = json.loads(completed.stdout)
        if inventory.get("kind") != "jumpship-mvp-packet-runtime-inventory":
            raise GateRunnerError("canonical packet runtime inventory has the wrong kind")
        commands = inventory["commands"]
        if not all(
            isinstance(commands.get(key), list)
            for key in ("targets", "selectors", "internal_targets")
        ):
            raise GateRunnerError("canonical packet runtime inventory is malformed")
    except (AttributeError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise GateRunnerError("canonical packet runtime inventory is malformed") from exc
    return inventory


def expected_inactive_coverage(
    inventory: Mapping[str, Any], target: str, make_variables: Sequence[str]
) -> frozenset[str]:
    """Resolve inactive direct or exact selected-dispatcher coverage."""

    commands = inventory["commands"]
    targets = commands["targets"]
    selectors = commands["selectors"]
    internal_targets = commands["internal_targets"]
    target_matches = [
        item
        for item in targets
        if isinstance(item, dict) and item.get("name") == target
    ]
    if len(target_matches) != 1:
        raise GateRunnerError(f"target {target!r} is not uniquely declared")
    target_record = target_matches[0]
    lifecycle = target_record.get("lifecycle")
    if lifecycle not in {"planned", "present", "active"}:
        raise GateRunnerError(f"target {target!r} has an invalid runtime lifecycle")
    if lifecycle != "active":
        return frozenset({f"{target}={lifecycle}"})

    assignments = dict(value.split("=", 1) for value in make_variables)
    matches = [
        selector
        for selector in selectors
        if isinstance(selector, dict)
        and selector.get("target") == target
        and assignments.get(str(selector.get("key"))) == selector.get("value")
    ]
    if not matches:
        return frozenset()
    if len(matches) != 1:
        raise GateRunnerError(f"target {target!r} has ambiguous selected coverage")
    selector = matches[0]
    hook_refs = selector.get("hook_refs", [])
    if not isinstance(hook_refs, list):
        raise GateRunnerError(f"target {target!r} has malformed hook references")
    references = set(hook_refs)
    candidates = [
        item
        for item in internal_targets
        if isinstance(item, dict)
        and item.get("dispatcher") == target
        and (
            item.get("target") in references
            if references
            else item.get("selector_key") == selector.get("key")
            and item.get("selector") == selector.get("value")
        )
    ]
    if not candidates:
        return frozenset()
    inactive: set[str] = set()
    for item in candidates:
        item_target = item.get("target")
        item_lifecycle = item.get("lifecycle")
        if not isinstance(item_target, str) or item_lifecycle not in {
            "planned",
            "present",
            "active",
        }:
            raise GateRunnerError(f"target {target!r} has malformed selected coverage")
        if item_lifecycle != "active":
            inactive.add(f"{item_target}={item_lifecycle}")
    return frozenset(inactive)


def append_summary(
    title: str,
    owner: str,
    overall: str,
    results: Sequence[dict[str, object]],
) -> None:
    destination = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not destination:
        return
    with open(destination, "a", encoding="utf-8") as summary:
        summary.write(f"### {title}\n\n")
        summary.write(f"- Qualification status: `{overall}`\n")
        summary.write(f"- Continuation owner: `{owner}`\n")
        summary.write("- Target results:\n")
        for result in results:
            summary.write(f"  - `{result['target']}`: `{result['status']}`\n")
        summary.write("\n")


def redact_line(line: str, root: Path) -> str:
    """Remove endpoint, cloud-resource, path, and credential data before retention."""

    redacted = line
    replacements = (
        (str(root.resolve()), "<repo>"),
        (str(Path.home()), "<home>"),
        (os.environ.get("HOME", ""), "<home>"),
    )
    for value, marker in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        if value:
            redacted = redacted.replace(value, marker)
    redacted = URL_RE.sub("<redacted-url>", redacted)
    redacted = AWS_RESOURCE_RE.sub("<redacted-cloud-resource>", redacted)
    redacted = AWS_ACCESS_KEY_RE.sub("<redacted-access-key>", redacted)
    redacted = JWT_RE.sub("<redacted-token>", redacted)
    redacted = PROVIDER_TOKEN_RE.sub("<redacted-token>", redacted)
    redacted = CLOUD_ENDPOINT_RE.sub("<redacted-cloud-endpoint>", redacted)
    redacted = IPV4_RE.sub("<redacted-ip-address>", redacted)
    redacted = HEADER_SECRET_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted>", redacted
    )
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted>", redacted
    )
    return ENDPOINT_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted-endpoint>", redacted
    )


def run_target(
    root: Path,
    target: str,
    make_variables: Sequence[str],
    log,
) -> tuple[int, str]:
    command = ["make", "--no-print-directory", target, *make_variables]
    display = " ".join(command)
    print(f"$ {display}")
    log.write(f"$ {display}\n")
    log.flush()

    process = subprocess.Popen(
        command,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert process.stdout is not None
    digest = hashlib.sha256()
    for line in process.stdout:
        safe_line = redact_line(line, root)
        digest.update(safe_line.encode("utf-8", errors="replace"))
        sys.stdout.write(safe_line)
        log.write(safe_line)
    return process.wait(), digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run active Make gates and retain explicit planned status."
    )
    parser.add_argument("--title", required=True)
    parser.add_argument("--owner", required=True, help="Packet that owns absent targets")
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--target", action="append", required=True)
    parser.add_argument("--make-var", action="append", default=[])
    parser.add_argument(
        "--allow-planned",
        action="store_true",
        help="Represent undefined later-owner targets as planned, not passed",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = repository_root()

    invalid_targets = [target for target in args.target if not TARGET_RE.fullmatch(target)]
    invalid_variables = [value for value in args.make_var if not make_variable_is_allowed(value)]
    if invalid_targets or invalid_variables:
        print("gate runner: DENY: invalid target or Make variable", file=sys.stderr)
        return 2

    try:
        output_directory = artifact_directory(root, args.artifact_dir)
    except ValueError as exc:
        print(f"gate runner: DENY: {exc}", file=sys.stderr)
        return 2
    output_directory.mkdir(parents=True, exist_ok=True)

    try:
        runtime_inventory = load_runtime_inventory(root)
    except GateRunnerError as exc:
        print(f"gate runner: DENY: {exc}", file=sys.stderr)
        return 2

    results: list[dict[str, object]] = []
    failed = False
    planned = False
    log_path = output_directory / "gate.log"
    with log_path.open("w", encoding="utf-8") as log:
        for target in args.target:
            try:
                expected_inactive = expected_inactive_coverage(
                    runtime_inventory, target, args.make_var
                )
            except GateRunnerError as exc:
                failed = True
                results.append(
                    {
                        "target": target,
                        "status": "failed",
                        "reason": str(exc),
                    }
                )
                log.write(f"DENY {target}: {exc}\n")
                break
            if expected_inactive:
                planned = True
                results.append(
                    {
                        "target": target,
                        "status": "planned-not-evaluated",
                        "owner": args.owner,
                        "inactive_coverage": sorted(expected_inactive),
                    }
                )
                log.write(
                    f"PLANNED {target}: canonical runtime lifecycle is inactive; "
                    f"continuation owner is {args.owner}\n"
                )
                continue
            exit_code, redacted_stdout_sha256 = run_target(
                root, target, args.make_var, log
            )
            status = "passed" if exit_code == 0 else "failed"
            results.append(
                {
                    "target": target,
                    "status": status,
                    "exit_code": exit_code,
                    "redacted_stdout_sha256": redacted_stdout_sha256,
                }
            )
            if exit_code != 0:
                failed = True
                break

    if planned and not args.allow_planned:
        failed = True
        results.append(
            {
                "target": "workflow-policy",
                "status": "failed",
                "reason": "undefined target without --allow-planned",
            }
        )

    overall = (
        "failed"
        if failed
        else "planned-not-evaluated"
        if planned
        else "passed"
    )
    payload = {
        "schema_version": "1.0.0",
        "title": args.title,
        "owner": args.owner,
        "qualification_status": overall,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "make_variables": args.make_var,
        "results": results,
    }
    (output_directory / "result.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    append_summary(args.title, args.owner, overall, results)
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
