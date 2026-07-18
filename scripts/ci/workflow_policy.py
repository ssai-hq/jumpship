#!/usr/bin/env python3
"""Validate the P03 GitHub Actions contract without a YAML dependency.

P03 workflows deliberately use JSON syntax, which is valid YAML.  Keeping the
files in that subset lets a clean clone perform strict structural and semantic
checks with the Python standard library before repository-local tools exist.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping, Sequence


CHECKOUT_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
CACHE_SHA = "5a3ec84eff668545956fd18022155c47e93e2684"
UPLOAD_SHA = "ea165f8d65b6e75b540449e92b4886f43607fa02"

PINNED_ACTIONS = {
    "actions/checkout": CHECKOUT_SHA,
    "actions/cache": CACHE_SHA,
    "actions/upload-artifact": UPLOAD_SHA,
}

EXTERNAL_ACTION_RE = re.compile(r"\A([^/@]+/[^/@]+)@([0-9a-f]{40})\Z")
FORBIDDEN_CONTROL_PLANE_RUN_RE = re.compile(
    r"(?im)(?:^|[;&|]\s*)(?:aws|gcloud|kubectl)\s+|"
    r"\b(?:terraform|tofu)\s+apply\b|\bdocker\s+login\b"
)
SETUP_ACTION = "./.github/actions/setup-repository"

EXPECTED_WORKFLOWS: Mapping[str, Mapping[str, Any]] = {
    "ci-pr.yml": {
        "triggers": {"pull_request", "workflow_dispatch"},
        "retention": {7},
        "targets": {
            "doctor",
            "docs-check",
            "capability-check",
            "command-check",
            "packet-graph-check",
            "gen-check",
            "fmt",
            "lint",
            "architecture-check",
            "test-unit",
            "test-contracts",
            "test-security",
            "tofu-fmt-check",
            "tofu-validate",
            "tofu-policy-test",
        },
    },
    "ci-merge.yml": {
        "triggers": {"push", "schedule", "workflow_dispatch"},
        "retention": {14},
        "targets": {"verify"},
    },
    "ci-images.yml": {
        "triggers": {"pull_request", "push", "workflow_dispatch"},
        "retention": {30},
        "targets": {
            "build-images",
            "image-scan",
            "sbom",
            "image-verify-signature",
            "supply-chain-verify",
        },
    },
    "ci-infra.yml": {
        "triggers": {"workflow_dispatch"},
        "retention": {1},
        "targets": {
            "deployment-profile-validate",
            "tofu-fmt-check",
            "tofu-validate",
            "tofu-policy-test",
            "tofu-plan",
        },
    },
    "quality-evals.yml": {
        "triggers": {"push", "schedule", "workflow_dispatch"},
        "retention": {14},
        "targets": {"eval-validate", "eval-unit", "eval-sanitize", "eval-run"},
    },
    "test-browser.yml": {
        "triggers": {"pull_request", "push", "workflow_dispatch"},
        "retention": {7},
        "targets": {"web-test-e2e", "web-test-a11y", "web-test-visual"},
    },
    "test-chaos.yml": {
        "triggers": {"schedule", "workflow_dispatch"},
        "retention": {14},
        "targets": {"test-chaos"},
    },
    "release-qualify.yml": {
        "triggers": {"workflow_dispatch"},
        "retention": {30},
        "targets": {"release-qualify"},
    },
}

EXPECTED_ACTIONS = {"setup-repository/action.yml"}

FUTURE_OWNER_WORKFLOW_RE = re.compile(
    r"\A(?:platform|signer|deploy|recovery|cell|mothership)-[a-z0-9][a-z0-9-]*\.yml\Z"
)

FORBIDDEN_WORKFLOW_TEXT = (
    "pull_request_target",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "secrets.",
    "tofu-apply",
    "deploy-production",
    "smoke-production",
    "aws-actions/configure-aws-credentials",
    "curl ",
    "wget ",
)


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def load_json_document(path: Path, root: Path, errors: list[str]) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{relative(path, root)}: not strict JSON-compatible YAML: {exc}")
        return None


def iter_steps(document: Mapping[str, Any]) -> Iterable[tuple[str, Mapping[str, Any]]]:
    jobs = document.get("jobs", {})
    if not isinstance(jobs, dict):
        return
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, dict):
                yield str(job_name), step


def run_text(document: Mapping[str, Any]) -> str:
    return "\n".join(
        str(step.get("run", "")) for _, step in iter_steps(document) if "run" in step
    )


def validate_action_reference(
    uses: Any,
    location: str,
    errors: list[str],
) -> None:
    if not isinstance(uses, str):
        errors.append(f"{location}: uses must be a string")
        return
    if uses == SETUP_ACTION:
        return
    if uses.startswith("./.github/actions/"):
        errors.append(f"{location}: local action is outside the P03 allowlist: {uses}")
        return
    match = EXTERNAL_ACTION_RE.fullmatch(uses)
    if match is None:
        errors.append(f"{location}: external action is not pinned to a full commit SHA: {uses}")
        return
    action, sha = match.groups()
    expected_sha = PINNED_ACTIONS.get(action)
    if expected_sha is None:
        errors.append(f"{location}: external action is not approved by P03 policy: {action}")
    elif sha != expected_sha:
        errors.append(
            f"{location}: {action} uses unexpected SHA {sha}; expected {expected_sha}"
        )


def validate_permissions(
    permissions: Any,
    location: str,
    errors: list[str],
    *,
    allow_id_token: bool,
) -> None:
    if not isinstance(permissions, dict):
        errors.append(f"{location}: explicit least-privilege permissions are required")
        return
    allowed = {"contents"}
    if allow_id_token:
        allowed.add("id-token")
    unexpected = sorted(set(permissions) - allowed)
    if unexpected:
        errors.append(f"{location}: forbidden permission keys: {', '.join(unexpected)}")
    if permissions.get("contents") != "read":
        errors.append(f"{location}: contents permission must be read")
    if "id-token" in permissions and permissions["id-token"] != "write":
        errors.append(f"{location}: id-token must be write when explicitly enabled")


def validate_artifacts(
    name: str,
    document: Mapping[str, Any],
    expected_retention: set[int],
    errors: list[str],
) -> None:
    found = 0
    observed_retention: set[int] = set()
    for job_name, step in iter_steps(document):
        if step.get("uses") != f"actions/upload-artifact@{UPLOAD_SHA}":
            continue
        found += 1
        location = f".github/workflows/{name}:{job_name}:{step.get('name', 'artifact')}"
        if step.get("if") != "${{ always() }}":
            errors.append(f"{location}: evidence upload must run under always()")
        inputs = step.get("with")
        if not isinstance(inputs, dict):
            errors.append(f"{location}: artifact inputs are required")
            continue
        artifact_name = str(inputs.get("name", ""))
        if "${{ github.run_id }}" not in artifact_name or "${{ github.run_attempt }}" not in artifact_name:
            errors.append(f"{location}: artifact name must bind run_id and run_attempt")
        artifact_path = str(inputs.get("path", ""))
        if not artifact_path.startswith(".ci-artifacts/"):
            errors.append(f"{location}: detailed artifacts must live under .ci-artifacts/")
        if inputs.get("include-hidden-files") != "true":
            errors.append(
                f"{location}: hidden .ci-artifacts content must be included explicitly"
            )
        if inputs.get("if-no-files-found") != "error":
            errors.append(f"{location}: missing detailed artifacts must fail closed")
        try:
            retention = int(inputs.get("retention-days"))
        except (TypeError, ValueError):
            errors.append(f"{location}: retention-days must be an integer string")
        else:
            observed_retention.add(retention)

    if found == 0:
        errors.append(f".github/workflows/{name}: no retained detailed artifact upload")
    if observed_retention != expected_retention:
        errors.append(
            f".github/workflows/{name}: retention {sorted(observed_retention)} does not "
            f"match {sorted(expected_retention)}"
        )


def validate_common_workflow(
    root: Path,
    name: str,
    document: Mapping[str, Any],
    policy: Mapping[str, Any],
    errors: list[str],
) -> None:
    location = f".github/workflows/{name}"
    if not isinstance(document.get("name"), str) or not document["name"].strip():
        errors.append(f"{location}: non-empty workflow name is required")

    triggers = document.get("on")
    if not isinstance(triggers, dict):
        errors.append(f"{location}: trigger mapping is required")
    elif set(triggers) != policy["triggers"]:
        errors.append(
            f"{location}: triggers {sorted(triggers)} do not match "
            f"{sorted(policy['triggers'])}"
        )

    validate_permissions(
        document.get("permissions"), f"{location}:top-level", errors, allow_id_token=False
    )

    concurrency = document.get("concurrency")
    if not isinstance(concurrency, dict):
        errors.append(f"{location}: explicit concurrency policy is required")
    else:
        group = concurrency.get("group")
        if not isinstance(group, str) or "${{" not in group:
            errors.append(f"{location}: concurrency group must bind workflow context")
        cancel = concurrency.get("cancel-in-progress")
        if not isinstance(cancel, (bool, str)):
            errors.append(f"{location}: cancel-in-progress policy is required")

    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        errors.append(f"{location}: at least one job is required")
        return

    summary_found = False
    setup_found = False
    for job_name, job in jobs.items():
        job_location = f"{location}:{job_name}"
        if not isinstance(job, dict):
            errors.append(f"{job_location}: job must be a mapping")
            continue
        if job.get("runs-on") != "ubuntu-24.04":
            errors.append(f"{job_location}: runner must be pinned to ubuntu-24.04")
        timeout = job.get("timeout-minutes")
        if not isinstance(timeout, int) or not 1 <= timeout <= 180:
            errors.append(f"{job_location}: timeout-minutes must be between 1 and 180")
        if "permissions" in job:
            allow_id_token = name == "ci-infra.yml" and job_name == "plan"
            validate_permissions(
                job["permissions"], job_location, errors, allow_id_token=allow_id_token
            )
        steps = job.get("steps")
        if not isinstance(steps, list) or not steps:
            errors.append(f"{job_location}: non-empty steps are required")
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                errors.append(f"{job_location}:step-{index}: step must be a mapping")
                continue
            step_location = f"{job_location}:step-{index}"
            if "uses" in step:
                validate_action_reference(step["uses"], step_location, errors)
                if step["uses"] == SETUP_ACTION:
                    setup_found = True
                if step["uses"] == f"actions/checkout@{CHECKOUT_SHA}":
                    checkout_inputs = step.get("with", {})
                    if checkout_inputs.get("persist-credentials") != "false":
                        errors.append(
                            f"{step_location}: checkout must disable persisted credentials"
                        )
            if "GITHUB_STEP_SUMMARY" in str(step.get("run", "")):
                summary_found = True

    if not summary_found:
        errors.append(f"{location}: concise GITHUB_STEP_SUMMARY output is required")
    if not setup_found and name != "ci-merge.yml":
        errors.append(f"{location}: pinned setup-repository action is required")

    combined_run = run_text(document)
    if FORBIDDEN_CONTROL_PLANE_RUN_RE.search(combined_run):
        errors.append(f"{location}: workflow contains a direct cloud/apply/login command")
    if "scripts/ci/run_gate.py" not in combined_run:
        errors.append(f"{location}: stable gate runner is not used")
    for target in sorted(policy["targets"]):
        if f"--target {target}" not in combined_run:
            errors.append(f"{location}: missing stable Make mapping for {target}")

    validate_artifacts(name, document, set(policy["retention"]), errors)

    raw = json.dumps(document, sort_keys=True)
    for forbidden in FORBIDDEN_WORKFLOW_TEXT:
        if forbidden in raw:
            errors.append(f"{location}: forbidden workflow text: {forbidden}")


def validate_setup_action(root: Path, errors: list[str]) -> None:
    path = root / ".github/actions/setup-repository/action.yml"
    document = load_json_document(path, root, errors)
    if not isinstance(document, dict):
        return
    if document.get("runs", {}).get("using") != "composite":
        errors.append(f"{relative(path, root)}: action must use the composite runtime")
    steps = document.get("runs", {}).get("steps", [])
    if not isinstance(steps, list) or not steps:
        errors.append(f"{relative(path, root)}: composite steps are required")
        return
    cache_steps = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("uses") == f"actions/cache@{CACHE_SHA}"
    ]
    if len(cache_steps) != 1:
        errors.append(f"{relative(path, root)}: exactly one pinned cache action is required")
    else:
        cache_inputs = cache_steps[0].get("with", {})
        key = str(cache_inputs.get("key", ""))
        required_key_parts = (
            "${{ runner.os }}",
            "${{ runner.arch }}",
            "${{ inputs.cache-namespace }}",
            "hashFiles('tools/manifest.yaml', 'go.sum', 'pnpm-lock.yaml')",
        )
        for part in required_key_parts:
            if part not in key:
                errors.append(f"{relative(path, root)}: cache key is missing {part}")
        paths = str(cache_inputs.get("path", ""))
        if "build/tools/cache" not in paths or "build/tools/_toolchains" not in paths:
            errors.append(f"{relative(path, root)}: pinned tool caches are incomplete")

    action_raw = json.dumps(document, sort_keys=True)
    if "make bootstrap" not in action_raw:
        errors.append(f"{relative(path, root)}: checksummed bootstrap step is required")
    for index, step in enumerate(steps):
        if isinstance(step, dict) and "uses" in step:
            validate_action_reference(
                step["uses"], f"{relative(path, root)}:step-{index}", errors
            )


def validate_infra_workflow(document: Mapping[str, Any], errors: list[str]) -> None:
    location = ".github/workflows/ci-infra.yml"
    dispatch = document.get("on", {}).get("workflow_dispatch", {})
    profile = dispatch.get("inputs", {}).get("profile", {})
    if profile.get("default") != "ephemeral-nonprod":
        errors.append(f"{location}: cloud default must be ephemeral-nonprod")
    if profile.get("options") != ["ephemeral-nonprod", "persistent-nonprod"]:
        errors.append(f"{location}: cloud choices must be the closed non-production profiles")

    jobs = document.get("jobs", {})
    guard = jobs.get("profile-gate", {})
    plan = jobs.get("plan", {})
    if guard.get("permissions") != {"contents": "read"}:
        errors.append(f"{location}: selector guard must not receive an OIDC token")
    if plan.get("needs") != ["profile-gate"]:
        errors.append(f"{location}: OIDC plan job must depend on selector validation")
    if plan.get("permissions") != {"contents": "read", "id-token": "write"}:
        errors.append(f"{location}: downstream plan must use exact OIDC permissions")
    if plan.get("environment") != "nonprod-plan":
        errors.append(f"{location}: OIDC plan must bind the nonprod-plan environment")
    required_plan_if = (
        "${{ github.event_name == 'workflow_dispatch' && "
        "github.ref == 'refs/heads/main' }}"
    )
    if plan.get("if") != required_plan_if:
        errors.append(f"{location}: OIDC plan must be manual and main-branch-only")
    guard_run = run_text({"jobs": {"profile-gate": guard}})
    if "profile_guard.py" not in guard_run or "--mode cloud" not in guard_run:
        errors.append(f"{location}: guard must enforce cloud profile mode")
    if "--require-main-ref" not in guard_run:
        errors.append(f"{location}: selector guard must reject non-main dispatches")
    plan_run = run_text({"jobs": {"plan": plan}})
    required_plan_variables = (
        "ENV=nonprod",
        "ROOT=control-plane",
        "PROFILE=$VALIDATED_PROFILE",
    )
    for value in required_plan_variables:
        if value not in plan_run:
            errors.append(f"{location}: infrastructure Make handoff is missing {value}")


def validate_release_workflow(document: Mapping[str, Any], errors: list[str]) -> None:
    location = ".github/workflows/release-qualify.yml"
    dispatch = document.get("on", {}).get("workflow_dispatch", {})
    inputs = dispatch.get("inputs", {})
    profile = inputs.get("profile", {})
    digest = inputs.get("release_digest", {})
    if profile.get("default") != "paid-production" or profile.get("options") != [
        "paid-production"
    ]:
        errors.append(f"{location}: release profile must be fixed to paid-production")
    if digest.get("required") is not True:
        errors.append(f"{location}: immutable release digest is required")

    jobs = document.get("jobs", {})
    gate = jobs.get("release-input-gate", {})
    qualify = jobs.get("qualify", {})
    if gate.get("permissions") != {"contents": "read"}:
        errors.append(f"{location}: release input gate must not receive OIDC")
    if "release-input-gate" not in qualify.get("needs", []):
        errors.append(f"{location}: qualification must depend on release input validation")
    if qualify.get("environment") != "production-qualification":
        errors.append(
            f"{location}: qualification must bind the production-qualification environment"
        )
    required_qualify_if = (
        "${{ github.event_name == 'workflow_dispatch' && "
        "github.ref == 'refs/heads/main' }}"
    )
    if qualify.get("if") != required_qualify_if:
        errors.append(f"{location}: production qualification must be manual and main-branch-only")
    gate_run = run_text({"jobs": {"release-input-gate": gate}})
    if "--mode release" not in gate_run or "--release-digest" not in gate_run:
        errors.append(f"{location}: exact profile and digest guard is required")
    if "--require-main-ref" not in gate_run:
        errors.append(f"{location}: release input guard must reject non-main dispatches")
    qualify_run = run_text({"jobs": {"qualify": qualify}})
    required = (
        "ENV=production",
        "PROFILE=$VALIDATED_PROFILE",
        "RELEASE_DIGEST=$VALIDATED_DIGEST",
    )
    for value in required:
        if value not in qualify_run:
            errors.append(f"{location}: release Make handoff is missing {value}")


def validate_clean_clone(document: Mapping[str, Any], errors: list[str]) -> None:
    run = run_text(document)
    required = (
        "git switch -C main \"$GITHUB_SHA\"",
        "PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/clean_clone_rehearsal.py --machine",
        "--output .ci-artifacts/clean-clone/report.json",
    )
    for fragment in required:
        if fragment not in run:
            errors.append(f".github/workflows/ci-merge.yml: clean-clone missing {fragment}")


def validate_pr_workflow(
    root: Path, document: Mapping[str, Any], errors: list[str]
) -> None:
    location = ".github/workflows/ci-pr.yml"
    runs = [str(step.get("run", "")) for _, step in iter_steps(document)]
    repository_runs = [
        run for run in runs if ".ci-artifacts/pr-fast/repository" in run
    ]
    policy_runs = [
        run for run in runs if ".ci-artifacts/pr-fast/infra-policy" in run
    ]
    if len(repository_runs) != 1:
        errors.append(f"{location}: exactly one repository fast-gate invocation is required")
    if len(policy_runs) != 1:
        errors.append(f"{location}: exactly one P09 policy-gate invocation is required")
    elif "--allow-planned" not in policy_runs[0] or "--owner P09" not in policy_runs[0]:
        errors.append(f"{location}: P09 policy gates must remain explicit planned handoffs")

    secret_scan = root / "scripts" / "ci" / "secret_scan.py"
    if not secret_scan.is_file():
        errors.append(f"{location}: repository secret scanner is missing")
    packet_fragment = root / "mk" / "packets" / "P03.mk"
    try:
        packet_text = packet_fragment.read_text(encoding="utf-8")
    except OSError:
        errors.append(f"{location}: P03 Make hook is unavailable")
    else:
        if "python3 ./scripts/ci/secret_scan.py" not in packet_text:
            errors.append(f"{location}: P03 test-security hook must run the secret scanner")
    if len(repository_runs) == 1 and "--target test-security" not in repository_runs[0]:
        errors.append(f"{location}: PR fast gate must include the secret-scanning security hook")


def validate_image_workflow(document: Mapping[str, Any], errors: list[str]) -> None:
    location = ".github/workflows/ci-images.yml"
    triggers = document.get("on", {})
    for trigger in ("pull_request", "push"):
        configuration = triggers.get(trigger, {})
        if not isinstance(configuration, dict):
            errors.append(f"{location}: {trigger} configuration must be a mapping")
            continue
        if "paths" in configuration or "paths-ignore" in configuration:
            errors.append(
                f"{location}: {trigger} must not filter repository image inputs"
            )


def check(root: Path) -> list[str]:
    errors: list[str] = []
    workflows_dir = root / ".github/workflows"
    workflow_paths = sorted(workflows_dir.glob("*.yml")) if workflows_dir.is_dir() else []
    observed_workflows = {path.name for path in workflow_paths}
    expected_workflows = set(EXPECTED_WORKFLOWS)
    for missing in sorted(expected_workflows - observed_workflows):
        errors.append(f".github/workflows/{missing}: required workflow is missing")
    for unexpected in sorted(observed_workflows - expected_workflows):
        if FUTURE_OWNER_WORKFLOW_RE.fullmatch(unexpected) is None:
            errors.append(f".github/workflows/{unexpected}: workflow is outside P03 inventory")
    yaml_aliases = sorted(workflows_dir.glob("*.yaml")) if workflows_dir.is_dir() else []
    for path in yaml_aliases:
        errors.append(f"{relative(path, root)}: use the governed .yml inventory")

    documents: dict[str, Mapping[str, Any]] = {}
    for name, policy in EXPECTED_WORKFLOWS.items():
        path = workflows_dir / name
        if not path.is_file():
            continue
        document = load_json_document(path, root, errors)
        if not isinstance(document, dict):
            continue
        documents[name] = document
        validate_common_workflow(root, name, document, policy, errors)

    actions_root = root / ".github/actions"
    observed_actions = {
        path.relative_to(actions_root).as_posix()
        for path in actions_root.glob("*/action.yml")
    } if actions_root.is_dir() else set()
    for missing in sorted(EXPECTED_ACTIONS - observed_actions):
        errors.append(f".github/actions/{missing}: required local action is missing")
    for unexpected in sorted(observed_actions - EXPECTED_ACTIONS):
        errors.append(f".github/actions/{unexpected}: action is outside P03 inventory")
    validate_setup_action(root, errors)

    if "ci-infra.yml" in documents:
        validate_infra_workflow(documents["ci-infra.yml"], errors)
    if "release-qualify.yml" in documents:
        validate_release_workflow(documents["release-qualify.yml"], errors)
    if "ci-merge.yml" in documents:
        validate_clean_clone(documents["ci-merge.yml"], errors)
    if "ci-pr.yml" in documents:
        validate_pr_workflow(root, documents["ci-pr.yml"], errors)
    if "ci-images.yml" in documents:
        validate_image_workflow(documents["ci-images.yml"], errors)
    return sorted(set(errors))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate governed P03 workflows.")
    parser.add_argument("command", choices=("check",))
    parser.add_argument(
        "--root", type=Path, default=repository_root(), help="Repository root"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    errors = check(root)
    if errors:
        for error in errors:
            print(f"workflow policy: ERROR: {error}", file=sys.stderr)
        return 1
    print(
        "workflow policy: ok "
        f"({len(EXPECTED_WORKFLOWS)} workflows, {len(EXPECTED_ACTIONS)} local action)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
