"""Security vulnerability and best practice checks for GitHub Actions workflows."""
from typing import List, Dict, Any, Optional
import re
import shlex
import subprocess
import tempfile
import json
import os
import base64
from github_client import GitHubClient
import sys
from pathlib import Path

# Add parent directory to path to import config_loader
sys.path.insert(0, str(Path(__file__).parent.parent))
from config_loader import get_trusted_publishers

# Security vulnerability and best practice checks


def _on_events(workflow: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize the ``on:`` block to ``{event_name: config_dict}``.

    ``on`` may be a string (``on: push``), a list (``on: [push, pull_request]``)
    or a mapping whose values can be ``None`` (``workflow_call:`` with no body).
    Every trigger-aware check goes through this so none of them crash on, or
    silently ignore, the shorter forms.
    """
    on = workflow.get("on") if isinstance(workflow, dict) else None
    if isinstance(on, str):
        return {on: {}}
    if isinstance(on, list):
        return {str(e): {} for e in on if isinstance(e, (str, int))}
    if isinstance(on, dict):
        return {str(k): (v if isinstance(v, dict) else {}) for k, v in on.items()}
    return {}


def _event_inputs(workflow: Dict[str, Any], event: str) -> Dict[str, Any]:
    """Return the ``inputs`` mapping of workflow_dispatch / workflow_call (never None)."""
    inputs = _on_events(workflow).get(event, {}).get("inputs")
    return inputs if isinstance(inputs, dict) else {}


def _runner_labels(runs_on: Any) -> List[str]:
    """Flatten ``runs-on`` (string, list, or ``{group, labels}`` mapping) to lowercase labels."""
    if isinstance(runs_on, str):
        return [runs_on.lower()]
    if isinstance(runs_on, list):
        return [str(r).lower() for r in runs_on]
    if isinstance(runs_on, dict):
        labels = runs_on.get("labels", [])
        labels = [labels] if isinstance(labels, str) else (labels if isinstance(labels, list) else [])
        group = runs_on.get("group")
        return [str(label).lower() for label in labels] + ([f"group:{str(group).lower()}"] if group else [])
    return []


def _is_self_hosted(runs_on: Any) -> bool:
    """A job is self-hosted if it asks for the ``self-hosted`` label or a runner group.

    Runner groups (``runs-on: {group: ...}``) only contain self-hosted or larger
    runners, so they carry the same exposure as an explicit self-hosted label.
    """
    return any("self-hosted" in label or label.startswith("group:") for label in _runner_labels(runs_on))


def _effective_permissions(workflow: Dict[str, Any], job: Dict[str, Any]) -> Any:
    """Job-level ``permissions`` replace workflow-level ones entirely when present."""
    if isinstance(job, dict) and "permissions" in job:
        return job.get("permissions")
    return workflow.get("permissions")


# Actions that upload SARIF to code scanning, which requires security-events: write.
_SARIF_UPLOADERS = ("github/codeql-action/", "0xcardinal/actsense@")


def _justified_write_scopes(job: Dict[str, Any]) -> set:
    """Write scopes a job's own steps demonstrably need."""
    scopes = set()
    steps = job.get("steps") if isinstance(job, dict) else None
    for step in steps if isinstance(steps, list) else []:
        uses = step.get("uses") if isinstance(step, dict) else None
        if isinstance(uses, str) and uses.strip().lower().startswith(_SARIF_UPLOADERS):
            scopes.add("security-events")
    return scopes


def _unjustified_writes(permissions: Any, job: Dict[str, Any]) -> bool:
    if permissions == "write-all":
        return True
    if not isinstance(permissions, dict):
        return False
    justified = _justified_write_scopes(job)
    return any(v == "write" and k not in justified for k, v in permissions.items())


def _is_truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in ("true", "1", "yes", "on"))


def check_secrets_in_workflow(workflow: Dict[str, Any], content: Optional[str] = None) -> List[Dict[str, Any]]:
    """Check for potential secret exposure issues and long-term credentials."""
    issues = []

    def check_value(value, path=""):
        if isinstance(value, str):
            # Check for hardcoded secrets patterns in string values
            if re.search(r'(password|secret|token|key|api[_-]?key)\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}', value, re.IGNORECASE):
                issues.append({
                    "type": "potential_hardcoded_secret",
                    "severity": "critical",
                    "message": f"Potential hardcoded secret found at {path}. This is a critical security vulnerability that could expose sensitive credentials.",
                    "path": path,
                    "evidence": {
                        "location": path,
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/potential_hardcoded_secret"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/potential_hardcoded_secret"
                })
            # Also check if the value itself looks like a secret: a long token under a
            # secret-looking key that mixes letters and digits. Requiring both keeps
            # human-readable values such as a cache key
            # ("linux-node-modules-build-cache") from being reported as credentials.
            elif (
                len(value) >= 20
                and re.match(r'^[a-zA-Z0-9_\-]{20,}$', value)
                and re.search(r'[0-9]', value)
                and re.search(r'[a-zA-Z]', value)
                and path
                and re.search(r'(password|secret|token|api[_-]?key|(^|[._-])key$)', path, re.IGNORECASE)
            ):
                issues.append({
                    "type": "potential_hardcoded_secret",
                    "severity": "critical",
                    "message": f"Potential hardcoded secret found at {path}. This is a critical security vulnerability that could expose sensitive credentials.",
                    "path": path,
                    "evidence": {
                        "location": path,
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/potential_hardcoded_secret"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/potential_hardcoded_secret"
                })
        elif isinstance(value, dict):
            for k, v in value.items():
                check_value(v, f"{path}.{k}" if path else k)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                check_value(item, f"{path}[{i}]" if path else f"[{i}]")

    check_value(workflow)

    # Run TruffleHog if content is available
    if content:
        trufflehog_issues = _run_trufflehog(content)
        issues.extend(trufflehog_issues)

    # Long-term cloud credentials (static keys instead of OIDC federation).
    # Only secret material counts: AZURE_CLIENT_ID / AZURE_TENANT_ID are also
    # what azure/login uses *with* OIDC, so they are not evidence of a static key.
    aws_env = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
    azure_env = ("AZURE_CLIENT_SECRET", "AZURE_CREDENTIALS")
    gcp_env = ("GCP_SA_KEY", "GOOGLE_CREDENTIALS", "GCP_CREDENTIALS", "GOOGLE_APPLICATION_CREDENTIALS")
    # Action inputs that take a static key (the OIDC variants of these actions
    # use role-to-assume / workload_identity_provider / client-id instead).
    aws_inputs = ("aws-access-key-id", "aws-secret-access-key")
    azure_inputs = ("creds", "client-secret")
    gcp_inputs = ("credentials_json", "service_account_key")

    def long_term_issue(kind: str, provider: str, job_name: str, step_name: Optional[str], where: str):
        return {
            "type": f"long_term_{kind}_credentials",
            "severity": "high",
            "message": f"Job '{job_name}' uses long-term {provider} credentials ({where}) instead of OIDC. Long-term credentials are less secure and harder to rotate.",
            "job": job_name,
            "step": step_name,
            "evidence": {
                "job": job_name,
                "step": step_name,
                "location": where,
                "credential_type": f"{provider} long-term credentials",
                "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/long_term_cloud_credentials"
            },
            "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/long_term_cloud_credentials"
        }

    def scan_env(env: Any, job_name: str, step_name: Optional[str], scope: str, reported: set):
        if not isinstance(env, dict):
            return
        for kind, provider, keys in (("aws", "AWS", aws_env), ("azure", "Azure", azure_env), ("gcp", "GCP", gcp_env)):
            hit = next((k for k in keys if k in env), None)
            if hit and (kind, step_name) not in reported:
                reported.add((kind, step_name))
                issues.append(long_term_issue(kind, provider, job_name, step_name, f"{scope} env {hit}"))

    jobs = workflow.get("jobs", {})
    jobs = jobs if isinstance(jobs, dict) else {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        reported: set = set()
        scan_env(job.get("env"), job_name, None, "job", reported)
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            step_name = step.get("name", "unnamed")
            scan_env(step.get("env"), job_name, step_name, "step", reported)

            with_params = step.get("with") if isinstance(step.get("with"), dict) else {}
            uses = str(step.get("uses", "")).lower()
            for kind, provider, keys, action_hint in (
                ("aws", "AWS", aws_inputs, "aws-actions/configure-aws-credentials"),
                ("azure", "Azure", azure_inputs, "azure/login"),
                ("gcp", "GCP", gcp_inputs, "google-github-actions/auth"),
            ):
                hit = next((k for k in keys if with_params.get(k)), None)
                if hit and action_hint in uses and (kind, step_name) not in reported:
                    reported.add((kind, step_name))
                    issues.append(long_term_issue(kind, provider, job_name, step_name, f"input '{hit}'"))

            # Hardcoded key material in run commands. Only a *literal* value is a
            # finding: `aws configure set aws_access_key_id "$KEY"` or a
            # `${{ secrets.X }}` reference is the correct way to pass a key.
            run = step.get("run", "")
            if isinstance(run, str) and (
                re.search(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b', run)
                or re.search(
                    r'(aws_access_key_id|aws_secret_access_key|azure_client_secret)["\']?\s*[=:\s]\s*["\']?(?![$"\'{])[A-Za-z0-9/+=]{16,}',
                    run, re.IGNORECASE,
                )
            ):
                issues.append({
                    "type": "potential_hardcoded_cloud_credentials",
                    "severity": "critical",
                    "message": f"Job '{job_name}' appears to contain hardcoded cloud credentials in a run command. This is a critical security vulnerability.",
                    "job": job_name,
                    "step": step_name,
                    "evidence": {
                        "job": job_name,
                        "step": step_name,
                        "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/potential_hardcoded_cloud_credentials"
                    },
                    "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/potential_hardcoded_cloud_credentials"
                })

    # Workflow-level env applies to every job.
    top_reported: set = set()
    scan_env(workflow.get("env"), "(workflow)", None, "workflow", top_reported)

    return issues


def check_self_hosted_runners(workflow: Dict[str, Any], is_public_repo: bool = False) -> List[Dict[str, Any]]:
    """Check for use of self-hosted runners and related security issues."""
    issues = []

    jobs = workflow.get("jobs", {})
    on_events = _on_events(workflow)
    is_pr_triggered = "pull_request" in on_events or "pull_request_target" in on_events
    is_issue_triggered = any(e in on_events for e in ("issues", "issue_comment", "discussion", "discussion_comment"))

    uses_self_hosted_runner = _is_self_hosted

    # Check each job for self-hosted runners
    for job_name, job in jobs.items():
        runs_on_value = job.get("runs-on", "")
        if not uses_self_hosted_runner(runs_on_value):
            continue

        # Basic self-hosted runner warning
        issues.append({
            "type": "self_hosted_runner",
            "severity": "low",
            "message": f"Job '{job_name}' uses self-hosted runner '{runs_on_value}'. Self-hosted runners can be compromised and pose security risks.",
            "job": job_name,
            "runs-on": runs_on_value,
            "evidence": {
                "job": job_name,
                "runner": runs_on_value,
                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/self_hosted_runner"
            },
            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/self_hosted_runner"
        })

        # Check for PR exposure in public repositories (CRITICAL)
        if is_pr_triggered and is_public_repo:
            issues.append({
                "type": "self_hosted_runner_pr_exposure",
                "severity": "critical",
                "message": f"Self-hosted runner in job '{job_name}' is exposed to pull requests in a public repository. This allows potential code execution from forks.",
                "job": job_name,
                "evidence": {
                    "job": job_name,
                    "runner": runs_on_value,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_pr_exposure"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_pr_exposure"
            })

        # Check for issue exposure in public repositories (HIGH)
        if is_issue_triggered and is_public_repo:
            issues.append({
                "type": "self_hosted_runner_issue_exposure",
                "severity": "high",
                "message": f"Self-hosted runner in job '{job_name}' can be triggered by issue events in a public repository, allowing potential abuse.",
                "job": job_name,
                "evidence": {
                    "job": job_name,
                    "runner": runs_on_value,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_issue_exposure"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_issue_exposure"
            })

        # Check for write-all permissions (CRITICAL)
        permissions = _effective_permissions(workflow, job)
        has_write_all = permissions == "write-all" or (
            isinstance(permissions, dict)
            and permissions.get("contents") == "write"
            and all(v == "write" for v in permissions.values())
        )

        if has_write_all:
            issues.append({
                "type": "self_hosted_runner_write_all",
                "severity": "critical",
                "message": f"Self-hosted runner in job '{job_name}' has write-all permissions, creating excessive privilege risk.",
                "job": job_name,
                "evidence": {
                    "job": job_name,
                    "runner": runs_on_value,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_write_all"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_write_all"
            })

    return issues


def check_runner_label_confusion(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for runner label confusion attacks."""
    issues = []

    jobs = workflow.get("jobs", {})

    # GitHub-hosted runner labels. The real confusion vector is a job that lists
    # `self-hosted` AND one of these hosted-style labels in the SAME runs-on set:
    # GitHub may route the job to a hosted runner, or an attacker who registers a
    # self-hosted runner advertising this label could intercept it. Generic OS
    # labels like `linux`/`windows`/`macos` are legitimate, expected self-hosted
    # labels and are intentionally NOT flagged.
    hosted_labels = {"ubuntu-latest", "windows-latest", "macos-latest"}

    for job_name, job in jobs.items():
        runs_on_value = job.get("runs-on", "")
        if not runs_on_value:
            continue

        runner_set = set(_runner_labels(runs_on_value))
        if not runner_set:
            continue

        # Only relevant when the job targets a self-hosted runner.
        if not any("self-hosted" in r for r in runner_set):
            continue

        # Flag only when a hosted-style label is mixed in alongside self-hosted.
        collisions = sorted(runner_set & hosted_labels)
        if collisions:
            issues.append({
                "type": "runner_label_confusion",
                "severity": "high",
                "message": f"Job '{job_name}' combines a self-hosted runner with GitHub-hosted runner label(s) {', '.join(collisions)} in the same runs-on. This is ambiguous and can be exploited via runner label confusion.",
                "job": job_name,
                "runner": runs_on_value,
                "evidence": {
                    "job": job_name,
                    "runner": runs_on_value,
                    "confusing_labels": collisions,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/runner_label_confusion"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/runner_label_confusion"
            })

    return issues


def check_self_hosted_runner_secrets(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for secrets management issues with self-hosted runners."""
    issues = []

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        if not _is_self_hosted(job.get("runs-on", "")):
            continue

        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str):
                # Normalize whitespace and use substring checks to avoid regex complexity on untrusted input.
                normalized_run = "".join(run.lower().split())
                has_secret_expression = "${{secrets." in normalized_run and "}}" in normalized_run
            else:
                has_secret_expression = False

            if has_secret_expression:
                issues.append({
                    "type": "self_hosted_runner_secrets_in_run",
                    "severity": "high",
                    "message": f"Self-hosted runner in job '{job_name}' uses secrets directly in run commands. Secrets may be exposed in process lists or logs.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_secrets_in_run"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_secrets_in_run"
                })

    return issues


def check_runner_environment_security(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for environment-specific security issues with self-hosted runners."""
    issues = []

    jobs = workflow.get("jobs", {})

    # Network security risk patterns
    network_risks = [
        (r'curl.*\|\s*(sudo\s+)?(ba)?sh\b', 'curl piped to shell'),
        (r'wget.*\|\s*(sudo\s+)?(ba)?sh\b', 'wget piped to shell'),
        (r'Invoke-WebRequest.*\|\s*iex', 'PowerShell download and execute'),
        (r'docker\s+run.*--privileged', 'Docker with privileged mode'),
        (r'docker\s+run.*--cap-add', 'Docker with additional capabilities'),
    ]

    for job_name, job in jobs.items():
        if not _is_self_hosted(job.get("runs-on", "")):
            continue

        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str):
                for pattern, description in network_risks:
                    if re.search(pattern, run, re.IGNORECASE):
                        issues.append({
                            "type": "self_hosted_runner_network_risk",
                            "severity": "high",
                            "message": f"Self-hosted runner in job '{job_name}' performs risky network operations: {description}. This could compromise the runner environment.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": description,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_network_risk"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_network_risk"
                        })
                        break  # Only report once per step

    return issues


def check_repository_visibility_risks(workflow: Dict[str, Any], is_public_repo: bool = False) -> List[Dict[str, Any]]:
    """Check for risks based on repository visibility with self-hosted runners."""
    issues = []

    if not is_public_repo:
        return issues  # Only check for public repositories

    jobs = workflow.get("jobs", {})
    has_self_hosted = False

    # Check if any job uses self-hosted runner
    for job in jobs.values():
        if _is_self_hosted(job.get("runs-on", "")):
            has_self_hosted = True
            break

    if not has_self_hosted:
        return issues

    # Check for secrets access
    def has_secrets_access(wf: Dict[str, Any]) -> bool:
        """Check if workflow has access to secrets."""
        jobs = wf.get("jobs", {})
        for job in jobs.values():
            steps = job.get("steps", [])
            for step in steps:
                # Check with parameters
                with_params = step.get("with", {})
                if with_params:
                    for value in with_params.values():
                        if isinstance(value, str) and "secrets." in value:
                            return True
                # Check environment variables
                env = step.get("env", {})
                if env:
                    for value in env.values():
                        if isinstance(value, str) and "secrets." in value:
                            return True
                # Check run commands
                run = step.get("run", "")
                if isinstance(run, str) and "secrets." in run:
                    return True
        return False

    if has_secrets_access(workflow):
        issues.append({
            "type": "public_repo_self_hosted_secrets",
            "severity": "critical",
            "message": "Self-hosted runner in public repository has access to secrets, creating potential exposure risk.",
            "evidence": {
                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/public_repo_self_hosted_secrets"
            },
            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/public_repo_self_hosted_secrets"
        })

    # Check for environment access
    def has_environment_access(wf: Dict[str, Any]) -> bool:
        """Check if workflow has environment access."""
        jobs = wf.get("jobs", {})
        for job in jobs.values():
            if job.get("environment"):
                return True
            steps = job.get("steps", [])
            for step in steps:
                if step.get("environment"):
                    return True
        return False

    if has_environment_access(workflow):
        issues.append({
            "type": "public_repo_self_hosted_environment",
            "severity": "high",
            "message": "Self-hosted runner in public repository has environment access, creating potential privilege escalation risk.",
            "evidence": {
                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/public_repo_self_hosted_environment"
            },
            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/public_repo_self_hosted_environment"
        })

    return issues


# Expressions that make actions/checkout fetch the pull request's own code.
_PR_HEAD_REF_MARKERS = (
    "pull_request.head",          # .sha / .ref / .repo.full_name
    "github.head_ref",
    "refs/pull/",                 # refs/pull/<n>/merge|head
    "pull_request.number",
    "github.event.number",
    "merge_commit_sha",
    "workflow_run.head_sha",
    "workflow_run.head_branch",
    "workflow_run.head_repository",
)


def _checkout_targets_untrusted_code(with_params: Dict[str, Any]) -> bool:
    """True when a checkout step's ref/repository points at PR (fork) code."""
    for key in ("ref", "repository"):
        value = str(with_params.get(key, "") or "").lower()
        if any(marker in value for marker in _PR_HEAD_REF_MARKERS):
            return True
    return False


def check_dangerous_events(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for dangerous workflow trigger events."""
    issues = []

    on_events = _on_events(workflow)
    jobs = workflow.get("jobs", {}) if isinstance(workflow.get("jobs"), dict) else {}

    # pull_request_target / workflow_run run with the base repository's secrets
    # and a read/write token. They are only exploitable when the workflow then
    # checks out and runs the untrusted PR code. A bare `actions/checkout`
    # under pull_request_target checks out the *base* commit, which is safe.
    for event in ("pull_request_target", "workflow_run"):
        if event not in on_events:
            continue
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps", []) or []:
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", ""))
                with_params = step.get("with") if isinstance(step.get("with"), dict) else {}
                if "actions/checkout" in uses and _checkout_targets_untrusted_code(with_params):
                    ref = with_params.get("ref") or with_params.get("repository")
                    # pull_request_target always runs for fork PRs. For workflow_run the
                    # checked-out head is only untrusted if the *triggering* workflow
                    # accepts fork PRs, which cannot be seen from this file alone.
                    if event == "pull_request_target":
                        severity = "critical"
                        message = f"Workflow triggered by pull_request_target checks out the pull request's code (ref: {ref}) in job '{job_name}'. Any later step that builds or runs it executes attacker-controlled code with access to secrets and a write-scoped token."
                    else:
                        severity = "high"
                        message = f"Workflow triggered by workflow_run checks out the triggering run's head (ref: {ref}) in job '{job_name}'. If the triggering workflow runs on pull requests from forks, this executes untrusted code with this workflow's secrets and token."
                    issues.append({
                        "type": "insecure_pull_request_target",
                        "severity": severity,
                        "message": message,
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "event": event,
                        "evidence": {
                            "event": event,
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "checkout_ref": str(ref),
                            "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/insecure_pull_request_target"
                        },
                        "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/insecure_pull_request_target"
                    })

    if "pull_request_target" in on_events and not any(
        i.get("event") == "pull_request_target" and i["type"] == "insecure_pull_request_target" for i in issues
    ):
        issues.append({
            "type": "dangerous_event",
            "severity": "high",
            "message": "Workflow uses the pull_request_target event, which runs with the base repository's secrets and a write-scoped token for pull requests from forks. It is safe only as long as no step checks out or executes the PR's code.",
            "event": "pull_request_target",
            "evidence": {
                "event": "pull_request_target",
                "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/dangerous_event"
            },
            "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/dangerous_event"
        })

    if "workflow_run" in on_events and not any(i.get("event") == "workflow_run" for i in issues):
        issues.append({
            "type": "dangerous_event",
            "severity": "medium",
            "message": "Workflow uses the workflow_run event, which runs privileged after a (possibly fork-triggered) workflow. Artifacts and outputs from the triggering run must be treated as untrusted.",
            "event": "workflow_run",
            "evidence": {
                "event": "workflow_run",
                "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/dangerous_event"
            },
            "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/dangerous_event"
        })

    # Optional free-form inputs on a reusable workflow are a hygiene concern, not
    # an exploit on their own: callers are workflows in repositories that chose
    # to call this one. The injection sink itself is reported separately.
    for input_name, input_def in _event_inputs(workflow, "workflow_call").items():
        if isinstance(input_def, dict) and input_def.get("type") == "string" and not input_def.get("required", False):
            if _input_used_in_run_command(workflow, input_name):
                issues.append({
                    "type": "unvalidated_workflow_input",
                    "severity": "medium",
                    "message": f"Reusable workflow input '{input_name}' is optional, free-form, and interpolated into a shell command. Validate it before use.",
                    "input": input_name,
                    "evidence": {
                        "input": input_name,
                        "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unvalidated_workflow_input"
                    },
                    "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/unvalidated_workflow_input"
                })

    return issues


def check_checkout_actions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for unsafe checkout action usage."""
    issues = []

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        steps = job.get("steps", []) or []
        job_uploads_artifacts = any(
            isinstance(st, dict) and "upload-artifact" in str(st.get("uses", "")).lower()
            for st in steps
        )
        for step in steps:
            uses = str(step.get("uses", ""))
            if "actions/checkout" not in uses:
                continue
            with_params = step.get("with") if isinstance(step.get("with"), dict) else {}

            # actions/checkout persists the token into .git/config by default.
            # Explicit `true` is always reported. The default is reported when
            # the same job uploads artifacts, the path by which the persisted
            # token most often leaks (e.g. uploading the workspace).
            persist = with_params.get("persist-credentials")
            explicit_true = _is_truthy(persist)
            implicit_true = persist is None and job_uploads_artifacts
            if explicit_true or implicit_true:
                issues.append({
                    "type": "unsafe_checkout",
                    "severity": "high" if explicit_true else "medium",
                    "message": (
                        f"Job '{job_name}' uses checkout with persist-credentials=true. The GITHUB_TOKEN is written to .git/config, where every later step and any uploaded artifact containing .git can read it."
                        if explicit_true else
                        f"Job '{job_name}' checks out without persist-credentials: false (the default is true) and uploads artifacts. The GITHUB_TOKEN stored in .git/config can leak through the artifact."
                    ),
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "parameter": "persist-credentials=true" if explicit_true else "persist-credentials not set (defaults to true)",
                        "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unsafe_checkout"
                    },
                    "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/unsafe_checkout"
                })

            ref = with_params.get("ref")
            if isinstance(ref, str) and "${{" in ref and not ref.startswith("refs/"):
                issues.append({
                    "type": "unsafe_checkout_ref",
                    "severity": "medium",
                    "message": f"Job '{job_name}' uses checkout with potentially unsafe ref: {ref}. The ref may be manipulated if not properly validated.",
                    "job": job_name,
                    "ref": ref,
                    "evidence": {
                        "job": job_name,
                        "ref": ref,
                        "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unsafe_checkout_ref"
                    },
                    "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/unsafe_checkout_ref"
                })

            fetch_depth = with_params.get("fetch-depth")
            if fetch_depth == 0 or (isinstance(fetch_depth, str) and fetch_depth.strip() == "0"):
                issues.append({
                    "type": "checkout_full_history",
                    "severity": "low",
                    "message": f"Job '{job_name}' fetches full git history (fetch-depth: 0). This enlarges what a compromised step or leaked workspace exposes; prefer a shallow clone unless history is required.",
                    "job": job_name,
                    "evidence": {
                        "job": job_name,
                        "fetch_depth": 0,
                        "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/checkout_full_history"
                    },
                    "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/checkout_full_history"
                })

    return issues


def check_script_injection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for potential script injection vulnerabilities with enhanced patterns."""
    issues = []

    jobs = workflow.get("jobs", {})

    # High-risk shell injection patterns (more specific)
    high_risk_patterns = [
        (r'eval.*\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body)|github\.head_ref)', 'eval with direct user input'),
        (r'(bash|sh|zsh)\s+-c\s+["\'].*\$\{\{\s*(github\.event\.(issue|pull_request|comment)|github\.head_ref)', 'Shell -c with user-controlled input'),
        (r'echo.*\$\{\{\s*(github\.event\.(issue|pull_request|comment)|github\.head_ref).*\|\s*(bash|sh|zsh)', 'Echo piping user input to shell'),
    ]

    # Medium-risk patterns
    medium_risk_patterns = [
        (r'\$\([^)]*\$\{\{\s*github\.event\.[^}]*\}\}[^)]*\)', 'Command substitution with user input'),
    ]

    # Dangerous commands fed with user input (piping into an interpreter)
    dangerous_command_patterns = [
        (r'\bcurl\b.*\|\s*(sudo\s+)?(ba|z)?sh\b', 'curl piped to bash'),
        (r'\bwget\b.*\|\s*(sudo\s+)?(ba|z)?sh\b', 'wget piped to shell'),
        (r'\becho\b.*\|\s*(sudo\s+)?(ba|z)?sh\b', 'echo piped to shell'),
        (r'\bprintf\b.*\|\s*(sudo\s+)?(ba|z)?sh\b', 'printf piped to bash'),
    ]

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str):
                # `shell: bash` already runs `bash --noprofile --norc -eo pipefail {0}`.
                # Only a custom template (`bash {0}`) can drop -e.
                shell = step.get("shell", "")
                if (
                    isinstance(shell, str)
                    and "{0}" in shell
                    and re.search(r'\bbash\b', shell)
                    and not re.search(r'\s-[a-z]*e', shell)
                    and "errexit" not in shell
                ):
                    issues.append({
                        "type": "unsafe_shell",
                        "severity": "medium",
                        "message": f"Job '{job_name}' uses bash without -e flag. Errors may not be caught, leading to unexpected behavior.",
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "evidence": {
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "shell": shell,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unsafe_shell"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unsafe_shell"
                    })

                # Check high-risk shell injection patterns
                for pattern, description in high_risk_patterns:
                    if re.search(pattern, run, re.IGNORECASE):
                        issues.append({
                            "type": "shell_injection",
                            "severity": "critical",
                            "message": f"Job '{job_name}' contains shell injection vulnerability: {description}. User input is executed directly in shell context.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": description,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/shell_injection"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/shell_injection"
                        })
                        break  # Only report once per step

                # Check medium-risk patterns
                for pattern, description in medium_risk_patterns:
                    if re.search(pattern, run, re.IGNORECASE):
                        issues.append({
                            "type": "shell_injection",
                            "severity": "high",
                            "message": f"Job '{job_name}' contains potential shell injection: {description}. GitHub Actions expressions are used in command substitution.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": description,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/shell_injection"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/shell_injection"
                        })
                        break  # Only report once per step

                # Check dangerous commands with user input
                for pattern, description in dangerous_command_patterns:
                    if re.search(pattern, run, re.IGNORECASE) and _has_risky_context(run):
                        issues.append({
                            "type": "shell_injection",
                            "severity": "high",
                            "message": f"Job '{job_name}' executes dangerous shell command with user-controlled input: {description}",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": description,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/shell_injection"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/shell_injection"
                        })
                        break  # Only report once per step

    return issues


def check_github_script_injection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for JavaScript injection vulnerabilities in github-script action."""
    issues = []

    jobs = workflow.get("jobs", {})

    # Dangerous JavaScript patterns
    dangerous_js_patterns = [
        (r'eval\s*\(\s*.*\$\{\{[^}]*\}\}.*\)', 'eval with user input'),
        (r'new\s+Function\s*\(\s*.*\$\{\{[^}]*\}\}.*\)', 'Function constructor with user input'),
        (r'require\s*\(\s*.*\$\{\{[^}]*\}\}.*\)', 'Dynamic require with user input'),
        (r'import\s*\(\s*.*\$\{\{[^}]*\}\}.*\)', 'Dynamic import with user input'),
        (r'exec\s*\(\s*.*\$\{\{[^}]*\}\}.*\)', 'exec with user input'),
        (r'spawn\s*\(\s*.*\$\{\{[^}]*\}\}.*\)', 'spawn with user input'),
    ]

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if isinstance(uses, str) and "actions/github-script@" in uses:
                with_params = step.get("with", {})
                if with_params and "script" in with_params:
                    script = str(with_params["script"])

                    # Interpolating attacker-controlled context into the script
                    # body is code injection on its own: ${{ }} is substituted
                    # before the JavaScript is parsed.
                    if _has_risky_context(script):
                        issues.append({
                            "type": "script_injection",
                            "severity": "critical",
                            "message": f"Job '{job_name}' interpolates user-controllable context directly into an actions/github-script script. The value becomes JavaScript source; pass it through env: and read process.env instead.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": "expression interpolated into script",
                                "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/script_injection"
                            },
                            "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/script_injection"
                        })
                        continue

                    for pattern, description in dangerous_js_patterns:
                        if re.search(pattern, script, re.IGNORECASE):
                            issues.append({
                                "type": "script_injection",
                                "severity": "critical",
                                "message": f"Job '{job_name}' contains JavaScript injection vulnerability in github-script action: {description}",
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "evidence": {
                                    "job": job_name,
                                    "step": step.get("name", "unnamed"),
                                    "pattern": description,
                                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/script_injection"
                                },
                                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/script_injection"
                            })
                            break  # Only report once per step

    return issues


# --- Attacker-controllable context classification --------------------------
#
# An expression is dangerous when it expands to text an outside contributor can
# choose: issue/PR/comment titles and bodies, branch names, commit messages,
# author names/emails, labels, wiki page names. IDs, numbers, SHAs, URLs and
# anything describing the *base* repository are not attacker-chosen.

_EXPRESSION_RE = re.compile(r'\$\{\{(.*?)\}\}', re.DOTALL)
_CONTEXT_PATH_RE = re.compile(r'\bgithub\.(?:event(?:\.[A-Za-z0-9_*-]+|\[[^\]]*\])+|head_ref\b|ref_name\b)')
_RISKY_LEAVES = {
    "body", "title", "message", "name", "ref", "head_ref", "head_branch",
    "label", "default_branch", "email", "page_name", "description",
}
_SAFE_CONTEXT_PREFIXES = (
    "github.event.repository.",    # the base repository
    "github.event.organization.",
    "github.event.enterprise.",
    "github.event.installation.",
    "github.event.sender.",        # login is restricted to [A-Za-z0-9-]
    "github.event.inputs.",        # workflow_dispatch inputs: see code_injection_via_input
)


def _risky_contexts_in(value: Any) -> List[str]:
    """Return attacker-controllable GitHub context paths used inside ${{ }} in value."""
    if not isinstance(value, str) or "${{" not in value:
        return []
    found: List[str] = []
    for expression in _EXPRESSION_RE.findall(value):
        for match in _CONTEXT_PATH_RE.finditer(expression):
            path = match.group(0)
            lowered = path.lower()
            if lowered in ("github.head_ref", "github.ref_name"):
                risky = True
            elif lowered.startswith(_SAFE_CONTEXT_PREFIXES):
                risky = False
            else:
                leaf = re.split(r'[.\[]', lowered.rstrip("]"))[-1].strip("'\"")
                risky = leaf in _RISKY_LEAVES
            if risky and path not in found:
                found.append(path)
    return found


def check_risky_context_usage(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for risky GitHub context usage that can be exploited for injection attacks.

    Severity follows where the value lands:
      * ``run:`` - the expression is substituted into the script *before* the
        shell parses it: direct command injection (critical).
      * ``env:`` - the recommended mitigation. Reported as low so the value is
        still reviewed (it must be quoted, and not eval'd, where it is used).
      * ``with:`` - handed to an action as data; low, informational.
    ``actions/github-script``'s ``script`` input is reported by
    check_github_script_injection instead.
    """
    issues = []
    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            step_name = step.get("name", "unnamed")
            in_run = _risky_contexts_in(step.get("run", ""))

            in_env: List[str] = []
            env = step.get("env", {})
            if isinstance(env, dict):
                for env_value in env.values():
                    for ctx in _risky_contexts_in(env_value):
                        if ctx not in in_env:
                            in_env.append(ctx)

            in_with: List[str] = []
            with_params = step.get("with", {})
            is_github_script = "actions/github-script@" in str(step.get("uses", ""))
            if isinstance(with_params, dict):
                for key, param_value in with_params.items():
                    if is_github_script and key == "script":
                        continue
                    for ctx in _risky_contexts_in(param_value):
                        if ctx not in in_with:
                            in_with.append(ctx)

            def preview(ctxs: List[str]) -> str:
                return ", ".join(ctxs[:3]) + ("..." if len(ctxs) > 3 else "")

            if in_run:
                issues.append({
                    "type": "risky_context_usage",
                    "severity": "critical",
                    "message": f"Job '{job_name}' interpolates user-controllable context directly into a shell command (step: '{step_name}'): {preview(in_run)}. The value is substituted into the script before the shell runs it, so crafted input executes as code. Pass it through env: and reference the variable instead.",
                    "job": job_name,
                    "step": step_name,
                    "evidence": {
                        "job": job_name,
                        "step": step_name,
                        "risky_contexts": list(dict.fromkeys(in_run + in_env + in_with)),
                        "usage_location": "run_command",
                        "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/risky_context_usage"
                    },
                    "recommendation": "Move risky context variables to environment variables and add input validation. Never use ${{ github.event.* }} directly in shell commands. See: https://actsense.dev/vulnerabilities/risky_context_usage"
                })
            elif in_env:
                issues.append({
                    "type": "risky_context_usage",
                    "severity": "low",
                    "message": f"Job '{job_name}' passes user-controllable context through environment variables (step: '{step_name}'): {preview(in_env)}. This is the safe pattern; make sure the variable is always double-quoted and never passed to eval or a nested shell.",
                    "job": job_name,
                    "step": step_name,
                    "evidence": {
                        "job": job_name,
                        "step": step_name,
                        "risky_contexts": in_env,
                        "usage_location": "environment_variable",
                        "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/risky_context_usage"
                    },
                    "recommendation": "Quote the variable (\"$VAR\") wherever it is used and validate it against an allowlist if it drives control flow. See: https://actsense.dev/vulnerabilities/risky_context_usage"
                })
            elif in_with:
                issues.append({
                    "type": "risky_context_usage",
                    "severity": "low",
                    "message": f"Job '{job_name}' passes user-controllable context to an action input (step: '{step_name}'): {preview(in_with)}. Confirm the action treats this input as data and does not execute it.",
                    "job": job_name,
                    "step": step_name,
                    "evidence": {
                        "job": job_name,
                        "step": step_name,
                        "risky_contexts": in_with,
                        "usage_location": "action_parameter",
                        "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/risky_context_usage"
                    },
                    "recommendation": "Validate risky context variables before passing to actions. Use allowlists and sanitize input. See: https://actsense.dev/vulnerabilities/risky_context_usage"
                })

    return issues


_SHELL_SEPARATORS = {"&&", "||", ";", "|"}


def _has_risky_context(value: str) -> bool:
    """Return True when a GitHub expression references attacker-controlled context."""
    return bool(_risky_contexts_in(value))


def _split_shell_tokens(line: str) -> List[str]:
    """Split a shell-like line into bounded tokens for lightweight command checks."""
    spaced = line.replace("&&", " && ").replace("||", " || ")
    spaced = spaced.replace(";", " ; ").replace("|", " | ")
    try:
        return shlex.split(spaced, comments=False, posix=True)
    except ValueError:
        return spaced.split()


def _command_tail(tokens: List[str], command_index: int, subcommands: set[str]) -> List[str]:
    """Return package arguments after a command/subcommand pair until a shell separator."""
    if command_index + 1 >= len(tokens):
        return []
    if tokens[command_index + 1].lower() not in subcommands:
        return []
    tail = []
    for token in tokens[command_index + 2:]:
        if token in _SHELL_SEPARATORS:
            break
        tail.append(token)
    return tail


def _is_shell_variable_name(value: str) -> bool:
    if not value:
        return False
    return (value[0].isalpha() or value[0] == "_") and all(
        ch.isalnum() or ch == "_" for ch in value
    )


def _assigned_shell_variable(line: str) -> Optional[str]:
    stripped = line.lstrip()
    if stripped.startswith("export "):
        stripped = stripped[len("export "):].lstrip()
    if "=" not in stripped:
        return None
    name = stripped.split("=", 1)[0].strip()
    return name if _is_shell_variable_name(name) else None


def _references_shell_variable(line: str, variable: str) -> bool:
    braced = f"${{{variable}}}"
    if braced in line:
        return True
    needle = f"${variable}"
    start = 0
    while True:
        idx = line.find(needle, start)
        if idx == -1:
            return False
        end = idx + len(needle)
        if end == len(line) or not (line[end].isalnum() or line[end] == "_"):
            return True
        start = end


def _iter_shell_command_tokens(run: str):
    """Yield token groups for shell commands separated by common operators."""
    for line in run.splitlines():
        current = []
        for token in _split_shell_tokens(line):
            if token in _SHELL_SEPARATORS:
                if current:
                    yield current
                    current = []
                continue
            current.append(token)
        if current:
            yield current


def _has_file_tamper_command(run: str) -> bool:
    """Detect in-place or destructive file mutation commands without regex backtracking."""
    for tokens in _iter_shell_command_tokens(run):
        if tokens and tokens[0] == "sudo":
            tokens = tokens[1:]
        if not tokens:
            continue
        command = tokens[0]
        if command in ("sed", "perl") and any(t == "-i" or t.startswith("-i") for t in tokens[1:]):
            return True
        if command == "rm" and any(t.startswith("-") and ("r" in t or "f" in t) for t in tokens[1:]):
            return True
        if command in ("mv", "cp", "install", "truncate", "dd", "tee"):
            return True
    return False


def _iter_run_steps(workflow: Dict[str, Any]):
    """Yield (job_name, step, run_text) for every step with a string run command."""
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            run = step.get("run", "")
            if isinstance(run, str) and run:
                yield job_name, step, run


def _npm_unpinned_packages(run: str) -> List[str]:
    """Return npm package specs installed without immutable version pins."""
    unpinned = []
    for line in run.splitlines():
        tokens = _split_shell_tokens(line)
        for idx, token in enumerate(tokens):
            if token.lower() != "npm":
                continue
            install_tokens = _command_tail(tokens, idx, {"install", "i", "add"})
            for token in install_tokens:
                token = token.strip("'\"")
                if not token or token.startswith("-"):
                    continue
                if token in (".", "./") or token.startswith(("./", "../", "$", "${{")):
                    continue
                if token.endswith((".tgz", ".tar.gz")) or "://" in token:
                    continue
                if token == "@latest" or token.endswith("@latest"):
                    unpinned.append(token)
                    continue
                # Scoped package pins look like @scope/name@1.2.3; unscoped pins
                # look like name@1.2.3. Bare @scope/name is unpinned.
                if token.startswith("@"):
                    if token.count("@") < 2:
                        unpinned.append(token)
                elif "@" not in token:
                    unpinned.append(token)
            break
    return unpinned


def _pip_install_tokens(tokens: List[str], idx: int) -> List[str]:
    token = tokens[idx].lower()
    if token in ("pip", "pip3"):
        if idx + 1 < len(tokens) and tokens[idx + 1].lower() == "install":
            tail = []
            for item in tokens[idx + 2:]:
                if item in _SHELL_SEPARATORS:
                    break
                tail.append(item)
            return tail
        return []
    if token in ("python", "python3") and idx + 3 < len(tokens):
        if tokens[idx + 1] == "-m" and tokens[idx + 2].lower() in ("pip", "pip3") and tokens[idx + 3].lower() == "install":
            tail = []
            for item in tokens[idx + 4:]:
                if item in _SHELL_SEPARATORS:
                    break
                tail.append(item)
            return tail
    return []


def _pip_unpinned_packages(run: str) -> List[str]:
    """Return pip package specs installed without exact version pins."""
    unpinned = []
    for line in run.splitlines():
        tokens = _split_shell_tokens(line)
        install_tokens = []
        for idx in range(len(tokens)):
            install_tokens = _pip_install_tokens(tokens, idx)
            if install_tokens:
                break
        if not install_tokens:
            continue
        skip_next = False
        for token in install_tokens:
            token = token.strip("'\"")
            if not token or token.startswith("-"):
                if token in ("-r", "--requirement", "-c", "--constraint"):
                    skip_next = True
                continue
            if skip_next:
                skip_next = False
                continue
            if token.startswith(("./", "../", "$", "${{")):
                continue
            if token.endswith((".whl", ".tar.gz", ".zip")) or "://" in token or token.startswith("git+"):
                continue
            if "==" not in token and "===" not in token:
                unpinned.append(token)
    return unpinned


def check_workflow_package_installs(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check workflow run steps for unpinned npm and Python package installs."""
    issues = []

    for job_name, step, run in _iter_run_steps(workflow):
        step_name = step.get("name", "unnamed")
        npm_packages = _npm_unpinned_packages(run)
        if npm_packages:
            issues.append({
                "type": "unpinned_npm_packages",
                "severity": "high",
                "message": f"Job '{job_name}' installs NPM packages without version locking in step '{step_name}'. Unpinned packages can introduce supply-chain vulnerabilities.",
                "job": job_name,
                "step": step_name,
                "evidence": {
                    "job": job_name,
                    "step": step_name,
                    "packages": npm_packages,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_npm_packages"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_npm_packages"
            })

        pip_packages = _pip_unpinned_packages(run)
        if pip_packages:
            issues.append({
                "type": "unpinned_python_packages",
                "severity": "high",
                "message": f"Job '{job_name}' installs Python packages without exact version pinning in step '{step_name}'. Unpinned packages can introduce supply-chain vulnerabilities.",
                "job": job_name,
                "step": step_name,
                "evidence": {
                    "job": job_name,
                    "step": step_name,
                    "packages": pip_packages,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_python_packages"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_python_packages"
            })

    return issues


def check_github_env_injection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for untrusted input written to the runner environment files.

    Appending attacker-controllable context to ``$GITHUB_ENV`` or ``$GITHUB_PATH``
    lets an attacker define variables such as ``LD_PRELOAD``/``NODE_OPTIONS`` or
    prepend a directory to ``PATH``, achieving code execution in later (trusted)
    steps. Writing it to ``$GITHUB_OUTPUT`` can similarly poison downstream steps
    that consume the output.
    """
    issues = []

    for job_name, step, run in _iter_run_steps(workflow):
        if not _has_risky_context(run):
            continue

        # Track shell variables assigned from a risky context, so a value that is
        # first stored in a variable and later written to the sink on another line
        # (e.g. TITLE="${{ ... }}"; echo "T=$TITLE" >> $GITHUB_ENV) is still caught.
        tainted = set()
        for line in run.splitlines():
            assigned = _assigned_shell_variable(line)
            if assigned and _has_risky_context(line):
                tainted.add(assigned)

        def _line_tainted(line):
            if _has_risky_context(line):
                return True
            return any(_references_shell_variable(line, v) for v in tainted)

        # Flag when the untrusted value (directly, or via a tainted variable) is on
        # a line that also writes to the sink, to avoid coincidental co-occurrence.
        for line in run.splitlines():
            if not _line_tainted(line):
                continue
            if "GITHUB_ENV" in line or "GITHUB_PATH" in line:
                issues.append({
                    "type": "github_env_injection",
                    "severity": "critical",
                    "message": f"Job '{job_name}' writes user-controllable input to $GITHUB_ENV/$GITHUB_PATH (step: '{step.get('name', 'unnamed')}'). An attacker can inject variables like LD_PRELOAD or alter PATH to execute code in later steps.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "sink": "GITHUB_ENV/GITHUB_PATH",
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/github_env_injection"
                    },
                    "recommendation": "Never write ${{ github.event.* }} (or other user-controllable context) to $GITHUB_ENV or $GITHUB_PATH. Pass the value via an intermediate env var and validate it first. See: https://actsense.dev/vulnerabilities/github_env_injection"
                })
                break
            if "GITHUB_OUTPUT" in line:
                issues.append({
                    "type": "github_output_injection",
                    "severity": "high",
                    "message": f"Job '{job_name}' writes user-controllable input to $GITHUB_OUTPUT (step: '{step.get('name', 'unnamed')}'). This can poison step outputs consumed by later steps or jobs.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "sink": "GITHUB_OUTPUT",
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/github_output_injection"
                    },
                    "recommendation": "Do not write user-controllable context directly to $GITHUB_OUTPUT. Sanitize and validate the value via an intermediate env var first. See: https://actsense.dev/vulnerabilities/github_output_injection"
                })
                break

    return issues


def check_excessive_secret_exposure(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for bulk exposure of the entire secrets context.

    ``${{ toJson(secrets) }}`` (and equivalents) serializes every secret into a
    single value, exposing all credentials to a step that should only need one.
    """
    issues = []

    # toJson(secrets) / toJSON( secrets ) anywhere in the expression.
    pattern = re.compile(r'tojson\s*\(\s*secrets\s*\)', re.IGNORECASE)

    def scan_value(value, job_name, step, location):
        if isinstance(value, str) and pattern.search(value):
            step_name = step.get("name", "unnamed") if isinstance(step, dict) else None
            where = f"step: '{step_name}', " if step_name else ""
            scope = f"Job '{job_name}'" if job_name else "The workflow"
            issues.append({
                "type": "excessive_secret_exposure",
                "severity": "high",
                "message": f"{scope} serializes the entire secrets context with toJson(secrets) ({where}{location}). This exposes every secret instead of only the ones it needs.",
                "job": job_name,
                "step": step_name,
                "evidence": {
                    "job": job_name,
                    "step": step_name,
                    "location": location,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/excessive_secret_exposure"
                },
                "recommendation": "Pass only the individual secrets a step needs, by name. Avoid toJson(secrets). See: https://actsense.dev/vulnerabilities/excessive_secret_exposure"
            })

    def scan_env(env, job_name, step, location):
        if isinstance(env, dict):
            for v in env.values():
                scan_value(v, job_name, step, location)

    # Workflow-level env
    scan_env(workflow.get("env"), None, None, "workflow_env")

    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return issues
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        # Job-level env
        scan_env(job.get("env"), job_name, None, "job_env")
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            run = step.get("run", "")
            scan_value(run, job_name, step, "run_command")
            scan_env(step.get("env"), job_name, step, "environment_variable")
            with_params = step.get("with", {})
            if isinstance(with_params, dict):
                for v in with_params.values():
                    scan_value(v, job_name, step, "action_parameter")

    return issues


def check_secrets_inherit(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for reusable workflow calls that inherit all secrets.

    ``secrets: inherit`` forwards every secret available to the caller to the
    called workflow, with no per-secret control.
    """
    issues = []

    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return issues

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        uses = job.get("uses", "")
        secrets = job.get("secrets")
        if isinstance(secrets, str) and secrets.strip().lower() == "inherit":
            issues.append({
                "type": "secrets_inherit",
                "severity": "medium",
                "message": f"Job '{job_name}' calls reusable workflow '{uses}' with 'secrets: inherit', forwarding all of the caller's secrets without restriction.",
                "job": job_name,
                "action": uses,
                "evidence": {
                    "job": job_name,
                    "workflow": uses,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/secrets_inherit"
                },
                "recommendation": "Pass only the secrets the reusable workflow requires, explicitly by name, instead of 'secrets: inherit'. See: https://actsense.dev/vulnerabilities/secrets_inherit"
            })

    return issues


def check_cache_poisoning(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for cache usage in workflows triggered by untrusted events.

    When a workflow that runs in a privileged context (``pull_request_target``,
    ``workflow_run``) also restores/saves a cache, attacker-controlled code from a
    fork can poison the cache, which later trusted runs will consume.
    """
    issues = []

    triggers = set(_on_events(workflow))

    dangerous = triggers & {"pull_request_target", "workflow_run"}
    if not dangerous:
        return issues

    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return issues

    # Caching can be explicit (actions/cache) or implicit (cache: input on common
    # setup-* actions).
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            uses = str(step.get("uses", "")).lower()
            with_params = step.get("with", {}) if isinstance(step.get("with"), dict) else {}
            uses_cache = "actions/cache" in uses or (
                uses.startswith("actions/setup-") and "cache" in with_params
            )
            if uses_cache:
                issues.append({
                    "type": "cache_poisoning",
                    "severity": "high",
                    "message": f"Job '{job_name}' uses caching in a workflow triggered by {', '.join(sorted(dangerous))} (step: '{step.get('name', 'unnamed')}'). Untrusted code from a fork can poison the cache for later trusted runs.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "trigger": sorted(dangerous),
                        "action": step.get("uses", ""),
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/cache_poisoning"
                    },
                    "recommendation": "Avoid restoring or saving caches in workflows triggered by pull_request_target or workflow_run, or gate the caching steps so they never run on untrusted code. See: https://actsense.dev/vulnerabilities/cache_poisoning"
                })

    return issues


def check_missing_permissions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for workflows without an explicit permissions block.

    With no ``permissions`` key at the workflow or job level, the GITHUB_TOKEN
    falls back to the repository default, which is frequently broader than the
    workflow needs.
    """
    issues = []

    if "permissions" in workflow:
        return issues  # Explicit top-level permissions present.

    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict) or not jobs:
        return issues

    # If every job sets its own permissions, the workflow is already explicit.
    if all(isinstance(job, dict) and "permissions" in job for job in jobs.values()):
        return issues

    issues.append({
        "type": "missing_permissions",
        "severity": "low",
        "message": "Workflow does not set an explicit 'permissions' block, so the GITHUB_TOKEN uses the repository default, which may grant more access than needed.",
        "evidence": {
            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/missing_permissions"
        },
        "recommendation": "Add an explicit least-privilege 'permissions' block (e.g. 'permissions: {contents: read}') at the workflow level, then widen per job only where required. See: https://actsense.dev/vulnerabilities/missing_permissions"
    })

    return issues


def _iter_env_scopes(workflow: Dict[str, Any]):
    """Yield (scope_label, job_name, step, env_dict) for every env: block."""
    top_env = workflow.get("env", {})
    if isinstance(top_env, dict):
        yield ("workflow", None, None, top_env)
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_env = job.get("env", {})
        if isinstance(job_env, dict):
            yield ("job", job_name, None, job_env)
        for step in job.get("steps", []) or []:
            if isinstance(step, dict):
                step_env = step.get("env", {})
                if isinstance(step_env, dict):
                    yield ("step", job_name, step, step_env)


def check_insecure_commands(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for re-enabling of deprecated, injectable workflow commands.

    Setting ``ACTIONS_ALLOW_UNSECURE_COMMANDS: true`` re-enables the deprecated
    ``set-env`` and ``add-path`` stdout commands, which let any printed line define
    environment variables or modify PATH — a direct injection sink equivalent to
    writing to ``$GITHUB_ENV``/``$GITHUB_PATH``.
    """
    issues = []

    def is_truthy(val) -> bool:
        return val is True or (isinstance(val, str) and val.strip().lower() in ("true", "1", "yes", "on"))

    for scope, job_name, step, env in _iter_env_scopes(workflow):
        if "ACTIONS_ALLOW_UNSECURE_COMMANDS" in env and is_truthy(env["ACTIONS_ALLOW_UNSECURE_COMMANDS"]):
            step_name = step.get("name", "unnamed") if isinstance(step, dict) else None
            issues.append({
                "type": "insecure_commands",
                "severity": "high",
                "message": f"ACTIONS_ALLOW_UNSECURE_COMMANDS is enabled at the {scope} level" + (f" (job '{job_name}')" if job_name else "") + ". This re-enables the deprecated set-env/add-path stdout commands, allowing any printed output to inject environment variables or modify PATH.",
                "job": job_name,
                "step": step_name,
                "evidence": {
                    "scope": scope,
                    "job": job_name,
                    "step": step_name,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/insecure_commands"
                },
                "recommendation": "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and migrate to the $GITHUB_ENV / $GITHUB_PATH environment files with validated input. See: https://actsense.dev/vulnerabilities/insecure_commands"
            })

    # Also flag direct use of the deprecated stdout commands themselves.
    deprecated_cmd = re.compile(r'::(set-env|add-path)\s', re.IGNORECASE)
    for job_name, step, run in _iter_run_steps(workflow):
        if deprecated_cmd.search(run):
            issues.append({
                "type": "insecure_commands",
                "severity": "high",
                "message": f"Job '{job_name}' uses a deprecated set-env/add-path stdout command (step: '{step.get('name', 'unnamed')}'). These commands are an injection sink and are disabled unless ACTIONS_ALLOW_UNSECURE_COMMANDS is set.",
                "job": job_name,
                "step": step.get("name", "unnamed"),
                "evidence": {
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/insecure_commands"
                },
                "recommendation": "Replace set-env/add-path with the $GITHUB_ENV / $GITHUB_PATH environment files and validate any user-controllable values. See: https://actsense.dev/vulnerabilities/insecure_commands"
            })

    return issues


def check_bot_conditions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for security gates that rely on the spoofable actor context.

    Conditions such as ``if: github.actor == 'dependabot[bot]'`` are not a reliable
    trust boundary: the actor/triggering-actor is attacker-influenceable in several
    trigger contexts, so gating privileged behaviour on it can be bypassed.
    """
    issues = []

    # Any use of the actor context inside a condition — direct comparison
    # (== / !=) or via helpers such as contains(...) — is a spoofable gate.
    actor_cond = re.compile(r'github\.(?:actor|triggering_actor)\b', re.IGNORECASE)

    def scan(condition, job_name, step):
        if isinstance(condition, str) and actor_cond.search(condition):
            step_name = step.get("name", "unnamed") if isinstance(step, dict) else None
            issues.append({
                "type": "spoofable_actor_condition",
                "severity": "medium",
                "message": f"Job '{job_name}' gates behaviour on github.actor/github.triggering_actor" + (f" (step: '{step_name}')" if step_name else "") + ". The actor context is spoofable in several trigger contexts and is not a reliable trust boundary.",
                "job": job_name,
                "step": step_name,
                "evidence": {
                    "job": job_name,
                    "step": step_name,
                    "condition": condition.strip()[:200],
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/spoofable_actor_condition"
                },
                "recommendation": "Do not use github.actor as a security gate. Rely on event payload verification, permissions, environment protection rules, or GitHub App identity instead. See: https://actsense.dev/vulnerabilities/spoofable_actor_condition"
            })

    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return issues
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        scan(job.get("if"), job_name, None)
        for step in job.get("steps", []) or []:
            if isinstance(step, dict):
                scan(step.get("if"), job_name, step)

    return issues


def check_hardcoded_container_credentials(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for hardcoded registry credentials on job containers/services."""
    issues = []

    def is_hardcoded(val) -> bool:
        # A secret/expression reference is fine; a literal string is not.
        return isinstance(val, str) and val != "" and "${{" not in val

    def check_credentials(creds, job_name, source, service_name=""):
        if not isinstance(creds, dict):
            return
        # Only the password is a secret; a hardcoded username is not a finding.
        if is_hardcoded(creds.get("password")):
            where = f"service '{service_name}'" if source == "service" else "container"
            issues.append({
                "type": "hardcoded_container_credentials",
                "severity": "high",
                "message": f"Job '{job_name}' hardcodes the {where} registry password. Credentials committed to a workflow are exposed to anyone with read access and to git history.",
                "job": job_name,
                "evidence": {
                    "job": job_name,
                    "source": source,
                    "service_name": service_name,
                    "field": "password",
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/hardcoded_container_credentials"
                },
                "recommendation": "Store registry credentials in GitHub Secrets and reference them as ${{ secrets.NAME }} instead of hardcoding them. See: https://actsense.dev/vulnerabilities/hardcoded_container_credentials"
            })

    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return issues
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        container = job.get("container")
        if isinstance(container, dict):
            check_credentials(container.get("credentials"), job_name, "container")
        services = job.get("services", {})
        if isinstance(services, dict):
            for svc_name, svc in services.items():
                if isinstance(svc, dict):
                    check_credentials(svc.get("credentials"), job_name, "service", svc_name)

    return issues


def check_secrets_outside_env(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for secrets interpolated directly into run commands.

    Referencing ``${{ secrets.* }}`` directly inside a ``run:`` command risks
    leaking the value into process listings, shell traces, or logs. Passing the
    secret through a step ``env:`` variable is the recommended pattern. Self-hosted
    runners are covered separately by check_self_hosted_runner_secrets.
    """
    issues = []

    secret_ref = re.compile(r'\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}')

    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return issues
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        # Self-hosted runners have a dedicated, higher-severity check.
        if "self-hosted" in str(job.get("runs-on", "")).lower():
            continue
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            run = step.get("run", "")
            if isinstance(run, str) and secret_ref.search(run):
                issues.append({
                    "type": "secrets_outside_env",
                    "severity": "medium",
                    "message": f"Job '{job_name}' references a secret directly in a run command (step: '{step.get('name', 'unnamed')}'). Secrets interpolated into shell commands can leak via process listings, traces, or logs.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/secrets_outside_env"
                    },
                    "recommendation": "Pass the secret through a step env: variable and reference the env var in the command, e.g. env: { TOKEN: ${{ secrets.TOKEN }} } then use \"$TOKEN\". See: https://actsense.dev/vulnerabilities/secrets_outside_env"
                })

    return issues


def check_artifact_poisoning(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for consuming artifacts from untrusted runs.

    Downloading artifacts in a workflow triggered by ``workflow_run`` or
    ``pull_request_target`` can pull attacker-controlled content produced by an
    untrusted (for example, fork) run, which the privileged workflow then trusts.
    """
    issues = []

    triggers = set(_on_events(workflow))

    dangerous = triggers & {"pull_request_target", "workflow_run"}
    if not dangerous:
        return issues

    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return issues
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            uses = str(step.get("uses", "")).lower()
            # actions/download-artifact or common third-party download actions.
            if "download-artifact" in uses:
                issues.append({
                    "type": "artifact_poisoning",
                    "severity": "medium",
                    "message": f"Job '{job_name}' downloads an artifact in a workflow triggered by {', '.join(sorted(dangerous))} (step: '{step.get('name', 'unnamed')}'). The artifact may have been produced by an untrusted run and should not be trusted without validation.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "trigger": sorted(dangerous),
                        "action": step.get("uses", ""),
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/artifact_poisoning"
                    },
                    "recommendation": "Treat artifacts from untrusted runs as untrusted input: validate names and contents, avoid executing downloaded files, and prefer not consuming fork artifacts in privileged workflows. See: https://actsense.dev/vulnerabilities/artifact_poisoning"
                })

    return issues


def check_powershell_injection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for PowerShell injection vulnerabilities."""
    issues = []

    jobs = workflow.get("jobs", {})

    # PowerShell injection patterns
    powershell_patterns = [
        (r'Invoke-Expression.*\$\{\{[^}]*\}\}', 'Invoke-Expression with user input'),
        (r'Invoke-Command.*\$\{\{[^}]*\}\}', 'Invoke-Command with user input'),
        (r'(^|[\s;(])&\s*\$\{\{[^}]*\}\}', 'Call operator with user input'),
        (r'(^|[\s;(])\.\s+\$\{\{[^}]*\}\}', 'Dot sourcing with user input'),
    ]

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            shell = step.get("shell", "")
            run = step.get("run", "")

            # Here dispatch/reusable-workflow inputs count too: Invoke-Expression
            # executes whatever string it is given.
            if isinstance(run, str) and shell in ("powershell", "pwsh") and (
                _has_risky_context(run) or re.search(r'\$\{\{[^}]*\binputs\.', run)
            ):
                for pattern, description in powershell_patterns:
                    if re.search(pattern, run, re.IGNORECASE):
                        issues.append({
                            "type": "script_injection",
                            "severity": "critical",
                            "message": f"Job '{job_name}' contains PowerShell injection vulnerability: {description}",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": description,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/script_injection"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/script_injection"
                        })
                        break  # Only report once per step

    return issues


def check_malicious_curl_pipe_bash(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for curl/wget piped to bash/sh/zsh, which can execute malicious code."""
    issues = []

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str):
                # Check for curl/wget piped to shell
                # \b after the shell name: `| sha256sum` / `| shasum` are checksum
                # verification, the opposite of this pattern.
                patterns = [
                    (r'\bcurl\s+.*\|\s*(sudo\s+(-\S+\s+)*)?(bash|sh|zsh)\b', 'curl piped to shell'),
                    (r'\bwget\s+.*\|\s*(sudo\s+(-\S+\s+)*)?(bash|sh|zsh)\b', 'wget piped to shell'),
                    (r'\bcurl\s+.*\|\s*(sudo\s+(-\S+\s+)*)?/(usr/)?bin/(bash|sh|zsh)\b', 'curl piped to absolute shell path'),
                    (r'\bwget\s+.*\|\s*(sudo\s+(-\S+\s+)*)?/(usr/)?bin/(bash|sh|zsh)\b', 'wget piped to absolute shell path'),
                    (r'(ba|z)?sh\s+(-c\s+)?["\']?\$\(\s*(curl|wget)\b', 'shell executing downloaded script via command substitution'),
                ]

                for pattern, description in patterns:
                    if re.search(pattern, run, re.IGNORECASE):
                        issues.append({
                            "type": "malicious_curl_pipe_bash",
                            "severity": "critical",
                            "message": f"Job '{job_name}' contains {description}. This pattern can execute malicious code downloaded from the internet.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": description,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/malicious_curl_pipe_bash"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/malicious_curl_pipe_bash"
                        })
                        break  # Only report once per step

    return issues


def check_malicious_base64_decode(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for base64 decode execution patterns and decode base64 strings to detect hidden malicious code."""
    issues = []

    def is_valid_base64(s: str) -> bool:
        """Check if a string is valid base64."""
        try:
            # Remove whitespace and common quote characters
            cleaned = s.strip().strip('"\'')
            # Base64 strings should be at least 4 characters and contain only valid chars
            if len(cleaned) < 4:
                return False
            # Check if it matches base64 pattern (A-Z, a-z, 0-9, +, /, =)
            if not re.match(r'^[A-Za-z0-9+/=]+$', cleaned):
                return False
            # Try to decode it
            base64.b64decode(cleaned, validate=True)
            return True
        except Exception:
            return False

    def decode_base64(s: str) -> Optional[str]:
        """Try to decode a base64 string, return None if it fails."""
        try:
            cleaned = s.strip().strip('"\'')
            decoded = base64.b64decode(cleaned, validate=True)
            return decoded.decode('utf-8', errors='ignore')
        except Exception:
            return None

    def check_malicious_content(content: str) -> Optional[str]:
        """Check decoded content for malicious patterns."""
        content_lower = content.lower()
        
        # Malicious patterns to check for in decoded content
        malicious_patterns = [
            (r'curl\s+.*\s*\|\s*(bash|sh|zsh|python|perl)', 'curl piped to shell/interpreter'),
            (r'wget\s+.*\s*-O\s*-?\s*\|\s*(bash|sh|zsh|python|perl)', 'wget piped to shell/interpreter'),
            (r'wget\s+.*\s*\|\s*(bash|sh|zsh|python|perl)', 'wget piped to shell/interpreter'),
            (r'eval\s*\(', 'eval execution'),
            (r'exec\s*\(', 'exec execution'),
            (r'system\s*\(', 'system execution'),
            (r'subprocess\s*\.', 'subprocess execution'),
            (r'os\.system', 'os.system execution'),
            (r'rm\s+-rf\s+/', 'dangerous rm -rf /'),
            (r'mkfifo\s+.*\s*\|\s*(bash|sh|zsh)', 'mkfifo piped to shell'),
            (r'nc\s+.*\s+-e\s+', 'netcat with execute flag'),
            (r'python\s+-c\s+["\']import\s+os', 'python os import'),
            (r'powershell\s+-encodedcommand', 'powershell encoded command'),
            (r'iex\s*\(', 'powershell invoke expression'),
            (r'chmod\s+[0-7]{3,4}\s+', 'chmod with numeric permissions'),
        ]
        
        for pattern, description in malicious_patterns:
            if re.search(pattern, content_lower):
                return description
        return None

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str):
                # First, check for base64 decode execution patterns (existing check)
                decode_patterns = [
                    (r'echo\s+["\']?([A-Za-z0-9+/=]+)["\']?\s*\|\s*base64\s+-d\s*\|\s*(bash|sh|zsh)\b', 'base64 decode piped to shell'),
                    (r'base64\s+(-d|--decode)\b.*\|\s*(sudo\s+)?(bash|sh|zsh)\b', 'base64 decode piped to shell'),
                    (r'echo\s+["\']?([A-Za-z0-9+/=]+)["\']?\s*\|\s*base64\s+--decode\s*\|\s*(bash|sh|zsh)\b', 'base64 decode piped to shell'),
                    (r'eval\s*\(\s*base64\s+-d', 'eval with base64 decode'),
                    (r'eval\s*\(\s*base64\s+--decode', 'eval with base64 decode'),
                ]

                for pattern, description in decode_patterns:
                    match = re.search(pattern, run, re.IGNORECASE)
                    if match:
                        # Try to extract and decode the base64 string
                        base64_str = None
                        if match.groups():
                            # Try to get the base64 string from the match
                            for group in match.groups():
                                if group and is_valid_base64(group):
                                    base64_str = group
                                    break
                        
                        decoded_content = None
                        if base64_str:
                            decoded_content = decode_base64(base64_str)
                        
                        # Check decoded content for malicious patterns
                        malicious_desc = None
                        if decoded_content:
                            malicious_desc = check_malicious_content(decoded_content)
                        
                        issues.append({
                            "type": "malicious_base64_decode",
                            "severity": "critical",
                            "message": f"Job '{job_name}' contains {description}. This pattern can hide and execute malicious code." + 
                                      (f" Decoded content contains: {malicious_desc}." if malicious_desc else ""),
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": description,
                                "decoded_content_detected": malicious_desc if malicious_desc else "No malicious patterns detected in decoded content",
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/malicious_base64_decode"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/malicious_base64_decode"
                        })
                        break  # Only report once per step

                # Second, scan for base64 strings in the workflow and decode them
                # Look for potential base64 strings (long alphanumeric strings with +/=)
                base64_pattern = r'["\']?([A-Za-z0-9+/=]{20,})["\']?'
                base64_matches = re.finditer(base64_pattern, run)
                
                for match in base64_matches:
                    potential_base64 = match.group(1)
                    if is_valid_base64(potential_base64):
                        decoded = decode_base64(potential_base64)
                        if decoded:
                            # Check if decoded content looks malicious
                            malicious_desc = check_malicious_content(decoded)
                            if malicious_desc:
                                issues.append({
                                    "type": "malicious_base64_decode",
                                    "severity": "critical",
                                    "message": f"Job '{job_name}' contains a base64-encoded string that decodes to content with {malicious_desc}. This may be an attempt to hide malicious code.",
                                    "job": job_name,
                                    "step": step.get("name", "unnamed"),
                                    "evidence": {
                                        "job": job_name,
                                        "step": step.get("name", "unnamed"),
                                        "decoded_content_detected": malicious_desc,
                                        "base64_length": len(potential_base64),
                                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/malicious_base64_decode"
                                    },
                                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/malicious_base64_decode"
                                })
                                break  # Only report once per step

    return issues


def check_obfuscation_detection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for code obfuscation patterns that may hide malicious code."""
    issues = []

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str):
                # Check for various obfuscation patterns
                # Single escapes are everyday terminal colouring (printf '\033[31m',
                # '\x1b[0m'); obfuscation encodes whole strings, so require a run.
                # "${arr[*]}" is ordinary bash array expansion and is not flagged.
                obfuscation_patterns = [
                    (r'\beval\s*["\']?\$\(.*base64.*\)', 'Base64 decoded eval', 'critical'),
                    (r'\$\(\$\(.*\)\)', 'Nested command substitution', 'medium'),
                    (r'(\\x[0-9a-f]{2}){4,}', 'Hex-encoded characters', 'medium'),
                    (r'\$\{[^}]*#[^}]*\$\{\{[^}]*\}\}[^}]*\}', 'Parameter expansion with user input pattern removal', 'high'),
                    (r'\|\s*xxd\s+-r', 'Hex decode pipeline', 'high'),
                    (r'(\\[0-3][0-7]{2}){4,}', 'Octal escape sequences', 'medium'),
                ]

                for pattern, description, severity in obfuscation_patterns:
                    if re.search(pattern, run, re.IGNORECASE):
                        issues.append({
                            "type": "obfuscation_detection",
                            "severity": severity,
                            "message": f"Job '{job_name}' contains obfuscation pattern: {description}. This may hide malicious code.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": description,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/obfuscation_detection"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/obfuscation_detection"
                        })
                        break  # Only report once per step

    return issues


def check_artifact_exposure_risk(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for artifact exposure risks from unsafe artifact upload configurations."""
    issues: List[Dict[str, Any]] = []

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        steps = job.get("steps", []) or []

        # 1. Detect if this job uses actions/checkout with persisted credentials
        checkout_persists_credentials = False
        for step in steps:
            uses = str(step.get("uses", "")).lower()
            if "actions/checkout" in uses:
                with_params = step.get("with", {}) or {}
                persist = with_params.get("persist-credentials")
                # Default is True when not set
                if persist is None or str(persist).lower() != "false":
                    checkout_persists_credentials = True
                    break

        for idx, step in enumerate(steps):
            uses = str(step.get("uses", "")).lower()
            if "upload-artifact" in uses or "download-artifact" in uses:
                with_params = step.get("with", {}) or {}
                step_name = step.get("name", f"step_{idx}")

                # 2. Check for overly broad / dangerous path patterns
                if "path" in with_params and "upload-artifact" in uses:
                    path = str(with_params["path"]).strip()

                    # Patterns that are too broad or likely to include .git / secrets
                    dangerous_patterns = [
                        (r'^\.?/?$', 'Current directory (.)'),
                        (r'^\.$', 'Current directory (.)'),
                        (r'^\./$', 'Current directory (./)'),
                        (r'^\*\*$', 'Double wildcard (**)'),
                        (r'^\*$', 'Single wildcard (*)'),
                        (r'^\*\*/\*$', 'Recursive wildcard (**/*)'),
                        (r'\${{\s*github\.workspace\s*}}', 'Entire GitHub workspace (${{ github.workspace }})'),
                        (r'\.\./', 'Path traversal (../)'),
                        (r'~', 'Home directory (~)'),
                    ]

                    matched_description = None
                    for pattern, description in dangerous_patterns:
                        if re.search(pattern, path):
                            matched_description = description
                            break

                    if matched_description:
                        # upload-artifact v4.4+ excludes dotfiles (and so .git/config)
                        # unless include-hidden-files is set; v3 and older include them.
                        ref = uses.split("@", 1)[1] if "@" in uses else ""
                        major = re.match(r'^v?(\d+)', ref)
                        hidden_included = _is_truthy(with_params.get("include-hidden-files")) or (
                            major is not None and int(major.group(1)) < 4
                        )
                        severity = "high"
                        if checkout_persists_credentials and hidden_included and (
                            path in (".", "./")
                            or re.search(r'\${{\s*github\.workspace\s*}}', path)
                        ):
                            severity = "critical"

                        message_parts = [
                            f"Job '{job_name}' uploads artifacts with a broad path pattern: {matched_description}."
                        ]

                        if checkout_persists_credentials and hidden_included:
                            message_parts.append(
                                "This job also uses actions/checkout with persisted credentials, "
                                "so `.git/config` may contain a credentialed URL with `GITHUB_TOKEN`, "
                                "and uploading the workspace can expose that token via artifacts."
                            )

                        issues.append({
                            "type": "artifact_exposure_risk",
                            "severity": severity,
                            "message": " ".join(message_parts),
                            "job": job_name,
                            "step": step_name,
                            "evidence": {
                                "job": job_name,
                                "step": step_name,
                                "path": path,
                                "pattern": matched_description,
                                "checkout_persists_credentials": checkout_persists_credentials,
                                "vulnerability": (
                                    "For detailed information about this vulnerability, visit: "
                                    "https://actsense.dev/vulnerabilities/artifact_exposure_risk"
                                ),
                                "risk_description": (
                                    "This path pattern may unintentionally include sensitive internal repositories, "
                                    "credentials stored in .git/config, build logs, or other confidential files."
                                ),
                            },
                            "recommendation": (
                                "Use explicit artifact paths instead of broad globs or workspace uploads. "
                                "Exclude .git/, node_modules/, and other sensitive directories. "
                                "Set actions/checkout to persist-credentials: false when possible. "
                                "For more mitigation steps, visit: "
                                "https://actsense.dev/vulnerabilities/artifact_exposure_risk"
                            ),
                        })

                # 3. Check for missing retention policies on upload-artifact
                if "upload-artifact" in uses:
                    if "retention-days" not in with_params:
                        issues.append({
                            "type": "artifact_exposure_risk",
                            "severity": "low",
                            "message": (
                                f"Job '{job_name}' uploads artifacts without an explicit `retention-days` value. "
                                "Artifacts will use the repository default retention, which may be longer than necessary "
                                "for potentially sensitive data."
                            ),
                            "job": job_name,
                            "step": step_name,
                            "evidence": {
                                "job": job_name,
                                "step": step_name,
                                "vulnerability": (
                                    "For detailed information about this vulnerability, visit: "
                                    "https://actsense.dev/vulnerabilities/artifact_exposure_risk"
                                ),
                                "risk_description": (
                                    "Missing retention-days configuration increases the exposure window for any sensitive "
                                    "data that may be included in artifacts."
                                ),
                            },
                            "recommendation": (
                                "Set retention-days to the minimal necessary value. "
                                "For mitigation steps, visit: "
                                "https://actsense.dev/vulnerabilities/artifact_exposure_risk"
                            ),
                        })


    return issues


def check_token_permission_escalation(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for patterns that could lead to token permission escalation."""
    issues = []

    jobs = workflow.get("jobs", {})

    # Patterns that could lead to permission escalation
    escalation_patterns = [
        # Encoding the token defeats log masking -- the classic exfiltration
        # step. Ordinary use of the token (an Authorization header, gh CLI) is
        # not escalation and is intentionally not matched.
        (r'(GITHUB_TOKEN|github\.token|secrets\.[A-Z0-9_]*TOKEN).*\|\s*(base64|xxd|od|rev)\b', 'token encoded to bypass log masking'),
        (r'\bbase64\b.*<<<\s*["\']?\$\{?(GITHUB_TOKEN|GH_TOKEN)', 'token encoded to bypass log masking'),
        (r'git\s+config.*credential.*helper.*token', 'Git credential helper with token'),
    ]

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str):
                for pattern, description in escalation_patterns:
                    if re.search(pattern, run, re.IGNORECASE):
                        issues.append({
                            "type": "token_permission_escalation",
                            "severity": "high",
                            "message": f"Job '{job_name}' contains pattern that could be used to escalate token permissions: {description}",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": description,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/token_permission_escalation"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/token_permission_escalation"
                        })
                        break  # Only report once per step

    return issues


def check_cross_repository_access(workflow: Dict[str, Any], current_repo: Optional[str] = None) -> List[Dict[str, Any]]:
    """Check for unauthorized cross-repository access."""
    issues = []

    jobs = workflow.get("jobs", {})

    # Patterns that suggest cross-repository access
    cross_repo_patterns = [
        (r'gh\s+repo\s+clone\s+[^/]+/[^/\s]+', 'GitHub CLI repo clone'),
        (r'git\s+clone\s+https://github\.com/[^/]+/[^/\s]+', 'Git clone from GitHub'),
        (r'curl.*api\.github\.com/repos/[^/]+/[^/\s]+', 'GitHub API repository access'),
    ]

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            # Check checkout actions with different repositories
            uses = step.get("uses", "")
            if "actions/checkout" in uses:
                with_params = step.get("with", {})
                if with_params and "repository" in with_params:
                    repo = str(with_params["repository"])
                    # Check if it's accessing a different repository
                    if current_repo and repo and not repo.startswith("${{"):
                        if repo.lower() != current_repo.lower():
                            issues.append({
                                "type": "cross_repository_access",
                                "severity": "high",
                                "message": f"Job '{job_name}' accesses a different repository: {repo}. This may have security implications.",
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "repository": repo,
                                "evidence": {
                                    "job": job_name,
                                    "step": step.get("name", "unnamed"),
                                    "repository": repo,
                                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/cross_repository_access"
                                },
                                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/cross_repository_access"
                            })

            # Check run commands for cross-repo access
            run = step.get("run", "")
            if isinstance(run, str):
                for pattern, description in cross_repo_patterns:
                    if re.search(pattern, run, re.IGNORECASE):
                        issues.append({
                            "type": "cross_repository_access_command",
                            "severity": "high",
                            "message": f"Job '{job_name}' accesses external repositories via command: {description}. This may have security implications.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": description,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/cross_repository_access_command"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/cross_repository_access_command"
                        })
                        break  # Only report once per step

    return issues


def check_environment_bypass(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for potential environment protection bypass."""
    issues = []

    on_events = _on_events(workflow)
    is_pr_triggered = "pull_request" in on_events or "pull_request_target" in on_events

    # Check if workflow can bypass environment protections
    if is_pr_triggered:
        # Look for actions that might bypass environment controls
        bypass_patterns = [
            (r'gh\s+workflow\s+run', 'GitHub CLI workflow run'),
            (r'repository_dispatch', 'repository_dispatch event'),
            (r'workflow_dispatch', 'workflow_dispatch event'),
        ]

        jobs = workflow.get("jobs", {})
        for job_name, job in jobs.items():
            steps = job.get("steps", [])
            for step in steps:
                run = step.get("run", "")
                if isinstance(run, str):
                    for pattern, description in bypass_patterns:
                        if re.search(pattern, run, re.IGNORECASE):
                            issues.append({
                                "type": "environment_bypass_risk",
                                "severity": "high",
                                "message": f"Pull request triggered workflow may bypass environment protections via {description}",
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "evidence": {
                                    "job": job_name,
                                    "step": step.get("name", "unnamed"),
                                    "pattern": description,
                                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/environment_bypass_risk"
                                },
                                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/environment_bypass_risk"
                            })
                            break  # Only report once per step

    return issues


def check_secrets_access_untrusted(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for secrets passed to untrusted actions."""
    issues = []

    # Load trusted publishers from config file
    # Config file location: backend/config.yaml
    # See config.yaml for instructions on adding trusted publishers
    trusted_publishers = get_trusted_publishers()

    trusted_lower = [t.lower() for t in trusted_publishers]

    def is_untrusted_action(action_uses: str) -> bool:
        """Check if action is from untrusted publisher (local actions are the repo's own code)."""
        if not isinstance(action_uses, str) or not action_uses or action_uses.startswith(("./", "docker://")):
            return False
        return not any(action_uses.lower().startswith(t) for t in trusted_lower)

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if uses and is_untrusted_action(uses):
                # Check if secrets are passed to this action
                with_params = step.get("with", {})
                env = step.get("env", {})

                has_secrets = False
                secret_evidence = []

                # Check with parameters
                if with_params:
                    for key, value in with_params.items():
                        if isinstance(value, str) and "secrets." in value:
                            has_secrets = True
                            secret_evidence.append(f"{key}: {value}")

                # Check environment variables
                if env:
                    for key, value in env.items():
                        if isinstance(value, str) and "secrets." in value:
                            has_secrets = True
                            secret_evidence.append(f"{key}: {value}")

                if has_secrets:
                    issues.append({
                        "type": "secrets_access_untrusted",
                        "severity": "medium",
                        "message": f"Job '{job_name}' passes secrets to untrusted action '{uses}'. This is a security risk.",
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "action": uses,
                        "evidence": {
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "action": uses,
                            "secrets": secret_evidence,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/secrets_access_untrusted"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/secrets_access_untrusted"
                    })

            # Check for secrets in environment variables. Only flag this when the
            # step consumes an untrusted action: passing a secret to a step via a
            # step-scoped env var is the GitHub-recommended pattern, so flagging it
            # unconditionally produced a false positive for every safe usage.
            env = step.get("env", {})
            if uses and is_untrusted_action(uses) and env:
                for env_key, env_value in env.items():
                    if isinstance(env_value, str) and "secrets." in env_value:
                        issues.append({
                            "type": "secret_in_environment",
                            "severity": "high",
                            "message": f"Job '{job_name}' exposes secret in environment variable '{env_key}'. Secrets in environment variables may be logged or visible.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "env_key": env_key,
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "env_key": env_key,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/secret_in_environment"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/secret_in_environment"
                        })
                        break  # Only report once per step

    return issues


def check_network_traffic_filtering(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for potentially dangerous network operations that could exfiltrate data."""
    issues = []

    jobs = workflow.get("jobs", {})

    # Check for potentially dangerous network operations
    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str):
                # Check for network operations that could exfiltrate data
                dangerous_patterns = [
                    r'\bcurl\s+.*https?://',
                    r'\bwget\s+.*https?://',
                    r'(^|[\s;|&])nc\s+\S+\s+\d+',
                    r'\bncat\s+\S+\s+\d+',
                    r'\bssh\s+(\S+\s+)*\S+@\S+',
                ]
                for pattern in dangerous_patterns:
                    if re.search(pattern, run, re.IGNORECASE):
                        issues.append({
                            "type": "unfiltered_network_traffic",
                            "severity": "low",
                            "message": f"Job '{job_name}' makes outbound network connections with no egress filtering configured. If a step or dependency is compromised, nothing restricts where it can send credentials or data.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unfiltered_network_traffic"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unfiltered_network_traffic"
                        })
                        break

    return issues


def check_file_tampering_protection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for build jobs that modify files, which could be tampered with."""
    issues = []

    jobs = workflow.get("jobs", {})

    # Only consider build/release-style jobs, identified by the job name rather
    # than a substring match against the whole serialized job (which matched far
    # too eagerly).
    build_keywords = ("build", "deploy", "release", "publish", "package")

    for job_name, job in jobs.items():
        is_build_job = any(keyword in job_name.lower() for keyword in build_keywords)

        if is_build_job:
            # Check for file modification operations
            steps = job.get("steps", [])
            for step in steps:
                run = step.get("run", "")
                if isinstance(run, str):
                    # Check for in-place / destructive file operations
                    if _has_file_tamper_command(run):
                        issues.append({
                            "type": "no_file_tampering_protection",
                            "severity": "low",
                            "message": f"Build job '{job_name}' modifies files, which could be tampered with during build. File tampering protection should be implemented.",
                            "job": job_name,
                            "evidence": {
                                "job": job_name,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/no_file_tampering_protection"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/no_file_tampering_protection"
                        })
                        break

    return issues


def check_branch_protection_bypass(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for workflows that could bypass branch protection rules."""
    issues = []

    on_events = _on_events(workflow)

    # Check for workflows that auto-approve PRs
    if "pull_request" in on_events or "pull_request_target" in on_events:
        jobs = workflow.get("jobs", {})
        for job_name, job in jobs.items():
            steps = job.get("steps", [])
            for step in steps:
                run = step.get("run", "")
                uses = step.get("uses", "")

                # Check for auto-approval or auto-merge. Match specific sinks
                # only: the `gh pr review/merge/approve` CLI commands or a direct
                # call to the PR reviews API approving the PR. Bare words like
                # "merge"/"approve"/"bypass" (e.g. `git merge main`) are not flagged.
                if isinstance(run, str):
                    if re.search(r'gh\s+pr\s+(review|merge|approve)\b', run, re.IGNORECASE) or \
                       re.search(r'pulls/[^/\s]+/reviews', run, re.IGNORECASE):
                        issues.append({
                            "type": "branch_protection_bypass",
                            "severity": "high",
                            "message": f"Workflow may auto-approve/merge PRs, bypassing branch protection rules. This undermines code review and security controls.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/branch_protection_bypass"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/branch_protection_bypass"
                        })

                if isinstance(uses, str):
                    if "auto-approve" in uses.lower() or "auto-merge" in uses.lower():
                        issues.append({
                            "type": "branch_protection_bypass",
                            "severity": "high",
                            "message": f"Workflow uses action that may auto-approve/merge PRs. This bypasses branch protection rules and security controls.",
                            "job": job_name,
                            "action": uses,
                            "evidence": {
                                "job": job_name,
                                "action": uses,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/branch_protection_bypass"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/branch_protection_bypass"
                        })

    return issues


def _input_used_in_run_command(workflow: Dict[str, Any], input_name: str) -> bool:
    """Return True if ${{ inputs.<input_name> }} is interpolated inside any run: command.

    Direct interpolation of a workflow input into a shell command is the actual
    code-injection sink. Using the input elsewhere (an ``if:`` condition, an
    action ``with:`` parameter, an ``env:`` value) is not equivalent, so callers
    must not treat mere presence of the input anywhere in the workflow as a hit.
    """
    pattern = re.compile(
        r'\$\{\{[^}]*\b(?:github\.event\.)?inputs\.' + re.escape(input_name) + r'\b[^}]*\}\}'
    )
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return False
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            run = step.get("run", "")
            if isinstance(run, str) and pattern.search(run):
                return True
    return False


def check_code_injection_via_workflow_inputs(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for workflow_dispatch string inputs interpolated into run commands.

    Only people with write access can dispatch a workflow, so this is high
    rather than critical, but it still lets a less-trusted maintainer (or a
    stolen PAT with only actions:write) run arbitrary code with the
    workflow's secrets.
    """
    issues = []
    for input_name, input_def in _event_inputs(workflow, "workflow_dispatch").items():
        input_type = input_def.get("type", "string") if isinstance(input_def, dict) else "string"
        if input_type == "string" and _input_used_in_run_command(workflow, input_name):
            issues.append({
                "type": "code_injection_via_input",
                "severity": "high",
                "message": f"Workflow_dispatch input '{input_name}' is interpolated directly into a shell command. A crafted value executes as code; pass it through env: instead.",
                "input": input_name,
                "evidence": {
                    "input": input_name,
                    "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/code_injection_via_input"
                },
                "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/code_injection_via_input"
            })
    return issues


def check_typosquatting_actions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for potential typosquatting in action names."""
    issues = []

    # Popular actions that are commonly typosquatted
    popular_actions = {
        "actions/checkout": ["action/checkout", "actions/check-out", "actions/checkout-action"],
        "actions/setup-node": ["action/setup-node", "actions/setupnode", "actions/setup-node-action"],
        "actions/setup-python": ["action/setup-python", "actions/setuppython", "actions/setup-python-action"],
        "actions/upload-artifact": ["action/upload-artifact", "actions/uploadartifact", "actions/upload-artifact-action"],
        "actions/download-artifact": ["action/download-artifact", "actions/downloadartifact", "actions/download-artifact-action"],
    }

    # Common typosquatting patterns
    # Anchored on the owner: "someorg/deploy-action/sub" is not a typo of
    # "actions/*". Owners that impersonate GitHub's own orgs are.
    suspicious_patterns = [
        (r'^action/[^/]+', 'Uses "action" instead of "actions" (singular)'),
        (r'^(actions?-?(official|github|org|team)|github-?actions?|actons|acitons|actiions)/', 'Owner name imitates the official "actions" organization'),
    ]

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if not uses or "@" not in uses:
                continue

            action_name = uses.split("@")[0]

            # Check against known popular actions
            for popular, common_typos in popular_actions.items():
                if action_name.lower() in [typo.lower() for typo in common_typos]:
                    issues.append({
                        "type": "typosquatting_action",
                        "severity": "high",
                        "message": f"Job '{job_name}' uses action '{uses}' which appears similar to popular action '{popular}'. This might be a typosquatting attempt.",
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "action": uses,
                        "similar_to": popular,
                        "evidence": {
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "action": uses,
                            "similar_to": popular,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/typosquatting_action"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/typosquatting_action"
                    })
                    break

            # Check for suspicious patterns
            for pattern, description in suspicious_patterns:
                if re.search(pattern, action_name, re.IGNORECASE):
                    # Only flag if it's not from a known trusted publisher
                    owner = action_name.split("/")[0] if "/" in action_name else ""
                    if owner.lower() not in ["actions", "github"]:
                        issues.append({
                            "type": "typosquatting_action",
                            "severity": "high",
                            "message": f"Job '{job_name}' uses action '{uses}' with suspicious pattern: {description}. This might be a typosquatting attempt.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "action": uses,
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "action": uses,
                                "pattern": description,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/typosquatting_action"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/typosquatting_action"
                        })
                        break

    return issues


def check_untrusted_third_party_actions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for use of untrusted third-party GitHub Actions with enhanced suspicious pattern detection."""
    issues = []

    # Trusted publishers from backend/config.yaml: "owner/" trusts an owner,
    # "owner/repo@" a single action. A bare "owner" is read as "owner/".
    trusted_prefixes = tuple(
        (p if "/" in p else f"{p}/").lower() for p in get_trusted_publishers()
    )

    jobs = workflow.get("jobs", {})
    actions_used = set()

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if isinstance(uses, str) and "/" in uses and "@" in uses and not uses.startswith(("./", "docker://")):
                # Extract owner from action reference
                action_part = uses.split("@")[0]
                if "/" in action_part:
                    owner = action_part.split("/")[0]
                    actions_used.add((uses, owner, job_name, step.get("name", "unnamed")))

    # Check each action
    for action_ref, owner, job_name, step_name in actions_used:
        if not action_ref.lower().startswith(trusted_prefixes):
            # Additional checks for suspicious patterns
            is_suspicious = False
            suspicious_reasons = []

            # Check for actions using branch names instead of versions/SHA
            if "@" in action_ref:
                ref = action_ref.split("@")[-1]
                # Check if it's a branch (not a version tag or SHA)
                if not ref.startswith("v") and len(ref) < 7 and not re.match(r'^[a-f0-9]{7,}$', ref):
                    is_suspicious = True
                    suspicious_reasons.append("uses branch name instead of pinned version")

            # Check for unusual naming patterns
            action_name = action_ref.split("@")[0]
            if ".." in action_name or "--" in action_name:
                is_suspicious = True
                suspicious_reasons.append("unusual naming pattern")

            # Check for very short or suspicious owner names
            if len(owner) < 3 or owner.lower() in ["test", "demo", "example", "temp", "tmp"]:
                is_suspicious = True
                suspicious_reasons.append("suspicious owner name")

            # Check if it's pinned (has version tag or SHA)
            if "@" in action_ref:
                ref = action_ref.split("@")[-1]
                # Check if it's a branch (unpinned)
                if not ref.startswith("v") and len(ref) < 7 and not re.match(r'^[a-f0-9]{7,}$', ref):
                    issues.append({
                        "type": "untrusted_action_unpinned",
                        "severity": "high",
                        "message": f"Untrusted third-party action '{action_ref}' is not pinned to a specific version. This is extremely dangerous as the action can be updated with malicious code.",
                        "job": job_name,
                        "step": step_name,
                        "action": action_ref,
                        "owner": owner,
                        "evidence": {
                            "action": action_ref,
                            "owner": owner,
                            "reference": ref,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/untrusted_action_unpinned"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/untrusted_action_unpinned"
                    })
                else:
                    # Action is pinned, but check for suspicious patterns
                    severity = "medium"
                    description = "Action is from an untrusted or unknown publisher"
                    if is_suspicious:
                        severity = "high"
                        description = f"Action is from an untrusted publisher and {', '.join(suspicious_reasons)}"

                    issues.append({
                        "type": "untrusted_action_source",
                        "severity": severity,
                        "message": f"Job '{job_name}' uses action '{action_ref}' from untrusted publisher. {description}.",
                        "job": job_name,
                        "step": step_name,
                        "action": action_ref,
                        "owner": owner,
                        "evidence": {
                            "action": action_ref,
                            "owner": owner,
                            "suspicious_patterns": suspicious_reasons if is_suspicious else [],
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/untrusted_action_source"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/untrusted_action_source"
                    })

    return issues

def _run_trufflehog(content: str) -> List[Dict[str, Any]]:
    """Run TruffleHog on workflow content to detect secrets.

    Returns an empty list (without raising) when TruffleHog is not installed or
    times out, so callers always receive a usable result.  A warning is printed
    once when the binary is absent so operators are aware that this check is
    being skipped.
    """
    import logging
    logger = logging.getLogger(__name__)

    issues = []
    tmp_file_path = None

    try:
        # Write content to a temp file.  Assign the path before entering the
        # inner try so the finally block can always attempt cleanup.
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as tmp_file:
            tmp_file.write(content)
            tmp_file_path = tmp_file.name

        # Run TruffleHog on the file
        # Using --json flag for structured output
        result = subprocess.run(
            ['trufflehog', 'filesystem', '--json', '--no-update', tmp_file_path],
            capture_output=True,
            text=True,
            timeout=30
        )

        # Parse TruffleHog output (can be multiple JSON objects, one per line)
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        # Extract relevant information
                        detector_name = finding.get('DetectorName', 'Unknown')
                        verified = finding.get('Verified', False)

                        # Report all secrets (verified and unverified)
                        severity = "critical" if verified else "high"
                        verification_status = "verified" if verified else "unverified"

                        if verified:
                            vulnerability_text = (
                                f"TruffleHog detected a VERIFIED secret of type '{detector_name}' in the workflow file. "
                                f"This means the secret has been verified to be a real, active credential:\n"
                                f"  - The secret is exposed in the workflow file\n"
                                f"  - Anyone with read access can see and use this credential\n"
                                f"  - The secret is stored in git history permanently\n"
                                f"  - The credential is active and can be used by attackers immediately\n\n"
                                f"Immediate actions required:\n"
                                f"  - Rotate/revoke this credential immediately in the target system\n"
                                f"  - Review access logs for unauthorized usage\n"
                                f"  - Remove the secret from the workflow file\n"
                                f"  - Remove from git history if possible"
                            )
                        else:
                            vulnerability_text = (
                                f"TruffleHog detected a potential secret of type '{detector_name}' in the workflow file. "
                                f"While not verified, this pattern matches known secret formats:\n"
                                f"  - The pattern matches a known secret type\n"
                                f"  - This could be a real credential or a false positive\n"
                                f"  - If it's a real secret, it's exposed to anyone with read access\n"
                                f"  - Secrets in workflow files are stored in git history permanently\n\n"
                                f"Recommended actions:\n"
                                f"  - Verify if this is a real credential\n"
                                f"  - If real, rotate/revoke immediately\n"
                                f"  - Remove the secret from the workflow file\n"
                                f"  - Use GitHub Secrets instead"
                            )

                        issues.append({
                            "type": "trufflehog_secret_detected",
                            "severity": severity,
                            "message": f"TruffleHog detected {verification_status} secret: {detector_name}. This is a security vulnerability.",
                            "evidence": {
                                "detector": detector_name,
                                "verified": verified,
                                "verification_status": verification_status,
                                "vulnerability": vulnerability_text
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/trufflehog_secret_detected"
                        })
                    except json.JSONDecodeError:
                        # Skip invalid JSON lines
                        continue

    except subprocess.TimeoutExpired:
        logger.warning("TruffleHog timed out scanning workflow content; skipping TruffleHog check.")
    except FileNotFoundError:
        logger.warning(
            "TruffleHog binary not found. Install it (https://github.com/trufflesecurity/trufflehog) "
            "to enable secret detection. TruffleHog check will be skipped."
        )
    except Exception:
        logger.exception("Unexpected error running TruffleHog; skipping TruffleHog check.")
    finally:
        # Always clean up the temporary file, regardless of how the block exits.
        if tmp_file_path and os.path.exists(tmp_file_path):
            try:
                os.unlink(tmp_file_path)
            except OSError:
                logger.warning("Failed to delete TruffleHog temp file: %s", tmp_file_path)

    return issues


# ============================================================================
# Best Practice Checks
# ============================================================================

def check_pinned_version(action_ref: str) -> Dict[str, Any]:
    """
    Check if action uses pinned version (tag or SHA).

    Returns detailed vulnerability information with evidence and mitigation steps.
    """
    # Local actions (./path) ship in the same commit as the calling workflow.
    if action_ref.startswith("./"):
        return None

    # Docker images are pinned only by digest (docker://img@sha256:...).
    if action_ref.startswith("docker://"):
        if "@sha256:" in action_ref:
            return None
        return {
            "type": "unpinned_version",
            "severity": "high",
            "message": f"Docker image '{action_ref}' is referenced by a mutable tag instead of an immutable @sha256 digest.",
            "action": action_ref,
            "evidence": {
                "action_reference": action_ref,
                "reference_type": "docker_tag",
                "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_version"
            },
            "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_version"
        }

    # Extract action name and reference
    if "@" in action_ref:
        action_name, ref = action_ref.rsplit("@", 1)
    else:
        action_name = action_ref
        ref = None

    # Case 1: No version/tag specified at all
    if "@" not in action_ref or ref is None:
        return {
        "type": "unpinned_version",
        "severity": "high",
            "message": f"Action '{action_ref}' is missing version/tag/SHA pinning. This is a critical security vulnerability.",
            "action": action_ref,
            "evidence": {
                "action_reference": action_ref,
                "reference_type": "missing",
                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_version"
            },
            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_version"
        }

    # Case 2: Branch reference (not pinned)
    if not ref.startswith("v") and len(ref) < 7 and not re.match(r'^[a-f0-9]+$', ref):
        return {
            "type": "unpinned_version",
            "severity": "high",
            "message": f"Action '{action_ref}' uses branch reference '{ref}' instead of a pinned version. Branch references are mutable and pose a security risk.",
            "action": action_ref,
            "evidence": {
                "action_reference": action_ref,
                "reference_type": "branch",
                "reference_value": ref,
                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_version"
            },
            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_version"
        }

    # Case 3: Valid SHA (pinned) - return None (no issue)
    if len(ref) >= 7 and re.match(r'^[a-f0-9]+$', ref):
        return None  # Pinned with SHA - this is secure

    # Case 4: Valid version tag (pinned) - return None (no issue)
    if ref.startswith("v") or re.match(r'^\d+\.\d+', ref):
        return None  # Pinned with version tag - acceptable

    # Case 5: Ambiguous or unrecognized reference format
    return {
        "type": "unpinned_version",
        "severity": "high",
        "message": f"Action '{action_ref}' uses unrecognized or potentially unpinned reference '{ref}'. This may be a security risk.",
        "action": action_ref,
        "evidence": {
            "action_reference": action_ref,
            "reference_type": "unrecognized",
            "reference_value": ref,
            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_version"
        },
        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_version"
    }


def check_hash_pinning(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Check if actions in workflow use hash pinning (commit SHA) instead of tags.

    Returns detailed vulnerability information with evidence and mitigation steps.
    """
    issues = []

    jobs = workflow.get("jobs", {})
    actions_used = set()

    # Extract all action references from workflow
    def extract_actions_from_value(value):
        if isinstance(value, dict):
            if "uses" in value:
                uses_value = value.get("uses", "")
                if isinstance(uses_value, str) and "/" in uses_value and "@" in uses_value:
                    actions_used.add(uses_value)
            for v in value.values():
                extract_actions_from_value(v)
        elif isinstance(value, list):
            for item in value:
                extract_actions_from_value(item)

    extract_actions_from_value(workflow)

    # Check each action for hash pinning
    for action_ref in actions_used:
        if "@" not in action_ref:
            continue

        action_name, ref = action_ref.rsplit("@", 1)

        # Check if it's a full commit SHA (40 characters)
        is_full_sha = len(ref) == 40 and re.match(r'^[a-f0-9]+$', ref)

        # Check if it's a short SHA (7+ characters)
        is_short_sha = len(ref) >= 7 and len(ref) < 40 and re.match(r'^[a-f0-9]+$', ref)

        # Check if it's a tag (starts with v or is a version number)
        is_tag = ref.startswith("v") or re.match(r'^\d+\.\d+', ref)

        # If it's neither a SHA nor a tag, it might be a branch
        if not (is_full_sha or is_short_sha or is_tag):
            # Likely a branch or unpinned - handled by check_pinned_version
            continue

        # Case 1: Tag instead of SHA (medium severity)
        if is_tag and not (is_full_sha or is_short_sha):
            issues.append({
                "type": "no_hash_pinning",
                "severity": "medium",
                "message": f"Action '{action_ref}' uses version tag '{ref}' instead of an immutable commit SHA hash. Tags can be moved or overwritten, creating a security risk.",
                "action": action_ref,
                "tag": ref,
                "evidence": {
                    "action_reference": action_ref,
                    "action_name": action_name,
                    "reference_type": "version_tag",
                    "reference_value": ref,
                    "current_pinning": f"Tag: {ref}",
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/no_hash_pinning"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/no_hash_pinning"
            })

        # Case 2: Short SHA instead of full SHA (low severity)
        elif is_short_sha:
            issues.append({
                "type": "short_hash_pinning",
                "severity": "low",
                "message": f"Action '{action_ref}' uses short SHA '{ref}' ({len(ref)} characters) instead of the full 40-character commit SHA. While functional, full SHA provides better security.",
                "action": action_ref,
                "sha": ref,
                "evidence": {
                    "action_reference": action_ref,
                    "action_name": action_name,
                    "reference_type": "short_sha",
                    "reference_value": ref,
                    "sha_length": len(ref),
                    "current_pinning": f"Short SHA: {ref} ({len(ref)} chars)",
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/short_hash_pinning"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/short_hash_pinning"
            })

    return issues


async def check_ref_version_mismatch(content: Optional[str] = None, client: Optional[GitHubClient] = None) -> List[Dict[str, Any]]:
    """Check for SHA-pinned actions whose version comment does not match the SHA.

    A common convention is ``uses: owner/repo@<sha>  # v1.2.3``. If the comment's
    tag resolves to a different commit than the pinned SHA, the comment is
    misleading — the workflow is not actually running the version it claims to,
    which can hide a downgrade or a swapped commit.
    """
    issues = []
    if not content or not client:
        return issues

    # uses: owner/repo(/subpath)@<40-hex-sha>   # v1.2.3  (or  # 1.2.3)
    line_re = re.compile(
        r'uses:\s*["\']?([A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)@([0-9a-fA-F]{40})["\']?\s*#\s*(v?\d[\w.\-]*)',
    )

    seen = set()
    for raw_line in content.splitlines():
        m = line_re.search(raw_line)
        if not m:
            continue
        action_path, pinned_sha, comment_tag = m.group(1), m.group(2).lower(), m.group(3)
        owner = action_path.split("/")[0]
        repo = action_path.split("/")[1] if "/" in action_path else None
        if not repo:
            continue
        key = (owner, repo, pinned_sha, comment_tag)
        if key in seen:
            continue
        seen.add(key)

        try:
            resolved = await client.resolve_tag_to_sha(owner, repo, comment_tag)
        except Exception:
            continue

        if resolved and resolved.lower() != pinned_sha:
            issues.append({
                "type": "ref_version_mismatch",
                "severity": "medium",
                "message": f"Action '{owner}/{repo}' is pinned to SHA {pinned_sha[:7]} but its comment claims '{comment_tag}', which resolves to a different commit ({resolved[:7]}). The version comment is misleading.",
                "action": f"{owner}/{repo}@{pinned_sha}",
                "evidence": {
                    "action": f"{owner}/{repo}",
                    "pinned_sha": pinned_sha,
                    "comment_tag": comment_tag,
                    "tag_resolves_to": resolved,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/ref_version_mismatch"
                },
                "recommendation": f"Update the pinned SHA to match '{comment_tag}' ({resolved[:7]}), or correct the comment to reflect the commit actually in use. See: https://actsense.dev/vulnerabilities/ref_version_mismatch"
            })

    return issues


async def check_older_action_versions(workflow: Dict[str, Any], client: Optional[GitHubClient] = None) -> List[Dict[str, Any]]:
    """Check if actions in workflow use older versions (tags or commit hashes) that may have security vulnerabilities."""
    issues = []

    jobs = workflow.get("jobs", {})
    actions_used = set()

    # Extract all action references from workflow
    def extract_actions_from_value(value):
        if isinstance(value, dict):
            if "uses" in value:
                uses_value = value.get("uses", "")
                if isinstance(uses_value, str) and "/" in uses_value and "@" in uses_value:
                    actions_used.add(uses_value)
            for v in value.values():
                extract_actions_from_value(v)
        elif isinstance(value, list):
            for item in value:
                extract_actions_from_value(item)

    extract_actions_from_value(workflow)

    def parse_version(version_str: str) -> Optional[tuple]:
        """Parse version string into tuple for comparison (major, minor, patch)."""
        # Remove 'v' prefix if present
        if version_str.startswith("v"):
            version_str = version_str[1:]

        # Match semantic version: major.minor.patch
        match = re.match(r'^(\d+)\.?(\d*)?\.?(\d*)?', version_str)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2)) if match.group(2) else 0
            patch = int(match.group(3)) if match.group(3) else 0
            return (major, minor, patch)
        return None

    def is_sha(ref: str) -> bool:
        """Check if reference is a commit SHA (full or short)."""
        return len(ref) >= 7 and re.match(r'^[a-f0-9]+$', ref)

    def days_between_dates(date1_str: str, date2_str: str) -> Optional[int]:
        """Calculate how many days date1 is older than date2. Negative means date1 is newer."""
        try:
            from datetime import datetime
            date1 = datetime.fromisoformat(date1_str.replace('Z', '+00:00'))
            date2 = datetime.fromisoformat(date2_str.replace('Z', '+00:00'))
            return (date2 - date1).days
        except Exception:
            return None

    async def repository_exists(owner: Optional[str], repo: Optional[str]) -> Optional[bool]:
        """Return repository existence when detectable, otherwise None."""
        if not client or not owner or not repo:
            return None

        get_repo_info = getattr(client, "get_repository_info", None)
        if not callable(get_repo_info):
            return None

        cache_key = f"{owner}/{repo}"
        cached = repo_existence_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            repo_info = await get_repo_info(owner, repo)
            exists = repo_info is not None
            repo_existence_cache[cache_key] = exists
            return exists
        except Exception:
            # Do not guess repository existence on API errors.
            return None

    repo_existence_cache: Dict[str, bool] = {}

    # Check each action for older versions
    for action_ref in actions_used:
        if "@" not in action_ref:
            continue

        ref = action_ref.split("@")[-1]
        owner, repo, _, subdir = client.parse_action_reference(action_ref) if client else (None, None, None, None)

        # If repository is confirmed missing, skip older-version checks.
        # A missing repository is handled by check_missing_action_repositories.
        repo_exists = await repository_exists(owner, repo)
        if repo_exists is False:
            continue

        # Check if it's a SHA-based reference
        if is_sha(ref):
            if not client or not owner or not repo:
                continue  # Can't check SHA age without client

            try:
                # Get commit date for the SHA
                commit_date = await client.get_commit_date(owner, repo, ref)
                if not commit_date:
                    continue  # Couldn't fetch commit date

                # Get latest tag's commit date for comparison
                latest_tag_commit_date = await client.get_latest_tag_commit_date(owner, repo)

                if latest_tag_commit_date:
                    # Compare commit dates
                    days_old = days_between_dates(commit_date, latest_tag_commit_date)
                    if days_old and days_old > 365:  # More than 1 year old
                        # Show appropriate SHA format (full or short)
                        sha_display = ref[:7] if len(ref) >= 7 else ref
                        issues.append({
                            "type": "older_action_version",
                            "severity": "medium",
                            "message": f"Action '{action_ref}' uses commit SHA '{sha_display}...' which is {days_old} days older than the latest tag. Consider upgrading to a newer version for security fixes and improvements.",
                            "action": action_ref,
                            "version": ref,
                            "commit_date": commit_date,
                            "days_old": days_old,
                            "evidence": {
                                "action_reference": action_ref,
                                "reference_type": "commit_sha",
                                "reference_value": ref,
                                "commit_date": commit_date,
                                "days_old": days_old,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/older_action_version"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/older_action_version"
                        })
                else:
                    # Fallback: flag commits older than 1 year from now
                    from datetime import datetime, timezone
                    try:
                        commit_dt = datetime.fromisoformat(commit_date.replace('Z', '+00:00'))
                        now = datetime.now(timezone.utc)
                        days_old = (now - commit_dt).days
                        if days_old > 365:  # More than 1 year old
                            # Show appropriate SHA format (full or short)
                            sha_display = ref[:7] if len(ref) >= 7 else ref
                            issues.append({
                                "type": "older_action_version",
                                "severity": "medium",
                                "message": f"Action '{action_ref}' uses commit SHA '{sha_display}...' which is {days_old} days old. Consider upgrading to a newer version for security fixes and improvements.",
                                "action": action_ref,
                                "version": ref,
                                "commit_date": commit_date,
                                "days_old": days_old,
                                "evidence": {
                                    "action_reference": action_ref,
                                    "reference_type": "commit_sha",
                                    "reference_value": ref,
                                    "commit_date": commit_date,
                                    "days_old": days_old,
                                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/older_action_version"
                                },
                                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/older_action_version"
                            })
                    except Exception:
                        pass
            except Exception:
                # If we can't fetch commit info, skip
                pass
            continue

        # Check version tags
        current_version = parse_version(ref)
        if not current_version:
            continue  # Not a version tag we can parse

        # If we have a client, check the latest version from GitHub
        version_checked = False
        if client and owner and repo:
            try:
                # For subdirectory actions, we check the parent repo
                latest_tag = await client.get_latest_tag(owner, repo)
                if latest_tag:
                    latest_version = parse_version(latest_tag)
                    if latest_version:
                        version_checked = True
                        # A floating tag only pins the components it names: `v4`
                        # tracks every 4.x release, so it is only behind when the
                        # latest major is newer. Compare at the tag's precision.
                        precision = len(re.findall(r'\d+', ref.lstrip("v").split("-")[0])[:3]) or 1
                        if current_version[:precision] < latest_version[:precision]:
                            issues.append({
                                "type": "older_action_version",
                                "severity": "medium",
                                "message": f"Action '{action_ref}' uses version '{ref}', but the latest version is '{latest_tag}'. Consider upgrading for security fixes and improvements.",
                                "action": action_ref,
                                "version": ref,
                                "latest_version": latest_tag,
                                "evidence": {
                                    "action_reference": action_ref,
                                    "reference_type": "version_tag",
                                    "current_version": ref,
                                    "latest_version": latest_tag,
                                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/older_action_version"
                                },
                                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/older_action_version"
                            })
            except Exception:
                # If we can't fetch the latest version, fall back to heuristic
                pass

    return issues


def check_inconsistent_action_versions(workflow_actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Check for actions that are used with different versions across multiple workflows.

    Args:
        workflow_actions: List of dicts with keys:
            - 'workflow_name': Name of the workflow file
            - 'workflow_path': Path to the workflow file
            - 'actions': List of action references (e.g., 'owner/repo@v1')

    Returns:
        List of issues for each inconsistent action
    """
    issues = []

    # Build a map: action_name -> {version: [workflow_info]}
    # action_name is without version (e.g., 'owner/repo' or 'owner/repo/path')
    action_versions_map = {}

    for workflow_info in workflow_actions:
        workflow_name = workflow_info.get('workflow_name', '')
        workflow_path = workflow_info.get('workflow_path', '')
        actions = workflow_info.get('actions', [])

        for action_ref in actions:
            if "@" not in action_ref:
                continue

            # Split action name and version
            action_name, version = action_ref.rsplit("@", 1)

            # Normalize action name (remove any subdirectory for comparison)
            # We want to detect if actions/checkout@v2 and actions/checkout@v3 are used
            if action_name not in action_versions_map:
                action_versions_map[action_name] = {}

            if version not in action_versions_map[action_name]:
                action_versions_map[action_name][version] = []

            action_versions_map[action_name][version].append({
                'workflow_name': workflow_name,
                'workflow_path': workflow_path,
                'full_action_ref': action_ref
            })

    # Check for actions with multiple versions
    for action_name, versions_dict in action_versions_map.items():
        if len(versions_dict) > 1:
            # This action is used with multiple versions
            versions_list = list(versions_dict.keys())
            all_workflows = []

            # Collect all workflows using this action
            for version, workflows in versions_dict.items():
                for workflow in workflows:
                    all_workflows.append({
                        'version': version,
                        'workflow_name': workflow['workflow_name'],
                        'workflow_path': workflow['workflow_path'],
                        'full_action_ref': workflow['full_action_ref']
                    })

            # Create an issue for each version found (so users can see all instances)
            # But we'll create one main issue with details about all versions
            versions_str = ', '.join(sorted(versions_list))

            issues.append({
                "type": "inconsistent_action_version",
                "severity": "low",
                "message": f"Action '{action_name}' is used with different versions ({versions_str}) across {len(all_workflows)} workflow file(s). This can lead to inconsistent behavior and security vulnerabilities.",
                "action": action_name,
                "versions": versions_list,
                "version_count": len(versions_list),
                "workflows": all_workflows,
                "workflow_count": len(all_workflows),
                "evidence": {
                    "action_name": action_name,
                    "versions_found": versions_list,
                    "version_count": len(versions_list),
                    "workflow_count": len(all_workflows),
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/inconsistent_action_version"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/inconsistent_action_version"
                })

    return issues


def check_permissions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for overly permissive workflow permissions."""
    issues = []

    permissions = workflow.get("permissions", {})
    
    # Handle case where permissions is a string (e.g., "write-all")
    if isinstance(permissions, str):
        if permissions == "write-all":
            issues.append({
                "type": "overly_permissive",
                "severity": "high",
                "message": "Workflow has write permissions to repository contents. This increases the attack surface if the workflow is compromised.",
                "permissions": permissions,
                "evidence": {
                    "permissions": permissions,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/overly_permissive"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/overly_permissive"
            })
        return issues  # Can't check individual permissions if it's a string
    
    # Handle case where permissions is a dict
    if isinstance(permissions, dict):
        if permissions.get("contents") == "write":
            issues.append({
                "type": "overly_permissive",
                "severity": "high",
                "message": "Workflow has write permissions to repository contents. This increases the attack surface if the workflow is compromised.",
                "permissions": permissions,
                "evidence": {
                    "permissions": permissions,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/overly_permissive"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/overly_permissive"
            })
    
    if isinstance(permissions, dict) and permissions.get("actions") == "write":
        issues.append({
            "type": "overly_permissive",
            "severity": "high",
            "message": "Workflow has write permissions to GitHub Actions. This allows the workflow to modify or create actions, which is extremely dangerous.",
            "permissions": permissions,
            "evidence": {
                "permissions": permissions,
                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/overly_permissive"
            },
            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/overly_permissive"
        })

    return issues


def check_github_token_permissions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for GITHUB_TOKEN permissions that are too permissive."""
    issues = []

    permissions = workflow.get("permissions", {})
    jobs = workflow.get("jobs", {})

    # Check top-level permissions
    if permissions == "write-all":
        issues.append({
            "type": "github_token_write_all",
            "severity": "high",
            "message": "Workflow uses write-all permissions for GITHUB_TOKEN. This grants excessive access and significantly increases the attack surface.",
            "permissions": permissions,
            "evidence": {
                "permissions": "write-all",
                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/github_token_write_all"
            },
            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/github_token_write_all"
        })
    elif isinstance(permissions, dict):
        write_permissions = [k for k, v in permissions.items() if v == "write"]
        if write_permissions:
            issues.append({
                "type": "github_token_write_permissions",
                "severity": "high",
                "message": f"GITHUB_TOKEN has write permissions: {', '.join(write_permissions)}. Review if these are necessary.",
                "permissions": permissions,
                "evidence": {
                    "permissions": permissions,
                    "write_permissions": write_permissions,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/github_token_write_permissions"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/github_token_write_permissions"
            })

    # Check job-level permissions
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_permissions = job.get("permissions", {})
        if job_permissions == "write-all":
            issues.append({
                "type": "github_token_write_all",
                "severity": "high",
                "message": f"Job '{job_name}' uses write-all permissions for GITHUB_TOKEN",
                "job": job_name,
                "permissions": job_permissions,
                "evidence": {
                    "job": job_name,
                    "permissions": "write-all",
                    "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/github_token_write_all"
                },
                "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/github_token_write_all"
            })
        elif isinstance(job_permissions, dict):
            justified = _justified_write_scopes(job)
            write_perms = [k for k, v in job_permissions.items() if v == "write" and k not in justified]
            if write_perms:
                issues.append({
                    "type": "github_token_write_permissions",
                    "severity": "medium",
                    "message": f"Job '{job_name}' GITHUB_TOKEN has write permissions: {', '.join(write_perms)}",
                    "job": job_name,
                    "permissions": job_permissions,
                    "evidence": {
                        "job": job_name,
                        "permissions": job_permissions,
                        "write_permissions": write_perms,
                        "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/github_token_write_permissions"
                    },
                    "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/github_token_write_permissions"
                })

    return issues


def check_continue_on_error_critical_job(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for continue-on-error in critical jobs that should fail on error."""
    issues = []

    jobs = workflow.get("jobs", {})

    # Define critical job patterns
    critical_patterns = [
        'deploy', 'release', 'publish', 'build', 'test', 'security', 'audit',
        'lint', 'check', 'verify', 'validate', 'sign', 'push', 'production'
    ]

    for job_name, job in jobs.items():
        # Check if job is critical
        is_critical = any(pattern in job_name.lower() for pattern in critical_patterns)

        # Check for continue-on-error at job level
        if job.get("continue-on-error", False):
            if is_critical:
                issues.append({
                    "type": "continue_on_error_critical_job",
                    "severity": "medium",
                    "message": f"Job '{job_name}' is a critical job but has continue-on-error enabled. Failures may be silently ignored.",
                    "job": job_name,
                    "evidence": {
                        "job": job_name,
                        "continue_on_error": True,
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/continue_on_error_critical_job"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/continue_on_error_critical_job"
                })

        # Check for continue-on-error at step level in critical jobs
        if is_critical:
            steps = job.get("steps", [])
            for step in steps:
                if step.get("continue-on-error", False):
                    step_name = step.get("name", "unnamed")
                    # Check if step is critical
                    is_critical_step = any(pattern in step_name.lower() for pattern in critical_patterns)
                    if is_critical_step:
                        issues.append({
                            "type": "continue_on_error_critical_job",
                            "severity": "medium",
                            "message": f"Critical step '{step_name}' in job '{job_name}' has continue-on-error enabled. Failures may be silently ignored.",
                            "job": job_name,
                            "step": step_name,
                            "evidence": {
                                "job": job_name,
                                "step": step_name,
                                "continue_on_error": True,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/continue_on_error_critical_job"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/continue_on_error_critical_job"
                        })

    return issues


def check_excessive_write_permissions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for write-scoped tokens on jobs that look read-only (test/lint/scan...).

    Uses each job's *effective* permissions: job-level ``permissions`` replace
    the workflow-level block, so a read-only job in a workflow that grants
    write elsewhere is not reported.
    """
    issues = []
    read_only_operations = ('test', 'lint', 'check', 'validate', 'scan', 'audit', 'analyze', 'verify')
    write_operations = ('deploy', 'release', 'publish', 'push', 'tag', 'merge', 'commit', 'label', 'comment', 'update', 'bump', 'sync')

    jobs = workflow.get("jobs", {})
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        name_lower = f"{job_name} {job.get('name', '')}".lower()
        if not any(op in name_lower for op in read_only_operations):
            continue
        if any(op in name_lower for op in write_operations):
            continue
        permissions = _effective_permissions(workflow, job)
        if not _unjustified_writes(permissions, job):
            continue
        scope = "job" if "permissions" in job else "workflow"
        issues.append({
            "type": "excessive_write_permissions",
            "severity": "medium",
            "message": f"Job '{job_name}' appears to be read-only but its GITHUB_TOKEN has write permissions (set at the {scope} level). Grant write only to jobs that need it.",
            "job": job_name,
            "evidence": {
                "job": job_name,
                "permissions": permissions,
                "scope": scope,
                "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/excessive_write_permissions"
            },
            "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/excessive_write_permissions"
        })

    return issues


def check_artifact_retention(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for artifact retention settings."""
    issues = []

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if "actions/upload-artifact" in uses:
                with_params = step.get("with") if isinstance(step.get("with"), dict) else {}
                retention_days = with_params.get("retention-days")
                try:
                    retention_value = int(str(retention_days).strip())
                except (TypeError, ValueError):
                    continue  # unset, or an expression resolved at runtime
                if retention_value > 90:
                    issues.append({
                        "type": "long_artifact_retention",
                        "severity": "low",
                        "message": f"Job '{job_name}' has artifact retention > 90 days ({retention_days} days). This may violate data retention policies.",
                        "job": job_name,
                        "retention-days": retention_days,
                        "evidence": {
                            "job": job_name,
                            "retention_days": retention_days,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/long_artifact_retention"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/long_artifact_retention"
                    })

    return issues


def check_matrix_strategy(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for unsafe matrix strategy usage."""
    issues = []

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        strategy = job.get("strategy", {})
        matrix = strategy.get("matrix", {}) if isinstance(strategy, dict) else strategy

        if matrix:
            # Check if secrets are used in matrix
            matrix_str = str(matrix)
            if "${{" in matrix_str and "secrets" in matrix_str:
                issues.append({
                    "type": "secrets_in_matrix",
                    "severity": "critical",
                    "message": f"Job '{job_name}' uses secrets in matrix strategy. Secrets are exposed to all matrix job combinations, creating a critical security vulnerability.",
                    "job": job_name,
                    "evidence": {
                        "job": job_name,
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/secrets_in_matrix"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/secrets_in_matrix"
                })

            # Size is only knowable for a literal matrix (a fromJSON(...) matrix
            # is a string). include/exclude adjust combinations, not dimensions.
            if not isinstance(matrix, dict):
                continue
            total_combinations = 1
            for key, values in matrix.items():
                if key in ("include", "exclude"):
                    continue
                total_combinations *= len(values) if isinstance(values, list) else 1
            if isinstance(matrix.get("include"), list):
                total_combinations += len(matrix["include"])

            if total_combinations > 100:
                issues.append({
                    "type": "large_matrix",
                    "severity": "low",
                    "message": f"Job '{job_name}' has large matrix with {total_combinations} combinations. Large matrices may impact performance and costs.",
                    "job": job_name,
                    "combinations": total_combinations,
                    "evidence": {
                        "job": job_name,
                        "combinations": total_combinations,
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/large_matrix"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/large_matrix"
                })

    return issues


def check_workflow_dispatch_inputs(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for workflow_dispatch inputs without validation."""
    issues = []

    for input_name, input_def in _event_inputs(workflow, "workflow_dispatch").items():
        if isinstance(input_def, dict):
            input_type = input_def.get("type", "string")
            required = input_def.get("required", False)

            # Check if input is used without validation
            if not required and input_type == "string":
                # Flag only when the optional input is interpolated directly
                # into a run: command, where lack of validation is exploitable.
                if _input_used_in_run_command(workflow, input_name):
                    issues.append({
                        "type": "unvalidated_workflow_input",
                        "severity": "medium",
                        "message": f"Workflow_dispatch input '{input_name}' may be used without validation. Optional inputs should be validated to prevent security issues.",
                        "input": input_name,
                        "evidence": {
                            "input": input_name,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unvalidated_workflow_input"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unvalidated_workflow_input"
                    })

    return issues


def check_environment_secrets(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for environment secrets usage patterns."""
    issues = []

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        environment = job.get("environment", "")
        if environment:
            # Check if environment is used with secrets
            if isinstance(environment, dict):
                env_name = environment.get("name", "")
                if env_name:
                    # Check if secrets are accessed in this job
                    job_str = str(job)
                    if "secrets." in job_str:
                        issues.append({
                            "type": "environment_with_secrets",
                            "severity": "medium",
                            "message": f"Job '{job_name}' uses environment '{env_name}' with secrets. Ensure environment protection rules are configured.",
                            "job": job_name,
                            "environment": env_name,
                            "evidence": {
                                "job": job_name,
                                "environment": env_name,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/environment_with_secrets"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/environment_with_secrets"
                        })

    return issues


async def check_deprecated_actions(workflow: Dict[str, Any], client: Optional[GitHubClient] = None) -> List[Dict[str, Any]]:
    """Check for usage of deprecated actions and archived repositories."""
    issues = []

    # Known deprecated actions with replacement recommendations
    # action -> (first supported major, replacement advice). Majors below the
    # threshold are deprecated or have been shut off by GitHub: artifact
    # actions v1-v3 and cache v1-v2 stopped working in early 2025, and the
    # setup-* v1 majors run on removed Node runtimes.
    deprecated_majors = {
        "actions/upload-artifact": (4, "Upgrade to actions/upload-artifact@v4 or later; v1-v3 were shut down on GitHub.com in January 2025."),
        "actions/download-artifact": (4, "Upgrade to actions/download-artifact@v4 or later; v1-v3 were shut down on GitHub.com in January 2025."),
        "actions/cache": (3, "Upgrade to actions/cache@v4; v1 and v2 were shut down on GitHub.com in February 2025."),
        "actions/checkout": (2, "Upgrade to a supported actions/checkout major (v4 or later)."),
        "actions/setup-node": (2, "Use actions/setup-node@v4 or later"),
        "actions/setup-python": (2, "Use actions/setup-python@v5 or later"),
        "actions/setup-go": (2, "Use actions/setup-go@v5 or later"),
        "actions/setup-java": (2, "Use actions/setup-java@v4 or later"),
        "stefanzweifel/git-auto-commit-action": (4, "Use stefanzweifel/git-auto-commit-action@v4 or later"),
    }

    def deprecated_advice(uses_ref: str) -> Optional[str]:
        if "@" not in uses_ref:
            return None
        name, ref = uses_ref.rsplit("@", 1)
        rule = deprecated_majors.get(name.lower())
        major = re.match(r'^v?(\d+)(\.|$)', ref)
        if rule and major and int(major.group(1)) < rule[0]:
            return rule[1]
        return None

    jobs = workflow.get("jobs", {})
    checked_repos = {}  # Cache for repository archived status

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if not isinstance(uses, str) or not uses or uses.startswith(("./", "docker://")):
                continue

            # Extract action owner/repo for archived check
            action_owner = None
            action_repo = None
            if "/" in uses:
                action_part = uses.split("@")[0]  # Remove version/tag
                parts = action_part.split("/", 1)
                if len(parts) == 2:
                    action_owner = parts[0]
                    # Handle subdirectory actions (owner/repo/path)
                    repo_part = parts[1]
                    if "/" in repo_part:
                        action_repo = repo_part.split("/")[0]
                    else:
                        action_repo = repo_part

            # Check if repository is archived (if client is available)
            if client and action_owner and action_repo:
                repo_key = f"{action_owner}/{action_repo}"
                if repo_key not in checked_repos:
                    try:
                        repo_info = await client.get_repository_info(action_owner, action_repo)
                        if repo_info:
                            checked_repos[repo_key] = repo_info.get("archived", False)
                        else:
                            checked_repos[repo_key] = None  # Couldn't fetch (private or doesn't exist)
                    except Exception:
                        checked_repos[repo_key] = None  # Error fetching, skip archived check
                
                is_archived = checked_repos.get(repo_key)
                if is_archived is True:
                    issues.append({
                        "type": "deprecated_action",
                        "severity": "medium",
                        "message": f"Job '{job_name}' uses action '{uses}' from archived repository '{repo_key}'. Archived repositories are no longer maintained and may have security vulnerabilities.",
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "action": uses,
                        "evidence": {
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "action": uses,
                            "repository": repo_key,
                            "archived": True,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/deprecated_action"
                        },
                        "recommendation": f"Replace '{uses}' with an actively maintained alternative. Archived repositories receive no security updates."
                    })
                    continue  # Skip other checks if archived

            # Known-deprecated majors. (A generic "any @v1 is deprecated" guess
            # was removed: v1 is the current major of many maintained actions;
            # staleness is reported by the older_action_version check.)
            advice = deprecated_advice(uses) if isinstance(uses, str) else None
            if advice:
                issues.append({
                    "type": "deprecated_action",
                    "severity": "medium",
                    "message": f"Job '{job_name}' uses deprecated action '{uses}'. This version is no longer supported and may have security vulnerabilities or stop working.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "action": uses,
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "action": uses,
                        "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/deprecated_action"
                    },
                    "recommendation": advice
                })

    return issues


async def check_missing_action_repositories(workflow: Dict[str, Any], client: Optional[GitHubClient] = None) -> List[Dict[str, Any]]:
    """Check if any referenced action repositories don't exist or are inaccessible."""
    issues = []

    if not client:
        # Can't check without GitHub client
        return issues

    jobs = workflow.get("jobs", {})
    checked_repos = {}  # Cache for repository existence status

    async def _check_uses_ref(uses: str, job_name: str, step_name: str = ""):
        """Check a single uses reference for missing repositories."""
        if not uses or not isinstance(uses, str):
            return
        if uses.startswith(("./", "docker://", "http://", "https://")):
            return

        action_part = uses.split("@")[0].strip()
        if "/" not in action_part:
            return

        parts = action_part.split("/", 1)
        if len(parts) != 2:
            return

        action_owner = parts[0].strip()
        repo_path = parts[1].strip()
        if not action_owner:
            return

        repo_path_parts = repo_path.split("/")
        action_repo = repo_path_parts[0].strip()
        if not action_repo:
            return

        repo_key = f"{action_owner}/{action_repo}"
        if repo_key not in checked_repos:
            try:
                repo_info = await client.get_repository_info(action_owner, action_repo)
                checked_repos[repo_key] = repo_info is not None
            except Exception:
                return

        if checked_repos.get(repo_key) is False:
            issues.append({
                "type": "missing_action_repository",
                "severity": "critical",
                "message": f"Job '{job_name}' references action '{uses}' from repository '{repo_key}' that does not exist or is not accessible. This will cause workflow failures at runtime.",
                "job": job_name,
                "step": step_name,
                "action": uses,
                "evidence": {
                    "job": job_name,
                    "step": step_name,
                    "action": uses,
                    "repository": repo_key,
                    "exists": False,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/missing_action_repository"
                },
                "recommendation": f"Verify the action reference '{uses}' is correct. The repository '{repo_key}' may have been deleted, moved, made private, or the reference may contain a typo. Update the workflow to use a valid action reference."
            })

    for job_name, job in jobs.items():
        # Check job-level reusable workflows
        if isinstance(job, dict) and "uses" in job:
            await _check_uses_ref(job["uses"], job_name)

        # Check step-level actions
        steps = job.get("steps", []) if isinstance(job, dict) else []
        for step in steps:
            await _check_uses_ref(step.get("uses", ""), job_name, step.get("name", "unnamed"))

    return issues


def check_audit_logging(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for sensitive operations that should have detailed audit logging."""
    issues = []

    jobs = workflow.get("jobs", {})

    # Strong signals of a genuinely sensitive operation. Weak keywords such as
    # "token", "secret", "artifact", "upload" and "download" were removed: they
    # appear in almost every non-trivial job (e.g. any use of GITHUB_TOKEN or
    # upload-artifact) and made this check fire indiscriminately.
    sensitive_job_keywords = ("deploy", "publish", "release", "sign", "provision")

    # Deployment / publishing / signing commands seen in step run blocks.
    sensitive_run_pattern = re.compile(
        r'\b('
        r'docker\s+push|npm\s+publish|yarn\s+publish|twine\s+upload|'
        r'gh\s+release|helm\s+(install|upgrade)|terraform\s+apply|'
        r'kubectl\s+apply|cosign\s+sign|gpg\s+--sign|aws\s+deploy'
        r')\b',
        re.IGNORECASE,
    )

    for job_name, job in jobs.items():
        has_sensitive_ops = any(kw in job_name.lower() for kw in sensitive_job_keywords)

        if not has_sensitive_ops and isinstance(job, dict):
            for step in job.get("steps", []) or []:
                if not isinstance(step, dict):
                    continue
                run = step.get("run", "")
                if isinstance(run, str) and sensitive_run_pattern.search(run):
                    has_sensitive_ops = True
                    break

        if has_sensitive_ops:
            issues.append({
                "type": "insufficient_audit_logging",
                "severity": "low",
                "message": f"Job '{job_name}' performs sensitive operations that should have detailed audit logging. Insufficient logging makes forensic analysis difficult.",
                "job": job_name,
                "evidence": {
                    "job": job_name,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/insufficient_audit_logging"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/insufficient_audit_logging"
            })

    return issues


def check_unpinnable_docker_action(action_yml: Dict[str, Any], action_ref: str, dockerfile_content: Optional[str] = None) -> List[Dict[str, Any]]:
    """Check for unpinnable Docker actions (using mutable tags instead of digests)."""
    issues = []

    runs = action_yml.get("runs", {})
    if runs.get("using") == "docker":
        # Check for Docker image with mutable tag
        image = runs.get("image", "")
        if isinstance(image, str) and image.startswith("docker://"):
            # Registry image: pinned only by digest. No tag at all means :latest.
            ref = image[len("docker://"):]
            last_segment = ref.rsplit("/", 1)[-1]
            tag = last_segment.split(":", 1)[1] if ":" in last_segment else "latest"
            if "@sha256:" not in ref:
                issues.append({
                    "type": "unpinnable_docker_image",
                    "severity": "high",
                    "message": f"Docker action uses mutable tag '{tag}' instead of immutable digest. Tags can be moved or overwritten, creating a security risk.",
                    "action": action_ref,
                    "image": image,
                    "evidence": {
                        "action": action_ref,
                        "image": image,
                        "tag": tag,
                        "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinnable_docker_image"
                    },
                    "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinnable_docker_image"
                })

        # Check Dockerfile for unpinned dependencies (if Dockerfile path is specified)
        dockerfile_path = runs.get("image", "")
        if isinstance(dockerfile_path, str) and dockerfile_path and not dockerfile_path.startswith("docker://"):
            # This is a Dockerfile path
            content_to_check = dockerfile_content or ""

            # Check for unpinned Python packages (RUN lines, with continuations joined)
            run_text = re.sub(r'\\\n', ' ', content_to_check)
            if _pip_unpinned_packages(run_text):
                issues.append({
                    "type": "unpinned_dockerfile_dependencies",
                    "severity": "high",
                    "message": f"Docker action Dockerfile installs Python packages without version pinning. Unpinned packages can introduce security vulnerabilities.",
                    "action": action_ref,
                    "evidence": {
                        "action": action_ref,
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_dockerfile_dependencies"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_dockerfile_dependencies"
                })

            # Check for unpinned external resources
            if re.search(r'(wget|curl)\s+.*http', content_to_check, re.IGNORECASE) and not re.search(r'(sha256|sha512|md5|checksum)', content_to_check, re.IGNORECASE):
                issues.append({
                    "type": "unpinned_dockerfile_resources",
                    "severity": "high",
                    "message": f"Docker action Dockerfile downloads external resources without checksum verification. Downloaded resources can be tampered with.",
                    "action": action_ref,
                    "evidence": {
                        "action": action_ref,
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_dockerfile_resources"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_dockerfile_resources"
                })

    return issues


def check_unpinnable_composite_action(action_yml: Dict[str, Any], action_ref: str) -> List[Dict[str, Any]]:
    """Check for unpinnable composite actions (using unpinned sub-actions or dependencies)."""
    issues = []

    runs = action_yml.get("runs", {})
    if runs.get("using") == "composite":
        steps = runs.get("steps", [])
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    uses = step.get("uses", "")
                    if isinstance(uses, str) and "/" in uses:
                        # Check if sub-action is pinned to full commit SHA
                        if "@" in uses:
                            ref = uses.split("@")[-1]
                            # Check if it's a full commit SHA (40 chars) or short SHA (7+ chars)
                            if not (len(ref) >= 7 and re.match(r'^[a-f0-9]+$', ref)):
                                # It's using a tag or branch, not a commit SHA
                                issues.append({
                                    "type": "unpinnable_composite_subaction",
                                    "severity": "high",
                                    "message": f"Composite action uses sub-action '{uses}' without full commit SHA pinning. Tags and branches are mutable and pose security risks.",
                                    "action": action_ref,
                                    "subaction": uses,
                                    "evidence": {
                                        "action": action_ref,
                                        "subaction": uses,
                                        "reference": ref,
                                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinnable_composite_subaction"
                                    },
                                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinnable_composite_subaction"
                                })

                    run = step.get("run", "")
                    if isinstance(run, str):
                        normalized_run = " ".join(run.lower().split())
                        # Check for NPM install without version locking
                        npm_packages = _npm_unpinned_packages(run)
                        if npm_packages:
                            issues.append({
                                "type": "unpinned_npm_packages",
                                "severity": "high",
                                "message": f"Composite action installs NPM packages without version locking. Unpinned packages can introduce security vulnerabilities.",
                                "action": action_ref,
                                "evidence": {
                                    "action": action_ref,
                                    "packages": npm_packages,
                                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_npm_packages"
                                },
                                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_npm_packages"
                            })

                        # Check for pip install without version pinning
                        pip_packages = _pip_unpinned_packages(run)
                        if pip_packages:
                            issues.append({
                                "type": "unpinned_python_packages",
                                "severity": "high",
                                "message": f"Composite action installs Python packages without version pinning. Unpinned packages can introduce security vulnerabilities.",
                                "action": action_ref,
                                "evidence": {
                                    "action": action_ref,
                                    "packages": pip_packages,
                                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_python_packages"
                                },
                                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_python_packages"
                            })

                        # Check for downloading external resources without checksums
                        has_download = ("wget " in normalized_run) or ("curl " in normalized_run)
                        references_http = "http" in normalized_run
                        has_checksum = any(marker in normalized_run for marker in ("sha256", "sha512", "md5", "checksum"))
                        if has_download and references_http and not has_checksum:
                            issues.append({
                                "type": "unpinned_external_resources",
                                "severity": "high",
                                "message": f"Composite action downloads external resources without checksum verification. Downloaded resources can be tampered with.",
                                "action": action_ref,
                                "evidence": {
                                    "action": action_ref,
                                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_external_resources"
                                },
                                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_external_resources"
                            })

    return issues


def check_unpinnable_javascript_action(action_yml: Dict[str, Any], action_ref: str, action_content: Optional[str] = None) -> List[Dict[str, Any]]:
    """Check for unpinnable JavaScript actions (downloading external resources without checksums)."""
    issues = []

    runs = action_yml.get("runs", {})
    if str(runs.get("using", "")).lower() in ("node12", "node16", "node20", "node24"):
        # Check action code if available
        if action_content:
            # Check for downloading external resources without checksums
            if re.search(r'(wget|curl|fetch|download).*http', action_content, re.IGNORECASE) and not re.search(r'(sha256|sha512|md5|checksum|verify)', action_content, re.IGNORECASE):
                issues.append({
                    "type": "unpinned_javascript_resources",
                    "severity": "high",
                    "message": f"JavaScript action downloads external resources without checksum verification. Downloaded resources can be tampered with, creating supply chain risks.",
                    "action": action_ref,
                    "evidence": {
                        "action": action_ref,
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_javascript_resources"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_javascript_resources"
                })

    return issues


def _find_line_number(content: str, search_text: str, context: Optional[str] = None) -> Optional[int]:
    """Helper to find line number in content."""
    if not content:
        return None
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        if search_text.lower() in line.lower():
            if context:
                # Check surrounding lines for context
                start = max(0, i - 5)
                end = min(len(lines), i + 5)
                context_area = '\n'.join(lines[start:end]).lower()
                if context.lower() in context_area:
                    return i
            else:
                return i
    return None


def check_unpinned_container_images(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for unpinned container, service, and docker:// action images.

    Flags images that use mutable tags (e.g. 'node:20', 'postgres:latest')
    instead of immutable digests (e.g. 'node@sha256:abc...').
    """
    issues = []
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return issues

    def _is_pinned(image: str) -> bool:
        """An image is pinned if it references a digest via @sha256:."""
        return "@sha256:" in image

    def _check_image(image: str, job_name: str, source: str, service_name: str = "", step_name: str = ""):
        if not image or not isinstance(image, str):
            return
        # Skip expression-based images that are resolved at runtime
        if image.startswith("${{"):
            return
        if _is_pinned(image):
            return

        if source == "service":
            context = f"service '{service_name}' in job"
        elif source == "docker_action":
            context = f"Docker action step '{step_name}' in job"
        else:
            context = "job"
        issues.append({
            "type": "unpinned_container_image",
            "severity": "medium",
            "message": f"Container image '{image}' used by {context} '{job_name}' is not pinned to a digest. Mutable tags can be overwritten, leading to supply chain attacks.",
            "job": job_name,
            "step": step_name or None,
            "evidence": {
                "image": image,
                "job": job_name,
                "source": source,
                "service_name": service_name,
                "step": step_name,
                "vulnerability": "For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_container_image"
            },
            "recommendation": "For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_container_image"
        })

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue

        container = job.get("container")
        if isinstance(container, str):
            _check_image(container, job_name, "container")
        elif isinstance(container, dict):
            _check_image(container.get("image", ""), job_name, "container")

        services = job.get("services", {})
        if isinstance(services, dict):
            for svc_name, svc in services.items():
                if isinstance(svc, str):
                    _check_image(svc, job_name, "service", svc_name)
                elif isinstance(svc, dict):
                    _check_image(svc.get("image", ""), job_name, "service", svc_name)

        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            if isinstance(uses, str) and uses.startswith("docker://"):
                _check_image(uses, job_name, "docker_action", step_name=step.get("name", "unnamed"))

    return issues
