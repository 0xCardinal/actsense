"""Security vulnerability and best practice checks for GitHub Actions workflows."""
from typing import List, Dict, Any, Optional
import re
import subprocess
import tempfile
import json
import os
import base64
from github_client import GitHubClient
from fastapi import HTTPException
import sys
from pathlib import Path

# Add parent directory to path to import config_loader
sys.path.insert(0, str(Path(__file__).parent.parent))
from config_loader import get_trusted_publishers

# Security vulnerability and best practice checks

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
            # Also check if the value itself looks like a secret (long alphanumeric string)
            elif len(value) >= 20 and re.match(r'^[a-zA-Z0-9_\-]{20,}$', value) and path and re.search(r'(password|secret|token|key|api[_-]?key)', path, re.IGNORECASE):
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

    # Check for long-term credentials in jobs
    jobs = workflow.get("jobs", {})
    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            env = step.get("env", {})
            run = step.get("run", "")

            # Check for AWS credentials
            if any(key in env for key in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]):
                issues.append({
                    "type": "long_term_aws_credentials",
                    "severity": "high",
                    "message": f"Job '{job_name}' uses long-term AWS credentials instead of OIDC. Long-term credentials are less secure and harder to rotate.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "credential_type": "AWS long-term credentials",
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/long_term_cloud_credentials"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/long_term_cloud_credentials"
                })

            # Check for Azure credentials
            if any(key in env for key in ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"]):
                issues.append({
                    "type": "long_term_azure_credentials",
                    "severity": "high",
                    "message": f"Job '{job_name}' uses long-term Azure credentials instead of OIDC. Long-term credentials are less secure and harder to rotate.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "credential_type": "Azure long-term credentials",
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/long_term_cloud_credentials"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/long_term_cloud_credentials"
                })

            # Check for GCP credentials
            if "GOOGLE_APPLICATION_CREDENTIALS" in env or "GCP_SA_KEY" in env:
                issues.append({
                    "type": "long_term_gcp_credentials",
                    "severity": "high",
                    "message": f"Job '{job_name}' uses long-term GCP credentials instead of OIDC. Long-term credentials are less secure and harder to rotate.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "credential_type": "GCP long-term credentials",
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/long_term_cloud_credentials"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/long_term_cloud_credentials"
                })

            # Check for hardcoded credentials in run commands
            if isinstance(run, str):
                # Check for common credential patterns
                if re.search(r'(aws_access_key|aws_secret|azure_client_secret|gcp_key|service_account_key)', run, re.IGNORECASE):
                    issues.append({
                        "type": "potential_hardcoded_cloud_credentials",
                        "severity": "critical",
                        "message": f"Job '{job_name}' may contain hardcoded cloud credentials in run command. This is a critical security vulnerability.",
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "evidence": {
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/potential_hardcoded_cloud_credentials"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/potential_hardcoded_cloud_credentials"
                    })

    return issues


def check_self_hosted_runners(workflow: Dict[str, Any], is_public_repo: bool = False) -> List[Dict[str, Any]]:
    """Check for use of self-hosted runners and related security issues."""
    issues = []

    jobs = workflow.get("jobs", {})
    on_events = workflow.get("on", {})
    is_pr_triggered = "pull_request" in on_events or "pull_request_target" in on_events
    is_issue_triggered = "issues" in on_events

    def uses_self_hosted_runner(runs_on_value) -> bool:
        """Check if runs-on uses self-hosted runner."""
        if isinstance(runs_on_value, str):
            return "self-hosted" in runs_on_value.lower()
        elif isinstance(runs_on_value, list):
            return any("self-hosted" in str(r).lower() for r in runs_on_value)
        return False

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
                "severity": "critical",
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
        permissions = workflow.get("permissions", {})
        job_permissions = job.get("permissions", {})
        has_write_all = (
            permissions == "write-all" or 
            job_permissions == "write-all" or
            (isinstance(permissions, dict) and permissions.get("contents") == "write" and all(v == "write" for v in permissions.values())) or
            (isinstance(job_permissions, dict) and job_permissions.get("contents") == "write" and all(v == "write" for v in job_permissions.values()))
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

    # Common label confusion patterns
    confusing_labels = {
        "ubuntu-latest": "May be confused with GitHub-hosted runners",
        "windows-latest": "May be confused with GitHub-hosted runners",
        "macos-latest": "May be confused with GitHub-hosted runners",
        "linux": "Generic label that could be confused",
        "windows": "Generic label that could be confused",
        "macos": "Generic label that could be confused",
        "self-hosted-ubuntu": "Could be confused with ubuntu-latest",
        "self-hosted-windows": "Could be confused with windows-latest",
        "self-hosted-macos": "Could be confused with macos-latest",
    }

    for job_name, job in jobs.items():
        runs_on_value = job.get("runs-on", "")
        if not runs_on_value:
            continue

        # Parse runs-on (can be string or list)
        runners = []
        if isinstance(runs_on_value, str):
            runners = [runs_on_value]
        elif isinstance(runs_on_value, list):
            runners = [str(r) for r in runs_on_value]

        # Check if any runner is self-hosted
        has_self_hosted = any("self-hosted" in str(r).lower() for r in runners)
        if not has_self_hosted:
            continue

        # Check for confusing label combinations
        for runner in runners:
            runner_lower = runner.lower()
            if "self-hosted" not in runner_lower:
                continue

            for confusing_label, description in confusing_labels.items():
                if confusing_label in runner_lower or (len(runners) > 1 and any(confusing_label in str(r).lower() for r in runners)):
                    issues.append({
                        "type": "runner_label_confusion",
                        "severity": "high",
                        "message": f"Job '{job_name}' uses potentially confusing runner label. {description}",
                        "job": job_name,
                        "runner": runner,
                        "evidence": {
                            "job": job_name,
                            "runner": runner,
                            "confusing_label": confusing_label,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/runner_label_confusion"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/runner_label_confusion"
                    })
                    break  # Only report once per job

    return issues


def check_self_hosted_runner_secrets(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for secrets management issues with self-hosted runners."""
    issues = []

    jobs = workflow.get("jobs", {})

    # Pattern to detect secrets in run commands
    secrets_pattern = re.compile(r'\$\{\{\s*secrets\.[^}]+\}\}')

    for job_name, job in jobs.items():
        runs_on_value = job.get("runs-on", "")
        if not runs_on_value or "self-hosted" not in str(runs_on_value).lower():
            continue

        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str) and secrets_pattern.search(run):
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
        (r'curl.*\|\s*bash', 'curl piped to bash'),
        (r'wget.*\|\s*sh', 'wget piped to shell'),
        (r'Invoke-WebRequest.*\|\s*iex', 'PowerShell download and execute'),
        (r'docker\s+run.*--privileged', 'Docker with privileged mode'),
        (r'docker\s+run.*--cap-add', 'Docker with additional capabilities'),
    ]

    for job_name, job in jobs.items():
        runs_on_value = job.get("runs-on", "")
        if not runs_on_value or "self-hosted" not in str(runs_on_value).lower():
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
        runs_on_value = job.get("runs-on", "")
        if runs_on_value and "self-hosted" in str(runs_on_value).lower():
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


def check_dangerous_events(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for dangerous workflow trigger events."""
    issues = []

    on_events = workflow.get("on", {})

    # Check for pull_request_target (can be dangerous)
    if "pull_request_target" in on_events:
        # Check if workflow uses checkout with pull_request_target (critical vulnerability)
        has_checkout = False
        jobs = workflow.get("jobs", {})
        for job_name, job in jobs.items():
            steps = job.get("steps", [])
            for step in steps:
                uses = step.get("uses", "")
                if "actions/checkout" in uses:
                    has_checkout = True
                    # Check if it's checking out the PR branch (dangerous)
                    with_params = step.get("with", {})
                    ref = with_params.get("ref", "")
                    # If no ref specified or ref points to PR head, it's dangerous
                    if not ref or "pull_request.head" in str(ref) or "pull_request.head.sha" in str(ref):
                        issues.append({
                            "type": "insecure_pull_request_target",
                            "severity": "high",
                            "message": f"Workflow uses pull_request_target with checkout of PR code. This is a critical vulnerability that allows PRs from forks to execute code with write permissions.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "event": "pull_request_target",
                            "evidence": {
                                "event": "pull_request_target",
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "checkout_ref": ref or "default (PR branch)",
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/insecure_pull_request_target"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/insecure_pull_request_target"
                        })
                        break
                    # If checking out base branch, it's safer but still warn
                    elif "pull_request.base" in str(ref) or "base.ref" in str(ref):
                        # This is the safe pattern, but still warn about pull_request_target usage
                        pass

        # General warning about pull_request_target (if no critical checkout issue found)
        if not any(issue.get("type") == "insecure_pull_request_target" for issue in issues):
            issues.append({
                "type": "dangerous_event",
                "severity": "high",
                "message": "Workflow uses pull_request_target event which can be exploited by PRs from forks. This event runs with write permissions and can be dangerous.",
                "event": "pull_request_target",
                "evidence": {
                    "event": "pull_request_target",
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/dangerous_event"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/dangerous_event"
            })

    # Check for workflow_run (can be chained)
    if "workflow_run" in on_events:
        issues.append({
            "type": "dangerous_event",
            "severity": "medium",
            "message": "Workflow uses workflow_run event which can create dependency chains and potential security risks.",
            "event": "workflow_run",
            "evidence": {
                "event": "workflow_run",
                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/dangerous_event"
            },
            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/dangerous_event"
        })

    # Check for workflow_call without proper validation
    if "workflow_call" in on_events:
        inputs = on_events.get("workflow_call", {}).get("inputs", {})
        for input_name, input_def in inputs.items():
            if isinstance(input_def, dict):
                if input_def.get("type") == "string" and not input_def.get("required", False):
                    # Check if input might be used in dangerous ways
                    issues.append({
                        "type": "unvalidated_workflow_input",
                        "severity": "high",
                        "message": f"Workflow_call has optional input '{input_name}' without validation. Optional inputs should be validated to prevent security issues.",
                        "input": input_name,
                        "evidence": {
                            "input": input_name,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unvalidated_workflow_input"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unvalidated_workflow_input"
                    })

    return issues


def check_checkout_actions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for unsafe checkout action usage."""
    issues = []

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if "actions/checkout" in uses:
                with_params = step.get("with", {})

                # Check for persist-credentials
                if with_params.get("persist-credentials") == "true":
                    issues.append({
                        "type": "unsafe_checkout",
                        "severity": "high",
                        "message": f"Job '{job_name}' uses checkout with persist-credentials=true. This can expose credentials to subsequent steps.",
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "evidence": {
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "parameter": "persist-credentials=true",
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unsafe_checkout"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unsafe_checkout"
                    })

                # Check for ref without proper validation
                ref = with_params.get("ref")
                if ref and not ref.startswith("refs/"):
                    # Check if it's a variable that could be manipulated
                    if "${{" in str(ref):
                        issues.append({
                            "type": "unsafe_checkout_ref",
                            "severity": "medium",
                            "message": f"Job '{job_name}' uses checkout with potentially unsafe ref: {ref}. The ref may be manipulated if not properly validated.",
                            "job": job_name,
                            "ref": ref,
                            "evidence": {
                                "job": job_name,
                                "ref": ref,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unsafe_checkout_ref"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unsafe_checkout_ref"
                        })

                # Check for fetch-depth
                fetch_depth = with_params.get("fetch-depth")
                if fetch_depth == 0:
                    issues.append({
                        "type": "checkout_full_history",
                        "severity": "medium",
                        "message": f"Job '{job_name}' fetches full git history (fetch-depth: 0). This may expose sensitive information from commit history.",
                        "job": job_name,
                        "evidence": {
                            "job": job_name,
                            "fetch_depth": 0,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/checkout_full_history"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/checkout_full_history"
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

    # Dangerous commands with user input
    dangerous_command_patterns = [
        (r'curl.*\|.*bash', 'curl piped to bash'),
        (r'wget.*\|.*sh', 'wget piped to shell'),
        (r'echo.*\|.*sh', 'echo piped to shell'),
        (r'printf.*\|.*bash', 'printf piped to bash'),
    ]

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str):
                # Check for unsafe shell usage
                shell = step.get("shell", "")
                if shell and "bash" in shell.lower() and "-e" not in shell:
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
                    if re.search(pattern, run, re.IGNORECASE) and "${{" in run:
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
            if uses and "actions/github-script@" in uses:
                with_params = step.get("with", {})
                if with_params and "script" in with_params:
                    script = str(with_params["script"])

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


def check_risky_context_usage(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for risky GitHub context usage that can be exploited for injection attacks."""
    issues = []
    
    jobs = workflow.get("jobs", {})
    
    # Specific risky GitHub context patterns (user-controllable)
    risky_context_patterns = [
        # Issue-related
        (r'\$\{\{\s*github\.event\.issue\.title\s*\}\}', 'github.event.issue.title'),
        (r'\$\{\{\s*github\.event\.issue\.body\s*\}\}', 'github.event.issue.body'),
        # Issue comment
        (r'\$\{\{\s*github\.event\.issue_comment\.body\s*\}\}', 'github.event.issue_comment.body'),
        (r'\$\{\{\s*github\.event\.comment\.body\s*\}\}', 'github.event.comment.body'),
        # Pull request related
        (r'\$\{\{\s*github\.event\.pull_request\.title\s*\}\}', 'github.event.pull_request.title'),
        (r'\$\{\{\s*github\.event\.pull_request\.body\s*\}\}', 'github.event.pull_request.body'),
        (r'\$\{\{\s*github\.event\.pull_request\.head_ref\s*\}\}', 'github.event.pull_request.head_ref'),
        (r'\$\{\{\s*github\.event\.pull_request\.base_ref\s*\}\}', 'github.event.pull_request.base_ref'),
        # Release related
        (r'\$\{\{\s*github\.event\.release\.name\s*\}\}', 'github.event.release.name'),
        (r'\$\{\{\s*github\.event\.release\.tag_name\s*\}\}', 'github.event.release.tag_name'),
        # Discussion
        (r'\$\{\{\s*github\.event\.discussion\.body\s*\}\}', 'github.event.discussion.body'),
        # Ref and branch related
        (r'\$\{\{\s*github\.event\.ref\s*\}\}', 'github.event.ref'),
        (r'\$\{\{\s*github\.ref_name\s*\}\}', 'github.ref_name'),
        (r'\$\{\{\s*github\.event\.repository\.default_branch\s*\}\}', 'github.event.repository.default_branch'),
        # Label
        (r'\$\{\{\s*github\.event\.label\.name\s*\}\}', 'github.event.label.name'),
        # Sender
        (r'\$\{\{\s*github\.event\.sender\.email\s*\}\}', 'github.event.sender.email'),
        # Page
        (r'\$\{\{\s*github\.event\.page_name\s*\}\}', 'github.event.page_name'),
    ]
    
    # Generic patterns for risky suffixes (any context ending in these)
    risky_suffix_patterns = [
        (r'\$\{\{\s*github\.event\.[^}]*\.body\s*\}\}', 'context ending in .body'),
        (r'\$\{\{\s*github\.event\.[^}]*\.title\s*\}\}', 'context ending in .title'),
        (r'\$\{\{\s*github\.event\.[^}]*\.message\s*\}\}', 'context ending in .message'),
        (r'\$\{\{\s*github\.event\.[^}]*\.name\s*\}\}', 'context ending in .name'),
        (r'\$\{\{\s*github\.event\.[^}]*\.ref\s*\}\}', 'context ending in .ref'),
        (r'\$\{\{\s*github\.event\.[^}]*\.head_ref\s*\}\}', 'context ending in .head_ref'),
        (r'\$\{\{\s*github\.event\.[^}]*\.default_branch\s*\}\}', 'context ending in .default_branch'),
        (r'\$\{\{\s*github\.event\.[^}]*\.email\s*\}\}', 'context ending in .email'),
    ]
    
    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            found_contexts_in_run = []
            found_contexts_in_env = []
            found_contexts_in_with = []
            
            # Check in run commands (most dangerous - direct interpolation)
            run = step.get("run", "")
            if isinstance(run, str):
                # Check specific risky contexts
                for pattern, context_name in risky_context_patterns:
                    if re.search(pattern, run, re.IGNORECASE):
                        found_contexts_in_run.append(context_name)
                
                # Check generic risky suffix patterns
                for pattern, suffix_desc in risky_suffix_patterns:
                    matches = re.finditer(pattern, run, re.IGNORECASE)
                    for match in matches:
                        context_expr = match.group(0)
                        # Extract the actual context name
                        context_match = re.search(r'github\.event\.([^}]+)', context_expr)
                        if context_match:
                            context_name = context_match.group(1)
                            full_name = f"{context_name} ({suffix_desc})"
                            if full_name not in found_contexts_in_run:
                                found_contexts_in_run.append(full_name)
            
            # Check in environment variables (safer but still risky without validation)
            env = step.get("env", {})
            if isinstance(env, dict):
                for env_key, env_value in env.items():
                    if isinstance(env_value, str):
                        for pattern, context_name in risky_context_patterns:
                            if re.search(pattern, env_value, re.IGNORECASE):
                                if context_name not in found_contexts_in_env:
                                    found_contexts_in_env.append(context_name)
                        
                        for pattern, suffix_desc in risky_suffix_patterns:
                            matches = re.finditer(pattern, env_value, re.IGNORECASE)
                            for match in matches:
                                context_expr = match.group(0)
                                context_match = re.search(r'github\.event\.([^}]+)', context_expr)
                                if context_match:
                                    context_name = context_match.group(1)
                                    full_name = f"{context_name} ({suffix_desc})"
                                    if full_name not in found_contexts_in_env:
                                        found_contexts_in_env.append(full_name)
            
            # Check in with parameters
            with_params = step.get("with", {})
            if isinstance(with_params, dict):
                for param_key, param_value in with_params.items():
                    if isinstance(param_value, str):
                        for pattern, context_name in risky_context_patterns:
                            if re.search(pattern, param_value, re.IGNORECASE):
                                if context_name not in found_contexts_in_with:
                                    found_contexts_in_with.append(context_name)
                        
                        for pattern, suffix_desc in risky_suffix_patterns:
                            matches = re.finditer(pattern, param_value, re.IGNORECASE)
                            for match in matches:
                                context_expr = match.group(0)
                                context_match = re.search(r'github\.event\.([^}]+)', context_expr)
                                if context_match:
                                    context_name = context_match.group(1)
                                    full_name = f"{context_name} ({suffix_desc})"
                                    if full_name not in found_contexts_in_with:
                                        found_contexts_in_with.append(full_name)
            
            # Report direct use in run commands (most critical)
            if found_contexts_in_run:
                all_contexts = found_contexts_in_run + found_contexts_in_env + found_contexts_in_with
                unique_contexts = list(dict.fromkeys(all_contexts))  # Preserve order, remove duplicates
                issues.append({
                    "type": "risky_context_usage",
                    "severity": "critical",
                    "message": f"Job '{job_name}' uses risky GitHub context variables directly in shell commands (step: '{step.get('name', 'unnamed')}'). User-controllable context like {', '.join(found_contexts_in_run[:3])}{'...' if len(found_contexts_in_run) > 3 else ''} should be passed through environment variables and validated before use to prevent command injection attacks.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "risky_contexts": unique_contexts,
                        "usage_location": "run_command",
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/risky_context_usage"
                    },
                    "recommendation": "Move risky context variables to environment variables and add input validation. Never use ${{ github.event.* }} directly in shell commands. See: https://actsense.dev/vulnerabilities/risky_context_usage"
                })
            # Report use in environment variables (still risky without validation, but less critical)
            elif found_contexts_in_env:
                issues.append({
                    "type": "risky_context_usage",
                    "severity": "high",
                    "message": f"Job '{job_name}' uses risky GitHub context variables in environment variables (step: '{step.get('name', 'unnamed')}'). While using environment variables is safer than direct interpolation, these values must be validated before use to prevent injection attacks: {', '.join(found_contexts_in_env[:3])}{'...' if len(found_contexts_in_env) > 3 else ''}",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "risky_contexts": found_contexts_in_env,
                        "usage_location": "environment_variable",
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/risky_context_usage"
                    },
                    "recommendation": "Add input validation for environment variables containing user-controllable context. Validate against allowlists and sanitize before use. See: https://actsense.dev/vulnerabilities/risky_context_usage"
                })
            # Report use in with parameters
            elif found_contexts_in_with:
                issues.append({
                    "type": "risky_context_usage",
                    "severity": "high",
                    "message": f"Job '{job_name}' uses risky GitHub context variables in action parameters (step: '{step.get('name', 'unnamed')}'). These values should be validated: {', '.join(found_contexts_in_with[:3])}{'...' if len(found_contexts_in_with) > 3 else ''}",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "risky_contexts": found_contexts_in_with,
                        "usage_location": "action_parameter",
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/risky_context_usage"
                    },
                    "recommendation": "Validate risky context variables before passing to actions. Use allowlists and sanitize input. See: https://actsense.dev/vulnerabilities/risky_context_usage"
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
        (r'&\s*\$\{\{[^}]*\}\}', 'Call operator with user input'),
        (r'\.\s*\$\{\{[^}]*\}\}', 'Dot sourcing with user input'),
    ]

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            shell = step.get("shell", "")
            run = step.get("run", "")

            if isinstance(run, str) and (shell == "powershell" or shell == "pwsh") and "${{" in run:
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
                patterns = [
                    (r'curl\s+.*\|\s*(bash|sh|zsh)', 'curl piped to shell'),
                    (r'wget\s+.*\|\s*(bash|sh|zsh)', 'wget piped to shell'),
                    (r'curl\s+.*\|\s*/\s*bin/(bash|sh|zsh)', 'curl piped to absolute shell path'),
                    (r'wget\s+.*\|\s*/\s*bin/(bash|sh|zsh)', 'wget piped to absolute shell path'),
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
                    (r'echo\s+["\']?([A-Za-z0-9+/=]+)["\']?\s*\|\s*base64\s+-d\s*\|\s*(bash|sh|zsh)', 'base64 decode piped to shell'),
                    (r'base64\s+-d\s+.*\s*\|\s*(bash|sh|zsh)', 'base64 decode piped to shell'),
                    (r'base64\s+--decode\s+.*\s*\|\s*(bash|sh|zsh)', 'base64 decode piped to shell'),
                    (r'echo\s+["\']?([A-Za-z0-9+/=]+)["\']?\s*\|\s*base64\s+--decode\s*\|\s*(bash|sh|zsh)', 'base64 decode piped to shell'),
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
                obfuscation_patterns = [
                    (r'\$\{[^}]*\[.*\*.*\].*\}', 'Variable expansion with wildcards', 'high'),
                    (r'eval\s*\$\(.*base64.*\)', 'Base64 decoded eval', 'critical'),
                    (r'\$\(\$\(.*\)\)', 'Nested command substitution', 'medium'),
                    (r'\\x[0-9a-f]{2}', 'Hex-encoded characters', 'medium'),
                    (r'\$\{[^}]*#[^}]*\$\{\{[^}]*\}\}[^}]*\}', 'Parameter expansion with user input pattern removal', 'high'),
                    (r'\|\s*xxd\s*-r', 'Hex decode pipeline', 'high'),
                    (r'printf.*\\[0-9]{3}', 'Octal escape sequences', 'medium'),
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


def check_artipacked_vulnerability(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for artifact packing vulnerabilities."""
    issues = []

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if "upload-artifact" in uses or "download-artifact" in uses:
                with_params = step.get("with", {})

                # Check for overly broad path patterns
                if "path" in with_params:
                    path = str(with_params["path"])

                    # Dangerous patterns
                    dangerous_patterns = [
                        (r'^\.$', 'Current directory (.)'),
                        (r'^/\*$', 'Root wildcard (/*)'),
                        (r'^\*\*$', 'Double wildcard (**)'),
                        (r'\.\./', 'Path traversal (../)'),
                        (r'~', 'Home directory (~)'),
                    ]

                    for pattern, description in dangerous_patterns:
                        if re.search(pattern, path):
                            severity = "critical" if "../" in path else "high"
                            issues.append({
                                "type": "artipacked_vulnerability",
                                "severity": severity,
                                "message": f"Job '{job_name}' uses dangerous artifact path pattern: {description}. This may include sensitive files or enable path traversal.",
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "evidence": {
                                    "job": job_name,
                                    "step": step.get("name", "unnamed"),
                                    "path": path,
                                    "pattern": description,
                                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/artipacked_vulnerability"
                                },
                                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/artipacked_vulnerability"
                            })
                            break

                # Check for missing retention policies on upload-artifact
                if "upload-artifact" in uses:
                    if "retention-days" not in with_params:
                        issues.append({
                            "type": "artipacked_vulnerability",
                            "severity": "high",
                            "message": f"Job '{job_name}' uploads artifacts without explicit retention policy. Artifacts may store sensitive data indefinitely.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/artipacked_vulnerability"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/artipacked_vulnerability"
                        })

    return issues


def check_token_permission_escalation(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for patterns that could lead to token permission escalation."""
    issues = []

    jobs = workflow.get("jobs", {})

    # Patterns that could lead to permission escalation
    escalation_patterns = [
        (r'gh\s+auth\s+token', 'GitHub CLI token generation'),
        (r'GITHUB_TOKEN.*base64', 'GITHUB_TOKEN base64 encoding'),
        (r'echo.*GITHUB_TOKEN.*\|\s*base64', 'GITHUB_TOKEN base64 encoding via echo'),
        (r'curl.*-H.*Authorization.*Bearer.*GITHUB_TOKEN', 'GITHUB_TOKEN in curl Authorization header'),
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

    on_events = workflow.get("on", {})
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

    def is_untrusted_action(action_uses: str) -> bool:
        """Check if action is from untrusted publisher."""
        if not action_uses:
            return False
        for trusted in trusted_publishers:
            if action_uses.startswith(trusted):
                return False
        return True

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

            # Check for secrets in environment variables
            env = step.get("env", {})
            if env:
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
                    r'curl\s+.*(http|https)://',
                    r'wget\s+.*(http|https)://',
                    r'nc\s+.*\d+',
                    r'ncat\s+.*\d+',
                    r'ssh\s+.*@',
                ]
                for pattern in dangerous_patterns:
                    if re.search(pattern, run, re.IGNORECASE):
                        issues.append({
                            "type": "unfiltered_network_traffic",
                            "severity": "high",
                            "message": f"Job '{job_name}' performs network operations that could exfiltrate credentials or data. Unfiltered network traffic poses security risks.",
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

    # Check for build/deployment jobs that modify files
    for job_name, job in jobs.items():
        job_str = str(job).lower()
        is_build_job = any(keyword in job_str for keyword in ["build", "deploy", "release", "publish", "package"])

        if is_build_job:
            # Check for file modification operations
            steps = job.get("steps", [])
            for step in steps:
                run = step.get("run", "")
                if isinstance(run, str):
                    # Check for file write operations
                    if re.search(r'(>|>>|cp\s+|mv\s+|rm\s+|write|overwrite)', run, re.IGNORECASE):
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

    on_events = workflow.get("on", {})

    # Check for workflows that auto-approve PRs
    if "pull_request" in on_events or "pull_request_target" in on_events:
        jobs = workflow.get("jobs", {})
        for job_name, job in jobs.items():
            steps = job.get("steps", [])
            for step in steps:
                run = step.get("run", "")
                uses = step.get("uses", "")

                # Check for auto-approval or auto-merge
                if isinstance(run, str):
                    if re.search(r'(gh\s+pr\s+(review|merge|approve)|approve|merge|bypass)', run, re.IGNORECASE):
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


def check_code_injection_via_workflow_inputs(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for code injection via workflow inputs."""
    issues = []

    on_events = workflow.get("on", {})

    # Handle case where 'on' is a list (e.g., ["push", "pull_request"])
    if isinstance(on_events, list):
        # If 'on' is a list, workflow_dispatch won't be present
        return issues

    # Check workflow_dispatch inputs
    workflow_dispatch = on_events.get("workflow_dispatch", {}) if isinstance(on_events, dict) else {}
    if workflow_dispatch:
        inputs = workflow_dispatch.get("inputs", {})
        for input_name, input_def in inputs.items():
            if isinstance(input_def, dict):
                input_type = input_def.get("type", "string")
                if input_type == "string":
                    # Check if input is used in run commands without validation
                    workflow_str = str(workflow)
                    input_usage = f"${{{{ inputs.{input_name} }}}}"
                    if input_usage in workflow_str:
                        # Check if used in potentially dangerous contexts
                        if "run:" in workflow_str:
                            # Check for shell injection patterns
                            if any(pattern in workflow_str for pattern in [
                                f"${{{{ inputs.{input_name} }}}}",
                                f"${{{{ inputs.{input_name} }}}}",
                            ]):
                                issues.append({
                                    "type": "code_injection_via_input",
                                    "severity": "critical",
                                    "message": f"Workflow_dispatch input '{input_name}' may be vulnerable to code injection. User-controlled input is used in shell commands without proper validation.",
                                    "input": input_name,
                                    "evidence": {
                                        "input": input_name,
                                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/code_injection_via_input"
                                    },
                                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/code_injection_via_input"
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
    suspicious_patterns = [
        (r'action/[^/]+', 'Uses "action" instead of "actions" (singular)'),
        (r'actions/[^/]+-action', 'Uses "-action" suffix (uncommon for official actions)'),
        (r'actions/[^/]+action', 'Uses "action" without hyphen (uncommon)'),
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

    # Load trusted publishers from config file (removes trailing "/" for set comparison)
    # Config file location: backend/config.yaml
    # See config.yaml for instructions on adding trusted publishers
    trusted_publishers_list = get_trusted_publishers()
    trusted_publishers = {p.rstrip("/") for p in trusted_publishers_list}  # Convert to set without "/"

    jobs = workflow.get("jobs", {})
    actions_used = set()

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if isinstance(uses, str) and "/" in uses and "@" in uses:
                # Extract owner from action reference
                action_part = uses.split("@")[0]
                if "/" in action_part:
                    owner = action_part.split("/")[0]
                    actions_used.add((uses, owner, job_name, step.get("name", "unnamed")))

    # Check each action
    for action_ref, owner, job_name, step_name in actions_used:
        if owner.lower() not in trusted_publishers:
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
    """Run TruffleHog on workflow content to detect secrets."""
    issues = []

    try:
        # Create a temporary file with the workflow content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as tmp_file:
            tmp_file.write(content)
            tmp_file_path = tmp_file.name

        try:
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
                            raw = finding.get('Raw', '')

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
        finally:
            # Clean up temporary file
            if os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)

    except subprocess.TimeoutExpired:
        # TruffleHog timed out, skip silently
        pass
    except FileNotFoundError:
        # TruffleHog not installed, skip silently
        pass
    except Exception as e:
        # Any other error, skip silently
        pass

    return issues


# ============================================================================
# Best Practice Checks
# ============================================================================

def check_pinned_version(action_ref: str) -> Dict[str, Any]:
    """
    Check if action uses pinned version (tag or SHA).

    Returns detailed vulnerability information with evidence and mitigation steps.
    """
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
                "severity": "high",
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
        """Calculate days between two ISO 8601 date strings."""
        try:
            from datetime import datetime
            date1 = datetime.fromisoformat(date1_str.replace('Z', '+00:00'))
            date2 = datetime.fromisoformat(date2_str.replace('Z', '+00:00'))
            delta = abs((date2 - date1).days)
            return delta
        except Exception:
            return None

    # Check each action for older versions
    for action_ref in actions_used:
        if "@" not in action_ref:
            continue

        ref = action_ref.split("@")[-1]
        owner, repo, _, subdir = client.parse_action_reference(action_ref) if client else (None, None, None, None)

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
                        # Compare versions
                        if current_version < latest_version:
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

        # Fallback heuristic: Flag v1 and v2 as potentially outdated
        # This is only used when we can't fetch the latest version or client is not available
        if not version_checked and current_version[0] <= 2:
            issues.append({
                "type": "older_action_version",
                "severity": "medium",
                "message": f"Action '{action_ref}' uses version '{ref}' which may be outdated. Consider checking for newer versions for security fixes and improvements.",
                "action": action_ref,
                "version": ref,
                "major_version": current_version[0],
                "evidence": {
                    "action_reference": action_ref,
                    "reference_type": "version_tag",
                    "current_version": ref,
                    "major_version": current_version[0],
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/older_action_version"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/older_action_version"
            })

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
        job_permissions = job.get("permissions", {})
        if job_permissions == "write-all":
            issues.append({
                "type": "github_token_write_all",
                "severity": "high",
                "message": f"Job '{job_name}' uses write-all permissions for GITHUB_TOKEN",
                "job": job_name,
                "permissions": job_permissions
            })
        elif isinstance(job_permissions, dict):
            write_perms = [k for k, v in job_permissions.items() if v == "write"]
            if write_perms:
                issues.append({
                    "type": "github_token_write_permissions",
                    "severity": "medium",
                    "message": f"Job '{job_name}' GITHUB_TOKEN has write permissions: {', '.join(write_perms)}",
                    "job": job_name,
                    "permissions": job_permissions
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
    """Check for excessive write permissions on read-only workflows."""
    issues = []

    # Check if workflow has write permissions
    def has_write_permissions(wf: Dict[str, Any]) -> bool:
        permissions = wf.get("permissions", {})
        if permissions == "write-all" or permissions == "write":
            return True
        if isinstance(permissions, dict):
            for perm_value in permissions.values():
                if perm_value == "write":
                    return True
        # Check job-level permissions
        jobs = wf.get("jobs", {})
        for job in jobs.values():
            job_perms = job.get("permissions", {})
            if job_perms == "write-all" or job_perms == "write":
                return True
            if isinstance(job_perms, dict):
                for perm_value in job_perms.values():
                    if perm_value == "write":
                        return True
        return False

    if not has_write_permissions(workflow):
        return issues  # No write permissions, nothing to check

    # Check if workflow appears to be read-only
    read_only_operations = ['test', 'build', 'lint', 'check', 'validate', 'scan', 'audit', 'analyze']

    workflow_name = workflow.get("name", "").lower()
    if not workflow_name:
        # Try to infer from file path
        # This would need the file path, but we don't have it in the workflow dict
        # So we'll check job names instead
        jobs = workflow.get("jobs", {})
        for job_name in jobs.keys():
            job_name_lower = job_name.lower()
            for operation in read_only_operations:
                if operation in job_name_lower:
                    issues.append({
                        "type": "excessive_write_permissions",
                        "severity": "high",
                        "message": f"Workflow has write permissions but job '{job_name}' appears to be read-only. Consider using read-only permissions.",
                        "job": job_name,
                        "evidence": {
                            "job": job_name,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/excessive_write_permissions"
                        },
                        "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/excessive_write_permissions"
                    })
                    break

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
                with_params = step.get("with", {})
                retention_days = with_params.get("retention-days")
                if retention_days and int(retention_days) > 90:
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
        matrix = strategy.get("matrix", {})

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

            # Check for large matrix sizes
            matrix_sizes = [len(v) if isinstance(v, list) else 1 for v in matrix.values()]
            total_combinations = 1
            for size in matrix_sizes:
                total_combinations *= size

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

    on_events = workflow.get("on", {})
    # Handle case where 'on' is a list (e.g., ["push", "pull_request"])
    if isinstance(on_events, list):
        # If 'on' is a list, workflow_dispatch won't be present
        return issues
    
    # Handle case where 'on' is a dict
    workflow_dispatch = on_events.get("workflow_dispatch", {}) if isinstance(on_events, dict) else {}

    if workflow_dispatch:
        inputs = workflow_dispatch.get("inputs", {})
        for input_name, input_def in inputs.items():
            if isinstance(input_def, dict):
                input_type = input_def.get("type", "string")
                required = input_def.get("required", False)

                # Check if input is used without validation
                if not required and input_type == "string":
                    # Check if it's used in potentially unsafe contexts
                    workflow_str = str(workflow)
                    if f"${{{{ inputs.{input_name} }}}}" in workflow_str:
                        # Check for unsafe usage patterns
                        if any(pattern in workflow_str for pattern in [
                            f"${{{{ inputs.{input_name} }}}}",
                        ]):
                            # Check if used in shell commands
                            if "run:" in workflow_str:
                                issues.append({
                                    "type": "unvalidated_workflow_input",
                                    "severity": "high",
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
    deprecated_actions = {
        "actions/setup-node@v1": "Use actions/setup-node@v2 or later",
        "actions/setup-python@v1": "Use actions/setup-python@v2 or later",
        "actions/setup-go@v1": "Use actions/setup-go@v2 or later",
        "actions/setup-java@v1": "Use actions/setup-java@v2 or later",
        "actions/cache@v1": "Use actions/cache@v2 or later",
        "actions/upload-artifact@v1": "Use actions/upload-artifact@v2 or later",
        "actions/download-artifact@v1": "Use actions/download-artifact@v2 or later",
        "stefanzweifel/git-auto-commit-action@v2": "Use stefanzweifel/git-auto-commit-action@v4 or later",
    }

    jobs = workflow.get("jobs", {})
    checked_repos = {}  # Cache for repository archived status

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if not uses:
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

            # Check if action is in deprecated list
            if uses in deprecated_actions:
                issues.append({
                    "type": "deprecated_action",
                    "severity": "medium",
                    "message": f"Job '{job_name}' uses deprecated action '{uses}'. This version may have security vulnerabilities.",
                    "job": job_name,
                    "step": step.get("name", "unnamed"),
                    "action": uses,
                    "evidence": {
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "action": uses,
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/deprecated_action"
                    },
                    "recommendation": deprecated_actions[uses]
                })
            else:
                # Check for generic v1 versions (potentially deprecated)
                if "@v1" in uses and uses not in deprecated_actions:
                    # Extract action name without version
                    action_name = uses.split("@")[0]
                    # Skip if it's a well-known action that might legitimately use v1
                    if action_name not in ["actions/checkout", "actions/upload-artifact", "actions/download-artifact"]:
                        issues.append({
                            "type": "deprecated_action",
                            "severity": "medium",
                            "message": f"Job '{job_name}' uses action '{uses}' with v1 version. v1 versions are often deprecated in favor of newer versions.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "action": uses,
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "action": uses,
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/deprecated_action"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/deprecated_action"
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

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if not uses or not isinstance(uses, str):
                continue

            # Skip local paths, docker images, and URLs
            if uses.startswith(("./", "docker://", "http://", "https://")):
                continue

            # Extract action owner/repo
            action_owner = None
            action_repo = None
            
            # Remove version/tag to get just the repo reference
            action_part = uses.split("@")[0].strip()
            
            # Must have at least one slash for owner/repo format
            if "/" not in action_part:
                continue
            
            # Split into owner and rest
            parts = action_part.split("/", 1)
            if len(parts) != 2:
                continue
            
            action_owner = parts[0].strip()
            repo_path = parts[1].strip()
            
            # Validate owner is not empty
            if not action_owner:
                continue
            
            # Handle subdirectory actions (owner/repo/path/to/action)
            # The repo name is the first part after owner/
            repo_path_parts = repo_path.split("/")
            action_repo = repo_path_parts[0].strip()
            
            # Validate repo is not empty
            if not action_repo:
                continue

            # Check if repository exists (if client is available)
            if action_owner and action_repo:
                repo_key = f"{action_owner}/{action_repo}"
                if repo_key not in checked_repos:
                    try:
                        repo_info = await client.get_repository_info(action_owner, action_repo)
                        if repo_info is None:
                            # Repository doesn't exist or is inaccessible (404)
                            checked_repos[repo_key] = False
                        else:
                            # Repository exists
                            checked_repos[repo_key] = True
                    except HTTPException as e:
                        # For HTTP exceptions (rate limits, etc.), skip this check
                        # Don't assume repo is missing due to API errors
                        continue
                    except Exception:
                        # For other unexpected errors, skip this check
                        # Don't assume repo is missing due to errors
                        continue
                
                repo_exists = checked_repos.get(repo_key)
                if repo_exists is False:
                    issues.append({
                        "type": "missing_action_repository",
                        "severity": "high",
                        "message": f"Job '{job_name}' references action '{uses}' from repository '{repo_key}' that does not exist or is not accessible. This will cause workflow failures at runtime.",
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "action": uses,
                        "evidence": {
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "action": uses,
                            "repository": repo_key,
                            "exists": False,
                            "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/missing_action_repository"
                        },
                        "recommendation": f"Verify the action reference '{uses}' is correct. The repository '{repo_key}' may have been deleted, moved, made private, or the reference may contain a typo. Update the workflow to use a valid action reference."
                    })

    return issues


def check_audit_logging(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for sensitive operations that should have detailed audit logging."""
    issues = []

    jobs = workflow.get("jobs", {})

    # Check for sensitive operations that should be logged
    for job_name, job in jobs.items():
        job_str = str(job).lower()
        has_sensitive_ops = any(
            keyword in job_str for keyword in [
                "secret", "credential", "token", "deploy", "publish",
                "registry", "artifact", "upload", "download"
            ]
        )

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
        if isinstance(image, str):
            # Check if it uses a mutable tag (latest, v1, v2, etc.) instead of digest
            if ":" in image:
                tag = image.split(":")[-1]
                # Check if it's a digest (sha256:... or just a long hex string)
                if not (tag.startswith("sha256:") or (len(tag) >= 40 and re.match(r'^[a-f0-9]+$', tag))):
                    # It's a mutable tag
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
                                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinnable_docker_image"
                            },
                            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinnable_docker_image"
                    })

        # Check Dockerfile for unpinned dependencies (if Dockerfile path is specified)
        dockerfile_path = runs.get("image", "")
        if dockerfile_path and not dockerfile_path.startswith("docker://") and ":" not in dockerfile_path:
            # This is likely a Dockerfile path
            content_to_check = dockerfile_content or ""

            # Check for unpinned Python packages
            if re.search(r'pip\s+install\s+(?!.*==)', content_to_check, re.IGNORECASE):
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
                        # Check for NPM install without version locking
                        if re.search(r'npm\s+install\s+(?!.*@)', run, re.IGNORECASE) or re.search(r'npm\s+install\s+.*@latest', run, re.IGNORECASE):
                            issues.append({
                                "type": "unpinned_npm_packages",
                                "severity": "high",
                                "message": f"Composite action installs NPM packages without version locking. Unpinned packages can introduce security vulnerabilities.",
                                "action": action_ref,
                                "evidence": {
                                    "action": action_ref,
                                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_npm_packages"
                                },
                                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_npm_packages"
                            })

                        # Check for pip install without version pinning
                        if re.search(r'pip\s+install\s+(?!.*==)', run, re.IGNORECASE):
                            issues.append({
                                "type": "unpinned_python_packages",
                                "severity": "high",
                                "message": f"Composite action installs Python packages without version pinning. Unpinned packages can introduce security vulnerabilities.",
                                "action": action_ref,
                                "evidence": {
                                    "action": action_ref,
                                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/unpinned_python_packages"
                                },
                                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/unpinned_python_packages"
                            })

                        # Check for downloading external resources without checksums
                        if re.search(r'(wget|curl)\s+.*http', run, re.IGNORECASE) and not re.search(r'(sha256|sha512|md5|checksum)', run, re.IGNORECASE):
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
    if runs.get("using") == "node12" or runs.get("using") == "node16" or runs.get("using") == "node20":
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

