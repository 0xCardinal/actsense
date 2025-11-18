"""Security vulnerability checks for GitHub Actions workflows."""
from typing import List, Dict, Any, Optional
import re
import subprocess
import tempfile
import json
import os
from github_client import GitHubClient

# Security vulnerability checks

def check_secrets_in_workflow(workflow: Dict[str, Any], content: Optional[str] = None) -> List[Dict[str, Any]]:
    """Check for potential secret exposure issues and long-term credentials."""
    issues = []

    def check_value(value, path=""):
        if isinstance(value, str):
            # Check for hardcoded secrets patterns
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
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/long_term_aws_credentials"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/long_term_aws_credentials"
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
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/long_term_azure_credentials"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/long_term_azure_credentials"
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
                        "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/long_term_gcp_credentials"
                    },
                    "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/long_term_gcp_credentials"
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

    def has_untrusted_code_execution(job: Dict[str, Any]) -> bool:
        """Check if job executes potentially untrusted user input."""
        steps = job.get("steps", [])
        user_input_patterns = [
            r'\$\{\{\s*github\.event\.[^}]+\}\}',
            r'\$\{\{\s*github\.head_ref\s*\}\}',
            r'\$\{\{\s*github\.base_ref\s*\}\}',
        ]
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str):
                for pattern in user_input_patterns:
                    if re.search(pattern, run):
                        return True
        return False

    # Check each job for self-hosted runners
    for job_name, job in jobs.items():
        runs_on_value = job.get("runs-on", "")
        if not uses_self_hosted_runner(runs_on_value):
            continue

        # Basic self-hosted runner warning
        issues.append({
            "type": "self_hosted_runner",
            "severity": "medium",
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

        # Check for untrusted code execution (CRITICAL)
        if has_untrusted_code_execution(job):
            issues.append({
                "type": "self_hosted_runner_untrusted_code",
                "severity": "critical",
                "message": f"Self-hosted runner in job '{job_name}' executes potentially untrusted user input, creating code injection risk.",
                "job": job_name,
                "evidence": {
                    "job": job_name,
                    "runner": runs_on_value,
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_untrusted_code"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/self_hosted_runner_untrusted_code"
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
                        "severity": "medium",
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
            "severity": "high",
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
            "severity": "medium",
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
                            "severity": "critical",
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
                        "severity": "medium",
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
                        "severity": "low",
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
                            "severity": "high",
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
    """Check for base64 decode execution patterns, which can hide malicious code."""
    issues = []

    jobs = workflow.get("jobs", {})

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run", "")
            if isinstance(run, str):
                # Check for base64 decode execution patterns
                patterns = [
                    (r'echo\s+["\']?[A-Za-z0-9+/=]+["\']?\s*\|\s*base64\s+-d\s*\|\s*(bash|sh|zsh)', 'base64 decode piped to shell'),
                    (r'base64\s+-d\s+.*\s*\|\s*(bash|sh|zsh)', 'base64 decode piped to shell'),
                    (r'base64\s+--decode\s+.*\s*\|\s*(bash|sh|zsh)', 'base64 decode piped to shell'),
                    (r'echo\s+["\']?[A-Za-z0-9+/=]+["\']?\s*\|\s*base64\s+--decode\s*\|\s*(bash|sh|zsh)', 'base64 decode piped to shell'),
                    (r'eval\s*\(\s*base64\s+-d', 'eval with base64 decode'),
                    (r'eval\s*\(\s*base64\s+--decode', 'eval with base64 decode'),
                ]

                for pattern, description in patterns:
                    if re.search(pattern, run, re.IGNORECASE):
                        issues.append({
                            "type": "malicious_base64_decode",
                            "severity": "critical",
                            "message": f"Job '{job_name}' contains {description}. This pattern can hide and execute malicious code.",
                            "job": job_name,
                            "step": step.get("name", "unnamed"),
                            "evidence": {
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "pattern": description,
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
                            severity = "high" if "../" in path else "medium"
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
                            "severity": "low",
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
                                "severity": "medium",
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
                            "severity": "medium",
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

    # List of trusted action publishers
    trusted_publishers = [
        "actions/",
        "github/",
        "microsoft/",
        "azure/",
        "docker/",
        "hashicorp/",
        "google-github-actions/",
        "aws-actions/",
        "step-security/",
    ]

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
                        "severity": "high",
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
                            "severity": "medium",
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
                            "severity": "medium",
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

    # Check workflow_dispatch inputs
    workflow_dispatch = on_events.get("workflow_dispatch", {})
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
                                    "severity": "high",
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

    # List of known trusted action publishers
    trusted_publishers = {
        "actions",  # GitHub official actions
        "github",   # GitHub official
        "microsoft",  # Microsoft
        "azure",     # Azure
        "docker",    # Docker
        "hashicorp", # HashiCorp
        "google-github-actions", # Google
        "aws-actions", # AWS
        "step-security", # Step Security
    }

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

