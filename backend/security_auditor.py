"""Security issue detection for GitHub Actions."""
from typing import List, Dict, Any, Optional
import re


class SecurityAuditor:
    @staticmethod
    def check_pinned_version(action_ref: str) -> Dict[str, Any]:
        """Check if action uses pinned version (tag or SHA)."""
        issue = {
            "type": "unpinned_version",
            "severity": "high",
            "message": "",
            "action": action_ref
        }
        
        if "@" not in action_ref:
            issue["message"] = "Action reference missing version/tag"
            return issue
        
        ref = action_ref.split("@")[-1]
        
        # Check if it's a branch (not pinned)
        if not ref.startswith("v") and len(ref) < 7:
            issue["message"] = f"Action uses branch reference '{ref}' instead of pinned version"
            return issue
        
        # Check if it's a SHA (40 chars for full SHA, 7+ for short)
        if len(ref) >= 7 and re.match(r'^[a-f0-9]+$', ref):
            return None  # Pinned with SHA
        
        # Check if it's a version tag
        if ref.startswith("v") or re.match(r'^\d+\.\d+', ref):
            return None  # Pinned with version tag
        
        issue["message"] = f"Action may use unpinned reference '{ref}'"
        return issue

    @staticmethod
    def check_hash_pinning(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if actions in workflow use hash pinning (commit SHA) instead of tags."""
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
            if "@" in action_ref:
                ref = action_ref.split("@")[-1]
                
                # Check if it's a full commit SHA (40 characters)
                is_full_sha = len(ref) == 40 and re.match(r'^[a-f0-9]+$', ref)
                
                # Check if it's a short SHA (7+ characters)
                is_short_sha = len(ref) >= 7 and len(ref) < 40 and re.match(r'^[a-f0-9]+$', ref)
                
                # Check if it's a tag (starts with v or is a version number)
                is_tag = ref.startswith("v") or re.match(r'^\d+\.\d+', ref)
                
                # If it's neither a SHA nor a tag, it might be a branch
                if not (is_full_sha or is_short_sha or is_tag):
                    # Likely a branch or unpinned
                    continue
                
                # If it's a tag but not a SHA, flag it
                if is_tag and not (is_full_sha or is_short_sha):
                    issues.append({
                        "type": "no_hash_pinning",
                        "severity": "medium",
                        "message": f"Action '{action_ref}' uses tag '{ref}' instead of commit SHA hash",
                        "action": action_ref,
                        "tag": ref,
                        "recommendation": "Pin actions to full commit SHA (40 characters) for maximum security. Tags can be moved or overwritten."
                    })
                elif is_short_sha:
                    # Short SHA is acceptable but full SHA is preferred
                    issues.append({
                        "type": "short_hash_pinning",
                        "severity": "low",
                        "message": f"Action '{action_ref}' uses short SHA '{ref}' instead of full 40-character commit SHA",
                        "action": action_ref,
                        "sha": ref,
                        "recommendation": "Use full 40-character commit SHA for maximum security and immutability"
                    })
        
        return issues

    @staticmethod
    def check_secrets_in_workflow(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potential secret exposure issues."""
        issues = []
        
        def check_value(value, path=""):
            if isinstance(value, str):
                # Check for hardcoded secrets patterns
                if re.search(r'(password|secret|token|key|api[_-]?key)\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}', value, re.IGNORECASE):
                    issues.append({
                        "type": "potential_hardcoded_secret",
                        "severity": "critical",
                        "message": f"Potential hardcoded secret found at {path}",
                        "path": path
                    })
            elif isinstance(value, dict):
                for k, v in value.items():
                    check_value(v, f"{path}.{k}" if path else k)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    check_value(item, f"{path}[{i}]" if path else f"[{i}]")
        
        check_value(workflow)
        return issues

    @staticmethod
    def check_permissions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for overly permissive workflow permissions."""
        issues = []
        
        permissions = workflow.get("permissions", {})
        if permissions == "write-all" or permissions.get("contents") == "write":
            issues.append({
                "type": "overly_permissive",
                "severity": "medium",
                "message": "Workflow has write permissions to contents",
                "permissions": permissions
            })
        
        if permissions.get("actions") == "write":
            issues.append({
                "type": "overly_permissive",
                "severity": "high",
                "message": "Workflow has write permissions to actions",
                "permissions": permissions
            })
        
        return issues

    @staticmethod
    def check_self_hosted_runners(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for use of self-hosted runners."""
        issues = []
        
        runs_on = workflow.get("on", {}).get("workflow_run", {})
        jobs = workflow.get("jobs", {})
        
        for job_name, job in jobs.items():
            runs_on_value = job.get("runs-on", "")
            if isinstance(runs_on_value, str) and runs_on_value != "ubuntu-latest" and "self-hosted" in runs_on_value.lower():
                issues.append({
                    "type": "self_hosted_runner",
                    "severity": "medium",
                    "message": f"Job '{job_name}' uses self-hosted runner",
                    "job": job_name,
                    "runs-on": runs_on_value
                })
        
        return issues

    @staticmethod
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
                "message": "Workflow uses write-all permissions for GITHUB_TOKEN",
                "permissions": permissions
            })
        elif isinstance(permissions, dict):
            write_permissions = [k for k, v in permissions.items() if v == "write"]
            if write_permissions:
                issues.append({
                    "type": "github_token_write_permissions",
                    "severity": "medium",
                    "message": f"GITHUB_TOKEN has write permissions: {', '.join(write_permissions)}",
                    "permissions": permissions
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

    @staticmethod
    def check_dangerous_events(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for dangerous workflow trigger events."""
        issues = []
        
        on_events = workflow.get("on", {})
        
        # Check for pull_request_target (can be dangerous)
        if "pull_request_target" in on_events:
            issues.append({
                "type": "dangerous_event",
                "severity": "high",
                "message": "Workflow uses pull_request_target event which can be exploited by PRs from forks",
                "event": "pull_request_target"
            })
        
        # Check for workflow_run (can be chained)
        if "workflow_run" in on_events:
            issues.append({
                "type": "dangerous_event",
                "severity": "medium",
                "message": "Workflow uses workflow_run event which can create dependency chains",
                "event": "workflow_run"
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
                            "message": f"Workflow_call has optional input '{input_name}' without validation",
                            "input": input_name
                        })
        
        return issues

    @staticmethod
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
                            "message": f"Job '{job_name}' uses checkout with persist-credentials=true",
                            "job": job_name,
                            "step": step.get("name", "unnamed")
                        })
                    
                    # Check for ref without proper validation
                    ref = with_params.get("ref")
                    if ref and not ref.startswith("refs/"):
                        # Check if it's a variable that could be manipulated
                        if "${{" in str(ref):
                            issues.append({
                                "type": "unsafe_checkout_ref",
                                "severity": "medium",
                                "message": f"Job '{job_name}' uses checkout with potentially unsafe ref: {ref}",
                                "job": job_name,
                                "ref": ref
                            })
                    
                    # Check for fetch-depth
                    fetch_depth = with_params.get("fetch-depth")
                    if fetch_depth == 0:
                        issues.append({
                            "type": "checkout_full_history",
                            "severity": "low",
                            "message": f"Job '{job_name}' fetches full git history (fetch-depth: 0)",
                            "job": job_name
                        })
        
        return issues

    @staticmethod
    def check_script_injection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potential script injection vulnerabilities."""
        issues = []
        
        jobs = workflow.get("jobs", {})
        
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
                            "message": f"Job '{job_name}' uses bash without -e flag (errors not caught)",
                            "job": job_name,
                            "step": step.get("name", "unnamed")
                        })
                    
                    # Check for direct variable interpolation in commands
                    if "${{" in run and "github.event" in run:
                        # Check if it's used in a potentially unsafe way
                        if any(pattern in run.lower() for pattern in ["curl", "wget", "eval", "exec", "$("]):
                            issues.append({
                                "type": "potential_script_injection",
                                "severity": "high",
                                "message": f"Job '{job_name}' may have script injection risk with github.event variables",
                                "job": job_name,
                                "step": step.get("name", "unnamed")
                            })
        
        return issues

    @staticmethod
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
                            "message": f"Job '{job_name}' has artifact retention > 90 days ({retention_days} days)",
                            "job": job_name,
                            "retention-days": retention_days
                        })
        
        return issues

    @staticmethod
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
                        "message": f"Job '{job_name}' uses secrets in matrix strategy (secrets exposed to all matrix jobs)",
                        "job": job_name
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
                        "message": f"Job '{job_name}' has large matrix with {total_combinations} combinations",
                        "job": job_name,
                        "combinations": total_combinations
                    })
        
        return issues

    @staticmethod
    def check_workflow_dispatch_inputs(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for workflow_dispatch inputs without validation."""
        issues = []
        
        on_events = workflow.get("on", {})
        workflow_dispatch = on_events.get("workflow_dispatch", {})
        
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
                                        "severity": "medium",
                                        "message": f"Workflow_dispatch input '{input_name}' may be used without validation",
                                        "input": input_name
                                    })
        
        return issues

    @staticmethod
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
                                "severity": "low",
                                "message": f"Job '{job_name}' uses environment '{env_name}' with secrets",
                                "job": job_name,
                                "environment": env_name
                            })
        
        return issues

    @staticmethod
    def check_untrusted_third_party_actions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for use of untrusted third-party GitHub Actions."""
        issues = []
        
        # List of known trusted action publishers
        trusted_publishers = {
            "actions",  # GitHub official actions
            "github",   # GitHub official
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
                        actions_used.add((uses, owner))
        
        # Check each action
        for action_ref, owner in actions_used:
            if owner.lower() not in trusted_publishers:
                # Check if it's pinned (has version tag or SHA)
                if "@" in action_ref:
                    ref = action_ref.split("@")[-1]
                    # Check if it's a branch (unpinned)
                    if not ref.startswith("v") and len(ref) < 7 and not re.match(r'^[a-f0-9]{7,}$', ref):
                        issues.append({
                            "type": "untrusted_action_unpinned",
                            "severity": "high",
                            "message": f"Untrusted third-party action '{action_ref}' is not pinned to a specific version",
                            "action": action_ref,
                            "owner": owner
                        })
                    else:
                        issues.append({
                            "type": "untrusted_third_party_action",
                            "severity": "medium",
                            "message": f"Workflow uses third-party action from untrusted publisher: '{action_ref}'",
                            "action": action_ref,
                            "owner": owner
                        })
        
        return issues

    @staticmethod
    def check_long_term_credentials(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for use of long-term credentials instead of OIDC."""
        issues = []
        
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
                        "message": f"Job '{job_name}' uses long-term AWS credentials instead of OIDC",
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "recommendation": "Use GitHub OIDC to authenticate with AWS"
                    })
                
                # Check for Azure credentials
                if any(key in env for key in ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"]):
                    issues.append({
                        "type": "long_term_azure_credentials",
                        "severity": "high",
                        "message": f"Job '{job_name}' uses long-term Azure credentials instead of OIDC",
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "recommendation": "Use GitHub OIDC to authenticate with Azure"
                    })
                
                # Check for GCP credentials
                if "GOOGLE_APPLICATION_CREDENTIALS" in env or "GCP_SA_KEY" in env:
                    issues.append({
                        "type": "long_term_gcp_credentials",
                        "severity": "high",
                        "message": f"Job '{job_name}' uses long-term GCP credentials instead of OIDC",
                        "job": job_name,
                        "step": step.get("name", "unnamed"),
                        "recommendation": "Use GitHub OIDC to authenticate with GCP"
                    })
                
                # Check for hardcoded credentials in run commands
                if isinstance(run, str):
                    # Check for common credential patterns
                    if re.search(r'(aws_access_key|aws_secret|azure_client_secret|gcp_key|service_account_key)', run, re.IGNORECASE):
                        issues.append({
                            "type": "potential_hardcoded_cloud_credentials",
                            "severity": "critical",
                            "message": f"Job '{job_name}' may contain hardcoded cloud credentials in run command",
                            "job": job_name,
                            "step": step.get("name", "unnamed")
                        })
        
        return issues

    @staticmethod
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
                                "message": f"Job '{job_name}' performs network operations that could exfiltrate credentials or data",
                                "job": job_name,
                                "step": step.get("name", "unnamed"),
                                "recommendation": "Implement network segmentation and traffic filtering to prevent credential exfiltration"
                            })
                            break
        
        return issues

    @staticmethod
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
                                "message": f"Build job '{job_name}' modifies files, which could be tampered with during build",
                                "job": job_name,
                                "recommendation": "Implement endpoint detection and response (EDR) tools to detect source code or artifact tampering during build"
                            })
                            break
        
        return issues

    @staticmethod
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
                    "severity": "medium",
                    "message": f"Job '{job_name}' performs sensitive operations that should have detailed audit logging",
                    "job": job_name,
                    "recommendation": "Keep detailed audit logs for CI/CD activities to enable forensic analysis"
                })
        
        return issues

    @staticmethod
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
                                "message": f"Workflow may auto-approve/merge PRs, bypassing branch protection rules",
                                "job": job_name,
                                "step": step.get("name", "unnamed")
                            })
                    
                    if isinstance(uses, str):
                        if "auto-approve" in uses.lower() or "auto-merge" in uses.lower():
                            issues.append({
                                "type": "branch_protection_bypass",
                                "severity": "high",
                                "message": f"Workflow uses action that may auto-approve/merge PRs",
                                "job": job_name,
                                "action": uses
                            })
        
        return issues

    @staticmethod
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
                                        "message": f"Workflow_dispatch input '{input_name}' may be vulnerable to code injection",
                                        "input": input_name,
                                        "recommendation": "Validate and sanitize workflow inputs before use in shell commands"
                                    })
        
        return issues

    @staticmethod
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
                            "message": f"Docker action uses mutable tag '{tag}' instead of immutable digest",
                            "action": action_ref,
                            "image": image,
                            "recommendation": "Use Docker image digest (sha256:...) instead of tags to ensure immutability"
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
                        "message": f"Docker action Dockerfile installs Python packages without version pinning",
                        "action": action_ref,
                        "recommendation": "Pin all package versions in Dockerfile (e.g., pip install package==1.2.3)"
                    })
                
                # Check for unpinned external resources
                if re.search(r'(wget|curl)\s+.*http', content_to_check, re.IGNORECASE) and not re.search(r'(sha256|sha512|md5|checksum)', content_to_check, re.IGNORECASE):
                    issues.append({
                        "type": "unpinned_dockerfile_resources",
                        "severity": "high",
                        "message": f"Docker action Dockerfile downloads external resources without checksum verification",
                        "action": action_ref,
                        "recommendation": "Verify checksums for all downloaded external resources"
                    })
        
        return issues

    @staticmethod
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
                                        "message": f"Composite action uses sub-action '{uses}' without full commit SHA pinning",
                                        "action": action_ref,
                                        "subaction": uses,
                                        "recommendation": "Pin all sub-actions to full commit SHA for immutability"
                                    })
                        
                        run = step.get("run", "")
                        if isinstance(run, str):
                            # Check for NPM install without version locking
                            if re.search(r'npm\s+install\s+(?!.*@)', run, re.IGNORECASE) or re.search(r'npm\s+install\s+.*@latest', run, re.IGNORECASE):
                                issues.append({
                                    "type": "unpinned_npm_packages",
                                    "severity": "high",
                                    "message": f"Composite action installs NPM packages without version locking",
                                    "action": action_ref,
                                    "recommendation": "Lock NPM package versions (use package-lock.json or specify exact versions)"
                                })
                            
                            # Check for pip install without version pinning
                            if re.search(r'pip\s+install\s+(?!.*==)', run, re.IGNORECASE):
                                issues.append({
                                    "type": "unpinned_python_packages",
                                    "severity": "high",
                                    "message": f"Composite action installs Python packages without version pinning",
                                    "action": action_ref,
                                    "recommendation": "Pin all Python package versions (e.g., pip install package==1.2.3)"
                                })
                            
                            # Check for downloading external resources without checksums
                            if re.search(r'(wget|curl)\s+.*http', run, re.IGNORECASE) and not re.search(r'(sha256|sha512|md5|checksum)', run, re.IGNORECASE):
                                issues.append({
                                    "type": "unpinned_external_resources",
                                    "severity": "high",
                                    "message": f"Composite action downloads external resources without checksum verification",
                                    "action": action_ref,
                                    "recommendation": "Verify checksums for all downloaded external resources"
                                })
        
        return issues

    @staticmethod
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
                        "message": f"JavaScript action downloads external resources without checksum verification",
                        "action": action_ref,
                        "recommendation": "Verify checksums for all downloaded external resources to ensure immutability"
                    })
        
        return issues

    @staticmethod
    def audit_action(action_ref: str, action_yml: Optional[Dict[str, Any]] = None, action_content: Optional[str] = None, dockerfile_content: Optional[str] = None) -> List[Dict[str, Any]]:
        """Audit a single action for security issues."""
        issues = []
        
        # Check pinned version
        version_issue = SecurityAuditor.check_pinned_version(action_ref)
        if version_issue:
            issues.append(version_issue)
        
        # Check action.yml if available
        if action_yml:
            # Check for secrets in inputs
            inputs = action_yml.get("inputs", {})
            for input_name, input_def in inputs.items():
                if isinstance(input_def, dict):
                    description = input_def.get("description", "").lower()
                    if "secret" in description or "password" in description or "token" in description:
                        if not input_def.get("required", False):
                            issues.append({
                                "type": "optional_secret_input",
                                "severity": "medium",
                                "message": f"Action has optional secret input '{input_name}'",
                                "action": action_ref
                            })
            
            # Check for unpinnable actions (Palo Alto Networks research)
            issues.extend(SecurityAuditor.check_unpinnable_docker_action(action_yml, action_ref, dockerfile_content))
            issues.extend(SecurityAuditor.check_unpinnable_composite_action(action_yml, action_ref))
            issues.extend(SecurityAuditor.check_unpinnable_javascript_action(action_yml, action_ref, action_content))
        
        return issues

    @staticmethod
    def audit_workflow(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit a workflow file for security issues."""
        issues = []
        
        # Check permissions
        issues.extend(SecurityAuditor.check_permissions(workflow))
        
        # Check GITHUB_TOKEN permissions
        issues.extend(SecurityAuditor.check_github_token_permissions(workflow))
        
        # Check for secrets
        issues.extend(SecurityAuditor.check_secrets_in_workflow(workflow))
        
        # Check self-hosted runners
        issues.extend(SecurityAuditor.check_self_hosted_runners(workflow))
        
        # Check dangerous events
        issues.extend(SecurityAuditor.check_dangerous_events(workflow))
        
        # Check checkout actions
        issues.extend(SecurityAuditor.check_checkout_actions(workflow))
        
        # Check script injection
        issues.extend(SecurityAuditor.check_script_injection(workflow))
        
        # Check artifact retention
        issues.extend(SecurityAuditor.check_artifact_retention(workflow))
        
        # Check matrix strategy
        issues.extend(SecurityAuditor.check_matrix_strategy(workflow))
        
        # Check workflow_dispatch inputs
        issues.extend(SecurityAuditor.check_workflow_dispatch_inputs(workflow))
        
        # Check environment secrets
        issues.extend(SecurityAuditor.check_environment_secrets(workflow))
        
        # Check for untrusted third-party actions (GitHub Actions Goat #5)
        issues.extend(SecurityAuditor.check_untrusted_third_party_actions(workflow))
        
        # Check for long-term credentials (GitHub Actions Goat #4)
        issues.extend(SecurityAuditor.check_long_term_credentials(workflow))
        
        # Check for network traffic filtering (GitHub Actions Goat #1)
        issues.extend(SecurityAuditor.check_network_traffic_filtering(workflow))
        
        # Check for file tampering protection (GitHub Actions Goat #2)
        issues.extend(SecurityAuditor.check_file_tampering_protection(workflow))
        
        # Check for audit logging (GitHub Actions Goat #3)
        issues.extend(SecurityAuditor.check_audit_logging(workflow))
        
        # Check for branch protection bypass
        issues.extend(SecurityAuditor.check_branch_protection_bypass(workflow))
        
        # Check for code injection via workflow inputs
        issues.extend(SecurityAuditor.check_code_injection_via_workflow_inputs(workflow))
        
        # Check for hash pinning (commit SHA) instead of tags
        issues.extend(SecurityAuditor.check_hash_pinning(workflow))
        
        return issues

