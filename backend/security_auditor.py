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
    def audit_action(action_ref: str, action_yml: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
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
        
        return issues

    @staticmethod
    def audit_workflow(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit a workflow file for security issues."""
        issues = []
        
        # Check permissions
        issues.extend(SecurityAuditor.check_permissions(workflow))
        
        # Check for secrets
        issues.extend(SecurityAuditor.check_secrets_in_workflow(workflow))
        
        # Check self-hosted runners
        issues.extend(SecurityAuditor.check_self_hosted_runners(workflow))
        
        return issues

