"""Best practice checks for GitHub Actions workflows."""
from typing import List, Dict, Any, Optional
import re
from github_client import GitHubClient

# Best practice checks

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
    if permissions == "write-all" or permissions.get("contents") == "write":
        issues.append({
            "type": "overly_permissive",
            "severity": "medium",
            "message": "Workflow has write permissions to repository contents. This increases the attack surface if the workflow is compromised.",
            "permissions": permissions,
            "evidence": {
                "permissions": permissions,
                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/overly_permissive"
            },
            "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/overly_permissive"
        })

    if permissions.get("actions") == "write":
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
                "severity": "medium",
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
                        "severity": "medium",
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
                            "severity": "low",
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


def check_deprecated_actions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for usage of deprecated actions."""
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

    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if not uses:
                continue

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
                            "severity": "low",
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
