"""Security issue detection for GitHub Actions."""
from typing import List, Dict, Any, Optional
from github_client import GitHubClient

# Import rules from rules module
from rules import security as security_rules


class SecurityAuditor:
    @staticmethod
    def check_pinned_version(action_ref: str) -> Dict[str, Any]:
        """
        Check if action uses pinned version (tag or SHA).
        
        Returns detailed vulnerability information with evidence and mitigation steps.
        """
        return security_rules.check_pinned_version(action_ref)
    @staticmethod
    def check_hash_pinning(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check if actions in workflow use hash pinning (commit SHA) instead of tags.
        
        Returns detailed vulnerability information with evidence and mitigation steps.
        """
        return security_rules.check_hash_pinning(workflow)
    @staticmethod
    async def check_older_action_versions(workflow: Dict[str, Any], client: Optional[GitHubClient] = None) -> List[Dict[str, Any]]:
        """Check if actions in workflow use older versions (tags or commit hashes) that may have security vulnerabilities."""
        return await security_rules.check_older_action_versions(workflow, client)

    @staticmethod
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
        return security_rules.check_inconsistent_action_versions(workflow_actions)
    @staticmethod
    def _run_trufflehog(content: str) -> List[Dict[str, Any]]:
        """Run TruffleHog on workflow content to detect secrets."""
        return security_rules._run_trufflehog(content)

    @staticmethod
    def check_secrets_in_workflow(workflow: Dict[str, Any], content: Optional[str] = None) -> List[Dict[str, Any]]:
        """Check for potential secret exposure issues and long-term credentials."""
        return security_rules.check_secrets_in_workflow(workflow, content)
    @staticmethod
    def check_permissions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for overly permissive workflow permissions."""
        return security_rules.check_permissions(workflow)
    @staticmethod
    def check_self_hosted_runners(workflow: Dict[str, Any], is_public_repo: bool = False) -> List[Dict[str, Any]]:
        """Check for use of self-hosted runners and related security issues."""
        return security_rules.check_self_hosted_runners(workflow, is_public_repo)
    @staticmethod
    def check_runner_label_confusion(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for runner label confusion attacks."""
        return security_rules.check_runner_label_confusion(workflow)

    @staticmethod
    def check_self_hosted_runner_secrets(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for secrets management issues with self-hosted runners."""
        return security_rules.check_self_hosted_runner_secrets(workflow)
    
    @staticmethod
    def check_runner_environment_security(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for environment-specific security issues with self-hosted runners."""
        return security_rules.check_runner_environment_security(workflow)
    
    @staticmethod
    def check_repository_visibility_risks(workflow: Dict[str, Any], is_public_repo: bool = False) -> List[Dict[str, Any]]:
        """Check for risks based on repository visibility with self-hosted runners."""
        return security_rules.check_repository_visibility_risks(workflow, is_public_repo)
    @staticmethod
    def check_github_token_permissions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for GITHUB_TOKEN permissions that are too permissive."""
        return security_rules.check_github_token_permissions(workflow)

    @staticmethod
    def check_dangerous_events(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for dangerous workflow trigger events."""
        return security_rules.check_dangerous_events(workflow)
    @staticmethod
    def check_checkout_actions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for unsafe checkout action usage."""
        return security_rules.check_checkout_actions(workflow)
    @staticmethod
    def check_script_injection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potential script injection vulnerabilities with enhanced patterns."""
        return security_rules.check_script_injection(workflow)
    @staticmethod
    def check_github_script_injection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for JavaScript injection vulnerabilities in github-script action."""
        return security_rules.check_github_script_injection(workflow)
    @staticmethod
    def check_powershell_injection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for PowerShell injection vulnerabilities."""
        return security_rules.check_powershell_injection(workflow)
    @staticmethod
    def check_risky_context_usage(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for risky GitHub context usage that can be exploited for injection attacks."""
        return security_rules.check_risky_context_usage(workflow)
    @staticmethod
    def check_malicious_curl_pipe_bash(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for curl/wget piped to bash/sh/zsh, which can execute malicious code."""
        return security_rules.check_malicious_curl_pipe_bash(workflow)
    
    @staticmethod
    def check_malicious_base64_decode(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for base64 decode execution patterns, which can hide malicious code."""
        return security_rules.check_malicious_base64_decode(workflow)
    
    @staticmethod
    def check_continue_on_error_critical_job(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for continue-on-error in critical jobs that should fail on error."""
        return security_rules.check_continue_on_error_critical_job(workflow)
    @staticmethod
    def check_obfuscation_detection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for code obfuscation patterns that may hide malicious code."""
        return security_rules.check_obfuscation_detection(workflow)
    @staticmethod
    def check_artipacked_vulnerability(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for artifact packing vulnerabilities."""
        return security_rules.check_artipacked_vulnerability(workflow)
    @staticmethod
    def check_token_permission_escalation(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for patterns that could lead to token permission escalation."""
        return security_rules.check_token_permission_escalation(workflow)
    @staticmethod
    def check_cross_repository_access(workflow: Dict[str, Any], current_repo: Optional[str] = None) -> List[Dict[str, Any]]:
        """Check for unauthorized cross-repository access."""
        return security_rules.check_cross_repository_access(workflow, current_repo)
    
    @staticmethod
    def check_environment_bypass(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potential environment protection bypass."""
        return security_rules.check_environment_bypass(workflow)
    @staticmethod
    def check_secrets_access_untrusted(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for secrets passed to untrusted actions."""
        return security_rules.check_secrets_access_untrusted(workflow)
    
    @staticmethod
    def check_excessive_write_permissions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for excessive write permissions on read-only workflows."""
        return security_rules.check_excessive_write_permissions(workflow)

    @staticmethod
    def check_artifact_retention(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for artifact retention settings."""
        return security_rules.check_artifact_retention(workflow)
    @staticmethod
    def check_matrix_strategy(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for unsafe matrix strategy usage."""
        return security_rules.check_matrix_strategy(workflow)
    
    @staticmethod
    def check_workflow_dispatch_inputs(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for workflow_dispatch inputs without validation."""
        return security_rules.check_workflow_dispatch_inputs(workflow)
    
    @staticmethod
    def check_environment_secrets(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for environment secrets usage patterns."""
        return security_rules.check_environment_secrets(workflow)
    
    @staticmethod
    async def check_deprecated_actions(workflow: Dict[str, Any], client: Optional[GitHubClient] = None) -> List[Dict[str, Any]]:
        """Check for usage of deprecated actions."""
        return await security_rules.check_deprecated_actions(workflow, client)
    
    @staticmethod
    async def check_missing_action_repositories(workflow: Dict[str, Any], client: Optional[GitHubClient] = None) -> List[Dict[str, Any]]:
        """Check if any referenced action repositories don't exist or are inaccessible."""
        return await security_rules.check_missing_action_repositories(workflow, client)
    
    @staticmethod
    def check_typosquatting_actions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potential typosquatting in action names."""
        return security_rules.check_typosquatting_actions(workflow)
    @staticmethod
    def check_untrusted_third_party_actions(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for use of untrusted third-party GitHub Actions with enhanced suspicious pattern detection."""
        return security_rules.check_untrusted_third_party_actions(workflow)
    @staticmethod
    def check_network_traffic_filtering(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potentially dangerous network operations that could exfiltrate data."""
        return security_rules.check_network_traffic_filtering(workflow)
    @staticmethod
    def check_file_tampering_protection(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for build jobs that modify files, which could be tampered with."""
        return security_rules.check_file_tampering_protection(workflow)
    @staticmethod
    def check_audit_logging(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for sensitive operations that should have detailed audit logging."""
        return security_rules.check_audit_logging(workflow)
    @staticmethod
    def check_branch_protection_bypass(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for workflows that could bypass branch protection rules."""
        return security_rules.check_branch_protection_bypass(workflow)
    @staticmethod
    def check_code_injection_via_workflow_inputs(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for code injection via workflow inputs."""
        return security_rules.check_code_injection_via_workflow_inputs(workflow)
    @staticmethod
    def check_unpinnable_docker_action(action_yml: Dict[str, Any], action_ref: str, dockerfile_content: Optional[str] = None) -> List[Dict[str, Any]]:
        """Check for unpinnable Docker actions (using mutable tags instead of digests)."""
        return security_rules.check_unpinnable_docker_action(action_yml, action_ref, dockerfile_content)
    @staticmethod
    def check_unpinnable_composite_action(action_yml: Dict[str, Any], action_ref: str) -> List[Dict[str, Any]]:
        """Check for unpinnable composite actions (using unpinned sub-actions or dependencies)."""
        return security_rules.check_unpinnable_composite_action(action_yml, action_ref)
    @staticmethod
    def check_unpinnable_javascript_action(action_yml: Dict[str, Any], action_ref: str, action_content: Optional[str] = None) -> List[Dict[str, Any]]:
        """Check for unpinnable JavaScript actions (downloading external resources without checksums)."""
        return security_rules.check_unpinnable_javascript_action(action_yml, action_ref, action_content)
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
            issues.extend(security_rules.check_unpinnable_docker_action(action_yml, action_ref, dockerfile_content))
            issues.extend(security_rules.check_unpinnable_composite_action(action_yml, action_ref))
            issues.extend(security_rules.check_unpinnable_javascript_action(action_yml, action_ref, action_content))
        
        return issues

    @staticmethod
    def _find_line_number(content: str, search_text: str, context: Optional[str] = None) -> Optional[int]:
        """Helper to find line number in content."""
        return security_rules._find_line_number(content, search_text, context)
    @staticmethod
    async def audit_workflow(workflow: Dict[str, Any], content: Optional[str] = None, client: Optional[GitHubClient] = None) -> List[Dict[str, Any]]:
        """Audit a workflow file for security issues."""
        issues = []
        
        # Check permissions
        perm_issues = SecurityAuditor.check_permissions(workflow)
        if content and perm_issues:
            for issue in perm_issues:
                line_num = security_rules._find_line_number(content, "permissions")
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(perm_issues)
        
        # Check GITHUB_TOKEN permissions
        token_issues = SecurityAuditor.check_github_token_permissions(workflow)
        if content and token_issues:
            for issue in token_issues:
                line_num = security_rules._find_line_number(content, "permissions", issue.get("message", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(token_issues)
        
        # Check for secrets and long-term credentials
        secret_issues = SecurityAuditor.check_secrets_in_workflow(workflow, content)
        if content and secret_issues:
            for issue in secret_issues:
                # Try to find the secret pattern in content
                if issue.get("path"):
                    line_num = security_rules._find_line_number(content, issue["path"].split(".")[-1])
                    if line_num:
                        issue["line_number"] = line_num
                # For long-term credential issues, look for credential keys
                elif issue.get("type") in ["long_term_aws_credentials", "long_term_azure_credentials", "long_term_gcp_credentials", "potential_hardcoded_cloud_credentials"]:
                    cred_keys = ["AWS_ACCESS_KEY", "AZURE_CLIENT", "GOOGLE_APPLICATION", "GCP_SA_KEY", "aws_access_key", "aws_secret", "azure_client_secret", "gcp_key", "service_account_key"]
                    for key in cred_keys:
                        line_num = security_rules._find_line_number(content, key, issue.get("job", ""))
                        if line_num:
                            issue["line_number"] = line_num
                            break
                # For TruffleHog findings, try to find the detector name in content
                elif issue.get("type") == "trufflehog_secret_detected":
                    detector = issue.get("evidence", {}).get("detector", "")
                    if detector:
                        # Try to find the detector name or common patterns
                        line_num = security_rules._find_line_number(content, detector.lower().replace(" ", ""))
                        if not line_num:
                            # Try common secret patterns
                            secret_patterns = ["secret", "password", "token", "key", "api_key", "credential"]
                            for pattern in secret_patterns:
                                line_num = security_rules._find_line_number(content, pattern)
                                if line_num:
                                    break
                        if line_num:
                            issue["line_number"] = line_num
        issues.extend(secret_issues)
        
        # Check self-hosted runners (with repository visibility context)
        # Note: is_public_repo would need to be passed from the caller if available
        # For now, we'll default to False (conservative approach)
        runner_issues = SecurityAuditor.check_self_hosted_runners(workflow, is_public_repo=False)
        if content and runner_issues:
            for issue in runner_issues:
                line_num = security_rules._find_line_number(content, "self-hosted", issue.get("job", ""))
                if not line_num:
                    line_num = security_rules._find_line_number(content, "runs-on", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(runner_issues)
        
        # Check runner label confusion
        label_confusion_issues = SecurityAuditor.check_runner_label_confusion(workflow)
        if content and label_confusion_issues:
            for issue in label_confusion_issues:
                line_num = security_rules._find_line_number(content, "runs-on", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(label_confusion_issues)
        
        # Check self-hosted runner secrets
        runner_secrets_issues = SecurityAuditor.check_self_hosted_runner_secrets(workflow)
        if content and runner_secrets_issues:
            for issue in runner_secrets_issues:
                line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(runner_secrets_issues)
        
        # Check runner environment security
        runner_env_issues = SecurityAuditor.check_runner_environment_security(workflow)
        if content and runner_env_issues:
            for issue in runner_env_issues:
                line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(runner_env_issues)
        
        # Check repository visibility risks
        visibility_risks_issues = SecurityAuditor.check_repository_visibility_risks(workflow, is_public_repo=False)
        if content and visibility_risks_issues:
            for issue in visibility_risks_issues:
                line_num = security_rules._find_line_number(content, "runs-on")
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(visibility_risks_issues)
        
        # Check dangerous events (includes insecure_pull_request_target)
        event_issues = SecurityAuditor.check_dangerous_events(workflow)
        if content and event_issues:
            for issue in event_issues:
                event_name = issue.get("event", "")
                if event_name:
                    line_num = security_rules._find_line_number(content, event_name)
                    if line_num:
                        issue["line_number"] = line_num
                # For insecure_pull_request_target, also try to find checkout line
                if issue.get("type") == "insecure_pull_request_target":
                    job_name = issue.get("job", "")
                    line_num = security_rules._find_line_number(content, "actions/checkout", job_name)
                    if line_num:
                        issue["line_number"] = line_num
        issues.extend(event_issues)
        
        # Check checkout actions
        checkout_issues = SecurityAuditor.check_checkout_actions(workflow)
        if content and checkout_issues:
            for issue in checkout_issues:
                line_num = security_rules._find_line_number(content, "actions/checkout", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(checkout_issues)
        
        # Check script injection (enhanced with specific patterns)
        script_issues = SecurityAuditor.check_script_injection(workflow)
        if content and script_issues:
            for issue in script_issues:
                line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(script_issues)
        
        # Check JavaScript injection in github-script action
        github_script_issues = SecurityAuditor.check_github_script_injection(workflow)
        if content and github_script_issues:
            for issue in github_script_issues:
                line_num = security_rules._find_line_number(content, "actions/github-script", issue.get("job", ""))
                if not line_num:
                    line_num = security_rules._find_line_number(content, "script:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(github_script_issues)
        
        # Check PowerShell injection
        powershell_issues = SecurityAuditor.check_powershell_injection(workflow)
        if content and powershell_issues:
            for issue in powershell_issues:
                line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(powershell_issues)
        
        # Check risky context usage
        risky_context_issues = SecurityAuditor.check_risky_context_usage(workflow)
        if content and risky_context_issues:
            for issue in risky_context_issues:
                # Try to find line number using the specific context variable
                risky_contexts = issue.get("evidence", {}).get("risky_contexts", [])
                line_num = None
                if risky_contexts:
                    # Try to find the first risky context in the content
                    for ctx in risky_contexts:
                        # Extract just the context name (e.g., "github.event.pull_request.title")
                        ctx_name = ctx.split(" (")[0] if " (" in ctx else ctx
                        # Try different search terms
                        search_terms = [
                            ctx_name,  # Full context name
                            ctx_name.replace("github.event.", ""),  # Without github.event prefix
                            ctx_name.split(".")[-1] if "." in ctx_name else ctx_name,  # Just the last part
                        ]
                        for search_term in search_terms:
                            line_num = security_rules._find_line_number(content, search_term, issue.get("job", ""))
                            if line_num:
                                break
                        if line_num:
                            break
                # Fallback to searching for ${{ or run: with job context
                if not line_num:
                    # Search for ${{ near the step name or job
                    step_name = issue.get("step", "")
                    if step_name and step_name != "unnamed":
                        line_num = security_rules._find_line_number(content, step_name, issue.get("job", ""))
                        if line_num:
                            # Look for ${{ near this line
                            lines = content.split('\n')
                            start = max(0, line_num - 3)
                            end = min(len(lines), line_num + 5)
                            for i in range(start, end):
                                if "${{" in lines[i]:
                                    line_num = i + 1
                                    break
                if not line_num:
                    line_num = security_rules._find_line_number(content, "${{", issue.get("job", ""))
                if not line_num:
                    line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(risky_context_issues)
        
        # Check artifact retention
        artifact_issues = SecurityAuditor.check_artifact_retention(workflow)
        if content and artifact_issues:
            for issue in artifact_issues:
                line_num = security_rules._find_line_number(content, "upload-artifact", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(artifact_issues)
        
        # Check matrix strategy
        matrix_issues = SecurityAuditor.check_matrix_strategy(workflow)
        if content and matrix_issues:
            for issue in matrix_issues:
                line_num = security_rules._find_line_number(content, "matrix:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(matrix_issues)
        
        # Check workflow_dispatch inputs
        dispatch_issues = SecurityAuditor.check_workflow_dispatch_inputs(workflow)
        if content and dispatch_issues:
            for issue in dispatch_issues:
                line_num = security_rules._find_line_number(content, "workflow_dispatch", issue.get("input", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(dispatch_issues)
        
        # Check environment secrets
        env_issues = SecurityAuditor.check_environment_secrets(workflow)
        if content and env_issues:
            for issue in env_issues:
                line_num = security_rules._find_line_number(content, "environment:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(env_issues)
        
        # Check deprecated actions
        deprecated_issues = await SecurityAuditor.check_deprecated_actions(workflow, client)
        if content and deprecated_issues:
            for issue in deprecated_issues:
                line_num = security_rules._find_line_number(content, issue.get("action", ""), issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(deprecated_issues)
        
        # Check missing action repositories
        missing_repo_issues = await SecurityAuditor.check_missing_action_repositories(workflow, client)
        if content and missing_repo_issues:
            for issue in missing_repo_issues:
                line_num = security_rules._find_line_number(content, issue.get("action", ""), issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(missing_repo_issues)
        
        # Check typosquatting actions
        typosquatting_issues = SecurityAuditor.check_typosquatting_actions(workflow)
        if content and typosquatting_issues:
            for issue in typosquatting_issues:
                line_num = security_rules._find_line_number(content, issue.get("action", ""), issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(typosquatting_issues)
        
        # Check untrusted third-party actions (enhanced with suspicious patterns)
        untrusted_issues = SecurityAuditor.check_untrusted_third_party_actions(workflow)
        if content and untrusted_issues:
            for issue in untrusted_issues:
                action_ref = issue.get("action", "")
                if action_ref:
                    # Extract action name
                    action_name = action_ref.split("@")[0].split("/")[-1] if "@" in action_ref else action_ref
                    line_num = security_rules._find_line_number(content, action_name)
                    if line_num:
                        issue["line_number"] = line_num
        issues.extend(untrusted_issues)
        
        # Long-term credentials are now checked in check_secrets_in_workflow above
        
        # Check for network traffic filtering
        network_issues = SecurityAuditor.check_network_traffic_filtering(workflow)
        if content and network_issues:
            for issue in network_issues:
                line_num = security_rules._find_line_number(content, "curl", issue.get("job", ""))
                if not line_num:
                    line_num = security_rules._find_line_number(content, "wget", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(network_issues)
        
        # Check for file tampering protection
        tamper_issues = SecurityAuditor.check_file_tampering_protection(workflow)
        if content and tamper_issues:
            for issue in tamper_issues:
                line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(tamper_issues)
        
        # Check for audit logging
        audit_issues = SecurityAuditor.check_audit_logging(workflow)
        if content and audit_issues:
            for issue in audit_issues:
                line_num = security_rules._find_line_number(content, issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(audit_issues)
        
        # Check for branch protection bypass
        branch_issues = SecurityAuditor.check_branch_protection_bypass(workflow)
        if content and branch_issues:
            for issue in branch_issues:
                line_num = security_rules._find_line_number(content, "gh pr", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(branch_issues)
        
        # Check for code injection via workflow inputs
        injection_issues = SecurityAuditor.check_code_injection_via_workflow_inputs(workflow)
        if content and injection_issues:
            for issue in injection_issues:
                input_name = issue.get("input", "")
                if input_name:
                    line_num = security_rules._find_line_number(content, f"inputs.{input_name}")
                    if line_num:
                        issue["line_number"] = line_num
        issues.extend(injection_issues)
        
        # Check for malicious curl pipe bash
        curl_pipe_issues = SecurityAuditor.check_malicious_curl_pipe_bash(workflow)
        if content and curl_pipe_issues:
            for issue in curl_pipe_issues:
                line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(curl_pipe_issues)
        
        # Check for malicious base64 decode
        base64_issues = SecurityAuditor.check_malicious_base64_decode(workflow)
        if content and base64_issues:
            for issue in base64_issues:
                line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(base64_issues)
        
        # Check for continue-on-error in critical jobs
        continue_error_issues = SecurityAuditor.check_continue_on_error_critical_job(workflow)
        if content and continue_error_issues:
            for issue in continue_error_issues:
                line_num = security_rules._find_line_number(content, "continue-on-error", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(continue_error_issues)
        
        # Check for obfuscation patterns
        obfuscation_issues = SecurityAuditor.check_obfuscation_detection(workflow)
        if content and obfuscation_issues:
            for issue in obfuscation_issues:
                line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(obfuscation_issues)
        
        # Check for artifact packing vulnerabilities
        artipacked_issues = SecurityAuditor.check_artipacked_vulnerability(workflow)
        if content and artipacked_issues:
            for issue in artipacked_issues:
                line_num = security_rules._find_line_number(content, "upload-artifact", issue.get("job", ""))
                if not line_num:
                    line_num = security_rules._find_line_number(content, "download-artifact", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(artipacked_issues)
        
        # Check for hash pinning (commit SHA) instead of tags
        hash_issues = SecurityAuditor.check_hash_pinning(workflow)
        if content and hash_issues:
            for issue in hash_issues:
                action_ref = issue.get("action", "")
                if action_ref:
                    action_name = action_ref.split("@")[0].split("/")[-1] if "@" in action_ref else action_ref
                    line_num = security_rules._find_line_number(content, action_name)
                    if line_num:
                        issue["line_number"] = line_num
        issues.extend(hash_issues)
        
        # Check for older action versions
        version_issues = await SecurityAuditor.check_older_action_versions(workflow, client)
        if content and version_issues:
            for issue in version_issues:
                action_ref = issue.get("action", "")
                if action_ref:
                    action_name = action_ref.split("@")[0].split("/")[-1] if "@" in action_ref else action_ref
                    line_num = security_rules._find_line_number(content, action_name)
                    if line_num:
                        issue["line_number"] = line_num
        issues.extend(version_issues)
        
        # Advanced privilege analysis checks
        # Extract current repository from client if available
        current_repo = None
        if client:
            # Try to infer from workflow path or other context
            # For now, we'll pass None and let the check handle it
            pass
        
        # Check token permission escalation
        token_escalation_issues = SecurityAuditor.check_token_permission_escalation(workflow)
        if content and token_escalation_issues:
            for issue in token_escalation_issues:
                line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(token_escalation_issues)
        
        # Check cross-repository access
        cross_repo_issues = SecurityAuditor.check_cross_repository_access(workflow, current_repo)
        if content and cross_repo_issues:
            for issue in cross_repo_issues:
                if issue.get("type") == "cross_repository_access":
                    line_num = security_rules._find_line_number(content, "actions/checkout", issue.get("job", ""))
                else:
                    line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(cross_repo_issues)
        
        # Check environment bypass
        env_bypass_issues = SecurityAuditor.check_environment_bypass(workflow)
        if content and env_bypass_issues:
            for issue in env_bypass_issues:
                line_num = security_rules._find_line_number(content, "run:", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(env_bypass_issues)
        
        # Check secrets access to untrusted actions
        secrets_untrusted_issues = SecurityAuditor.check_secrets_access_untrusted(workflow)
        if content and secrets_untrusted_issues:
            for issue in secrets_untrusted_issues:
                action = issue.get("action", "")
                if action:
                    action_name = action.split("@")[0].split("/")[-1] if "@" in action else action
                    line_num = security_rules._find_line_number(content, action_name)
                    if line_num:
                        issue["line_number"] = line_num
        issues.extend(secrets_untrusted_issues)
        
        # Check excessive write permissions
        excessive_write_issues = SecurityAuditor.check_excessive_write_permissions(workflow)
        if content and excessive_write_issues:
            for issue in excessive_write_issues:
                line_num = security_rules._find_line_number(content, "permissions", issue.get("job", ""))
                if line_num:
                    issue["line_number"] = line_num
        issues.extend(excessive_write_issues)
        
        return issues

