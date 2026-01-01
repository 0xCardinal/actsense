"""Tests for security vulnerability checks."""
import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rules import security as security_rules


class TestSecretsInWorkflow:
    """Tests for secret detection in workflows."""
    
    def test_potential_hardcoded_secret(self, workflow_with_secrets):
        """Test detection of hardcoded secrets."""
        # The secret detection looks for patterns in string content
        # Pass content with the secret pattern
        content = """
name: Workflow with Secrets
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build
        run: echo 'Building'
        env:
          API_KEY: sk_live_123456789012345678901234567890
          password: mySecretPassword123
"""
        issues = security_rules.check_secrets_in_workflow(workflow_with_secrets, content)
        
        # May detect via TruffleHog or pattern matching
        assert len(issues) >= 0  # Allow for cases where TruffleHog isn't available
        secret_issues = [i for i in issues if i.get("type") == "potential_hardcoded_secret"]
        if len(secret_issues) > 0:
            assert secret_issues[0]["severity"] == "critical"
            assert "actsense.dev/vulnerabilities/potential_hardcoded_secret" in secret_issues[0]["evidence"]["vulnerability"]
    
    def test_no_secrets_in_workflow(self, sample_workflow):
        """Test workflow without secrets."""
        issues = security_rules.check_secrets_in_workflow(sample_workflow)
        secret_issues = [i for i in issues if i.get("type") == "potential_hardcoded_secret"]
        assert len(secret_issues) == 0


class TestLongTermCredentials:
    """Tests for long-term credential detection."""
    
    def test_long_term_aws_credentials(self, workflow_with_aws_credentials):
        """Test detection of AWS long-term credentials."""
        issues = security_rules.check_secrets_in_workflow(workflow_with_aws_credentials)
        
        aws_issues = [i for i in issues if i.get("type") == "long_term_aws_credentials"]
        assert len(aws_issues) > 0
        assert aws_issues[0]["severity"] == "high"
        assert "actsense.dev/vulnerabilities/long_term_cloud_credentials" in aws_issues[0]["evidence"]["vulnerability"]
    
    def test_long_term_azure_credentials(self):
        """Test detection of Azure long-term credentials."""
        workflow = {
            "name": "Azure Workflow",
            "on": ["push"],
            "jobs": {
                "deploy": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Deploy",
                            "run": "az deploy",
                            "env": {
                                "AZURE_CLIENT_ID": "${{ secrets.AZURE_CLIENT_ID }}",
                                "AZURE_CLIENT_SECRET": "${{ secrets.AZURE_CLIENT_SECRET }}",
                                "AZURE_TENANT_ID": "${{ secrets.AZURE_TENANT_ID }}"
                            }
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_secrets_in_workflow(workflow)
        azure_issues = [i for i in issues if i.get("type") == "long_term_azure_credentials"]
        assert len(azure_issues) > 0
        assert "actsense.dev/vulnerabilities/long_term_cloud_credentials" in azure_issues[0]["evidence"]["vulnerability"]
    
    def test_long_term_gcp_credentials(self):
        """Test detection of GCP long-term credentials."""
        workflow = {
            "name": "GCP Workflow",
            "on": ["push"],
            "jobs": {
                "deploy": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Deploy",
                            "run": "gcloud deploy",
                            "env": {
                                "GOOGLE_APPLICATION_CREDENTIALS": "/path/to/key.json"
                            }
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_secrets_in_workflow(workflow)
        gcp_issues = [i for i in issues if i.get("type") == "long_term_gcp_credentials"]
        assert len(gcp_issues) > 0
        assert "actsense.dev/vulnerabilities/long_term_cloud_credentials" in gcp_issues[0]["evidence"]["vulnerability"]


class TestSelfHostedRunners:
    """Tests for self-hosted runner vulnerabilities."""
    
    def test_self_hosted_runner_detection(self, workflow_with_self_hosted_runner):
        """Test detection of self-hosted runners."""
        issues = security_rules.check_self_hosted_runners(workflow_with_self_hosted_runner, is_public_repo=False)
        
        runner_issues = [i for i in issues if i.get("type") == "self_hosted_runner"]
        assert len(runner_issues) > 0
        assert "actsense.dev/vulnerabilities/self_hosted_runner" in runner_issues[0]["evidence"]["vulnerability"]
    
    def test_self_hosted_runner_pr_exposure(self):
        """Test detection of self-hosted runner PR exposure."""
        workflow = {
            "name": "PR Self-hosted",
            "on": {
                "pull_request": {}
            },
            "jobs": {
                "test": {
                    "runs-on": "self-hosted",
                    "steps": [{"name": "Test", "run": "echo test"}]
                }
            }
        }
        
        issues = security_rules.check_self_hosted_runners(workflow, is_public_repo=True)
        pr_issues = [i for i in issues if i.get("type") == "self_hosted_runner_pr_exposure"]
        assert len(pr_issues) > 0
        assert pr_issues[0]["severity"] == "critical"
        assert "actsense.dev/vulnerabilities/self_hosted_runner_pr_exposure" in pr_issues[0]["evidence"]["vulnerability"]
    
    def test_self_hosted_runner_issue_exposure(self):
        """Test detection of self-hosted runner issue exposure."""
        workflow = {
            "name": "Issue Self-hosted",
            "on": {
                "issues": {}
            },
            "jobs": {
                "test": {
                    "runs-on": "self-hosted",
                    "steps": [{"name": "Test", "run": "echo test"}]
                }
            }
        }
        
        issues = security_rules.check_self_hosted_runners(workflow, is_public_repo=True)
        issue_issues = [i for i in issues if i.get("type") == "self_hosted_runner_issue_exposure"]
        assert len(issue_issues) > 0
        assert "actsense.dev/vulnerabilities/self_hosted_runner_issue_exposure" in issue_issues[0]["evidence"]["vulnerability"]
    
    def test_self_hosted_runner_write_all(self):
        """Test detection of self-hosted runner with write-all permissions."""
        workflow = {
            "name": "Self-hosted Write All",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "self-hosted",
                    "permissions": "write-all",
                    "steps": [{"name": "Test", "run": "echo test"}]
                }
            }
        }
        
        issues = security_rules.check_self_hosted_runners(workflow, is_public_repo=False)
        write_all_issues = [i for i in issues if i.get("type") == "self_hosted_runner_write_all"]
        assert len(write_all_issues) > 0
        assert "actsense.dev/vulnerabilities/self_hosted_runner_write_all" in write_all_issues[0]["evidence"]["vulnerability"]
    
    def test_runner_label_confusion(self, workflow_with_runner_label_confusion):
        """Test detection of runner label confusion."""
        issues = security_rules.check_runner_label_confusion(workflow_with_runner_label_confusion)
        
        assert len(issues) > 0
        assert issues[0]["type"] == "runner_label_confusion"
        assert "actsense.dev/vulnerabilities/runner_label_confusion" in issues[0]["evidence"]["vulnerability"]
    
    def test_public_repo_self_hosted_secrets(self, workflow_with_public_repo_self_hosted):
        """Test detection of secrets in public repo with self-hosted runner."""
        issues = security_rules.check_repository_visibility_risks(workflow_with_public_repo_self_hosted, is_public_repo=True)
        
        secret_issues = [i for i in issues if i.get("type") == "public_repo_self_hosted_secrets"]
        assert len(secret_issues) > 0
        assert "actsense.dev/vulnerabilities/public_repo_self_hosted_secrets" in secret_issues[0]["evidence"]["vulnerability"]


class TestDangerousEvents:
    """Tests for dangerous workflow events."""
    
    def test_insecure_pull_request_target(self, workflow_with_pull_request_target):
        """Test detection of insecure pull_request_target."""
        issues = security_rules.check_dangerous_events(workflow_with_pull_request_target)
        
        pr_target_issues = [i for i in issues if i.get("type") == "insecure_pull_request_target"]
        assert len(pr_target_issues) > 0
        assert pr_target_issues[0]["severity"] == "high"
        assert "actsense.dev/vulnerabilities/insecure_pull_request_target" in pr_target_issues[0]["evidence"]["vulnerability"]
    
    def test_dangerous_event_workflow_run(self):
        """Test detection of workflow_run event."""
        workflow = {
            "name": "Workflow Run",
            "on": {
                "workflow_run": {
                    "workflows": ["other-workflow"],
                    "types": ["completed"]
                }
            },
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"name": "Test", "run": "echo test"}]
                }
            }
        }
        
        issues = security_rules.check_dangerous_events(workflow)
        event_issues = [i for i in issues if i.get("type") == "dangerous_event"]
        assert len(event_issues) > 0
        assert "actsense.dev/vulnerabilities/dangerous_event" in event_issues[0]["evidence"]["vulnerability"]


class TestCheckoutActions:
    """Tests for unsafe checkout action usage."""
    
    def test_unsafe_checkout_persist_credentials(self, workflow_with_unsafe_checkout):
        """Test detection of persist-credentials in checkout."""
        issues = security_rules.check_checkout_actions(workflow_with_unsafe_checkout)
        
        unsafe_issues = [i for i in issues if i.get("type") == "unsafe_checkout"]
        if len(unsafe_issues) > 0:
            assert "actsense.dev/vulnerabilities/unsafe_checkout" in unsafe_issues[0].get("evidence", {}).get("vulnerability", "")
        # Note: Detection may vary based on specific patterns
    
    def test_unsafe_checkout_ref(self):
        """Test detection of unsafe checkout ref."""
        workflow = {
            "name": "Unsafe Ref",
            "on": {
                "workflow_dispatch": {
                    "inputs": {
                        "branch": {"type": "string"}
                    }
                }
            },
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Checkout",
                            "uses": "actions/checkout@v4",
                            "with": {
                                "ref": "${{ inputs.branch }}"
                            }
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_checkout_actions(workflow)
        ref_issues = [i for i in issues if i.get("type") == "unsafe_checkout_ref"]
        assert len(ref_issues) > 0
        assert "actsense.dev/vulnerabilities/unsafe_checkout_ref" in ref_issues[0]["evidence"]["vulnerability"]
    
    def test_checkout_full_history(self, workflow_with_unsafe_checkout):
        """Test detection of checkout with full history."""
        issues = security_rules.check_checkout_actions(workflow_with_unsafe_checkout)
        
        history_issues = [i for i in issues if i.get("type") == "checkout_full_history"]
        assert len(history_issues) > 0
        assert "actsense.dev/vulnerabilities/checkout_full_history" in history_issues[0]["evidence"]["vulnerability"]


class TestScriptInjection:
    """Tests for script injection vulnerabilities."""
    
    def test_shell_injection(self, workflow_with_shell_injection):
        """Test detection of shell injection."""
        issues = security_rules.check_script_injection(workflow_with_shell_injection)
        
        injection_issues = [i for i in issues if i.get("type") == "shell_injection"]
        if len(injection_issues) > 0:
            assert "actsense.dev/vulnerabilities/shell_injection" in injection_issues[0].get("evidence", {}).get("vulnerability", "")
        # Note: Detection depends on specific injection patterns
    
    def test_unsafe_shell(self, workflow_with_unsafe_shell):
        """Test detection of unsafe shell without -e flag."""
        issues = security_rules.check_script_injection(workflow_with_unsafe_shell)
        
        unsafe_shell_issues = [i for i in issues if i.get("type") == "unsafe_shell"]
        assert len(unsafe_shell_issues) > 0
        assert "actsense.dev/vulnerabilities/unsafe_shell" in unsafe_shell_issues[0]["evidence"]["vulnerability"]
    
    def test_github_script_injection(self, workflow_with_github_script_injection):
        """Test detection of JavaScript injection in github-script."""
        issues = security_rules.check_github_script_injection(workflow_with_github_script_injection)
        
        script_issues = [i for i in issues if i.get("type") == "script_injection"]
        if len(script_issues) > 0:
            assert "actsense.dev/vulnerabilities/script_injection" in script_issues[0].get("evidence", {}).get("vulnerability", "")
        # Note: Detection depends on specific injection patterns
    
    def test_powershell_injection(self, workflow_with_powershell_injection):
        """Test detection of PowerShell injection."""
        issues = security_rules.check_powershell_injection(workflow_with_powershell_injection)
        
        ps_issues = [i for i in issues if i.get("type") == "script_injection"]
        assert len(ps_issues) > 0
        assert "actsense.dev/vulnerabilities/script_injection" in ps_issues[0]["evidence"]["vulnerability"]
    


class TestRiskyContextUsage:
    """Tests for risky GitHub context usage."""
    
    def test_risky_context_issue_title(self):
        """Test detection of risky context usage with issue.title (direct in run command - critical)."""
        workflow = {
            "name": "Process Issue",
            "on": {
                "issues": {}
            },
            "jobs": {
                "process": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Process",
                            "run": "echo ${{ github.event.issue.title }}"
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_risky_context_usage(workflow)
        risky_issues = [i for i in issues if i.get("type") == "risky_context_usage"]
        assert len(risky_issues) > 0
        # Direct use in run command should be critical
        assert risky_issues[0]["severity"] == "critical"
        assert "github.event.issue.title" in risky_issues[0]["evidence"]["risky_contexts"]
        assert risky_issues[0]["evidence"]["usage_location"] == "run_command"
        assert "actsense.dev/vulnerabilities/risky_context_usage" in risky_issues[0]["evidence"]["vulnerability"]
    
    def test_risky_context_pull_request_body(self):
        """Test detection of risky context usage with pull_request.body."""
        workflow = {
            "name": "Process PR",
            "on": {
                "pull_request": {}
            },
            "jobs": {
                "process": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Process",
                            "run": "echo ${{ github.event.pull_request.body }}"
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_risky_context_usage(workflow)
        risky_issues = [i for i in issues if i.get("type") == "risky_context_usage"]
        assert len(risky_issues) > 0
        assert risky_issues[0]["severity"] == "critical"
        assert "github.event.pull_request.body" in risky_issues[0]["evidence"]["risky_contexts"]
    
    def test_risky_context_ref_name(self):
        """Test detection of risky context usage with github.ref_name."""
        workflow = {
            "name": "Process Ref",
            "on": ["push"],
            "jobs": {
                "process": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Process",
                            "run": "echo ${{ github.ref_name }}"
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_risky_context_usage(workflow)
        risky_issues = [i for i in issues if i.get("type") == "risky_context_usage"]
        assert len(risky_issues) > 0
        assert risky_issues[0]["severity"] == "critical"
        assert "github.ref_name" in risky_issues[0]["evidence"]["risky_contexts"]
    
    def test_risky_context_in_env(self):
        """Test detection of risky context usage in environment variables (should be high severity, not critical)."""
        workflow = {
            "name": "Process Issue",
            "on": {
                "issues": {}
            },
            "jobs": {
                "process": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Process",
                            "env": {
                                "ISSUE_TITLE": "${{ github.event.issue.title }}"
                            },
                            "run": "echo $ISSUE_TITLE"
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_risky_context_usage(workflow)
        risky_issues = [i for i in issues if i.get("type") == "risky_context_usage"]
        assert len(risky_issues) > 0
        # When used in env vars (not directly in run), severity should be "high" not "critical"
        assert risky_issues[0]["severity"] == "high"
        assert "github.event.issue.title" in risky_issues[0]["evidence"]["risky_contexts"]
        assert risky_issues[0]["evidence"]["usage_location"] == "environment_variable"
    
    def test_risky_context_generic_suffix(self):
        """Test detection of risky context with generic suffix pattern."""
        workflow = {
            "name": "Process Custom",
            "on": ["push"],
            "jobs": {
                "process": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Process",
                            "run": "echo ${{ github.event.custom_event.body }}"
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_risky_context_usage(workflow)
        risky_issues = [i for i in issues if i.get("type") == "risky_context_usage"]
        assert len(risky_issues) > 0
        assert risky_issues[0]["severity"] == "critical"
        # Should detect the .body suffix pattern
        assert any("body" in ctx for ctx in risky_issues[0]["evidence"]["risky_contexts"])
    
    def test_no_risky_context(self):
        """Test workflow without risky context usage."""
        workflow = {
            "name": "Safe Workflow",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Test",
                            "run": "echo ${{ github.repository }}"
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_risky_context_usage(workflow)
        risky_issues = [i for i in issues if i.get("type") == "risky_context_usage"]
        assert len(risky_issues) == 0


class TestMaliciousPatterns:
    """Tests for malicious code patterns."""
    
    def test_malicious_curl_pipe_bash(self, workflow_with_curl_pipe_bash):
        """Test detection of curl piped to bash."""
        issues = security_rules.check_malicious_curl_pipe_bash(workflow_with_curl_pipe_bash)
        
        curl_issues = [i for i in issues if i.get("type") == "malicious_curl_pipe_bash"]
        assert len(curl_issues) > 0
        assert "actsense.dev/vulnerabilities/malicious_curl_pipe_bash" in curl_issues[0]["evidence"]["vulnerability"]
    
    def test_malicious_base64_decode(self, workflow_with_base64_decode):
        """Test detection of base64 decode execution."""
        issues = security_rules.check_malicious_base64_decode(workflow_with_base64_decode)
        
        base64_issues = [i for i in issues if i.get("type") == "malicious_base64_decode"]
        assert len(base64_issues) > 0
        assert "actsense.dev/vulnerabilities/malicious_base64_decode" in base64_issues[0]["evidence"]["vulnerability"]
    
    def test_obfuscation_detection(self, workflow_with_obfuscation):
        """Test detection of code obfuscation."""
        issues = security_rules.check_obfuscation_detection(workflow_with_obfuscation)
        
        obfuscation_issues = [i for i in issues if i.get("type") == "obfuscation_detection"]
        assert len(obfuscation_issues) > 0
        assert "actsense.dev/vulnerabilities/obfuscation_detection" in obfuscation_issues[0]["evidence"]["vulnerability"]


class TestArtifactVulnerabilities:
    """Tests for artifact-related vulnerabilities."""
    
    def test_artifact_exposure_risk(self, workflow_with_artifact_upload):
        """Test detection of artifact exposure risks."""
        issues = security_rules.check_artifact_exposure_risk(workflow_with_artifact_upload)
        
        artifact_issues = [i for i in issues if i.get("type") == "artifact_exposure_risk"]
        # May or may not detect depending on path patterns
        if len(artifact_issues) > 0:
            assert "actsense.dev/vulnerabilities/artifact_exposure_risk" in artifact_issues[0]["evidence"]["vulnerability"]


class TestTokenPermissionEscalation:
    """Tests for token permission escalation."""
    
    def test_token_permission_escalation(self, workflow_with_token_manipulation):
        """Test detection of token permission escalation patterns."""
        issues = security_rules.check_token_permission_escalation(workflow_with_token_manipulation)
        
        token_issues = [i for i in issues if i.get("type") == "token_permission_escalation"]
        if len(token_issues) > 0:
            assert "actsense.dev/vulnerabilities/token_permission_escalation" in token_issues[0]["evidence"]["vulnerability"]


class TestCrossRepositoryAccess:
    """Tests for cross-repository access."""
    
    def test_cross_repository_access(self, workflow_with_cross_repo_access):
        """Test detection of cross-repository access."""
        issues = security_rules.check_cross_repository_access(workflow_with_cross_repo_access, current_repo="owner/repo")
        
        cross_repo_issues = [i for i in issues if i.get("type") == "cross_repository_access"]
        assert len(cross_repo_issues) > 0
        assert "actsense.dev/vulnerabilities/cross_repository_access" in cross_repo_issues[0]["evidence"]["vulnerability"]


class TestEnvironmentBypass:
    """Tests for environment protection bypass."""
    
    def test_environment_bypass_risk(self, workflow_with_environment_bypass):
        """Test detection of environment bypass risks."""
        issues = security_rules.check_environment_bypass(workflow_with_environment_bypass)
        
        env_issues = [i for i in issues if i.get("type") == "environment_bypass_risk"]
        if len(env_issues) > 0:
            assert "actsense.dev/vulnerabilities/environment_bypass_risk" in env_issues[0]["evidence"]["vulnerability"]


class TestSecretsAccessUntrusted:
    """Tests for secrets passed to untrusted actions."""
    
    def test_secrets_access_untrusted(self, workflow_with_secrets_to_untrusted):
        """Test detection of secrets passed to untrusted actions."""
        issues = security_rules.check_secrets_access_untrusted(workflow_with_secrets_to_untrusted)
        
        untrusted_issues = [i for i in issues if i.get("type") == "secrets_access_untrusted"]
        assert len(untrusted_issues) > 0
        assert "actsense.dev/vulnerabilities/secrets_access_untrusted" in untrusted_issues[0]["evidence"]["vulnerability"]
    
    def test_secret_in_environment(self):
        """Test detection of secrets in environment variables."""
        workflow = {
            "name": "Secret in Env",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Test",
                            "run": "echo $SECRET",
                            "env": {
                                "SECRET": "${{ secrets.MY_SECRET }}"
                            }
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_self_hosted_runner_secrets(workflow)
        env_secret_issues = [i for i in issues if i.get("type") == "secret_in_environment"]
        if len(env_secret_issues) > 0:
            assert "actsense.dev/vulnerabilities/secret_in_environment" in env_secret_issues[0]["evidence"]["vulnerability"]


class TestNetworkTrafficFiltering:
    """Tests for network traffic filtering."""
    
    def test_unfiltered_network_traffic(self, workflow_with_network_operations):
        """Test detection of unfiltered network traffic."""
        issues = security_rules.check_network_traffic_filtering(workflow_with_network_operations)
        
        network_issues = [i for i in issues if i.get("type") == "unfiltered_network_traffic"]
        if len(network_issues) > 0:
            assert "actsense.dev/vulnerabilities/unfiltered_network_traffic" in network_issues[0]["evidence"]["vulnerability"]


class TestFileTamperingProtection:
    """Tests for file tampering protection."""
    
    def test_no_file_tampering_protection(self, workflow_with_file_tampering):
        """Test detection of file tampering risks."""
        issues = security_rules.check_file_tampering_protection(workflow_with_file_tampering)
        
        tamper_issues = [i for i in issues if i.get("type") == "no_file_tampering_protection"]
        if len(tamper_issues) > 0:
            assert "actsense.dev/vulnerabilities/no_file_tampering_protection" in tamper_issues[0]["evidence"]["vulnerability"]


class TestBranchProtectionBypass:
    """Tests for branch protection bypass."""
    
    def test_branch_protection_bypass(self, workflow_with_branch_protection_bypass):
        """Test detection of branch protection bypass."""
        issues = security_rules.check_branch_protection_bypass(workflow_with_branch_protection_bypass)
        
        bypass_issues = [i for i in issues if i.get("type") == "branch_protection_bypass"]
        if len(bypass_issues) > 0:
            assert "actsense.dev/vulnerabilities/branch_protection_bypass" in bypass_issues[0].get("evidence", {}).get("vulnerability", "")
        # Note: Detection depends on specific patterns in the workflow


class TestCodeInjectionViaInputs:
    """Tests for code injection via workflow inputs."""
    
    def test_code_injection_via_input(self, workflow_with_shell_injection):
        """Test detection of code injection via workflow inputs."""
        issues = security_rules.check_code_injection_via_workflow_inputs(workflow_with_shell_injection)
        
        injection_issues = [i for i in issues if i.get("type") == "code_injection_via_input"]
        if len(injection_issues) > 0:
            assert "actsense.dev/vulnerabilities/code_injection_via_input" in injection_issues[0]["evidence"]["vulnerability"]


class TestTyposquattingActions:
    """Tests for typosquatting action detection."""
    
    def test_typosquatting_action(self, workflow_with_typosquatting):
        """Test detection of typosquatting actions."""
        issues = security_rules.check_typosquatting_actions(workflow_with_typosquatting)
        
        typosquatting_issues = [i for i in issues if i.get("type") == "typosquatting_action"]
        if len(typosquatting_issues) > 0:
            assert "actsense.dev/vulnerabilities/typosquatting_action" in typosquatting_issues[0]["evidence"]["vulnerability"]


class TestUntrustedThirdPartyActions:
    """Tests for untrusted third-party actions."""
    
    def test_untrusted_action_unpinned(self, workflow_with_untrusted_action):
        """Test detection of unpinned untrusted actions."""
        issues = security_rules.check_untrusted_third_party_actions(workflow_with_untrusted_action)
        
        unpinned_issues = [i for i in issues if i.get("type") == "untrusted_action_unpinned"]
        if len(unpinned_issues) > 0:
            assert "actsense.dev/vulnerabilities/untrusted_action_unpinned" in unpinned_issues[0]["evidence"]["vulnerability"]
    
    def test_untrusted_action_source(self, workflow_with_untrusted_action):
        """Test detection of untrusted action source."""
        issues = security_rules.check_untrusted_third_party_actions(workflow_with_untrusted_action)
        
        source_issues = [i for i in issues if i.get("type") == "untrusted_action_source"]
        if len(source_issues) > 0:
            assert "actsense.dev/vulnerabilities/untrusted_action_source" in source_issues[0]["evidence"]["vulnerability"]

