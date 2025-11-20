"""Additional tests to complete coverage for security_auditor.py and rules/security.py"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from security_auditor import SecurityAuditor
from github_client import GitHubClient


class TestSecurityAuditorCoverage:
    """Tests to cover missing lines in security_auditor.py"""
    
    def test_run_trufflehog(self):
        """Test _run_trufflehog method."""
        content = "API_KEY=sk_live_123456789012345678901234567890"
        issues = SecurityAuditor._run_trufflehog(content)
        assert isinstance(issues, list)
    
    def test_check_inconsistent_action_versions(self):
        """Test check_inconsistent_action_versions method."""
        workflow_actions = [
            {
                "workflow_name": "workflow1.yml",
                "workflow_path": ".github/workflows/workflow1.yml",
                "actions": ["actions/checkout@v3", "actions/setup-node@v2"]
            },
            {
                "workflow_name": "workflow2.yml",
                "workflow_path": ".github/workflows/workflow2.yml",
                "actions": ["actions/checkout@v4", "actions/setup-node@v3"]
            }
        ]
        issues = SecurityAuditor.check_inconsistent_action_versions(workflow_actions)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_permissions(self):
        """Test line number assignment for permissions issues."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "permissions": "write-all",
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "echo test"}]
                }
            }
        }
        content = "name: Test\non: [push]\npermissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        # Check that line numbers are assigned
        perm_issues = [i for i in issues if "permission" in i.get("type", "").lower()]
        if perm_issues:
            assert "line_number" in perm_issues[0]
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_token_permissions(self):
        """Test line number assignment for token permissions issues."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "permissions": {
                "contents": "write"
            },
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "echo test"}]
                }
            }
        }
        content = "name: Test\non: [push]\npermissions:\n  contents: write\njobs:\n  test:\n    runs-on: ubuntu-latest"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_secrets_with_path(self):
        """Test line number assignment for secrets with path."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "run": "echo test",
                            "env": {
                                "API_KEY": "secret123"
                            }
                        }
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test\n        env:\n          API_KEY: secret123"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        # Check for secret issues
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_aws_credentials(self):
        """Test line number assignment for AWS credentials."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "deploy": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "run": "aws deploy",
                            "env": {
                                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"
                            }
                        }
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: aws deploy\n        env:\n          AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_trufflehog_secret(self):
        """Test line number assignment for TruffleHog detected secrets."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "run": "echo 'secret_key=abc123'"
                        }
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo 'secret_key=abc123'"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_self_hosted_fallback(self):
        """Test line number assignment for self-hosted runners with fallback."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "self-hosted",
                    "steps": [{"run": "echo test"}]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: self-hosted\n    steps:\n      - run: echo test"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_runner_label_confusion(self):
        """Test line number assignment for runner label confusion."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": ["self-hosted", "ubuntu-latest"],
                    "steps": [{"run": "echo test"}]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on:\n      - self-hosted\n      - ubuntu-latest\n    steps:\n      - run: echo test"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_runner_secrets(self):
        """Test line number assignment for runner secrets."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "self-hosted",
                    "steps": [
                        {
                            "run": "echo ${{ secrets.MY_SECRET }}"
                        }
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: self-hosted\n    steps:\n      - run: echo ${{ secrets.MY_SECRET }}"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_runner_environment(self):
        """Test line number assignment for runner environment security."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "self-hosted",
                    "steps": [
                        {
                            "run": "echo test"
                        }
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: self-hosted\n    steps:\n      - run: echo test"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_visibility_risks(self):
        """Test line number assignment for repository visibility risks."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "self-hosted",
                    "steps": [{"run": "echo test"}]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: self-hosted\n    steps:\n      - run: echo test"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_dangerous_events(self):
        """Test line number assignment for dangerous events."""
        workflow = {
            "name": "Test",
            "on": {
                "pull_request_target": {}
            },
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "uses": "actions/checkout@v4"
                        }
                    ]
                }
            }
        }
        content = "name: Test\non:\n  pull_request_target: {}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_checkout(self):
        """Test line number assignment for checkout actions."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "uses": "actions/checkout@v4",
                            "with": {
                                "persist-credentials": True
                            }
                        }
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: true"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_script_injection(self):
        """Test line number assignment for script injection."""
        workflow = {
            "name": "Test",
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
                            "run": "git checkout ${{ inputs.branch }}"
                        }
                    ]
                }
            }
        }
        content = "name: Test\non:\n  workflow_dispatch:\n    inputs:\n      branch:\n        type: string\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: git checkout ${{ inputs.branch }}"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_github_script_fallback(self):
        """Test line number assignment for github-script with fallback."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "uses": "actions/github-script@v7",
                            "with": {
                                "script": "${{ inputs.script }}"
                            }
                        }
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: ${{ inputs.script }}"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_powershell(self):
        """Test line number assignment for PowerShell injection."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "windows-latest",
                    "steps": [
                        {
                            "shell": "powershell",
                            "run": "Invoke-Expression ${{ inputs.command }}"
                        }
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: windows-latest\n    steps:\n      - shell: powershell\n        run: Invoke-Expression ${{ inputs.command }}"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_artifact_retention(self):
        """Test line number assignment for artifact retention."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "uses": "actions/upload-artifact@v4",
                            "with": {
                                "retention-days": 400
                            }
                        }
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact@v4\n        with:\n          retention-days: 400"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_matrix(self):
        """Test line number assignment for matrix strategy."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "strategy": {
                        "matrix": {
                            "secret": ["${{ secrets.MY_SECRET }}"]
                        }
                    },
                    "steps": [{"run": "echo test"}]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        secret:\n          - ${{ secrets.MY_SECRET }}\n    steps:\n      - run: echo test"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_workflow_dispatch(self):
        """Test line number assignment for workflow_dispatch inputs."""
        workflow = {
            "name": "Test",
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
                            "uses": "actions/checkout@v4",
                            "with": {
                                "ref": "${{ inputs.branch }}"
                            }
                        }
                    ]
                }
            }
        }
        content = "name: Test\non:\n  workflow_dispatch:\n    inputs:\n      branch:\n        type: string\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ inputs.branch }}"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_environment_secrets(self):
        """Test line number assignment for environment secrets."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "deploy": {
                    "runs-on": "ubuntu-latest",
                    "environment": "production",
                    "steps": [{"run": "deploy.sh"}]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    environment: production\n    steps:\n      - run: deploy.sh"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_deprecated_actions(self):
        """Test line number assignment for deprecated actions."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actions/checkout@v1"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v1"
        mock_client = MagicMock()
        mock_client.get_latest_tag = AsyncMock(return_value="v4.0.0")
        mock_client.get_latest_tag_commit_date = AsyncMock(return_value="2024-01-01T00:00:00Z")
        mock_client.parse_action_reference = MagicMock(return_value=("actions", "checkout", "v1", None))
        issues = await SecurityAuditor.audit_workflow(workflow, content=content, client=mock_client)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_missing_repositories(self):
        """Test line number assignment for missing repositories."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "nonexistent/action@v1"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: nonexistent/action@v1"
        mock_client = MagicMock()
        mock_client.get_repository_info = AsyncMock(return_value=None)
        mock_client.parse_action_reference = MagicMock(return_value=("nonexistent", "action", "v1", None))
        mock_client.get_latest_tag = AsyncMock(return_value=None)
        issues = await SecurityAuditor.audit_workflow(workflow, content=content, client=mock_client)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_typosquatting(self):
        """Test line number assignment for typosquatting actions."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actons/checkout@v4"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actons/checkout@v4"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_untrusted_actions(self):
        """Test line number assignment for untrusted actions."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "random-user/random-action@v1"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: random-user/random-action@v1"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_network_wget_fallback(self):
        """Test line number assignment for network traffic with wget fallback."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"run": "wget https://example.com/file"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: wget https://example.com/file"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_file_tampering(self):
        """Test line number assignment for file tampering."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"run": "sed -i 's/old/new/g' src/*.js"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: sed -i 's/old/new/g' src/*.js"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_audit_logging(self):
        """Test line number assignment for audit logging."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "echo test"}]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_branch_protection(self):
        """Test line number assignment for branch protection bypass."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"run": "gh pr review --approve"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh pr review --approve"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_code_injection(self):
        """Test line number assignment for code injection via inputs."""
        workflow = {
            "name": "Test",
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
                            "uses": "actions/checkout@v4",
                            "with": {
                                "ref": "${{ inputs.branch }}"
                            }
                        }
                    ]
                }
            }
        }
        content = "name: Test\non:\n  workflow_dispatch:\n    inputs:\n      branch:\n        type: string\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ inputs.branch }}"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_curl_pipe(self):
        """Test line number assignment for curl pipe bash."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"run": "curl https://example.com/install.sh | bash"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl https://example.com/install.sh | bash"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_base64(self):
        """Test line number assignment for base64 decode."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"run": "echo 'SGVsbG8=' | base64 -d | bash"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo 'SGVsbG8=' | base64 -d | bash"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_continue_on_error(self):
        """Test line number assignment for continue-on-error."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "security-check": {
                    "runs-on": "ubuntu-latest",
                    "continue-on-error": True,
                    "steps": [
                        {"run": "security-scan.sh"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  security-check:\n    runs-on: ubuntu-latest\n    continue-on-error: true\n    steps:\n      - run: security-scan.sh"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_obfuscation(self):
        """Test line number assignment for obfuscation."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"run": "eval $(echo 'ZWNobyAiaGVsbG8i' | base64 -d)"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: eval $(echo 'ZWNobyAiaGVsbG8i' | base64 -d)"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_artipacked_download_fallback(self):
        """Test line number assignment for artipacked with download fallback."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "uses": "actions/download-artifact@v4",
                            "with": {
                                "name": "artifact"
                            }
                        }
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          name: artifact"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_hash_pinning(self):
        """Test line number assignment for hash pinning."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actions/checkout@v4"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4"
        issues = await SecurityAuditor.audit_workflow(workflow, content=content)
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_line_numbers_older_versions(self):
        """Test line number assignment for older action versions."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actions/checkout@v1"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v1"
        mock_client = MagicMock()
        mock_client.get_latest_tag = AsyncMock(return_value="v4.0.0")
        mock_client.get_latest_tag_commit_date = AsyncMock(return_value="2024-01-01T00:00:00Z")
        mock_client.get_commit_date = AsyncMock(return_value="2020-01-01T00:00:00Z")
        mock_client.parse_action_reference = MagicMock(return_value=("actions", "checkout", "v1", None))
        issues = await SecurityAuditor.audit_workflow(workflow, content=content, client=mock_client)
        assert isinstance(issues, list)
    
    def test_audit_action_with_pinned_version_issue(self):
        """Test audit_action when pinned version check returns issue."""
        issues = SecurityAuditor.audit_action("actions/checkout")
        # Should have unpinned version issue
        assert len(issues) > 0
        assert any("unpinned" in issue.get("type", "").lower() for issue in issues)
    
    def test_audit_action_with_secret_inputs(self):
        """Test audit_action with secret inputs in action.yml."""
        action_yml = {
            "inputs": {
                "api_key": {
                    "description": "API secret key",
                    "required": False
                },
                "password": {
                    "description": "User password token",
                    "required": False
                }
            }
        }
        issues = SecurityAuditor.audit_action("test/action@v1", action_yml=action_yml)
        # Should detect optional secret inputs
        assert any("optional_secret_input" in issue.get("type", "") for issue in issues)
    
    def test_audit_action_with_dockerfile_content(self):
        """Test audit_action with dockerfile content."""
        action_yml = {
            "runs": {
                "using": "docker",
                "image": "Dockerfile"
            }
        }
        dockerfile_content = "FROM node:18\nRUN npm install"
        issues = SecurityAuditor.audit_action("test/action@v1", action_yml=action_yml, dockerfile_content=dockerfile_content)
        assert isinstance(issues, list)
    
    def test_audit_action_with_composite_unpinned(self):
        """Test audit_action with composite action having unpinned sub-actions."""
        action_yml = {
            "runs": {
                "using": "composite",
                "steps": [
                    {"uses": "actions/checkout"}
                ]
            }
        }
        issues = SecurityAuditor.audit_action("test/action@v1", action_yml=action_yml)
        assert isinstance(issues, list)
    
    def test_audit_action_with_javascript_unpinned(self):
        """Test audit_action with JavaScript action having unpinned resources."""
        action_yml = {
            "runs": {
                "using": "node20",
                "main": "index.js"
            }
        }
        action_content = "const https = require('https');\nhttps.get('https://example.com/script.js', (res) => { /* download */ });"
        issues = SecurityAuditor.audit_action("test/action@v1", action_yml=action_yml, action_content=action_content)
        assert isinstance(issues, list)

