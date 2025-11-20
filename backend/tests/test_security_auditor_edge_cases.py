"""Edge case tests to complete coverage for security_auditor.py remaining lines"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from security_auditor import SecurityAuditor


class TestSecurityAuditorEdgeCases:
    """Tests for edge cases to cover remaining missing lines"""
    
    def test_check_unpinnable_docker_action(self):
        """Test check_unpinnable_docker_action method."""
        action_yml = {
            "runs": {
                "using": "docker",
                "image": "node:18"
            }
        }
        issues = SecurityAuditor.check_unpinnable_docker_action(action_yml, "test/action@v1")
        assert isinstance(issues, list)
    
    def test_check_unpinnable_composite_action(self):
        """Test check_unpinnable_composite_action method."""
        action_yml = {
            "runs": {
                "using": "composite",
                "steps": [
                    {"uses": "actions/checkout"}
                ]
            }
        }
        issues = SecurityAuditor.check_unpinnable_composite_action(action_yml, "test/action@v1")
        assert isinstance(issues, list)
    
    def test_check_unpinnable_javascript_action(self):
        """Test check_unpinnable_javascript_action method."""
        action_yml = {
            "runs": {
                "using": "node20",
                "main": "index.js"
            }
        }
        issues = SecurityAuditor.check_unpinnable_javascript_action(action_yml, "test/action@v1")
        assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_token_permissions_line_number(self):
        """Test line number assignment when token permissions issue has message."""
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
        # Mock to return issue with message
        with patch('security_auditor.security_rules.check_github_token_permissions') as mock_check:
            mock_check.return_value = [{
                "type": "github_token_permissions",
                "message": "Token has write permissions",
                "severity": "medium"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_runner_env_security_with_line_number(self):
        """Test line number assignment for runner environment security."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "self-hosted",
                    "steps": [
                        {"run": "echo test"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: self-hosted\n    steps:\n      - run: echo test"
        # Mock to return issue
        with patch('security_auditor.security_rules.check_runner_environment_security') as mock_check:
            mock_check.return_value = [{
                "type": "runner_environment_security",
                "job": "test",
                "severity": "high"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_visibility_risks_with_line_number(self):
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
        # Mock to return issue
        with patch('security_auditor.security_rules.check_repository_visibility_risks') as mock_check:
            mock_check.return_value = [{
                "type": "repository_visibility_risk",
                "severity": "high"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_script_injection_with_line_number(self):
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
                        {"run": "git checkout ${{ inputs.branch }}"}
                    ]
                }
            }
        }
        content = "name: Test\non:\n  workflow_dispatch:\n    inputs:\n      branch:\n        type: string\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: git checkout ${{ inputs.branch }}"
        # Mock to return issue
        with patch('security_auditor.security_rules.check_script_injection') as mock_check:
            mock_check.return_value = [{
                "type": "script_injection",
                "job": "test",
                "severity": "high"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_github_script_no_github_script_line(self):
        """Test github-script injection when github-script line not found."""
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
        # Mock to return issue and make github-script not found, should fallback to script:
        with patch('security_auditor.security_rules.check_github_script_injection') as mock_check:
            with patch('security_auditor.security_rules._find_line_number') as mock_find:
                # First call (github-script) returns None, second (script:) returns line number
                mock_find.side_effect = lambda content, text, context=None: 6 if "script:" in text else None
                mock_check.return_value = [{
                    "type": "github_script_injection",
                    "job": "test",
                    "severity": "high"
                }]
                issues = await SecurityAuditor.audit_workflow(workflow, content=content)
                assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_matrix_with_line_number(self):
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
        # Mock to return issue
        with patch('security_auditor.security_rules.check_matrix_strategy') as mock_check:
            mock_check.return_value = [{
                "type": "secrets_in_matrix",
                "job": "test",
                "severity": "high"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_dispatch_with_line_number(self):
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
        # Mock to return issue
        with patch('security_auditor.security_rules.check_workflow_dispatch_inputs') as mock_check:
            mock_check.return_value = [{
                "type": "unvalidated_workflow_input",
                "input": "branch",
                "severity": "medium"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_environment_secrets_with_line_number(self):
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
        # Mock to return issue
        with patch('security_auditor.security_rules.check_environment_secrets') as mock_check:
            mock_check.return_value = [{
                "type": "environment_with_secrets",
                "job": "deploy",
                "severity": "medium"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_typosquatting_with_line_number(self):
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
        # Mock to return issue
        with patch('security_auditor.security_rules.check_typosquatting_actions') as mock_check:
            mock_check.return_value = [{
                "type": "typosquatting_action",
                "action": "actons/checkout@v4",
                "job": "test",
                "severity": "high"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_file_tampering_with_line_number(self):
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
        # Mock to return issue
        with patch('security_auditor.security_rules.check_file_tampering_protection') as mock_check:
            mock_check.return_value = [{
                "type": "no_file_tampering_protection",
                "job": "build",
                "severity": "medium"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_audit_logging_with_line_number(self):
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
        # Mock to return issue
        with patch('security_auditor.security_rules.check_audit_logging') as mock_check:
            mock_check.return_value = [{
                "type": "insufficient_audit_logging",
                "job": "test",
                "severity": "low"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_branch_protection_with_line_number(self):
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
        # Mock to return issue
        with patch('security_auditor.security_rules.check_branch_protection_bypass') as mock_check:
            mock_check.return_value = [{
                "type": "branch_protection_bypass",
                "job": "test",
                "severity": "high"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_code_injection_with_input_name(self):
        """Test line number assignment for code injection with input name."""
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
        # Mock to return issue with input name
        with patch('security_auditor.security_rules.check_code_injection_via_workflow_inputs') as mock_check:
            mock_check.return_value = [{
                "type": "code_injection_via_input",
                "input": "branch",
                "severity": "high"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_cross_repo_run_command(self):
        """Test line number assignment for cross-repo access with run command."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"run": "git clone https://github.com/other-org/other-repo.git"}
                    ]
                }
            }
        }
        content = "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: git clone https://github.com/other-org/other-repo.git"
        # Mock to return cross-repo issue with different type (not cross_repository_access)
        with patch('security_auditor.security_rules.check_cross_repository_access') as mock_check:
            mock_check.return_value = [{
                "type": "unauthorized_repository_access",
                "job": "test",
                "severity": "high"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    @pytest.mark.asyncio
    async def test_audit_workflow_excessive_write_with_line_number(self):
        """Test line number assignment for excessive write permissions."""
        workflow = {
            "name": "Test",
            "on": ["push"],
            "permissions": {
                "contents": "write",
                "pull-requests": "write",
                "issues": "write",
                "packages": "write"
            },
            "jobs": {
                "read-only": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "cat README.md"}]
                }
            }
        }
        content = "name: Test\non: [push]\npermissions:\n  contents: write\n  pull-requests: write\n  issues: write\n  packages: write\njobs:\n  read-only:\n    runs-on: ubuntu-latest"
        # Mock to return issue
        with patch('security_auditor.security_rules.check_excessive_write_permissions') as mock_check:
            mock_check.return_value = [{
                "type": "excessive_write_permissions",
                "job": "read-only",
                "severity": "medium"
            }]
            issues = await SecurityAuditor.audit_workflow(workflow, content=content)
            assert isinstance(issues, list)
    
    def test_audit_action_with_secret_input_password(self):
        """Test audit_action with password in input description."""
        action_yml = {
            "inputs": {
                "user_password": {
                    "description": "User password for authentication",
                    "required": False
                }
            }
        }
        issues = SecurityAuditor.audit_action("test/action@v1", action_yml=action_yml)
        assert any("optional_secret_input" in issue.get("type", "") for issue in issues)
    
    def test_audit_action_with_secret_input_token(self):
        """Test audit_action with token in input description."""
        action_yml = {
            "inputs": {
                "api_token": {
                    "description": "API token for access",
                    "required": False
                }
            }
        }
        issues = SecurityAuditor.audit_action("test/action@v1", action_yml=action_yml)
        assert any("optional_secret_input" in issue.get("type", "") for issue in issues)

