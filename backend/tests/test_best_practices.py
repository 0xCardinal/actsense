"""Tests for best practice checks."""
import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rules import best_practices as best_practices_rules


class TestPinnedVersion:
    """Tests for action version pinning."""
    
    def test_unpinned_version(self, workflow_with_unpinned_actions):
        """Test detection of unpinned actions."""
        issues = []
        for step in workflow_with_unpinned_actions["jobs"]["test"]["steps"]:
            if "uses" in step:
                result = best_practices_rules.check_pinned_version(step["uses"])
                if result:
                    issues.append(result)
        
        unpinned_issues = [i for i in issues if i.get("type") == "unpinned_version"]
        assert len(unpinned_issues) > 0
        assert unpinned_issues[0]["severity"] == "high"
        assert "actsense.dev/vulnerabilities/unpinned_version" in unpinned_issues[0]["evidence"]["vulnerability"]
    
    def test_pinned_version(self):
        """Test that pinned versions are not flagged."""
        result = best_practices_rules.check_pinned_version("actions/checkout@v4")
        assert result is None or result.get("type") != "unpinned_version"
    
    def test_no_hash_pinning(self, workflow_with_no_hash_pinning):
        """Test detection of tag pinning instead of SHA."""
        issues = best_practices_rules.check_hash_pinning(workflow_with_no_hash_pinning)
        
        hash_issues = [i for i in issues if i.get("type") == "no_hash_pinning"]
        if len(hash_issues) > 0:
            assert "actsense.dev/vulnerabilities/no_hash_pinning" in hash_issues[0]["evidence"]["vulnerability"]
    
    def test_short_hash_pinning(self, workflow_with_short_hash):
        """Test detection of short SHA hash."""
        issues = best_practices_rules.check_hash_pinning(workflow_with_short_hash)
        
        short_hash_issues = [i for i in issues if i.get("type") == "short_hash_pinning"]
        if len(short_hash_issues) > 0:
            assert "actsense.dev/vulnerabilities/short_hash_pinning" in short_hash_issues[0]["evidence"]["vulnerability"]


@pytest.mark.asyncio
class TestOlderActionVersions:
    """Tests for older action version detection."""
    
    async def test_older_action_version(self, workflow_with_older_action_version, mock_github_client):
        """Test detection of older action versions."""
        issues = await best_practices_rules.check_older_action_versions(
            workflow_with_older_action_version,
            client=mock_github_client
        )
        
        older_version_issues = [i for i in issues if i.get("type") == "older_action_version"]
        if len(older_version_issues) > 0:
            assert "actsense.dev/vulnerabilities/older_action_version" in older_version_issues[0]["evidence"]["vulnerability"]
    
    def test_inconsistent_action_versions(self, workflow_with_inconsistent_versions):
        """Test detection of inconsistent action versions."""
        issues = best_practices_rules.check_inconsistent_action_versions(workflow_with_inconsistent_versions)
        
        inconsistent_issues = [i for i in issues if i.get("type") == "inconsistent_action_version"]
        assert len(inconsistent_issues) > 0
        assert "actsense.dev/vulnerabilities/inconsistent_action_version" in inconsistent_issues[0]["evidence"]["vulnerability"]


class TestPermissions:
    """Tests for permission checks."""
    
    def test_overly_permissive(self, workflow_with_overly_permissive):
        """Test detection of overly permissive permissions."""
        issues = best_practices_rules.check_permissions(workflow_with_overly_permissive)
        
        permissive_issues = [i for i in issues if i.get("type") == "overly_permissive"]
        if len(permissive_issues) > 0:
            assert "actsense.dev/vulnerabilities/overly_permissive" in permissive_issues[0]["evidence"]["vulnerability"]
    
    def test_github_token_write_all(self, workflow_with_write_all_permissions):
        """Test detection of write-all permissions."""
        issues = best_practices_rules.check_github_token_permissions(workflow_with_write_all_permissions)
        
        write_all_issues = [i for i in issues if i.get("type") == "github_token_write_all"]
        assert len(write_all_issues) > 0
        assert write_all_issues[0]["severity"] == "high"
        assert "actsense.dev/vulnerabilities/github_token_write_all" in write_all_issues[0]["evidence"]["vulnerability"]
    
    def test_github_token_write_permissions(self):
        """Test detection of write permissions."""
        workflow = {
            "name": "Write Permissions",
            "on": ["push"],
            "permissions": {
                "contents": "write",
                "pull-requests": "write"
            },
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"name": "Test", "run": "echo test"}]
                }
            }
        }
        
        issues = best_practices_rules.check_github_token_permissions(workflow)
        write_perm_issues = [i for i in issues if i.get("type") == "github_token_write_permissions"]
        if len(write_perm_issues) > 0:
            assert "actsense.dev/vulnerabilities/github_token_write_permissions" in write_perm_issues[0]["evidence"]["vulnerability"]
    
    def test_excessive_write_permissions(self, workflow_with_overly_permissive):
        """Test detection of excessive write permissions."""
        issues = best_practices_rules.check_excessive_write_permissions(workflow_with_overly_permissive)
        
        excessive_issues = [i for i in issues if i.get("type") == "excessive_write_permissions"]
        if len(excessive_issues) > 0:
            assert "actsense.dev/vulnerabilities/excessive_write_permissions" in excessive_issues[0]["evidence"]["vulnerability"]


class TestMatrixStrategy:
    """Tests for matrix strategy vulnerabilities."""
    
    def test_secrets_in_matrix(self, workflow_with_secrets_in_matrix):
        """Test detection of secrets in matrix."""
        issues = best_practices_rules.check_matrix_strategy(workflow_with_secrets_in_matrix)
        
        matrix_secret_issues = [i for i in issues if i.get("type") == "secrets_in_matrix"]
        assert len(matrix_secret_issues) > 0
        assert "actsense.dev/vulnerabilities/secrets_in_matrix" in matrix_secret_issues[0]["evidence"]["vulnerability"]
    
    def test_large_matrix(self, workflow_with_large_matrix):
        """Test detection of large matrix strategy."""
        issues = best_practices_rules.check_matrix_strategy(workflow_with_large_matrix)
        
        large_matrix_issues = [i for i in issues if i.get("type") == "large_matrix"]
        if len(large_matrix_issues) > 0:
            assert "actsense.dev/vulnerabilities/large_matrix" in large_matrix_issues[0]["evidence"]["vulnerability"]


class TestWorkflowDispatchInputs:
    """Tests for workflow_dispatch input validation."""
    
    def test_unvalidated_workflow_input(self, workflow_with_unvalidated_inputs):
        """Test detection of unvalidated workflow inputs."""
        issues = best_practices_rules.check_workflow_dispatch_inputs(workflow_with_unvalidated_inputs)
        
        input_issues = [i for i in issues if i.get("type") == "unvalidated_workflow_input"]
        if len(input_issues) > 0:
            assert "actsense.dev/vulnerabilities/unvalidated_workflow_input" in input_issues[0]["evidence"]["vulnerability"]


class TestArtifactRetention:
    """Tests for artifact retention settings."""
    
    def test_long_artifact_retention(self, workflow_with_long_artifact_retention):
        """Test detection of long artifact retention."""
        issues = best_practices_rules.check_artifact_retention(workflow_with_long_artifact_retention)
        
        retention_issues = [i for i in issues if i.get("type") == "long_artifact_retention"]
        if len(retention_issues) > 0:
            assert "actsense.dev/vulnerabilities/long_artifact_retention" in retention_issues[0]["evidence"]["vulnerability"]


class TestEnvironmentSecrets:
    """Tests for environment secrets."""
    
    def test_environment_with_secrets(self, workflow_with_environment_secrets):
        """Test detection of environment with secrets."""
        issues = best_practices_rules.check_environment_secrets(workflow_with_environment_secrets)
        
        env_secret_issues = [i for i in issues if i.get("type") == "environment_with_secrets"]
        if len(env_secret_issues) > 0:
            assert "actsense.dev/vulnerabilities/environment_with_secrets" in env_secret_issues[0]["evidence"]["vulnerability"]


class TestDeprecatedActions:
    """Tests for deprecated action detection."""
    
    @pytest.mark.asyncio
    async def test_deprecated_action(self, workflow_with_deprecated_action):
        """Test detection of deprecated actions."""
        issues = await best_practices_rules.check_deprecated_actions(workflow_with_deprecated_action)
        
        deprecated_issues = [i for i in issues if i.get("type") == "deprecated_action"]
        if len(deprecated_issues) > 0:
            assert "actsense.dev/vulnerabilities/deprecated_action" in deprecated_issues[0]["evidence"]["vulnerability"]


class TestContinueOnError:
    """Tests for continue-on-error in critical jobs."""
    
    def test_continue_on_error_critical_job(self, workflow_with_continue_on_error):
        """Test detection of continue-on-error in critical jobs."""
        issues = best_practices_rules.check_continue_on_error_critical_job(workflow_with_continue_on_error)
        
        continue_error_issues = [i for i in issues if i.get("type") == "continue_on_error_critical_job"]
        if len(continue_error_issues) > 0:
            assert "actsense.dev/vulnerabilities/continue_on_error_critical_job" in continue_error_issues[0]["evidence"]["vulnerability"]


class TestAuditLogging:
    """Tests for audit logging."""
    
    def test_insufficient_audit_logging(self):
        """Test detection of insufficient audit logging."""
        workflow = {
            "name": "No Audit Logging",
            "on": ["push"],
            "jobs": {
                "deploy": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Deploy",
                            "run": "deploy.sh"
                        }
                    ]
                }
            }
        }
        
        issues = best_practices_rules.check_audit_logging(workflow)
        audit_issues = [i for i in issues if i.get("type") == "insufficient_audit_logging"]
        if len(audit_issues) > 0:
            assert "actsense.dev/vulnerabilities/insufficient_audit_logging" in audit_issues[0]["evidence"]["vulnerability"]


class TestUnpinnableActions:
    """Tests for unpinnable action detection."""
    
    def test_unpinnable_docker_action(self, workflow_with_unpinnable_docker):
        """Test detection of unpinnable Docker actions."""
        issues = best_practices_rules.check_unpinnable_docker_action(
            workflow_with_unpinnable_docker,
            "test/docker-action@v1",
            None
        )
        
        docker_issues = [i for i in issues if i.get("type") == "unpinnable_docker_image"]
        if len(docker_issues) > 0:
            assert "actsense.dev/vulnerabilities/unpinnable_docker_image" in docker_issues[0]["evidence"]["vulnerability"]
    
    def test_unpinnable_composite_action(self, workflow_with_unpinnable_composite):
        """Test detection of unpinnable composite actions."""
        issues = best_practices_rules.check_unpinnable_composite_action(
            workflow_with_unpinnable_composite,
            "test/composite-action@v1"
        )
        
        composite_issues = [i for i in issues if i.get("type") == "unpinnable_composite_subaction"]
        if len(composite_issues) > 0:
            assert "actsense.dev/vulnerabilities/unpinnable_composite_subaction" in composite_issues[0]["evidence"]["vulnerability"]
    
    def test_unpinnable_javascript_action(self, workflow_with_unpinnable_javascript):
        """Test detection of unpinnable JavaScript actions."""
        issues = best_practices_rules.check_unpinnable_javascript_action(
            workflow_with_unpinnable_javascript,
            "test/js-action@v1",
            None
        )
        
        js_issues = [i for i in issues if i.get("type") == "unpinned_javascript_resources"]
        if len(js_issues) > 0:
            assert "actsense.dev/vulnerabilities/unpinned_javascript_resources" in js_issues[0]["evidence"]["vulnerability"]


class TestUnpinnedDockerfileResources:
    """Tests for unpinned Dockerfile resources."""
    
    def test_unpinned_dockerfile_dependencies(self):
        """Test detection of unpinned Dockerfile dependencies."""
        dockerfile_content = """
FROM node:18
RUN apt-get update && apt-get install -y python3
RUN pip install requests
"""
        
        action_yml = {
            "name": "Docker Action",
            "runs": {
                "using": "docker",
                "image": "Dockerfile"
            }
        }
        
        issues = best_practices_rules.check_unpinnable_docker_action(
            action_yml,
            "test/action@v1",
            dockerfile_content
        )
        
        deps_issues = [i for i in issues if i.get("type") == "unpinned_dockerfile_dependencies"]
        if len(deps_issues) > 0:
            assert "actsense.dev/vulnerabilities/unpinned_dockerfile_dependencies" in deps_issues[0]["evidence"]["vulnerability"]
    
    def test_unpinned_dockerfile_resources(self):
        """Test detection of unpinned Dockerfile resources."""
        dockerfile_content = """
FROM node:18
RUN curl https://example.com/script.sh | bash
RUN wget https://example.com/file.tar.gz
"""
        
        action_yml = {
            "name": "Docker Action",
            "runs": {
                "using": "docker",
                "image": "Dockerfile"
            }
        }
        
        issues = best_practices_rules.check_unpinnable_docker_action(
            action_yml,
            "test/action@v1",
            dockerfile_content
        )
        
        resource_issues = [i for i in issues if i.get("type") == "unpinned_dockerfile_resources"]
        if len(resource_issues) > 0:
            assert "actsense.dev/vulnerabilities/unpinned_dockerfile_resources" in resource_issues[0]["evidence"]["vulnerability"]


class TestUnpinnedPackages:
    """Tests for unpinned package dependencies."""
    
    def test_unpinned_npm_packages(self):
        """Test detection of unpinned npm packages."""
        action_content = """
const core = require('@actions/core');
const axios = require('axios');
"""
        
        action_yml = {
            "name": "JavaScript Action",
            "runs": {
                "using": "node20",
                "main": "index.js"
            }
        }
        
        issues = best_practices_rules.check_unpinnable_javascript_action(
            action_yml,
            "test/action@v1",
            action_content
        )
        
        npm_issues = [i for i in issues if i.get("type") == "unpinned_npm_packages"]
        if len(npm_issues) > 0:
            assert "actsense.dev/vulnerabilities/unpinned_npm_packages" in npm_issues[0]["evidence"]["vulnerability"]
    
    def test_unpinned_python_packages(self):
        """Test detection of unpinned Python packages."""
        action_content = """
import requests
import boto3
"""
        
        action_yml = {
            "name": "Python Action",
            "runs": {
                "using": "composite",
                "steps": [
                    {
                        "run": "pip install requests boto3"
                    }
                ]
            }
        }
        
        issues = best_practices_rules.check_unpinnable_javascript_action(
            action_yml,
            "test/action@v1",
            action_content
        )
        
        python_issues = [i for i in issues if i.get("type") == "unpinned_python_packages"]
        if len(python_issues) > 0:
            assert "actsense.dev/vulnerabilities/unpinned_python_packages" in python_issues[0]["evidence"]["vulnerability"]
    
    def test_unpinned_external_resources(self):
        """Test detection of unpinned external resources."""
        action_content = """
const https = require('https');
https.get('https://example.com/script.js', (res) => {
    // Download and execute
});
"""
        
        action_yml = {
            "name": "JavaScript Action",
            "runs": {
                "using": "node20",
                "main": "index.js"
            }
        }
        
        issues = best_practices_rules.check_unpinnable_javascript_action(
            action_yml,
            "test/action@v1",
            action_content
        )
        
        external_issues = [i for i in issues if i.get("type") == "unpinned_external_resources"]
        if len(external_issues) > 0:
            assert "actsense.dev/vulnerabilities/unpinned_external_resources" in external_issues[0]["evidence"]["vulnerability"]

