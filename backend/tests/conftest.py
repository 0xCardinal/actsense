"""Pytest configuration and fixtures."""
import pytest
from typing import Dict, Any


@pytest.fixture
def sample_workflow() -> Dict[str, Any]:
    """Basic workflow structure for testing."""
    return {
        "name": "Test Workflow",
        "on": {
            "push": {
                "branches": ["main"]
            }
        },
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Checkout",
                        "uses": "actions/checkout@v4"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_secrets() -> Dict[str, Any]:
    """Workflow with hardcoded secrets."""
    return {
        "name": "Workflow with Secrets",
        "on": ["push"],
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Build",
                        "run": "echo 'Building'",
                        "env": {
                            "API_KEY": "sk_live_123456789012345678901234567890",
                            "password": "mySecretPassword123"
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_aws_credentials() -> Dict[str, Any]:
    """Workflow with AWS long-term credentials."""
    return {
        "name": "AWS Workflow",
        "on": ["push"],
        "jobs": {
            "deploy": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Deploy",
                        "run": "aws s3 sync . s3://bucket",
                        "env": {
                            "AWS_ACCESS_KEY_ID": "${{ secrets.AWS_ACCESS_KEY_ID }}",
                            "AWS_SECRET_ACCESS_KEY": "${{ secrets.AWS_SECRET_ACCESS_KEY }}"
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_self_hosted_runner() -> Dict[str, Any]:
    """Workflow using self-hosted runner."""
    return {
        "name": "Self-hosted Workflow",
        "on": {
            "pull_request": {}
        },
        "jobs": {
            "test": {
                "runs-on": "self-hosted",
                "steps": [
                    {
                        "name": "Test",
                        "run": "echo 'Testing'"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_unpinned_actions() -> Dict[str, Any]:
    """Workflow with unpinned actions."""
    return {
        "name": "Unpinned Actions",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Checkout",
                        "uses": "actions/checkout"
                    },
                    {
                        "name": "Setup Node",
                        "uses": "actions/setup-node@main"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_write_all_permissions() -> Dict[str, Any]:
    """Workflow with write-all permissions."""
    return {
        "name": "Write All Permissions",
        "on": ["push"],
        "permissions": "write-all",
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Test",
                        "run": "echo 'test'"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_pull_request_target() -> Dict[str, Any]:
    """Workflow using pull_request_target event."""
    return {
        "name": "PR Target Workflow",
        "on": {
            "pull_request_target": {}
        },
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Checkout",
                        "uses": "actions/checkout@v4",
                        "with": {
                            "ref": "${{ github.event.pull_request.head.sha }}"
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_shell_injection() -> Dict[str, Any]:
    """Workflow vulnerable to shell injection."""
    return {
        "name": "Shell Injection",
        "on": {
            "workflow_dispatch": {
                "inputs": {
                    "branch": {
                        "type": "string"
                    }
                }
            }
        },
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Dangerous",
                        "run": "git checkout ${{ inputs.branch }}"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_curl_pipe_bash() -> Dict[str, Any]:
    """Workflow with curl piped to bash."""
    return {
        "name": "Curl Pipe Bash",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Install",
                        "run": "curl https://example.com/install.sh | bash"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_base64_decode() -> Dict[str, Any]:
    """Workflow with base64 decode execution."""
    return {
        "name": "Base64 Decode",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Decode",
                        "run": "echo 'SGVsbG8gV29ybGQ=' | base64 -d | bash"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_secrets_in_matrix() -> Dict[str, Any]:
    """Workflow with secrets in matrix."""
    return {
        "name": "Secrets in Matrix",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "strategy": {
                    "matrix": {
                        "env": ["dev", "prod"],
                        "secret": ["${{ secrets.DEV_SECRET }}", "${{ secrets.PROD_SECRET }}"]
                    }
                },
                "steps": [
                    {
                        "name": "Test",
                        "run": "echo 'Testing'"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_continue_on_error() -> Dict[str, Any]:
    """Workflow with continue-on-error in critical job."""
    return {
        "name": "Continue on Error",
        "on": ["push"],
        "jobs": {
            "security-check": {
                "runs-on": "ubuntu-latest",
                "continue-on-error": True,
                "steps": [
                    {
                        "name": "Security Scan",
                        "run": "security-scan.sh"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_unvalidated_inputs() -> Dict[str, Any]:
    """Workflow with unvalidated workflow_call inputs."""
    return {
        "name": "Unvalidated Inputs",
        "on": {
            "workflow_call": {
                "inputs": {
                    "branch": {
                        "type": "string",
                        "required": False
                    }
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


@pytest.fixture
def workflow_with_unsafe_checkout() -> Dict[str, Any]:
    """Workflow with unsafe checkout configuration."""
    return {
        "name": "Unsafe Checkout",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Checkout",
                        "uses": "actions/checkout@v4",
                        "with": {
                            "persist-credentials": True,
                            "fetch-depth": 0
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_typosquatting() -> Dict[str, Any]:
    """Workflow with potential typosquatting."""
    return {
        "name": "Typosquatting",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Checkout",
                        "uses": "actons/checkout@v4"  # Typo: actons instead of actions
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_untrusted_action() -> Dict[str, Any]:
    """Workflow with untrusted third-party action."""
    return {
        "name": "Untrusted Action",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Untrusted",
                        "uses": "random-user/random-action@v1"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_network_operations() -> Dict[str, Any]:
    """Workflow with unfiltered network operations."""
    return {
        "name": "Network Operations",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Download",
                        "run": "curl https://example.com/data && wget https://example.com/file"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_branch_protection_bypass() -> Dict[str, Any]:
    """Workflow that could bypass branch protection."""
    return {
        "name": "Branch Protection Bypass",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Auto Approve",
                        "run": "gh pr review --approve"
                    },
                    {
                        "name": "Auto Merge",
                        "run": "gh pr merge --auto"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_artifact_upload() -> Dict[str, Any]:
    """Workflow with artifact upload."""
    return {
        "name": "Artifact Upload",
        "on": ["push"],
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Upload",
                        "uses": "actions/upload-artifact@v4",
                        "with": {
                            "path": "."
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_environment_secrets() -> Dict[str, Any]:
    """Workflow with environment secrets."""
    return {
        "name": "Environment Secrets",
        "on": ["push"],
        "jobs": {
            "deploy": {
                "runs-on": "ubuntu-latest",
                "environment": "production",
                "steps": [
                    {
                        "name": "Deploy",
                        "run": "deploy.sh"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_deprecated_action() -> Dict[str, Any]:
    """Workflow with deprecated action."""
    return {
        "name": "Deprecated Action",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Old Action",
                        "uses": "actions/checkout@v1"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_older_action_version() -> Dict[str, Any]:
    """Workflow with older action version."""
    return {
        "name": "Older Version",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Old Version",
                        "uses": "actions/checkout@v1"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_no_hash_pinning() -> Dict[str, Any]:
    """Workflow with tag pinning instead of SHA."""
    return {
        "name": "No Hash Pinning",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Checkout",
                        "uses": "actions/checkout@v4"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_short_hash() -> Dict[str, Any]:
    """Workflow with short SHA hash."""
    return {
        "name": "Short Hash",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Checkout",
                        "uses": "actions/checkout@8f4b7f8"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_overly_permissive() -> Dict[str, Any]:
    """Workflow with overly permissive permissions."""
    return {
        "name": "Overly Permissive",
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
                "steps": [
                    {
                        "name": "Read",
                        "run": "cat README.md"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_github_script_injection() -> Dict[str, Any]:
    """Workflow with github-script injection vulnerability."""
    return {
        "name": "GitHub Script Injection",
        "on": {
            "workflow_dispatch": {
                "inputs": {
                    "script": {
                        "type": "string"
                    }
                }
            }
        },
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Run Script",
                        "uses": "actions/github-script@v7",
                        "with": {
                            "script": "${{ inputs.script }}"
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_powershell_injection() -> Dict[str, Any]:
    """Workflow with PowerShell injection vulnerability."""
    return {
        "name": "PowerShell Injection",
        "on": {
            "workflow_dispatch": {
                "inputs": {
                    "command": {
                        "type": "string"
                    }
                }
            }
        },
        "jobs": {
            "test": {
                "runs-on": "windows-latest",
                "steps": [
                    {
                        "name": "Run Command",
                        "shell": "powershell",
                        "run": "Invoke-Expression ${{ inputs.command }}"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_cross_repo_access() -> Dict[str, Any]:
    """Workflow with cross-repository access."""
    return {
        "name": "Cross Repo Access",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Checkout Other Repo",
                        "uses": "actions/checkout@v4",
                        "with": {
                            "repository": "other-org/other-repo"
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_obfuscation() -> Dict[str, Any]:
    """Workflow with code obfuscation."""
    return {
        "name": "Obfuscation",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Obfuscated",
                        "run": "eval $(echo 'ZWNobyAiaGVsbG8i' | base64 -d)"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_token_manipulation() -> Dict[str, Any]:
    """Workflow with token permission escalation patterns."""
    return {
        "name": "Token Manipulation",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Token Manipulation",
                        "run": "echo ${{ secrets.GITHUB_TOKEN }} | base64"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_unsafe_shell() -> Dict[str, Any]:
    """Workflow with unsafe shell (no -e flag)."""
    return {
        "name": "Unsafe Shell",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Unsafe",
                        "shell": "bash",
                        "run": "false\necho 'This should not run'"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_environment_bypass() -> Dict[str, Any]:
    """Workflow that could bypass environment protection."""
    return {
        "name": "Environment Bypass",
        "on": {
            "pull_request": {}
        },
        "jobs": {
            "deploy": {
                "runs-on": "ubuntu-latest",
                "environment": "production",
                "steps": [
                    {
                        "name": "Deploy",
                        "run": "deploy.sh"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_secrets_to_untrusted() -> Dict[str, Any]:
    """Workflow passing secrets to untrusted action."""
    return {
        "name": "Secrets to Untrusted",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Untrusted Action",
                        "uses": "random-user/action@v1",
                        "with": {
                            "secret": "${{ secrets.MY_SECRET }}"
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_file_tampering() -> Dict[str, Any]:
    """Workflow that modifies files during build."""
    return {
        "name": "File Tampering",
        "on": ["push"],
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Modify Files",
                        "run": "sed -i 's/old/new/g' src/*.js"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_large_matrix() -> Dict[str, Any]:
    """Workflow with large matrix strategy."""
    return {
        "name": "Large Matrix",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "strategy": {
                    "matrix": {
                        "os": ["ubuntu-20.04", "ubuntu-22.04", "windows-2019", "windows-2022", "macos-11", "macos-12", "macos-13", "macos-14"],
                        "node": ["14", "16", "18", "20"],
                        "python": ["3.8", "3.9", "3.10", "3.11", "3.12"]
                    }
                },
                "steps": [
                    {
                        "name": "Test",
                        "run": "echo 'Testing'"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_long_artifact_retention() -> Dict[str, Any]:
    """Workflow with long artifact retention."""
    return {
        "name": "Long Retention",
        "on": ["push"],
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Upload",
                        "uses": "actions/upload-artifact@v4",
                        "with": {
                            "path": "dist",
                            "retention-days": 400
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_runner_label_confusion() -> Dict[str, Any]:
    """Workflow with confusing runner labels."""
    return {
        "name": "Runner Label Confusion",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": ["self-hosted", "ubuntu-latest"],
                "steps": [
                    {
                        "name": "Test",
                        "run": "echo 'test'"
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_public_repo_self_hosted() -> Dict[str, Any]:
    """Public repo workflow with self-hosted runner."""
    return {
        "name": "Public Repo Self-hosted",
        "on": ["push"],
        "jobs": {
            "test": {
                "runs-on": "self-hosted",
                "steps": [
                    {
                        "name": "Test",
                        "run": "echo 'test'",
                        "env": {
                            "SECRET": "${{ secrets.MY_SECRET }}"
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def workflow_with_inconsistent_versions() -> Dict[str, Any]:
    """Multiple workflows with inconsistent action versions."""
    return [
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


@pytest.fixture
def workflow_with_unpinnable_docker() -> Dict[str, Any]:
    """Action with unpinnable Docker image."""
    return {
        "name": "Docker Action",
        "runs": {
            "using": "docker",
            "image": "node:18"
        },
        "inputs": {}
    }


@pytest.fixture
def workflow_with_unpinnable_composite() -> Dict[str, Any]:
    """Composite action with unpinned sub-actions."""
    return {
        "name": "Composite Action",
        "runs": {
            "using": "composite",
            "steps": [
                {
                    "uses": "actions/checkout@v4"
                },
                {
                    "uses": "actions/setup-node@v3"
                }
            ]
        }
    }


@pytest.fixture
def workflow_with_unpinnable_javascript() -> Dict[str, Any]:
    """JavaScript action with unpinned resources."""
    return {
        "name": "JavaScript Action",
        "runs": {
            "using": "node20",
            "main": "index.js"
        }
    }


@pytest.fixture
def workflow_content_with_secret() -> str:
    """Workflow content with hardcoded secret."""
    return """
name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test
        run: |
          export API_KEY="sk_live_123456789012345678901234567890"
          echo "Testing"
"""


@pytest.fixture
def mock_github_client():
    """Mock GitHub client for testing."""
    from unittest.mock import AsyncMock, MagicMock
    
    client = MagicMock()
    client.get_latest_tag = AsyncMock(return_value="v4.0.0")
    client.get_latest_tag_commit_date = AsyncMock(return_value="2024-01-01T00:00:00Z")
    client.get_commit_date = AsyncMock(return_value="2023-01-01T00:00:00Z")
    client.parse_action_reference = MagicMock(return_value=("actions", "checkout", None, None))
    return client


