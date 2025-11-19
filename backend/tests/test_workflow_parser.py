"""Tests for workflow_parser.py"""
import pytest
import yaml
from workflow_parser import WorkflowParser


class TestWorkflowParser:
    """Test WorkflowParser class."""
    
    def test_parse_workflow_valid(self):
        """Test parsing a valid workflow."""
        content = """
name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        result = WorkflowParser.parse_workflow(content)
        assert isinstance(result, dict)
        assert result["name"] == "Test Workflow"
        assert "jobs" in result
    
    def test_parse_workflow_invalid_yaml(self):
        """Test parsing invalid YAML."""
        content = "invalid: yaml: content: ["
        result = WorkflowParser.parse_workflow(content)
        assert "error" in result
    
    def test_parse_workflow_empty(self):
        """Test parsing empty content."""
        result = WorkflowParser.parse_workflow("")
        assert result == {}
    
    def test_parse_workflow_none(self):
        """Test parsing None content."""
        result = WorkflowParser.parse_workflow("---")
        assert result == {}
    
    def test_parse_workflow_string(self):
        """Test parsing YAML that results in a string."""
        result = WorkflowParser.parse_workflow("just a string")
        assert result == {}
    
    def test_parse_workflow_list(self):
        """Test parsing YAML that results in a list."""
        result = WorkflowParser.parse_workflow("- item1\n- item2")
        assert result == {}
    
    def test_extract_actions_basic(self):
        """Test extracting actions from workflow."""
        workflow = {
            "jobs": {
                "test": {
                    "steps": [
                        {"uses": "actions/checkout@v4"},
                        {"uses": "actions/setup-node@v3"}
                    ]
                }
            }
        }
        actions = WorkflowParser.extract_actions(workflow)
        assert "actions/checkout@v4" in actions
        assert "actions/setup-node@v3" in actions
    
    def test_extract_actions_nested(self):
        """Test extracting actions from nested structure."""
        workflow = {
            "jobs": {
                "job1": {
                    "steps": [
                        {"uses": "actions/checkout@v4"}
                    ]
                },
                "job2": {
                    "steps": [
                        {"uses": "actions/setup-node@v3"}
                    ]
                }
            }
        }
        actions = WorkflowParser.extract_actions(workflow)
        assert len(actions) == 2
    
    def test_extract_actions_no_actions(self):
        """Test extracting actions when none exist."""
        workflow = {
            "jobs": {
                "test": {
                    "steps": [
                        {"run": "echo 'test'"}
                    ]
                }
            }
        }
        actions = WorkflowParser.extract_actions(workflow)
        assert actions == []
    
    def test_extract_actions_skips_local_paths(self):
        """Test that local paths are skipped."""
        workflow = {
            "jobs": {
                "test": {
                    "steps": [
                        {"uses": "./local-action"},
                        {"uses": "actions/checkout@v4"}
                    ]
                }
            }
        }
        actions = WorkflowParser.extract_actions(workflow)
        assert "./local-action" not in actions
        assert "actions/checkout@v4" in actions
    
    def test_extract_actions_skips_docker(self):
        """Test that docker:// URLs are skipped."""
        workflow = {
            "jobs": {
                "test": {
                    "steps": [
                        {"uses": "docker://alpine:latest"},
                        {"uses": "actions/checkout@v4"}
                    ]
                }
            }
        }
        actions = WorkflowParser.extract_actions(workflow)
        assert "docker://alpine:latest" not in actions
        assert "actions/checkout@v4" in actions
    
    def test_extract_actions_skips_http_urls(self):
        """Test that HTTP URLs are skipped."""
        workflow = {
            "jobs": {
                "test": {
                    "steps": [
                        {"uses": "http://example.com/action"},
                        {"uses": "actions/checkout@v4"}
                    ]
                }
            }
        }
        actions = WorkflowParser.extract_actions(workflow)
        assert "http://example.com/action" not in actions
        assert "actions/checkout@v4" in actions
    
    def test_extract_actions_skips_workflow_files(self):
        """Test that workflow file paths are skipped."""
        workflow = {
            "jobs": {
                "test": {
                    "steps": [
                        {"uses": ".github/workflows/other.yml"},
                        {"uses": "actions/checkout@v4"}
                    ]
                }
            }
        }
        actions = WorkflowParser.extract_actions(workflow)
        assert ".github/workflows/other.yml" not in actions
        assert "actions/checkout@v4" in actions
    
    def test_extract_actions_deduplicates(self):
        """Test that duplicate actions are deduplicated."""
        workflow = {
            "jobs": {
                "test": {
                    "steps": [
                        {"uses": "actions/checkout@v4"},
                        {"uses": "actions/checkout@v4"}
                    ]
                }
            }
        }
        actions = WorkflowParser.extract_actions(workflow)
        assert actions.count("actions/checkout@v4") == 1
    
    def test_parse_action_yml_valid(self):
        """Test parsing valid action.yml."""
        content = """
name: 'My Action'
description: 'A test action'
inputs:
  name:
    description: 'Name input'
    required: true
runs:
  using: 'composite'
  steps:
    - run: echo "Hello"
"""
        result = WorkflowParser.parse_action_yml(content)
        assert isinstance(result, dict)
        assert result["name"] == "My Action"
        assert "runs" in result
    
    def test_parse_action_yml_invalid(self):
        """Test parsing invalid action.yml."""
        content = "invalid: yaml: ["
        result = WorkflowParser.parse_action_yml(content)
        assert "error" in result
    
    def test_parse_action_yml_empty(self):
        """Test parsing empty action.yml."""
        result = WorkflowParser.parse_action_yml("")
        assert result == {}
    
    def test_extract_action_dependencies_composite(self):
        """Test extracting dependencies from composite action."""
        action_yml = {
            "runs": {
                "using": "composite",
                "steps": [
                    {"uses": "actions/checkout@v4"},
                    {"uses": "actions/setup-node@v3"}
                ]
            }
        }
        deps = WorkflowParser.extract_action_dependencies(action_yml)
        assert "actions/checkout@v4" in deps
        assert "actions/setup-node@v3" in deps
    
    def test_extract_action_dependencies_no_runs(self):
        """Test extracting dependencies when no runs section."""
        action_yml = {
            "name": "My Action"
        }
        deps = WorkflowParser.extract_action_dependencies(action_yml)
        assert deps == []
    
    def test_extract_action_dependencies_docker(self):
        """Test extracting dependencies from Docker action."""
        action_yml = {
            "runs": {
                "using": "docker",
                "image": "alpine:latest"
            }
        }
        deps = WorkflowParser.extract_action_dependencies(action_yml)
        assert deps == []
    
    def test_extract_action_dependencies_javascript(self):
        """Test extracting dependencies from JavaScript action."""
        action_yml = {
            "runs": {
                "using": "node20",
                "main": "index.js"
            }
        }
        deps = WorkflowParser.extract_action_dependencies(action_yml)
        assert deps == []
    
    def test_extract_action_dependencies_no_steps(self):
        """Test extracting dependencies when no steps in composite."""
        action_yml = {
            "runs": {
                "using": "composite"
            }
        }
        deps = WorkflowParser.extract_action_dependencies(action_yml)
        assert deps == []
    
    def test_extract_action_dependencies_steps_without_uses(self):
        """Test extracting dependencies when steps don't have uses."""
        action_yml = {
            "runs": {
                "using": "composite",
                "steps": [
                    {"run": "echo 'test'"}
                ]
            }
        }
        deps = WorkflowParser.extract_action_dependencies(action_yml)
        assert deps == []
    
    def test_extract_actions_complex_nested(self):
        """Test extracting actions from complex nested structure."""
        workflow = {
            "jobs": {
                "build": {
                    "steps": [
                        {"uses": "actions/checkout@v4"},
                        {
                            "name": "Setup",
                            "uses": "actions/setup-node@v3",
                            "with": {
                                "node-version": "18"
                            }
                        }
                    ]
                },
                "test": {
                    "steps": [
                        {"uses": "actions/checkout@v4"},
                        {"run": "npm test"}
                    ]
                }
            }
        }
        actions = WorkflowParser.extract_actions(workflow)
        assert "actions/checkout@v4" in actions
        assert "actions/setup-node@v3" in actions

