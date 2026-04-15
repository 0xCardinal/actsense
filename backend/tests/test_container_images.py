"""Tests for container image detection and security checks."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rules import security as security_rules
from workflow_parser import WorkflowParser


parser = WorkflowParser()


class TestExtractContainerImages:
    """Tests for WorkflowParser.extract_container_images."""

    def test_job_container_string(self):
        workflow = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "container": "node:20",
                    "steps": [{"run": "node -v"}],
                }
            }
        }
        images = parser.extract_container_images(workflow)
        assert len(images) == 1
        assert images[0]["image"] == "node:20"
        assert images[0]["source"] == "container"
        assert images[0]["job"] == "build"

    def test_job_container_dict(self):
        workflow = {
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "container": {"image": "python:3.12-slim", "env": {"FOO": "bar"}},
                    "steps": [],
                }
            }
        }
        images = parser.extract_container_images(workflow)
        assert len(images) == 1
        assert images[0]["image"] == "python:3.12-slim"

    def test_service_images(self):
        workflow = {
            "jobs": {
                "integration": {
                    "runs-on": "ubuntu-latest",
                    "services": {
                        "db": {"image": "postgres:15"},
                        "cache": {"image": "redis:7"},
                    },
                    "steps": [],
                }
            }
        }
        images = parser.extract_container_images(workflow)
        assert len(images) == 2
        image_names = {i["image"] for i in images}
        assert image_names == {"postgres:15", "redis:7"}
        assert all(i["source"] == "service" for i in images)

    def test_mixed_container_and_services(self):
        workflow = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "container": "node:20",
                    "services": {
                        "db": {"image": "postgres:15"},
                    },
                    "steps": [],
                }
            }
        }
        images = parser.extract_container_images(workflow)
        assert len(images) == 2

    def test_no_containers(self):
        workflow = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "echo hi"}],
                }
            }
        }
        images = parser.extract_container_images(workflow)
        assert len(images) == 0

    def test_empty_workflow(self):
        assert parser.extract_container_images({}) == []
        assert parser.extract_container_images({"jobs": {}}) == []


class TestCheckUnpinnedContainerImages:
    """Tests for check_unpinned_container_images."""

    def test_unpinned_container_detected(self):
        workflow = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "container": "node:20",
                    "steps": [],
                }
            }
        }
        issues = security_rules.check_unpinned_container_images(workflow)
        matching = [i for i in issues if i["type"] == "unpinned_container_image"]
        assert len(matching) == 1
        assert matching[0]["severity"] == "medium"
        assert "node:20" in matching[0]["message"]
        assert "actsense.dev/vulnerabilities/unpinned_container_image" in matching[0]["evidence"]["vulnerability"]

    def test_unpinned_service_detected(self):
        workflow = {
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "services": {
                        "db": {"image": "postgres:latest"},
                    },
                    "steps": [],
                }
            }
        }
        issues = security_rules.check_unpinned_container_images(workflow)
        matching = [i for i in issues if i["type"] == "unpinned_container_image"]
        assert len(matching) == 1
        assert "postgres:latest" in matching[0]["message"]

    def test_pinned_container_no_issue(self):
        workflow = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "container": "node@sha256:a5e0ed056baaa3b684d4c5ef4b0cda0d138398c6a3f2a4b0a1d2e3f4a5b6c7d8",
                    "steps": [],
                }
            }
        }
        issues = security_rules.check_unpinned_container_images(workflow)
        assert len([i for i in issues if i["type"] == "unpinned_container_image"]) == 0

    def test_expression_image_skipped(self):
        workflow = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "container": "${{ inputs.image }}",
                    "steps": [],
                }
            }
        }
        issues = security_rules.check_unpinned_container_images(workflow)
        assert len([i for i in issues if i["type"] == "unpinned_container_image"]) == 0

    def test_multiple_unpinned(self):
        workflow = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "container": {"image": "node:20"},
                    "services": {
                        "db": {"image": "postgres:15"},
                        "cache": {"image": "redis:7"},
                    },
                    "steps": [],
                }
            }
        }
        issues = security_rules.check_unpinned_container_images(workflow)
        matching = [i for i in issues if i["type"] == "unpinned_container_image"]
        assert len(matching) == 3

    def test_no_jobs(self):
        assert security_rules.check_unpinned_container_images({}) == []
        assert security_rules.check_unpinned_container_images({"jobs": {}}) == []
