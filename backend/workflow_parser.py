"""Parse GitHub Actions workflows and action.yml files."""
import yaml
from typing import List, Dict, Any, Optional, Tuple
import re
import logging

logger = logging.getLogger(__name__)


class WorkflowParser:
    @staticmethod
    def parse_workflow(content: str) -> Dict[str, Any]:
        """Parse a workflow YAML file."""
        try:
            parsed = yaml.safe_load(content)
            # Ensure we return a dict, not a string or other type
            if isinstance(parsed, dict):
                return parsed
            elif parsed is None:
                return {}
            else:
                # If YAML parsed to a non-dict type (string, list, etc.), return empty dict
                return {}
        except yaml.YAMLError:
            logger.exception("Failed to parse workflow YAML")
            return {"error": "Invalid YAML content"}

    @staticmethod
    def extract_actions(workflow: Dict[str, Any]) -> List[str]:
        """Extract all action references from a workflow."""
        actions = []
        
        def is_action_reference(value: str) -> bool:
            """Check if a string is likely an action reference."""
            if not isinstance(value, str):
                return False
            # Skip local paths and plain URLs
            if value.startswith(("./", "http://", "https://")):
                return False
            # Include docker images as references so they appear in the graph
            if value.startswith("docker://"):
                return True
            # Action references (including reusable workflows) have owner/repo@ref format
            if "/" in value and "@" in value:
                parts = value.split("@")
                if len(parts) == 2 and "/" in parts[0]:
                    return True
            return False
        
        def extract_from_value(value):
            if isinstance(value, dict):
                # Check for "uses" key which is the standard way to reference actions
                if "uses" in value:
                    uses_value = value["uses"]
                    if isinstance(uses_value, str) and is_action_reference(uses_value):
                        actions.append(uses_value)
                # Recursively check other values
                for v in value.values():
                    extract_from_value(v)
            elif isinstance(value, list):
                for item in value:
                    extract_from_value(item)
        
        extract_from_value(workflow)
        return list(set(actions))

    @staticmethod
    def extract_container_images(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract container and service images from workflow jobs.

        Returns a list of dicts with keys: image, job, source ('container' or 'service'),
        and optionally service_name.
        """
        images = []
        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            return images

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue

            # jobs.<id>.container
            container = job.get("container")
            if isinstance(container, str) and container:
                images.append({"image": container, "job": job_name, "source": "container"})
            elif isinstance(container, dict):
                img = container.get("image", "")
                if isinstance(img, str) and img:
                    images.append({"image": img, "job": job_name, "source": "container"})

            # jobs.<id>.services.<svc>.image
            services = job.get("services", {})
            if isinstance(services, dict):
                for svc_name, svc in services.items():
                    if isinstance(svc, str) and svc:
                        images.append({"image": svc, "job": job_name, "source": "service", "service_name": svc_name})
                    elif isinstance(svc, dict):
                        img = svc.get("image", "")
                        if isinstance(img, str) and img:
                            images.append({"image": img, "job": job_name, "source": "service", "service_name": svc_name})

        return images

    @staticmethod
    def parse_action_yml(content: str) -> Dict[str, Any]:
        """Parse an action.yml or action.yaml file."""
        try:
            return yaml.safe_load(content) or {}
        except yaml.YAMLError:
            logger.exception("Failed to parse action YAML")
            return {"error": "Invalid YAML content"}

    @staticmethod
    def extract_action_dependencies(action_yml: Dict[str, Any]) -> List[str]:
        """Extract dependencies (runs.using and other actions) from action.yml."""
        dependencies = []
        
        if "runs" in action_yml:
            runs = action_yml["runs"]
            if "using" in runs:
                using = runs["using"]
                if isinstance(using, str) and using == "composite":
                    # Composite actions can have steps with uses
                    if "steps" in runs:
                        for step in runs["steps"]:
                            if isinstance(step, dict) and "uses" in step:
                                uses_value = step["uses"]
                                if isinstance(uses_value, str):
                                    dependencies.append(uses_value)
            # Docker actions might reference other actions
            if "image" in runs:
                image = runs["image"]
                if isinstance(image, str) and not image.startswith("docker://"):
                    # Could be a Dockerfile reference
                    pass
        
        return dependencies

