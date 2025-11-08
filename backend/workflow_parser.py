"""Parse GitHub Actions workflows and action.yml files."""
import yaml
from typing import List, Dict, Any, Optional
import re


class WorkflowParser:
    @staticmethod
    def parse_workflow(content: str) -> Dict[str, Any]:
        """Parse a workflow YAML file."""
        try:
            return yaml.safe_load(content) or {}
        except yaml.YAMLError as e:
            return {"error": str(e)}

    @staticmethod
    def extract_actions(workflow: Dict[str, Any]) -> List[str]:
        """Extract all action references from a workflow."""
        actions = []
        
        def is_action_reference(value: str) -> bool:
            """Check if a string is likely an action reference."""
            if not isinstance(value, str):
                return False
            # Skip local paths, docker images, and URLs
            if value.startswith(("./", "docker://", "http://", "https://")):
                return False
            # Action references typically have owner/repo@ref format
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
    def parse_action_yml(content: str) -> Dict[str, Any]:
        """Parse an action.yml or action.yaml file."""
        try:
            return yaml.safe_load(content) or {}
        except yaml.YAMLError as e:
            return {"error": str(e)}

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

