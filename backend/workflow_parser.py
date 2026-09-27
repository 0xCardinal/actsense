"""Parse GitHub Actions workflows and action.yml files."""
import re
import yaml
from typing import List, Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class _WorkflowYamlLoader(yaml.SafeLoader):
    """SafeLoader configuration for GitHub Actions YAML boolean handling.

    GitHub Actions uses ``on:`` as the trigger key. Under YAML 1.1 (which PyYAML
    implements) the bare word ``on`` resolves to the boolean ``True``, so ``on:``
    becomes the dict key ``True`` and ``workflow.get("on")`` returns nothing. Every
    trigger-aware check (dangerous events, pull_request_target, cache poisoning,
    self-hosted PR/issue exposure, branch-protection bypass, workflow-input
    injection, ...) then silently fails to fire. This loader keeps only
    ``true``/``false`` as booleans so ``on``, ``off``, ``yes`` and ``no`` are
    preserved as strings, matching how GitHub Actions itself reads the file.
    """


# Rebuild the implicit-resolver table without the YAML 1.1 bool entries, then
# re-register a bool resolver limited to true/false. Building a fresh dict with
# fresh lists avoids mutating yaml.SafeLoader's shared class state.
_WORKFLOW_SAFE_RESOLVERS = {
    ch: [(tag, regexp) for tag, regexp in mappings
         if tag != "tag:yaml.org,2002:bool"]
    for ch, mappings in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_BOOL_TRUE_FALSE = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
for _ch in "tTfF":
    _WORKFLOW_SAFE_RESOLVERS.setdefault(_ch, []).append(
        ("tag:yaml.org,2002:bool", _BOOL_TRUE_FALSE)
    )
_WorkflowYamlLoader.yaml_implicit_resolvers = _WORKFLOW_SAFE_RESOLVERS


def _safe_load_workflow_yaml(content: str) -> Any:
    """yaml.safe_load with GitHub Actions compatible bool resolution.

    Uses the dedicated loader subclass instead of temporarily swapping the
    resolver table on yaml.SafeLoader, which would leak into any other
    yaml.safe_load call made while this one is in progress.
    """
    return yaml.load(content, Loader=_WorkflowYamlLoader)  # noqa: S506 - SafeLoader subclass


class WorkflowParser:
    @staticmethod
    def parse_workflow(content: str) -> Dict[str, Any]:
        """Parse a workflow YAML file."""
        try:
            parsed = _safe_load_workflow_yaml(content)
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
            parsed = _safe_load_workflow_yaml(content)
        except yaml.YAMLError:
            logger.exception("Failed to parse action YAML")
            return {"error": "Invalid YAML content"}
        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def extract_local_references(workflow: Dict[str, Any]) -> List[str]:
        """Extract local ``./path`` references (local actions and reusable workflows)."""
        refs: List[str] = []

        def walk(value):
            if isinstance(value, dict):
                uses_value = value.get("uses")
                if isinstance(uses_value, str) and uses_value.startswith("./"):
                    refs.append(uses_value.strip())
                for v in value.values():
                    walk(v)
            elif isinstance(value, list):
                for item in value:
                    walk(item)

        walk(workflow)
        return list(dict.fromkeys(refs))

    @staticmethod
    def extract_action_dependencies(action_yml: Dict[str, Any]) -> List[str]:
        """Extract the ``uses`` references of a composite action's steps."""
        dependencies = []
        runs = action_yml.get("runs") if isinstance(action_yml, dict) else None
        if not isinstance(runs, dict) or runs.get("using") != "composite":
            return dependencies
        steps = runs.get("steps")
        if not isinstance(steps, list):
            return dependencies
        for step in steps:
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                dependencies.append(step["uses"].strip())
        return dependencies

    @staticmethod
    def extract_dockerfile_base_images(dockerfile: str) -> List[str]:
        """Return external base images from Dockerfile FROM lines.

        Skips ``scratch`` and references to earlier build stages
        (``FROM builder``), which are not images pulled from a registry.
        """
        images: List[str] = []
        stages = set()
        for raw in (dockerfile or "").splitlines():
            line = raw.strip()
            if not line.upper().startswith("FROM "):
                continue
            tokens = [t for t in line.split()[1:] if not t.startswith("--")]
            if not tokens:
                continue
            image = tokens[0]
            if len(tokens) >= 3 and tokens[1].upper() == "AS":
                stages.add(tokens[2].lower())
            if image.lower() == "scratch" or image.lower() in stages or "$" in image:
                continue
            images.append(image)
        return list(dict.fromkeys(images))
