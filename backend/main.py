"""FastAPI backend for GitHub Actions security auditor."""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Set, Callable
import asyncio
import json
import os
import re
import logging
import uvicorn
import yaml
from urllib.parse import urlparse
from github_client import GitHubClient
from workflow_parser import WorkflowParser
from security_auditor import SecurityAuditor
from graph_builder import GraphBuilder
from repo_cloner import RepoCloner, CloneError
from analysis_storage import AnalysisStorage

app = FastAPI(
    title="actsense - GitHub Actions Security Auditor",
    version="1.0.0",
)

# CORS middleware — origins configurable via CORS_ORIGINS env var (comma-separated).
# Defaults to localhost dev origins when the variable is not set.
_cors_origins_env = os.environ.get("CORS_ORIGINS", "")
_cors_origins: list[str] = (
    [o.strip() for o in _cors_origins_env.split(",") if o.strip()]
    if _cors_origins_env
    else ["http://localhost:3000", "http://localhost:5173"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

parser = WorkflowParser()
auditor = SecurityAuditor()
cloner = RepoCloner()
storage = AnalysisStorage()
logger = logging.getLogger(__name__)

# Serve frontend static files if they exist (for production builds)
# This must be added AFTER API routes
FRONTEND_BUILD_PATH = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.exists(FRONTEND_BUILD_PATH):
    app.mount("/static", StaticFiles(directory=os.path.join(FRONTEND_BUILD_PATH, "assets")), name="static")


class AuditRequest(BaseModel):
    repository: Optional[str] = None
    action: Optional[str] = None
    github_token: Optional[str] = None
    use_clone: bool = False  # New option to use clone instead of API


class AuditYAMLRequest(BaseModel):
    yaml_content: str
    github_token: Optional[str] = None


async def resolve_action_dependencies(
    client: GitHubClient,
    action_ref: str,
    graph: GraphBuilder,
    visited: Set[str],
    depth: int = 0,
    max_depth: int = 5,
    log_fn: Optional[Callable[[str], None]] = None
):
    """Recursively resolve action dependencies."""
    if depth > max_depth or action_ref in visited:
        return
    
    _log = log_fn or (lambda _: None)
    visited.add(action_ref)
    _log(f"Resolving {action_ref}")
    
    # Handle docker images: add as a node but don't try to resolve further
    if action_ref.startswith("docker://"):
        graph.add_node(action_ref, action_ref, "docker_image", {"image": action_ref})
        issues = auditor.audit_action(action_ref, None, None, None)
        if issues:
            graph.add_issues_to_node(action_ref, issues)
        return
    
    # Parse action reference
    owner, repo, ref, subdir = client.parse_action_reference(action_ref)
    if not owner or not repo:
        return
    
    # Handle reusable workflows
    if subdir and (".github/workflows" in subdir or subdir.endswith((".yml", ".yaml"))):
        display_name = f"{owner}/{repo}/{subdir}@{ref}"
        graph.add_node(action_ref, display_name, "reusable_workflow", {"owner": owner, "repo": repo, "ref": ref, "subdir": subdir})
        try:
            workflow_content = await client.get_file_content(owner, repo, subdir)
            workflow = parser.parse_workflow(workflow_content)
            if isinstance(workflow, dict) and "error" not in workflow:
                workflow_issues = await auditor.audit_workflow(workflow, content=workflow_content, client=client)
                if workflow_issues:
                    graph.add_issues_to_node(action_ref, workflow_issues)
                dependencies = parser.extract_actions(workflow)
                for dep in dependencies:
                    graph.add_edge(action_ref, dep)
                    await resolve_action_dependencies(client, dep, graph, visited, depth + 1, max_depth, log_fn)
        except Exception:
            pass
        return
    
    # Add node to graph
    display_name = f"{owner}/{repo}"
    if subdir:
        display_name = f"{display_name}/{subdir}"
    display_name = f"{display_name}@{ref}"
    
    graph.add_node(
        action_ref,
        display_name,
        "action",
        {"owner": owner, "repo": repo, "ref": ref, "subdir": subdir}
    )
    
    # Check if repository exists
    repo_key = f"{owner}/{repo}"
    repo_exists = None
    try:
        repo_info = await client.get_repository_info(owner, repo)
        repo_exists = repo_info is not None
    except HTTPException:
        # For API errors (rate limits, network issues), don't assume repo is missing
        # Skip this check rather than marking as missing
        return
    except Exception:
        # For other unexpected errors, don't assume repo is missing
        return
    
    # If repository doesn't exist, add a critical issue
    if repo_exists is False:
        missing_repo_issue = {
            "type": "missing_action_repository",
            "severity": "critical",
            "message": f"Action '{action_ref}' references repository '{repo_key}' that does not exist or is not accessible. This will cause workflow failures at runtime.",
            "action": action_ref,
            "evidence": {
                "action": action_ref,
                "repository": repo_key,
                "exists": False,
                "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/missing_action_repository"
            },
            "recommendation": f"Verify the action reference '{action_ref}' is correct. The repository '{repo_key}' may have been deleted, moved, made private, or the reference may contain a typo. Update the workflow to use a valid action reference."
        }
        graph.add_issues_to_node(action_ref, [missing_repo_issue])
        # Don't try to fetch metadata if repository doesn't exist
        return
    
    # Get action metadata first (needed for comprehensive auditing)
    action_yml = None
    js_action_code = None
    dockerfile_content = None
    try:
        action_metadata = await client.get_action_metadata(owner, repo, ref, subdir)
        if action_metadata:
            action_yml = parser.parse_action_yml(action_metadata["content"])
            
            runs = action_yml.get("runs", {})
            
            # For JavaScript actions, try to get the main entry point code
            if runs.get("using") in ["node12", "node16", "node20"]:
                main_file = runs.get("main", "index.js")
                if subdir:
                    main_path = f"{subdir.rstrip('/')}/{main_file}"
                else:
                    main_path = main_file
                
                try:
                    js_action_code = await client.get_file_content(owner, repo, main_path)
                except Exception:
                    # If main file doesn't exist, try dist/index.js or index.js in root
                    for alt_path in [f"{subdir.rstrip('/')}/dist/index.js" if subdir else "dist/index.js", "index.js"]:
                        try:
                            js_action_code = await client.get_file_content(owner, repo, alt_path)
                            break
                        except Exception:
                            continue
            
            # For Docker actions, try to get Dockerfile content if Dockerfile path is specified
            elif runs.get("using") == "docker":
                dockerfile_path = runs.get("image", "")
                if dockerfile_path and not dockerfile_path.startswith("docker://") and ":" not in dockerfile_path:
                    # This is likely a Dockerfile path
                    if subdir:
                        dockerfile_full_path = f"{subdir.rstrip('/')}/{dockerfile_path}"
                    else:
                        dockerfile_full_path = dockerfile_path
                    
                    try:
                        dockerfile_content = await client.get_file_content(owner, repo, dockerfile_full_path)
                    except Exception:
                        # Try common Dockerfile names
                        for alt_name in ["Dockerfile", "dockerfile", f"{subdir.rstrip('/')}/Dockerfile" if subdir else "Dockerfile"]:
                            try:
                                dockerfile_content = await client.get_file_content(owner, repo, alt_name)
                                break
                            except Exception:
                                continue
    except Exception as e:
        # Silently skip if action.yml doesn't exist (e.g., for Docker-only actions)
        pass
    
    # Audit the action (with metadata if available)
    # action_content parameter expects JavaScript code for JS actions, not action.yml content
    issues = auditor.audit_action(action_ref, action_yml, js_action_code, dockerfile_content)
    graph.add_issues_to_node(action_ref, issues)
    
    # Resolve dependencies if action_yml is available
    if action_yml:
        try:
            dependencies = parser.extract_action_dependencies(action_yml)
            
            for dep in dependencies:
                graph.add_edge(action_ref, dep)
                await resolve_action_dependencies(
                    client, dep, graph, visited, depth + 1, max_depth, log_fn
                )
        except Exception as e:
            # Silently skip if there's an error resolving dependencies
            pass


def _add_workflow_container_image_nodes(
    graph: GraphBuilder,
    workflow: Dict[str, Any],
    workflow_node_id: str,
    workflow_issues: List[Dict[str, Any]],
) -> None:
    """Add container_image nodes and copy unpinned-container issues onto them for UI clarity."""
    for img_info in parser.extract_container_images(workflow):
        img_node_id = f"container://{img_info['image']}"
        graph.add_node(img_node_id, img_info["image"], "container_image", img_info)
        graph.add_edge(workflow_node_id, img_node_id)
        img = img_info.get("image")
        if not img:
            continue
        related = [
            i
            for i in workflow_issues
            if i.get("type") == "unpinned_container_image"
            and (i.get("evidence") or {}).get("image") == img
        ]
        if related:
            graph.add_issues_to_node(img_node_id, related)


async def audit_repository(
    client: GitHubClient,
    owner: str,
    repo: str,
    graph: GraphBuilder,
    use_clone: bool = False,
    token: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None
):
    """Audit a repository's workflows."""
    _log = log_fn or (lambda _: None)
    
    repo_node_id = f"{owner}/{repo}"
    # default_branch is used for GitHub web URLs (e.g. /blob/<branch>/<path>#L<line>).
    # `HEAD` is *not* a valid branch name for /blob/ paths in the GitHub UI, so we must
    # use the repository's real default branch when available.
    default_branch = "main"
    is_public_repo = False
    _log(f"Checking repository metadata for {owner}/{repo}")
    try:
        repo_info = await client.get_repository_info(owner, repo)
        if repo_info:
            is_public_repo = not repo_info.get("private", True)
            if repo_info.get("default_branch"):
                default_branch = str(repo_info["default_branch"])
            _log(
                f"Repository is {'public' if is_public_repo else 'private'} "
                f"(default branch: {default_branch})"
            )
    except Exception:
        # If the repo is missing/private, or GitHub is unavailable, we still continue with a
        # best-effort default branch for URL construction.
        pass

    graph.add_node(
        repo_node_id,
        repo_node_id,
        "repository",
        {"owner": owner, "repo": repo, "default_branch": default_branch},
    )
    
    current_repo = f"{owner}/{repo}"
    
    clone_path = None
    workflow_actions_data = []  # Collect actions from all workflows for inconsistency checking
    
    try:
        if use_clone:
            _log(f"Cloning {owner}/{repo}...")
            clone_path, _ = cloner.clone_repository(owner, repo, token)
            workflows = cloner.get_workflow_files(clone_path)
            _log(f"Found {len(workflows)} workflow(s)")
            
            visited = set()
            
            for workflow_file in workflows:
                try:
                    _log(f"Parsing {workflow_file['name']}")
                    content = cloner.get_file_content(clone_path, workflow_file["path"])
                    workflow = parser.parse_workflow(content)
                    
                    if not isinstance(workflow, dict) or "error" in workflow:
                        continue
                    
                    _log(f"Auditing {workflow_file['name']}")
                    workflow_issues = await auditor.audit_workflow(workflow, content=content, client=client, current_repo=current_repo, is_public_repo=is_public_repo, log_fn=log_fn)
                    workflow_node_id = f"{repo_node_id}:{workflow_file['name']}"
                    graph.add_node(
                        workflow_node_id,
                        workflow_file["name"],
                        "workflow",
                        {"path": workflow_file["path"]}
                    )
                    graph.add_edge(repo_node_id, workflow_node_id)
                    graph.add_issues_to_node(workflow_node_id, workflow_issues)
                    
                    # Extract actions
                    actions = parser.extract_actions(workflow)
                    
                    # Collect actions for inconsistency checking
                    workflow_actions_data.append({
                        'workflow_name': workflow_file['name'],
                        'workflow_path': workflow_file['path'],
                        'actions': actions
                    })
                    
                    for action_ref in actions:
                        graph.add_edge(workflow_node_id, action_ref)
                        await resolve_action_dependencies(
                            client, action_ref, graph, visited, log_fn=log_fn
                        )
                    
                    _add_workflow_container_image_nodes(
                        graph, workflow, workflow_node_id, workflow_issues
                    )
                except Exception as e:
                    _log(f"Error processing {workflow_file['name']}: {e}")
                    graph.add_issues_to_node(repo_node_id, [{
                        "type": "workflow_processing_error",
                        "severity": "low",
                        "message": f"Failed to process workflow '{workflow_file['name']}': {e}",
                        "evidence": {"workflow": workflow_file["name"], "error": str(e)},
                        "recommendation": "Check if the workflow file is valid YAML and accessible."
                    }])
        else:
            _log(f"Fetching workflows via API...")
            workflows = await client.get_workflows(owner, repo)
            _log(f"Found {len(workflows)} workflow(s)")
            
            visited = set()
            
            for workflow_file in workflows:
                try:
                    _log(f"Parsing {workflow_file['name']}")
                    content = await client.get_file_content(owner, repo, workflow_file["path"])
                    workflow = parser.parse_workflow(content)
                    
                    if not isinstance(workflow, dict) or "error" in workflow:
                        continue
                    
                    _log(f"Auditing {workflow_file['name']}")
                    workflow_issues = await auditor.audit_workflow(workflow, content=content, client=client, current_repo=current_repo, is_public_repo=is_public_repo, log_fn=log_fn)
                    workflow_node_id = f"{repo_node_id}:{workflow_file['name']}"
                    graph.add_node(
                        workflow_node_id,
                        workflow_file["name"],
                        "workflow",
                        {"path": workflow_file["path"]}
                    )
                    graph.add_edge(repo_node_id, workflow_node_id)
                    graph.add_issues_to_node(workflow_node_id, workflow_issues)
                    
                    # Extract actions
                    actions = parser.extract_actions(workflow)
                    
                    # Collect actions for inconsistency checking
                    workflow_actions_data.append({
                        'workflow_name': workflow_file['name'],
                        'workflow_path': workflow_file['path'],
                        'actions': actions
                    })
                    
                    for action_ref in actions:
                        graph.add_edge(workflow_node_id, action_ref)
                        await resolve_action_dependencies(
                            client, action_ref, graph, visited, log_fn=log_fn
                        )
                    
                    _add_workflow_container_image_nodes(
                        graph, workflow, workflow_node_id, workflow_issues
                    )
                except Exception as e:
                    _log(f"Error processing {workflow_file['name']}: {e}")
                    graph.add_issues_to_node(repo_node_id, [{
                        "type": "workflow_processing_error",
                        "severity": "low",
                        "message": f"Failed to process workflow '{workflow_file['name']}': {e}",
                        "evidence": {"workflow": workflow_file["name"], "error": str(e)},
                        "recommendation": "Check if the workflow file is valid YAML and accessible."
                    }])
        
        _log("Checking version consistency across workflows")
        # Check for inconsistent action versions across workflows
        if len(workflow_actions_data) > 1:  # Only check if there are multiple workflows
            inconsistency_issues = auditor.check_inconsistent_action_versions(workflow_actions_data)
            if inconsistency_issues:
                graph.add_issues_to_node(repo_node_id, inconsistency_issues)
    finally:
        # Cleanup cloned repository
        if clone_path:
            cloner.cleanup(clone_path)


@app.post("/api/audit")
async def audit(request: AuditRequest):
    """Audit a repository or action."""
    client = GitHubClient(token=request.github_token)
    graph = GraphBuilder()
    
    try:
        repository = None
        action = None
        
        if request.repository:
            # Parse repository: owner/repo or full URL
            repo_str = request.repository
            # Check if repo_str is a full GitHub URL
            parsed_url = urlparse(repo_str)
            if parsed_url.scheme and parsed_url.netloc:
                # Allow both github.com and www.github.com
                if parsed_url.netloc not in ("github.com", "www.github.com"):
                    raise HTTPException(status_code=400, detail="Only github.com repository URLs are supported")
                path_parts = parsed_url.path.strip("/").split("/")
                if len(path_parts) < 2:
                    raise HTTPException(status_code=400, detail="Invalid repository URL")
                owner, repo = path_parts[0], path_parts[1].replace(".git", "")
            else:
                # Not a full URL, treat as owner/repo format
                parts = repo_str.split("/")
                if len(parts) != 2:
                    raise HTTPException(status_code=400, detail="Invalid repository format. Use 'owner/repo'")
                owner, repo = parts
            
            repository = f"{owner}/{repo}"
            await audit_repository(client, owner, repo, graph, request.use_clone, request.github_token)
        
        elif request.action:
            # Audit a single action
            action = request.action
            visited = set()
            await resolve_action_dependencies(client, request.action, graph, visited)
        
        else:
            raise HTTPException(status_code=400, detail="Either repository or action must be provided")
        
        graph_data = graph.get_graph_data()
        statistics = graph.get_statistics()
        
        # Save analysis
        analysis_id = storage.save_analysis(
            repository=repository,
            action=action,
            graph_data=graph_data,
            statistics=statistics,
            method="clone" if request.use_clone else "api"
        )
        
        return {
            "id": analysis_id,
            "graph": graph_data,
            "statistics": statistics
        }
    
    except HTTPException:
        raise
    except CloneError as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except Exception:
        logger.exception("Unexpected error during repository audit")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/audit/stream")
async def audit_stream(request: AuditRequest):
    """Audit with Server-Sent Events for real-time progress."""
    log_queue: asyncio.Queue[Optional[str]] = asyncio.Queue()

    def log_callback(msg: str):
        log_queue.put_nowait(msg)

    async def run_audit():
        """Execute the audit and push the result (or error) onto the queue."""
        client = GitHubClient(token=request.github_token)
        graph = GraphBuilder()
        try:
            repository = None
            action = None

            if request.repository:
                repo_str = request.repository
                parsed_url = urlparse(repo_str)
                if parsed_url.scheme and parsed_url.netloc:
                    if parsed_url.netloc not in ("github.com", "www.github.com"):
                        raise HTTPException(status_code=400, detail="Only github.com repository URLs are supported")
                    path_parts = parsed_url.path.strip("/").split("/")
                    if len(path_parts) < 2:
                        raise HTTPException(status_code=400, detail="Invalid repository URL")
                    owner, repo = path_parts[0], path_parts[1].replace(".git", "")
                else:
                    parts = repo_str.split("/")
                    if len(parts) != 2:
                        raise HTTPException(status_code=400, detail="Invalid repository format. Use 'owner/repo'")
                    owner, repo = parts

                repository = f"{owner}/{repo}"
                await audit_repository(client, owner, repo, graph, request.use_clone, request.github_token, log_fn=log_callback)

            elif request.action:
                action = request.action
                visited: Set[str] = set()
                await resolve_action_dependencies(client, request.action, graph, visited, log_fn=log_callback)
            else:
                raise HTTPException(status_code=400, detail="Either repository or action must be provided")

            log_callback("Building final graph...")
            graph_data = graph.get_graph_data()
            statistics = graph.get_statistics()

            analysis_id = storage.save_analysis(
                repository=repository,
                action=action,
                graph_data=graph_data,
                statistics=statistics,
                method="clone" if request.use_clone else "api"
            )

            result = {"id": analysis_id, "graph": graph_data, "statistics": statistics}
            log_queue.put_nowait(("__RESULT__", result))
        except HTTPException as exc:
            log_queue.put_nowait(("__ERROR__", exc.detail))
        except CloneError as e:
            log_queue.put_nowait(("__ERROR__", e.detail))
        except Exception:
            logger.exception("Unexpected error during streaming audit")
            log_queue.put_nowait(("__ERROR__", "Internal server error"))

    async def event_generator():
        task = asyncio.create_task(run_audit())
        try:
            while True:
                msg = await log_queue.get()
                if msg is None:
                    break
                if isinstance(msg, tuple):
                    kind, payload = msg
                    if kind == "__RESULT__":
                        yield f"event: result\ndata: {json.dumps(payload)}\n\n"
                        break
                    elif kind == "__ERROR__":
                        yield f"event: error\ndata: {json.dumps({'detail': payload})}\n\n"
                        break
                else:
                    yield f"event: log\ndata: {json.dumps({'message': msg})}\n\n"
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/audit/fix")
async def audit_fix(request: AuditYAMLRequest):
    """Audit YAML and return issues with concrete auto-fix suggestions."""
    try:
        parsed_yaml = yaml.safe_load(request.yaml_content)
        if parsed_yaml is None:
            raise HTTPException(status_code=400, detail="YAML file is empty")
    except yaml.YAMLError as e:
        line_num = e.problem_mark.line + 1 if hasattr(e, 'problem_mark') and e.problem_mark else None
        msg = f"YAML syntax error at line {line_num}" if line_num else "YAML syntax error"
        raise HTTPException(status_code=400, detail=msg)

    workflow = parser.parse_workflow(request.yaml_content)
    if not isinstance(workflow, dict) or "error" in workflow:
        raise HTTPException(status_code=400, detail="Invalid workflow YAML")

    client = GitHubClient(token=request.github_token)
    issues = await auditor.audit_workflow(workflow, content=request.yaml_content, client=client)

    lines = request.yaml_content.split('\n')
    fixes = []
    seen_fixes = set()

    rate_limited = False

    for issue in issues:
        issue_type = issue.get("type", "")
        line_num = issue.get("line_number")

        if issue_type in ("no_hash_pinning", "unpinned_version"):
            action_ref = issue.get("action", "")
            if not action_ref or "@" not in action_ref:
                continue
            action_name, tag = action_ref.rsplit("@", 1)
            if len(tag) >= 7 and re.match(r'^[a-f0-9]+$', tag):
                continue
            fix_key = f"pin:{action_ref}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)

            owner, repo_name, _, _ = client.parse_action_reference(action_ref)
            sha = None
            if owner and repo_name and not rate_limited:
                try:
                    sha = await client.resolve_tag_to_sha(owner, repo_name, tag)
                except HTTPException:
                    rate_limited = True

            fix_line = None
            original = None
            for i, l in enumerate(lines):
                if action_ref in l:
                    fix_line = i + 1
                    original = l
                    break
            if original is None:
                continue

            if sha:
                replacement = original.replace(action_ref, f"{action_name}@{sha} # {tag}")
                fixes.append({
                    "line": fix_line or line_num,
                    "original": original,
                    "replacement": replacement,
                    "issue_type": issue_type,
                    "severity": issue.get("severity", "medium"),
                    "description": f"Pin {action_name}@{tag} to commit SHA {sha[:12]}..."
                })
            else:
                desc = f"Pin {action_name}@{tag} to a full commit SHA"
                if rate_limited:
                    desc += " (provide a GitHub token to auto-resolve)"
                fixes.append({
                    "line": fix_line or line_num,
                    "original": original,
                    "replacement": original.replace(action_ref, f"{action_name}@<SHA> # {tag}"),
                    "issue_type": issue_type,
                    "severity": issue.get("severity", "medium"),
                    "description": desc
                })

        elif issue_type == "unpinned_container_image":
            image = issue.get("evidence", {}).get("image", "")
            if not image:
                continue
            fix_key = f"container:{image}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)

            fix_line = None
            original = None
            for i, l in enumerate(lines):
                if image in l:
                    fix_line = i + 1
                    original = l
                    break
            if original is None:
                continue
            tag_part = image.split(':')[-1] if ':' in image else 'latest'
            pinned = f"{image.split(':')[0]}@sha256:<digest> # {tag_part}"
            replacement = original.replace(image, pinned)
            fixes.append({
                "line": fix_line or line_num,
                "original": original,
                "replacement": replacement,
                "issue_type": issue_type,
                "severity": issue.get("severity", "medium"),
                "description": f"Pin container image '{image}' to a digest. Run: docker inspect --format='{{{{index .RepoDigests 0}}}}' {image}"
            })

        elif issue_type in ("overly_permissive", "github_token_write_all", "github_token_write_permissions"):
            fix_key = f"perms:{issue_type}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)

            has_top_level_perms = False
            for i, l in enumerate(lines):
                stripped = l.strip()
                if stripped.startswith("permissions:") and not l.startswith(" "):
                    has_top_level_perms = True
                    # Capture the full permissions block (this line + indented children)
                    block_lines = [l]
                    for j in range(i + 1, len(lines)):
                        child = lines[j]
                        if child.strip() == '' or child.startswith(' ') or child.startswith('\t'):
                            block_lines.append(child)
                        else:
                            break
                    # Strip trailing blank lines from the block
                    while block_lines and block_lines[-1].strip() == '':
                        block_lines.pop()
                    original_block = '\n'.join(block_lines)
                    fixes.append({
                        "line": i + 1,
                        "original": original_block,
                        "replacement": "permissions: read-all",
                        "issue_type": issue_type,
                        "severity": issue.get("severity", "high"),
                        "description": "Restrict workflow-level permissions to read-only"
                    })
                    break
            if not has_top_level_perms:
                for i, l in enumerate(lines):
                    stripped = l.strip()
                    if stripped.startswith("on:") or stripped.startswith("'on':") or stripped.startswith('"on":'):
                        fixes.append({
                            "line": i + 1,
                            "original": l,
                            "replacement": l + "\n\npermissions: read-all",
                            "issue_type": issue_type,
                            "severity": issue.get("severity", "high"),
                            "description": "Add least-privilege permissions (read-all) to the workflow"
                        })
                        break

        elif issue_type == "artifact_retention":
            job_name = issue.get("job", "")
            fix_key = f"retention:{job_name}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            for i, l in enumerate(lines):
                if "upload-artifact" in l:
                    # Find the `with:` block under this step
                    indent = len(l) - len(l.lstrip())
                    with_idx = None
                    insert_idx = i + 1
                    for j in range(i + 1, min(i + 10, len(lines))):
                        if lines[j].strip().startswith("with:"):
                            with_idx = j
                            insert_idx = j + 1
                            break
                        if lines[j].strip() and not lines[j].startswith(" " * (indent + 1)):
                            break
                    if with_idx is not None:
                        # Check if retention-days already exists
                        already_has = False
                        for j in range(with_idx + 1, min(with_idx + 10, len(lines))):
                            if "retention-days" in lines[j]:
                                already_has = True
                                break
                            if lines[j].strip() and not lines[j].startswith(" " * (indent + 2)):
                                break
                        if not already_has:
                            with_line = lines[with_idx]
                            child_indent = " " * (indent + 6)
                            fixes.append({
                                "line": with_idx + 1,
                                "original": with_line,
                                "replacement": with_line + f"\n{child_indent}retention-days: 7",
                                "issue_type": issue_type,
                                "severity": issue.get("severity", "low"),
                                "description": f"Add explicit retention-days to artifact upload in job '{job_name}'"
                            })
                    break

        elif issue_type == "unsafe_checkout":
            job_name = issue.get("job", "")
            fix_key = f"checkout:{job_name}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            for i, l in enumerate(lines):
                if "actions/checkout" in l and "persist-credentials" not in request.yaml_content[sum(len(lines[k])+1 for k in range(max(0,i-1), min(i+8, len(lines)))):]:
                    # Find with: block or add one
                    indent = len(l) - len(l.lstrip())
                    for j in range(i + 1, min(i + 8, len(lines))):
                        if lines[j].strip().startswith("with:"):
                            with_line = lines[j]
                            child_indent = " " * (indent + 6)
                            fixes.append({
                                "line": j + 1,
                                "original": with_line,
                                "replacement": with_line + f"\n{child_indent}persist-credentials: false",
                                "issue_type": issue_type,
                                "severity": issue.get("severity", "high"),
                                "description": f"Disable persist-credentials on checkout in job '{job_name}'"
                            })
                            break
                        if lines[j].strip() and not lines[j].startswith(" " * (indent + 1)):
                            child_indent = " " * (indent + 4)
                            fixes.append({
                                "line": i + 1,
                                "original": l,
                                "replacement": l + f"\n{child_indent}with:\n{child_indent}  persist-credentials: false",
                                "issue_type": issue_type,
                                "severity": issue.get("severity", "high"),
                                "description": f"Add persist-credentials: false to checkout in job '{job_name}'"
                            })
                            break
                    break

        elif issue_type == "unsafe_shell":
            job_name = issue.get("job", "")
            for i, l in enumerate(lines):
                if "shell:" in l and "bash" in l and "-e" not in l:
                    fix_key = f"shell:{i}"
                    if fix_key in seen_fixes:
                        continue
                    seen_fixes.add(fix_key)
                    fixes.append({
                        "line": i + 1,
                        "original": l,
                        "replacement": l.replace("bash", "bash -e"),
                        "issue_type": issue_type,
                        "severity": issue.get("severity", "medium"),
                        "description": f"Add -e flag to bash shell in job '{job_name}' to fail on errors"
                    })
                    break

        elif issue_type == "long_artifact_retention":
            job_name = issue.get("job", "")
            fix_key = f"long_retention:{job_name}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            for i, l in enumerate(lines):
                if "retention-days" in l:
                    try:
                        val = int(l.split("retention-days")[-1].strip().lstrip(":").strip())
                        if val > 30:
                            fixes.append({
                                "line": i + 1,
                                "original": l,
                                "replacement": l.replace(str(val), "7"),
                                "issue_type": issue_type,
                                "severity": issue.get("severity", "low"),
                                "description": f"Reduce artifact retention from {val} to 7 days in job '{job_name}'"
                            })
                            break
                    except (ValueError, IndexError):
                        pass

        elif issue_type == "checkout_full_history":
            job_name = issue.get("job", "")
            fix_key = f"full_history:{job_name}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            for i, l in enumerate(lines):
                if "fetch-depth" in l and "0" in l:
                    fixes.append({
                        "line": i + 1,
                        "original": l,
                        "replacement": l.replace("0", "1"),
                        "issue_type": issue_type,
                        "severity": issue.get("severity", "low"),
                        "description": f"Change fetch-depth from 0 (full history) to 1 (shallow) in job '{job_name}'"
                    })
                    break

        elif issue_type == "continue_on_error_critical_job":
            job_name = issue.get("job", "")
            fix_key = f"continue_error:{job_name}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            for i, l in enumerate(lines):
                if "continue-on-error" in l and "true" in l.lower():
                    fixes.append({
                        "line": i + 1,
                        "original": l,
                        "replacement": l.replace("true", "false").replace("True", "false"),
                        "issue_type": issue_type,
                        "severity": issue.get("severity", "medium"),
                        "description": f"Set continue-on-error to false for critical job '{job_name}'"
                    })
                    break

        elif issue_type == "excessive_write_permissions":
            job_name = issue.get("job", "")
            fix_key = f"excessive_write:{job_name}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            for i, l in enumerate(lines):
                if "permissions:" in l and l.startswith(" "):
                    # Job-level permissions block
                    block_start = i
                    block_lines_list = [l]
                    perm_indent = len(l) - len(l.lstrip())
                    for j in range(i + 1, len(lines)):
                        child = lines[j]
                        if child.strip() == '' or (child.startswith(" " * (perm_indent + 1)) and child.strip()):
                            block_lines_list.append(child)
                        else:
                            break
                    while block_lines_list and block_lines_list[-1].strip() == '':
                        block_lines_list.pop()
                    original_block = '\n'.join(block_lines_list)
                    replacement_block = " " * perm_indent + "permissions: read-all"
                    fixes.append({
                        "line": block_start + 1,
                        "original": original_block,
                        "replacement": replacement_block,
                        "issue_type": issue_type,
                        "severity": issue.get("severity", "medium"),
                        "description": f"Restrict job '{job_name}' permissions to read-only"
                    })
                    break

        elif issue_type == "insecure_pull_request_target":
            fix_key = "insecure_prt"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            for i, l in enumerate(lines):
                if "pull_request_target" in l:
                    fixes.append({
                        "line": i + 1,
                        "original": l,
                        "replacement": l.replace("pull_request_target", "pull_request"),
                        "issue_type": issue_type,
                        "severity": issue.get("severity", "critical"),
                        "description": "Replace pull_request_target with pull_request to avoid running untrusted code with write access"
                    })
                    break

        elif issue_type == "secret_in_environment":
            job_name = issue.get("job", "")
            fix_key = f"secret_env:{job_name}:{issue.get('message', '')[:40]}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            env_var = issue.get("evidence", {}).get("env_var", "")
            if env_var:
                for i, l in enumerate(lines):
                    if env_var in l and "secrets." in l:
                        fixes.append({
                            "line": i + 1,
                            "original": l,
                            "replacement": f"# {l.strip()}  # REVIEW: consider using environment protection rules",
                            "issue_type": issue_type,
                            "severity": issue.get("severity", "medium"),
                            "description": f"Review secret '{env_var}' passed via environment variable -- use environment protection rules"
                        })
                        break

        elif issue_type == "potential_hardcoded_secret":
            # Find the line with the hardcoded secret and replace value with secrets reference
            evidence_path = issue.get("path", "")
            fix_key = f"secret:{evidence_path}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            if line_num and 0 < line_num <= len(lines):
                original_line = lines[line_num - 1]
                # Replace the hardcoded value with a secrets reference
                match = re.search(r'(:\s*)["\']?([a-zA-Z0-9_\-]{20,})["\']?\s*$', original_line)
                if match:
                    secret_name = evidence_path.split(".")[-1].upper() if evidence_path else "SECRET_VALUE"
                    replacement_line = original_line[:match.start(2)] + "${{ secrets." + secret_name + " }}" + original_line[match.end(2):]
                    fixes.append({
                        "line": line_num,
                        "original": original_line,
                        "replacement": replacement_line,
                        "issue_type": issue_type,
                        "severity": "critical",
                        "description": f"Replace hardcoded secret with ${{{{ secrets.{secret_name} }}}} reference"
                    })

        elif issue_type == "malicious_curl_pipe_bash":
            job_name = issue.get("job", "")
            fix_key = f"curl_pipe:{job_name}:{line_num}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            if line_num and 0 < line_num <= len(lines):
                original_line = lines[line_num - 1]
                fixes.append({
                    "line": line_num,
                    "original": original_line,
                    "replacement": f"# REMOVED: {original_line.strip()}  # CRITICAL: curl piped to shell is unsafe, download and verify first",
                    "issue_type": issue_type,
                    "severity": "critical",
                    "description": f"Remove curl-pipe-to-bash pattern in job '{job_name}'. Download the script, inspect it, then execute."
                })

        elif issue_type == "malicious_base64_decode":
            job_name = issue.get("job", "")
            fix_key = f"base64:{job_name}:{line_num}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            if line_num and 0 < line_num <= len(lines):
                original_line = lines[line_num - 1]
                fixes.append({
                    "line": line_num,
                    "original": original_line,
                    "replacement": f"# REMOVED: {original_line.strip()}  # CRITICAL: base64 decode execution is suspicious",
                    "issue_type": issue_type,
                    "severity": "critical",
                    "description": f"Remove base64-decode-and-execute pattern in job '{job_name}'. This is a common obfuscation technique."
                })

        elif issue_type in ("shell_injection", "script_injection", "code_injection_via_input", "risky_context_usage"):
            job_name = issue.get("job", "")
            fix_key = f"injection:{job_name}:{line_num}:{issue_type}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            if line_num and 0 < line_num <= len(lines):
                original_line = lines[line_num - 1]
                # Find the first ${{ ... }} expression using index lookups (avoid regex backtracking)
                expr_start = original_line.find("${{")
                expr_end = original_line.find("}}", expr_start + 3) if expr_start != -1 else -1
                if expr_start != -1 and expr_end != -1:
                    expr = original_line[expr_start:expr_end + 2]
                    # Extract a reasonable env var name
                    inner = expr.strip("${ }")
                    env_name = re.sub(r'[^a-zA-Z0-9]', '_', inner).upper()
                    if len(env_name) > 30:
                        env_name = env_name[:30]
                    indent = " " * (len(original_line) - len(original_line.lstrip()))
                    fixes.append({
                        "line": line_num,
                        "original": original_line,
                        "replacement": original_line.replace(expr, f"${env_name}"),
                        "issue_type": issue_type,
                        "severity": "critical",
                        "description": f"Move '{expr}' to an environment variable to prevent injection. Add `env: {env_name}: {expr}` to the step."
                    })

        elif issue_type == "secrets_in_matrix":
            job_name = issue.get("job", "")
            fix_key = f"secrets_matrix:{job_name}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            for i, l in enumerate(lines):
                if "matrix" in l and "secrets" in str(lines[max(0,i):min(len(lines),i+10)]):
                    fixes.append({
                        "line": i + 1,
                        "original": l,
                        "replacement": f"{l}  # CRITICAL: remove secrets from matrix strategy",
                        "issue_type": issue_type,
                        "severity": "critical",
                        "description": f"Secrets in matrix strategy of job '{job_name}' are logged in plaintext. Move secrets to environment variables."
                    })
                    break

        elif issue_type in ("self_hosted_runner_pr_exposure", "public_repo_self_hosted_secrets"):
            job_name = issue.get("job", "")
            fix_key = f"runner:{issue_type}:{job_name}"
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            for i, l in enumerate(lines):
                if "self-hosted" in l:
                    fixes.append({
                        "line": i + 1,
                        "original": l,
                        "replacement": l.replace("self-hosted", "ubuntu-latest"),
                        "issue_type": issue_type,
                        "severity": "critical",
                        "description": f"Replace self-hosted runner with GitHub-hosted runner in job '{job_name}' to avoid exposure to untrusted code"
                    })
                    break

    return {"issues": issues, "fixes": fixes, "rate_limited": rate_limited}


async def _audit_yaml_body(request: AuditYAMLRequest) -> Dict[str, Any]:
    """Core YAML audit logic; raises HTTPException on client errors."""
    # Validate YAML syntax first
    try:
        parsed_yaml = yaml.safe_load(request.yaml_content)
        if parsed_yaml is None:
            raise HTTPException(status_code=400, detail="YAML file is empty or contains no valid content")
    except yaml.YAMLError as e:
        if hasattr(e, "problem_mark") and e.problem_mark:
            line_num = e.problem_mark.line + 1
            error_msg = f"YAML syntax error at line {line_num}"
        else:
            error_msg = "YAML syntax error"
        raise HTTPException(status_code=400, detail=f"Invalid YAML syntax: {error_msg}")

    workflow = parser.parse_workflow(request.yaml_content)

    if "error" in workflow:
        raise HTTPException(status_code=400, detail="Invalid workflow YAML")

    if not isinstance(workflow, dict):
        raise HTTPException(status_code=400, detail="Invalid workflow format: Expected a dictionary")

    if not workflow.get("jobs") and not workflow.get("on"):
        raise HTTPException(status_code=400, detail="Invalid workflow: Missing required 'jobs' or 'on' fields")

    graph = GraphBuilder()
    client = GitHubClient(token=request.github_token)

    workflow_node_id = "workflow:inline"
    graph.add_node(
        workflow_node_id,
        "Inline Workflow",
        "workflow",
        {"path": "inline", "is_inline": True}
    )

    workflow_issues = await auditor.audit_workflow(
        workflow,
        content=request.yaml_content,
        client=client
    )

    graph.add_issues_to_node(workflow_node_id, workflow_issues)

    actions = parser.extract_actions(workflow)
    visited = set()

    for action_ref in actions:
        graph.add_edge(workflow_node_id, action_ref)
        await resolve_action_dependencies(
            client, action_ref, graph, visited, depth=0, max_depth=5
        )

    _add_workflow_container_image_nodes(graph, workflow, workflow_node_id, workflow_issues)

    graph_data = graph.get_graph_data()
    statistics = graph.get_statistics()

    analysis_id = storage.save_analysis(
        repository=None,
        action=None,
        graph_data=graph_data,
        statistics=statistics,
        method="yaml"
    )

    return {
        "id": analysis_id,
        "graph": graph_data,
        "statistics": statistics
    }


@app.post("/api/audit/yaml")
async def audit_yaml(request: AuditYAMLRequest):
    """Audit a raw YAML workflow file."""
    try:
        return await _audit_yaml_body(request)
    except HTTPException:
        raise
    except yaml.YAMLError as e:
        if hasattr(e, "problem_mark") and e.problem_mark:
            line_num = e.problem_mark.line + 1
            raise HTTPException(status_code=400, detail=f"YAML syntax error at line {line_num}")
        raise HTTPException(status_code=400, detail="YAML syntax error")
    except Exception:
        logger.exception("Unexpected error during YAML audit")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/api/analyses")
async def list_analyses(repository: Optional[str] = None, limit: int = 50):
    """List all saved analyses."""
    return storage.list_analyses(limit=limit, repository=repository)


@app.get("/api/analyses/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Get a specific analysis by ID."""
    analysis = storage.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis


@app.delete("/api/analyses/{analysis_id}")
async def delete_analysis(analysis_id: str):
    """Delete an analysis by ID."""
    if storage.delete_analysis(analysis_id):
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Analysis not found")


# Serve frontend for all non-API routes (must be last)
if os.path.exists(FRONTEND_BUILD_PATH):
    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        """Serve frontend for all non-API routes."""
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found")
        
        # Normalize and check the path is within FRONTEND_BUILD_PATH
        abs_frontend_root = os.path.abspath(FRONTEND_BUILD_PATH)
        file_path = os.path.normpath(os.path.join(FRONTEND_BUILD_PATH, full_path))
        abs_file_path = os.path.abspath(file_path)
        if abs_file_path.startswith(abs_frontend_root) and os.path.exists(abs_file_path) and os.path.isfile(abs_file_path):
            return FileResponse(abs_file_path)
        # Serve index.html for SPA routing
        return FileResponse(os.path.join(FRONTEND_BUILD_PATH, "index.html"))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

