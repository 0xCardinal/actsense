"""FastAPI backend for GitHub Actions security auditor."""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Set
import os
import uvicorn
import yaml
from urllib.parse import urlparse
from github_client import GitHubClient
from workflow_parser import WorkflowParser
from security_auditor import SecurityAuditor
from graph_builder import GraphBuilder
from repo_cloner import RepoCloner
from analysis_storage import AnalysisStorage

app = FastAPI(title="actsense - GitHub Actions Security Auditor")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

parser = WorkflowParser()
auditor = SecurityAuditor()
cloner = RepoCloner()
storage = AnalysisStorage()

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
    max_depth: int = 5
):
    """Recursively resolve action dependencies."""
    if depth > max_depth or action_ref in visited:
        return
    
    visited.add(action_ref)
    
    # Parse action reference
    owner, repo, ref, subdir = client.parse_action_reference(action_ref)
    if not owner or not repo:
        return
    
    # Skip workflow files - they shouldn't be treated as actions
    if subdir and (".github/workflows" in subdir or subdir.endswith((".yml", ".yaml"))):
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
                    client, dep, graph, visited, depth + 1, max_depth
                )
        except Exception as e:
            # Silently skip if there's an error resolving dependencies
            pass


async def audit_repository(
    client: GitHubClient,
    owner: str,
    repo: str,
    graph: GraphBuilder,
    use_clone: bool = False,
    token: Optional[str] = None
):
    """Audit a repository's workflows."""
    # Add repository as root node
    repo_node_id = f"{owner}/{repo}"
    graph.add_node(repo_node_id, repo_node_id, "repository", {"owner": owner, "repo": repo})
    
    clone_path = None
    workflow_actions_data = []  # Collect actions from all workflows for inconsistency checking
    
    try:
        if use_clone:
            # Clone repository
            clone_path, _ = cloner.clone_repository(owner, repo, token)
            workflows = cloner.get_workflow_files(clone_path)
            
            visited = set()
            
            for workflow_file in workflows:
                try:
                    content = cloner.get_file_content(clone_path, workflow_file["path"])
                    workflow = parser.parse_workflow(content)
                    
                    # Skip if workflow is not a dict or has an error
                    if not isinstance(workflow, dict) or "error" in workflow:
                        continue
                    
                    # Audit workflow with content for line number tracking
                    workflow_issues = await auditor.audit_workflow(workflow, content=content, client=client)
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
                            client, action_ref, graph, visited
                        )
                except Exception as e:
                    print(f"Error processing workflow {workflow_file['name']}: {e}")
        else:
            # Use API method (original)
            workflows = await client.get_workflows(owner, repo)
            
            visited = set()
            
            for workflow_file in workflows:
                try:
                    content = await client.get_file_content(owner, repo, workflow_file["path"])
                    workflow = parser.parse_workflow(content)
                    
                    # Skip if workflow is not a dict or has an error
                    if not isinstance(workflow, dict) or "error" in workflow:
                        continue
                    
                    # Audit workflow with content for line number tracking
                    workflow_issues = await auditor.audit_workflow(workflow, content=content, client=client)
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
                            client, action_ref, graph, visited
                        )
                except Exception as e:
                    print(f"Error processing workflow {workflow_file['name']}: {e}")
        
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/audit/yaml")
async def audit_yaml(request: AuditYAMLRequest):
    """Audit a raw YAML workflow file."""
    try:
        # Validate YAML syntax first
        try:
            parsed_yaml = yaml.safe_load(request.yaml_content)
            if parsed_yaml is None:
                raise HTTPException(status_code=400, detail="YAML file is empty or contains no valid content")
        except yaml.YAMLError as e:
            # Extract line number if available
            if hasattr(e, 'problem_mark') and e.problem_mark:
                line_num = e.problem_mark.line + 1
                error_msg = f"YAML syntax error at line {line_num}"
            else:
                error_msg = "YAML syntax error"
            raise HTTPException(status_code=400, detail=f"Invalid YAML syntax: {error_msg}")
        
        # Parse the YAML content using workflow parser
        workflow = parser.parse_workflow(request.yaml_content)
        
        if "error" in workflow:
            raise HTTPException(status_code=400, detail=f"Invalid workflow YAML: {workflow['error']}")
        
        if not isinstance(workflow, dict):
            raise HTTPException(status_code=400, detail="Invalid workflow format: Expected a dictionary")
        
        # Basic workflow structure validation
        if not workflow.get("jobs") and not workflow.get("on"):
            raise HTTPException(status_code=400, detail="Invalid workflow: Missing required 'jobs' or 'on' fields")
        
        # Create a graph for the workflow
        graph = GraphBuilder()
        client = GitHubClient(token=request.github_token)
        
        # Add a synthetic workflow node
        workflow_node_id = "workflow:inline"
        graph.add_node(
            workflow_node_id,
            "Inline Workflow",
            "workflow",
            {"path": "inline", "is_inline": True}
        )
        
        # Audit the workflow
        workflow_issues = await auditor.audit_workflow(
            workflow, 
            content=request.yaml_content, 
            client=client
        )
        
        # Add issues to the workflow node
        graph.add_issues_to_node(workflow_node_id, workflow_issues)
        
        # Extract actions and resolve dependencies
        actions = parser.extract_actions(workflow)
        visited = set()
        
        for action_ref in actions:
            graph.add_edge(workflow_node_id, action_ref)
            await resolve_action_dependencies(
                client, action_ref, graph, visited, depth=0, max_depth=5
            )
        
        graph_data = graph.get_graph_data()
        statistics = graph.get_statistics()
        
        # Save analysis
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
    
    except HTTPException:
        raise
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"YAML parsing error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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

