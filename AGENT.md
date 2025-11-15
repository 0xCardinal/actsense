# Agent Documentation for action-auditor

This document provides comprehensive information for AI agents working with the actsense codebase.

## Project Overview

**actsense** is a security auditing tool for GitHub Actions that:
- Analyzes GitHub Actions workflows and their dependencies
- Detects 30+ security vulnerabilities and best practice violations
- Visualizes action dependencies in an interactive graph
- Provides detailed security recommendations

## Architecture

### Backend (Python/FastAPI)
- **FastAPI** web framework
- **Async/await** for concurrent operations
- **GitHub API** integration for fetching repository data
- **YAML parsing** for workflow files
- **Graph-based** dependency tracking

### Frontend (React)
- **React 18** with functional components
- **ReactFlow** for graph visualization
- **Vite** for build tooling
- **Modern CSS** with component-scoped styles

## Key Components

### Backend Modules

#### `main.py`
- FastAPI application entry point
- API endpoints: `/api/audit`, `/api/analyses`, `/api/health`
- Repository and action auditing orchestration
- Dependency resolution logic

#### `github_client.py`
- GitHub API client with authentication
- Methods:
  - `get_repo_contents()` - Get repository files
  - `get_file_content()` - Get file content
  - `get_workflows()` - Get workflow files
  - `get_action_metadata()` - Get action.yml files
  - `get_latest_tag()` - Get latest version tag (NEW)
  - `get_commit_date()` - Get commit date for SHA (NEW)
  - `get_latest_tag_commit_date()` - Get latest tag's commit date (NEW)
  - `parse_action_reference()` - Parse action references

#### `security_auditor.py`
- Comprehensive security issue detection
- 30+ security checks organized by category
- Main methods:
  - `audit_workflow()` - Audit a workflow file (async)
  - `audit_action()` - Audit a single action
  - `check_older_action_versions()` - Check for outdated versions (async, NEW)
  - `check_inconsistent_action_versions()` - Check version consistency across workflows (NEW)

#### `workflow_parser.py`
- YAML parsing and extraction
- Action reference detection
- Dependency extraction from composite actions

#### `graph_builder.py`
- Dependency graph construction
- Node and edge management
- Issue attachment to nodes
- Statistics calculation

#### `repo_cloner.py`
- Git repository cloning
- Local file access
- Cleanup management

#### `analysis_storage.py`
- JSON-based analysis persistence
- UUID-based storage
- Query and deletion operations

### Frontend Components

#### `App.jsx`
- Main application state management
- API communication
- View mode switching

#### `ActionGraph.jsx`
- ReactFlow graph visualization
- Node selection and filtering
- Interactive controls

#### `NodeDetailsPanel.jsx`
- Detailed node information display
- Security issues list
- Issue details modal integration

#### `IssueDetailsModal.jsx`
- Security issue details display
- Description and mitigation strategies
- Version inconsistency display (NEW)

## Security Checks Reference

### Severity Levels
- **critical**: Immediate security risk
- **high**: Significant security concern
- **medium**: Moderate security issue
- **low**: Minor security concern

### Issue Types by Category

#### Action Pinning & Immutability
- `unpinned_version` (high) - Action not pinned to version/tag/SHA
- `no_hash_pinning` (medium) - Uses tag instead of commit SHA
- `short_hash_pinning` (low) - Uses short SHA instead of full SHA
- `older_action_version` (medium) - Action uses older version than latest (NEW)
- `inconsistent_action_version` (low) - Same action with different versions across workflows (NEW)
- `unpinnable_docker_image` (high) - Docker action with mutable tag
- `unpinnable_composite_subaction` (high) - Composite action with unpinned sub-actions
- `unpinnable_javascript_resources` (high) - JavaScript action downloads without checksums

#### Permissions & Access Control
- `overly_permissive` (high) - Write permissions to contents
- `github_token_write_all` (high) - GITHUB_TOKEN write-all permissions
- `github_token_write_permissions` (medium) - GITHUB_TOKEN write permissions
- `self_hosted_runner` (medium) - Self-hosted runners
- `branch_protection_bypass` (high) - Branch protection bypass

#### Secrets & Credentials
- `potential_hardcoded_secret` (high) - Hardcoded secrets detected
- `optional_secret_input` (medium) - Optional secret inputs
- `long_term_aws_credentials` (high) - AWS credentials instead of OIDC
- `long_term_azure_credentials` (high) - Azure credentials instead of OIDC
- `long_term_gcp_credentials` (high) - GCP credentials instead of OIDC
- `environment_with_secrets` (low) - Environment used with secrets

#### Workflow Security
- `dangerous_event` (high) - pull_request_target, workflow_run events
- `unsafe_checkout` (high) - Checkout with persist-credentials
- `unsafe_checkout_ref` (medium) - Potentially unsafe checkout ref
- `checkout_full_history` (low) - Fetches full git history
- `potential_script_injection` (high) - Script injection risk
- `code_injection_via_input` (high) - Code injection via workflow inputs
- `unvalidated_workflow_input` (medium) - Unvalidated workflow dispatch inputs
- `unsafe_shell` (medium) - Bash without -e flag

#### Supply Chain Security
- `untrusted_third_party_action` (medium) - Third-party action from untrusted publisher
- `untrusted_action_unpinned` (high) - Untrusted action not pinned
- `unpinned_dockerfile_dependencies` (medium) - Dockerfile installs unpinned packages
- `unpinned_dockerfile_resources` (medium) - Dockerfile downloads without checksums
- `unpinned_npm_packages` (medium) - NPM packages without version locking
- `unpinned_python_packages` (medium) - Python packages without version pinning
- `unpinned_external_resources` (medium) - External resources without checksums
- `unfiltered_network_traffic` (high) - Network operations without filtering
- `no_file_tampering_protection` (medium) - File modifications without protection

#### Best Practices
- `artifact_retention` (low) - Artifact retention > 90 days
- `secrets_in_matrix` (high) - Secrets used in matrix strategy
- `large_matrix` (low) - Matrix with > 100 combinations
- `insufficient_audit_logging` (medium) - Missing audit logs

## New Features (Recent Additions)

### Older Action Version Detection
- **Function**: `check_older_action_versions()` (async)
- **Purpose**: Detects when actions use outdated versions (tags or commit hashes)
- **How it works**:
  1. For version tags: Fetches latest tag from GitHub API and compares versions
  2. For commit hashes: Fetches commit date and compares to latest tag's commit date
  3. Flags versions that are significantly older (>1 year for hashes, or older than latest for tags)
- **Severity**: Medium
- **Requires**: GitHubClient for API calls

### Inconsistent Action Version Detection
- **Function**: `check_inconsistent_action_versions()`
- **Purpose**: Detects when the same action is used with different versions across multiple workflows
- **How it works**:
  1. Collects all actions from all workflows in a repository
  2. Groups by action name (without version)
  3. Detects when multiple versions of the same action are used
  4. Creates issues listing all versions found and which workflows use each
- **Severity**: Low
- **Scope**: Repository-level (attached to repository node)

### GitHub Client Enhancements
- `get_latest_tag()` - Fetches latest version tag from GitHub (releases API or tags API)
- `get_commit_date()` - Gets commit date for a specific SHA
- `get_latest_tag_commit_date()` - Gets commit date of the latest tag

## Data Flow

### Audit Request Flow
1. User submits repository/action via frontend
2. Backend receives request at `/api/audit`
3. `audit_repository()` or `resolve_action_dependencies()` called
4. Workflows parsed and actions extracted
5. Security checks run (including async version checks)
6. Dependency graph built
7. Results stored and returned

### Version Checking Flow (New)
1. During workflow audit, actions collected
2. `check_older_action_versions()` called (async)
3. For each action with version tag:
   - Fetch latest tag from GitHub
   - Compare versions semantically
   - Flag if outdated
4. For each action with commit hash:
   - Fetch commit date
   - Compare to latest tag's commit date
   - Flag if >1 year old
5. After all workflows processed:
   - `check_inconsistent_action_versions()` called
   - Detects version inconsistencies
   - Creates repository-level issues

## API Endpoints

### POST `/api/audit`
Audit a repository or action.

**Request**:
```json
{
  "repository": "owner/repo",
  "action": "owner/repo@v1",
  "github_token": "ghp_...",
  "use_clone": false
}
```

**Response**:
```json
{
  "id": "uuid",
  "graph": {
    "nodes": [...],
    "edges": [...],
    "issues": {...}
  },
  "statistics": {...}
}
```

### GET `/api/analyses`
List saved analyses (optional: filter by repository, limit results).

### GET `/api/analyses/{id}`
Get specific analysis by ID.

### DELETE `/api/analyses/{id}`
Delete analysis by ID.

## Adding New Security Checks

### Workflow-Level Check
```python
@staticmethod
def check_your_new_check(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for your security issue."""
    issues = []
    # Your check logic
    if condition:
        issues.append({
            "type": "your_issue_type",
            "severity": "high|medium|low",
            "message": "Issue description",
            "recommendation": "How to fix"
        })
    return issues
```

Then add to `audit_workflow()`:
```python
issues.extend(SecurityAuditor.check_your_new_check(workflow))
```

### Async Check (Requires GitHub API)
```python
@staticmethod
async def check_your_async_check(workflow: Dict[str, Any], client: Optional[GitHubClient] = None) -> List[Dict[str, Any]]:
    """Async check that requires GitHub API."""
    issues = []
    if client:
        # Use client for API calls
        pass
    return issues
```

### Repository-Level Check
For checks that span multiple workflows:
1. Collect data during workflow processing
2. After all workflows processed, run check
3. Attach issues to repository node

Example: `check_inconsistent_action_versions()`

## Frontend Integration

### Adding New Issue Type
1. Add description and mitigation to `IssueDetailsModal.jsx`:
```javascript
'inconsistent_action_version': {
  description: '...',
  mitigation: '...'
}
```

2. Optionally add custom display section:
```javascript
{issue.type === 'your_issue_type' && issue.customData && (
  <div className="issue-modal-section">
    {/* Custom display */}
  </div>
)}
```

## Testing Considerations

- **Async operations**: Ensure proper awaiting of async checks
- **API rate limits**: Be mindful of GitHub API rate limits
- **Error handling**: Gracefully handle API failures
- **Edge cases**: Empty workflows, missing actions, invalid versions

## Common Patterns

### Extracting Actions from Workflow
```python
actions = parser.extract_actions(workflow)
```

### Parsing Action Reference
```python
owner, repo, ref, subdir = client.parse_action_reference(action_ref)
```

### Adding Issues to Node
```python
graph.add_issues_to_node(node_id, issues)
```

### Version Comparison
```python
# Parse version
version_tuple = (major, minor, patch)
# Compare
if current_version < latest_version:
    # Flag as outdated
```

## File Locations

- Backend security checks: `backend/security_auditor.py`
- GitHub API client: `backend/github_client.py`
- Workflow parsing: `backend/workflow_parser.py`
- Main API: `backend/main.py`
- Frontend components: `frontend/src/components/`
- Issue descriptions: `frontend/src/components/IssueDetailsModal.jsx`

## Key Design Decisions

1. **Async version checking**: Version checks require GitHub API calls, so they're async
2. **Repository-level issues**: Inconsistency checks span multiple workflows, so attached to repo node
3. **Fallback heuristics**: When API calls fail, use heuristics (e.g., flag v1/v2 as potentially outdated)
4. **Semantic version comparison**: Properly compares version numbers, not just strings
5. **Commit date comparison**: For hashes, compares commit dates rather than trying to determine version

## Future Enhancements

- Caching of version lookups to reduce API calls
- Batch API requests for better performance
- More granular version comparison (e.g., flag if >6 months old)
- Support for action version policies (e.g., "must use v3+")

