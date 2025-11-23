# Contributing to actsense

Thank you for your interest in contributing to actsense! This document provides technical details and development guidelines.

## Project Structure

```
actsense/
├── backend/
│   ├── main.py                 # FastAPI application
│   ├── github_client.py        # GitHub API client
│   ├── workflow_parser.py       # YAML parsing
│   ├── security_auditor.py     # Security checks (30+ checks)
│   ├── graph_builder.py         # Dependency graph builder
│   ├── repo_cloner.py          # Git repository cloning
│   ├── analysis_storage.py     # Analysis persistence
│   └── requirements.txt        # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Main application component
│   │   ├── components/         # React components
│   │   │   ├── ActionGraph.jsx  # Graph visualization
│   │   │   ├── NodesTable.jsx  # Table view
│   │   │   ├── Statistics.jsx  # Stats display
│   │   │   └── ...
│   │   └── utils/              # Utility functions
│   ├── package.json
│   └── vite.config.js
├── docs/                       # Hugo site for documentation
│   ├── hugo.yaml               # Site configuration
│   ├── content/                # Markdown docs (see vulnerabilities/)
│   ├── layouts/                # Theme overrides & partials
│   ├── assets/                 # Custom CSS/JS
│   ├── public/                 # Built static site output
│   └── resources/_gen/         # Hugo cache (generated)
└── data/                       # Generated data (gitignored)
    ├── analyses/              # Saved analyses
    └── clones/                # Cloned repositories
```

## Development Setup

### Backend

1. Create virtual environment:
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run development server:
```bash
uvicorn main:app --reload --port 8000
```

### Frontend

1. Install dependencies:
```bash
cd frontend
npm install
```

2. Run development server:
```bash
npm run dev
```

The frontend will proxy API requests to `http://localhost:8000`.

### Documentation Site (Hugo)

1. Install the Hugo Extended binary (v0.125+ recommended).
2. Run the docs locally:
```bash
cd docs
hugo server --config hugo.yaml --disableFastRender
```
   The site will be served at `http://localhost:1313`.
3. Build the static site (outputs to `docs/public/`):
```bash
cd docs
hugo --config hugo.yaml
```

All public-facing vulnerability write-ups live under `docs/content/vulnerabilities/`. Each Markdown file maps 1:1 with the `/vulnerabilities/*` routes, so add or update files there when documenting new checks.

### Integrated Development

Use the provided script:
```bash
./start.sh
```

This builds the frontend and starts the backend server.

## Production Build

1. Build frontend:
```bash
cd frontend
npm run build
```

2. Start backend (serves built frontend):
```bash
cd backend
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000
```

## API Documentation

### POST `/api/audit`

Audit a repository or action.

**Request Body:**
```json
{
  "repository": "owner/repo",      // Optional
  "action": "owner/repo@v1",       // Optional
  "github_token": "ghp_...",        // Optional
  "use_clone": false                // Optional, repositories only
}
```

**Response:**
```json
{
  "id": "analysis-uuid",
  "graph": {
    "nodes": [
      {
        "id": "node-id",
        "label": "Display Name",
        "type": "repository|workflow|action",
        "metadata": {},
        "issues": [],
        "issue_count": 0,
        "severity": "none|low|medium|high|critical"
      }
    ],
    "edges": [
      {
        "source": "node-id",
        "target": "node-id",
        "type": "uses"
      }
    ],
    "issues": {
      "node-id": [
        {
          "type": "issue-type",
          "severity": "low|medium|high|critical",
          "message": "Issue description",
          "action": "action-ref",
          "recommendation": "How to fix"
        }
      ]
    }
  },
  "statistics": {
    "total_nodes": 10,
    "total_edges": 15,
    "total_issues": 5,
    "severity_counts": {
      "critical": 1,
      "high": 2,
      "medium": 1,
      "low": 1
    },
    "nodes_with_issues": 3
  }
}
```

### GET `/api/analyses`

List all saved analyses.

**Query Parameters:**
- `repository` (optional): Filter by repository
- `limit` (optional): Maximum results (default: 50)

**Response:**
```json
[
  {
    "id": "analysis-uuid",
    "timestamp": "2024-01-01T00:00:00",
    "repository": "owner/repo",
    "action": null,
    "method": "api|clone",
    "statistics": {...}
  }
]
```

### GET `/api/analyses/{analysis_id}`

Get a specific analysis by ID.

### DELETE `/api/analyses/{analysis_id}`

Delete an analysis by ID.

## Security Checks Reference

### High Severity

- **unpinned_version**: Action not pinned to version/tag/SHA
- **unpinnable_docker_image**: Docker action uses mutable tag instead of digest
- **unpinnable_composite_subaction**: Composite action uses unpinned sub-action
- **unpinnable_javascript_resources**: JavaScript action downloads resources without checksums
- **potential_hardcoded_secret**: Hardcoded secret detected
- **overly_permissive**: Workflow has write permissions
- **github_token_write_all**: GITHUB_TOKEN has write-all permissions
- **dangerous_event**: Uses pull_request_target or workflow_run
- **unsafe_checkout**: Checkout with persist-credentials=true
- **potential_script_injection**: Script injection vulnerability
- **secrets_in_matrix**: Secrets used in matrix strategy
- **untrusted_action_unpinned**: Untrusted third-party action not pinned
- **long_term_aws_credentials**: Uses AWS credentials instead of OIDC
- **long_term_azure_credentials**: Uses Azure credentials instead of OIDC
- **long_term_gcp_credentials**: Uses GCP credentials instead of OIDC
- **potential_hardcoded_cloud_credentials**: Hardcoded cloud credentials
- **unfiltered_network_traffic**: Network operations without filtering
- **branch_protection_bypass**: Workflow may bypass branch protection
- **code_injection_via_input**: Code injection via workflow inputs

### Medium Severity

- **no_hash_pinning**: Uses tag instead of commit SHA
- **older_action_version**: Action uses older version (tag or commit hash) compared to latest
- **unpinned_dockerfile_dependencies**: Dockerfile installs unpinned packages
- **unpinned_dockerfile_resources**: Dockerfile downloads without checksums
- **unpinned_npm_packages**: NPM packages without version locking
- **unpinned_python_packages**: Python packages without version pinning
- **unpinned_external_resources**: External resources without checksums
- **optional_secret_input**: Action has optional secret input
- **github_token_write_permissions**: GITHUB_TOKEN has write permissions
- **self_hosted_runner**: Uses self-hosted runner
- **unsafe_checkout_ref**: Checkout with potentially unsafe ref
- **unsafe_shell**: Bash without -e flag
- **unvalidated_workflow_input**: Workflow input without validation
- **untrusted_third_party_action**: Uses untrusted third-party action
- **no_file_tampering_protection**: Build job modifies files without protection
- **insufficient_audit_logging**: Sensitive operations without audit logging

### Low Severity

- **short_hash_pinning**: Uses short SHA (7+ chars) instead of full 40-char SHA
- **inconsistent_action_version**: Same action used with different versions across multiple workflows
- **checkout_full_history**: Fetches full git history
- **long_artifact_retention**: Artifact retention > 90 days
- **large_matrix**: Matrix with > 100 combinations
- **environment_with_secrets**: Environment used with secrets

## Adding New Security Checks

1. Add a new static method to `SecurityAuditor` class in `backend/security_auditor.py`:
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

2. Add the check to `audit_workflow` method:
```python
issues.extend(SecurityAuditor.check_your_new_check(workflow))
```

3. For action-specific checks, add to `audit_action` method.

## Frontend Components

### ActionGraph
- Uses ReactFlow for graph visualization
- Supports hierarchical and dependency layouts
- Custom nodes with security issue indicators

### NodesTable
- Displays nodes in table format
- Filterable by security issues
- Sortable columns

### TransitiveDependenciesTable
- Accordion-style dependency tree
- Shows transitive dependencies for each node

### NodeDetailsPanel
- Slide-in panel with node details
- Security issues list
- Dependency chain visualization

## Testing

### Backend Testing
```bash
cd backend
source venv/bin/activate
python -m pytest  # If tests are added
```

### Frontend Testing
```bash
cd frontend
npm test  # If tests are added
```

## Code Style

- **Python**: Follow PEP 8, use type hints
- **JavaScript**: Use ES6+, follow React best practices
- **CSS**: Use BEM-like naming, keep styles modular

## Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request with a clear description

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [GitHub Actions Goat](https://github.com/step-security/github-actions-goat)
- [Unpinnable Actions Research](https://www.paloaltonetworks.com/blog/cloud-security/unpinnable-actions-github-security/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://react.dev/)
- [ReactFlow Documentation](https://reactflow.dev/)

