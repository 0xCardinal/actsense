# Code Index

This document provides a comprehensive index of the action-auditor codebase structure, components, and their purposes.

## Project Overview

**actsense** (action-auditor) is a security auditor for GitHub Actions that analyzes workflows and their dependencies to identify security vulnerabilities. It consists of a FastAPI backend and a React frontend.

## Directory Structure

```
action-auditor/
├── backend/              # Python FastAPI backend
│   ├── main.py          # FastAPI application and API endpoints
│   ├── github_client.py # GitHub API client
│   ├── workflow_parser.py # YAML workflow parser
│   ├── security_auditor.py # Security issue detection
│   ├── graph_builder.py # Dependency graph construction
│   ├── repo_cloner.py   # Repository cloning functionality
│   ├── analysis_storage.py # Analysis result persistence
│   ├── requirements.txt  # Python dependencies
│   └── venv/            # Python virtual environment
├── frontend/            # React frontend application
│   ├── src/
│   │   ├── App.jsx      # Main application component
│   │   ├── components/  # React components
│   │   └── utils/       # Utility functions
│   ├── package.json     # Node.js dependencies
│   └── dist/           # Production build output
├── data/
│   ├── analyses/       # Stored analysis results (JSON)
│   └── clones/         # Temporary repository clones
├── setup.sh            # Setup script
├── start-backend.sh    # Backend startup script
├── start-frontend.sh   # Frontend startup script
├── start-integrated.sh # Integrated startup script
└── README.md           # Project documentation
```

## Backend Components

### Core Application

#### `main.py`
**Purpose**: FastAPI application entry point and API route definitions

**Key Components**:
- FastAPI app initialization with CORS middleware
- API endpoints:
  - `POST /api/audit` - Main audit endpoint
  - `GET /api/health` - Health check
  - `GET /api/analyses` - List saved analyses
  - `GET /api/analyses/{id}` - Get specific analysis
  - `DELETE /api/analyses/{id}` - Delete analysis
- Frontend static file serving (production mode)
- Dependency resolution logic (`resolve_action_dependencies`)
- Repository auditing logic (`audit_repository`)

**Dependencies**: All other backend modules

#### `github_client.py`
**Purpose**: GitHub API client for fetching repository data

**Key Methods**:
- `get_repo_contents()` - Get repository contents at path
- `get_file_content()` - Get file content from repository
- `get_workflows()` - Get all workflow files from `.github/workflows`
- `get_action_metadata()` - Get `action.yml` or `action.yaml`
- `parse_action_reference()` - Parse action reference strings

**Features**:
- Token-based authentication
- Rate limit handling
- Base64 content decoding

#### `workflow_parser.py`
**Purpose**: Parse and extract information from YAML workflow files

**Key Methods**:
- `parse_workflow()` - Parse workflow YAML content
- `extract_actions()` - Extract all action references from workflow
- `parse_action_yml()` - Parse action.yml files
- `extract_action_dependencies()` - Extract dependencies from action.yml

**Features**:
- YAML parsing with error handling
- Action reference detection
- Dependency extraction from composite actions

#### `security_auditor.py`
**Purpose**: Comprehensive security issue detection

**Key Security Checks**:

**Action Pinning & Immutability**:
- `check_pinned_version()` - Unpinned action versions
- `check_hash_pinning()` - Hash pinning vs tags
- `check_unpinnable_docker_action()` - Unpinnable Docker actions
- `check_unpinnable_composite_action()` - Unpinnable composite actions
- `check_unpinnable_javascript_action()` - Unpinnable JavaScript actions

**Permissions & Access Control**:
- `check_permissions()` - Overly permissive workflow permissions
- `check_github_token_permissions()` - GITHUB_TOKEN write permissions
- `check_self_hosted_runners()` - Self-hosted runners
- `check_branch_protection_bypass()` - Branch protection bypass

**Secrets & Credentials**:
- `check_secrets_in_workflow()` - Hardcoded secrets detection
- `check_environment_secrets()` - Environment secrets usage
- `check_long_term_credentials()` - Long-term cloud credentials (AWS, Azure, GCP)

**Workflow Security**:
- `check_dangerous_events()` - Dangerous workflow events
- `check_checkout_actions()` - Unsafe checkout actions
- `check_script_injection()` - Script injection vulnerabilities
- `check_code_injection_via_workflow_inputs()` - Code injection via inputs
- `check_workflow_dispatch_inputs()` - Unvalidated workflow dispatch inputs

**Supply Chain Security**:
- `check_untrusted_third_party_actions()` - Untrusted third-party actions
- `check_network_traffic_filtering()` - Network traffic filtering
- `check_file_tampering_protection()` - File tampering protection

**Best Practices**:
- `check_artifact_retention()` - Artifact retention settings
- `check_matrix_strategy()` - Matrix strategy security
- `check_audit_logging()` - Audit logging

**Main Methods**:
- `audit_action()` - Audit a single action
- `audit_workflow()` - Audit a workflow file

#### `graph_builder.py`
**Purpose**: Build dependency graph for visualization

**Key Methods**:
- `add_node()` - Add node to graph
- `add_edge()` - Add edge between nodes
- `add_issues_to_node()` - Attach security issues to node
- `get_graph_data()` - Get formatted graph data for frontend
- `get_statistics()` - Calculate graph statistics

**Data Structure**:
- Nodes: Actions, workflows, repositories
- Edges: Dependency relationships
- Issues: Security issues per node

#### `repo_cloner.py`
**Purpose**: Clone repositories locally for analysis

**Key Methods**:
- `clone_repository()` - Clone repository to temporary directory
- `get_file_content()` - Read file from cloned repository
- `get_workflow_files()` - Get all workflow files
- `cleanup()` - Remove cloned repository

**Features**:
- Token-based authentication for private repos
- Shallow cloning (depth=1)
- Automatic cleanup
- Timeout handling

#### `analysis_storage.py`
**Purpose**: Persist and retrieve analysis results

**Key Methods**:
- `save_analysis()` - Save analysis with UUID
- `get_analysis()` - Retrieve analysis by ID
- `list_analyses()` - List all analyses (with filtering)
- `delete_analysis()` - Delete analysis by ID

**Storage Format**: JSON files in `data/analyses/` directory

## Frontend Components

### Main Application

#### `App.jsx`
**Purpose**: Main React application component

**State Management**:
- `graphData` - Graph visualization data
- `statistics` - Analysis statistics
- `loading` - Loading state
- `error` - Error messages
- `selectedNode` - Currently selected node
- `graphFilter` - Active filter
- `viewMode` - Current view mode (graph/table)

**Key Handlers**:
- `handleAudit()` - Submit audit request
- `handleLoadAnalysis()` - Load saved analysis

### React Components

#### `InputForm.jsx`
**Purpose**: Form for submitting audit requests

**Features**:
- Repository/action input
- GitHub token input (optional)
- Clone vs API method selection
- Loading state handling

#### `ActionGraph.jsx`
**Purpose**: Interactive graph visualization using ReactFlow

**Features**:
- Node rendering with severity colors
- Edge visualization
- Node selection
- Filtering support
- Zoom and pan controls

#### `Statistics.jsx`
**Purpose**: Display analysis statistics and filters

**Features**:
- Total nodes/edges/issues counts
- Severity breakdown
- Filter controls
- View mode toggle (graph/table)

#### `NodeDetailsPanel.jsx`
**Purpose**: Side panel showing detailed node information

**Features**:
- Node metadata display
- Security issues list
- Issue severity highlighting
- Close button

#### `NodesTable.jsx`
**Purpose**: Table view of all nodes

**Features**:
- Sortable columns
- Filterable by type/severity
- Node selection
- Issue count display

#### `TransitiveDependenciesTable.jsx`
**Purpose**: Table view of transitive dependencies

**Features**:
- Dependency chain visualization
- Filtering by dependency depth
- Node selection

#### `IssuesTable.jsx`
**Purpose**: Table view of all security issues

**Features**:
- Issue type and severity
- Associated node/action
- Message and recommendations

#### `AnalysisHistory.jsx`
**Purpose**: Display and load saved analyses

**Features**:
- List of previous analyses
- Timestamp display
- Load analysis functionality
- Delete analysis functionality

#### `CustomNode.jsx`
**Purpose**: Custom ReactFlow node component

**Features**:
- Severity-based styling
- Issue count badges
- Node type indicators

#### `ErrorBoundary.jsx`
**Purpose**: React error boundary for error handling

## Data Flow

### Audit Request Flow

1. **User Input** (`InputForm.jsx`)
   - User enters repository/action
   - Optionally provides GitHub token
   - Selects analysis method (API/clone)

2. **API Request** (`App.jsx` → `main.py`)
   - POST to `/api/audit`
   - Request includes repository/action, token, method

3. **Backend Processing** (`main.py`)
   - Create `GitHubClient` with token
   - Create `GraphBuilder` for results
   - If repository: call `audit_repository()`
   - If action: call `resolve_action_dependencies()`

4. **Dependency Resolution** (`main.py`)
   - Parse action reference
   - Fetch action metadata via `GitHubClient`
   - Parse action.yml via `WorkflowParser`
   - Audit action via `SecurityAuditor`
   - Recursively resolve dependencies
   - Build graph via `GraphBuilder`

5. **Security Auditing** (`security_auditor.py`)
   - Run all security checks
   - Collect issues per node
   - Return issue list

6. **Graph Building** (`graph_builder.py`)
   - Add nodes and edges
   - Attach issues to nodes
   - Calculate statistics
   - Format for frontend

7. **Storage** (`analysis_storage.py`)
   - Save analysis with UUID
   - Store in `data/analyses/`

8. **Response** (`main.py` → `App.jsx`)
   - Return graph data and statistics
   - Update frontend state
   - Render visualization

### Visualization Flow

1. **Graph View** (`ActionGraph.jsx`)
   - Render nodes and edges
   - Apply filters
   - Handle node selection

2. **Table Views** (`NodesTable.jsx`, `TransitiveDependenciesTable.jsx`)
   - Display filtered data
   - Enable sorting
   - Handle selection

3. **Details Panel** (`NodeDetailsPanel.jsx`)
   - Show selected node details
   - Display security issues
   - Show recommendations

## Security Checks Reference

### Severity Levels
- **critical**: Immediate security risk
- **high**: Significant security concern
- **medium**: Moderate security issue
- **low**: Minor security concern

### Issue Types

**Action Pinning**:
- `unpinned_version` - Action missing version/tag
- `no_hash_pinning` - Using tag instead of commit SHA
- `short_hash_pinning` - Using short SHA instead of full SHA
- `unpinnable_docker_image` - Docker action with mutable tag
- `unpinnable_composite_subaction` - Composite action with unpinned sub-actions
- `unpinnable_javascript_resources` - JavaScript action downloading without checksums

**Permissions**:
- `overly_permissive` - Write permissions to contents
- `github_token_write_all` - Write-all permissions
- `github_token_write_permissions` - Write permissions to specific scopes

**Secrets**:
- `potential_hardcoded_secret` - Hardcoded secrets detected
- `optional_secret_input` - Optional secret inputs
- `long_term_aws_credentials` - AWS credentials instead of OIDC
- `long_term_azure_credentials` - Azure credentials instead of OIDC
- `long_term_gcp_credentials` - GCP credentials instead of OIDC

**Workflow Security**:
- `dangerous_event` - pull_request_target, workflow_run events
- `unsafe_checkout` - Checkout with persist-credentials
- `unsafe_checkout_ref` - Potentially unsafe checkout ref
- `potential_script_injection` - Script injection risk
- `code_injection_via_input` - Code injection via workflow inputs
- `unvalidated_workflow_input` - Unvalidated workflow dispatch inputs

**Supply Chain**:
- `untrusted_third_party_action` - Third-party action from untrusted publisher
- `untrusted_action_unpinned` - Untrusted action not pinned
- `unfiltered_network_traffic` - Network operations without filtering
- `no_file_tampering_protection` - File modifications without protection

**Best Practices**:
- `long_artifact_retention` - Artifact retention > 90 days
- `secrets_in_matrix` - Secrets used in matrix strategy
- `large_matrix` - Matrix with > 100 combinations
- `insufficient_audit_logging` - Missing audit logs for sensitive operations
- `branch_protection_bypass` - Workflow bypassing branch protection

## API Endpoints

### `POST /api/audit`
**Request Body**:
```json
{
  "repository": "owner/repo",  // Optional
  "action": "owner/repo@v1",   // Optional
  "github_token": "token",      // Optional
  "use_clone": false            // Optional, default false
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
  "statistics": {
    "total_nodes": 10,
    "total_edges": 15,
    "total_issues": 5,
    "severity_counts": {...},
    "nodes_with_issues": 3
  }
}
```

### `GET /api/analyses`
**Query Parameters**:
- `repository` (optional) - Filter by repository
- `limit` (optional, default 50) - Limit results

**Response**: Array of analysis metadata

### `GET /api/analyses/{id}`
**Response**: Full analysis data including graph

### `DELETE /api/analyses/{id}`
**Response**: `{"status": "deleted"}`

## Dependencies

### Backend (`requirements.txt`)
- `fastapi>=0.115.0` - Web framework
- `uvicorn>=0.32.0` - ASGI server
- `httpx>=0.27.0` - HTTP client
- `pyyaml>=6.0.1` - YAML parsing
- `python-multipart>=0.0.12` - Form data handling
- `pydantic>=2.10.0` - Data validation

### Frontend (`package.json`)
- `react@^18.2.0` - UI framework
- `react-dom@^18.2.0` - React DOM bindings
- `reactflow@^11.10.1` - Graph visualization
- `axios@^1.6.2` - HTTP client (not currently used)
- `vite@^5.0.8` - Build tool
- `@vitejs/plugin-react@^4.2.1` - Vite React plugin

## Configuration

### Environment Variables
- None currently required (GitHub token provided via API)

### Data Directories
- `data/analyses/` - Analysis storage (created automatically)
- `data/clones/` - Temporary repository clones (created automatically)

## Development Scripts

- `setup.sh` - Initial setup (creates venv, installs dependencies)
- `start-backend.sh` - Start backend server
- `start-frontend.sh` - Start frontend dev server
- `start-integrated.sh` - Start both backend and frontend

## Key Design Decisions

1. **Dual Analysis Methods**: Support both GitHub API and local cloning for flexibility
2. **Recursive Dependency Resolution**: Automatically resolve transitive dependencies up to 5 levels deep
3. **Comprehensive Security Checks**: 30+ security checks covering multiple attack vectors
4. **Graph-Based Visualization**: Use ReactFlow for interactive dependency visualization
5. **Persistent Storage**: Save analyses for later review and comparison
6. **Modular Architecture**: Separate concerns (parsing, auditing, graph building, storage)

## Future Enhancements

Potential areas for improvement:
- Real-time analysis progress updates
- Export analysis results (PDF, CSV)
- Comparison between analyses
- Custom security check rules
- Integration with CI/CD pipelines
- Webhook support for automated auditing

