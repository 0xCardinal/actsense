# GitHub Actions Security Auditor

A comprehensive security auditing tool for GitHub Actions that analyzes workflows and their transitive dependencies, identifying security issues and visualizing the action dependency graph.

## Features

- 🔍 **Repository Auditing**: Analyze all workflows in a GitHub repository
- 🔗 **Action Dependency Resolution**: Recursively resolve and audit transitive action dependencies
- 🛡️ **Security Checks**:
  - Unpinned action versions
  - Overly permissive permissions
  - Potential hardcoded secrets
  - Self-hosted runner usage
  - Optional secret inputs
- 📊 **Interactive Graph Visualization**: Visual representation of action dependencies with security issue highlighting
- 📈 **Statistics Dashboard**: Overview of security issues by severity

## Architecture

- **Backend**: Python with FastAPI
- **Frontend**: React with Vite and React Flow for graph visualization

## Setup

### Quick Start (Recommended)

**Option 1: Run both servers together (Development)**
```bash
./start.sh
```
This starts both backend (port 8000) and frontend (port 3000) servers. Open `http://localhost:3000` in your browser.

**Option 2: Integrated mode (Production-like)**
```bash
./start-integrated.sh
```
This builds the frontend and serves it from the Python backend. Everything runs on `http://localhost:8000`.

### Manual Setup

#### Backend

1. Navigate to the backend directory:
```bash
cd backend
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the server:
```bash
python main.py
```

The API will be available at `http://localhost:8000`

#### Frontend

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install --ignore-scripts
```

3. Start the development server:
```bash
npm run dev
```

The frontend will be available at `http://localhost:3000`

## Usage

1. Open the frontend in your browser
2. Enter either:
   - A repository in the format `owner/repo` (e.g., `actions/checkout`)
   - An action reference in the format `owner/repo@version` (e.g., `actions/checkout@v3`)
3. Optionally provide a GitHub token for private repositories or higher rate limits
4. Click "Audit" to analyze
5. View the interactive graph and security issues

## API Endpoints

### POST `/api/audit`

Audit a repository or action.

**Request Body:**
```json
{
  "repository": "owner/repo",  // Optional
  "action": "owner/repo@v1",   // Optional
  "github_token": "ghp_..."    // Optional
}
```

**Response:**
```json
{
  "graph": {
    "nodes": [...],
    "edges": [...],
    "issues": {...}
  },
  "statistics": {
    "total_nodes": 10,
    "total_edges": 15,
    "total_issues": 5,
    "severity_counts": {
      "high": 3,
      "medium": 2
    }
  }
}
```

## Security Checks

The auditor checks for:

1. **Unpinned Versions**: Actions using branch references instead of tags or SHAs
2. **Overly Permissive Permissions**: Workflows with write access to contents or actions
3. **Hardcoded Secrets**: Potential secrets in workflow files
4. **Self-Hosted Runners**: Usage of self-hosted runners (potential security risk)
5. **Optional Secret Inputs**: Actions with optional secret inputs

## Graph Visualization

- **Nodes**: Represent repositories, workflows, and actions
- **Edges**: Show dependencies between actions
- **Colors**: Indicate security severity:
  - 🔴 Red: Critical issues
  - 🟠 Orange: High severity
  - 🟡 Yellow: Medium severity
  - 🟢 Green: Safe
- **Badges**: Show the number of issues per node
- **Click**: Click on nodes to see detailed security issues

## Limitations

- Rate limiting: GitHub API has rate limits (60 requests/hour without token, 5000/hour with token)
- Depth limit: Dependency resolution is limited to 5 levels deep by default
- Public repos only: Without a token, only public repositories can be accessed

## License

MIT

