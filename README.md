# actsense

A security auditor for GitHub Actions that analyzes workflows and their dependencies to identify security vulnerabilities.

## Features

- 🔍 **Comprehensive Security Auditing**: Detects 30+ security issues in GitHub Actions workflows
- 📊 **Interactive Graph Visualization**: Visualize action dependencies with an interactive graph
- 📋 **Table Views**: View nodes and dependencies in organized table formats
- 🔗 **Transitive Dependency Analysis**: Automatically resolves and audits all action dependencies
- 💾 **Analysis History**: Save and load previous analyses
- 🔐 **Multiple Analysis Methods**: Use GitHub API or clone repositories locally
- 🎨 **Modern UI**: Clean, professional interface built with React

## Security Checks

actsense performs comprehensive security audits including:

### Action Pinning & Immutability
- Unpinned action versions
- Hash pinning (commit SHA) vs tags
- Unpinnable Docker actions (mutable tags)
- Unpinnable composite actions
- Unpinnable JavaScript actions

### Permissions & Access Control
- Overly permissive workflow permissions
- GITHUB_TOKEN write permissions
- Self-hosted runners
- Branch protection bypass

### Secrets & Credentials
- Hardcoded secrets detection
- Optional secret inputs
- Long-term cloud credentials (AWS, Azure, GCP)
- Environment secrets usage

### Workflow Security
- Dangerous workflow events (pull_request_target, workflow_run)
- Unsafe checkout actions
- Script injection vulnerabilities
- Code injection via workflow inputs
- Unvalidated workflow dispatch inputs

### Supply Chain Security
- Untrusted third-party actions
- Unpinned dependencies in Dockerfiles
- External resources without checksums
- Network traffic filtering
- File tampering protection

### Best Practices
- Artifact retention settings
- Matrix strategy security
- Audit logging
- And more...

## Installation

### Quick Setup

Run the setup script to install everything automatically:

```bash
./setup.sh
```

This will:
- Check prerequisites (Python, Node.js, npm, Git)
- Create Python virtual environment
- Install backend dependencies
- Install frontend dependencies
- Create necessary data directories

### Manual Installation

#### Prerequisites

- Python 3.8+
- Node.js 16+
- Git (optional, for repository cloning)

If you prefer to install manually:

1. **Backend:**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. **Frontend:**
```bash
cd frontend
npm install
```

### Running

**Development (integrated):**
```bash
./start-integrated.sh
```

**Or manually:**
```bash
# Terminal 1 - Backend
cd backend && source venv/bin/activate && uvicorn main:app --reload

# Terminal 2 - Frontend
cd frontend && npm run dev
```

Visit `http://localhost:5173` (dev) or `http://localhost:8000` (production)

## Usage

1. Enter a repository (e.g., `actions/checkout`) or action reference (e.g., `actions/checkout@v3`)
2. Optionally provide a GitHub token for higher rate limits
3. Click "Audit" to analyze
4. View results in the interactive graph or table views
5. Click any node to see detailed security issues

## GitHub Token (Optional)

A GitHub Personal Access Token increases rate limits from 60/hour to 5,000/hour.

[Create a token](https://github.com/settings/tokens) with `public_repo` scope (or `repo` for private repos).

## Security Checks

actsense detects issues including:
- Unpinned action versions
- Hardcoded secrets
- Overly permissive permissions
- Unpinnable actions (Docker, composite, JavaScript)
- Script injection vulnerabilities
- Untrusted third-party actions
- And 20+ more security issues

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for technical details, API documentation, and development guidelines.

## License

MIT License
