# actsense
<img width="1484" height="917" alt="image" src="https://github.com/user-attachments/assets/f83358db-abf2-4da9-97a5-4f7fbac98773" />


A security auditor for GitHub Actions that analyzes workflows and their dependencies to identify security vulnerabilities.

## Features

- 🔍 **Comprehensive Security Auditing**: Detects 30+ security issues in GitHub Actions workflows
- 📊 **Interactive Graph Visualization**: Visualize action dependencies with an interactive graph
- 🔎 **Powerful Search**: Search security issues and assets with natural language queries (Cmd+K / Ctrl+K)
- 📋 **Table Views**: View nodes and dependencies in organized table formats
- 🔗 **Transitive Dependency Analysis**: Automatically resolves and audits all action dependencies
- 💾 **Analysis History**: Save and load previous analyses
- 🔐 **Multiple Analysis Methods**: Use GitHub API or clone repositories locally
- 📖 **Detailed Issue Documentation**: Each vulnerability links to comprehensive documentation on actsense.dev
- 🎨 **Modern UI**: Clean, professional interface built with React

## Security Checks

actsense performs comprehensive security audits including:

### Action Pinning & Immutability
- Unpinned action versions
- Hash pinning (commit SHA) vs tags
- Older action versions (tags and commit hashes)
- Inconsistent action versions across workflows
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

### Docker (recommended)

Build and run the bundled backend + frontend container:

```bash
docker compose up --build
```

Then visit `http://localhost:8000`. The `./data` directory is mounted into the container so saved analyses persist, and you can pass a GitHub token for higher API limits:

```bash
GITHUB_TOKEN=ghp_example docker compose up --build
```

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

Visit `http://localhost:3000` (dev) or `http://localhost:8000` (production)

## Usage

1. Enter a repository (e.g., `actions/checkout`) or action reference (e.g., `actions/checkout@v3`)
2. Optionally provide a GitHub token for higher rate limits
3. Click "Audit" to analyze
4. View results in the interactive graph or table views
5. Click any node to see detailed security issues
6. Use **Cmd+K** (Mac) or **Ctrl+K** (Windows/Linux) to search for issues and assets
7. Click on any security issue to view detailed information, evidence, and mitigation strategies

## GitHub Token (Optional)

A GitHub Personal Access Token increases rate limits from 60/hour to 5,000/hour.

[Create a token](https://github.com/settings/tokens) with `public_repo` scope (or `repo` for private repos).

## Security Checks

actsense detects issues including:
- Unpinned action versions
- Older action versions (checks against latest from GitHub)
- Inconsistent action versions across workflows
- Hardcoded secrets
- Overly permissive permissions
- Unpinnable actions (Docker, composite, JavaScript)
- Script injection vulnerabilities
- Untrusted third-party actions
- And 30+ more security issues

## Configuration

### Trusted Action Publishers

By default, actsense flags actions from unknown publishers when secrets are passed to them. You can configure which publishers are trusted by editing `backend/config.yaml`.

**To add a trusted publisher:**

1. Open `backend/config.yaml`
2. Add the publisher prefix to the `trusted_publishers` list:

```yaml
trusted_publishers:
  - "actions/"
  - "github/"
  # ... existing publishers ...
  - "your-org/"
```

3. Restart the application

**Example:** To trust `0xCardinal/Publish-Docker-Github-Action@v5`, add `"0xCardinal/"` to the list. This will trust all actions from the `0xCardinal` organization.

## Documentation

### Vulnerability Documentation

Each security issue detected by actsense includes:
- **Title and Description**: Clear explanation of the vulnerability
- **Evidence**: Specific details about where and how the issue was found
- **Mitigation Strategy**: Step-by-step guidance on how to fix the issue
- **External Reference**: Links to comprehensive documentation on [actsense.dev](https://actsense.dev)

All vulnerability documentation is available at `docs/content/vulnerabilities/` and hosted on [actsense.dev](https://actsense.dev/vulnerabilities).

## Testing

The project includes a comprehensive test suite for all security checks:

```bash
cd backend
source venv/bin/activate
pytest
```

Or use the convenience script:

```bash
./backend/run_tests.sh
```

See `backend/tests/README.md` for more details on the test suite.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for technical details, API documentation, and development guidelines.
