---
title: "Getting Started"
description: "Quick start guide for actsense - GitHub Actions security auditor"
---

## Quick Start

Get started with actsense in minutes. This guide will help you set up and run your first security audit.

### Prerequisites

Before you begin, ensure you have:

- **Docker and Docker Compose** (for Docker installation) OR
- **Python 3.12+** installed (for manual installation)
- **Node.js 16+** and npm installed (for manual installation)
- **Git** (optional, for repository cloning)
- **just** (optional but recommended for one-command local workflows)

## Installation

### Option 1: Docker (Recommended) 🐳

The easiest way to get started with actsense is using Docker. This method bundles both the backend and frontend into a single container.

**Quick Start:**

```bash
docker compose up --build
```

Then visit `http://localhost:8000` in your browser.

**With GitHub Token (for higher rate limits):**

```bash
GITHUB_TOKEN=ghp_your_token_here docker compose up --build
```

**What Docker provides:**
- ✅ No need to install Python or Node.js locally
- ✅ All dependencies pre-configured
- ✅ Consistent environment across different systems
- ✅ Data persistence (saved analyses stored in `./data` directory)
- ✅ Easy updates (just rebuild the container)

**Stopping the container:**
```bash
docker compose down
```

**Viewing logs:**
```bash
docker compose logs -f
```

### Option 2: Quick Setup Script

If you prefer to run actsense locally without Docker:

```bash
./setup.sh
```

This script will:
- Check prerequisites (Python, Node.js, npm, Git)
- Create Python virtual environment
- Install backend dependencies
- Install frontend dependencies
- Create necessary data directories

### Option 3: Manual Installation

**Backend Setup:**

```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Frontend Setup:**

```bash
cd frontend
npm install
```

## Running actsense

### Docker (Recommended)

If you installed using Docker:

```bash
docker compose up
```

The application will be available at `http://localhost:8000`.

### Using Just (Recommended Local Commands)

If you have [`just`](https://github.com/casey/just) installed, you can use the project recipes instead of remembering multiple commands:

```bash
just up
```

This starts both:
- actsense containers (`docker compose up -d --build` - http://localhost:8000)
- docs server (`http://localhost:1313`)

Useful companion commands:

```bash
just status
just down
```

### Development Mode (Local Installation)

Use the integrated development script:

```bash
./start.sh
```

This will:
- Build the frontend
- Start the backend server on port 8000
- Serve the frontend on port 3000

### Manual Start (Local Installation)

**Terminal 1 - Backend:**
```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

## First Audit

1. Open your browser to:
   - `http://localhost:8000` (Docker or production)
   - `http://localhost:3000` (development mode)
2. Enter a repository (e.g., `actions/checkout`) or action reference (e.g., `actions/checkout@v3`)
3. Optionally provide a GitHub token for higher rate limits
4. Click "Audit" to analyze
5. View results in the interactive graph or table views

## GitHub Token (Optional)

A GitHub Personal Access Token increases rate limits from 60/hour to 5,000/hour.

[Create a token](https://github.com/settings/tokens) with `public_repo` scope (or `repo` for private repos).

**For Docker:**
```bash
GITHUB_TOKEN=ghp_your_token_here docker compose up
```

**For Local Installation:**
Enter the token in the web interface when prompted, or set it as an environment variable.

## API and automation

The full **HTTP API** (routes, request and response models, and schemas) is on **[API Reference](/api-reference/)** — that page is the single source for endpoint details. When the app is running, you can also use `GET /openapi.json`, `GET /docs` (Swagger UI), and `GET /redoc` on the same base URL (for example `http://localhost:8000`).

### Trigger a scan via the API

The primary endpoint is **`POST /api/audit`**. Send JSON with either a **`repository`** or an **`action`** (one of the two audit modes).

| Field | Type | Description |
| --- | --- | --- |
| `repository` | string (optional) | `owner/repo` or a `https://github.com/...` URL (github.com only). |
| `action` | string (optional) | A single action reference, e.g. `actions/checkout@v4`. |
| `github_token` | string (optional) | GitHub PAT for private repositories or higher rate limits. |
| `use_clone` | boolean (optional) | If `true`, workflows are loaded by **cloning** the repo instead of the GitHub API. For private repos, also set **`GITHUB_TOKEN`** in the server environment (e.g. Docker) or pass `github_token` in the body. |

Either `repository` or `action` must be present (not both required for every call, but one of them is needed to start an audit).

**Examples** (local default: `http://localhost:8000`):

```bash
# Scan a public repository (GitHub API mode)
curl -sS -X POST http://localhost:8000/api/audit \
  -H "Content-Type: application/json" \
  -d '{"repository":"octocat/Hello-World"}'
```

```bash
# Scan with a token and clone mode
curl -sS -X POST http://localhost:8000/api/audit \
  -H "Content-Type: application/json" \
  -d '{"repository":"owner/private-repo","github_token":"ghp_XXX","use_clone":true}'
```

```bash
# Audit a single action and its dependencies
curl -sS -X POST http://localhost:8000/api/audit \
  -H "Content-Type: application/json" \
  -d '{"action":"actions/checkout@v4"}'
```

**Streaming** (progress log lines as Server-Sent Events): use **`POST /api/audit/stream`** with the same JSON body as `/api/audit`.

**Other routes** (e.g. analyses, YAML audit, fix suggestions) are listed in the [API Reference](/api-reference/).

### Whitelist a GitHub Actions publisher

Some rules (for example **untrusted third-party actions** and **secrets passed to untrusted actions**) compare the **owner** part of `uses: owner/repo@ref` against a configurable list.

1. Edit **`backend/config.yaml`** and add an entry under **`trusted_publishers`**, using the **organization or user name** plus a slash, for example:

   ```yaml
   trusted_publishers:
     # ...existing entries...
     - "my-org/"
   ```

2. **Restart** the actsense API (or rebuild/restart the Docker container) so the list is reloaded.

3. Optionally set environment variable **`TRUSTED_PUBLISHERS_CONFIG`** to the absolute path of a different YAML file if you do not want to edit the copy inside the repo.

Whitelisting applies to the **publisher** (the `owner` in `owner/repo@ref`), not to a single tag or commit. Other checks (unpinned actions, hash pinning, etc.) are separate.

## Next Steps

- Explore [vulnerability documentation](/vulnerabilities/) to understand security issues
- Check out the [usage guide](/usage/) for the full platform (graphs, search, editor, and more)
- Review [installation guide](/installation/) for advanced setup

{{< callout type="info" >}}
**Need help?** Visit our [GitHub repository](https://github.com/0xCardinal/actsense) for issues, discussions, and contributions.
{{< /callout >}}
