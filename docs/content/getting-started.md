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

## Next Steps

- Explore [vulnerability documentation](/vulnerabilities/) to understand security issues
- Check out the [usage guide](/usage/) to learn about all features
- Review [installation guide](/installation/) for advanced setup

{{< callout type="info" >}}
**Need help?** Visit our [GitHub repository](https://github.com/0xCardinal/actsense) for issues, discussions, and contributions.
{{< /callout >}}
