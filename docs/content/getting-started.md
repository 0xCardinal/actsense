---
title: "Getting Started"
description: "Quick start guide for actsense - GitHub Actions security auditor"
---

## Quick Start

Get started with actsense in minutes. This guide will help you set up and run your first security audit.

### Prerequisites

Before you begin, ensure you have:

- **Python 3.8+** installed
- **Node.js 16+** and npm installed
- **Git** (optional, for repository cloning)

### Installation

#### Option 1: Quick Setup Script

The fastest way to get started:

```bash
./setup.sh
```

This script will:
- Check prerequisites
- Create Python virtual environment
- Install backend dependencies
- Install frontend dependencies
- Create necessary data directories

#### Option 2: Manual Installation

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

### Running actsense

#### Development Mode (Recommended)

Use the integrated development script:

```bash
./start-integrated.sh
```

This will:
- Build the frontend
- Start the backend server on port 8000
- Serve the frontend on port 3000

#### Manual Start

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

### First Audit

1. Open your browser to `http://localhost:3000`
2. Enter a repository (e.g., `actions/checkout`) or action reference (e.g., `actions/checkout@v3`)
3. Optionally provide a GitHub token for higher rate limits
4. Click "Audit" to analyze
5. View results in the interactive graph or table views

### GitHub Token (Optional)

A GitHub Personal Access Token increases rate limits from 60/hour to 5,000/hour.

[Create a token](https://github.com/settings/tokens) with `public_repo` scope (or `repo` for private repos).

### Next Steps

- Explore [vulnerability documentation](/vulnerabilities/) to understand security issues
- Review [installation guide](/installation/) for advanced setup

{{< callout type="info" >}}
**Need help?** Visit our [GitHub repository](https://github.com/0xCardinal/actsense) for issues, discussions, and contributions.
{{< /callout >}}

