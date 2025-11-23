---
title: "Installation"
description: "Detailed installation guide for actsense"
---

## Installation Guide

This guide covers detailed installation instructions for actsense on different platforms and configurations.

### System Requirements

- **Python**: 3.12 or higher
- **Node.js**: 20.0 or higher
- **npm**: Comes with Node.js
- **Git**: Required for repository cloning features
- **uv**: Python package manager (installed automatically by setup script)
- **Operating System**: macOS, Linux, or Windows

### Installation Methods

#### Method 1: Automated Setup (Recommended)

The setup script handles everything automatically:

```bash
chmod +x setup.sh
./setup.sh
```

#### Method 2: Manual Installation

**Step 1: Clone the Repository**

```bash
git clone https://github.com/0xCardinal/actsense.git
cd actsense
```

**Step 2: Backend Setup**

```bash
cd backend

# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.cargo/bin:$PATH"

# Install dependencies using uv
uv sync
```

**Note:** `uv` is a fast Python package manager that handles dependency locking automatically. The project uses `pyproject.toml` and `uv.lock` for reproducible builds.

**Step 3: Frontend Setup**

```bash
cd ../frontend

# Install dependencies
npm install
```

**Step 4: Create Data Directories**

```bash
cd ..
mkdir -p data/analyses
mkdir -p data/clones
```

### Configuration

#### GitHub Token Setup

For higher rate limits, create a GitHub Personal Access Token:

1. Go to [GitHub Settings > Developer settings > Personal access tokens](https://github.com/settings/tokens)
2. Click "Generate new token (classic)"
3. Select scopes:
   - `public_repo` (for public repositories)
   - `repo` (for private repositories)
4. Copy the token
5. Use it when prompted in the actsense interface

#### Environment Variables

Create a `.env` file in the backend directory (optional):

```bash
cd backend
cat > .env << EOF
GITHUB_TOKEN=your_token_here
EOF
```

### Running actsense

#### Development Mode

**Integrated Script:**
```bash
./start.sh
```

**Manual Start:**
```bash
# Terminal 1 - Backend
cd backend
uv run uvicorn main:app --reload --port 8000

# Terminal 2 - Frontend
cd frontend
npm run dev
```

**Note:** With `uv`, you don't need to activate a virtual environment. `uv run` automatically manages the environment.

#### Production Mode

**Backend:**
```bash
cd backend
uv run uvicorn main:app --host 0.0.0.0 --port 8000
```

**Frontend:**
```bash
cd frontend
npm run build
# The backend will automatically serve the built frontend from frontend/dist
```

### Docker Installation

Docker installation is available and recommended for production use:

```bash
docker compose up --build
```

Or with a GitHub token:

```bash
GITHUB_TOKEN=ghp_your_token_here docker compose up --build
```

The Docker image uses `uv` for fast, reproducible dependency installation.

### Troubleshooting

#### Python Issues

**Problem:** `python3: command not found` or Python version too old

**Solution:**
- macOS: Install via Homebrew: `brew install python@3.12`
- Linux: `sudo apt-get install python3.12 python3.12-venv`
- Windows: Download Python 3.12+ from [python.org](https://www.python.org/downloads/)

**Problem:** `uv: command not found`

**Solution:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.cargo/bin:$PATH"
```

#### Node.js Issues

**Problem:** `npm: command not found`

**Solution:**
- Install Node.js from [nodejs.org](https://nodejs.org/)
- Or use a version manager like `nvm`

#### Port Already in Use

**Problem:** Port 8000 or 3000 is already in use

**Solution:**
```bash
# Change backend port
uvicorn main:app --port 8001

# Change frontend port (edit vite.config.js)
```

#### uv Issues

**Problem:** `uv sync` fails or dependencies not installing

**Solution:**
```bash
# Ensure you're in the backend directory
cd backend

# Clear uv cache and reinstall
uv cache clean
uv sync

# If issues persist, check Python version
python3 --version  # Should be 3.12 or higher
```

### Verification

To verify your installation:

1. Start the backend: `cd backend && uv run uvicorn main:app`
2. Visit `http://localhost:8000/docs` - you should see the API documentation
3. Start the frontend: `cd frontend && npm run dev`
4. Visit `http://localhost:3000` - you should see the actsense interface

Or use the integrated script:
```bash
./start.sh
```
Then visit `http://localhost:8000` - the backend serves the built frontend.

### Next Steps

- Read the [Getting Started](/getting-started/) guide
- Explore [vulnerability documentation](/vulnerabilities/)

{{< callout type="warning" >}}
**Security Note:** Never commit your GitHub token to version control. Always use environment variables or secure storage.
{{< /callout >}}

