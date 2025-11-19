---
title: "Installation"
description: "Detailed installation guide for actsense"
---

## Installation Guide

This guide covers detailed installation instructions for actsense on different platforms and configurations.

### System Requirements

- **Python**: 3.8 or higher
- **Node.js**: 16.0 or higher
- **npm**: Comes with Node.js
- **Git**: Optional, for repository cloning features
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

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

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
./start-integrated.sh
```

**Manual Start:**
```bash
# Terminal 1 - Backend
cd backend
source venv/bin/activate
uvicorn main:app --reload --port 8000

# Terminal 2 - Frontend
cd frontend
npm run dev
```

#### Production Mode

**Backend:**
```bash
cd backend
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000
```

**Frontend:**
```bash
cd frontend
npm run build
# Serve the dist/ directory with a web server
```

### Docker Installation (Coming Soon)

Docker installation will be available in a future release.

### Troubleshooting

#### Python Issues

**Problem:** `python3: command not found`

**Solution:**
- macOS: Install via Homebrew: `brew install python3`
- Linux: `sudo apt-get install python3 python3-pip`
- Windows: Download from [python.org](https://www.python.org/downloads/)

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

#### Virtual Environment Issues

**Problem:** `venv` module not found

**Solution:**
```bash
# Install venv
python3 -m pip install --user virtualenv
```

### Verification

To verify your installation:

1. Start the backend: `cd backend && source venv/bin/activate && uvicorn main:app`
2. Visit `http://localhost:8000/docs` - you should see the API documentation
3. Start the frontend: `cd frontend && npm run dev`
4. Visit `http://localhost:3000` - you should see the actsense interface

### Next Steps

- Read the [Getting Started](/getting-started/) guide
- Explore [vulnerability documentation](/vulnerabilities/)

{{< callout type="warning" >}}
**Security Note:** Never commit your GitHub token to version control. Always use environment variables or secure storage.
{{< /callout >}}

