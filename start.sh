#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting GitHub Actions Security Auditor (Integrated Mode)...${NC}\n"

# Build frontend first
echo -e "${GREEN}Building frontend...${NC}"
cd frontend
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install --ignore-scripts
fi
npm run build
cd ..

# Start backend (which will serve the frontend)
echo -e "${GREEN}Starting integrated server...${NC}"
cd backend

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# Install dependencies if needed
uv sync

echo -e "\n${GREEN}✓ Server running on http://localhost:8000${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop${NC}\n"

uv run python main.py

