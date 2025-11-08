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
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -r requirements.txt
fi

echo -e "\n${GREEN}✓ Server running on http://localhost:8000${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop${NC}\n"

./venv/bin/python main.py

