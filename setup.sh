#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
print_status "Checking prerequisites..."

# Check Python
if ! command_exists python3; then
    print_error "Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
print_success "Python $PYTHON_VERSION found"

# Check Node.js
if ! command_exists node; then
    print_error "Node.js is not installed. Please install Node.js 16 or higher."
    exit 1
fi

NODE_VERSION=$(node --version)
print_success "Node.js $NODE_VERSION found"

# Check npm
if ! command_exists npm; then
    print_error "npm is not installed. Please install npm."
    exit 1
fi

NPM_VERSION=$(npm --version)
print_success "npm $NPM_VERSION found"

# Check Git (optional but recommended)
if command_exists git; then
    GIT_VERSION=$(git --version | awk '{print $3}')
    print_success "Git $GIT_VERSION found"
else
    print_warning "Git is not installed. Repository cloning feature will not work."
fi

echo ""

# Setup Backend
print_status "Setting up backend..."

cd backend || exit 1

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    print_status "Creating Python virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        print_error "Failed to create virtual environment"
        exit 1
    fi
    print_success "Virtual environment created"
else
    print_status "Virtual environment already exists"
fi

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Check if uv is installed, install if not
if ! command -v uv &> /dev/null; then
    print_status "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# Install Python dependencies using uv
print_status "Installing Python dependencies with uv..."
cd backend
uv sync

if [ $? -ne 0 ]; then
    print_error "Failed to install Python dependencies"
    exit 1
fi
cd ..

print_success "Backend setup complete"
deactivate

cd ..

echo ""

# Setup Frontend
print_status "Setting up frontend..."

cd frontend || exit 1

# Install npm dependencies
if [ ! -d "node_modules" ]; then
    print_status "Installing npm dependencies (this may take a few minutes)..."
    npm install --ignore-scripts --silent
    
    if [ $? -ne 0 ]; then
        print_error "Failed to install npm dependencies"
        exit 1
    fi
    print_success "npm dependencies installed"
else
    print_status "npm dependencies already installed"
fi

cd ..

echo ""

# Create data directories
print_status "Creating data directories..."
mkdir -p data/analyses
mkdir -p data/clones
print_success "Data directories created"

echo ""

# Summary
print_success "Setup complete! 🎉"
echo ""
print_status "Next steps:"
echo "  1. Run './start.sh' to start the application"
echo "  2. Or run backend and frontend separately:"
echo "     - Backend: cd backend && source venv/bin/activate && uvicorn main:app --reload"
echo "     - Frontend: cd frontend && npm run dev"
echo ""
print_status "The application will be available at:"
echo "  - Development: http://localhost:5173 (frontend) and http://localhost:8000 (backend)"
echo "  - Production: http://localhost:8000 (integrated)"
echo ""

