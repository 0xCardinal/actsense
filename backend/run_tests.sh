#!/bin/bash

# Test runner script for GitHub Actions Security Auditor

set -e

cd "$(dirname "$0")"

echo "🔍 Running tests for GitHub Actions Security Auditor"
echo ""

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Creating..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Activate venv
echo "📦 Activating virtual environment..."
source venv/bin/activate

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "📥 Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# Install/upgrade dependencies
echo "📥 Installing dependencies..."
uv sync

# Run tests
echo ""
echo "🧪 Running tests..."
echo ""

if [ "$1" == "--verbose" ] || [ "$1" == "-v" ]; then
    uv run pytest tests/ -v
elif [ "$1" == "--coverage" ] || [ "$1" == "-c" ]; then
    uv run pytest tests/ --cov=. --cov-report=term-missing
elif [ -n "$1" ]; then
    uv run pytest tests/ -v -k "$1"
else
    uv run pytest tests/ -v --tb=short
fi

echo ""
echo "✅ Tests completed!"


