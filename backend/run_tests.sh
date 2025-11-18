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

# Install/upgrade dependencies
echo "📥 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Run tests
echo ""
echo "🧪 Running tests..."
echo ""

if [ "$1" == "--verbose" ] || [ "$1" == "-v" ]; then
    python -m pytest tests/ -v
elif [ "$1" == "--coverage" ] || [ "$1" == "-c" ]; then
    pip install -q pytest-cov
    python -m pytest tests/ --cov=. --cov-report=term-missing
elif [ -n "$1" ]; then
    python -m pytest tests/ -v -k "$1"
else
    python -m pytest tests/ -v --tb=short
fi

echo ""
echo "✅ Tests completed!"


