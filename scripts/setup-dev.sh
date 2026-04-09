#!/usr/bin/env bash
# Dev Environment Bootstrap
set -euo pipefail

echo "🚀 Setting up Diamond Citadel development environment..."

# Check Python version
python3 --version | grep -q "3.12" || { echo "❌ Python 3.12+ required"; exit 1; }

# Install uv if not present
if ! command -v uv &> /dev/null; then
    echo "📦 Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi

# Sync workspace
echo "📦 Installing dependencies..."
uv sync --all-packages

echo "✅ Development environment ready!"
echo "Run 'make dev' to start the development environment."
