#!/bin/bash
# Development environment setup script

set -e

echo "=========================================="
echo "AI Threat Hunting Simulator - Dev Setup"
echo "=========================================="
echo ""

# Check Python version
echo "Checking Python version..."
python3 --version

if [ $? -ne 0 ]; then
    echo "Error: Python 3.11+ is required"
    exit 1
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
echo "✓ Python dependencies installed"

# Create output directories
echo ""
echo "Creating output directories..."
mkdir -p output/scenarios
mkdir -p output/reports
mkdir -p output/telemetry
echo "✓ Output directories created"

# Set up pre-commit hooks (if available)
if command -v pre-commit &> /dev/null; then
    echo ""
    echo "Setting up pre-commit hooks..."
    pre-commit install
    echo "✓ Pre-commit hooks installed"
fi

echo ""
echo "=========================================="
echo "✓ Development environment ready!"
echo "=========================================="
echo ""
echo "To activate the environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To run a scenario:"
echo "  python cli/run_scenario.py --scenario iam_priv_escalation --output ./output/test"
echo ""
echo "To start the API server:"
echo "  python -m uvicorn analysis_engine.api.server:app --reload"
echo ""
