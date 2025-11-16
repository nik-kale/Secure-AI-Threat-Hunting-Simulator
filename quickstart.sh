#!/bin/bash
#
# AI Threat Hunting Simulator - Quick Start Script
#
# This script helps you get started quickly by:
# 1. Checking prerequisites
# 2. Setting up the environment
# 3. Running a demo scenario
# 4. Launching the SOC Dashboard
#

set -e  # Exit on error

# Colors for output
RED='\033[0.31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print with color
print_green() { echo -e "${GREEN}$1${NC}"; }
print_yellow() { echo -e "${YELLOW}$1${NC}"; }
print_red() { echo -e "${RED}$1${NC}"; }
print_blue() { echo -e "${BLUE}$1${NC}"; }

# Banner
echo ""
print_blue "╔══════════════════════════════════════════════════════════╗"
print_blue "║   AI Threat Hunting Simulator - Quick Start             ║"
print_blue "╚══════════════════════════════════════════════════════════╝"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
print_yellow "Checking prerequisites..."
echo ""

# Check Docker
if command_exists docker; then
    print_green "✓ Docker found: $(docker --version)"
else
    print_red "✗ Docker not found. Please install Docker first:"
    print_red "  https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Docker Compose
if command_exists docker-compose || docker compose version >/dev/null 2>&1; then
    print_green "✓ Docker Compose found"
else
    print_red "✗ Docker Compose not found. Please install Docker Compose:"
    print_red "  https://docs.docker.com/compose/install/"
    exit 1
fi

# Check Python (optional)
if command_exists python3; then
    print_green "✓ Python found: $(python3 --version)"
    HAS_PYTHON=true
else
    print_yellow "⚠ Python not found (optional for CLI usage)"
    HAS_PYTHON=false
fi

echo ""
print_green "All prerequisites met!"
echo ""

# Setup environment
print_yellow "Setting up environment..."
echo ""

if [ ! -f .env ]; then
    print_yellow "Creating .env file from template..."
    cp .env.example .env
    print_green "✓ Created .env file (you can customize it later)"
else
    print_green "✓ .env file already exists"
fi

# Create necessary directories
mkdir -p ./output
mkdir -p ./data
print_green "✓ Created output directories"

echo ""
print_green "Environment setup complete!"
echo ""

# Ask user what they want to do
print_blue "What would you like to do?"
echo ""
echo "  1) Run demo scenario with Docker (recommended)"
echo "  2) Start all services with Docker Compose"
echo "  3) Generate scenario locally with Python CLI"
echo "  4) View available scenarios"
echo "  5) Exit"
echo ""
read -p "Enter choice [1-5]: " choice

case $choice in
    1)
        print_yellow ""
        print_yellow "Running demo IAM Privilege Escalation scenario..."
        echo ""

        # Check if Docker images are built
        if ! docker images | grep -q "ai-threat-hunting-simulator"; then
            print_yellow "Building Docker images (this may take a few minutes)..."
            docker-compose build
            print_green "✓ Docker images built"
        fi

        # Run demo scenario
        print_yellow "Generating synthetic attack telemetry..."
        docker-compose run --rm generator python -m generator.attack_traces.iam_priv_escalation.generator

        print_green "✓ Scenario generated!"
        print_yellow ""
        print_yellow "Analyzing telemetry..."
        docker-compose run --rm analysis-engine python cli/analyze.py ./output/iam_priv_escalation/telemetry.jsonl

        print_green "✓ Analysis complete!"
        echo ""
        print_blue "Results saved to: ./output/iam_priv_escalation/"
        print_blue "  - telemetry.jsonl (synthetic logs)"
        print_blue "  - analysis_report.json (structured results)"
        print_blue "  - analysis_report.md (human-readable)"
        echo ""
        print_yellow "To view in SOC Dashboard, run: docker-compose up"
        ;;

    2)
        print_yellow ""
        print_yellow "Starting all services..."
        echo ""
        print_blue "This will start:"
        print_blue "  - Analysis Engine API on http://localhost:8000"
        print_blue "  - SOC Dashboard UI on http://localhost:3000"
        print_blue "  - Database (PostgreSQL)"
        echo ""
        print_yellow "Building images (first time only)..."
        docker-compose up --build
        ;;

    3)
        if [ "$HAS_PYTHON" = false ]; then
            print_red "Python is required for local CLI usage."
            print_yellow "Please use Docker option instead (choice 1 or 2)"
            exit 1
        fi

        print_yellow ""
        print_yellow "Installing Python dependencies..."
        python3 -m pip install -r requirements.txt

        echo ""
        print_blue "Available scenarios:"
        echo "  - iam_priv_escalation"
        echo "  - container_escape"
        echo "  - cred_stuffing"
        echo "  - lateral_movement"
        echo "  - data_exfiltration"
        echo "  - supply_chain"
        echo ""
        read -p "Enter scenario name: " scenario_name

        print_yellow ""
        print_yellow "Generating scenario: $scenario_name..."
        python3 cli/run_scenario.py --scenario "$scenario_name" --output "./output/${scenario_name}_demo"

        print_green "✓ Scenario generated!"
        print_blue "Results saved to: ./output/${scenario_name}_demo/"
        ;;

    4)
        print_blue ""
        print_blue "═══════════════════════════════════════════════════════"
        print_blue "Available Attack Scenarios"
        print_blue "═══════════════════════════════════════════════════════"
        echo ""

        echo "1. IAM Privilege Escalation"
        echo "   MITRE: T1078.004, T1548.005, T1136.003"
        echo "   Description: PassRole exploitation via Lambda function"
        echo "   Events: ~31 | Duration: 1 hour | Difficulty: Medium"
        echo ""

        echo "2. Container Escape"
        echo "   MITRE: T1611, T1068"
        echo "   Description: Escape from containerized workload"
        echo "   Events: ~33 | Duration: 1.5 hours | Difficulty: Hard"
        echo ""

        echo "3. Credential Stuffing"
        echo "   MITRE: T1110.004, T1078.004"
        echo "   Description: Automated credential attacks against APIs"
        echo "   Events: ~105 | Duration: 2 hours | Difficulty: Easy"
        echo ""

        echo "4. Lateral Movement"
        echo "   MITRE: T1078, T1552"
        echo "   Description: Multi-hop pivoting through cloud resources"
        echo "   Events: ~48 | Duration: 2 hours | Difficulty: Medium"
        echo ""

        echo "5. Data Exfiltration"
        echo "   MITRE: T1530, T1537"
        echo "   Description: Sensitive data theft from cloud storage"
        echo "   Events: ~57 | Duration: 1.5 hours | Difficulty: Medium"
        echo ""

        echo "6. Supply Chain Attack"
        echo "   MITRE: T1195, T1525"
        echo "   Description: CI/CD pipeline compromise"
        echo "   Events: ~57 | Duration: 2 hours | Difficulty: Hard"
        echo ""
        ;;

    5)
        print_blue "Goodbye!"
        exit 0
        ;;

    *)
        print_red "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
print_green "═══════════════════════════════════════════════════════"
print_green "Quick Start Complete!"
print_green "═══════════════════════════════════════════════════════"
echo ""
print_blue "Next steps:"
echo ""
echo "  • View documentation: cat README.md"
echo "  • Explore scenarios: ls -la ./output/"
echo "  • Launch SOC Dashboard: docker-compose up"
echo "  • Access API docs: http://localhost:8000/docs"
echo "  • Read deployment guide: cat DEPLOYMENT.md"
echo ""
print_yellow "For LLM-powered analysis, edit .env and add:"
print_yellow "  LLM_PROVIDER=openai"
print_yellow "  OPENAI_API_KEY=sk-..."
echo ""
print_blue "Happy threat hunting! 🛡️"
echo ""
