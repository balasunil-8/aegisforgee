#!/bin/bash
# AegisForge Linux/Mac Installer
# Automated installation and setup script
# Version 2.0

set -e  # Exit on error

echo ""
echo "========================================"
echo "   AegisForge Linux/Mac Installer v2.0"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "[1/7] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} Python 3 is not installed"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info[0])')
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info[1])')

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo -e "${RED}[ERROR]${NC} Python 3.8 or higher is required"
    echo "Current version: $PYTHON_VERSION"
    echo "Please upgrade Python"
    exit 1
fi

echo "Python $PYTHON_VERSION"
echo -e "${GREEN}[OK]${NC} Python version check passed"
echo ""

# Check disk space (require at least 3GB)
echo "[2/7] Checking disk space..."
AVAILABLE_SPACE=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$AVAILABLE_SPACE" -lt 3 ]; then
    echo -e "${YELLOW}[WARNING]${NC} Low disk space detected"
    echo "At least 3GB free space recommended"
fi
echo -e "${GREEN}[OK]${NC} Sufficient disk space available"
echo ""

# Check if virtual environment exists
echo "[3/7] Setting up virtual environment..."
if [ -d ".venv" ]; then
    echo "[INFO] Virtual environment already exists"
else
    echo "Creating virtual environment..."
    python3 -m venv .venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} Failed to create virtual environment"
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} Virtual environment created"
fi
echo ""

# Activate virtual environment
echo "[4/7] Activating virtual environment..."
source .venv/bin/activate
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Failed to activate virtual environment"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Virtual environment activated"
echo ""

# Install dependencies
echo "[5/7] Installing dependencies from requirements.txt..."
echo "This may take 2-5 minutes..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Failed to install dependencies"
    echo "Try running: pip install -r requirements.txt manually"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} All dependencies installed successfully"
echo ""

# Initialize databases
echo "[6/7] Initializing databases..."
echo ""
echo "[6.1/7] Initializing SecureBank database..."
python backend/apps/securebank/database.py
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[WARNING]${NC} SecureBank database initialization failed"
else
    echo -e "${GREEN}[OK]${NC} SecureBank database initialized"
fi
echo ""

echo "[6.2/7] Initializing ShopVuln database..."
python backend/apps/shopvuln/database.py
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[WARNING]${NC} ShopVuln database initialization failed"
else
    echo -e "${GREEN}[OK]${NC} ShopVuln database initialized"
fi
echo ""

# Seed database data
echo "[6.3/7] Seeding database with test data..."
python backend/apps/securebank/seed_data.py > /dev/null 2>&1
python backend/apps/shopvuln/seed_data.py > /dev/null 2>&1
echo -e "${GREEN}[OK]${NC} Test data seeded"
echo ""

# Run health check
echo "[7/7] Running system health check..."
python scripts/python/health_check.py
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[WARNING]${NC} Some health checks failed"
    echo "You can still proceed, but some features may not work"
else
    echo -e "${GREEN}[OK]${NC} All health checks passed"
fi
echo ""

# Display success message
echo "========================================"
echo "   Installation Complete!"
echo "========================================"
echo ""
echo "AegisForge has been successfully installed!"
echo ""
echo "Next Steps:"
echo ""
echo "1. Activate virtual environment (if not already active):"
echo "   source .venv/bin/activate"
echo ""
echo "2. Start all applications:"
echo "   ./scripts/linux/start_all_apps.sh"
echo ""
echo "3. Or start individual apps:"
echo "   - SecureBank Red:  python backend/apps/securebank/securebank_red_api.py"
echo "   - SecureBank Blue: python backend/apps/securebank/securebank_blue_api.py"
echo "   - ShopVuln Red:    python backend/apps/shopvuln/shopvuln_red_api.py"
echo "   - ShopVuln Blue:   python backend/apps/shopvuln/shopvuln_blue_api.py"
echo ""
echo "4. Read QUICKSTART.md for a 5-minute guide"
echo ""
echo "5. Access applications at:"
echo "   - SecureBank Red:  http://localhost:5000"
echo "   - SecureBank Blue: http://localhost:5001"
echo "   - ShopVuln Red:    http://localhost:5002"
echo "   - ShopVuln Blue:   http://localhost:5003"
echo ""
echo "Test Credentials:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "========================================"
echo ""
