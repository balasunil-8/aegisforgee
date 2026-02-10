#!/bin/bash
# AegisForge Installation Script for Linux/Mac
# Version 1.0

echo ""
echo "================================================"
echo "  AegisForge Installation v1.0"
echo "================================================"
echo ""

# Check Python version
echo "[1/6] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found"
    echo "Please install Python 3.8 or higher"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "  macOS: brew install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')

# Enforce Python >= 3.8
PY_MAJOR=${PYTHON_VERSION%%.*}
PY_MINOR_PATCH=${PYTHON_VERSION#*.}
PY_MINOR=${PY_MINOR_PATCH%%.*}

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    echo "ERROR: Python $PYTHON_VERSION detected"
    echo "Python 3.8 or higher is required."
    exit 1
fi
echo "✓ Python $PYTHON_VERSION detected"

# Check disk space
echo ""
echo "[2/6] Checking disk space..."
echo "Minimum 3GB required, 5GB recommended"
AVAILABLE=$(df -h . | awk 'NR==2 {print $4}')
echo "Available: $AVAILABLE"
echo ""

# Install dependencies
echo "[3/6] Installing Python dependencies..."
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install dependencies"
    exit 1
fi
echo "✓ Dependencies installed successfully"

# Initialize SecureBank database
echo ""
echo "[4/6] Initializing SecureBank database..."
cd backend/apps/securebank
python3 database.py
if [ $? -ne 0 ]; then
    echo "WARNING: SecureBank database initialization failed"
fi
python3 seed_data.py
if [ $? -ne 0 ]; then
    echo "WARNING: SecureBank seed data failed"
fi
cd ../../..
echo "✓ SecureBank database ready"

# Initialize ShopVuln database
echo ""
echo "[5/6] Initializing ShopVuln database..."
cd backend/apps/shopvuln
python3 database.py
if [ $? -ne 0 ]; then
    echo "WARNING: ShopVuln database initialization failed"
fi
python3 seed_data.py
if [ $? -ne 0 ]; then
    echo "WARNING: ShopVuln seed data failed"
fi
cd ../../..
echo "✓ ShopVuln database ready"

# Run health check
echo ""
echo "[6/6] Running system health check..."
python3 scripts/python/health_check.py
if [ $? -ne 0 ]; then
    echo "WARNING: Health check reported issues"
fi

# Installation complete
echo ""
echo "================================================"
echo "  Installation Complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo "  1. Start all applications: ./scripts/linux/start_all_apps.sh"
echo "  2. Open browser: http://localhost:5000"
echo "  3. Login with: alice / password123"
echo ""
echo "Documentation: docs/getting-started/first-time-setup.md"
echo "Quick Start: QUICKSTART.md"
echo ""
