#!/bin/bash
# AegisForge - Database Initialization
# Initializes and seeds all databases
# Version 2.0

echo ""
echo "========================================"
echo "   AegisForge Database Initialization"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if Python is available
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} Python is not installed or not in PATH"
    exit 1
fi

# Use python3 if available, otherwise python
PYTHON_CMD="python3"
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD="python"
fi

echo "[1/4] Initializing SecureBank database..."
$PYTHON_CMD backend/apps/securebank/database.py
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Failed to initialize SecureBank database"
    echo "Check if the backend/apps/securebank/ directory exists"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} SecureBank database created"
echo ""

echo "[2/4] Seeding SecureBank with test data..."
$PYTHON_CMD backend/apps/securebank/seed_data.py
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[WARNING]${NC} Failed to seed SecureBank data"
else
    echo -e "${GREEN}[OK]${NC} SecureBank data seeded"
fi
echo ""

echo "[3/4] Initializing ShopVuln database..."
$PYTHON_CMD backend/apps/shopvuln/database.py
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Failed to initialize ShopVuln database"
    echo "Check if the backend/apps/shopvuln/ directory exists"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} ShopVuln database created"
echo ""

echo "[4/4] Seeding ShopVuln with test data..."
$PYTHON_CMD backend/apps/shopvuln/seed_data.py
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[WARNING]${NC} Failed to seed ShopVuln data"
else
    echo -e "${GREEN}[OK]${NC} ShopVuln data seeded"
fi
echo ""

# Check if databases were created
echo "Verifying database files..."
if [ -f "backend/apps/securebank/securebank.db" ]; then
    echo -e "${GREEN}[OK]${NC} SecureBank database file found"
else
    echo -e "${RED}[ERROR]${NC} SecureBank database file not found"
fi

if [ -f "backend/apps/shopvuln/shopvuln.db" ]; then
    echo -e "${GREEN}[OK]${NC} ShopVuln database file found"
else
    echo -e "${RED}[ERROR]${NC} ShopVuln database file not found"
fi

echo ""
echo "========================================"
echo "   Database Initialization Complete"
echo "========================================"
echo ""
echo "Databases created:"
echo "  - backend/apps/securebank/securebank.db"
echo "  - backend/apps/shopvuln/shopvuln.db"
echo ""
echo "Test credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "  Username: alice"
echo "  Password: alice123"
echo ""
echo "  Username: customer"
echo "  Password: customer123"
echo ""
echo "To start applications:"
echo "  ./scripts/linux/start_all_apps.sh"
echo ""
