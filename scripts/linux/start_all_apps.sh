#!/bin/bash
# AegisForge - Start All Applications
# Launches all four applications simultaneously
# Version 2.0

echo ""
echo "========================================"
echo "   AegisForge - Starting All Apps"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if databases exist
if [ ! -f "backend/apps/securebank/securebank.db" ]; then
    echo -e "${RED}[ERROR]${NC} SecureBank database not found!"
    echo "Please run: ./scripts/linux/init_databases.sh"
    exit 1
fi

if [ ! -f "backend/apps/shopvuln/shopvuln.db" ]; then
    echo -e "${RED}[ERROR]${NC} ShopVuln database not found!"
    echo "Please run: ./scripts/linux/init_databases.sh"
    exit 1
fi

echo -e "${GREEN}[INFO]${NC} Databases found - OK"
echo ""

# Check if ports are available
echo "Checking port availability..."
for port in 5000 5001 5002 5003; do
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}[WARNING]${NC} Port $port is already in use"
        echo "Please stop the process using this port or run:"
        echo "./scripts/linux/stop_all_apps.sh"
    fi
done

echo ""
echo "Starting applications in background..."
echo ""

# Start SecureBank Red Team (Port 5000)
echo -e "[1/4] Starting SecureBank Red Team on port 5000..."
python backend/apps/securebank/securebank_red_api.py > logs/securebank_red.log 2>&1 &
SECUREBANK_RED_PID=$!
echo $SECUREBANK_RED_PID > /tmp/aegisforge_securebank_red.pid
sleep 2
echo -e "${GREEN}[OK]${NC} SecureBank Red Team started (PID: $SECUREBANK_RED_PID)"

# Start SecureBank Blue Team (Port 5001)
echo -e "[2/4] Starting SecureBank Blue Team on port 5001..."
python backend/apps/securebank/securebank_blue_api.py > logs/securebank_blue.log 2>&1 &
SECUREBANK_BLUE_PID=$!
echo $SECUREBANK_BLUE_PID > /tmp/aegisforge_securebank_blue.pid
sleep 2
echo -e "${GREEN}[OK]${NC} SecureBank Blue Team started (PID: $SECUREBANK_BLUE_PID)"

# Start ShopVuln Red Team (Port 5002)
echo -e "[3/4] Starting ShopVuln Red Team on port 5002..."
python backend/apps/shopvuln/shopvuln_red_api.py > logs/shopvuln_red.log 2>&1 &
SHOPVULN_RED_PID=$!
echo $SHOPVULN_RED_PID > /tmp/aegisforge_shopvuln_red.pid
sleep 2
echo -e "${GREEN}[OK]${NC} ShopVuln Red Team started (PID: $SHOPVULN_RED_PID)"

# Start ShopVuln Blue Team (Port 5003)
echo -e "[4/4] Starting ShopVuln Blue Team on port 5003..."
python backend/apps/shopvuln/shopvuln_blue_api.py > logs/shopvuln_blue.log 2>&1 &
SHOPVULN_BLUE_PID=$!
echo $SHOPVULN_BLUE_PID > /tmp/aegisforge_shopvuln_blue.pid
sleep 2
echo -e "${GREEN}[OK]${NC} ShopVuln Blue Team started (PID: $SHOPVULN_BLUE_PID)"

echo ""
echo "========================================"
echo "   All Applications Started!"
echo "========================================"
echo ""
echo "Applications are running in the background."
echo ""
echo "Applications are accessible at:"
echo ""
echo "  [RED TEAM - Vulnerable]"
echo "  - SecureBank Red:  http://localhost:5000"
echo "  - ShopVuln Red:    http://localhost:5002"
echo ""
echo "  [BLUE TEAM - Secure]"
echo "  - SecureBank Blue: http://localhost:5001"
echo "  - ShopVuln Blue:   http://localhost:5003"
echo ""
echo "Test Credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "Log files:"
echo "  - logs/securebank_red.log"
echo "  - logs/securebank_blue.log"
echo "  - logs/shopvuln_red.log"
echo "  - logs/shopvuln_blue.log"
echo ""
echo "To stop all applications:"
echo "  ./scripts/linux/stop_all_apps.sh"
echo ""
echo "========================================"
echo ""

# Try to open browsers
echo "Opening browsers in 5 seconds..."
sleep 5

if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:5000 2>/dev/null &
    sleep 1
    xdg-open http://localhost:5001 2>/dev/null &
    sleep 1
    xdg-open http://localhost:5002 2>/dev/null &
    sleep 1
    xdg-open http://localhost:5003 2>/dev/null &
elif command -v open &> /dev/null; then
    open http://localhost:5000 2>/dev/null &
    sleep 1
    open http://localhost:5001 2>/dev/null &
    sleep 1
    open http://localhost:5002 2>/dev/null &
    sleep 1
    open http://localhost:5003 2>/dev/null &
fi

echo ""
echo -e "${GREEN}[OK]${NC} Browsers opened"
echo ""
echo "Happy Ethical Hacking!"
echo ""
