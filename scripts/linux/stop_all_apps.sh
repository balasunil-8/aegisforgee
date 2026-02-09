#!/bin/bash
# AegisForge - Stop All Applications
# Kills all Python processes on ports 5000-5003
# Version 2.0

echo ""
echo "========================================"
echo "   AegisForge - Stopping All Apps"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Searching for applications on ports 5000-5003..."
echo ""

# Stop processes using PID files
for app in securebank_red securebank_blue shopvuln_red shopvuln_blue; do
    PID_FILE="/tmp/aegisforge_${app}.pid"
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "Stopping $app (PID: $PID)"
            kill "$PID" 2>/dev/null
            sleep 1
            # Force kill if still running
            if kill -0 "$PID" 2>/dev/null; then
                kill -9 "$PID" 2>/dev/null
            fi
            rm -f "$PID_FILE"
            echo -e "${GREEN}[OK]${NC} Stopped $app"
        else
            rm -f "$PID_FILE"
        fi
    fi
done

# Also try to stop by port
for port in 5000 5001 5002 5003; do
    PID=$(lsof -ti :$port 2>/dev/null)
    if [ -n "$PID" ]; then
        echo "Stopping process on port $port (PID: $PID)"
        kill "$PID" 2>/dev/null
        sleep 1
        # Force kill if still running
        if kill -0 "$PID" 2>/dev/null; then
            kill -9 "$PID" 2>/dev/null
        fi
    fi
done

echo ""

# Verify ports are freed
for port in 5000 5001 5002 5003; do
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}[WARNING]${NC} Port $port still in use"
    else
        echo -e "${GREEN}[OK]${NC} Port $port freed"
    fi
done

echo ""
echo "========================================"
echo "   All Applications Stopped"
echo "========================================"
echo ""
echo "All AegisForge applications have been stopped."
echo "Ports 5000-5003 should now be available."
echo ""
echo "To start applications again:"
echo "  ./scripts/linux/start_all_apps.sh"
echo ""
