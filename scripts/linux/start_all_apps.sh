#!/bin/bash
# AegisForge - Start All Applications (Linux/Mac)
# Version 1.0

echo ""
echo "================================================"
echo "  Starting AegisForge Applications..."
echo "================================================"
echo ""

# Function to start app in background
start_app() {
    local name=$1
    local port=$2
    local path=$3
    local script=$4
    
    echo "[$5/4] Starting $name (port $port)..."
    cd "$path"
    nohup python3 "$script" > "/tmp/aegisforge_${name// /_}.log" 2>&1 &
    echo $! > "/tmp/aegisforge_${name// /_}.pid"
    cd - > /dev/null
    sleep 3
}

# Start all applications
start_app "SecureBank Red" 5000 "backend/apps/securebank" "securebank_red_api.py" 1
start_app "SecureBank Blue" 5001 "backend/apps/securebank" "securebank_blue_api.py" 2
start_app "ShopVuln Red" 5002 "backend/apps/shopvuln" "shopvuln_red_api.py" 3
start_app "ShopVuln Blue" 5003 "backend/apps/shopvuln" "shopvuln_blue_api.py" 4

# Wait for servers to start
echo ""
echo "Waiting for servers to initialize (10 seconds)..."
sleep 10

# Open browsers (Linux)
if command -v xdg-open &> /dev/null; then
    echo ""
    echo "Opening applications in browser..."
    xdg-open http://localhost:5000 2>/dev/null &
    sleep 2
    xdg-open http://localhost:5002 2>/dev/null &
# Open browsers (macOS)
elif command -v open &> /dev/null; then
    echo ""
    echo "Opening applications in browser..."
    open http://localhost:5000
    sleep 2
    open http://localhost:5002
fi

# Display info
echo ""
echo "================================================"
echo "  All Applications Running!"
echo "================================================"
echo ""
echo "  SecureBank Red:  http://localhost:5000"
echo "  SecureBank Blue: http://localhost:5001"
echo "  ShopVuln Red:    http://localhost:5002"
echo "  ShopVuln Blue:   http://localhost:5003"
echo ""
echo "Test Credentials:"
echo "  Username: alice"
echo "  Password: password123"
echo ""
echo "Logs location: /tmp/aegisforge_*.log"
echo "PID files: /tmp/aegisforge_*.pid"
echo ""
echo "To stop all applications:"
echo "  Run: ./scripts/linux/stop_all_apps.sh"
echo ""
