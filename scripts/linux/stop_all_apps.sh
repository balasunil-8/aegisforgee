#!/bin/bash
# AegisForge - Stop All Applications (Linux/Mac)
# Version 1.0

echo ""
echo "================================================"
echo "  Stopping AegisForge Applications..."
echo "================================================"
echo ""

# Function to stop app by PID file
stop_app() {
    local name=$1
    local pidfile="/tmp/aegisforge_${name// /_}.pid"
    
    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Stopping $name (PID: $pid)..."
            kill "$pid" 2>/dev/null
            rm "$pidfile"
        else
            echo "$name not running"
            rm "$pidfile"
        fi
    else
        echo "$name PID file not found"
    fi
}

# Stop all applications
stop_app "SecureBank_Red"
stop_app "SecureBank_Blue"
stop_app "ShopVuln_Red"
stop_app "ShopVuln_Blue"

# Also kill by port (fallback)
echo ""
echo "Checking ports..."
for port in 5000 5001 5002 5003; do
    pid=$(lsof -ti:$port 2>/dev/null)
    if [ -n "$pid" ]; then
        echo "Killing process on port $port (PID: $pid)..."
        kill -9 $pid 2>/dev/null
    fi
done

echo ""
echo "================================================"
echo "  All Applications Stopped"
echo "================================================"
echo ""
