#!/bin/bash
# AegisForge - System Health Check
# Verifies system requirements and configuration
# Version 2.0

echo ""
echo "========================================"
echo "   AegisForge System Health Check"
echo "========================================"
echo ""

# Use Python script for health check
if [ -f "scripts/python/health_check.py" ]; then
    if command -v python3 &> /dev/null; then
        python3 scripts/python/health_check.py
    elif command -v python &> /dev/null; then
        python scripts/python/health_check.py
    else
        echo "[ERROR] Python not found"
        exit 1
    fi
else
    echo "[ERROR] Health check script not found: scripts/python/health_check.py"
    exit 1
fi
