# VulnShop API - Integrated Startup Script for PowerShell
# This script activates the virtual environment and starts the app

Write-Host ""
Write-Host "================================================================================"
Write-Host "                        VulnShop API - Starting..."
Write-Host "================================================================================"
Write-Host ""

# Check if virtual environment exists
if (-not (Test-Path ".venv\Scripts\Activate.ps1")) {
    Write-Host "ERROR: Virtual environment not found!" -ForegroundColor Red
    Write-Host "Please create it first with: python -m venv .venv" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Activate virtual environment
& ".venv\Scripts\Activate.ps1"

# Run the startup script
python start_vulnshop.py

# If Python script exits, pause to show any error messages
Read-Host "Press Enter to exit"
