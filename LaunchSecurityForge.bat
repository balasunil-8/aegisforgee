@echo off
REM VulnShop API - Integrated Startup Batch File for Windows
REM This script activates the virtual environment and starts the app

echo.
echo ================================================================================
echo                     VulnShop API - Starting...
echo ================================================================================
echo.

REM Check if virtual environment exists
if not exist ".venv\Scripts\Activate.bat" (
    echo ERROR: Virtual environment not found!
    echo Please create it first with: python -m venv .venv
    pause
    exit /b 1
)

REM Activate virtual environment
call .venv\Scripts\Activate.bat

REM Run the startup script
python start_vulnshop.py

REM If Python script exits, pause to show any error messages
pause
