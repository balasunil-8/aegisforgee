@echo off
:: AegisForge Installation Script for Windows
:: Version 1.0

echo.
echo ================================================
echo   AegisForge Installation v1.0
echo ================================================
echo.

:: Check Python version
echo [1/6] Checking Python version...
python --version >nul 2>&1
IF %errorLevel% NEQ 0 (
    echo ERROR: Python not found
    echo Please install Python 3.8 or higher from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

:: Display Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Python %PYTHON_VERSION% detected

:: Check disk space (basic check)
echo.
echo [2/6] Checking disk space...
echo Minimum 3GB required, 5GB recommended
echo.

:: Install dependencies
echo [3/6] Installing Python dependencies...
pip install -r requirements.txt
IF %errorLevel% NEQ 0 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo Dependencies installed successfully

:: Initialize SecureBank database
echo.
echo [4/6] Initializing SecureBank database...
cd backend\apps\securebank
python database.py
IF %errorLevel% NEQ 0 (
    echo WARNING: SecureBank database initialization failed
)
python seed_data.py
IF %errorLevel% NEQ 0 (
    echo WARNING: SecureBank seed data failed
)
cd ..\..\..
echo SecureBank database ready

:: Initialize ShopVuln database
echo.
echo [5/6] Initializing ShopVuln database...
cd backend\apps\shopvuln
python database.py
IF %errorLevel% NEQ 0 (
    echo WARNING: ShopVuln database initialization failed
)
python seed_data.py
IF %errorLevel% NEQ 0 (
    echo WARNING: ShopVuln seed data failed
)
cd ..\..\..
echo ShopVuln database ready

:: Run health check
echo.
echo [6/6] Running system health check...
python scripts\python\health_check.py
IF %errorLevel% NEQ 0 (
    echo WARNING: Health check reported issues
)

:: Installation complete
echo.
echo ================================================
echo   Installation Complete!
echo ================================================
echo.
echo Next steps:
echo   1. Start all applications: scripts\windows\start_all_apps.bat
echo   2. Open browser: http://localhost:5000
echo   3. Login with: alice / password123
echo.
echo Documentation: docs\getting-started\first-time-setup.md
echo Quick Start: QUICKSTART.md
echo.
pause
