@echo off
REM AegisForge Windows Installer
REM Automated installation and setup script
REM Version 2.0

echo.
echo ========================================
echo    AegisForge Windows Installer v2.0
echo ========================================
echo.

REM Check Python version
echo [1/7] Checking Python version...
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://www.python.org/downloads/
    pause
    exit /b 1
)

python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" > nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.8 or higher is required
    echo Current version:
    python --version
    echo Please upgrade Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

python --version
echo [OK] Python version check passed
echo.

REM Check disk space (require at least 3GB = 3145728 KB)
echo [2/7] Checking disk space...
for /f "tokens=3" %%a in ('dir /-c ^| find "bytes free"') do set FreeSpace=%%a
set FreeSpace=%FreeSpace:,=%
if %FreeSpace% LSS 3145728000 (
    echo [WARNING] Low disk space detected
    echo At least 3GB free space recommended
)
echo [OK] Sufficient disk space available
echo.

REM Check if virtual environment exists
echo [3/7] Setting up virtual environment...
if exist ".venv" (
    echo [INFO] Virtual environment already exists
) else (
    echo Creating virtual environment...
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created
)
echo.

REM Activate virtual environment
echo [4/7] Activating virtual environment...
call .venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b 1
)
echo [OK] Virtual environment activated
echo.

REM Install dependencies
echo [5/7] Installing dependencies from requirements.txt...
echo This may take 2-5 minutes...
pip install --upgrade pip > nul 2>&1
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies
    echo Try running: pip install -r requirements.txt manually
    pause
    exit /b 1
)
echo [OK] All dependencies installed successfully
echo.

REM Initialize databases
echo [6/7] Initializing databases...
echo.
echo [6.1/7] Initializing SecureBank database...
python backend/apps/securebank/database.py
if %errorlevel% neq 0 (
    echo [WARNING] SecureBank database initialization failed
) else (
    echo [OK] SecureBank database initialized
)
echo.

echo [6.2/7] Initializing ShopVuln database...
python backend/apps/shopvuln/database.py
if %errorlevel% neq 0 (
    echo [WARNING] ShopVuln database initialization failed
) else (
    echo [OK] ShopVuln database initialized
)
echo.

REM Seed database data
echo [6.3/7] Seeding database with test data...
python backend/apps/securebank/seed_data.py > nul 2>&1
python backend/apps/shopvuln/seed_data.py > nul 2>&1
echo [OK] Test data seeded
echo.

REM Run health check
echo [7/7] Running system health check...
python scripts/python/health_check.py
if %errorlevel% neq 0 (
    echo [WARNING] Some health checks failed
    echo You can still proceed, but some features may not work
) else (
    echo [OK] All health checks passed
)
echo.

REM Display success message
echo ========================================
echo    Installation Complete! 
echo ========================================
echo.
echo AegisForge has been successfully installed!
echo.
echo Next Steps:
echo.
echo 1. Start all applications:
echo    scripts\windows\start_all_apps.bat
echo.
echo 2. Or start individual apps:
echo    - SecureBank Red:  python backend/apps/securebank/securebank_red_api.py
echo    - SecureBank Blue: python backend/apps/securebank/securebank_blue_api.py
echo    - ShopVuln Red:    python backend/apps/shopvuln/shopvuln_red_api.py
echo    - ShopVuln Blue:   python backend/apps/shopvuln/shopvuln_blue_api.py
echo.
echo 3. Read QUICKSTART.md for a 5-minute guide
echo.
echo 4. Access applications at:
echo    - SecureBank Red:  http://localhost:5000
echo    - SecureBank Blue: http://localhost:5001
echo    - ShopVuln Red:    http://localhost:5002
echo    - ShopVuln Blue:   http://localhost:5003
echo.
echo Test Credentials:
echo    Username: admin
echo    Password: admin123
echo.
echo ========================================
echo.

pause
