@echo off
REM AegisForge - System Health Check
REM Verifies system requirements and configuration
REM Version 2.0

echo.
echo ========================================
echo    AegisForge System Health Check
echo ========================================
echo.

set PASS_COUNT=0
set FAIL_COUNT=0

REM Check Python installation
echo [1/10] Checking Python installation...
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [FAIL] Python not found
    set /a FAIL_COUNT+=1
) else (
    python --version
    echo [PASS] Python is installed
    set /a PASS_COUNT+=1
)
echo.

REM Check Python version
echo [2/10] Checking Python version ^(3.8+ required^)...
python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" > nul 2>&1
if %errorlevel% neq 0 (
    echo [FAIL] Python 3.8 or higher required
    set /a FAIL_COUNT+=1
) else (
    echo [PASS] Python version is compatible
    set /a PASS_COUNT+=1
)
echo.

REM Check pip installation
echo [3/10] Checking pip installation...
pip --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [FAIL] pip not found
    set /a FAIL_COUNT+=1
) else (
    pip --version
    echo [PASS] pip is installed
    set /a PASS_COUNT+=1
)
echo.

REM Check critical dependencies
echo [4/10] Checking Flask installation...
python -c "import flask" > nul 2>&1
if %errorlevel% neq 0 (
    echo [FAIL] Flask not installed
    echo Run: pip install -r requirements.txt
    set /a FAIL_COUNT+=1
) else (
    python -c "import flask; print('Flask', flask.__version__)"
    echo [PASS] Flask is installed
    set /a PASS_COUNT+=1
)
echo.

echo [5/10] Checking SQLAlchemy installation...
python -c "import sqlalchemy" > nul 2>&1
if %errorlevel% neq 0 (
    echo [FAIL] SQLAlchemy not installed
    set /a FAIL_COUNT+=1
) else (
    echo [PASS] SQLAlchemy is installed
    set /a PASS_COUNT+=1
)
echo.

REM Check databases
echo [6/10] Checking SecureBank database...
if exist "backend\apps\securebank\securebank.db" (
    echo [PASS] SecureBank database exists
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] SecureBank database not found
    echo Run: scripts\windows\init_databases.bat
    set /a FAIL_COUNT+=1
)
echo.

echo [7/10] Checking ShopVuln database...
if exist "backend\apps\shopvuln\shopvuln.db" (
    echo [PASS] ShopVuln database exists
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] ShopVuln database not found
    echo Run: scripts\windows\init_databases.bat
    set /a FAIL_COUNT+=1
)
echo.

REM Check port availability
echo [8/10] Checking port 5000 availability...
netstat -ano | findstr ":5000.*LISTENING" > nul 2>&1
if %errorlevel% equ 0 (
    echo [WARN] Port 5000 is in use
    set /a FAIL_COUNT+=1
) else (
    echo [PASS] Port 5000 is available
    set /a PASS_COUNT+=1
)
echo.

echo [9/10] Checking port 5001 availability...
netstat -ano | findstr ":5001.*LISTENING" > nul 2>&1
if %errorlevel% equ 0 (
    echo [WARN] Port 5001 is in use
    set /a FAIL_COUNT+=1
) else (
    echo [PASS] Port 5001 is available
    set /a PASS_COUNT+=1
)
echo.

REM Check disk space
echo [10/10] Checking disk space...
for /f "tokens=3" %%a in ('dir /-c ^| find "bytes free"') do set FreeSpace=%%a
set FreeSpace=%FreeSpace:,=%
if %FreeSpace% LSS 3145728000 (
    echo [WARN] Low disk space ^(less than 3GB free^)
    set /a FAIL_COUNT+=1
) else (
    echo [PASS] Sufficient disk space available
    set /a PASS_COUNT+=1
)
echo.

REM Summary
echo ========================================
echo    Health Check Summary
echo ========================================
echo.
echo Passed: %PASS_COUNT%/10
echo Failed: %FAIL_COUNT%/10
echo.

if %FAIL_COUNT% equ 0 (
    echo [SUCCESS] All checks passed!
    echo AegisForge is ready to use.
    echo.
    echo To start applications:
    echo  Run: scripts\windows\start_all_apps.bat
) else (
    echo [WARNING] Some checks failed
    echo Please fix the issues above before starting applications
)

echo.
echo ========================================
echo.

pause
