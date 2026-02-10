@echo off
REM AegisForge - Start All Applications
REM Launches all four applications simultaneously
REM Version 2.0

setlocal enabledelayedexpansion

echo.
echo ========================================
echo    AegisForge - Starting All Apps
echo ========================================
echo.

REM Check if databases exist
if not exist "backend\apps\securebank\securebank.db" (
    echo [ERROR] SecureBank database not found!
    echo Please run: scripts\windows\init_databases.bat
    pause
    exit /b 1
)

if not exist "backend\apps\shopvuln\shopvuln.db" (
    echo [ERROR] ShopVuln database not found!
    echo Please run: scripts\windows\init_databases.bat
    pause
    exit /b 1
)

echo [INFO] Databases found - OK
echo.

REM Check if ports are available
echo Checking port availability...

for %%p in (5000 5001 5002 5003) do (
    netstat -ano | findstr ":%%p" | findstr "LISTENING" > nul
    if !errorlevel! equ 0 (
        echo [WARNING] Port %%p is already in use
        echo Please stop the process using this port or run:
        echo scripts\windows\stop_all_apps.bat
    )
)

echo.
echo Starting applications...
echo.

REM Start SecureBank Red Team (Port 5000)
echo [1/4] Starting SecureBank Red Team on port 5000...
start "AegisForge - SecureBank Red (Port 5000)" cmd /k "python backend/apps/securebank/securebank_red_api.py"
timeout /t 3 /nobreak > nul
echo [OK] SecureBank Red Team started

REM Start SecureBank Blue Team (Port 5001)
echo [2/4] Starting SecureBank Blue Team on port 5001...
start "AegisForge - SecureBank Blue (Port 5001)" cmd /k "python backend/apps/securebank/securebank_blue_api.py"
timeout /t 3 /nobreak > nul
echo [OK] SecureBank Blue Team started

REM Start ShopVuln Red Team (Port 5002)
echo [3/4] Starting ShopVuln Red Team on port 5002...
start "AegisForge - ShopVuln Red (Port 5002)" cmd /k "python backend/apps/shopvuln/shopvuln_red_api.py"
timeout /t 3 /nobreak > nul
echo [OK] ShopVuln Red Team started

REM Start ShopVuln Blue Team (Port 5003)
echo [4/4] Starting ShopVuln Blue Team on port 5003...
start "AegisForge - ShopVuln Blue (Port 5003)" cmd /k "python backend/apps/shopvuln/shopvuln_blue_api.py"
timeout /t 3 /nobreak > nul
echo [OK] ShopVuln Blue Team started

echo.
echo ========================================
echo    All Applications Started!
echo ========================================
echo.
echo Four separate command windows have been opened for each application.
echo.
echo Applications are accessible at:
echo.
echo  [RED TEAM - Vulnerable]
echo  - SecureBank Red:  http://localhost:5000
echo  - ShopVuln Red:    http://localhost:5002
echo.
echo  [BLUE TEAM - Secure]
echo  - SecureBank Blue: http://localhost:5001
echo  - ShopVuln Blue:   http://localhost:5003
echo.
echo Test Credentials:
echo  Username: admin
echo  Password: admin123
echo.
echo To stop all applications:
echo  Run: scripts\windows\stop_all_apps.bat
echo  Or close each command window manually
echo.
echo ========================================
echo.

REM Wait a bit then open browsers
echo Opening browsers in 5 seconds...
timeout /t 5 /nobreak > nul

REM Open browsers
start http://localhost:5000
timeout /t 1 /nobreak > nul
start http://localhost:5001
timeout /t 1 /nobreak > nul
start http://localhost:5002
timeout /t 1 /nobreak > nul
start http://localhost:5003

echo.
echo [OK] Browsers opened
echo.
echo Happy Ethical Hacking!
echo.

pause
