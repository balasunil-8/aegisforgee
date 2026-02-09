@echo off
:: AegisForge - Start All Applications (Windows)
:: Version 1.0

echo.
echo ================================================
echo   Starting AegisForge Applications...
echo ================================================
echo.

:: Start SecureBank Red
echo [1/4] Starting SecureBank Red (port 5000)...
start "SecureBank Red API" cmd /k "cd backend\apps\securebank && python securebank_red_api.py"
timeout /t 3 /nobreak >nul

:: Start SecureBank Blue
echo [2/4] Starting SecureBank Blue (port 5001)...
start "SecureBank Blue API" cmd /k "cd backend\apps\securebank && python securebank_blue_api.py"
timeout /t 3 /nobreak >nul

:: Start ShopVuln Red
echo [3/4] Starting ShopVuln Red (port 5002)...
start "ShopVuln Red API" cmd /k "cd backend\apps\shopvuln && python shopvuln_red_api.py"
timeout /t 3 /nobreak >nul

:: Start ShopVuln Blue
echo [4/4] Starting ShopVuln Blue (port 5003)...
start "ShopVuln Blue API" cmd /k "cd backend\apps\shopvuln && python shopvuln_blue_api.py"
timeout /t 3 /nobreak >nul

:: Wait for servers to start
echo.
echo Waiting for servers to initialize (10 seconds)...
timeout /t 10 /nobreak >nul

:: Open browsers
echo.
echo Opening applications in browser...
start http://localhost:5000
timeout /t 2 /nobreak >nul
start http://localhost:5002

:: Display info
echo.
echo ================================================
echo   All Applications Running!
echo ================================================
echo.
echo   SecureBank Red:  http://localhost:5000
echo   SecureBank Blue: http://localhost:5001
echo   ShopVuln Red:    http://localhost:5002
echo   ShopVuln Blue:   http://localhost:5003
echo.
echo Test Credentials:
echo   Username: alice
echo   Password: password123
echo.
echo To stop all applications:
echo   Run: scripts\windows\stop_all_apps.bat
echo   Or close the terminal windows
echo.
echo Press any key to exit this window...
pause >nul
