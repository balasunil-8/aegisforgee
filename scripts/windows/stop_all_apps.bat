@echo off
:: AegisForge - Stop All Applications (Windows)
:: Version 1.0

echo.
echo ================================================
echo   Stopping AegisForge Applications...
echo ================================================
echo.

:: Kill Python processes running on specific ports
echo Stopping SecureBank Red (port 5000)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5000 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1

echo Stopping SecureBank Blue (port 5001)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5001 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1

echo Stopping ShopVuln Red (port 5002)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5002 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1

echo Stopping ShopVuln Blue (port 5003)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5003 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1

echo.
echo ================================================
echo   All Applications Stopped
echo ================================================
echo.
pause
