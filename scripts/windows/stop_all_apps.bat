@echo off
REM AegisForge - Stop All Applications
REM Kills all Python processes on ports 5000-5003
REM Version 2.0

echo.
echo ========================================
echo    AegisForge - Stopping All Apps
echo ========================================
echo.

echo Searching for applications on ports 5000-5003...
echo.

REM Stop processes on port 5000 (SecureBank Red)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5000" ^| findstr "LISTENING"') do (
    echo Stopping process on port 5000 ^(PID: %%a^)
    taskkill /PID %%a /F > nul 2>&1
    if !errorlevel! equ 0 (
        echo [OK] Stopped SecureBank Red ^(Port 5000^)
    )
)

REM Stop processes on port 5001 (SecureBank Blue)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5001" ^| findstr "LISTENING"') do (
    echo Stopping process on port 5001 ^(PID: %%a^)
    taskkill /PID %%a /F > nul 2>&1
    if !errorlevel! equ 0 (
        echo [OK] Stopped SecureBank Blue ^(Port 5001^)
    )
)

REM Stop processes on port 5002 (ShopVuln Red)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5002" ^| findstr "LISTENING"') do (
    echo Stopping process on port 5002 ^(PID: %%a^)
    taskkill /PID %%a /F > nul 2>&1
    if !errorlevel! equ 0 (
        echo [OK] Stopped ShopVuln Red ^(Port 5002^)
    )
)

REM Stop processes on port 5003 (ShopVuln Blue)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5003" ^| findstr "LISTENING"') do (
    echo Stopping process on port 5003 ^(PID: %%a^)
    taskkill /PID %%a /F > nul 2>&1
    if !errorlevel! equ 0 (
        echo [OK] Stopped ShopVuln Blue ^(Port 5003^)
    )
)

echo.

REM Check if any are still running
netstat -ano | findstr ":5000.*LISTENING" > nul 2>&1
if %errorlevel% equ 0 (
    echo [WARNING] Port 5000 still in use
) else (
    echo [OK] Port 5000 freed
)

netstat -ano | findstr ":5001.*LISTENING" > nul 2>&1
if %errorlevel% equ 0 (
    echo [WARNING] Port 5001 still in use
) else (
    echo [OK] Port 5001 freed
)

netstat -ano | findstr ":5002.*LISTENING" > nul 2>&1
if %errorlevel% equ 0 (
    echo [WARNING] Port 5002 still in use
) else (
    echo [OK] Port 5002 freed
)

netstat -ano | findstr ":5003.*LISTENING" > nul 2>&1
if %errorlevel% equ 0 (
    echo [WARNING] Port 5003 still in use
) else (
    echo [OK] Port 5003 freed
)

echo.
echo ========================================
echo    All Applications Stopped
echo ========================================
echo.
echo All AegisForge applications have been stopped.
echo Ports 5000-5003 should now be available.
echo.
echo To start applications again:
echo  Run: scripts\windows\start_all_apps.bat
echo.

pause
