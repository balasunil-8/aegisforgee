@echo off
REM AegisForge - Database Initialization
REM Initializes and seeds all databases
REM Version 2.0

echo.
echo ========================================
echo    AegisForge Database Initialization
echo ========================================
echo.

REM Check if Python is available
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    pause
    exit /b 1
)

echo [1/4] Initializing SecureBank database...
python backend/apps/securebank/database.py
if %errorlevel% neq 0 (
    echo [ERROR] Failed to initialize SecureBank database
    echo Check if the backend/apps/securebank/ directory exists
    pause
    exit /b 1
)
echo [OK] SecureBank database created
echo.

echo [2/4] Seeding SecureBank with test data...
python backend/apps/securebank/seed_data.py
if %errorlevel% neq 0 (
    echo [WARNING] Failed to seed SecureBank data
) else (
    echo [OK] SecureBank data seeded
)
echo.

echo [3/4] Initializing ShopVuln database...
python backend/apps/shopvuln/database.py
if %errorlevel% neq 0 (
    echo [ERROR] Failed to initialize ShopVuln database
    echo Check if the backend/apps/shopvuln/ directory exists
    pause
    exit /b 1
)
echo [OK] ShopVuln database created
echo.

echo [4/4] Seeding ShopVuln with test data...
python backend/apps/shopvuln/seed_data.py
if %errorlevel% neq 0 (
    echo [WARNING] Failed to seed ShopVuln data
) else (
    echo [OK] ShopVuln data seeded
)
echo.

REM Check if databases were created
echo Verifying database files...
if exist "backend\apps\securebank\securebank.db" (
    echo [OK] SecureBank database file found
) else (
    echo [ERROR] SecureBank database file not found
)

if exist "backend\apps\shopvuln\shopvuln.db" (
    echo [OK] ShopVuln database file found
) else (
    echo [ERROR] ShopVuln database file not found
)

echo.
echo ========================================
echo    Database Initialization Complete
echo ========================================
echo.
echo Databases created:
echo  - backend/apps/securebank/securebank.db
echo  - backend/apps/shopvuln/shopvuln.db
echo.
echo Test credentials:
echo  Username: admin
echo  Password: admin123
echo.
echo  Username: alice
echo  Password: alice123
echo.
echo  Username: customer
echo  Password: customer123
echo.
echo To start applications:
echo  Run: scripts\windows\start_all_apps.bat
echo.

pause
