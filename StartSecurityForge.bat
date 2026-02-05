@echo off
REM Quick Start Script for VulnShop API Lab (Windows)
REM Author: OWASP Lab
REM Purpose: Setup and run the vulnerable API

setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   VulnShop API - OWASP Top 10 Lab
echo ============================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.9+ from https://www.python.org/
    exit /b 1
)

echo [1/5] Creating virtual environment...
if not exist ".venv" (
    python -m venv .venv
    echo [OK] Virtual environment created
) else (
    echo [OK] Virtual environment already exists
)

echo.
echo [2/5] Activating virtual environment...
call .venv\Scripts\activate.bat
echo [OK] Virtual environment activated

echo.
echo [3/5] Installing dependencies...
pip install -r requirements.txt > nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    exit /b 1
)
echo [OK] Dependencies installed

echo.
echo [4/5] Database setup...
if exist "vulnshop.db" (
    del vulnshop.db
    echo [OK] Old database cleaned
)

echo.
echo ============================================================
echo [5/5] Starting Vulnerable API Server...
echo ============================================================
echo.
echo URL: http://localhost:5000/api/health
echo.
echo When ready, import these into Postman:
echo   - VulnShop_Collection.json
echo   - VulnShop_Environment.json
echo.
echo Press Ctrl+C to stop the server
echo.

python vulnshop.py

pause
