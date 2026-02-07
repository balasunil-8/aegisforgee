# SecureBank Setup Guide

Complete installation and configuration guide for SecureBank Red Team and Blue Team environments.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Installation Steps](#installation-steps)
4. [Database Setup](#database-setup)
5. [Running Red Team API](#running-red-team-api)
6. [Running Blue Team API](#running-blue-team-api)
7. [Frontend Setup](#frontend-setup)
8. [Environment Configuration](#environment-configuration)
9. [Verification](#verification)
10. [Platform-Specific Instructions](#platform-specific-instructions)
11. [Troubleshooting Setup Issues](#troubleshooting-setup-issues)

---

## Prerequisites

Before installing SecureBank, ensure you have the following installed:

### Required Software

- **Python 3.8 or higher**
  - Check version: `python --version` or `python3 --version`
  - Download from: https://www.python.org/downloads/

- **pip** (Python package manager)
  - Usually comes with Python
  - Check version: `pip --version` or `pip3 --version`

- **Git** (for cloning repository)
  - Check version: `git --version`
  - Download from: https://git-scm.com/

- **Modern Web Browser**
  - Chrome, Firefox, Edge, or Safari
  - Must support JavaScript and localStorage

### Optional Tools

- **virtualenv** or **venv** (recommended for isolated environments)
- **Postman** (for API testing)
- **Burp Suite** (for security testing)
- **SQLMap** (for SQL injection testing)
- **OWASP ZAP** (for vulnerability scanning)

---

## System Requirements

### Minimum Requirements
- **CPU**: Dual-core processor
- **RAM**: 2GB available memory
- **Storage**: 500MB free disk space
- **OS**: Windows 10, macOS 10.14+, or Linux (Ubuntu 18.04+)

### Recommended Requirements
- **CPU**: Quad-core processor
- **RAM**: 4GB available memory
- **Storage**: 1GB free disk space
- **Network**: Internet connection for package installation

---

## Installation Steps

### Step 1: Clone the Repository

```bash
# Clone the AegisForge repository
git clone https://github.com/yourusername/aegisforgee.git
cd aegisforgee
```

### Step 2: Navigate to SecureBank Directory

```bash
cd backend/securebank
```

### Step 3: Create Virtual Environment (Recommended)

Creating a virtual environment keeps your SecureBank dependencies isolated.

**On Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**On Windows (Command Prompt):**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

> **Note**: If you get an execution policy error on Windows PowerShell, run:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### Step 4: Install Python Dependencies

```bash
# Install required packages
pip install -r requirements.txt
```

**Required packages include:**
- Flask (web framework)
- Flask-CORS (cross-origin support)
- SQLite3 (database - usually included with Python)
- Werkzeug (utilities)

If you encounter installation errors, try upgrading pip first:
```bash
pip install --upgrade pip
```

---

## Database Setup

SecureBank uses SQLite, which requires no separate installation. The database is automatically created when you run the initialization script.

### Initialize the Database

```bash
python init_db.py
```

**What this does:**
- Creates `securebank.db` file
- Creates tables: `users`, `accounts`, `transactions`, `sessions`
- Inserts sample data (users, accounts, transactions)
- Sets up test credentials

### Default Test Accounts

After initialization, you can log in with these accounts:

| Username | Password | Balance | Account Number |
|----------|----------|---------|----------------|
| alice    | alice123 | $5000   | 1001           |
| bob      | bob123   | $3000   | 1002           |
| charlie  | charlie123 | $7500 | 1003           |
| david    | david123 | $2000   | 1004           |

### Reset Database

To reset the database and start fresh:

```bash
# Remove existing database
rm securebank.db

# Reinitialize
python init_db.py
```

### Verify Database

Check that the database was created successfully:

```bash
# List files to see securebank.db
ls -l securebank.db

# Or on Windows
dir securebank.db
```

---

## Running Red Team API

The Red Team API contains vulnerabilities for educational exploitation.

### Start Red Team Server

```bash
python securebank_red.py
```

**Expected output:**
```
 * Serving Flask app 'securebank_red'
 * Debug mode: on
WARNING: This is a development server. Do not use in production.
 * Running on http://127.0.0.1:5001
Press CTRL+C to quit
```

### Configuration Options

You can customize the Red Team API:

```python
# In securebank_red.py, modify these settings:
app.run(
    host='0.0.0.0',  # Listen on all interfaces
    port=5001,        # Change port if needed
    debug=True        # Enable debug mode
)
```

### Test Red Team API

```bash
# In a new terminal, test the API
curl http://localhost:5001/api/health

# Expected response:
# {"status":"healthy","team":"red"}
```

---

## Running Blue Team API

The Blue Team API contains security defenses and protections.

### Start Blue Team Server

```bash
# In a new terminal (keep Red Team running)
python securebank_blue.py
```

**Expected output:**
```
 * Serving Flask app 'securebank_blue'
 * Debug mode: on
WARNING: This is a development server. Do not use in production.
 * Running on http://127.0.0.1:5002
Press CTRL+C to quit
```

### Test Blue Team API

```bash
curl http://localhost:5002/api/health

# Expected response:
# {"status":"healthy","team":"blue"}
```

---

## Frontend Setup

The SecureBank frontend is a single HTML file with JavaScript.

### Option 1: Python HTTP Server (Recommended)

```bash
# Navigate to frontend directory
cd frontend/securebank

# Start simple HTTP server
python -m http.server 8000

# Or on Python 2:
python -m SimpleHTTPServer 8000
```

**Access the application:**
- Open browser to: http://localhost:8000
- You should see the SecureBank login page

### Option 2: Direct File Access

You can also open the HTML file directly:

```bash
# Open with default browser (Linux)
xdg-open frontend/securebank/index.html

# Open with default browser (macOS)
open frontend/securebank/index.html

# Open with default browser (Windows)
start frontend/securebank/index.html
```

> **Note**: Some features may not work with `file://` protocol due to CORS restrictions. HTTP server is recommended.

### Option 3: VS Code Live Server

If using Visual Studio Code:
1. Install "Live Server" extension
2. Right-click `index.html`
3. Select "Open with Live Server"

---

## Environment Configuration

### Configure API Endpoints

Edit the frontend JavaScript to point to your APIs:

```javascript
// In frontend/securebank/index.html, find:
const RED_TEAM_API = 'http://localhost:5001';
const BLUE_TEAM_API = 'http://localhost:5002';

// Modify if running on different ports or hosts
```

### Configure CORS

If accessing from different domains, update CORS settings:

```python
# In securebank_red.py and securebank_blue.py
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:8000", "http://127.0.0.1:8000"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
```

### Port Configuration

Default ports:
- **Red Team API**: 5001
- **Blue Team API**: 5002
- **Frontend**: 8000

To change ports, modify the respective files:

```python
# In securebank_red.py
if __name__ == '__main__':
    app.run(port=5001, debug=True)

# In securebank_blue.py
if __name__ == '__main__':
    app.run(port=5002, debug=True)
```

---

## Verification

### Complete System Check

Run this verification checklist:

#### 1. Check Python Version
```bash
python --version
# Should be 3.8 or higher
```

#### 2. Check Database
```bash
ls -l securebank.db
# File should exist and be ~50KB or larger
```

#### 3. Check Red Team API
```bash
curl http://localhost:5001/api/health
# Should return: {"status":"healthy","team":"red"}
```

#### 4. Check Blue Team API
```bash
curl http://localhost:5002/api/health
# Should return: {"status":"healthy","team":"blue"}
```

#### 5. Check Frontend
- Open http://localhost:8000 in browser
- Should see SecureBank login page
- No console errors (check with F12)

#### 6. Test Login
- Username: `alice`
- Password: `alice123`
- Team: Select "Red Team"
- Should successfully log in and see dashboard

### Automated Verification Script

Create a verification script:

```bash
#!/bin/bash
# verify_setup.sh

echo "=== SecureBank Setup Verification ==="

# Check Python
echo "1. Checking Python..."
python3 --version || { echo "Python not found!"; exit 1; }

# Check database
echo "2. Checking database..."
[ -f securebank.db ] && echo "Database exists" || { echo "Database missing!"; exit 1; }

# Check Red Team API
echo "3. Checking Red Team API..."
curl -s http://localhost:5001/api/health | grep -q "red" && echo "Red Team API running" || echo "Red Team API not responding"

# Check Blue Team API
echo "4. Checking Blue Team API..."
curl -s http://localhost:5002/api/health | grep -q "blue" && echo "Blue Team API running" || echo "Blue Team API not responding"

echo "=== Verification Complete ==="
```

---

## Platform-Specific Instructions

### Windows

#### Python Installation
1. Download Python from python.org
2. Run installer
3. **Important**: Check "Add Python to PATH"
4. Verify: Open Command Prompt, run `python --version`

#### Common Windows Issues

**Issue**: `python` command not found
```cmd
# Try python3 instead
python3 --version

# Or use full path
C:\Python39\python.exe --version
```

**Issue**: Permission denied
```cmd
# Run Command Prompt as Administrator
# Right-click > "Run as administrator"
```

**Issue**: Port already in use
```cmd
# Find process using port 5001
netstat -ano | findstr :5001

# Kill process (replace PID)
taskkill /PID <process_id> /F
```

### macOS

#### Python Installation
```bash
# Check if Python is installed
python3 --version

# Install via Homebrew (if not installed)
brew install python3
```

#### Common macOS Issues

**Issue**: SSL certificate error
```bash
# Install certificates
/Applications/Python\ 3.9/Install\ Certificates.command
```

**Issue**: Permission denied
```bash
# Use pip with --user flag
pip3 install --user -r requirements.txt
```

### Linux (Ubuntu/Debian)

#### Python Installation
```bash
# Update package list
sudo apt update

# Install Python 3 and pip
sudo apt install python3 python3-pip python3-venv

# Verify installation
python3 --version
pip3 --version
```

#### Common Linux Issues

**Issue**: Permission denied on port
```bash
# Use sudo for ports below 1024
# Or change to port > 1024 (recommended)
```

**Issue**: Module not found
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall requirements
pip install -r requirements.txt
```

---

## Troubleshooting Setup Issues

### Database Issues

**Problem**: `securebank.db` not created

**Solution**:
```bash
# Check Python can create files in directory
touch test.txt && rm test.txt

# Check init_db.py exists
ls -l init_db.py

# Run with explicit Python
python3 init_db.py
```

**Problem**: Database locked error

**Solution**:
```bash
# Close all connections
# Stop all running SecureBank processes
pkill -f securebank

# Delete database and recreate
rm securebank.db
python init_db.py
```

### API Issues

**Problem**: Address already in use

**Solution**:
```bash
# Find and kill process on port 5001
lsof -ti:5001 | xargs kill -9

# Or use different port
python securebank_red.py --port 5003
```

**Problem**: CORS errors in browser console

**Solution**:
```python
# Update CORS configuration in securebank_red.py
from flask_cors import CORS

CORS(app, resources={r"/api/*": {"origins": "*"}})
```

**Problem**: Module not found error

**Solution**:
```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### Frontend Issues

**Problem**: Blank page in browser

**Solution**:
- Check browser console (F12) for errors
- Verify JavaScript is enabled
- Try different browser
- Check API endpoints are correct

**Problem**: Login not working

**Solution**:
- Verify APIs are running (check health endpoints)
- Check browser console for errors
- Clear browser cache and cookies
- Verify credentials: alice/alice123

**Problem**: CORS policy blocking requests

**Solution**:
```bash
# Start Chrome with CORS disabled (testing only)
# Linux
google-chrome --disable-web-security --user-data-dir=/tmp/chrome

# macOS
open -na "Google Chrome" --args --disable-web-security --user-data-dir=/tmp/chrome

# Windows
"C:\Program Files\Google\Chrome\Application\chrome.exe" --disable-web-security --user-data-dir=C:\tmp\chrome
```

### Network Issues

**Problem**: Cannot connect to localhost

**Solution**:
```bash
# Try 127.0.0.1 instead of localhost
curl http://127.0.0.1:5001/api/health

# Check firewall isn't blocking
# Windows: Check Windows Defender Firewall
# Linux: sudo ufw status
# macOS: System Preferences > Security & Privacy > Firewall
```

### Performance Issues

**Problem**: Slow API responses

**Solution**:
- Reduce debug output
- Check system resources (RAM, CPU)
- Reset database (may have grown large)
- Close unnecessary applications

---

## Next Steps

Once setup is complete:

1. **Read the User Guide** - Learn how to use SecureBank features
2. **Study Vulnerabilities** - Understand the security flaws in Red Team
3. **Try Exploitation** - Follow the Exploitation Guide
4. **Test Defenses** - Compare Red Team vs Blue Team
5. **Use Testing Tools** - Try Postman, Burp, SQLMap, and ZAP

---

## Quick Reference Commands

```bash
# Start Red Team API
python securebank_red.py

# Start Blue Team API
python securebank_blue.py

# Start Frontend
python -m http.server 8000

# Reset Database
rm securebank.db && python init_db.py

# Test APIs
curl http://localhost:5001/api/health
curl http://localhost:5002/api/health

# Access Application
# http://localhost:8000
```

---

## Getting Help

If you encounter issues not covered here:

1. Check the **Troubleshooting Guide** for detailed solutions
2. Review error messages carefully
3. Check GitHub Issues for known problems
4. Ensure all prerequisites are installed
5. Verify you're using compatible versions

---

## Security Note

⚠️ **Warning**: SecureBank Red Team intentionally contains vulnerabilities for educational purposes. Never deploy it to a production environment or expose it to the internet. Use only in isolated, controlled environments.

---

*Last Updated: 2024*
