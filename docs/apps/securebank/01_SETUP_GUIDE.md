# 🏦 SecureBank Setup Guide

**Complete Installation and Configuration Guide for SecureBank Red Team and Blue Team Environments**

Part of the AegisForge Security Education Platform

---

## 📋 Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [System Requirements](#system-requirements)
4. [Installation Steps](#installation-steps)
5. [Database Setup](#database-setup)
6. [Running Red Team API (Vulnerable)](#running-red-team-api-vulnerable)
7. [Running Blue Team API (Secure)](#running-blue-team-api-secure)
8. [Frontend Setup](#frontend-setup)
9. [Environment Configuration](#environment-configuration)
10. [Verification and Testing](#verification-and-testing)
11. [Platform-Specific Instructions](#platform-specific-instructions)
12. [Advanced Configuration](#advanced-configuration)
13. [Docker Installation (Alternative)](#docker-installation-alternative)
14. [Common Setup Issues](#common-setup-issues)
15. [Next Steps](#next-steps)

---

## Introduction

Welcome to the SecureBank Setup Guide! This guide will walk you through every step needed to install and run SecureBank on your computer. SecureBank is a realistic banking application with two versions:

- **Red Team (Vulnerable)**: Contains intentional security flaws for learning
- **Blue Team (Secure)**: Shows how to properly fix those security issues

### What You'll Accomplish

By the end of this guide, you will have:
- ✅ SecureBank installed on your computer
- ✅ Database set up with realistic banking data
- ✅ Both Red and Blue Team APIs running
- ✅ Frontend interface accessible in your browser
- ✅ Test accounts ready to use
- ✅ A working cybersecurity lab environment

### Time Estimate

- **First-time installation**: 30-45 minutes
- **Experienced users**: 10-15 minutes

### Why This Matters

Setting up a local security testing environment is essential for learning cybersecurity safely. With SecureBank running locally, you can:
- Practice finding vulnerabilities without legal consequences
- Test security tools in a safe environment
- Learn at your own pace without internet dependency
- Understand how real banking applications work

---

## Prerequisites

Before installing SecureBank, you need to install some software on your computer. Don't worry - we'll guide you through each step!

### Required Software

#### 1. Python 3.8 or Higher

Python is the programming language SecureBank is written in.

**Check if you have Python:**
```bash
# On Windows/Mac/Linux
python --version
# Or try
python3 --version
```

**What you should see:**
```
Python 3.8.0 (or higher)
```

**If you don't have Python:**
1. Visit https://www.python.org/downloads/
2. Download the installer for your operating system
3. Run the installer
4. **Important**: Check "Add Python to PATH" during installation

**Why Python?** Python is beginner-friendly, widely used in cybersecurity, and perfect for building web applications quickly.

#### 2. pip (Python Package Manager)

pip installs Python packages (libraries and tools).

**Check if you have pip:**
```bash
pip --version
# Or try
pip3 --version
```

**What you should see:**
```
pip 21.0 from /usr/local/lib/python3.8/site-packages/pip (python 3.8)
```

**If you don't have pip:**
- pip usually comes with Python 3.4+
- If missing, download: https://pip.pypa.io/en/stable/installation/

**Why pip?** It automatically downloads and installs all the libraries SecureBank needs to run.

#### 3. Git (Version Control)

Git lets you download (clone) the SecureBank code from the internet.

**Check if you have Git:**
```bash
git --version
```

**What you should see:**
```
git version 2.30.0
```

**If you don't have Git:**
1. Visit https://git-scm.com/downloads
2. Download the installer
3. Run with default settings

**Why Git?** It's the industry standard for managing code and downloading projects from GitHub.

#### 4. Modern Web Browser

You need a browser that supports JavaScript and modern web features.

**Recommended browsers:**
- Google Chrome (recommended for security testing)
- Mozilla Firefox
- Microsoft Edge
- Safari (Mac)

**Why a modern browser?** SecureBank's frontend uses JavaScript features that old browsers don't support.

### Optional but Recommended Software

#### Virtual Environment Tool

Keeps SecureBank's packages separate from your system Python.

**Built into Python 3.3+:**
```bash
python -m venv --help
```

**Why virtual environments?** They prevent conflicts between different Python projects on your computer.

### Optional Security Testing Tools

Install these later to test SecureBank's vulnerabilities:

- **Postman**: API testing (free) - https://www.postman.com/
- **Burp Suite Community**: Web security testing (free) - https://portswigger.net/burp
- **SQLMap**: Automated SQL injection testing (free) - https://sqlmap.org/
- **OWASP ZAP**: Vulnerability scanning (free) - https://www.zaproxy.org/

**Why these tools?** Professional penetration testers use these tools daily. Learning them gives you real-world skills.

---

## System Requirements

### Minimum Requirements

These are the bare minimum specs to run SecureBank:

- **CPU**: Dual-core processor (Intel i3 or equivalent)
- **RAM**: 2GB available memory
- **Storage**: 500MB free disk space
- **OS**: Windows 10, macOS 10.14+, or Linux (Ubuntu 18.04+)
- **Network**: Internet connection (for initial setup only)

**Will it run on my computer?** If your computer can browse the web and run basic applications, it can run SecureBank.

### Recommended Requirements

For the best experience:

- **CPU**: Quad-core processor (Intel i5 or better)
- **RAM**: 4GB available memory
- **Storage**: 1GB free disk space
- **Network**: High-speed internet (for faster package downloads)

**Why more is better:** Multiple APIs running simultaneously, security tools, and testing work smoother with more resources.

### Supported Operating Systems

SecureBank works on all major operating systems:

| Operating System | Versions | Notes |
|-----------------|----------|-------|
| **Windows** | Windows 10, 11 | Use Command Prompt or PowerShell |
| **macOS** | 10.14 (Mojave) or newer | Use Terminal |
| **Linux** | Ubuntu 18.04+, Debian 10+, Fedora 30+ | Use Terminal |

**Cross-platform:** The setup process is similar on all operating systems, with minor command differences.

---

## Installation Steps

Now let's install SecureBank! Follow these steps carefully.

### Step 1: Clone the AegisForge Repository

AegisForge contains multiple security applications, including SecureBank.

**Open your terminal/command prompt and run:**

```bash
# Navigate to where you want to install (e.g., your Documents folder)
cd ~/Documents  # Mac/Linux
# or
cd %USERPROFILE%\Documents  # Windows

# Clone the repository
git clone https://github.com/yourusername/aegisforgee.git

# Enter the directory
cd aegisforgee
```

**What happened?**
- Git downloaded all the code from GitHub
- You now have a folder called `aegisforgee` with all the files
- This includes SecureBank and other security applications

**Screenshot placeholder: [Terminal showing successful git clone]**

**Troubleshooting:**
- **"git: command not found"**: Install Git (see Prerequisites)
- **"Permission denied"**: Try running as administrator or use sudo (Linux/Mac)
- **Connection timeout**: Check your internet connection or try again later

### Step 2: Navigate to the Project Root

```bash
# You should already be in aegisforgee from Step 1
pwd  # Mac/Linux - shows current directory
# or
cd  # Windows - shows current directory

# Expected output: /path/to/aegisforgee
```

**Why this matters:** All subsequent commands assume you're in the `aegisforgee` directory.

### Step 3: Create a Virtual Environment

A virtual environment keeps SecureBank's dependencies isolated from your system Python.

**On Linux/macOS:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Your prompt should now show (venv)
```

**On Windows (Command Prompt):**
```cmd
REM Create virtual environment
python -m venv venv

REM Activate it
venv\Scripts\activate.bat

REM Your prompt should now show (venv)
```

**On Windows (PowerShell):**
```powershell
# Create virtual environment
python -m venv venv

# Activate it
.\venv\Scripts\Activate.ps1

# Your prompt should now show (venv)
```

**What happened?**
- Created a folder called `venv` with a clean Python environment
- Activated it (your terminal prompt shows `(venv)` before your path)
- Any packages you install now go into `venv`, not system-wide

**Screenshot placeholder: [Terminal showing (venv) in prompt]**

**Troubleshooting:**
- **PowerShell execution policy error:**
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```
  Then try activating again.

- **"No module named venv"**: Your Python version might be too old. Update to Python 3.8+.

### Step 4: Install Python Dependencies

SecureBank needs several Python packages to run. The `requirements.txt` file lists all of them.

```bash
# Make sure your virtual environment is activated (you see (venv) in prompt)
# Upgrade pip first (recommended)
pip install --upgrade pip

# Install all required packages
pip install -r requirements.txt
```

**What gets installed:**
- **Flask**: Web framework for building APIs
- **Flask-CORS**: Allows frontend to talk to backend
- **SQLAlchemy**: Database toolkit
- **Werkzeug**: Security utilities
- **bcrypt**: Password hashing
- **And more...** (see requirements.txt for full list)

**This might take 2-5 minutes.** You'll see progress as each package installs.

**Screenshot placeholder: [Terminal showing successful package installation]**

**Troubleshooting:**
- **"Could not find a version that satisfies the requirement"**: 
  - Update pip: `pip install --upgrade pip`
  - Check Python version: Should be 3.8+

- **Permission errors**: 
  - Make sure virtual environment is activated
  - On Linux/Mac, try `pip install --user -r requirements.txt`

- **Network errors**: 
  - Check internet connection
  - Try again (sometimes PyPI is temporarily slow)

### Step 5: Verify Installation

Let's make sure everything installed correctly.

```bash
# Check Flask
python -c "import flask; print(f'Flask {flask.__version__} installed successfully')"

# Check SQLAlchemy
python -c "import sqlalchemy; print(f'SQLAlchemy {sqlalchemy.__version__} installed successfully')"

# List all installed packages
pip list
```

**What you should see:**
```
Flask 2.3.0 installed successfully
SQLAlchemy 2.0.0 installed successfully
```

**If any package is missing**, reinstall: `pip install package-name`

---

## Database Setup

SecureBank uses SQLite, a lightweight database that requires no separate installation. The database file stores all users, accounts, transactions, and settings.

### Understanding the Database

**What is a database?** Think of it like an organized filing cabinet for digital information. SecureBank's database stores:
- **bank_users**: Customer information (names, emails, passwords)
- **bank_accounts**: Account numbers, balances, account types
- **transactions**: Money transfers, deposits, withdrawals
- **beneficiaries**: Saved recipients for transfers
- **user_settings**: User preferences and configurations

**SQLite vs. MySQL/PostgreSQL:** SQLite is simpler and needs no server, making it perfect for learning. Real banks use PostgreSQL or Oracle databases.

### Initialize the Database

Run the initialization script to create and populate the database:

```bash
# Make sure you're in the aegisforgee root directory
# and your virtual environment is activated (venv)

python backend/apps/securebank/database.py
```

**Alternative method:**
```bash
cd backend/apps/securebank
python database.py
cd ../../..  # Return to root
```

**What this script does:**
1. **Creates `securebank.db`** file in `backend/apps/securebank/`
2. **Creates tables**: 
   - bank_users
   - bank_accounts
   - transactions
   - beneficiaries
   - user_settings
3. **Seeds sample data**:
   - 5 test users with realistic profiles
   - 8 bank accounts (checking, savings, credit)
   - 20+ sample transactions
   - Saved beneficiaries

**Expected output:**
```
Creating database tables...
✓ Tables created successfully
Seeding sample data...
✓ Created 5 users
✓ Created 8 accounts
✓ Created 25 transactions
Database setup complete! 
Database location: backend/apps/securebank/securebank.db
```

**Screenshot placeholder: [Terminal showing successful database creation]**

**Verify database creation:**
```bash
# Check if database file exists
ls -lh backend/apps/securebank/securebank.db  # Mac/Linux
# or
dir backend\apps\securebank\securebank.db  # Windows

# Expected: File size around 50-100 KB
```

### Default Test Accounts

The database comes with pre-configured test accounts for hands-on learning:

| Username | Password | Role | Accounts | Purpose |
|----------|----------|------|----------|---------|
| `john.doe` | `password123` | user | Checking ($5,000), Savings ($10,000) | Primary test account |
| `jane.smith` | `password123` | user | Checking ($3,000), Savings ($7,500) | Secondary test account |
| `bob.wilson` | `password123` | user | Checking ($2,000), Credit ($500) | Testing transfers |
| `alice.brown` | `password123` | user | Savings ($15,000) | Testing IDOR vulnerability |
| `admin` | `admin123` | admin | N/A | Testing privilege escalation |

**Security Note:** These passwords are intentionally weak for educational purposes. **NEVER** use passwords like these in real applications!

### Database Schema Details

Want to understand how the database is structured? Here's the schema:

**bank_users table:**
```sql
CREATE TABLE bank_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,  -- bcrypt hashed
    email VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    address TEXT,
    role VARCHAR(20) DEFAULT 'user',  -- 'user' or 'admin'
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);
```

**bank_accounts table:**
```sql
CREATE TABLE bank_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    account_number VARCHAR(20) UNIQUE NOT NULL,
    account_type VARCHAR(20) NOT NULL,  -- 'Checking', 'Savings', 'Credit'
    balance FLOAT DEFAULT 0.0,
    currency VARCHAR(3) DEFAULT 'USD',
    status VARCHAR(20) DEFAULT 'active',
    opened_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES bank_users(id)
);
```

**Understanding the structure helps you later when testing SQL injection vulnerabilities!**

---

## Running Red Team API (Vulnerable)

The Red Team API is the intentionally vulnerable version of SecureBank. It contains security flaws for educational purposes.

### What is the Red Team API?

**Red Team** in cybersecurity refers to the attackers - professionals who try to break into systems to test security. Our Red Team API simulates a poorly secured banking application.

**What's vulnerable in it:**
- SQL Injection in login
- Insecure Direct Object References (IDOR)
- Race conditions in money transfers
- Cross-Site Scripting (XSS)
- Mass Assignment vulnerabilities
- Cross-Site Request Forgery (CSRF)

### Starting the Red Team API

**Open a NEW terminal/command prompt** (keep your first one open):

```bash
# Navigate to AegisForge directory
cd /path/to/aegisforgee

# Activate virtual environment
source venv/bin/activate  # Mac/Linux
# or
venv\Scripts\activate  # Windows

# Run the Red Team API
python backend/apps/securebank/securebank_red_api.py
```

**Expected output:**
```
 * Serving Flask app 'securebank_red_api'
 * Debug mode: on
WARNING: This is a RED TEAM (vulnerable) API - For educational purposes only!
 * Running on http://127.0.0.1:5001
 * Running on http://192.168.1.100:5001
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
```

**Screenshot placeholder: [Terminal showing Red Team API running]**

**What does this mean?**
- Flask web server started successfully
- API is listening on port **5001**
- Accessible at `http://127.0.0.1:5001` (localhost)
- Debug mode is ON (helpful for learning, shows detailed errors)

### Testing the Red Team API

Open your web browser and visit:
```
http://127.0.0.1:5001/api/health
```

**Expected response:**
```json
{
  "status": "healthy",
  "mode": "red_team",
  "database": "connected",
  "timestamp": "2024-01-15T10:30:00"
}
```

**This confirms:**
- ✅ API is running
- ✅ Database is connected
- ✅ You're running the Red Team (vulnerable) version

### Available Red Team Endpoints

The Red Team API exposes these endpoints:

| Endpoint | Method | Purpose | Vulnerability |
|----------|--------|---------|---------------|
| `/api/login` | POST | User authentication | SQL Injection |
| `/api/accounts/<id>` | GET | Get account details | IDOR |
| `/api/transfer` | POST | Transfer money | Race Condition |
| `/api/transactions` | GET | Transaction history | XSS (in notes) |
| `/api/profile` | PUT | Update user profile | Mass Assignment |
| `/api/settings` | POST | Update settings | CSRF |

**We'll explore exploiting these in later guides!**

### Keeping Red Team Running

**Important:** Keep this terminal window open and the API running. You'll need it throughout your testing.

**To stop the API:**
- Press `Ctrl+C` in the terminal
- The server will gracefully shut down

**To restart:**
- Just run the command again: `python backend/apps/securebank/securebank_red_api.py`

---

## Running Blue Team API (Secure)

The Blue Team API is the secure version with all vulnerabilities properly fixed.

### What is the Blue Team API?

**Blue Team** in cybersecurity refers to the defenders - professionals who protect systems from attacks. Our Blue Team API demonstrates industry-standard security practices.

**What's fixed in it:**
- Parameterized SQL queries (prevents SQL injection)
- Proper authorization checks (prevents IDOR)
- Transaction locking (prevents race conditions)
- HTML encoding and CSP (prevents XSS)
- Explicit field whitelisting (prevents mass assignment)
- CSRF tokens (prevents CSRF attacks)

### Starting the Blue Team API

**Open ANOTHER new terminal/command prompt** (you should now have 2 terminals open):

```bash
# Navigate to AegisForge directory
cd /path/to/aegisforgee

# Activate virtual environment
source venv/bin/activate  # Mac/Linux
# or
venv\Scripts\activate  # Windows

# Run the Blue Team API
python backend/apps/securebank/securebank_blue_api.py
```

**Expected output:**
```
 * Serving Flask app 'securebank_blue_api'
 * Debug mode: off
INFO: This is a BLUE TEAM (secure) API - Best practices implemented
 * Running on http://127.0.0.1:5002
 * Running on http://192.168.1.100:5002
Press CTRL+C to quit
```

**Notice the differences:**
- Runs on port **5002** (different from Red Team's 5001)
- Debug mode is **OFF** (more secure)
- Different startup message

**Screenshot placeholder: [Terminal showing Blue Team API running]**

### Testing the Blue Team API

Visit in your browser:
```
http://127.0.0.1:5002/api/health
```

**Expected response:**
```json
{
  "status": "healthy",
  "mode": "blue_team",
  "database": "connected",
  "security_features": [
    "parameterized_queries",
    "authorization_checks",
    "csrf_protection",
    "xss_prevention",
    "rate_limiting"
  ],
  "timestamp": "2024-01-15T10:35:00"
}
```

**This confirms:**
- ✅ Blue Team API is running
- ✅ Security features are enabled
- ✅ Running on different port than Red Team

### Comparing Red vs Blue

You can now compare the same endpoint in both versions:

**Red Team (Vulnerable):**
```
http://127.0.0.1:5001/api/login
```

**Blue Team (Secure):**
```
http://127.0.0.1:5002/api/login
```

**Try SQL injection on both and see the difference!**

---

## Frontend Setup

The frontend is the user interface - what users see and interact with in their browser.

### Frontend Architecture

SecureBank has TWO frontends:
- **Red Team Frontend**: `/frontend/apps/securebank/red/` - Works with vulnerable API
- **Blue Team Frontend**: `/frontend/apps/securebank/blue/` - Works with secure API

**Both frontends are identical in appearance** - the only difference is which API they connect to.

### Opening the Red Team Frontend

The frontend consists of HTML, CSS, and JavaScript files that run directly in your browser.

**Method 1: Direct File Opening (Simplest)**

```bash
# Navigate to frontend directory
cd frontend/apps/securebank/red/

# Open login.html in your browser
# On Mac:
open login.html

# On Linux:
xdg-open login.html

# On Windows:
start login.html
```

**Method 2: Using a Local Web Server (Recommended)**

```bash
# Python 3 includes a simple web server
cd frontend/apps/securebank/red/

# Start server on port 8000
python3 -m http.server 8000
```

Then visit: `http://127.0.0.1:8000/login.html`

**Why use a web server?** Avoids CORS issues and simulates a real deployment.

**Screenshot placeholder: [SecureBank login page in browser]**

### Opening the Blue Team Frontend

Same process, different directory:

```bash
cd frontend/apps/securebank/blue/
python3 -m http.server 8001  # Different port!
```

Visit: `http://127.0.0.1:8001/login.html`

### Frontend Features

Both frontends include:
- **Login page**: SQL injection demo (Red) vs secure login (Blue)
- **Dashboard**: Account overview, recent transactions
- **Accounts page**: View account details (IDOR demo)
- **Transfer page**: Money transfers (race condition demo)
- **Transactions page**: Transaction history (XSS demo)
- **Profile page**: Update personal info (mass assignment demo)
- **Settings page**: User preferences (CSRF demo)

---

## Environment Configuration

### API Configuration

Both APIs can be configured through environment variables or config files.

**Create a `.env` file** in `backend/apps/securebank/`:

```bash
# Database
DATABASE_URL=sqlite:///securebank.db

# Red Team API
RED_API_PORT=5001
RED_API_DEBUG=True

# Blue Team API
BLUE_API_PORT=5002
BLUE_API_DEBUG=False
BLUE_API_RATE_LIMIT=100

# Security (Blue Team only)
SECRET_KEY=your-secret-key-here-change-in-production
CSRF_TOKEN_EXPIRY=3600
SESSION_TIMEOUT=1800

# Logging
LOG_LEVEL=INFO
LOG_FILE=securebank.log
```

**Why environment variables?** They let you configure the app without changing code - a security best practice.

### Frontend Configuration

Edit `frontend/apps/securebank/red/js/config.js`:

```javascript
const CONFIG = {
    API_BASE_URL: 'http://127.0.0.1:5001/api',  // Red Team API
    TIMEOUT: 5000,  // Request timeout in ms
    DEBUG: true
};
```

And `frontend/apps/securebank/blue/js/config.js`:

```javascript
const CONFIG = {
    API_BASE_URL: 'http://127.0.0.1:5002/api',  // Blue Team API
    TIMEOUT: 5000,
    DEBUG: false,  // Disable debug in secure version
    CSRF_ENABLED: true
};
```

---

## Verification and Testing

Let's verify everything is working correctly!

### Complete System Check

**You should now have running:**
1. Red Team API on port 5001
2. Blue Team API on port 5002
3. Red Team Frontend on port 8000
4. Blue Team Frontend on port 8001

**Check all services:**

```bash
# Check Red Team API
curl http://127.0.0.1:5001/api/health

# Check Blue Team API
curl http://127.0.0.1:5002/api/health

# Check if frontends are accessible
curl http://127.0.0.1:8000/login.html | head -n 5
curl http://127.0.0.1:8001/login.html | head -n 5
```

### Test Login Functionality

**Using the Red Team Frontend:**

1. Open http://127.0.0.1:8000/login.html
2. Enter credentials:
   - Username: `john.doe`
   - Password: `password123`
3. Click "Login"
4. You should be redirected to the dashboard

**Screenshot placeholder: [Successful login and dashboard view]**

### Test API Endpoints

**Test account retrieval:**

```bash
# First, login and get a session token
curl -X POST http://127.0.0.1:5001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john.doe","password":"password123"}'

# Response includes a token - save it
# Then use it to get account info:
curl http://127.0.0.1:5001/api/accounts/1 \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

---

## Platform-Specific Instructions

### Windows-Specific Setup

**Using PowerShell:**

```powershell
# Clone repository
git clone https://github.com/yourusername/aegisforgee.git
cd aegisforgee

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Initialize database
python backend\apps\securebank\database.py

# Run Red Team API (Terminal 1)
python backend\apps\securebank\securebank_red_api.py

# Run Blue Team API (Terminal 2 - new PowerShell window)
python backend\apps\securebank\securebank_blue_api.py
```

**Using Command Prompt:**

```cmd
REM Same steps, but use:
venv\Scripts\activate.bat
REM instead of PowerShell activation
```

**Common Windows Issues:**

1. **"Python not recognized"**: Add Python to PATH in System Environment Variables
2. **Execution policy errors**: Run as Administrator or use `Set-ExecutionPolicy`
3. **Port already in use**: Change ports in API files or kill conflicting process

### macOS-Specific Setup

**Using Terminal:**

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python (if not installed)
brew install python3

# Clone and setup
git clone https://github.com/yourusername/aegisforgee.git
cd aegisforgee
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize database
python backend/apps/securebank/database.py

# Run APIs
python backend/apps/securebank/securebank_red_api.py &
python backend/apps/securebank/securebank_blue_api.py &
```

**macOS-Specific Notes:**
- Use `python3` and `pip3` explicitly
- May need to allow Python through Firewall in Security preferences
- Use `lsof -i :5001` to check what's using a port

### Linux-Specific Setup

**On Ubuntu/Debian:**

```bash
# Update package lists
sudo apt update

# Install Python and pip (if not installed)
sudo apt install python3 python3-pip python3-venv git

# Clone repository
git clone https://github.com/yourusername/aegisforgee.git
cd aegisforgee

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python backend/apps/securebank/database.py

# Run APIs
python backend/apps/securebank/securebank_red_api.py &
python backend/apps/securebank/securebank_blue_api.py &
```

**On Fedora/RHEL:**

```bash
# Install dependencies
sudo dnf install python3 python3-pip git

# Same steps as Ubuntu from here
```

**Linux-Specific Notes:**
- Use `netstat -tulpn | grep :5001` to check port usage
- May need `sudo` for ports below 1024
- Check firewall: `sudo ufw allow 5001` and `sudo ufw allow 5002`

---

## Advanced Configuration

### Running on Custom Ports

Edit the API files to use different ports:

**backend/apps/securebank/securebank_red_api.py:**
```python
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9001, debug=True)  # Changed from 5001
```

**Remember to update frontend config files too!**

### Enabling HTTPS (SSL/TLS)

For testing HTTPS locally:

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem -keyout key.pem -days 365

# Run API with SSL
python backend/apps/securebank/securebank_blue_api.py \
  --certfile=cert.pem --keyfile=key.pem
```

**Note:** Browsers will warn about self-signed certificates - this is expected.

### Database Backup and Restore

**Backup database:**
```bash
cp backend/apps/securebank/securebank.db securebank_backup.db
```

**Restore database:**
```bash
cp securebank_backup.db backend/apps/securebank/securebank.db
```

**Reset database to default:**
```bash
rm backend/apps/securebank/securebank.db
python backend/apps/securebank/database.py
```

---

## Docker Installation (Alternative)

Prefer Docker? Here's a containerized setup:

### Prerequisites

- Docker Desktop installed
- Docker Compose installed

### Docker Setup

**Create `docker-compose.yml` in `backend/apps/securebank/`:**

```yaml
version: '3.8'

services:
  red-api:
    build: .
    ports:
      - "5001:5001"
    environment:
      - MODE=red
    volumes:
      - ./securebank.db:/app/securebank.db
    command: python securebank_red_api.py
    
  blue-api:
    build: .
    ports:
      - "5002:5002"
    environment:
      - MODE=blue
    volumes:
      - ./securebank.db:/app/securebank.db
    command: python securebank_blue_api.py
```

**Run with Docker:**
```bash
docker-compose up -d
```

**Benefits of Docker:**
- Consistent environment across all machines
- No Python version conflicts
- Easy to tear down and rebuild
- Great for classroom/workshop settings

---

## Common Setup Issues

### Issue: Port Already in Use

**Symptoms:**
```
OSError: [Errno 48] Address already in use
```

**Solution:**
```bash
# Find what's using the port
lsof -i :5001  # Mac/Linux
netstat -ano | findstr :5001  # Windows

# Kill the process
kill -9 <PID>  # Mac/Linux
taskkill /PID <PID> /F  # Windows

# Or change the port in API file
```

### Issue: Module Not Found

**Symptoms:**
```
ModuleNotFoundError: No module named 'flask'
```

**Solution:**
```bash
# Make sure virtual environment is activated
source venv/bin/activate  # You should see (venv) in prompt

# Reinstall requirements
pip install -r requirements.txt

# Verify installation
pip list | grep -i flask
```

### Issue: Database Not Found

**Symptoms:**
```
sqlite3.OperationalError: unable to open database file
```

**Solution:**
```bash
# Recreate database
python backend/apps/securebank/database.py

# Verify file exists
ls -l backend/apps/securebank/securebank.db
```

### Issue: CORS Errors in Browser

**Symptoms:**
```
Access to XMLHttpRequest blocked by CORS policy
```

**Solution:**
1. Make sure Flask-CORS is installed
2. Use the Python web server for frontend (not file://)
3. Check that API has CORS enabled in code

### Issue: Permission Denied

**Linux/Mac:**
```bash
chmod +x backend/apps/securebank/*.py
```

**Windows:**
- Run Command Prompt/PowerShell as Administrator

---

## Next Steps

Congratulations! 🎉 You've successfully set up SecureBank!

### What's Next?

1. **Read the User Guide** (`02_USER_GUIDE.md`)
   - Learn how to use all banking features
   - Understand the user interface
   - Practice normal banking operations

2. **Study the Architecture** (`03_ARCHITECTURE.md`)
   - Understand the technical design
   - Learn about the code structure
   - See how components interact

3. **Start Testing Vulnerabilities**
   - Try SQL injection on the login page
   - Test IDOR by accessing other users' accounts
   - Exploit the race condition in transfers

4. **Learn Remediation** (`15_REMEDIATION_GUIDE.md`)
   - Understand how to fix each vulnerability
   - Compare Red Team vs Blue Team code
   - Learn security best practices

### Learning Path Recommendation

**Week 1: Setup & Exploration**
- Complete this setup guide
- Explore both frontends
- Test basic functionality

**Week 2: Vulnerability Testing**
- One vulnerability per day
- Use Postman to test APIs
- Take notes on findings

**Week 3: Defense & Remediation**
- Study Blue Team implementations
- Practice writing secure code
- Run security scanning tools

**Week 4: Advanced Topics**
- Integrate Burp Suite
- Try automated exploitation
- Build your own security tests

### Getting Help

**Documentation:**
- User Guide: `02_USER_GUIDE.md`
- Architecture Guide: `03_ARCHITECTURE.md`
- Individual vulnerability guides: `04_*.md` through `09_*.md`
- Testing guides: `10_*.md` through `13_*.md`

**Community:**
- GitHub Issues: Report bugs or ask questions
- Discord: Join the AegisForge community
- Stack Overflow: Tag `aegisforge` or `securebank`

**Resources:**
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackTheBox: https://www.hackthebox.com/

### Remember

- **Practice safely**: Only test on your local instance
- **Learn actively**: Don't just follow guides - experiment!
- **Document findings**: Keep a security journal
- **Share knowledge**: Help others in the community
- **Stay curious**: Security is a continuous learning journey

---

**Happy Learning! 🚀**

*Built with ❤️ by the AegisForge Team*
