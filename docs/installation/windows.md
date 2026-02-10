# 🪟 Windows Installation Guide

Complete installation guide for AegisForge on Windows 10/11.

---

## 📋 Prerequisites

### System Requirements
- **OS**: Windows 10 (1809+) or Windows 11
- **RAM**: 4GB minimum, 8GB recommended
- **Disk Space**: 2GB free space
- **Internet**: Required for downloading dependencies

### Required Software

#### Python 3.10+
1. Download from [python.org](https://www.python.org/downloads/)
2. Run installer
3. ✅ **Important**: Check "Add Python to PATH"
4. Select "Install Now"

Verify installation:
```powershell
python --version
# Should show: Python 3.10.x or higher
```

#### Git for Windows
1. Download from [git-scm.com](https://git-scm.com/download/win)
2. Run installer with default options
3. Verify:
```powershell
git --version
```

---

## 🚀 Installation Methods

### Method 1: Quick Start (Recommended)

#### Step 1: Clone Repository
```powershell
# Open PowerShell or Command Prompt
cd C:\
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
```

#### Step 2: Run Launcher
```powershell
# Double-click LaunchSecurityForge.bat
# OR run from command line:
.\LaunchSecurityForge.bat
```

The launcher will:
- Create virtual environment
- Install dependencies
- Initialize database
- Start the application

#### Step 3: Access Application
Open browser to: **http://localhost:5000**

---

### Method 2: Manual Installation

#### Step 1: Clone Repository
```powershell
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
```

#### Step 2: Create Virtual Environment
```powershell
# Create venv
python -m venv venv

# Activate (PowerShell)
.\venv\Scripts\Activate.ps1

# If you get execution policy error:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Alternative: Use Command Prompt activation
venv\Scripts\activate.bat
```

#### Step 3: Install Dependencies
```powershell
# Upgrade pip first
python -m pip install --upgrade pip

# Install core requirements
pip install -r requirements.txt

# Optional: Production features
pip install -r requirements_pro.txt
```

#### Step 4: Configure Environment
```powershell
# Copy environment template
copy .env.example .env

# Edit with Notepad
notepad .env
```

Key settings:
```ini
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///instance/aegisforge.db
DEBUG=True
```

#### Step 5: Initialize Database
```powershell
python init_db.py
```

#### Step 6: Start Application
```powershell
# Start API server
python aegisforge_api.py

# Server will start on http://localhost:5000
```

---

### Method 3: Docker Desktop

#### Prerequisites
- Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
- Enable WSL 2 backend (recommended)

#### Steps
```powershell
# Clone repository
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee

# Start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Access application
# http://localhost:5000
```

#### Docker Commands
```powershell
# Stop containers
docker-compose down

# Rebuild after changes
docker-compose build --no-cache

# View running containers
docker ps
```

---

## 🔧 Configuration

### Environment Variables

Edit `.env` file:

```ini
# Flask Settings
FLASK_ENV=development
SECRET_KEY=generate-secure-random-key
DEBUG=True

# Database (SQLite default)
DATABASE_URL=sqlite:///instance/aegisforge.db

# PostgreSQL (advanced)
# DATABASE_URL=postgresql://user:pass@localhost/aegisforge

# Redis (optional)
# REDIS_URL=redis://localhost:6379/0

# Security
JWT_SECRET_KEY=your-jwt-secret
RATE_LIMIT_ENABLED=True

# Features
CTF_MODE=True
LEADERBOARD_ENABLED=True
```

### PostgreSQL Setup (Optional)

1. **Install PostgreSQL**:
   - Download from [postgresql.org](https://www.postgresql.org/download/windows/)
   - Run installer, note password

2. **Create Database**:
```powershell
# Using psql
psql -U postgres
CREATE DATABASE aegisforge;
\q
```

3. **Update .env**:
```ini
DATABASE_URL=postgresql://postgres:yourpassword@localhost/aegisforge
```

4. **Initialize**:
```powershell
python init_db.py
```

---

## ✅ Verification

### Test Installation

```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run test
python test_endpoints.py

# Check API health
curl http://localhost:5000/api/health
# Or use browser
```

### Test CTF Mode

```powershell
# Start CTF manager
python ctf_manager.py

# View leaderboard
curl http://localhost:5000/api/leaderboard
```

---

## 🔍 Troubleshooting

### Python Not Found

**Problem**: `'python' is not recognized`

**Solution**:
1. Reinstall Python with "Add to PATH" checked
2. OR add manually:
   - Search "Environment Variables" in Windows
   - Edit PATH
   - Add: `C:\Users\YourName\AppData\Local\Programs\Python\Python310`
   - Add: `C:\Users\YourName\AppData\Local\Programs\Python\Python310\Scripts`

### Execution Policy Error

**Problem**: `cannot be loaded because running scripts is disabled`

**Solution**:
```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Alternative: Use .bat file instead of .ps1
venv\Scripts\activate.bat
```

### Port 5000 Already in Use

**Problem**: `Address already in use`

**Solution**:
```powershell
# Find process using port
netstat -ano | findstr :5000

# Kill process (replace PID)
taskkill /PID 1234 /F

# Or change port
$env:FLASK_RUN_PORT=8000
python aegisforge_api.py
```

### SSL Certificate Error

**Problem**: `SSL: CERTIFICATE_VERIFY_FAILED`

**Solution**:
```powershell
# Install certificates
python -m pip install --upgrade certifi

# Or disable SSL verification (not recommended)
$env:PYTHONHTTPSVERIFY=0
```

### Module Not Found Errors

**Problem**: `ModuleNotFoundError: No module named 'flask'`

**Solution**:
```powershell
# Ensure venv is activated
.\venv\Scripts\Activate.ps1

# Reinstall dependencies
pip install -r requirements.txt

# Verify installation
pip list
```

### Permission Errors

**Problem**: Access denied errors

**Solution**:
1. Run PowerShell/CMD as Administrator
2. Check antivirus isn't blocking
3. Ensure write permissions on aegisforgee folder

### SQLite Database Locked

**Problem**: `database is locked`

**Solution**:
```powershell
# Close all Python processes
tasklist | findstr python
taskkill /IM python.exe /F

# Delete database and reinitialize
del instance\aegisforge.db
python init_db.py
```

### Firewall Blocking

**Problem**: Can't access http://localhost:5000

**Solution**:
1. Add Python to Windows Firewall exceptions
2. Windows Defender Firewall → Allow an app
3. Browse to: `C:\Users\YourName\aegisforgee\venv\Scripts\python.exe`
4. Check both Private and Public

---

## 🎯 Windows-Specific Tips

### PowerShell vs Command Prompt

**PowerShell** (Recommended):
```powershell
.\venv\Scripts\Activate.ps1
$env:FLASK_ENV="development"
```

**Command Prompt**:
```cmd
venv\Scripts\activate.bat
set FLASK_ENV=development
```

### Windows Terminal

Install [Windows Terminal](https://aka.ms/terminal) for better experience:
- Multiple tabs
- Better colors
- Unicode support
- Integration with WSL

### Visual Studio Code

Recommended IDE for Windows:
1. Install from [code.visualstudio.com](https://code.visualstudio.com/)
2. Install Python extension
3. Select interpreter: `.\venv\Scripts\python.exe`
4. Use integrated terminal

---

## 📦 Optional Tools

### Postman
- Download from [postman.com](https://www.postman.com/downloads/)
- Import collection from `postman/` directory
- Configure environment

### OWASP ZAP
- Download from [zaproxy.org](https://www.zaproxy.org/download/)
- See `OWASP_ZAP_GUIDE.md` for integration

### Burp Suite Community
- Download from [portswigger.net](https://portswigger.net/burp/communitydownload)
- See `BURP_SUITE_GUIDE.md` for setup

---

## 🔄 Updates

### Update AegisForge

```powershell
cd C:\aegisforgee

# Pull latest changes
git pull origin main

# Activate venv
.\venv\Scripts\Activate.ps1

# Update dependencies
pip install -r requirements.txt --upgrade

# Update database
python init_db.py
```

---

## 🗑️ Uninstallation

```powershell
# Stop any running processes
taskkill /IM python.exe /F

# Deactivate venv
deactivate

# Delete folder
cd C:\
rmdir /s /q aegisforgee
```

---

## 📚 Next Steps

- **First Steps**: See [docs/getting-started/first-time-setup.md](../getting-started/first-time-setup.md)
- **API Testing**: Review [API_DOCUMENTATION.md](../../API_DOCUMENTATION.md)
- **CTF Challenges**: Start with beginner challenges
- **Tool Setup**: Configure Postman, Burp, or ZAP

---

## 🆘 Getting Help

- **Documentation**: [README.md](../../README.md)
- **Common Issues**: [docs/troubleshooting/common-issues.md](../troubleshooting/common-issues.md)
- **GitHub Issues**: [Report a bug](https://github.com/balasunil-8/aegisforgee/issues)

---

**Installation complete! Ready to start? Visit http://localhost:5000** 🚀
