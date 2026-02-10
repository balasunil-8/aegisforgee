# ⚡ AegisForge Quick Start Guide

**Get up and running in 5 minutes or less!**

---

## ✅ Prerequisites Checklist

Before installing AegisForge, ensure you have:

- [ ] **Python 3.8+** installed ([Download](https://www.python.org/downloads/))
- [ ] **pip** package manager (included with Python)
- [ ] **3GB+ free disk space**
- [ ] **4GB+ RAM** available
- [ ] **Ports 5000-5003** available
- [ ] **Internet connection** (for dependency installation)
- [ ] **Terminal/Command Prompt** access

### Quick Version Check

```bash
# Check Python version
python --version  # Should show 3.8.0 or higher

# Check pip
pip --version
```

If Python is not installed or version is below 3.8, install it first:
- **Windows**: Download from [python.org](https://www.python.org/downloads/)
- **Linux**: `sudo apt install python3.10 python3-pip`
- **macOS**: `brew install python@3.10`

---

## 🚀 One-Command Installation

### Windows

```batch
# Open Command Prompt or PowerShell as Administrator
cd C:\
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
scripts\windows\install.bat
```

The installer will automatically:
✅ Check Python version  
✅ Verify disk space  
✅ Install all dependencies  
✅ Initialize SecureBank database  
✅ Initialize ShopVuln database  
✅ Run health check  
✅ Display success message  

**Installation time**: 3-5 minutes

---

### Linux / macOS

```bash
# Open Terminal
cd ~
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
chmod +x scripts/linux/install.sh
./scripts/linux/install.sh
```

The installer will automatically:
✅ Check Python version  
✅ Verify disk space  
✅ Create virtual environment  
✅ Install dependencies  
✅ Initialize databases  
✅ Run health check  

**Installation time**: 3-5 minutes

---

### Manual Installation (Alternative)

If automated scripts don't work:

```bash
# 1. Clone repository
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee

# 2. Create virtual environment
python -m venv .venv

# 3. Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Initialize databases
python backend/apps/securebank/database.py
python backend/apps/shopvuln/database.py

# 6. Verify installation
python scripts/python/health_check.py
```

---

## 🎯 Launch Commands

### Option 1: Start All Applications (Recommended)

**Windows**:
```batch
scripts\windows\start_all_apps.bat
```

**Linux/macOS**:
```bash
./scripts/linux/start_all_apps.sh
```

This will start:
- 🔴 **SecureBank Red** (vulnerable) - Port 5000
- 🔵 **SecureBank Blue** (secure) - Port 5001
- 🛒 **ShopVuln Red** (vulnerable) - Port 5002
- 🛒 **ShopVuln Blue** (secure) - Port 5003

Your browser will automatically open to the applications!

---

### Option 2: Python Launcher (GUI)

```bash
python scripts/python/launcher.py
```

Interactive menu to:
1. Start individual applications
2. Start all applications
3. Stop applications
4. View status
5. Run health check

---

### Option 3: Start Individual Applications

**SecureBank Red Team (Port 5000)**:
```bash
python backend/apps/securebank/securebank_red_api.py
```

**SecureBank Blue Team (Port 5001)**:
```bash
python backend/apps/securebank/securebank_blue_api.py
```

**ShopVuln Red Team (Port 5002)**:
```bash
python backend/apps/shopvuln/shopvuln_red_api.py
```

**ShopVuln Blue Team (Port 5003)**:
```bash
python backend/apps/shopvuln/shopvuln_blue_api.py
```

---

## 🎯 Your First Vulnerability Demo

Let's exploit a SQL Injection vulnerability in under 2 minutes!

### Step 1: Start SecureBank Red Team

```bash
python backend/apps/securebank/securebank_red_api.py
```

Wait for: `Running on http://127.0.0.1:5000`

---

### Step 2: Test Normal Login (Baseline)

```bash
curl "http://localhost:5000/api/red/securebank/users/login?username=admin&password=admin123"
```

**Expected Response**:
```json
{
  "success": true,
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin"
  }
}
```

---

### Step 3: Exploit SQL Injection (Boolean-Based)

```bash
curl "http://localhost:5000/api/red/securebank/users/login?username=admin'--&password=anything"
```

**What happened?**
- The `'--` sequence comments out the password check
- SQL becomes: `SELECT * FROM users WHERE username='admin'--' AND password='...'`
- Everything after `--` is ignored
- You're logged in as admin **WITHOUT knowing the password**!

**Expected Response**:
```json
{
  "success": true,
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin"
  },
  "vulnerability": "SQL Injection - Authentication Bypass"
}
```

---

### Step 4: Compare with Secure Implementation

Stop the Red Team (Ctrl+C) and start Blue Team:

```bash
python backend/apps/securebank/securebank_blue_api.py
```

Try the same attack:

```bash
curl "http://localhost:5001/api/blue/securebank/users/login?username=admin'--&password=anything"
```

**Expected Response**:
```json
{
  "error": "Invalid input detected",
  "blocked": true,
  "reason": "SQL injection pattern detected",
  "status": 400
}
```

**Defense mechanism**: Input validation detected and blocked the SQL injection pattern!

---

## 🎓 Next Steps

Congratulations! You've successfully:
✅ Installed AegisForge  
✅ Launched applications  
✅ Exploited your first vulnerability  
✅ Tested secure defense  

### Continue Your Learning Journey

#### 1. **Explore More Vulnerabilities** (30 mins)

Try different attack types:

**XSS (Cross-Site Scripting)**:
```bash
curl "http://localhost:5000/api/red/securebank/search?query=<script>alert('XSS')</script>"
```

**IDOR (Insecure Direct Object Reference)**:
```bash
curl "http://localhost:5000/api/red/securebank/users/1"  # Access other user's data
```

**Command Injection**:
```bash
curl "http://localhost:5000/api/red/securebank/ping?host=127.0.0.1;whoami"
```

---

#### 2. **Use Professional Tools** (1 hour)

**Import Postman Collection**:
1. Open Postman
2. Click **Import**
3. Select `postman/AegisForge_Complete_Collection.json`
4. Start testing with 141+ pre-built requests!

**Guide**: [POSTMAN_GUIDE.md](POSTMAN_GUIDE.md)

---

#### 3. **Complete CTF Challenges** (2-4 hours)

Start the CTF leaderboard:

```bash
python aegisforge_leaderboard.py
```

View challenges:
```bash
curl http://localhost:5002/api/ctf/challenges
```

**Guide**: See CTF challenges in `ctf_challenges/` directory

---

#### 4. **Study Security Documentation** (Ongoing)

Essential reads:
- [SECURITY_COMPARISON.md](SECURITY_COMPARISON.md) - Red vs Blue analysis
- [API_DOCUMENTATION.md](API_DOCUMENTATION.md) - All endpoints documented
- [OWASP_COVERAGE_MATRIX.md](OWASP_COVERAGE_MATRIX.md) - Complete vulnerability list

---

#### 5. **Master Testing Tools** (1 week)

Follow these guides:
- **Burp Suite**: [BURP_SUITE_GUIDE.md](BURP_SUITE_GUIDE.md)
- **OWASP ZAP**: [OWASP_ZAP_GUIDE.md](OWASP_ZAP_GUIDE.md)
- **SQLMap**: [SQLMAP_GUIDE.md](SQLMAP_GUIDE.md)
- **FFUF**: [FFUF_GUIDE.md](FFUF_GUIDE.md)

---

## 🛑 Stopping Applications

**Windows**:
```batch
scripts\windows\stop_all_apps.bat
```

**Linux/macOS**:
```bash
./scripts/linux/stop_all_apps.sh
```

**Manual**:
- Press `Ctrl+C` in each terminal window running an application

---

## ⚠️ Troubleshooting

### Port Already in Use

**Error**: `Address already in use: Port 5000`

**Solution**:
```bash
# Windows - Find and kill process
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/macOS - Find and kill process
lsof -ti:5000 | xargs kill -9
```

---

### Import Error: Module Not Found

**Error**: `ModuleNotFoundError: No module named 'flask'`

**Solution**:
```bash
# Ensure virtual environment is activated
# Then reinstall dependencies
pip install -r requirements.txt
```

---

### Database Not Found

**Error**: `Database file not found`

**Solution**:
```bash
# Reinitialize databases
python backend/apps/securebank/database.py
python backend/apps/shopvuln/database.py
```

---

### Python Version Too Old

**Error**: `Python 3.8 or higher required`

**Solution**:
1. Uninstall old Python
2. Download Python 3.10+ from [python.org](https://www.python.org/downloads/)
3. Reinstall AegisForge

---

## 📚 More Help

- **Detailed Troubleshooting**: [docs/troubleshooting/common-issues.md](docs/troubleshooting/common-issues.md)
- **Full Installation Guide**: [INSTALL.md](INSTALL.md)
- **Community Support**: [GitHub Discussions](https://github.com/balasunil-8/aegisforgee/discussions)

---

## 🎯 Recommended Learning Path

| Week | Focus | Time | Completion |
|------|-------|------|------------|
| 1 | Setup + Basic SQLi/XSS | 5 hours | 🔰 Beginner |
| 2 | All OWASP Web vulnerabilities | 10 hours | 🔰 Beginner |
| 3 | Postman + Burp Suite | 8 hours | ⚡ Intermediate |
| 4 | CTF Challenges (Easy + Medium) | 12 hours | ⚡ Intermediate |
| 5 | Advanced tools (SQLMap, FFUF) | 10 hours | 🚀 Advanced |
| 6 | Blue Team defenses + Hard CTFs | 15 hours | 🚀 Advanced |

**Total**: ~60 hours to master the complete platform

---

## 🎮 Test Credentials Reminder

| Application | Username | Password | Role |
|-------------|----------|----------|------|
| SecureBank | `admin` | `admin123` | Administrator |
| SecureBank | `alice` | `alice123` | User |
| ShopVuln | `admin` | `admin123` | Admin |
| ShopVuln | `customer` | `customer123` | Customer |

---

## ✅ Health Check

Verify everything is working:

```bash
python scripts/python/health_check.py
```

Expected output:
```
✅ Python Version: 3.10.x
✅ Dependencies: All installed
✅ Databases: Both initialized
✅ Ports: 5000-5003 available
✅ Disk Space: 3.5GB free
✅ System Ready: YES
```

---

**🎉 You're all set! Happy ethical hacking!**

For detailed documentation, see [README.md](README.md) and [INSTALL.md](INSTALL.md).

Need help? Check [docs/troubleshooting/](docs/troubleshooting/) or open an issue on GitHub.

---

*Last Updated: February 2024*  
*AegisForge v2.0 - Quick Start Guide*
