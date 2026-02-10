# ⚡ AegisForge Quick Start Guide

**Get up and running in 5 minutes!**

---

## ✅ Prerequisites Checklist

Before starting, make sure you have:

- [ ] **Python 3.8 or higher** installed
  - Check: `python --version` or `python3 --version`
- [ ] **4GB RAM minimum** (8GB recommended)
- [ ] **3GB disk space** available
- [ ] **Internet connection** (for initial setup)
- [ ] **Administrator/sudo privileges** (for installation)

**Operating Systems Supported:**
- ✅ Windows 10/11
- ✅ Linux (Ubuntu 20.04+, Debian, Fedora, etc.)
- ✅ macOS 11+

---

## 🚀 One-Command Installation

### Windows

1. **Open Command Prompt as Administrator**
2. **Navigate to the project directory**
   ```batch
   cd C:\path\to\aegisforgee
   ```
3. **Run the installer**
   ```batch
   scripts\windows\install.bat
   ```

### Linux/Mac

1. **Open Terminal**
2. **Navigate to the project directory**
   ```bash
   cd /path/to/aegisforgee
   ```
3. **Make script executable and run**
   ```bash
   chmod +x scripts/linux/install.sh
   ./scripts/linux/install.sh
   ```

**What the installer does:**
- ✅ Verifies Python 3.8+ is installed
- ✅ Installs required Python packages
- ✅ Initializes SecureBank database
- ✅ Initializes ShopVuln database
- ✅ Seeds test data
- ✅ Runs system health check
- ✅ Displays next steps

**Expected output:**
```
AegisForge Installation v1.0
✓ Python 3.10 detected
✓ Dependencies installed
✓ SecureBank database initialized
✓ ShopVuln database initialized
✓ System health check passed
Installation complete!
```

---

## 🎮 Launch Applications

### Windows

**Open Command Prompt and run:**
```batch
scripts\windows\start_all_apps.bat
```

### Linux/Mac

**Open Terminal and run:**
```bash
./scripts/linux/start_all_apps.sh
```

**What happens:**
- 🏦 SecureBank Red starts on port 5000
- 🏦 SecureBank Blue starts on port 5001
- 🛒 ShopVuln Red starts on port 5002
- 🛒 ShopVuln Blue starts on port 5003
- 🌐 Your browser opens automatically

**Expected output:**
```
Starting AegisForge Applications...
✓ SecureBank Red API running on port 5000
✓ SecureBank Blue API running on port 5001
✓ ShopVuln Red API running on port 5002
✓ ShopVuln Blue API running on port 5003

All applications ready!
```

---

## 🌐 Access Your Applications

### Application URLs

| Application | URL | Description |
|------------|-----|-------------|
| **SecureBank Red** | http://localhost:5000 | 🔴 Vulnerable banking app |
| **SecureBank Blue** | http://localhost:5001 | 🔵 Secure banking app |
| **ShopVuln Red** | http://localhost:5002 | 🔴 Vulnerable e-commerce |
| **ShopVuln Blue** | http://localhost:5003 | 🔵 Secure e-commerce |

### Test User Accounts

| Username | Password | Role | Use Case |
|----------|----------|------|----------|
| `alice` | `password123` | Standard User | Basic testing |
| `bob` | `securepass456` | Standard User | Multi-user scenarios |
| `admin` | `admin123` | Administrator | Admin functionality |

**Note:** These are intentional test credentials for the vulnerable "Red" applications.

---

## 🎯 Your First SQL Injection Demo

**Let's test a SQL injection vulnerability in 60 seconds!**

### Step 1: Access SecureBank Red
Open http://localhost:5000 in your browser

### Step 2: Find the Login Page
Navigate to the login endpoint or use a tool like Postman

### Step 3: Test SQL Injection

**Using cURL:**
```bash
curl -X POST http://localhost:5000/api/red/securebank/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"admin' OR '1'='1\", \"password\": \"anything\"}"
```

**Using Postman:**
1. Create new POST request
2. URL: `http://localhost:5000/api/red/securebank/login`
3. Body (JSON):
   ```json
   {
     "username": "admin' OR '1'='1",
     "password": "anything"
   }
   ```
4. Send request

**Expected Result:**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "administrator"
  }
}
```

**🎉 Congratulations!** You just exploited your first SQL injection vulnerability!

### Step 4: Compare with Secure Version

Try the same attack on SecureBank Blue (port 5001):
```bash
curl -X POST http://localhost:5001/api/blue/securebank/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"admin' OR '1'='1\", \"password\": \"anything\"}"
```

**Expected Result:**
```json
{
  "error": "Invalid credentials"
}
```

**The Blue (secure) version uses parameterized queries and input validation!**

---

## 📊 Verify System Health

Run the health check anytime to verify everything is working:

**Windows:**
```batch
python scripts\python\health_check.py
```

**Linux/Mac:**
```bash
python3 scripts/python/health_check.py
```

**Health Check Output:**
```
==================================================
  AegisForge Health Check
==================================================

✓ Python 3.10
✓ Dependencies installed
✓ SecureBank database found
✓ ShopVuln database found

Port Availability:
  Port 5000 (SecureBank Red): In use
  Port 5001 (SecureBank Blue): In use
  Port 5002 (ShopVuln Red): In use
  Port 5003 (ShopVuln Blue): In use

Results: 4/4 checks passed

✓ System ready!
```

---

## 🛑 Stop All Applications

When you're done testing:

**Windows:**
```batch
scripts\windows\stop_all_apps.bat
```

**Linux/Mac:**
```bash
./scripts/linux/stop_all_apps.sh
```

---

## 📚 Next Steps

Now that you're up and running, here's what to explore next:

### 1. 🎓 Learn the Basics
**Recommended:** [First Time Setup Guide](docs/apps/first-time-setup.md)
- Understand the dual-mode architecture
- Learn about Red vs Blue teams
- Explore the platform features

### 2. 🔍 Explore More Vulnerabilities
**Recommended:** [Your First Vulnerability Guide](docs/apps/your-first-vulnerability.md)
- XSS (Cross-Site Scripting)
- CSRF (Cross-Site Request Forgery)
- IDOR (Insecure Direct Object Reference)
- Authentication bypass

### 3. 🛠️ Use Security Tools
**Recommended:** [Tools Integration Guide](TOOLS_INTEGRATION_GUIDE.md)
- **Burp Suite** - [Setup Guide](BURP_SUITE_GUIDE.md)
- **OWASP ZAP** - [Setup Guide](OWASP_ZAP_GUIDE.md)
- **SQLmap** - [Setup Guide](SQLMAP_GUIDE.md)
- **Postman** - [API Testing Guide](POSTMAN_GUIDE.md)

### 4. 🎮 Try CTF Challenges
**Recommended:** Visit http://localhost:5000/ctf (when running)
- 18 progressive challenges
- Easy (100 pts) → Medium (200 pts) → Hard (300 pts)
- Real-time leaderboard
- Instant feedback

### 5. 📖 Read Complete Documentation
**Recommended:** Explore the [docs/](docs/) directory
- 650+ pages of security guides
- Vulnerability deep-dives
- Exploitation techniques
- Remediation best practices

---

## 🐛 Troubleshooting

### Problem: Python not found
**Solution:**
- Install Python 3.8+ from [python.org](https://www.python.org/downloads/)
- Make sure to check "Add Python to PATH" during installation
- Restart terminal/command prompt after installation

### Problem: Port already in use
**Solution:**
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:5000 | xargs kill -9
```

### Problem: Database initialization fails
**Solution:**
```bash
# Delete existing databases
rm backend/apps/securebank/securebank.db
rm backend/apps/shopvuln/shopvuln.db

# Re-run installation
scripts/windows/install.bat  # Windows
./scripts/linux/install.sh    # Linux/Mac
```

### Problem: Modules not found
**Solution:**
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Problem: Permission denied (Linux/Mac)
**Solution:**
```bash
# Make scripts executable
chmod +x scripts/linux/*.sh

# Run with sudo if needed
sudo ./scripts/linux/install.sh
```

**For more help:** [Troubleshooting Guide](docs/installation/troubleshooting.md)

---

## 🎯 Quick Reference

### Common Commands

| Task | Windows | Linux/Mac |
|------|---------|-----------|
| Install | `scripts\windows\install.bat` | `./scripts/linux/install.sh` |
| Start All | `scripts\windows\start_all_apps.bat` | `./scripts/linux/start_all_apps.sh` |
| Stop All | `scripts\windows\stop_all_apps.bat` | `./scripts/linux/stop_all_apps.sh` |
| Health Check | `python scripts\python\health_check.py` | `python3 scripts/python/health_check.py` |
| Reset DBs | `scripts\windows\init_databases.bat` | `./scripts/linux/init_databases.sh` |

### Important Endpoints

**SecureBank Red API:**
- Login: `POST /api/red/securebank/login`
- Transfer: `POST /api/red/securebank/transfer`
- Profile: `GET /api/red/securebank/profile`

**ShopVuln Red API:**
- Login: `POST /api/red/shopvuln/login`
- Products: `GET /api/red/shopvuln/products`
- Cart: `POST /api/red/shopvuln/cart`

**Full API Documentation:** [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

---

## 💡 Pro Tips

1. **Use Incognito Mode** - Avoid cache/session issues
2. **Monitor Terminal Output** - See real-time request logs
3. **Test Both Red & Blue** - Understand the security differences
4. **Use Burp Suite** - Intercept and modify requests
5. **Read Error Messages** - They often contain exploitation hints

---

## 🤝 Need Help?

- 📖 **Documentation**: [docs/](docs/)
- 🐛 **Issues**: [GitHub Issues](https://github.com/balasunil-8/aegisforgee/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/balasunil-8/aegisforgee/discussions)
- 📧 **Contact**: See repository for contact info

---

<div align="center">

**🎉 You're ready to start your security testing journey!**

**[Full Documentation](README.md)** • **[Roadmap](ROADMAP.md)** • **[Contributing](CONTRIBUTING.md)**

</div>
