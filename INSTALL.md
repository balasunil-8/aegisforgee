# 📦 AegisForge Installation Guide

Complete installation instructions for all platforms.

---

## 📋 Table of Contents

- [System Requirements](#system-requirements)
- [Pre-Installation](#pre-installation)
- [Windows Installation](#windows-installation)
- [Linux Installation](#linux-installation)
- [macOS Installation](#macos-installation)
- [Manual Installation](#manual-installation)
- [Verification](#verification)
- [Post-Installation](#post-installation)
- [Troubleshooting](#troubleshooting)

---

## 💻 System Requirements

### Minimum Requirements
- **Operating System**: Windows 10+, Linux (Ubuntu 20.04+), macOS 11+
- **Python**: 3.8 or higher
- **RAM**: 4GB
- **Disk Space**: 3GB
- **Internet**: Required for initial setup

### Recommended Requirements
- **Python**: 3.10 or higher
- **RAM**: 8GB
- **Disk Space**: 5GB
- **Ports**: 5000-5003 available

---

## 🔍 Pre-Installation

### 1. Check Python Installation

**Windows:**
```batch
python --version
```

**Linux/Mac:**
```bash
python3 --version
```

**Expected output:** `Python 3.8.x` or higher

### 2. Install Python (if needed)

**Windows:**
1. Download from [python.org](https://www.python.org/downloads/)
2. Run installer
3. ✅ Check "Add Python to PATH"
4. Click "Install Now"

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

**macOS:**
```bash
brew install python3
```

### 3. Clone the Repository

```bash
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
```

---

## 🪟 Windows Installation

### Automated Installation (Recommended)

1. **Open Command Prompt as Administrator**
   - Press `Win + X`
   - Select "Command Prompt (Admin)" or "Windows Terminal (Admin)"

2. **Navigate to project directory**
   ```batch
   cd C:\path\to\aegisforgee
   ```

3. **Run installer**
   ```batch
   scripts\windows\install.bat
   ```

4. **Wait for completion** (~5 minutes)
   - Installs dependencies
   - Initializes databases
   - Runs health check

### Manual Installation

If automated installation fails:

```batch
:: Install dependencies
pip install -r requirements.txt

:: Initialize SecureBank
cd backend\apps\securebank
python database.py
python seed_data.py
cd ..\..\..

:: Initialize ShopVuln
cd backend\apps\shopvuln
python database.py
python seed_data.py
cd ..\..\..

:: Health check
python scripts\python\health_check.py
```

**Detailed guide:** [Windows Installation Guide](docs/installation/windows-install.md)

---

## 🐧 Linux Installation

### Automated Installation (Recommended)

1. **Open Terminal**

2. **Navigate to project directory**
   ```bash
   cd /path/to/aegisforgee
   ```

3. **Make installer executable**
   ```bash
   chmod +x scripts/linux/install.sh
   ```

4. **Run installer**
   ```bash
   ./scripts/linux/install.sh
   ```

5. **Wait for completion** (~5 minutes)

### Manual Installation

If automated installation fails:

```bash
# Install dependencies
pip3 install -r requirements.txt

# Initialize SecureBank
cd backend/apps/securebank
python3 database.py
python3 seed_data.py
cd ../../..

# Initialize ShopVuln
cd backend/apps/shopvuln
python3 database.py
python3 seed_data.py
cd ../../..

# Health check
python3 scripts/python/health_check.py
```

**Detailed guide:** [Linux Installation Guide](docs/installation/linux-install.md)

---

## 🍎 macOS Installation

### Automated Installation (Recommended)

Same as Linux installation:

```bash
cd /path/to/aegisforgee
chmod +x scripts/linux/install.sh
./scripts/linux/install.sh
```

### Using Homebrew

```bash
# Install Python if needed
brew install python3

# Follow automated installation steps above
```

**Detailed guide:** [macOS Installation Guide](docs/installation/macos-install.md)

---

## 🔧 Manual Installation

For advanced users or troubleshooting:

### Step 1: Create Virtual Environment (Optional but Recommended)

**Windows:**
```batch
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Initialize Databases

**SecureBank:**
```bash
cd backend/apps/securebank
python database.py      # or python3
python seed_data.py
cd ../../..
```

**ShopVuln:**
```bash
cd backend/apps/shopvuln
python database.py      # or python3
python seed_data.py
cd ../../..
```

### Step 4: Verify Installation

```bash
python scripts/python/health_check.py
```

---

## ✅ Verification

### Run Health Check

**Windows:**
```batch
python scripts\python\health_check.py
```

**Linux/Mac:**
```bash
python3 scripts/python/health_check.py
```

### Expected Output

```
==================================================
  AegisForge Health Check
==================================================

✓ Python 3.10
✓ All dependencies installed
✓ SecureBank database found (124.5 KB)
✓ ShopVuln database found (156.2 KB)
✓ Disk space: 25GB available

Port Availability:
  Port 5000 (SecureBank Red): Available
  Port 5001 (SecureBank Blue): Available
  Port 5002 (ShopVuln Red): Available
  Port 5003 (ShopVuln Blue): Available

==================================================
Results: 4/4 checks passed
==================================================

✓ System ready! All checks passed.
```

---

## 🚀 Post-Installation

### 1. Start Applications

**Windows:**
```batch
scripts\windows\start_all_apps.bat
```

**Linux/Mac:**
```bash
./scripts/linux/start_all_apps.sh
```

### 2. Access Applications

Open your browser and navigate to:
- http://localhost:5000 (SecureBank Red)
- http://localhost:5001 (SecureBank Blue)
- http://localhost:5002 (ShopVuln Red)
- http://localhost:5003 (ShopVuln Blue)

### 3. Test Login

Use these credentials:
- **Username:** alice
- **Password:** password123

### 4. Explore Documentation

- [Quick Start Guide](QUICKSTART.md)
- [First Time Setup](docs/getting-started/first-time-setup.md)
- [Your First Vulnerability](docs/getting-started/your-first-vulnerability.md)

---

## 🐛 Troubleshooting

### Issue: Python not found

**Solution:**
- Ensure Python 3.8+ is installed
- Check PATH environment variable
- Restart terminal/command prompt

### Issue: Port already in use

**Check what's using the port:**

**Windows:**
```batch
netstat -ano | findstr :5000
```

**Linux/Mac:**
```bash
lsof -ti:5000
```

**Kill the process:**

**Windows:**
```batch
taskkill /PID <PID> /F
```

**Linux/Mac:**
```bash
kill -9 <PID>
```

### Issue: Permission denied (Linux/Mac)

**Solution:**
```bash
chmod +x scripts/linux/*.sh
# Or run with sudo if needed
sudo ./scripts/linux/install.sh
```

### Issue: Module not found

**Solution:**
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Or use virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

### Issue: Database initialization fails

**Solution:**
```bash
# Delete existing databases
rm backend/apps/securebank/securebank.db
rm backend/apps/shopvuln/shopvuln.db

# Reinitialize
scripts/windows/init_databases.bat  # Windows
./scripts/linux/init_databases.sh   # Linux/Mac
```

### Issue: SSL Certificate Error

**Solution:**
```bash
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

**For more troubleshooting:** [Troubleshooting Guide](docs/installation/troubleshooting.md)

---

## 📚 Next Steps

After successful installation:

1. **Learn the Basics**
   - Read [QUICKSTART.md](QUICKSTART.md)
   - Follow [First Time Setup](docs/getting-started/first-time-setup.md)

2. **Try Your First Vulnerability**
   - [SQL Injection Tutorial](docs/getting-started/your-first-vulnerability.md)

3. **Explore Security Tools**
   - [Burp Suite Guide](BURP_SUITE_GUIDE.md)
   - [OWASP ZAP Guide](OWASP_ZAP_GUIDE.md)
   - [SQLmap Guide](SQLMAP_GUIDE.md)

4. **Take CTF Challenges**
   - Visit http://localhost:5000/ctf

---

## 🆘 Getting Help

- 📖 **Documentation**: [docs/](docs/)
- 🐛 **Report Issues**: [GitHub Issues](https://github.com/balasunil-8/aegisforgee/issues)
- 💬 **Ask Questions**: [GitHub Discussions](https://github.com/balasunil-8/aegisforgee/discussions)

---

<div align="center">

**Installation complete! Start learning security testing! 🎉**

**[Back to README](README.md)** • **[Quick Start](QUICKSTART.md)** • **[Roadmap](ROADMAP.md)**

</div>
