# 🍎 macOS Installation Guide

Complete installation guide for AegisForge on macOS (Monterey, Ventura, Sonoma).

---

## 📋 Prerequisites

### System Requirements
- **macOS**: 11.0+ (Big Sur or later)
- **RAM**: 4GB minimum, 8GB recommended
- **Disk Space**: 2GB free space
- **Architecture**: Intel or Apple Silicon (M1/M2/M3)

---

## 🚀 Quick Installation

### Method 1: Homebrew (Recommended)

#### Step 1: Install Homebrew
```bash
# If Homebrew is not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# For Apple Silicon, add to PATH (if needed)
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

#### Step 2: Install Dependencies
```bash
# Install Python, Git, PostgreSQL, and Redis
brew install python@3.10 git postgresql@14 redis

# Verify installations
python3 --version
git --version
```

#### Step 3: Quick Setup
```bash
# Clone repository
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure and initialize
cp .env.example .env
python init_db.py

# Start application
python aegisforge_api.py
```

#### Step 4: Access Application
Open browser to: **http://localhost:5000**

---

## 🛠️ Detailed Installation

### Install Python 3.10+

**Option A: Homebrew (Recommended)**
```bash
brew install python@3.10

# Add to PATH (add to ~/.zshrc or ~/.bash_profile)
echo 'export PATH="/opt/homebrew/opt/python@3.10/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**Option B: Official Installer**
1. Download from [python.org](https://www.python.org/downloads/macos/)
2. Run installer package
3. Verify: `python3 --version`

### Install Git

```bash
# Via Homebrew
brew install git

# Or install Xcode Command Line Tools
xcode-select --install
```

### Clone Repository

```bash
# Choose installation directory
cd ~/Documents  # or ~/Projects

# Clone repository
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
```

### Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Your prompt should now show (venv)
```

### Install Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install core requirements
pip install -r requirements.txt

# Optional: Production features
pip install -r requirements_pro.txt
```

### Configure Application

```bash
# Copy environment template
cp .env.example .env

# Edit with your preferred editor
nano .env  # or vim, code, etc.
```

Basic configuration:
```bash
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///instance/aegisforge.db
DEBUG=True
CTF_MODE=True
```

### Initialize Database

```bash
# Create database and tables
python init_db.py

# Verify database created
ls -la instance/
```

### Start Application

```bash
# Make launcher executable
chmod +x start_pentestlab.sh

# Start application
./start_pentestlab.sh

# Or start manually
python aegisforge_api.py
```

---

## 🐳 Docker Installation

### Prerequisites

Install Docker Desktop for Mac:
1. Download from [docker.com](https://www.docker.com/products/docker-desktop/)
2. Open DMG file and drag Docker to Applications
3. Launch Docker Desktop
4. Wait for Docker to start (whale icon in menu bar)

### Deploy with Docker

```bash
# Clone repository
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee

# Start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Access application
open http://localhost:5000
```

### Docker Commands

```bash
# Stop containers
docker-compose down

# Rebuild containers
docker-compose build --no-cache
docker-compose up -d

# View running containers
docker ps

# Shell into container
docker-compose exec app bash
```

---

## 🗄️ PostgreSQL Setup (Optional)

### Install PostgreSQL

```bash
# Install via Homebrew
brew install postgresql@14

# Start PostgreSQL service
brew services start postgresql@14

# Or start manually
pg_ctl -D /opt/homebrew/var/postgresql@14 start
```

### Create Database

```bash
# Create database
createdb aegisforge

# Create user (optional)
psql postgres
CREATE USER aegisforge WITH PASSWORD 'yourpassword';
GRANT ALL PRIVILEGES ON DATABASE aegisforge TO aegisforge;
\q
```

### Configure Application

Update `.env`:
```bash
DATABASE_URL=postgresql://aegisforge:yourpassword@localhost/aegisforge
```

Initialize:
```bash
python init_db.py
```

---

## 🔴 Redis Setup (Optional)

### Install Redis

```bash
# Install via Homebrew
brew install redis

# Start Redis service
brew services start redis

# Or start manually
redis-server /opt/homebrew/etc/redis.conf
```

### Test Connection

```bash
# Test Redis
redis-cli ping
# Should return: PONG
```

### Configure Application

Update `.env`:
```bash
REDIS_URL=redis://localhost:6379/0
```

---

## ⚙️ Configuration

### Environment Variables

Edit `.env` file:

```bash
# Flask Configuration
FLASK_ENV=development
SECRET_KEY=generate-secure-random-key
DEBUG=True

# Database
DATABASE_URL=sqlite:///instance/aegisforge.db
# Or PostgreSQL:
# DATABASE_URL=postgresql://aegisforge:password@localhost/aegisforge

# Redis (optional)
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET_KEY=your-jwt-secret

# Features
CTF_MODE=True
LEADERBOARD_ENABLED=True
RATE_LIMIT_ENABLED=True

# Server
HOST=0.0.0.0
PORT=5000
```

---

## 🔍 Troubleshooting

### Python Version Issues

**Problem**: Multiple Python versions installed

**Solution**:
```bash
# Check all Python versions
which -a python3

# Use specific version
python3.10 -m venv venv

# Or create alias (add to ~/.zshrc)
alias python=python3.10
```

### SSL Certificate Error

**Problem**: Certificate verification failed

**Solution**:
```bash
# Install certificates (if using python.org installer)
cd "/Applications/Python 3.10/"
sudo "./Install Certificates.command"

# Or install via pip
pip install --upgrade certifi
```

### Port 5000 Already in Use

**Problem**: AirPlay Receiver uses port 5000 on macOS 12+

**Solution 1 - Disable AirPlay Receiver**:
1. System Settings → General → AirDrop & Handoff
2. Uncheck "AirPlay Receiver"

**Solution 2 - Use Different Port**:
```bash
# Set custom port
export FLASK_RUN_PORT=8000
python aegisforge_api.py

# Or update .env
PORT=8000
```

### Homebrew Not Found (Apple Silicon)

**Problem**: Command not found after installing Homebrew

**Solution**:
```bash
# Add Homebrew to PATH
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
source ~/.zprofile

# Verify
brew --version
```

### PostgreSQL Connection Error

**Problem**: Can't connect to PostgreSQL

**Solution**:
```bash
# Check if PostgreSQL is running
brew services list

# Start PostgreSQL
brew services start postgresql@14

# Check port
lsof -i :5432

# Test connection
psql -h localhost -U postgres
```

### Permission Denied Errors

**Problem**: Permission errors when running scripts

**Solution**:
```bash
# Make scripts executable
chmod +x start_pentestlab.sh
chmod +x *.py

# Fix ownership if needed
sudo chown -R $USER:staff ~/aegisforgee
```

### Virtual Environment Not Activating

**Problem**: `venv` doesn't activate properly

**Solution**:
```bash
# Check shell
echo $SHELL

# For zsh (default on macOS Catalina+)
source venv/bin/activate

# Verify activation
which python
# Should show: /path/to/aegisforgee/venv/bin/python
```

### M1/M2/M3 (Apple Silicon) Issues

**Problem**: Some packages won't install on ARM architecture

**Solution**:
```bash
# Install Rosetta 2 (if not already installed)
softwareupdate --install-rosetta

# Use architecture-specific installation
arch -arm64 pip install -r requirements.txt

# Or use native ARM builds (preferred)
pip install --no-cache-dir -r requirements.txt
```

---

## 💻 macOS-Specific Tips

### Terminal Recommendations

**iTerm2** (Highly Recommended):
```bash
brew install --cask iterm2
```

Features:
- Better color support
- Split panes
- Search and autocomplete
- Tmux integration

### Shell Configuration

**Zsh** (Default on macOS):
```bash
# Install Oh My Zsh (optional)
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# Add useful aliases to ~/.zshrc
echo 'alias ll="ls -lah"' >> ~/.zshrc
echo 'alias aegis="cd ~/Documents/aegisforgee && source venv/bin/activate"' >> ~/.zshrc
source ~/.zshrc
```

### Visual Studio Code

```bash
# Install VS Code
brew install --cask visual-studio-code

# Open project in VS Code
cd aegisforgee
code .

# Install Python extension
code --install-extension ms-python.python
```

### Keyboard Shortcuts

```bash
# Stop server
Ctrl + C

# Search command history
Ctrl + R

# Clear terminal
Cmd + K  # or: clear
```

---

## 🔐 Security Considerations

### Firewall Configuration

```bash
# macOS firewall is off by default
# Enable in: System Settings → Network → Firewall

# Allow incoming connections (if needed)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /path/to/python
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblock /path/to/python
```

### Localhost-Only Access

By default, AegisForge binds to `0.0.0.0`. For localhost-only:

Edit `.env`:
```bash
HOST=127.0.0.1
```

---

## 📦 Optional Tools

### Install Postman

```bash
# Via Homebrew
brew install --cask postman

# Or download from postman.com
```

### Install OWASP ZAP

```bash
# Via Homebrew
brew install --cask owasp-zap

# See OWASP_ZAP_GUIDE.md for setup
```

### Install Burp Suite

Download from [portswigger.net](https://portswigger.net/burp/communitydownload)

---

## 🔄 Updates

```bash
# Navigate to directory
cd ~/Documents/aegisforgee

# Activate virtual environment
source venv/bin/activate

# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Update database
python init_db.py

# Restart application
python aegisforge_api.py
```

---

## 🌐 Production Deployment

### Use Gunicorn

```bash
# Install gunicorn
pip install gunicorn

# Start with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 aegisforge_api:app

# For production
gunicorn -w 4 -b 127.0.0.1:5000 --access-logfile - --error-logfile - aegisforge_api:app
```

### Launch Agent (Auto-start on boot)

Create `~/Library/LaunchAgents/com.aegisforge.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aegisforge</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/yourusername/Documents/aegisforgee/venv/bin/python</string>
        <string>/Users/yourusername/Documents/aegisforgee/aegisforge_api.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Users/yourusername/Documents/aegisforgee</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Load:
```bash
launchctl load ~/Library/LaunchAgents/com.aegisforge.plist
```

---

## 🗑️ Uninstallation

```bash
# Stop services
brew services stop postgresql@14
brew services stop redis

# Remove application
rm -rf ~/Documents/aegisforgee

# Remove Homebrew packages (optional)
brew uninstall postgresql@14 redis
```

---

## 📚 Next Steps

- **First Setup**: [docs/getting-started/first-time-setup.md](../getting-started/first-time-setup.md)
- **Learning Paths**: [docs/getting-started/learning-paths.md](../getting-started/learning-paths.md)
- **API Testing**: [API_DOCUMENTATION.md](../../API_DOCUMENTATION.md)
- **CTF Challenges**: Start with beginner challenges

---

## 🆘 Getting Help

- **Documentation**: [README.md](../../README.md)
- **Common Issues**: [docs/troubleshooting/common-issues.md](../troubleshooting/common-issues.md)
- **GitHub**: [Report issues](https://github.com/balasunil-8/aegisforgee/issues)

---

**Installation complete! Access at http://localhost:5000** 🚀
