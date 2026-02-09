# 🔧 Common Issues and Solutions

Quick solutions to frequently encountered issues with AegisForge.

---

## 🚨 Installation Issues

### Python Not Found

**Symptoms**:
```
'python' is not recognized as an internal or external command
command not found: python
```

**Solutions**:

**Windows**:
```powershell
# Reinstall Python with "Add to PATH" option
# Or add manually to PATH:
# C:\Users\YourName\AppData\Local\Programs\Python\Python310
```

**Linux/macOS**:
```bash
# Use python3 instead
python3 --version

# Create alias (add to ~/.bashrc or ~/.zshrc)
alias python=python3
```

---

### Virtual Environment Issues

**Symptoms**:
```
The virtual environment was not created successfully
venv: command not found
```

**Solutions**:

**Ubuntu/Debian**:
```bash
sudo apt install python3-venv
python3 -m venv venv
```

**Windows**:
```powershell
# Ensure Python installed correctly
python -m ensurepip
python -m pip install --upgrade pip
python -m venv venv
```

**macOS**:
```bash
# Use built-in venv
python3 -m venv venv

# Or install virtualenv
pip3 install virtualenv
virtualenv venv
```

---

### Pip Installation Failures

**Symptoms**:
```
ERROR: Could not find a version that satisfies the requirement
SSL: CERTIFICATE_VERIFY_FAILED
```

**Solutions**:

**SSL Certificate Issues**:
```bash
# Ubuntu/Debian
sudo apt install ca-certificates

# macOS
cd "/Applications/Python 3.10/"
sudo "./Install Certificates.command"

# Windows - Update certifi
pip install --upgrade certifi
```

**Upgrade Pip**:
```bash
python -m pip install --upgrade pip setuptools wheel
```

**Use Trusted Hosts** (temporary workaround):
```bash
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

---

## 🔌 Port and Network Issues

### Port 5000 Already in Use

**Symptoms**:
```
Address already in use
OSError: [Errno 48] Address already in use
```

**Solutions**:

**Find and Kill Process**:

**Linux/macOS**:
```bash
# Find process using port 5000
lsof -i :5000

# Kill process (replace PID)
kill -9 <PID>

# Or use fuser
sudo fuser -k 5000/tcp
```

**Windows**:
```powershell
# Find process
netstat -ano | findstr :5000

# Kill process (replace PID)
taskkill /PID <PID> /F
```

**Use Different Port**:
```bash
# Set environment variable
export FLASK_RUN_PORT=8000  # Linux/macOS
set FLASK_RUN_PORT=8000     # Windows

# Or update .env file
PORT=8000
```

**macOS Specific - AirPlay Receiver**:
```
1. System Settings → General → AirDrop & Handoff
2. Uncheck "AirPlay Receiver"
```

---

### Cannot Connect to Localhost

**Symptoms**:
```
Connection refused
Failed to connect to localhost
```

**Solutions**:

**Verify Server is Running**:
```bash
# Check if port is listening
# Linux/macOS
lsof -i :5000
netstat -an | grep 5000

# Windows
netstat -ano | findstr :5000
```

**Check Firewall**:

**Windows**:
```
1. Windows Defender Firewall
2. Allow an app
3. Add Python executable
```

**Linux**:
```bash
# UFW
sudo ufw allow 5000/tcp

# firewalld
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --reload
```

**Try Different Address**:
```bash
# Instead of localhost, try:
http://127.0.0.1:5000
http://0.0.0.0:5000
```

---

## 💾 Database Issues

### Database Locked Error

**Symptoms**:
```
sqlite3.OperationalError: database is locked
```

**Solutions**:

**Stop All Processes**:
```bash
# Linux/macOS
pkill -f python
pkill -f aegisforge

# Windows
taskkill /IM python.exe /F
```

**Remove Lock File**:
```bash
# SQLite creates journal files
rm instance/aegisforge.db-journal
rm instance/aegisforge.db-wal
```

**Increase Timeout** (in code):
```python
# config.py
SQLALCHEMY_DATABASE_URI = 'sqlite:///instance/aegisforge.db?timeout=30'
```

---

### Database Connection Failed (PostgreSQL)

**Symptoms**:
```
could not connect to server
Connection refused
```

**Solutions**:

**Check PostgreSQL Status**:
```bash
# Linux
sudo systemctl status postgresql
sudo systemctl start postgresql

# macOS
brew services list
brew services start postgresql@14

# Check if listening on port
ss -tlnp | grep 5432  # Linux
lsof -i :5432         # macOS
```

**Verify Connection String**:
```bash
# .env file format
DATABASE_URL=postgresql://username:password@localhost:5432/aegisforge

# Test connection
psql -h localhost -U username -d aegisforge
```

**Check pg_hba.conf**:
```bash
# Allow local connections
# Edit: /etc/postgresql/14/main/pg_hba.conf (Linux)
# Or: /opt/homebrew/var/postgresql@14/pg_hba.conf (macOS)

# Add line:
local   all   all   trust
host    all   all   127.0.0.1/32   md5
```

---

### Database Migration Errors

**Symptoms**:
```
Table already exists
Column does not exist
```

**Solutions**:

**Reset Database**:
```bash
# Backup first!
cp instance/aegisforge.db instance/aegisforge.db.backup

# Remove and reinitialize
rm instance/aegisforge.db
python init_db.py
```

**PostgreSQL Reset**:
```bash
# Drop and recreate
psql -U postgres
DROP DATABASE aegisforge;
CREATE DATABASE aegisforge;
\q

# Reinitialize
python init_db.py
```

---

## 🔐 Authentication Issues

### JWT Token Errors

**Symptoms**:
```
Signature verification failed
Token has expired
Invalid token
```

**Solutions**:

**Update JWT Secret**:
```bash
# Generate new secret
python -c "import secrets; print(secrets.token_hex(32))"

# Update .env
JWT_SECRET_KEY=<new-secret>

# Restart application
```

**Check Token Format**:
```bash
# Token should be: Bearer <token>
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..." \
  http://localhost:5000/api/protected
```

**Re-login**:
```bash
# Get fresh token
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}'
```

---

### Session Management Issues

**Symptoms**:
```
Session expired
Session not found
```

**Solutions**:

**Clear Session Data**:
```bash
# Delete session files
rm -rf instance/sessions/

# Or clear Redis (if using Redis)
redis-cli FLUSHALL
```

**Update Session Configuration**:
```python
# config.py
SESSION_PERMANENT = False
PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
```

---

## 📦 Module Import Errors

### ModuleNotFoundError

**Symptoms**:
```
ModuleNotFoundError: No module named 'flask'
ImportError: cannot import name 'app'
```

**Solutions**:

**Verify Virtual Environment**:
```bash
# Check if activated (should see (venv) in prompt)
which python  # Should point to venv/bin/python

# Activate if not:
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\Activate.ps1  # Windows
```

**Reinstall Dependencies**:
```bash
pip install -r requirements.txt

# Or install specific package
pip install flask
```

**Check Python Path**:
```bash
# Verify package is installed
pip list | grep flask

# Check Python can find it
python -c "import flask; print(flask.__version__)"
```

---

### Circular Import Errors

**Symptoms**:
```
ImportError: cannot import name 'X' from partially initialized module
```

**Solutions**:

**Check Import Order**:
```python
# Bad - circular import
# file1.py
from file2 import func2

# file2.py
from file1 import func1

# Good - import inside function or use TYPE_CHECKING
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from file1 import func1
```

**Restart Application**:
```bash
# Sometimes fixed by restart
pkill -f python
python aegisforge_api.py
```

---

## 🛠️ Tool Integration Issues

### Postman Collection Import Failed

**Symptoms**:
```
Invalid collection format
Unable to parse collection
```

**Solutions**:

**Re-download Collection**:
```bash
# Ensure you have latest version
git pull origin main

# Import from: postman/AegisForge_Collection.json
```

**Check Postman Version**:
```
Update to latest Postman version
Collections require Postman v8.0+
```

---

### OWASP ZAP Connection Issues

**Symptoms**:
```
Connection refused to proxy
ZAP not responding
```

**Solutions**:

**Start ZAP**:
```bash
# Linux
zap.sh -daemon -port 8080

# macOS
/Applications/OWASP\ ZAP.app/Contents/MacOS/OWASP\ ZAP.sh -daemon

# Windows
"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" -daemon
```

**Configure Proxy**:
```bash
# Browser should use:
HTTP Proxy: 127.0.0.1
Port: 8080
```

**Check API Key**:
```bash
# ZAP requires API key for REST API calls
# Find in: Tools → Options → API
```

---

### Burp Suite Certificate Issues

**Symptoms**:
```
Certificate verification failed
Proxy error
```

**Solutions**:

**Install CA Certificate**:
```
1. Start Burp Suite
2. Browse to: http://burp/cert
3. Download certificate
4. Install in browser/system trust store
```

**Disable SSL Verification** (testing only):
```bash
# Python requests
import requests
requests.get(url, verify=False)
```

---

## ⚡ Performance Issues

### Slow API Response

**Symptoms**:
```
Requests taking > 5 seconds
Timeouts
```

**Solutions**:

**Check Database**:
```bash
# SQLite - consider PostgreSQL for production
# Add indexes if needed
```

**Disable Debug Mode**:
```bash
# .env
DEBUG=False
FLASK_ENV=production
```

**Use Production Server**:
```bash
# Install gunicorn
pip install gunicorn

# Run with multiple workers
gunicorn -w 4 -b 0.0.0.0:5000 aegisforge_api:app
```

---

### High Memory Usage

**Symptoms**:
```
Out of memory
Python process using > 1GB RAM
```

**Solutions**:

**Restart Application**:
```bash
pkill -f python
python aegisforge_api.py
```

**Limit Workers**:
```bash
# When using gunicorn
gunicorn -w 2 --max-requests 1000 aegisforge_api:app
```

**Monitor Resources**:
```bash
# Linux
htop

# macOS
Activity Monitor

# Windows
Task Manager
```

---

## 🐳 Docker Issues

### Docker Container Won't Start

**Symptoms**:
```
Container exits immediately
Error response from daemon
```

**Solutions**:

**Check Logs**:
```bash
docker-compose logs

# Or for specific container
docker logs aegisforgee_app_1
```

**Rebuild Containers**:
```bash
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

**Fix Permissions**:
```bash
# Linux - may need sudo
sudo chown -R $USER:$USER .
```

---

### Docker Port Conflicts

**Symptoms**:
```
Port is already allocated
```

**Solutions**:

**Edit docker-compose.yml**:
```yaml
ports:
  - "8000:5000"  # Change host port to 8000
```

**Stop Conflicting Service**:
```bash
# Find what's using port
lsof -i :5000

# Stop container using port
docker stop <container-id>
```

---

## 🔍 Debugging Tips

### Enable Verbose Logging

```bash
# .env
DEBUG=True
LOG_LEVEL=DEBUG

# View logs
tail -f logs/aegisforge.log
```

### Test Minimal Setup

```bash
# Create test script
python -c "from flask import Flask; app = Flask(__name__); app.run()"
```

### Check Environment

```bash
# Verify all settings
python -c "from config import Config; print(Config.__dict__)"
```

---

## 📞 Getting More Help

### Before Asking for Help

1. **Check this guide** for similar issues
2. **Search GitHub issues**: https://github.com/balasunil-8/aegisforgee/issues
3. **Review documentation**: See docs/ directory
4. **Enable debug mode**: Get detailed error messages

### When Reporting Issues

Include:
- **OS and version**: Windows 11, Ubuntu 22.04, macOS 14
- **Python version**: `python --version`
- **Error message**: Full traceback
- **Steps to reproduce**: What you did before error
- **Configuration**: Relevant .env settings (hide secrets!)
- **Logs**: Output from application

### Support Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community help
- **Documentation**: Comprehensive guides in docs/

---

## 🔄 Quick Fixes Checklist

When something goes wrong:

- [ ] Restart application
- [ ] Check virtual environment is activated
- [ ] Verify port 5000 is available
- [ ] Check database file exists
- [ ] Review .env configuration
- [ ] Update dependencies: `pip install -r requirements.txt`
- [ ] Clear cache: Delete `__pycache__` directories
- [ ] Check logs: `tail -f logs/aegisforge.log`
- [ ] Test with curl: `curl http://localhost:5000/api/health`

---

**Still having issues? Open a GitHub issue with details!**
